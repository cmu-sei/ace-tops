/*
   ACE Tool

   Copyright 2026 Carnegie Mellon University.

   NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS
   FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
   EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
   PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE
   MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
   TRADEMARK, OR COPYRIGHT INFRINGEMENT.

   Licensed under a MIT (SEI)-style license, please see license.txt or contact
   permission@sei.cmu.edu for full terms.

   [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited
   distribution.  Please see Copyright notice for non-US Government use and distribution.

   This Software includes and/or makes use of Third-Party Software each subject to its own license.

   DM26-0670
*/

//! A fact base read from checkouts of the signed repositories, every signature verified as it is read:
//!
//! - the deployment: its last commit signed by the pipeline under the deployment CA, its record signed in the deployment
//!   record's domain, and the authority model the render gave the credentials agent, in that agent's ConfigMap;
//! - `polar-schedules`: every signed runtime document, verified under Polar's CA as an agent verifies it. One that does
//!   not verify is not in force anywhere, so it is left out, and said;
//! - `polar-evidence`: every record, verified in the evidence domain; one that does not verify is left out, and said;
//! - the scaffolds, as `nu infra/resolve.nu scaffolds <dir>` writes them.

use super::{Deployed, Evidence, FactBase, Instance, ScaffoldFact, Section};
use crate::scaffold::Scaffold;
use credentials_agent_model::Model;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The variable the render gives the credentials agent its model in.
const MODEL_VARIABLE: &str = "CREDENTIALS_AGENT_AUTHORITY_MODEL";

/// The common name of the certificate every commit to the deployment is signed with.
const PIPELINE: &str = "pipeline";

/// Where the facts are: a checkout of each repository, and the scaffolds' folder.
pub struct Sources<'a> {
    pub deployment: &'a Path,
    pub schedules: &'a Path,
    pub evidence: &'a Path,
    pub scaffolds: &'a Path,
}

/// What each kind of signature must chain to: Polar's CA for documents and evidence, the deployment CA for the pipeline.
pub struct Trusts<'a> {
    pub polar: &'a [String],
    pub deployment: &'a [String],
}

/// A fact base, and what was read and left out: a document or record that did not verify.
pub struct Read {
    pub facts: FactBase,
    pub left_out: Vec<String>,
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The fingerprint of the first certificate in `pem`: the digest of its DER.
pub fn fingerprint(pem: &str) -> Result<String, String> {
    use base64::Engine as _;
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| format!("the CA certificate is not PEM: {e}"))?;
    if der.is_empty() {
        return Err("the CA holds no certificate".to_string());
    }
    Ok(sha256(&der))
}

/// Every file under `dir` ending in `suffix`, in order, leaving out git's own.
fn files(dir: &Path, suffix: &str) -> Result<Vec<PathBuf>, String> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(at) = pending.pop() {
        let entries =
            std::fs::read_dir(&at).map_err(|e| format!("cannot read {}: {e}", at.display()))?;
        for entry in entries {
            let path = entry
                .map_err(|e| format!("cannot read {}: {e}", at.display()))?
                .path();
            if path.file_name().is_some_and(|n| n == ".git") {
                continue;
            }
            if path.is_dir() {
                pending.push(path);
            } else if path.to_string_lossy().ends_with(suffix) {
                found.push(path);
            }
        }
    }
    found.sort();
    Ok(found)
}

fn relative(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}

fn git(dir: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|e| format!("cannot run git: {e}"))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(format!(
            "{} is not a checkout git can read: {}",
            dir.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// The commit a checkout is at.
fn head(dir: &Path) -> Result<String, String> {
    Ok(String::from_utf8_lossy(&git(dir, &["rev-parse", "HEAD"])?)
        .trim()
        .to_string())
}

/// The authority model in a rendered manifest's ConfigMaps, if one holds it.
fn model_in(text: &str) -> Result<Option<String>, String> {
    use serde::Deserialize;
    for document in serde_yaml::Deserializer::from_str(text) {
        let value = match serde_yaml::Value::deserialize(document) {
            Ok(value) => value,
            Err(e) => return Err(format!("a manifest is not YAML: {e}")),
        };
        let value: Value = serde_json::to_value(value).map_err(|e| e.to_string())?;
        if value["kind"] != "ConfigMap" {
            continue;
        }
        for data in value["data"]
            .as_object()
            .into_iter()
            .flat_map(|d| d.values())
        {
            let Some(config) = data
                .as_str()
                .and_then(|t| serde_json::from_str::<Value>(t).ok())
            else {
                continue;
            };
            for section in config["sections"].as_array().into_iter().flatten() {
                for variable in section["variables"].as_array().into_iter().flatten() {
                    if variable["name"] == MODEL_VARIABLE
                        && let Some(model) = variable["value"].as_str()
                    {
                        return Ok(Some(model.to_string()));
                    }
                }
            }
        }
    }
    Ok(None)
}

/// What the deployment says: its target, what runs, its authority model, and what was read.
struct Deployment {
    target: String,
    deployed: Vec<Deployed>,
    model: Model,
    inputs: BTreeMap<String, String>,
}

/// The deployment: its last commit's signature, its record, and its authority model.
fn deployment(dir: &Path, trust: &[String], now: i64) -> Result<Deployment, String> {
    let trust_of =
        polar_signing::Trust::from_pem(trust).map_err(|e| format!("the deployment CA: {e}"))?;
    let commit = head(dir)?;
    // What is read is the working tree, and what is signed is the commit: they must be the same.
    let changed = git(dir, &["status", "--porcelain", "--untracked-files=all"])?;
    if !changed.is_empty() {
        return Err(format!(
            "{} has changes the pipeline did not sign: {}",
            dir.display(),
            String::from_utf8_lossy(&changed)
                .lines()
                .take(3)
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    let raw = git(dir, &["cat-file", "commit", "HEAD"])?;
    polar_signing::commit::verify_commit(&raw, &trust_of, PIPELINE, now).map_err(|e| {
        format!("the deployment's commit {commit} is not the pipeline's, signed under the deployment CA: {e}")
    })?;

    let record_path = dir.join("deployment-record.json");
    let text = std::fs::read_to_string(&record_path)
        .map_err(|e| format!("cannot read {}: {e}", record_path.display()))?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|e| format!("the deployment's record is not JSON: {e}"))?;
    let document = polar_signing::Document::from_value(&value).map_err(|e| e.to_string())?;
    polar_signing::verify_in(
        polar_signing::Domain::DEPLOYMENT_RECORD,
        &document,
        &trust_of,
        now,
    )
    .map_err(|e| format!("the deployment's record does not verify: {e}"))?;
    let record = document.payload;
    let target = record["target"]
        .as_str()
        .ok_or("the deployment's record names no target")?
        .to_string();
    let deployed = record["workloads"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|w| Deployed {
            identity: w["identity"].as_str().unwrap_or("").to_string(),
            owner_kind: w["owner_kind"].as_str().unwrap_or("").to_string(),
            images: w["containers"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|c| c["image"].as_str().map(str::to_string))
                .collect(),
        })
        .collect();

    let mut model = None;
    for path in files(&dir.join("layers"), ".yaml")? {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if let Some(found) = model_in(&text)? {
            model = Some(found);
            break;
        }
    }
    let model = Model::parse(&model.ok_or(
        "the deployment gives the credentials agent no authority model, so nothing can be judged",
    )?)?;

    let mut inputs = BTreeMap::new();
    inputs.insert("deployment".to_string(), commit);
    inputs.insert(
        "deployment_record_version".to_string(),
        record["version"].to_string(),
    );
    if let Ok(provenance) = std::fs::read_to_string(dir.join("provenance.json"))
        && let Ok(provenance) = serde_json::from_str::<Value>(&provenance)
        && let Some(source) = provenance["source"]["commit"].as_str()
    {
        inputs.insert("deployment_source".to_string(), source.to_string());
    }
    Ok(Deployment {
        target,
        deployed,
        model,
        inputs,
    })
}

/// Every signed runtime document in the schedules, and what was left out.
fn schedules(
    dir: &Path,
    trust: &[String],
    now: i64,
    left_out: &mut Vec<String>,
) -> Result<Vec<Section>, String> {
    let mut sections = Vec::new();
    for path in files(dir, ".dhall")? {
        let file = relative(&path, dir);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        // A schedule that is not a signed document is the scheduler's, and says nothing of a section.
        let Ok(value) = crate::evaluate(&text) else {
            left_out.push(format!("{file}: not valid Dhall"));
            continue;
        };
        if polar_signing::Document::from_value(&value).is_err() {
            continue;
        }
        match crate::verify_source(&text, trust, now) {
            Err(e) => left_out.push(format!(
                "{file}: does not verify, so no agent holds it: {e}"
            )),
            Ok((signer, payload)) if payload["type"] == "runtime" => {
                let body = payload["body"].clone();
                sections.push(Section {
                    agent: payload["target"]["agent"]
                        .as_str()
                        .unwrap_or("")
                        .to_string(),
                    name: payload["section"].as_str().unwrap_or("").to_string(),
                    id: payload["id"].as_str().unwrap_or("").to_string(),
                    version: payload["version"].as_u64().unwrap_or(0),
                    body_sha256: sha256(
                        &polar_signing::canonical::encode(&body).unwrap_or_default(),
                    ),
                    body,
                    signer: signer.username.unwrap_or_else(|| signer.serial.clone()),
                    file,
                });
            }
            Ok(_) => {}
        }
    }
    Ok(sections)
}

/// Every record in the evidence repository, and what was left out.
fn evidence(
    dir: &Path,
    trust: &[String],
    now: i64,
    left_out: &mut Vec<String>,
) -> Result<Vec<Evidence>, String> {
    let mut found = Vec::new();
    for path in files(dir, ".json")? {
        let file = relative(&path, dir);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        match crate::evidence::verify_record(&text, trust, now) {
            Ok((signer, record)) => found.push(Evidence {
                file,
                signer: signer.username.unwrap_or_else(|| signer.serial.clone()),
                record,
            }),
            Err(e) => left_out.push(format!("{file}: does not verify as evidence: {e}")),
        }
    }
    Ok(found)
}

/// Every scaffold in `dir`, by the agent it is of.
fn scaffolds(dir: &Path) -> Result<BTreeMap<String, ScaffoldFact>, String> {
    let mut found = BTreeMap::new();
    for path in files(dir, ".json")? {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let scaffold = Scaffold::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let document: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        found.insert(
            scaffold.agent,
            ScaffoldFact {
                sha256: sha256(text.as_bytes()),
                document,
            },
        );
    }
    Ok(found)
}

/// Reads the fact base of one instance from `sources`, verifying as it reads. An error is a check that cannot be made:
/// the deployment does not verify, or holds no model.
pub fn read(sources: &Sources<'_>, trusts: &Trusts<'_>, now: i64) -> Result<Read, String> {
    let Deployment {
        target,
        deployed,
        model,
        mut inputs,
    } = deployment(sources.deployment, trusts.deployment, now)?;
    let mut left_out = Vec::new();
    let sections = schedules(sources.schedules, trusts.polar, now, &mut left_out)?;
    let evidence = evidence(sources.evidence, trusts.polar, now, &mut left_out)?;
    for (name, dir) in [
        ("schedules", sources.schedules),
        ("evidence", sources.evidence),
    ] {
        if let Ok(commit) = head(dir) {
            inputs.insert(name.to_string(), commit);
        }
    }
    let ca = trusts
        .polar
        .first()
        .ok_or("no CA to verify documents with")?;
    Ok(Read {
        facts: FactBase {
            instance: Instance {
                target,
                ca_sha256: fingerprint(ca)?,
            },
            model,
            deployed,
            scaffolds: scaffolds(sources.scaffolds)?,
            sections,
            evidence,
            inputs,
        },
        left_out,
    })
}
