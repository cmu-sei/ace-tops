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

//! `polar-sign check` as an administrator runs it, over checkouts of the three repositories as a deployment has them:
//! the deployment, its last commit signed by the pipeline, with its record and the authority model in the credentials
//! agent's ConfigMap; polar-schedules, with the OpenAPI mapping and the state agent's sections signed; polar-evidence,
//! with the mapping's projection test.

use polar_signing::testing::{Spec, commit_signer, now, root, signer};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const TOOL: &str = env!("CARGO_BIN_EXE_polar-sign");
const MODEL: &str = include_str!("../../credentials-agent/model/tests/fixtures/sandbox-model.json");
const MAPPING: &str = include_str!("../../polar-projection/examples/openapi.dhall");

fn git(dir: &Path, args: &[&str]) -> Vec<u8> {
    let out = Command::new("git")
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.org",
            "-c",
            "commit.gpgsign=false",
        ])
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "init.defaultBranch=main",
        ])
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn commit_all(dir: &Path) {
    if !dir.join(".git").exists() {
        git(dir, &["init", "-q"]);
    }
    git(dir, &["add", "--all"]);
    git(dir, &["commit", "-q", "-m", "files"]);
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn processor_scaffold() -> String {
    json!({
        "agent": {"name": "openapi-processor"},
        "runtime": [{"name": "projection", "doc": "d", "body": {"rules": {"type": "a projection: polar-projection/projection.dhall, signed with polar-sign runtime --projection", "required": true}}}],
        "graph": [
            {"label": "OpenApiApplication", "access": "owns", "purpose": "p", "keys": [["source"]]},
            {"label": "OpenApiEndpoint", "access": "owns", "purpose": "p", "keys": [["source", "method", "path"]]}
        ],
        "graph_edges": [{"from": "OpenApiApplication", "kind": "HAS_ENDPOINT", "to": "OpenApiEndpoint", "purpose": "p"}]
    })
    .to_string()
}

/// An administrator's folder and the three checkouts, as a sound deployment has them.
struct Site {
    root: tempfile::TempDir,
    pipeline: polar_signing::testing::CommitSigner,
}

impl Site {
    fn new() -> Self {
        let site = Site {
            root: tempfile::tempdir().unwrap(),
            pipeline: commit_signer("pipeline"),
        };
        let polar = root_ca();
        let alice = signer(&polar, Spec::default());
        write(&site.admin().join("ca.pem"), &polar.pem);
        write(&site.admin().join("alice.crt"), &alice.cert_pem);
        write(&site.admin().join("alice.key"), &alice.key_pem);
        let identity = polar_sign::Identity {
            chain: vec![alice.cert_pem.clone()],
            key_pem: alice.key_pem.clone(),
        };

        // The scaffolds.
        let scaffolds = site.admin().join("scaffolds");
        write(
            &scaffolds.join("openapi-processor.json"),
            &processor_scaffold(),
        );
        for (agent, owns) in [
            ("soft-state-observer", json!([])),
            ("soft-state-processor", json!(["AgentHealth"])),
        ] {
            let graph: Vec<Value> = owns
                .as_array()
                .unwrap()
                .iter()
                .map(|l| json!({"label": l, "access": "owns", "purpose": "p", "keys": [["id"]]}))
                .collect();
            write(
                &scaffolds.join(format!("{agent}.json")),
                &json!({"agent": {"name": agent}, "runtime": [], "graph": graph}).to_string(),
            );
        }

        // The deployment, as the pipeline publishes it.
        let deploy_ca = root("Polar Deployment CA");
        let recorder = signer(&deploy_ca, Spec::default());
        write(
            &site.deploy_ca(),
            &format!("{}{}", site.pipeline.ca_pem, deploy_ca.pem),
        );
        let record = polar_signing::sign_in(
            polar_signing::Domain::DEPLOYMENT_RECORD,
            json!({ "schema": 1, "target": "sandbox-local", "version": 4, "workloads": [
                { "identity": "openapi-processor.polar.serviceaccount.cluster.local", "owner_kind": "Deployment",
                  "containers": [{ "name": "openapi-processor", "image": "localhost:30500/openapi-processor@sha256:aa" }] }
            ]}),
            std::slice::from_ref(&recorder.cert_pem),
            &recorder.key_pem,
        )
        .unwrap();
        let deployment = site.deployment();
        write(
            &deployment.join("deployment-record.json"),
            &serde_json::to_string_pretty(&record.to_value()).unwrap(),
        );
        write(
            &deployment.join("provenance.json"),
            &json!({ "source": { "commit": "abc" } }).to_string(),
        );
        let config = json!({ "sections": [{ "name": "credentials-agent", "variables": [
            { "name": "CREDENTIALS_AGENT_AUTHORITY_MODEL", "value": MODEL }
        ]}]});
        write(
            &deployment.join("layers/identity/credentials-agent-resources.yaml"),
            &format!(
                "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: credentials-agent\n---\n{}\n",
                json!({ "apiVersion": "v1", "kind": "ConfigMap", "metadata": { "name": "credentials-agent-config" },
                        "data": { "config.json": config.to_string() } })
            ),
        );
        commit_all(&deployment);
        site.sign_head();

        // The schedules, signed by alice.
        let model: Value = serde_json::from_str(MODEL).unwrap();
        let agents: Vec<Value> = model["workloads"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|w| w["kind"] == "agent" && w["config"] == "document")
            .map(|w| json!({ "workload": w["workload"], "identity": w["identity"] }))
            .collect();
        let documents = [
            (
                "openapi-processor",
                "projection",
                polar_sign::projection_body(MAPPING).unwrap(),
            ),
            (
                "soft-state-observer",
                "schema",
                json!({ "workloads": [
                    { "workload": "openapi-processor", "identity": "openapi-processor.polar.serviceaccount.cluster.local",
                      "owns": ["OpenApiApplication", "OpenApiEndpoint"], "reads": [] },
                    { "workload": "soft-state-processor", "identity": "soft-state-processor.polar.serviceaccount.cluster.local",
                      "owns": ["AgentHealth"], "reads": [] }
                ]}),
            ),
            (
                "soft-state-processor",
                "agents",
                json!({ "workloads": agents }),
            ),
        ];
        for (agent, section, body) in documents {
            let payload =
                polar_sign::runtime_payload(agent, section, 1, &format!("{agent}-{section}"), body);
            write(
                &site
                    .schedules()
                    .join(format!("permanent/{agent}/{section}.dhall")),
                &polar_sign::sign_to_dhall(payload, &identity).unwrap(),
            );
        }
        commit_all(&site.schedules());

        // The mapping's projection test.
        let tested = polar_sign::evidence::projection_test(
            &polar_sign::evidence::ProjectionTest {
                scaffold: &processor_scaffold(),
                section: "projection",
                mapping: MAPPING,
                mapping_name: "openapi.dhall",
                samples: &PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../polar-projection/examples/openapi"),
            },
            &identity,
            std::slice::from_ref(&polar.pem),
            now(),
        )
        .unwrap();
        let signed = polar_sign::evidence::sign_record(tested.record, &identity).unwrap();
        write(
            &site.evidence().join(polar_sign::evidence::place(
                "openapi-processor",
                "projection",
                &signed,
            )),
            &signed,
        );
        write(&site.evidence().join("README.md"), "evidence");
        commit_all(&site.evidence());
        site
    }

    /// Signs the deployment's last commit as the pipeline does.
    fn sign_head(&self) {
        let deployment = self.deployment();
        let raw = git(&deployment, &["cat-file", "commit", "HEAD"]);
        let signed = self.pipeline.sign(&raw);
        let mut hash = Command::new("git")
            .arg("-C")
            .arg(&deployment)
            .args(["hash-object", "-t", "commit", "-w", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(hash.stdin.as_mut().unwrap(), &signed).unwrap();
        let sha = String::from_utf8(hash.wait_with_output().unwrap().stdout).unwrap();
        git(&deployment, &["update-ref", "HEAD", sha.trim()]);
    }

    fn admin(&self) -> PathBuf {
        self.root.path().join("admin")
    }
    fn deploy_ca(&self) -> PathBuf {
        self.root.path().join("deploy-ca.pem")
    }
    fn deployment(&self) -> PathBuf {
        self.root.path().join("deployment")
    }
    fn schedules(&self) -> PathBuf {
        self.root.path().join("schedules")
    }
    fn evidence(&self) -> PathBuf {
        self.root.path().join("evidence")
    }

    fn check(&self) -> Output {
        Command::new(TOOL)
            .arg("check")
            .arg("--deployment")
            .arg(self.deployment())
            .arg("--schedules")
            .arg(self.schedules())
            .arg("--evidence")
            .arg(self.evidence())
            .arg("--deploy-ca")
            .arg(self.deploy_ca())
            .args(["--user", "alice", "--dir"])
            .arg(self.admin())
            .output()
            .unwrap()
    }
}

fn root_ca() -> polar_signing::testing::Authority {
    root("Polar Internal CA")
}

fn verdicts(record: &Value) -> Vec<(String, String)> {
    record["payload"]["verdicts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            (
                v["id"].as_str().unwrap().to_string(),
                v["verdict"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn a_sound_deployment_is_checked_and_every_invariant_holds_in_a_signed_record() {
    let site = Site::new();
    let out = site.check();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let record: Value = serde_json::from_slice(&out.stdout).unwrap();
    for (id, verdict) in verdicts(&record) {
        assert_eq!(verdict, "holds", "{id}: {stderr}");
    }
    let payload = &record["payload"];
    assert_eq!(payload["type"], "instance-check");
    assert_eq!(payload["subject"]["target"], "sandbox-local");
    assert_eq!(payload["inputs"]["deployment_record_version"], "4");
    assert_eq!(payload["inputs"]["deployment_source"], "abc");
    assert_eq!(payload["left_out"], json!([]));
    let (_, said) = polar_sign::evidence::verify_record(
        &String::from_utf8_lossy(&out.stdout),
        &[std::fs::read_to_string(site.admin().join("ca.pem")).unwrap()],
        now(),
    )
    .unwrap();
    assert_eq!(said["type"], "instance-check");
}

#[test]
fn a_violation_is_reported_and_signed_and_is_not_a_failure_of_the_tool() {
    let site = Site::new();
    // The state agent's list leaves the OpenAPI processor out.
    let path = site
        .schedules()
        .join("permanent/soft-state-processor/agents.dhall");
    let polar = std::fs::read_to_string(site.admin().join("ca.pem")).unwrap();
    let identity = polar_sign::load_identity(&site.admin(), "alice").unwrap();
    let (_, payload) =
        polar_sign::verify_source(&std::fs::read_to_string(&path).unwrap(), &[polar], now())
            .unwrap();
    let mut body = payload["body"].clone();
    body["workloads"]
        .as_array_mut()
        .unwrap()
        .retain(|w| w["workload"] != "openapi-processor");
    let next = polar_sign::runtime_payload(
        "soft-state-processor",
        "agents",
        2,
        "soft-state-processor-agents",
        body,
    );
    write(&path, &polar_sign::sign_to_dhall(next, &identity).unwrap());
    commit_all(&site.schedules());

    let out = site.check();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("violated seen-by-health"), "{stderr}");
    assert!(stderr.contains("openapi-processor (openapi-processor.polar.serviceaccount.cluster.local) is not in the agents list"));
    let record: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(verdicts(&record).contains(&("seen-by-health".into(), "violated".into())));
    assert_eq!(record["payload"]["result"]["passed"], false);
}

#[test]
fn a_document_that_does_not_verify_is_left_out_and_said() {
    let site = Site::new();
    let path = site
        .schedules()
        .join("permanent/openapi-processor/projection.dhall");
    let text = std::fs::read_to_string(&path).unwrap();
    write(
        &path,
        &text.replacen("OpenApiEndpoint", "OpenApiEndpoinT", 1),
    );
    commit_all(&site.schedules());
    let out = site.check();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr.contains("left out: permanent/openapi-processor/projection.dhall: does not verify"),
        "{stderr}"
    );
    let record: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(record["payload"]["left_out"].as_array().unwrap().len(), 1);
}

#[test]
fn a_deployment_record_changed_after_it_was_signed_cannot_be_judged() {
    let site = Site::new();
    let path = site.deployment().join("deployment-record.json");
    let mut record: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    record["payload"]["target"] = json!("elsewhere");
    write(&path, &record.to_string());
    commit_all(&site.deployment());
    site.sign_head();
    let out = site.check();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("the deployment's record does not verify"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// What is read is the working tree, and what the pipeline signed is the commit: a checkout changed since is refused.
#[test]
fn a_deployment_checkout_with_changes_the_pipeline_did_not_sign_cannot_be_judged() {
    let site = Site::new();
    let path = site
        .deployment()
        .join("layers/identity/credentials-agent-resources.yaml");
    let text = std::fs::read_to_string(&path).unwrap();
    write(
        &path,
        &text.replace("credentials-agent", "credentials-agent-x"),
    );
    let out = site.check();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("has changes the pipeline did not sign"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_deployment_commit_the_pipeline_did_not_sign_cannot_be_judged() {
    let site = Site::new();
    write(&site.deployment().join("README.md"), "changed by hand");
    commit_all(&site.deployment());
    let out = site.check();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("is not the pipeline's"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_migration_named_is_judged_by_its_file_and_its_applied_record_in_the_schedules() {
    let site = Site::new();
    let identity = polar_sign::load_identity(&site.admin(), "alice").unwrap();
    let cypher = b"MATCH (n:OpenApiEndpoint) SET n.kind = 'operation'";
    write(
        &site
            .schedules()
            .join("migrations/openapi-processor/m1.cypher"),
        std::str::from_utf8(cypher).unwrap(),
    );
    let sha = polar_sign::migration_sha256(cypher);
    let section = polar_sign::with_migrations(
        polar_sign::runtime_payload(
            "openapi-processor",
            "projection",
            2,
            "openapi-processor-projection-2",
            polar_sign::projection_body(MAPPING).unwrap(),
        ),
        &[polar_sign::Migration {
            id: "m1".into(),
            sha256: sha.clone(),
            after: false,
        }],
    );
    write(
        &site
            .schedules()
            .join("permanent/openapi-processor/projection.dhall"),
        &polar_sign::sign_to_dhall(section, &identity).unwrap(),
    );
    commit_all(&site.schedules());
    let verdict_of = |out: &Output, id: &str| -> String {
        let record: Value = serde_json::from_slice(&out.stdout).unwrap();
        verdicts(&record)
            .into_iter()
            .find(|(i, _)| i == id)
            .unwrap()
            .1
    };
    let out = site.check();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(verdict_of(&out, "migrations-applied"), "violated");
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("intended, and no record says it was applied")
    );

    let record = polar_sign::applied_payload(
        "openapi-processor",
        "projection",
        "m1",
        &sha,
        1,
        "12 endpoints",
    );
    write(
        &site
            .schedules()
            .join("migrations/openapi-processor/m1.applied.dhall"),
        &polar_sign::sign_to_dhall(record, &identity).unwrap(),
    );
    commit_all(&site.schedules());
    let out = site.check();
    assert_eq!(
        verdict_of(&out, "migrations-applied"),
        "holds",
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
