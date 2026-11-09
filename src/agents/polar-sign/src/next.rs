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

//! `polar-sign next`: the file for the next version of a signed runtime section, or of an agent's settings, made from the
//! latest version in the schedules repository (Vaughn's proposal, `docs/architecture/polar-sign-next.md`, taken
//! 2026-11-09). That version is verified as an agent verifies it, and version N+1 is written with its body as it was, its
//! `id` kept, to be edited and then signed with `polar-sign sign`, which still checks, seals and signs. `next` signs
//! nothing and reads no key.
//!
//! A sealed secret is not carried. Its ciphertext is bound to its agent, section, version and name
//! (`polar_escrow::binding_context`), so version N's cannot be opened as version N+1's: each is left `null`, which `sign`
//! refuses until it is typed again, and the file says which. What the file form cannot hold (a version range, migrations)
//! is named, not silently left behind.

use crate::push::{head, place, up_to_date};
use crate::verify_source;
use serde_json::{Map, Value, json};
use std::path::Path;

/// The latest signed version as it was read from the repository, verified.
#[derive(Debug, Clone)]
pub struct Latest {
    pub payload: Value,
    /// Who signed it, as `polar-sign verify` says it.
    pub signer: String,
    /// The schedules repository's commit it was read at.
    pub commit: String,
}

/// The file for the version after `latest`: what `polar-sign sign` takes.
pub fn file_for(agent: &str, section: Option<&str>, latest: &Latest) -> Result<String, String> {
    let payload = &latest.payload;
    let what = section.map_or("settings".to_string(), |s| format!("`{s}` section"));
    let whose = payload["target"]["agent"].as_str().unwrap_or_default();
    let kind = payload["type"].as_str().unwrap_or_default();
    let read_section = payload["section"].as_str();
    let fits = whose == agent
        && match section {
            Some(section) => kind == "runtime" && read_section == Some(section),
            None => kind == "configuration",
        };
    if !fits {
        return Err(format!(
            "the version read is not {agent}'s {what} (it is {}'s {})",
            if whose.is_empty() { "nobody" } else { whose },
            read_section.map_or(kind.to_string(), |s| format!("`{s}` section"))
        ));
    }
    let version = payload["version"]
        .as_u64()
        .ok_or("the version read has no version number")?;
    let next = version
        .checked_add(1)
        .ok_or("the version read is the last there can be")?;

    let mut file = Map::new();
    file.insert("agent".into(), json!(agent));
    let mut retype = Vec::new();
    match section {
        Some(section) => {
            let mut body = payload["body"].clone();
            unseal(&mut body, String::new(), &mut retype);
            file.insert("section".into(), json!(section));
            file.insert("body".into(), body);
        }
        None => {
            let settings: Map<String, Value> = payload["changes"]
                .as_array()
                .ok_or("the settings read have no changes")?
                .iter()
                .filter_map(|c| Some((c["name"].as_str()?.to_string(), c["value"].clone())))
                .collect();
            file.insert("settings".into(), Value::Object(settings));
        }
    }
    file.insert("version".into(), json!(next));
    if let Some(id) = payload["id"].as_str() {
        file.insert("id".into(), json!(id));
    }

    let known: &[&str] = match section {
        Some(_) => &["type", "id", "target", "section", "version", "body"],
        None => &["type", "id", "target", "version", "changes"],
    };
    let mut left: Vec<String> = payload
        .as_object()
        .map(|o| {
            o.keys()
                .filter(|k| !known.contains(&k.as_str()))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    if let Some(target) = payload["target"].as_object() {
        left.extend(
            target
                .keys()
                .filter(|k| *k != "agent")
                .map(|k| format!("target.{k}")),
        );
    }

    let mut header = vec![
        format!(
            "// polar-sign next: version {next} of {agent}'s {what}, made from version {version}, the latest in the repository"
        ),
        format!(
            "// (schedules commit {}; not necessarily the version the agent applied), signed by {}. Edit what changes, then",
            latest.commit, latest.signer
        ),
        "// sign it: polar-sign sign <this file> --user <you> [--push].".to_string(),
    ];
    if !retype.is_empty() {
        header.push(format!(
            "// Type again: a sealed secret is bound to its version, and version {next} cannot open version {version}'s. Left"
        ));
        header.push(format!(
            "// null, which `sign` refuses until each is typed: {}.",
            retype.join(", ")
        ));
    }
    if !left.is_empty() {
        header.push(format!(
            "// Not carried, since this file cannot hold it: {}. Give it again when signing, or version {next} is without it.",
            left.join(", ")
        ));
    }
    let body = serde_json::to_string_pretty(&Value::Object(file)).map_err(|e| e.to_string())?;
    Ok(format!("{}\n{body}\n", header.join("\n")))
}

/// Every sealed value in `value` made `null`, its JSON pointer in `found`.
fn unseal(value: &mut Value, at: String, found: &mut Vec<String>) {
    match value {
        Value::String(text) if polar_escrow::EscrowedSecret::from_document_text(text).is_ok() => {
            *value = Value::Null;
            found.push(at);
        }
        Value::Array(items) => {
            for (i, item) in items.iter_mut().enumerate() {
                unseal(item, format!("{at}/{i}"), found);
            }
        }
        Value::Object(fields) => {
            for (key, field) in fields.iter_mut() {
                let key = key.replace('~', "~0").replace('/', "~1");
                unseal(field, format!("{at}/{key}"), found);
            }
        }
        _ => {}
    }
}

/// The latest signed version of `agent`'s `section` (its settings for `None`) in the repository at `remote`, read in the
/// tool's clone at `workdir` brought up to date, and verified against `trust`.
pub fn latest(
    remote: &str,
    workdir: &Path,
    config: &[(String, String)],
    agent: &str,
    section: Option<&str>,
    trust: &[String],
    now: i64,
) -> Result<Latest, String> {
    up_to_date(remote, workdir, config)?;
    let relative = place(agent, section);
    let Ok(text) = std::fs::read_to_string(workdir.join(&relative)) else {
        return Err(format!(
            "{relative} is not in the repository: nothing of {agent}'s {} is signed yet; start from `polar-sign template \
             {agent}{}`",
            section.unwrap_or("settings"),
            section.map(|s| format!(" {s}")).unwrap_or_default()
        ));
    };
    let (who, payload) = verify_source(&text, trust, now)
        .map_err(|e| format!("{relative} does not verify, so nothing is made from it: {e}"))?;
    Ok(Latest {
        payload,
        signer: who
            .username
            .or(who.identity)
            .unwrap_or_else(|| format!("certificate {}", who.serial)),
        commit: head(workdir, config)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;
    use crate::author::{Document, read_input};
    use crate::flow::{Signing, sign_file};
    use crate::push::{Plan, push};
    use crate::scaffold::Scaffold;
    use crate::split_pem;
    use polar_signing::testing::{EscrowSpec, Spec, escrow_certificate_for, now, root, signer};
    use rsa::pkcs8::EncodePublicKey;
    use std::process::Command;

    const AGENT: &str = "git-repo-observer";

    fn scaffold() -> Scaffold {
        Scaffold::parse(
            &json!({
                "agent": {"name": AGENT},
                "sections": [{"name": "b", "variables": [
                    {"name": "RUST_LOG", "type": "text", "mutability": "dynamic", "default": "info"}]}],
                "runtime": [
                    {"name": "credentials", "doc": "d", "body": {"credentials": {"list_of": {
                        "name": {"type": "text", "required": true},
                        "host_pattern": {"type": "host pattern", "required": true},
                        "kind": {"type": "token | user-password", "required": true},
                        "secret": {"type": "ciphertext", "required": true, "secret": true}
                    }}}},
                    {"name": "watch", "doc": "d", "body": {"repositories": {"list_of": {
                        "url": {"type": "https URL of a host name", "required": true}
                    }}}}
                ]
            })
            .to_string(),
        )
        .unwrap()
    }

    struct World {
        ca: polar_signing::testing::Authority,
        author: Identity,
        escrow_cert: String,
    }

    fn world() -> World {
        let ca = root("Polar Internal CA");
        let s = signer(
            &ca,
            Spec {
                capabilities: vec!["c:update-runtime", "c:update-configuration"],
                ..Spec::default()
            },
        );
        let private = rsa::RsaPrivateKey::new(&mut rand::rng(), 2048).unwrap();
        let public_pem = private
            .to_public_key()
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let escrow_cert = escrow_certificate_for(&ca, EscrowSpec::default(), &public_pem);
        World {
            author: Identity {
                chain: vec![s.cert_pem],
                key_pem: s.key_pem,
            },
            ca,
            escrow_cert,
        }
    }

    /// `text`, a file for `sign`, signed as alice: the Dhall file a push commits.
    fn signed(w: &World, text: &str) -> String {
        let how = Signing {
            identity: &w.author,
            trust_pem: std::slice::from_ref(&w.ca.pem),
            now: now(),
            escrow_identity: None,
        };
        let fetch = |_: &str| Ok(w.escrow_cert.clone());
        let mut no_stdin = || Err("no standard input".to_string());
        sign_file(text, &scaffold(), &how, &fetch, &mut no_stdin)
            .unwrap()
            .dhall
    }

    fn verified(w: &World, dhall: &str) -> Latest {
        let (who, payload) = verify_source(dhall, &split_pem(&w.ca.pem), now()).unwrap();
        Latest {
            payload,
            signer: who.username.unwrap_or_default(),
            commit: "1a2b3c4".into(),
        }
    }

    fn watch(version: u64) -> String {
        json!({"agent": AGENT, "section": "watch", "version": version, "id": "watch-0001",
               "body": {"repositories": [{"url": "https://github.com/o/r"}, {"url": "https://git.example.org/a/b"}]}})
        .to_string()
    }

    #[test]
    fn the_next_file_is_the_signed_version_with_its_version_raised_and_nothing_else() {
        let w = world();
        let latest = verified(&w, &signed(&w, &watch(4)));
        let file = file_for(AGENT, Some("watch"), &latest).unwrap();
        let input = read_input(&file).unwrap();
        let before = read_input(&watch(4)).unwrap();
        assert_eq!(input.agent, AGENT);
        assert_eq!(input.version, 5);
        assert_eq!(
            input.id.as_deref(),
            Some("watch-0001"),
            "the document's id is kept"
        );
        assert_eq!(input.document, before.document);
        assert!(
            file.contains("from version 4") && file.contains("alice") && file.contains("1a2b3c4"),
            "{file}"
        );
        assert!(
            file.contains("latest in the repository"),
            "not said to be what the agent applied: {file}"
        );
    }

    #[test]
    fn a_sealed_secret_is_not_carried_and_the_file_says_which_to_type_again() {
        let w = world();
        let credentials = json!({"agent": AGENT, "section": "credentials", "version": 2, "body": {"credentials": [
            {"name": "gitea", "host_pattern": "git.example.org", "kind": "token", "secret": "a-token-nowhere-else"}]}})
        .to_string();
        let dhall = signed(&w, &credentials);
        let file = file_for(AGENT, Some("credentials"), &verified(&w, &dhall)).unwrap();
        let input = read_input(&file).unwrap();
        let Document::Runtime { body, .. } = input.document else {
            panic!("a section");
        };
        assert_eq!(body["credentials"][0]["secret"], Value::Null, "{file}");
        assert_eq!(body["credentials"][0]["name"], "gitea");
        assert!(file.contains("/credentials/0/secret"), "{file}");
        let sealed = verify_source(&dhall, &split_pem(&w.ca.pem), now())
            .unwrap()
            .1["body"]["credentials"][0]["secret"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            !file.contains(&sealed),
            "version 2's ciphertext is not in version 3's file"
        );
        // And `sign` refuses it until the secret is typed again.
        assert!(
            sign_file(
                &file,
                &scaffold(),
                &Signing {
                    identity: &w.author,
                    trust_pem: std::slice::from_ref(&w.ca.pem),
                    now: now(),
                    escrow_identity: None,
                },
                &|_: &str| Ok(w.escrow_cert.clone()),
                &mut || Err("no standard input".to_string())
            )
            .is_err()
        );
    }

    #[test]
    fn settings_come_through_as_settings() {
        let w = world();
        let dhall = signed(
            &w,
            &json!({"agent": AGENT, "version": 2, "settings": {"RUST_LOG": "debug"}}).to_string(),
        );
        let file = file_for(AGENT, None, &verified(&w, &dhall)).unwrap();
        let input = read_input(&file).unwrap();
        assert_eq!(input.version, 3);
        assert_eq!(
            input.document,
            Document::Settings {
                settings: json!({"RUST_LOG": "debug"})
            }
        );
    }

    #[test]
    fn a_version_for_another_agent_or_section_is_refused() {
        let w = world();
        let latest = verified(&w, &signed(&w, &watch(4)));
        assert!(file_for("another-agent", Some("watch"), &latest).is_err());
        assert!(file_for(AGENT, Some("credentials"), &latest).is_err());
        assert!(file_for(AGENT, None, &latest).is_err());
    }

    #[test]
    fn what_the_file_cannot_hold_is_named_not_left_behind() {
        let w = world();
        let mut latest = verified(&w, &signed(&w, &watch(4)));
        latest.payload["target"]["versions"] = json!({"since": "3.1.0"});
        latest.payload["migrations"] = json!([{"id": "m1"}]);
        let file = file_for(AGENT, Some("watch"), &latest).unwrap();
        assert!(
            file.contains("target.versions") && file.contains("migrations"),
            "{file}"
        );
    }

    // -- from the repository --------------------------------------------------------------------------------------------

    fn config() -> Vec<(String, String)> {
        vec![
            ("commit.gpgsign".to_string(), "false".to_string()),
            ("core.hooksPath".to_string(), "/dev/null".to_string()),
            ("init.defaultBranch".to_string(), "main".to_string()),
        ]
    }

    /// A schedules repository holding `dhall` at the watch section's place.
    fn repository(dhall: &str) -> (tempfile::TempDir, String) {
        let root = tempfile::tempdir().unwrap();
        let bare = root.path().join("schedules.git");
        assert!(
            Command::new("git")
                .args(["init", "-q", "--bare", "--initial-branch=main"])
                .arg(&bare)
                .status()
                .unwrap()
                .success()
        );
        let remote = bare.to_string_lossy().to_string();
        let relative = place(AGENT, Some("watch"));
        let cfg = config();
        push(&Plan {
            remote: &remote,
            workdir: &root.path().join("author"),
            relative: &relative,
            content: dhall,
            message: "feat: watch",
            author_name: "alice",
            author_email: "alice@example.org",
            git_config: &cfg,
        })
        .unwrap();
        (root, remote)
    }

    #[test]
    fn the_latest_version_is_read_where_sign_puts_it_verified_and_its_commit_named() {
        let w = world();
        let (root, remote) = repository(&signed(&w, &watch(7)));
        let workdir = root.path().join("tool");
        let latest = latest(
            &remote,
            &workdir,
            &config(),
            AGENT,
            Some("watch"),
            &split_pem(&w.ca.pem),
            now(),
        )
        .unwrap();
        assert_eq!(latest.payload["version"], 7);
        assert_eq!(latest.signer, "alice");
        assert_eq!(latest.commit.len(), 7, "a short commit: {}", latest.commit);
        let missing = super::latest(
            &remote,
            &workdir,
            &config(),
            AGENT,
            Some("credentials"),
            &split_pem(&w.ca.pem),
            now(),
        )
        .unwrap_err();
        assert!(missing.contains("template"), "{missing}");
    }

    #[test]
    fn a_version_that_does_not_verify_gives_no_file() {
        let w = world();
        let other = root("Another CA");
        let (root_dir, remote) = repository(&signed(&w, &watch(7)));
        let workdir = root_dir.path().join("tool");
        assert!(
            latest(
                &remote,
                &workdir,
                &config(),
                AGENT,
                Some("watch"),
                &split_pem(&other.pem),
                now()
            )
            .is_err()
        );

        let edited = signed(&w, &watch(7)).replace("github.com", "evil.example");
        let (root_dir, remote) = repository(&edited);
        let workdir = root_dir.path().join("tool");
        assert!(
            latest(
                &remote,
                &workdir,
                &config(),
                AGENT,
                Some("watch"),
                &split_pem(&w.ca.pem),
                now()
            )
            .is_err()
        );
    }
}
