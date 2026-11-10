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

//! What `polar-sign runtime` and `configuration` do with a secret: judged by the agent's scaffold, as `sign` judges, a
//! plaintext secret is refused by field and never signed, and neither it nor a mistyped change is ever printed. Each
//! case is refused before a certificate is read, so none needs one.

use std::process::{Command, Output};

const SECRET: &str = "hunter2-never-printed";

/// A folder with a scaffold for git-repo-observer: a credentials section whose `secret` is one, and a secret setting.
fn folder() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("scaffolds")).unwrap();
    let scaffold = serde_json::json!({
        "agent": {"name": "git-repo-observer"},
        "sections": [{"name": "b", "variables": [
            {"name": "RUST_LOG", "type": "text", "mutability": "dynamic", "default": "info"},
            {"name": "TOKEN", "type": "text", "mutability": "dynamic", "secret": true}
        ]}],
        "runtime": [{"name": "credentials", "doc": "d", "body": {
            "credentials": {"list_of": {
                "name": {"type": "text", "required": true},
                "secret": {"type": "ciphertext", "required": true, "secret": true}
            }}
        }}]
    });
    std::fs::write(
        dir.path().join("scaffolds/git-repo-observer.json"),
        scaffold.to_string(),
    )
    .unwrap();
    dir
}

fn run(dir: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_polar-sign"))
        .args(args)
        .args(["--user", "alice", "--dir", dir.to_str().unwrap()])
        .env_clear()
        .output()
        .expect("run polar-sign")
}

/// Refused, nothing on standard output, and the secret in neither stream. Gives standard error.
fn refused_without_the_secret(out: &Output) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(!out.status.success(), "signed: {stdout}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(!stderr.contains(SECRET), "{stderr}");
    assert!(!stderr.contains("hunter2"), "{stderr}");
    stderr
}

fn body() -> String {
    format!(r#"{{"credentials": [{{"name": "gh", "secret": "{SECRET}"}}]}}"#)
}

#[test]
fn a_runtime_body_holding_a_plaintext_secret_is_refused_and_never_printed() {
    let dir = folder();
    let body = body();
    let out = run(
        dir.path(),
        &[
            "runtime",
            "--agent",
            "git-repo-observer",
            "--section",
            "credentials",
            "--version",
            "1",
            "--body",
            &body,
        ],
    );
    let stderr = refused_without_the_secret(&out);
    assert!(stderr.contains("credentials[0].secret"), "{stderr}");
    assert!(stderr.contains("polar-sign sign"), "{stderr}");
}

#[test]
fn a_runtime_body_is_never_signed_without_the_agent_s_scaffold() {
    let dir = tempfile::tempdir().unwrap();
    let body = body();
    let out = run(
        dir.path(),
        &[
            "runtime",
            "--agent",
            "git-repo-observer",
            "--section",
            "credentials",
            "--version",
            "1",
            "--body",
            &body,
        ],
    );
    let stderr = refused_without_the_secret(&out);
    assert!(
        stderr.contains("cannot read the scaffold of git-repo-observer"),
        "{stderr}"
    );
}

#[test]
fn a_secret_setting_is_refused_and_never_printed() {
    let dir = folder();
    let set = format!("TOKEN={SECRET}");
    let out = run(
        dir.path(),
        &[
            "configuration",
            "--agent",
            "git-repo-observer",
            "--version",
            "1",
            "--set",
            &set,
        ],
    );
    let stderr = refused_without_the_secret(&out);
    assert!(stderr.contains("`TOKEN` is a secret setting"), "{stderr}");

    let none = tempfile::tempdir().unwrap();
    let out = run(
        none.path(),
        &[
            "configuration",
            "--agent",
            "git-repo-observer",
            "--version",
            "1",
            "--set",
            &set,
        ],
    );
    let stderr = refused_without_the_secret(&out);
    assert!(
        stderr.contains("cannot read the scaffold of git-repo-observer"),
        "{stderr}"
    );
}

#[test]
fn a_mistyped_change_is_never_repeated() {
    let dir = folder();
    for mistyped in [format!("={SECRET}"), SECRET.to_string()] {
        let out = run(
            dir.path(),
            &[
                "configuration",
                "--agent",
                "git-repo-observer",
                "--version",
                "1",
                "--set",
                &mistyped,
            ],
        );
        let stderr = refused_without_the_secret(&out);
        assert!(stderr.contains("NAME=VALUE"), "{stderr}");
    }
}
