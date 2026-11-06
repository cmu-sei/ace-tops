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

//! What `polar-running-config` says before it reaches for the broker: nothing here needs one.

use std::process::{Command, Output};

fn run(dir: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_polar-running-config"))
        .args(args)
        .args(["--dir", dir.to_str().unwrap()])
        .env_clear()
        .output()
        .expect("run polar-running-config")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

#[test]
fn a_scaffold_means_nothing_without_a_template() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(
        dir.path(),
        &["jira-observer", "--user", "alice", "--scaffold", "/s.json"],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("--template"), "{}", stderr(&out));
}

#[test]
fn with_no_scaffold_a_template_says_how_to_get_one_before_asking() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(
        dir.path(),
        &["jira-observer", "--user", "alice", "--template"],
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("nu infra/resolve.nu scaffolds"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn with_no_certificate_it_says_how_to_get_one() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(dir.path(), &["jira-observer", "--user", "alice"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("just admin-claim"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn with_no_user_and_no_environment_it_asks_whose() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(dir.path(), &["jira-observer"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("--user"), "{}", stderr(&out));
}
