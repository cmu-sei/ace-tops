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

//! `polar-sign projection test` as a person runs it: the files where the tool looks for them, the record on standard
//! output or pushed to an evidence repository, and `polar-sign verify --evidence` reading it back.

use polar_signing::testing::{Spec, root, signer};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const TOOL: &str = env!("CARGO_BIN_EXE_polar-sign");

fn examples() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../polar-projection/examples")
}

/// A user's folder as `just admin-claim` leaves it, with the agent's scaffold where `resolve.nu scaffolds` puts it, and
/// a copy of the example mapping and its samples.
struct Desk {
    root: tempfile::TempDir,
}

impl Desk {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("admin");
        std::fs::create_dir_all(dir.join("scaffolds")).unwrap();
        let ca = root_ca();
        let alice = signer(&ca, Spec::default());
        std::fs::write(dir.join("ca.pem"), &ca.pem).unwrap();
        std::fs::write(dir.join("alice.crt"), &alice.cert_pem).unwrap();
        std::fs::write(dir.join("alice.key"), &alice.key_pem).unwrap();
        let scaffold = json!({
            "agent": {"name": "openapi-processor"},
            "runtime": [{"name": "projection", "doc": "d", "body": {}}],
            "graph": [
                {"label": "OpenApiApplication", "access": "owns", "purpose": "p", "keys": [["source"]]},
                {"label": "OpenApiEndpoint", "access": "owns", "purpose": "p", "keys": [["source", "method", "path"]]}
            ],
            "graph_edges": [{"from": "OpenApiApplication", "kind": "HAS_ENDPOINT", "to": "OpenApiEndpoint", "purpose": "p"}]
        });
        std::fs::write(
            dir.join("scaffolds/openapi-processor.json"),
            scaffold.to_string(),
        )
        .unwrap();
        let work = root.path().join("work");
        std::fs::create_dir_all(work.join("openapi")).unwrap();
        std::fs::copy(examples().join("openapi.dhall"), work.join("openapi.dhall")).unwrap();
        for entry in std::fs::read_dir(examples().join("openapi")).unwrap() {
            let path = entry.unwrap().path();
            std::fs::copy(&path, work.join("openapi").join(path.file_name().unwrap())).unwrap();
        }
        Desk { root }
    }

    fn dir(&self) -> PathBuf {
        self.root.path().join("admin")
    }

    fn work(&self) -> PathBuf {
        self.root.path().join("work")
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(TOOL)
            .args(args)
            .arg("--dir")
            .arg(self.dir())
            .env_remove("POLAR_EVIDENCE_URL")
            .output()
            .unwrap()
    }

    fn test(&self, more: &[&str]) -> Output {
        let mapping = self.work().join("openapi.dhall");
        let mut args = vec![
            "projection",
            "test",
            mapping.to_str().unwrap(),
            "--agent",
            "openapi-processor",
            "--section",
            "projection",
        ];
        args.extend_from_slice(more);
        self.run(&args)
    }
}

fn root_ca() -> polar_signing::testing::Authority {
    root("Polar Internal CA")
}

fn text(out: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn a_mapping_that_passes_prints_a_record_that_verifies_as_evidence() {
    let desk = Desk::new();
    let out = desk.test(&["--user", "alice"]);
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "{stderr}");
    let record: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(record["payload"]["result"]["passed"], true);
    assert_eq!(record["payload"]["mapping"]["file"], "openapi.dhall");

    let file = desk.root.path().join("record.json");
    std::fs::write(&file, &stdout).unwrap();
    let verified = desk.run(&["verify", "--evidence", file.to_str().unwrap()]);
    let (said, stderr) = text(&verified);
    assert!(verified.status.success(), "{stderr}");
    assert!(
        said.contains("projection-test of openapi-processor's projection mapping"),
        "{said}"
    );
    assert!(said.contains(": passed"), "{said}");
    // It is not a configuration document.
    let as_configuration = desk.run(&["verify", file.to_str().unwrap()]);
    assert!(!as_configuration.status.success());
}

#[test]
fn a_mapping_that_fails_still_writes_its_record_and_the_tool_fails() {
    let desk = Desk::new();
    std::fs::remove_file(desk.work().join("openapi/no-paths.expected.json")).unwrap();
    let record = desk.root.path().join("record.json");
    let out = desk.test(&["--user", "alice", "--out", record.to_str().unwrap()]);
    let (_, stderr) = text(&out);
    assert!(!out.status.success());
    assert!(
        stderr.contains("`no-paths` has nothing beside it"),
        "{stderr}"
    );
    assert!(
        stderr.contains("1 problem(s), and the record says so"),
        "{stderr}"
    );
    let written: Value = serde_json::from_str(&std::fs::read_to_string(&record).unwrap()).unwrap();
    assert_eq!(written["payload"]["result"]["passed"], false);

    // Blessing writes what is missing, and then it passes.
    let blessed = desk.test(&["--bless"]);
    assert!(blessed.status.success(), "{}", text(&blessed).1);
    assert!(desk.work().join("openapi/no-paths.expected.json").exists());
    assert!(desk.test(&["--user", "alice"]).status.success());
}

fn bare(at: &Path) -> String {
    let status = Command::new("git")
        .args(["init", "-q", "--bare", "--initial-branch=main"])
        .arg(at)
        .status()
        .unwrap();
    assert!(status.success());
    at.to_string_lossy().to_string()
}

fn files_in(repo: &str) -> Vec<String> {
    let out = Command::new("git")
        .args(["--git-dir", repo, "ls-tree", "-r", "--name-only", "main"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn each_record_pushed_is_a_new_file_in_the_evidence_repository() {
    let desk = Desk::new();
    let repo = bare(&desk.root.path().join("evidence.git"));
    let workdir = desk.root.path().join("clone");
    let push = |desk: &Desk| {
        desk.test(&[
            "--user",
            "alice",
            "--push",
            "--repo",
            &repo,
            "--workdir",
            workdir.to_str().unwrap(),
            // A developer's global git settings (commit signing, hooks) must not decide this test.
            "--git-config",
            "commit.gpgsign=false",
            "--git-config",
            "core.hooksPath=/dev/null",
        ])
    };
    let first = push(&desk);
    assert!(first.status.success(), "{}", text(&first).1);
    // A second run is a second record, made at another time, beside the first.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let second = push(&desk);
    assert!(second.status.success(), "{}", text(&second).1);
    let files = files_in(&repo);
    assert_eq!(files.len(), 2, "{files:?}");
    for file in &files {
        assert!(
            file.starts_with("projection-test/openapi-processor/projection/")
                && file.ends_with(".json"),
            "{file}"
        );
    }
    let log = Command::new("git")
        .args(["--git-dir", &repo, "log", "--format=%s", "main"])
        .output()
        .unwrap();
    let subjects = String::from_utf8_lossy(&log.stdout);
    assert!(
        subjects
            .lines()
            .all(|s| s == "test(openapi-processor): the projection mapping passes its 5 sample(s)"),
        "{subjects}"
    );
}
