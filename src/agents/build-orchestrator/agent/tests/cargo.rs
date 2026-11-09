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

//! A build's dependencies end to end (D3c): what the orchestrator makes of them (a vendored crate by the digest its lock pins,
//! a git dependency as a shallow repository of its commit, the index of both) served by a stand-in registry, laid out by the
//! fetch's own `lay_out` as the build's pod lays them out, and the test's own Cargo building a project that depends on both,
//! `--locked`, with the Cargo home the fetch wrote. The git dependency is a member of its own workspace whose `Cargo.toml`
//! inherits from it, which Cargo resolves for itself; and its source names a host under `.invalid`, so a build that reached
//! for it would fail: what Cargo builds from is only what was laid out.

mod common;

use build_orchestrator::deps::{self, HeldGit};
use build_orchestrator::lock::{Crate, GitSource};
use build_orchestrator::push::digest_of;
use build_orchestrator::shallow;
use common::registry;
use git2::{Repository, Signature, Time};
use std::path::Path;
use std::process::Command;

const DEPENDENCY_URL: &str = "https://git.example.invalid/dep";

/// A gzipped tar of `files`.
fn tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    for (path, bytes) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        tar.append_data(&mut header, path, *bytes).unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap()
}

/// A repository whose one commit is a workspace with one member, `dep`, inheriting its version and edition.
fn dependency(dir: &Path) -> (Repository, String) {
    let repository = Repository::init_bare(dir).unwrap();
    let commit = commit_of(&repository);
    (repository, commit)
}

fn commit_of(repository: &Repository) -> String {
    let blob = |bytes: &[u8]| repository.blob(bytes).unwrap();
    let mut src = repository.treebuilder(None).unwrap();
    src.insert("lib.rs", blob(b"pub fn dep() -> u8 { 7 }\n"), 0o100644)
        .unwrap();
    let mut member = repository.treebuilder(None).unwrap();
    member
        .insert(
            "Cargo.toml",
            blob(
                b"[package]\nname = \"dep\"\nversion.workspace = true\nedition.workspace = true\n",
            ),
            0o100644,
        )
        .unwrap();
    member
        .insert("src", src.write().unwrap(), 0o040000)
        .unwrap();
    let mut root = repository.treebuilder(None).unwrap();
    root.insert(
        "Cargo.toml",
        blob(b"[workspace]\nmembers = [\"dep\"]\nresolver = \"2\"\n\n[workspace.package]\nversion = \"0.3.0\"\nedition = \"2021\"\n"),
        0o100644,
    )
    .unwrap();
    root.insert("dep", member.write().unwrap(), 0o040000)
        .unwrap();
    let tree = repository.find_tree(root.write().unwrap()).unwrap();
    let who = Signature::new("polar", "polar@example.org", &Time::new(1_800_000_000, 0)).unwrap();
    repository
        .commit(None, &who, &who, "a dependency", &tree, &[])
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn a_project_builds_from_its_dependencies_as_the_pod_lays_them_out() {
    let work = tempfile::tempdir().unwrap();
    // The dependencies, as the orchestrator makes them.
    let (dependency_repository, commit) = dependency(&work.path().join("dep.git"));
    let repository = shallow::repository(&dependency_repository, &commit, usize::MAX).unwrap();
    let crate_bytes = tar_gz(&[
        (
            "tiny-0.1.0/Cargo.toml",
            b"[package]\nname = \"tiny\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        ("tiny-0.1.0/src/lib.rs", b"pub fn tiny() -> u8 { 1 }\n"),
    ]);
    let tiny = Crate {
        name: "tiny".into(),
        version: "0.1.0".into(),
        sha256: digest_of(&crate_bytes)["sha256:".len()..].to_string(),
    };
    let git = HeldGit {
        git: GitSource {
            source: format!("git+{DEPENDENCY_URL}"),
            url: DEPENDENCY_URL.into(),
            commit: commit.clone(),
            packages: vec![("dep".into(), "0.3.0".into())],
        },
        digest: digest_of(&repository),
        size: repository.len() as u64,
    };
    let index = deps::index(std::slice::from_ref(&tiny), std::slice::from_ref(&git));
    // Served by a stand-in registry, by digest.
    let (server, held) = registry().await;
    for blob in [&crate_bytes, &repository, &index] {
        held.0
            .lock()
            .unwrap()
            .blobs
            .insert(digest_of(blob), blob.clone());
    }
    // Laid out by the fetch, as in the build's pod.
    let root = work.path().join("dependencies");
    let host = server.uri().strip_prefix("http://").unwrap().to_string();
    let index_reference = format!("{host}/build-dependencies@{}", digest_of(&index));
    let laid = build_fetch::dependencies::lay_out(
        &reqwest::Client::new(),
        Some(&index_reference),
        true,
        &root,
    )
    .await
    .unwrap();
    assert_eq!((laid.crates, laid.git), (1, 1));
    // A project that depends on both, its lock as the upstream repository would have it.
    let app = work.path().join("app");
    std::fs::create_dir_all(app.join("src")).unwrap();
    std::fs::write(
        app.join("Cargo.toml"),
        format!(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ntiny = \"0.1.0\"\n\
             dep = {{ git = \"{DEPENDENCY_URL}\" }}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        app.join("src/main.rs"),
        "fn main() { println!(\"{}\", tiny::tiny() + dep::dep()); }\n",
    )
    .unwrap();
    std::fs::write(
        app.join("Cargo.lock"),
        format!(
            "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n\
             [[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"dep\",\n \"tiny\",\n]\n\n\
             [[package]]\nname = \"dep\"\nversion = \"0.3.0\"\nsource = \"git+{DEPENDENCY_URL}#{commit}\"\n\n\
             [[package]]\nname = \"tiny\"\nversion = \"0.1.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"{}\"\n",
            tiny.sha256
        ),
    )
    .unwrap();
    let target = work.path().join("target");
    let built = Command::new(env!("CARGO"))
        .args(["build", "--locked", "--quiet"])
        .current_dir(&app)
        .env("CARGO_HOME", root.join("cargo"))
        .env("CARGO_TARGET_DIR", &target)
        .env_remove("RUSTC_WRAPPER")
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let ran = Command::new(target.join("debug/app")).output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&ran.stdout).trim(),
        "8",
        "tiny's 1 and dep's 7"
    );
}
