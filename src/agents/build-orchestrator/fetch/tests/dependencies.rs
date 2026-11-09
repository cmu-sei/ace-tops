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

//! A build's dependencies laid out by the fetch (D3b), from a stand-in registry serving blobs by digest: crates in their own
//! directories with their checksum files, git repositories beside them, and Cargo's source replacement; and what the index
//! may not say, refused.

use build_fetch::FetchError;
use build_fetch::dependencies::{Laid, lay_out};
use sha2::{Digest, Sha256};
use std::path::Path;
use wiremock::matchers::path;
use wiremock::{Mock, MockServer, ResponseTemplate};

fn hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// A gzipped tar of `files`, each `(path, contents)`.
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

/// A stand-in registry serving each of `blobs` at its digest.
async fn registry(blobs: &[&[u8]]) -> MockServer {
    let server = MockServer::start().await;
    for blob in blobs {
        Mock::given(path(format!(
            "/v2/build-dependencies/blobs/sha256:{}",
            hex(blob)
        )))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(blob.to_vec()))
        .mount(&server)
        .await;
    }
    server
}

fn host(server: &MockServer) -> String {
    server.uri().strip_prefix("http://").unwrap().to_string()
}

fn index_ref(server: &MockServer, index: &[u8]) -> String {
    format!("{}/build-dependencies@sha256:{}", host(server), hex(index))
}

async fn laid(index: &serde_json::Value, blobs: &[&[u8]], root: &Path) -> Result<Laid, FetchError> {
    let index = serde_json::to_vec(index).unwrap();
    let mut all: Vec<&[u8]> = blobs.to_vec();
    all.push(&index);
    let server = registry(&all).await;
    lay_out(
        &reqwest::Client::new(),
        Some(&index_ref(&server, &index)),
        true,
        root,
    )
    .await
}

#[tokio::test]
async fn crates_and_git_dependencies_are_laid_out_for_cargo() {
    let crate_bytes = tar_gz(&[
        ("tiny-0.1.0/Cargo.toml", b"[package]\nname = \"tiny\"\n"),
        ("tiny-0.1.0/src/lib.rs", b""),
    ]);
    let repo_bytes = tar_gz(&[("HEAD", b"ref: refs/heads/polar\n"), ("shallow", b"x\n")]);
    let index = serde_json::json!({
        "crates": [{"name": "tiny", "version": "0.1.0", "sha256": hex(&crate_bytes)}],
        "git": [{"source": "git+https://git.example.org/dep?branch=main", "url": "https://git.example.org/dep",
                 "commit": "1".repeat(40), "packages": [["dep", "0.1.0"]], "digest": format!("sha256:{}", hex(&repo_bytes))}],
    });
    let root = tempfile::tempdir().unwrap();
    let laid = laid(&index, &[&crate_bytes, &repo_bytes], root.path())
        .await
        .unwrap();
    assert_eq!(laid, Laid { crates: 1, git: 1 });
    let vendored = root.path().join("vendor/tiny-0.1.0");
    assert!(vendored.join("Cargo.toml").exists());
    assert_eq!(
        std::fs::read_to_string(vendored.join(".cargo-checksum.json")).unwrap(),
        format!("{{\"files\":{{}},\"package\":\"{}\"}}", hex(&crate_bytes))
    );
    assert!(root.path().join("git/0.git/HEAD").exists());
    let config = std::fs::read_to_string(root.path().join("cargo/config.toml")).unwrap();
    for line in [
        "[source.crates-io]\nreplace-with = \"polar-vendored\"".to_string(),
        format!("directory = \"{}\"", root.path().join("vendor").display()),
        "[source.\"git+https://git.example.org/dep?branch=main\"]\ngit = \"https://git.example.org/dep\"\nbranch = \"main\"\nreplace-with = \"polar-git-0\"".to_string(),
        format!("[source.polar-git-0]\ngit = \"file://{}\"", root.path().join("git/0.git").display()),
    ] {
        assert!(config.contains(&line), "{line}\n--- in ---\n{config}");
    }
}

#[tokio::test]
async fn a_build_given_no_dependencies_has_none_to_reach() {
    let root = tempfile::tempdir().unwrap();
    let laid = lay_out(&reqwest::Client::new(), None, true, root.path())
        .await
        .unwrap();
    assert_eq!(laid, Laid::default());
    let config = std::fs::read_to_string(root.path().join("cargo/config.toml")).unwrap();
    assert!(config.contains("[source.crates-io]\nreplace-with = \"polar-vendored\""));
    assert_eq!(
        std::fs::read_dir(root.path().join("vendor"))
            .unwrap()
            .count(),
        0
    );
}

#[tokio::test]
async fn a_crate_that_reaches_beyond_its_own_directory_is_refused() {
    let crate_bytes = tar_gz(&[
        ("tiny-0.1.0/Cargo.toml", b""),
        ("other-0.1.0/Cargo.toml", b""),
    ]);
    let index = serde_json::json!({"crates": [{"name": "tiny", "version": "0.1.0", "sha256": hex(&crate_bytes)}], "git": []});
    let root = tempfile::tempdir().unwrap();
    assert!(matches!(
        laid(&index, &[&crate_bytes], root.path()).await,
        Err(FetchError::Escapes(_))
    ));
    assert!(!root.path().join("vendor/other-0.1.0").exists());
}

#[tokio::test]
async fn what_the_index_may_not_say_is_refused() {
    let repo = tar_gz(&[("HEAD", b"")]);
    let digest = format!("sha256:{}", hex(&repo));
    let git = |source: &str, url: &str| {
        serde_json::json!({"crates": [], "git": [{"source": source, "url": url,
        "commit": "1".repeat(40), "packages": [], "digest": digest}]})
    };
    for (index, why) in [
        (
            serde_json::json!({"crates": [{"name": "../x", "version": "1", "sha256": "a".repeat(64)}], "git": []}),
            "not named",
        ),
        (
            serde_json::json!({"crates": [{"name": "x", "version": "..", "sha256": "a".repeat(64)}], "git": []}),
            "not named",
        ),
        (
            serde_json::json!({"crates": [{"name": "x", "version": "1", "sha256": "A".repeat(64)}], "git": []}),
            "not named",
        ),
        (
            serde_json::json!({"crates": [], "git": [], "more": 1}),
            "not one",
        ),
        (
            git(
                "git+https://g.example/d?branch=main&x=1",
                "https://g.example/d",
            ),
            "more than",
        ),
        (
            git("git+https://g.example/d?path=x", "https://g.example/d"),
            "more than",
        ),
        (git("git+http://g.example/d", "http://g.example/d"), "https"),
        (
            git("git+https://u@g.example/d", "https://u@g.example/d"),
            "https",
        ),
        (
            git("git+https://g.example/d", "https://g.example/e"),
            "do not agree",
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        match laid(&index, &[&repo], root.path()).await {
            Err(FetchError::Dependencies(said)) => assert!(said.contains(why), "{why}: {said}"),
            other => panic!("{why}: {other:?}"),
        }
    }
}

#[tokio::test]
async fn an_index_that_is_not_its_digest_is_refused() {
    let index = serde_json::to_vec(&serde_json::json!({"crates": [], "git": []})).unwrap();
    let server = MockServer::start().await;
    Mock::given(path(format!(
        "/v2/build-dependencies/blobs/sha256:{}",
        hex(&index)
    )))
    .respond_with(
        ResponseTemplate::new(200)
            .set_body_bytes(b"{\"crates\": [], \"git\": [], \"x\": 0}".to_vec()),
    )
    .mount(&server)
    .await;
    let root = tempfile::tempdir().unwrap();
    let refused = lay_out(
        &reqwest::Client::new(),
        Some(&index_ref(&server, &index)),
        true,
        root.path(),
    )
    .await;
    assert!(
        matches!(refused, Err(FetchError::WrongDigest { .. })),
        "{refused:?}"
    );
}
