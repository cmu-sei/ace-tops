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

//! A build's source step (O3c) through the real protocols: a commit fetched by the git handler from a stand-in git server,
//! archived from the clone it brought up to date, and pushed by the HTTP handler to a stand-in registry (`common`); the build
//! is given the archive by its digest.

mod common;

use build_orchestrator::archive::archive;
use build_orchestrator::push::{PUSH, digest_of};
use build_orchestrator::settings::REGISTRY_VAR;
use build_orchestrator::source::{FETCH, FETCH_PUBLIC, GitSource, Source};
use common::{Registry, registry};
use git2::{Repository, Signature, Time};
use orchestrator_core::types::{SourceRef, source_env};
use polar_agent_builder::protocol::OperationDecl;
use polar_agent_builder::protocol::testing::{GitOrigin, git_and_http_handle, git_ca};
use std::sync::Arc;
use wiremock::MockServer;

const OPERATIONS: &[OperationDecl] = &[FETCH, FETCH_PUBLIC, PUSH];

struct Rig {
    _origin_dir: tempfile::TempDir,
    origin_repository: Repository,
    origin: GitOrigin,
    _clones: tempfile::TempDir,
    _registry_server: MockServer,
    registry: Registry,
    registry_url: String,
    source: Arc<GitSource>,
    commit: String,
}

/// A repository with one commit on main, served; a stand-in registry; and the source step over both.
async fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let repository = Repository::init_bare(dir.path()).unwrap();
    let commit = {
        let mut tree = repository.treebuilder(None).unwrap();
        tree.insert(
            "README",
            repository.blob(b"a repository\n").unwrap(),
            0o100644,
        )
        .unwrap();
        tree.insert(
            "build.sh",
            repository.blob(b"#!/bin/sh\n").unwrap(),
            0o100755,
        )
        .unwrap();
        let tree = repository.find_tree(tree.write().unwrap()).unwrap();
        let who =
            Signature::new("polar", "polar@example.org", &Time::new(1_800_000_000, 0)).unwrap();
        repository
            .commit(Some("refs/heads/main"), &who, &who, "first", &tree, &[])
            .unwrap()
            .to_string()
    };
    repository.set_head("refs/heads/main").unwrap();
    let origin = GitOrigin::serving(dir.path()).await;
    let (registry_server, registry) = registry().await;
    let registry_url = registry_server.uri();
    let site = git_and_http_handle(
        &git_ca().pem,
        OPERATIONS,
        vec![(REGISTRY_VAR, registry_url.clone())],
        None,
    )
    .await;
    let clones = tempfile::tempdir().unwrap();
    let source = Arc::new(GitSource::new(
        site.handle,
        clones.path(),
        registry_url.clone(),
    ));
    Rig {
        _origin_dir: dir,
        origin_repository: repository,
        origin,
        _clones: clones,
        _registry_server: registry_server,
        registry,
        registry_url,
        source,
        commit,
    }
}

fn git(rig: &Rig, commit: &str) -> SourceRef {
    SourceRef::Git {
        url: rig.origin.url(),
        commit_sha: commit.to_string(),
    }
}

#[tokio::test]
async fn a_commit_is_fetched_archived_and_pushed_and_the_build_given_it_by_digest() {
    let rig = rig().await;
    let pinned = rig
        .source
        .prepare(&git(&rig, &rig.commit), None, usize::MAX)
        .await
        .unwrap();
    // What the origin's own commit archives to: the same bytes, whatever clone they were read from.
    let expected = archive(&rig.origin_repository, &rig.commit, usize::MAX).unwrap();
    let digest = digest_of(&expected);
    let host = rig.registry_url.strip_prefix("http://").unwrap();
    assert_eq!(pinned.reference(), format!("{host}/build-sources@{digest}"));
    assert_eq!(pinned.sha256(), &digest["sha256:".len()..]);
    let held = rig.registry.0.lock().unwrap();
    assert_eq!(held.blobs.get(&digest), Some(&expected));
    assert!(
        held.manifests
            .contains_key(&format!("build-sources:{}", rig.commit)),
        "the manifest, by the commit"
    );
    // The registry is plain http, and the fetch is told so.
    assert!(pinned.fetch_env().contains(&(
        source_env::REGISTRY_INSECURE.to_string(),
        "true".to_string()
    )));
}

#[tokio::test]
async fn a_commit_the_repository_does_not_have_pushes_nothing() {
    let rig = rig().await;
    let missing = "0123456789abcdef0123456789abcdef01234567";
    let why = rig
        .source
        .prepare(&git(&rig, missing), None, usize::MAX)
        .await
        .unwrap_err();
    assert!(
        why.contains("could not be archived") && why.contains("no commit"),
        "{why}"
    );
    assert!(rig.registry.0.lock().unwrap().asked.is_empty());
}

#[tokio::test]
async fn a_source_past_its_bound_pushes_nothing() {
    let rig = rig().await;
    let why = rig
        .source
        .prepare(&git(&rig, &rig.commit), None, 16)
        .await
        .unwrap_err();
    assert!(why.contains("larger than its bound"), "{why}");
    assert!(rig.registry.0.lock().unwrap().asked.is_empty());
}

#[tokio::test]
async fn two_builds_of_one_repository_at_once_each_get_their_source() {
    let rig = rig().await;
    let source = git(&rig, &rig.commit);
    let (one, two) = tokio::join!(
        rig.source.prepare(&source, None, usize::MAX),
        rig.source.prepare(&source, None, usize::MAX),
    );
    assert_eq!(one.unwrap(), two.unwrap());
}

#[tokio::test]
async fn a_mapping_that_names_a_credential_the_agent_does_not_hold_is_not_fetched_without_it() {
    let rig = rig().await;
    let why = rig
        .source
        .prepare(&git(&rig, &rig.commit), Some("git-a"), usize::MAX)
        .await
        .unwrap_err();
    assert!(why.contains("could not be fetched"), "{why}");
    assert!(rig.registry.0.lock().unwrap().asked.is_empty());
}

#[tokio::test]
async fn only_a_git_repositorys_source_is_fetched() {
    let rig = rig().await;
    let archive = SourceRef::RegistryArchive {
        purl: "pkg:cargo/x@1".into(),
        download_url: "https://static.example/x.crate".into(),
        sha256: "a".repeat(64),
    };
    assert!(
        rig.source
            .prepare(&archive, None, usize::MAX)
            .await
            .is_err()
    );
}
