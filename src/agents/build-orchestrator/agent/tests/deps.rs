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

//! A build's crates brought into the registry (D2) through the real HTTP protocol handler: downloaded from a stand-in crates
//! host by name and version, checked against the sha256 the lock pins, pushed once to a stand-in registry (`common`), and kept
//! by an index and a manifest by the commit.

mod common;

use build_orchestrator::deps::{
    CRATE_TYPE, DOWNLOAD, HeldGit, INDEX_TYPE, crate_path, index, manifest, store,
};
use build_orchestrator::lock::{Crate, Dependencies};
use build_orchestrator::push::{PUSH, digest_of};
use build_orchestrator::settings::{CRATES_VAR, REGISTRY_VAR};
use common::{Crates, Registry, crates_host, registry};
use polar_agent_builder::protocol::OperationDecl;
use polar_agent_builder::protocol::testing::{Site, git_ca, http_handle};
use proptest::prelude::*;
use serde_json::Value;
use wiremock::MockServer;

const OPERATIONS: &[OperationDecl] = &[DOWNLOAD, PUSH];

struct Rig {
    _crates_server: MockServer,
    crates: Crates,
    _registry_server: MockServer,
    registry: Registry,
    site: Site,
}

async fn rig() -> Rig {
    let (crates_server, crates) = crates_host().await;
    let (registry_server, registry) = registry().await;
    let site = http_handle(
        &git_ca().pem,
        OPERATIONS,
        vec![
            (CRATES_VAR, crates_server.uri()),
            (REGISTRY_VAR, registry_server.uri()),
        ],
        None,
    )
    .await;
    Rig {
        _crates_server: crates_server,
        crates,
        _registry_server: registry_server,
        registry,
        site,
    }
}

/// A crate the host serves, as a lock pins it.
fn served(rig: &Rig, name: &str, version: &str, bytes: &[u8]) -> Crate {
    let c = Crate {
        name: name.into(),
        version: version.into(),
        sha256: digest_of(bytes)["sha256:".len()..].to_string(),
    };
    rig.crates
        .0
        .lock()
        .unwrap()
        .files
        .insert(crate_path(&c), bytes.to_vec());
    c
}

fn commit() -> String {
    "c0ffee".repeat(6) + "c0ff"
}

#[tokio::test]
async fn a_builds_crates_are_downloaded_checked_and_kept_by_their_lock_digests() {
    let rig = rig().await;
    let crates = vec![
        served(&rig, "serde", "1.0.219", b"serde's crate"),
        served(&rig, "rkyv", "0.8.10", b"rkyv's crate"),
    ];
    let dependencies = Dependencies {
        crates: crates.clone(),
        git: vec![],
    };
    let index_digest = store(&rig.site.handle, &commit(), &dependencies, &[], u64::MAX)
        .await
        .unwrap();
    let held = rig.registry.0.lock().unwrap();
    for c in &crates {
        assert!(
            held.blobs.contains_key(&format!("sha256:{}", c.sha256)),
            "{}",
            c.name
        );
    }
    let index_bytes = held.blobs.get(&index_digest).expect("the index");
    let read: Value = serde_json::from_slice(index_bytes).unwrap();
    assert_eq!(read["crates"].as_array().unwrap().len(), 2);
    let (_, body) = held
        .manifests
        .get(&format!("build-dependencies:{}", commit()))
        .expect("the manifest, by the commit");
    let manifest: Value = serde_json::from_slice(body).unwrap();
    let layers = manifest["layers"].as_array().unwrap();
    assert_eq!(layers[0]["mediaType"], INDEX_TYPE);
    assert_eq!(layers[0]["digest"], index_digest);
    assert_eq!(layers.len(), 3);
    assert!(layers[1..].iter().all(|l| l["mediaType"] == CRATE_TYPE));
}

#[tokio::test]
async fn a_crate_the_registry_holds_is_not_downloaded_again() {
    let rig = rig().await;
    let c = served(&rig, "serde", "1.0.219", b"serde's crate");
    let dependencies = Dependencies {
        crates: vec![c.clone()],
        git: vec![],
    };
    store(&rig.site.handle, &commit(), &dependencies, &[], u64::MAX)
        .await
        .unwrap();
    let asked = rig.crates.0.lock().unwrap().asked.len();
    assert_eq!(asked, 1);
    store(
        &rig.site.handle,
        &"d".repeat(40),
        &dependencies,
        &[],
        u64::MAX,
    )
    .await
    .unwrap();
    assert_eq!(
        rig.crates.0.lock().unwrap().asked.len(),
        asked,
        "held, so not downloaded"
    );
}

#[tokio::test]
async fn a_crate_that_is_not_what_the_lock_pins_is_refused_and_nothing_is_kept() {
    let rig = rig().await;
    let mut c = served(&rig, "serde", "1.0.219", b"serde's crate");
    c.sha256 = "a".repeat(64);
    let dependencies = Dependencies {
        crates: vec![c],
        git: vec![],
    };
    let why = store(&rig.site.handle, &commit(), &dependencies, &[], u64::MAX)
        .await
        .unwrap_err();
    assert!(
        why.contains("serde 1.0.219") && why.contains("not what the lock pins"),
        "{why}"
    );
    let held = rig.registry.0.lock().unwrap();
    assert!(held.manifests.is_empty());
    assert!(!held.blobs.contains_key(&digest_of(b"serde's crate")));
}

#[tokio::test]
async fn a_crate_the_host_does_not_have_is_named() {
    let rig = rig().await;
    let missing = Crate {
        name: "nowhere".into(),
        version: "0.1.0".into(),
        sha256: "b".repeat(64),
    };
    let dependencies = Dependencies {
        crates: vec![missing],
        git: vec![],
    };
    let why = store(&rig.site.handle, &commit(), &dependencies, &[], u64::MAX)
        .await
        .unwrap_err();
    assert!(
        why.contains("nowhere 0.1.0") && why.contains("404"),
        "{why}"
    );
}

#[tokio::test]
async fn dependencies_past_their_bound_are_refused_and_no_manifest_kept() {
    let rig = rig().await;
    let c = served(&rig, "serde", "1.0.219", b"twenty bytes of crate");
    let dependencies = Dependencies {
        crates: vec![c],
        git: vec![],
    };
    let why = store(&rig.site.handle, &commit(), &dependencies, &[], 10)
        .await
        .unwrap_err();
    assert!(why.contains("past their bound"), "{why}");
    assert!(rig.registry.0.lock().unwrap().manifests.is_empty());
}

fn crate_strategy() -> impl Strategy<Value = Crate> {
    ("[a-z]{1,8}", "[0-9]\\.[0-9]\\.[0-9]", "[0-9a-f]{64}").prop_map(|(name, version, sha256)| {
        Crate {
            name,
            version,
            sha256,
        }
    })
}

proptest! {
    /// The index and the manifest of any dependencies are the same bytes in any order, and the manifest names the index and
    /// every crate and git dependency, each once, by its digest and size.
    #[test]
    fn the_index_and_manifest_are_canonical_and_name_everything_once(
        crates in proptest::collection::vec(crate_strategy(), 0..12),
        sizes in proptest::collection::vec(1u64..1_000_000, 12),
        reversed in any::<bool>(),
    ) {
        let held: Vec<(String, u64)> = crates.iter().zip(&sizes).map(|(c, s)| (format!("sha256:{}", c.sha256), *s)).collect();
        let git = vec![HeldGit {
            git: build_orchestrator::lock::GitSource {
                source: "git+https://git.example.org/x".into(),
                url: "https://git.example.org/x".into(),
                commit: "1".repeat(40),
                packages: vec![("x".into(), "0.1.0".into())],
            },
            digest: format!("sha256:{}", "e".repeat(64)),
            size: 7,
        }];
        let (mut c2, mut h2) = (crates.clone(), held.clone());
        if reversed {
            c2.reverse();
            h2.reverse();
        }
        let one = index(&crates, &git);
        prop_assert_eq!(&index(&c2, &git), &one);
        let m = manifest(&one, &held, &git);
        prop_assert_eq!(&manifest(&one, &h2, &git), &m);
        let read: Value = serde_json::from_slice(&m).unwrap();
        let digests: Vec<String> = read["layers"].as_array().unwrap().iter().map(|l| l["digest"].as_str().unwrap().to_string()).collect();
        let mut expected: Vec<String> = held.iter().map(|(d, _)| d.clone()).collect();
        expected.sort();
        expected.dedup();
        prop_assert_eq!(&digests[0], &digest_of(&one));
        prop_assert_eq!(&digests[1..digests.len() - 1], &expected[..]);
        prop_assert_eq!(digests.last().unwrap(), &git[0].digest);
    }
}
