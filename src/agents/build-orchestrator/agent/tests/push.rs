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

//! A build's source pushed through the real HTTP protocol handler to a stand-in registry that behaves as distribution's does
//! (`common`).

mod common;

use build_orchestrator::push::{ARCHIVE_TYPE, ARTIFACT_TYPE, PUSH, digest_of, push};
use build_orchestrator::settings::REGISTRY_VAR;
use common::{Registry, registry};
use polar_agent_builder::protocol::OperationDecl;
use polar_agent_builder::protocol::testing::{Site, git_ca, http_handle};
use serde_json::Value;
use wiremock::MockServer;

const OPERATIONS: &[OperationDecl] = &[PUSH];

async fn stand_in() -> (MockServer, Registry, Site) {
    let (server, registry) = registry().await;
    let site = http_handle(
        &git_ca().pem,
        OPERATIONS,
        vec![(REGISTRY_VAR, server.uri())],
        None,
    )
    .await;
    (server, registry, site)
}

fn commit() -> String {
    "c0ffee".repeat(6) + "c0ff"
}

#[tokio::test]
async fn a_source_is_its_blob_and_a_manifest_tagged_by_its_commit() {
    let (_server, registry, site) = stand_in().await;
    let archive = b"a gzipped tar, as far as the registry knows".to_vec();
    let digest = push(&site.handle, &commit(), &archive).await.unwrap();
    assert_eq!(digest, digest_of(&archive));
    let held = registry.0.lock().unwrap();
    assert_eq!(held.blobs.get(&digest), Some(&archive));
    assert_eq!(
        held.blobs.get(&digest_of(b"{}")).map(Vec::as_slice),
        Some(b"{}".as_slice())
    );
    let (kind, body) = held
        .manifests
        .get(&commit())
        .expect("a manifest by the commit");
    assert_eq!(kind, "application/vnd.oci.image.manifest.v1+json");
    let manifest: Value = serde_json::from_slice(body).unwrap();
    assert_eq!(manifest["artifactType"], ARTIFACT_TYPE);
    assert_eq!(manifest["config"]["digest"], digest_of(b"{}"));
    assert_eq!(manifest["layers"].as_array().unwrap().len(), 1);
    assert_eq!(manifest["layers"][0]["digest"], digest);
    assert_eq!(manifest["layers"][0]["size"], archive.len());
    assert_eq!(manifest["layers"][0]["mediaType"], ARCHIVE_TYPE);
    // The blobs before the manifest, so it never names what is not there.
    let last_blob = held
        .asked
        .iter()
        .rposition(|a| a.contains("/blobs/"))
        .unwrap();
    let manifest_at = held
        .asked
        .iter()
        .position(|a| a.contains("/manifests/"))
        .unwrap();
    assert!(last_blob < manifest_at, "{:?}", held.asked);
}

#[tokio::test]
async fn the_upload_goes_on_at_the_configured_host_whatever_location_names() {
    let (_server, registry, site) = stand_in().await;
    push(&site.handle, &commit(), b"archive").await.unwrap();
    // The stand-in names elsewhere.invalid; had the request gone there, it would not have reached the stand-in.
    assert!(
        registry
            .0
            .lock()
            .unwrap()
            .asked
            .iter()
            .any(|a| a.starts_with("PUT /v2/build-sources/blobs/uploads/"))
    );
    let records = site.records.lock().unwrap();
    assert!(!records.is_empty());
    for record in records.iter() {
        assert_eq!(record.operation, PUSH.name);
        assert_eq!(record.verdict, "allowed", "{record:?}");
    }
}

#[tokio::test]
async fn an_unchanged_source_sends_no_blob_again() {
    let (_server, registry, site) = stand_in().await;
    let archive = b"the same commit's archive".to_vec();
    push(&site.handle, &commit(), &archive).await.unwrap();
    let uploads = registry.0.lock().unwrap().uploads;
    assert_eq!(uploads, 2, "the archive and the empty config");
    push(&site.handle, &commit(), &archive).await.unwrap();
    assert_eq!(
        registry.0.lock().unwrap().uploads,
        uploads,
        "nothing opened again"
    );
}

#[tokio::test]
async fn a_blob_the_registry_refuses_leaves_no_manifest() {
    let (_server, registry, site) = stand_in().await;
    registry.0.lock().unwrap().refusing = true;
    let why = push(&site.handle, &commit(), b"archive").await.unwrap_err();
    assert!(
        why.contains("sending the archive") && why.contains("400"),
        "{why}"
    );
    assert!(registry.0.lock().unwrap().manifests.is_empty());
}

#[tokio::test]
async fn a_tag_a_registry_refuses_sends_nothing() {
    let (_server, registry, site) = stand_in().await;
    assert!(push(&site.handle, "not/a/tag", b"archive").await.is_err());
    assert!(registry.0.lock().unwrap().asked.is_empty());
}
