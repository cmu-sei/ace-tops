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

//! A build's log kept through the real HTTP protocol handler in a stand-in registry that behaves as distribution's does
//! (`common`): its blob, and a manifest tagged by the build's id, in `build-logs`.

mod common;

use build_orchestrator::logs::{ARTIFACT_TYPE, KeepLog, LOG_TYPE, REPOSITORY, RegistryLogs};
use build_orchestrator::push::{PUSH, digest_of};
use build_orchestrator::settings::REGISTRY_VAR;
use common::registry;
use polar_agent_builder::protocol::OperationDecl;
use polar_agent_builder::protocol::testing::{git_ca, http_handle};
use serde_json::Value;

const OPERATIONS: &[OperationDecl] = &[PUSH];
const BUILD: &str = "94f6c637-012f-42d5-ac25-b504b8a0e9d5";

#[tokio::test]
async fn a_log_is_its_blob_and_a_manifest_tagged_by_its_build() {
    let (server, registry) = registry().await;
    let site = http_handle(
        &git_ca().pem,
        OPERATIONS,
        vec![(REGISTRY_VAR, server.uri())],
        None,
    )
    .await;
    let log =
        b"[pipeline] cargo build --release\n[pipeline] polar-report {\"type\":\"stage_started\"}\n"
            .to_vec();
    let digest = RegistryLogs::new(site.handle.clone())
        .keep(BUILD, &log)
        .await
        .unwrap();
    assert_eq!(digest, digest_of(&log));
    let held = registry.0.lock().unwrap();
    assert_eq!(held.blobs.get(&digest), Some(&log));
    let (_, body) = held
        .manifests
        .get(&format!("{REPOSITORY}:{BUILD}"))
        .expect("a manifest by the build's id");
    let manifest: Value = serde_json::from_slice(body).unwrap();
    assert_eq!(manifest["artifactType"], ARTIFACT_TYPE);
    assert_eq!(manifest["layers"][0]["mediaType"], LOG_TYPE);
    assert_eq!(manifest["layers"][0]["digest"], digest);
    assert_eq!(manifest["layers"][0]["size"], log.len());
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
async fn a_log_the_registry_refuses_is_not_kept_and_says_why() {
    let (server, registry) = registry().await;
    registry.0.lock().unwrap().refusing = true;
    let site = http_handle(
        &git_ca().pem,
        OPERATIONS,
        vec![(REGISTRY_VAR, server.uri())],
        None,
    )
    .await;
    let why = RegistryLogs::new(site.handle.clone())
        .keep(BUILD, b"a log")
        .await
        .unwrap_err();
    assert!(why.contains("log"), "{why}");
    assert!(
        registry.0.lock().unwrap().manifests.is_empty(),
        "no manifest names what is not there"
    );
}
