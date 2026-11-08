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

//! Projection: turns one [`ProvenanceEvent`] into the graph operations that
//! record it.
//!
//! Every projection is a pure function from an event to `Vec<GraphOp>`. Nothing
//! here touches the graph or the broker. The supervisor sends one event's
//! operations as one transaction ([`transaction`]) to the `GraphControllerActor`,
//! which serializes all writes and writes a transaction all or none.
//!
//! Each operation is an idempotent MERGE, so projecting the same event twice
//! (a broker replay) leaves the graph unchanged, and events about the same
//! nodes may arrive in any order.
//!
//! The modules are cut by what the graph is *about*, which also tracks whose
//! word each fact is:
//!
//! | Module        | Subject                                         | Reported by          |
//! |---------------|-------------------------------------------------|----------------------|
//! | [`execution`] | `BuildJob`: what ran, where, and how it ended   | orchestrator, CI     |
//! | [`outputs`]   | what a build produced: artifacts, SBOMs, images | the producing build  |
//! | [`findings`]  | facts about packages: advisories, analyses      | scanners, analyzers  |
//! | [`registry`]  | what a registry actually serves                 | the resolver         |
//!
//! [`project`] is the only dispatch, and it has no wildcard arm: adding a
//! [`ProvenanceEvent`] variant fails to compile until it is routed here.

pub mod execution;
pub mod findings;
pub mod outputs;
pub mod registry;

use execution::When;
use polar::ProvenanceEvent;
use polar::graph::controller::{GraphOp, IntoGraphKey, Property};
use ractor::ActorProcessingErr;
use tracing::{debug, warn};

/// Project one event. `observed_at` (RFC 3339) is stamped on every node and
/// edge the event writes, so all writes for one event share one timestamp.
///
/// Errors only for payloads that can't be interpreted (e.g. a manifest that
/// isn't valid OCI JSON); nothing is written for that event.
pub fn project(
    event: ProvenanceEvent,
    observed_at: &str,
) -> Result<Vec<GraphOp>, ActorProcessingErr> {
    let ops = match event {
        // ── Execution ─────────────────────────────────────────────────────────
        ProvenanceEvent::ExecutionStarted {
            build_id,
            commit_sha,
            ref_name,
            repo_url,
            triggered_by,
            backend,
            at,
        } => execution::started(
            build_id,
            commit_sha,
            ref_name,
            repo_url,
            triggered_by,
            backend,
            &When {
                at: &reported(&at)?,
                observed_at,
            },
        ),
        ProvenanceEvent::StageStarted {
            build_id,
            stage_name,
            stage_id,
            at,
        } => execution::stage_started(
            build_id,
            stage_name,
            stage_id,
            &When {
                at: &reported(&at)?,
                observed_at,
            },
        ),
        ProvenanceEvent::StageCompleted {
            build_id,
            stage_name,
            stage_id,
            duration_secs,
            outcome,
            at,
        } => execution::stage_completed(
            build_id,
            stage_name,
            stage_id,
            duration_secs,
            outcome,
            &When {
                at: &reported(&at)?,
                observed_at,
            },
        ),
        ProvenanceEvent::ExecutionCompleted {
            build_id,
            duration_secs,
            at,
        } => execution::completed(
            build_id,
            duration_secs,
            &When {
                at: &reported(&at)?,
                observed_at,
            },
        ),
        ProvenanceEvent::ExecutionFailed {
            build_id,
            reason,
            stage,
            at,
        } => execution::failed(
            build_id,
            reason,
            stage,
            &When {
                at: &reported(&at)?,
                observed_at,
            },
        ),
        ProvenanceEvent::ExecutionCancelled {
            build_id,
            reason,
            at,
        } => execution::cancelled(
            build_id,
            reason,
            &When {
                at: &reported(&at)?,
                observed_at,
            },
        ),

        // ── Build outputs ─────────────────────────────────────────────────────
        ProvenanceEvent::ArtifactProduced(p) => outputs::artifact_produced(p),
        ProvenanceEvent::SbomAnalyzed(fragment) => outputs::sbom_analyzed(fragment),
        ProvenanceEvent::BinaryLinked(p) => outputs::binary_linked(p, observed_at),
        ProvenanceEvent::ContainerImageCreated(p) => outputs::container_image_created(p),

        // ── Findings ──────────────────────────────────────────────────────────
        ProvenanceEvent::SecurityAdvisoryFound(p) => findings::security_advisory(p, observed_at),
        ProvenanceEvent::PackageStatusFound(p) => findings::package_status(p, observed_at),

        // ── Registry ──────────────────────────────────────────────────────────
        ProvenanceEvent::OCIArtifactResolved {
            uri,
            digest,
            manifest_data,
            registry,
            ..
        } => registry::artifact_resolved(uri, digest, &manifest_data, registry, observed_at)?,
        ProvenanceEvent::OCIRegistryDiscovered { hostname } => {
            registry::registry_discovered(hostname)
        }

        // ── Not projected ─────────────────────────────────────────────────────
        // Discovery events are requests for the resolver to fetch and verify
        // something. The resolver reports the result (OCIArtifactResolved);
        // the unverified request itself is not recorded.
        ProvenanceEvent::OCIArtifactDiscovered { uri, .. } => {
            debug!("OCI artifact discovered: {uri} — the resolver records the resolved form");
            vec![]
        }
        ProvenanceEvent::ArtifactDiscovered { name, .. } => {
            debug!("artifact discovered: {name} — nothing to record");
            vec![]
        }
        // Defined in the vocabulary but emitted by no agent yet. Warn rather
        // than drop silently, so the first producer is noticed and gets a
        // projection instead of disappearing into a log.
        ProvenanceEvent::OCIArtifactCreated { digest, .. } => {
            warn!(%digest, "OCIArtifactCreated has no projection yet — not recorded");
            vec![]
        }
        ProvenanceEvent::ImageRefResolved { uri, .. } => {
            warn!(%uri, "ImageRefResolved has no projection yet — not recorded");
            vec![]
        }
        ProvenanceEvent::Ignored => vec![],
    };
    Ok(ops)
}

/// Whose word an event is, which says the one topic it is believed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Word {
    /// What a registry serves: the resolver's, on [`polar::topics::PROVENANCE_RESOLUTIONS`].
    Registry,
    /// What a build reports: on [`polar::topics::PROVENANCE_EVENTS`].
    Build,
    /// A request for the resolver to fetch and verify something, believed on neither.
    Request,
}

/// Whose word `event` is. No wildcard: a new [`ProvenanceEvent`] variant does not compile until it is placed.
pub fn whose_word(event: &ProvenanceEvent) -> Word {
    match event {
        ProvenanceEvent::OCIArtifactResolved { .. }
        | ProvenanceEvent::OCIRegistryDiscovered { .. }
        | ProvenanceEvent::ImageRefResolved { .. } => Word::Registry,
        ProvenanceEvent::ExecutionStarted { .. }
        | ProvenanceEvent::StageStarted { .. }
        | ProvenanceEvent::StageCompleted { .. }
        | ProvenanceEvent::ExecutionCompleted { .. }
        | ProvenanceEvent::ExecutionFailed { .. }
        | ProvenanceEvent::ExecutionCancelled { .. }
        | ProvenanceEvent::ArtifactProduced(_)
        | ProvenanceEvent::SbomAnalyzed(_)
        | ProvenanceEvent::BinaryLinked(_)
        | ProvenanceEvent::ContainerImageCreated(_)
        | ProvenanceEvent::OCIArtifactCreated { .. }
        | ProvenanceEvent::SecurityAdvisoryFound(_)
        | ProvenanceEvent::PackageStatusFound(_)
        | ProvenanceEvent::Ignored => Word::Build,
        ProvenanceEvent::OCIArtifactDiscovered { .. }
        | ProvenanceEvent::ArtifactDiscovered { .. } => Word::Request,
    }
}

/// Whether `event`, arriving on `topic`, is believed: a registry fact only from the resolver's topic, a build's report
/// only from the provenance stream. Who may publish on each is the broker's to decide, on the publisher's
/// broker-stamped identity, so a build publisher cannot speak for a registry.
pub fn believed_on(topic: &str, event: &ProvenanceEvent) -> bool {
    match whose_word(event) {
        Word::Registry => topic == polar::topics::PROVENANCE_RESOLUTIONS,
        Word::Build => topic == polar::topics::PROVENANCE_EVENTS,
        Word::Request => false,
    }
}

/// One event's writes as one transaction ([`GraphOp::Transaction`]): the graph controller writes all of them or none,
/// so a failure partway cannot leave half an event in the graph. `None` when the event writes nothing.
pub fn transaction(
    event: ProvenanceEvent,
    observed_at: &str,
) -> Result<Option<GraphOp>, ActorProcessingErr> {
    let ops = project(event, observed_at)?;
    Ok((!ops.is_empty()).then_some(GraphOp::Transaction { ops }))
}

/// When the reporter says an event happened, as the graph keeps a time: RFC 3339 in UTC. A time that is not RFC 3339
/// with its offset is refused, and the event with it.
fn reported(at: &str) -> Result<String, ActorProcessingErr> {
    let time = chrono::DateTime::parse_from_rfc3339(at)
        .map_err(|e| format!("the event's time {at:?} is not RFC 3339: {e}"))?;
    Ok(time
        .with_timezone(&chrono::Utc)
        .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true))
}

// ── Shared op builders ─────────────────────────────────────────────────────────

pub(crate) fn upsert(key: impl IntoGraphKey, props: Vec<Property>) -> GraphOp {
    GraphOp::UpsertNode {
        key: key.into_key(),
        props,
    }
}

pub(crate) fn edge(
    from: impl IntoGraphKey,
    rel_type: &str,
    to: impl IntoGraphKey,
    props: Vec<Property>,
) -> GraphOp {
    GraphOp::EnsureEdge {
        from: from.into_key(),
        rel_type: rel_type.to_string(),
        to: to.into_key(),
        props,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neo4rs::BoltType;
    use polar::graph::controller::compile_graph_op;
    use polar::{
        ArtifactProducedPayload, BackendIdentity, BinaryLinkedPayload,
        ContainerImageCreatedPayload, DependencyEdge, OciLayerEntry, PackageRef,
        PackageStatusFoundPayload, SbomGraphFragment, SecurityAdvisoryFoundPayload, StageOutcome,
    };

    const T0: &str = "2026-10-16T00:00:00Z";

    /// The single RawQuery an event projects to.
    fn raw(ops: &[GraphOp]) -> (&str, &[(String, BoltType)]) {
        match ops {
            [GraphOp::RawMergeWrite { cypher, params }] => (cypher, params),
            _ => panic!("expected exactly one RawQuery, got {} ops", ops.len()),
        }
    }

    /// Replays must not add edges: every timestamped edge is MERGEd on its
    /// endpoints alone, with `at` set only on creation.
    #[test]
    fn finding_edges_are_merged_without_timestamps() {
        let advisory = project(
            ProvenanceEvent::SecurityAdvisoryFound(SecurityAdvisoryFoundPayload {
                build_id: "b1".into(),
                severity: "high".into(),
                identifier: "RUSTSEC-2024-0001".into(),
                in_artifact: None,
                kind: None,
                scanner: None,
                affected_package: Some("pkg:cargo/itoa@1.0.18".into()),
                cve_id: None,
                ghsa_id: None,
                fix_version: None,
                unaffected_constraint: None,
                advisory_url: None,
            }),
            T0,
        )
        .unwrap();
        let (cypher, _) = raw(&advisory);
        assert!(
            !cypher.contains("{ at:"),
            "timestamp inside a MERGE pattern: {cypher}"
        );
        assert!(
            cypher.contains("SET r.at = coalesce(r.at, $observed_at)")
                && cypher.contains("SET af.at = coalesce(af.at, $observed_at)"),
            "an edge's time is not kept from its first write: {cypher}"
        );
    }

    #[test]
    fn container_image_layers_are_diff_ids_not_registry_layers() {
        let ops = project(
            ProvenanceEvent::ContainerImageCreated(ContainerImageCreatedPayload {
                image_name: "polar/app".into(),
                tarball_hash: "sha256:t".into(),
                config_digest: "sha256:c".into(),
                layers: vec![OciLayerEntry {
                    order: 0,
                    diff_id: "sha256:d0".into(),
                    tar_path: String::new(),
                }],
                os: String::new(),
                arch: String::new(),
                created: String::new(),
                entrypoint: String::new(),
                cmd: String::new(),
                repo_tags: vec![],
                digest: "sha256:m".into(),
                uri: "reg/polar/app@sha256:m".into(),
            }),
            T0,
        )
        .unwrap();
        let rendered = format!("{ops:?}");
        assert!(rendered.contains("OCILayerDiffId") && rendered.contains("HAS_DIFF_ID"));
        assert!(
            !rendered.contains("OCILayer {"),
            "pipeline wrote a registry layer node"
        );
    }

    #[test]
    fn container_image_without_digest_writes_nothing() {
        let ops = project(
            ProvenanceEvent::ContainerImageCreated(ContainerImageCreatedPayload {
                image_name: "polar/app".into(),
                tarball_hash: "sha256:t".into(),
                config_digest: "sha256:c".into(),
                layers: vec![],
                os: String::new(),
                arch: String::new(),
                created: String::new(),
                entrypoint: String::new(),
                cmd: String::new(),
                repo_tags: vec![],
                digest: String::new(),
                uri: String::new(),
            }),
            T0,
        )
        .unwrap();
        assert!(ops.is_empty());
    }

    #[test]
    fn invalid_manifest_is_an_error_not_a_partial_write() {
        let result = project(
            ProvenanceEvent::OCIArtifactResolved {
                uri: "reg/x@sha256:m".into(),
                digest: "sha256:m".into(),
                manifest_data: b"not json".to_vec(),
                registry: "reg".into(),
                source_ref: polar::DiscoverySourceRef::OCIRepository {
                    repo_uri: "reg/x".into(),
                },
            },
            T0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn archive_build_has_no_commit_edge() {
        let ops = project(
            ProvenanceEvent::ExecutionStarted {
                build_id: "b1".into(),
                commit_sha: String::new(),
                ref_name: String::new(),
                repo_url: "https://static.crates.io/crates/itoa/itoa-1.0.18.crate".into(),
                triggered_by: None,
                backend: None,
                at: T0.into(),
            },
            T0,
        )
        .unwrap();
        assert!(!format!("{ops:?}").contains("BUILT_BY"));
    }

    fn package(purl: &str) -> PackageRef {
        PackageRef {
            purl: purl.into(),
            name: "itoa".into(),
            version: "1.0.18".into(),
            component_type: "library".into(),
            license: Some("MIT".into()),
            source: Some("registry".into()),
        }
    }

    /// One event of every kind that is projected, each with what makes it write the most.
    fn one_of_each() -> Vec<ProvenanceEvent> {
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:config", "size": 100 },
            "layers": [
                { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:blob0", "size": 10 }
            ]
        });
        vec![
            ProvenanceEvent::ExecutionStarted {
                build_id: "b1".into(),
                commit_sha: "c0ffee".into(),
                ref_name: "refs/heads/main".into(),
                repo_url: "https://git.example/polar.git".into(),
                triggered_by: Some("orchestrator".into()),
                backend: Some(BackendIdentity {
                    node_label: "KubernetesJob".into(),
                    identity_props: vec![("uid".into(), "u1".into())],
                }),
                at: T0.into(),
            },
            ProvenanceEvent::StageStarted {
                build_id: "b1".into(),
                stage_name: "build".into(),
                stage_id: "s1".into(),
                at: T0.into(),
            },
            ProvenanceEvent::StageCompleted {
                build_id: "b1".into(),
                stage_name: "build".into(),
                stage_id: "s1".into(),
                duration_secs: 3,
                outcome: StageOutcome::Succeeded,
                at: T0.into(),
            },
            ProvenanceEvent::ExecutionCompleted {
                build_id: "b1".into(),
                duration_secs: 5,
                at: T0.into(),
            },
            ProvenanceEvent::ExecutionFailed {
                build_id: "b2".into(),
                reason: "exit 1".into(),
                stage: Some("build".into()),
                at: T0.into(),
            },
            ProvenanceEvent::ExecutionCancelled {
                build_id: "b3".into(),
                reason: Some("superseded".into()),
                at: T0.into(),
            },
            ProvenanceEvent::ArtifactProduced(ArtifactProducedPayload {
                artifact_content_hash: "sha256:art".into(),
                artifact_type: "binary".into(),
                name: "polar".into(),
                content_type: "application/octet-stream".into(),
                build_id: Some("b1".into()),
            }),
            ProvenanceEvent::SbomAnalyzed(SbomGraphFragment {
                artifact_content_hash: "sha256:sbom".into(),
                filename: "polar.cdx.json".into(),
                root: Some(package("pkg:cargo/polar@1.0.0")),
                components: vec![package("pkg:cargo/itoa@1.0.18")],
                edges: vec![DependencyEdge {
                    from_ref: "pkg:cargo/polar@1.0.0".into(),
                    to_refs: vec!["pkg:cargo/itoa@1.0.18".into()],
                }],
            }),
            ProvenanceEvent::BinaryLinked(BinaryLinkedPayload {
                binary_content_hash: "sha256:bin".into(),
                binary_name: "polar".into(),
                root_purl: "pkg:cargo/polar@1.0.0".into(),
                sbom_content_hash: "sha256:sbom".into(),
                binding_digest: "sha256:bind".into(),
            }),
            ProvenanceEvent::ContainerImageCreated(ContainerImageCreatedPayload {
                image_name: "polar/app".into(),
                tarball_hash: "sha256:t".into(),
                config_digest: "sha256:c".into(),
                layers: vec![OciLayerEntry {
                    order: 0,
                    diff_id: "sha256:d0".into(),
                    tar_path: String::new(),
                }],
                os: "linux".into(),
                arch: "amd64".into(),
                created: "2026-10-16T00:00:00Z".into(),
                entrypoint: "/bin/app".into(),
                cmd: "serve".into(),
                repo_tags: vec!["polar/app:1".into()],
                digest: "sha256:m".into(),
                uri: "reg/polar/app@sha256:m".into(),
            }),
            ProvenanceEvent::SecurityAdvisoryFound(SecurityAdvisoryFoundPayload {
                build_id: "b1".into(),
                severity: "high".into(),
                identifier: "RUSTSEC-2024-0001".into(),
                in_artifact: Some("sha256:art".into()),
                kind: Some("vulnerability".into()),
                scanner: Some("cargo-audit".into()),
                affected_package: Some("pkg:cargo/itoa@1.0.18".into()),
                cve_id: Some("CVE-2024-0001".into()),
                ghsa_id: Some("GHSA-xxxx".into()),
                fix_version: Some("1.0.19".into()),
                unaffected_constraint: Some(">=1.0.19".into()),
                advisory_url: Some("https://rustsec.org/advisories/RUSTSEC-2024-0001".into()),
            }),
            ProvenanceEvent::PackageStatusFound(PackageStatusFoundPayload {
                build_id: "b1".into(),
                kind: "unmaintained".into(),
                identifier: "RUSTSEC-2024-0002".into(),
                package_name: "itoa".into(),
                package_version: "1.0.18".into(),
                in_artifact: Some("sha256:art".into()),
                affected_package: Some("pkg:cargo/itoa@1.0.18".into()),
                advisory_url: Some("https://rustsec.org/advisories/RUSTSEC-2024-0002".into()),
                scanner: Some("cargo-audit".into()),
            }),
            ProvenanceEvent::OCIArtifactResolved {
                uri: "reg.example/polar/app@sha256:m".into(),
                digest: "sha256:m".into(),
                manifest_data: serde_json::to_vec(&manifest).unwrap(),
                registry: "reg.example".into(),
                source_ref: polar::DiscoverySourceRef::OCIRepository {
                    repo_uri: "reg.example/polar/app".into(),
                },
            },
            ProvenanceEvent::OCIRegistryDiscovered {
                hostname: "reg.example".into(),
            },
        ]
    }

    /// What a projection writes is only what the graph controller takes: a write it refuses is lost (the controller
    /// logs and drops it), so a projection whose Cypher the controller's guard rejects records nothing, silently.
    #[test]
    fn every_operation_a_projection_makes_is_one_the_controller_accepts() {
        for event in one_of_each() {
            let name = format!("{event:?}").chars().take(40).collect::<String>();
            let ops = project(event, T0).unwrap();
            assert!(!ops.is_empty(), "{name} wrote nothing");
            for op in &ops {
                if let Err(e) = compile_graph_op(op) {
                    panic!("{name}: the controller refuses {op:?}: {e}");
                }
            }
        }
    }

    /// One event is one transaction: all of its writes or none, so a failure cannot leave a build without its type edge
    /// or a manifest without its layers.
    #[test]
    fn every_event_is_written_as_one_transaction() {
        for event in one_of_each() {
            let name = format!("{event:?}").chars().take(40).collect::<String>();
            let Some(op) = transaction(event, T0).unwrap() else {
                panic!("{name} wrote nothing");
            };
            assert!(matches!(op, GraphOp::Transaction { .. }), "{name}");
            compile_graph_op(&op).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        let nothing = transaction(
            ProvenanceEvent::OCIArtifactDiscovered {
                uri: "reg/x:1".into(),
                source_ref: polar::DiscoverySourceRef::OCIRepository {
                    repo_uri: "reg/x".into(),
                },
            },
            T0,
        )
        .unwrap();
        assert!(nothing.is_none());
    }

    /// What a registry serves is the resolver's word alone, on its own topic; everything a build reports is on the
    /// provenance stream; and a discovery is a request to the resolver, believed on neither.
    #[test]
    fn each_kind_is_believed_on_one_topic_only() {
        use super::Word::{Build, Registry, Request};
        let registry_facts = [
            ProvenanceEvent::OCIArtifactResolved {
                uri: "reg/x@sha256:m".into(),
                digest: "sha256:m".into(),
                manifest_data: vec![],
                registry: "reg".into(),
                source_ref: polar::DiscoverySourceRef::OCIRepository {
                    repo_uri: "reg/x".into(),
                },
            },
            ProvenanceEvent::OCIRegistryDiscovered {
                hostname: "reg".into(),
            },
        ];
        for event in &registry_facts {
            assert_eq!(whose_word(event), Registry, "{event:?}");
            assert!(believed_on(polar::topics::PROVENANCE_RESOLUTIONS, event));
            assert!(!believed_on(polar::topics::PROVENANCE_EVENTS, event));
        }
        for event in one_of_each().into_iter().filter(|e| {
            !registry_facts
                .iter()
                .any(|r| std::mem::discriminant(r) == std::mem::discriminant(e))
        }) {
            assert_eq!(whose_word(&event), Build, "{event:?}");
            assert!(believed_on(polar::topics::PROVENANCE_EVENTS, &event));
            assert!(!believed_on(polar::topics::PROVENANCE_RESOLUTIONS, &event));
        }
        let request = ProvenanceEvent::OCIArtifactDiscovered {
            uri: "reg/x:1".into(),
            source_ref: polar::DiscoverySourceRef::OCIRepository {
                repo_uri: "reg/x".into(),
            },
        };
        assert_eq!(whose_word(&request), Request);
        for topic in [
            polar::topics::PROVENANCE_EVENTS,
            polar::topics::PROVENANCE_RESOLUTIONS,
            "elsewhere",
        ] {
            assert!(!believed_on(topic, &request), "{topic}");
        }
    }

    /// The labels of an edge's two ends, for every edge a projection writes through a key.
    fn edges_of(ops: &[GraphOp]) -> Vec<(String, String, String)> {
        let label =
            |key: &dyn polar::graph::controller::GraphNodeKey| key.identity().labels.join(":");
        ops.iter()
            .flat_map(|op| match op {
                GraphOp::Transaction { ops } => edges_of(ops),
                GraphOp::EnsureEdge {
                    from, rel_type, to, ..
                } => vec![(label(from.as_ref()), rel_type.clone(), label(to.as_ref()))],
                _ => vec![],
            })
            .collect()
    }

    /// The type anchors are what an instance IS (pipeline-design-reference.md, "The type-marker singleton idiom"):
    /// `(x)-[:IS]->(Artifact)`, never the other way, and nothing else points at an anchor or comes from one.
    #[test]
    fn an_instance_is_its_type_and_a_type_anchor_is_only_pointed_at_by_is() {
        const ANCHORS: [&str; 3] = ["Artifact", "Finding", "BuildExecution"];
        let mut is_edges = 0;
        for event in one_of_each() {
            let name = format!("{event:?}").chars().take(40).collect::<String>();
            for (from, rel, to) in edges_of(&project(event, T0).unwrap()) {
                assert!(
                    !ANCHORS.contains(&from.as_str()),
                    "{name}: ({from})-[:{rel}]->({to}) starts at an anchor"
                );
                if ANCHORS.contains(&to.as_str()) {
                    assert_eq!(rel, "IS", "{name}: ({from})-[:{rel}]->({to})");
                    is_edges += 1;
                }
            }
        }
        assert!(is_edges > 0, "no IS edge was written at all");
    }

    /// A dependency is a Package, keyed by purl: a ref that is not one (a CycloneDX bom-ref such as cargo's
    /// `path+file://...#0.1.0`) is not a package and makes no node, and the edges between purls are kept.
    #[test]
    fn a_dependency_ref_that_is_not_a_purl_makes_no_package() {
        let bom_ref = "path+file:///work/polar#0.1.0";
        let dep_ref = "registry+https://github.com/rust-lang/crates.io-index#itoa@1.0.18";
        let ops = project(
            ProvenanceEvent::SbomAnalyzed(SbomGraphFragment {
                artifact_content_hash: "sha256:sbom".into(),
                filename: "polar.cdx.json".into(),
                root: Some(package("pkg:cargo/polar@1.0.0")),
                components: vec![package("pkg:cargo/itoa@1.0.18")],
                edges: vec![
                    DependencyEdge {
                        from_ref: bom_ref.into(),
                        to_refs: vec![dep_ref.into()],
                    },
                    DependencyEdge {
                        from_ref: "pkg:cargo/polar@1.0.0".into(),
                        to_refs: vec!["pkg:cargo/itoa@1.0.18".into(), dep_ref.into()],
                    },
                ],
            }),
            T0,
        )
        .unwrap();
        let written = format!("{ops:?}");
        for not_a_purl in [bom_ref, dep_ref] {
            assert!(
                !written.contains(not_a_purl),
                "{not_a_purl} was written: {written}"
            );
        }
        assert!(written.contains("pkg:cargo/itoa@1.0.18"));
    }

    /// A package is keyed by its purl: a component with none (an SBOM entry the generator could not name) is not
    /// written, rather than merged with every other such entry into one `Package { purl: "" }`.
    #[test]
    fn a_component_without_a_purl_is_not_a_package() {
        let mut unnamed = package("");
        unnamed.name = "vendored-c-lib".into();
        let ops = project(
            ProvenanceEvent::SbomAnalyzed(SbomGraphFragment {
                artifact_content_hash: "sha256:sbom".into(),
                filename: "polar.cdx.json".into(),
                root: Some(package("pkg:cargo/polar@1.0.0")),
                components: vec![package("pkg:cargo/itoa@1.0.18"), unnamed],
                edges: vec![],
            }),
            T0,
        )
        .unwrap();
        let written = format!("{ops:?}");
        assert!(!written.contains("vendored-c-lib"), "{written}");
        assert!(
            !written.contains(r#"String("")"#),
            "an empty key was written: {written}"
        );
        assert!(written.contains("pkg:cargo/itoa@1.0.18"));
    }

    /// A build's states are keyed on when its reporter says each happened, in UTC, not on when it was seen: an event
    /// seen twice, or late, lands on the same state.
    #[test]
    fn a_builds_states_are_keyed_on_the_reporters_time() {
        let started = |observed: &str| {
            format!(
                "{:?}",
                project(
                    ProvenanceEvent::ExecutionStarted {
                        build_id: "b1".into(),
                        commit_sha: "c0ffee".into(),
                        ref_name: "refs/heads/main".into(),
                        repo_url: "https://git.example/polar.git".into(),
                        triggered_by: None,
                        backend: None,
                        at: "2026-10-16T02:00:00+02:00".into(),
                    },
                    observed,
                )
                .unwrap()
            )
        };
        let first = started("2026-11-01T00:00:00Z");
        assert!(
            first.contains(r#"valid_from: "2026-10-16T00:00:00Z""#),
            "{first}"
        );
        assert!(
            first.contains(r#"Property("at", String("2026-10-16T00:00:00Z"))"#),
            "{first}"
        );
        // Seen again a day later: the same writes, but for when it was seen.
        let again = started("2026-11-02T00:00:00Z");
        assert_eq!(
            first.replace("2026-11-01T00:00:00Z", "SEEN"),
            again.replace("2026-11-02T00:00:00Z", "SEEN")
        );
    }

    /// A time that is not RFC 3339 is not a time: the event is refused and writes nothing.
    #[test]
    fn an_event_whose_time_is_not_rfc3339_is_refused() {
        for at in [
            "",
            "yesterday",
            "2026-10-16 00:00:00",
            "2026-10-16T00:00:00",
        ] {
            let refused = project(
                ProvenanceEvent::ExecutionCompleted {
                    build_id: "b1".into(),
                    duration_secs: 3,
                    at: at.into(),
                },
                T0,
            );
            assert!(refused.is_err(), "{at:?} was taken");
        }
    }

    /// What the pipeline's `emit-execution-completed` writes (scripts/pipeline/core/events.nu, `reported-now`: the
    /// local offset and nanoseconds) is read, and its time kept in UTC.
    #[test]
    fn a_pipelines_json_event_and_its_time_are_read() {
        let json = r#"{"type":"execution_completed","build_id":"b1","duration_secs":3,"at":"2026-11-07T18:59:59.123456789-05:00"}"#;
        let event: ProvenanceEvent = serde_json::from_str(json).unwrap();
        let written = format!("{:?}", project(event, T0).unwrap());
        assert!(
            written.contains(r#"valid_from: "2026-11-07T23:59:59.123456789Z""#),
            "{written}"
        );
    }

    /// A backend that names no property of its job is not linked: it would match every job of its label.
    #[test]
    fn a_backend_job_with_no_identity_is_not_linked() {
        let ops = project(
            ProvenanceEvent::ExecutionStarted {
                build_id: "b1".into(),
                commit_sha: "c0ffee".into(),
                ref_name: "refs/heads/main".into(),
                repo_url: "https://git.example/polar.git".into(),
                triggered_by: None,
                backend: Some(BackendIdentity {
                    node_label: "KubernetesJob".into(),
                    identity_props: vec![],
                }),
                at: T0.into(),
            },
            T0,
        )
        .unwrap();
        assert!(!format!("{ops:?}").contains("EXECUTED_IN"));
        // The build itself is still written.
        assert!(format!("{ops:?}").contains("BuildJob"));
    }
}
