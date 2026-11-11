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

//! Projects real events against a real Neo4j (the deployed 5.26.2) through the
//! same path the agent uses: `project()` → `compile_graph_op` → execute.
//!
//! Requires a container runtime for testcontainers (with Podman, DOCKER_HOST at its socket).

use build_processor::aging::{cutoff, judged_lost, stale_builds};
use build_processor::project::transaction;
use neo4rs::{Graph, Query};
use polar::graph::controller::compile_graph_op;
use polar::{
    ContainerImageCreatedPayload, DependencyEdge, DiscoverySourceRef, FactLabel, FactRef,
    FactReportedPayload, OciLayerEntry, PackageRef, ProvenanceEvent, SbomGraphFragment,
    SecurityAdvisoryFoundPayload,
};
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::neo4j::Neo4j;

/// Project one event, stamped `observed_at`, and write it as the agent does: one transaction.
async fn apply(graph: &Graph, event: ProvenanceEvent, observed_at: &str) {
    let Some(op) = transaction(event, observed_at).unwrap() else {
        return;
    };
    let mut txn = graph.start_txn().await.unwrap();
    txn.run_queries(compile_graph_op(&op).unwrap())
        .await
        .unwrap();
    txn.commit().await.unwrap();
}

async fn count(graph: &Graph, cypher: &str) -> i64 {
    let mut rows = graph.execute(Query::new(cypher.to_string())).await.unwrap();
    rows.next().await.unwrap().unwrap().get::<i64>("n").unwrap()
}

fn advisory() -> ProvenanceEvent {
    ProvenanceEvent::SecurityAdvisoryFound(SecurityAdvisoryFoundPayload {
        build_id: "b1".into(),
        severity: "high".into(),
        identifier: "RUSTSEC-2024-0001".into(),
        in_artifact: None,
        kind: Some("vulnerability".into()),
        scanner: Some("cargo-audit".into()),
        affected_package: Some("pkg:cargo/openssl-sys@0.9.117".into()),
        cve_id: None,
        ghsa_id: None,
        fix_version: None,
        unaffected_constraint: None,
        advisory_url: None,
    })
}

const IMAGE_DIGEST: &str = "sha256:manifest";

fn image_built() -> ProvenanceEvent {
    ProvenanceEvent::ContainerImageCreated(ContainerImageCreatedPayload {
        image_name: "polar/app".into(),
        tarball_hash: "sha256:tarball".into(),
        config_digest: "sha256:config".into(),
        layers: ["sha256:diff0", "sha256:diff1"]
            .into_iter()
            .enumerate()
            .map(|(order, diff_id)| OciLayerEntry {
                order: order as u32,
                diff_id: diff_id.into(),
                tar_path: String::new(),
            })
            .collect(),
        os: "linux".into(),
        arch: "amd64".into(),
        created: String::new(),
        entrypoint: String::new(),
        cmd: String::new(),
        repo_tags: vec![],
        digest: IMAGE_DIGEST.into(),
        uri: format!("reg.example/polar/app@{IMAGE_DIGEST}"),
    })
}

fn image_resolved() -> ProvenanceEvent {
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:config",
            "size": 100
        },
        "layers": [
            { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:blob0", "size": 10 },
            { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:blob1", "size": 20 }
        ]
    });
    ProvenanceEvent::OCIArtifactResolved {
        uri: format!("reg.example/polar/app@{IMAGE_DIGEST}"),
        digest: IMAGE_DIGEST.into(),
        manifest_data: serde_json::to_vec(&manifest).unwrap(),
        registry: "reg.example".into(),
        source_ref: DiscoverySourceRef::OCIRepository {
            repo_uri: "reg.example/polar/app".into(),
        },
    }
}

#[tokio::test]
async fn projections_are_idempotent_and_keep_layer_identities_apart() {
    let container = Neo4j::default()
        .with_version("5.26.2")
        .start()
        .await
        .unwrap();
    let config = neo4rs::ConfigBuilder::new()
        .uri(format!(
            "bolt://{}:{}",
            container.get_host().await.unwrap(),
            container.image().bolt_port_ipv4().unwrap()
        ))
        .user(container.image().user().unwrap())
        .password(container.image().password().unwrap())
        .build()
        .unwrap();
    let graph = Graph::connect(config).unwrap();

    // Every event twice, at different times, as a broker replay would.
    for observed_at in ["2026-10-16T00:00:00Z", "2026-10-16T01:00:00Z"] {
        apply(&graph, advisory(), observed_at).await;
        apply(&graph, image_built(), observed_at).await;
        apply(&graph, image_resolved(), observed_at).await;
    }

    // ── Findings: replay adds nothing ────────────────────────────────────────
    assert_eq!(
        count(
            &graph,
            "MATCH (:BuildJob)-[r:REPORTED]->(:SecurityAdvisory) RETURN count(r) AS n"
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &graph,
            "MATCH (:SecurityAdvisory)-[r:AFFECTS]->(:Package) RETURN count(r) AS n"
        )
        .await,
        1
    );
    assert_eq!(
        count(&graph, "MATCH (t:Finding) RETURN count(t) AS n").await,
        1
    );
    assert_eq!(
        count(&graph, "MATCH (j:BuildJob) RETURN count(j) AS n").await,
        1
    );

    // ── Images: build and registry facts meet on one OCIArtifact ─────────────
    assert_eq!(
        count(&graph, "MATCH (a:OCIArtifact) RETURN count(a) AS n").await,
        1
    );
    assert_eq!(
        count(
            &graph,
            "MATCH (:OCIArtifact)-[r:HAS_DIFF_ID]->(:OCILayerDiffId) RETURN count(r) AS n"
        )
        .await,
        2
    );
    assert_eq!(
        count(
            &graph,
            "MATCH (:OCIArtifact)-[r:HAS_LAYER]->(:OCILayer) RETURN count(r) AS n"
        )
        .await,
        2
    );
    // No diff ID landed in the registry-layer space.
    assert_eq!(
        count(
            &graph,
            "MATCH (l:OCILayer) WHERE l.digest STARTS WITH 'sha256:diff' RETURN count(l) AS n"
        )
        .await,
        0
    );
    // Layer i and diff ID i are the same layer.
    assert_eq!(
        count(
            &graph,
            "MATCH (l:OCILayer)<-[hl:HAS_LAYER]-(a:OCIArtifact)-[hd:HAS_DIFF_ID]->(d:OCILayerDiffId)
             WHERE hl.order = hd.order
               AND ((l.digest = 'sha256:blob0' AND d.diff_id = 'sha256:diff0')
                 OR (l.digest = 'sha256:blob1' AND d.diff_id = 'sha256:diff1'))
             RETURN count(*) AS n"
        )
        .await,
        2
    );

    // ── A package's license stands until an SBOM says another ─────────────────
    let sbom = |hash: &str, license: Option<&str>| {
        ProvenanceEvent::SbomAnalyzed(SbomGraphFragment {
            artifact_content_hash: hash.into(),
            filename: format!("{hash}.cdx.json"),
            root: None,
            components: vec![PackageRef {
                purl: "pkg:cargo/itoa@1.0.18".into(),
                name: "itoa".into(),
                version: "1.0.18".into(),
                component_type: "library".into(),
                license: license.map(Into::into),
                source: Some("registry".into()),
            }],
            edges: vec![],
        })
    };
    apply(
        &graph,
        sbom("sha256:one", Some("MIT OR Apache-2.0")),
        "2026-10-16T03:00:00Z",
    )
    .await;
    apply(&graph, sbom("sha256:two", None), "2026-10-16T03:00:01Z").await;
    assert_eq!(
        count(
            &graph,
            "MATCH (p:Package {purl: 'pkg:cargo/itoa@1.0.18', license: 'MIT OR Apache-2.0'}) RETURN count(p) AS n"
        )
        .await,
        1,
        "an SBOM that gives no license erased the one recorded"
    );

    // ── An archive build has no commit to be BUILT_BY ────────────────────────
    let started = ProvenanceEvent::ExecutionStarted {
        build_id: "b1".into(),
        commit_sha: String::new(),
        ref_name: String::new(),
        repo_url: "https://static.crates.io/crates/openssl-sys/openssl-sys-0.9.117.crate".into(),
        triggered_by: Some("polar.analysis.scheduler".into()),
        backend: None,
        at: "2026-10-16T02:00:00Z".into(),
    };
    let started_again = || ProvenanceEvent::ExecutionStarted {
        build_id: "b1".into(),
        commit_sha: String::new(),
        ref_name: String::new(),
        repo_url: "https://static.crates.io/crates/openssl-sys/openssl-sys-0.9.117.crate".into(),
        triggered_by: Some("polar.analysis.scheduler".into()),
        backend: None,
        at: "2026-10-16T02:00:00Z".into(),
    };
    apply(&graph, started, "2026-10-16T02:00:01Z").await;
    apply(
        &graph,
        ProvenanceEvent::ExecutionCompleted {
            build_id: "b1".into(),
            duration_secs: 3,
            at: "2026-10-16T02:00:05Z".into(),
            log: None,
            refused_reports: 0,
        },
        "2026-10-16T02:00:06Z",
    )
    .await;
    assert_eq!(
        count(&graph, "MATCH (c:GitCommit) RETURN count(c) AS n").await,
        0
    );
    // The success marker the analysis scheduler relies on.
    assert_eq!(
        count(
            &graph,
            "MATCH (:BuildJob {build_id: 'b1'})-[:TRANSITIONED_TO]->(:BuildJobState {phase: 'succeeded'}) RETURN count(*) AS n"
        )
        .await,
        1
    );

    // ── A build's start seen again after it finished is the same state ───────
    // Redelivered, or late from a slow path, an hour after it happened: it lands on the start it already has, and the
    // build is still finished.
    apply(&graph, started_again(), "2026-10-16T03:00:00Z").await;
    assert_eq!(
        count(
            &graph,
            "MATCH (:BuildJob {build_id: 'b1'})-[:TRANSITIONED_TO]->(s:BuildJobState) RETURN count(s) AS n"
        )
        .await,
        2
    );
    assert_eq!(
        count(
            &graph,
            "MATCH (:BuildJob {build_id: 'b1'})-[:TRANSITIONED_TO]->(s:BuildJobState)
             WITH s ORDER BY s.valid_from DESC LIMIT 1
             WHERE s.phase = 'succeeded'
             RETURN count(s) AS n"
        )
        .await,
        1,
        "a start seen again made the finished build look running"
    );

    // ── A build nothing has been heard of for longer than the bound is judged lost ──
    let started = |build_id: &str, at: &str| ProvenanceEvent::ExecutionStarted {
        build_id: build_id.into(),
        commit_sha: String::new(),
        ref_name: String::new(),
        repo_url: "https://git.example/polar.git".into(),
        triggered_by: None,
        backend: None,
        at: at.into(),
    };
    let stage = |build_id: &str, at: &str| ProvenanceEvent::StageStarted {
        build_id: build_id.into(),
        stage_name: "build".into(),
        stage_id: "s1".into(),
        at: at.into(),
    };
    apply(
        &graph,
        started("quiet", "2026-10-01T00:00:00Z"),
        "2026-10-01T00:00:01Z",
    )
    .await;
    apply(
        &graph,
        stage("quiet", "2026-10-01T01:00:00Z"),
        "2026-10-01T01:00:01Z",
    )
    .await;
    apply(
        &graph,
        started("busy", "2026-10-01T00:00:00Z"),
        "2026-10-01T00:00:01Z",
    )
    .await;
    apply(
        &graph,
        stage("busy", "2026-11-08T11:00:00Z"),
        "2026-11-08T11:00:01Z",
    )
    .await;
    let now: chrono::DateTime<chrono::Utc> = "2026-11-08T12:00:00Z".parse().unwrap();
    let bound = std::time::Duration::from_secs(86_400);
    let stale = |graph: &Graph| {
        let graph = graph.clone();
        async move {
            let mut rows = graph
                .execute(stale_builds(&cutoff(now, bound)))
                .await
                .unwrap();
            let mut ids = Vec::new();
            while let Some(row) = rows.next().await.unwrap() {
                ids.push(row.get::<String>("build_id").unwrap());
            }
            ids.sort();
            ids
        }
    };
    // b1 finished, busy was heard of an hour ago: only quiet is lost.
    assert_eq!(stale(&graph).await, ["quiet"]);
    let judged = judged_lost(stale(&graph).await, now, bound).unwrap();
    let mut txn = graph.start_txn().await.unwrap();
    txn.run_queries(compile_graph_op(&judged).unwrap())
        .await
        .unwrap();
    txn.commit().await.unwrap();
    assert_eq!(
        count(&graph, "MATCH (j:BuildJob {build_id: 'quiet', lost_by: 'build-processor', lost_after_secs: 86400}) WHERE j.lost_at IS NOT NULL RETURN count(j) AS n").await,
        1
    );
    // Judged once.
    assert!(stale(&graph).await.is_empty());
    // Its end, arriving late, clears the judgement: it is heard from, and its end is what it reported.
    apply(
        &graph,
        ProvenanceEvent::ExecutionCompleted {
            build_id: "quiet".into(),
            duration_secs: 7200,
            at: "2026-10-01T02:00:00Z".into(),
            log: None,
            refused_reports: 0,
        },
        "2026-11-08T12:30:00Z",
    )
    .await;
    assert_eq!(
        count(&graph, "MATCH (j:BuildJob {build_id: 'quiet'}) WHERE j.lost_at IS NULL AND j.lost_by IS NULL AND j.lost_after_secs IS NULL RETURN count(j) AS n").await,
        1,
        "a build heard from is still judged lost"
    );
}

/// Each SBOM asserts its own dependency tree (Blitz's risk-gradients.md, slice 2). An unchanged tree is one node,
/// whichever SBOMs assert it and in whatever order they list it; a redelivered SBOM adds nothing; and nothing is
/// written into a global `DEPENDS_ON` web, from the root or from the tree.
#[tokio::test]
async fn an_unchanged_tree_is_one_node_and_a_redelivery_adds_nothing() {
    let container = Neo4j::default()
        .with_version("5.26.2")
        .start()
        .await
        .unwrap();
    let config = neo4rs::ConfigBuilder::new()
        .uri(format!(
            "bolt://{}:{}",
            container.get_host().await.unwrap(),
            container.image().bolt_port_ipv4().unwrap()
        ))
        .user(container.image().user().unwrap())
        .password(container.image().password().unwrap())
        .build()
        .unwrap();
    let graph = Graph::connect(config).unwrap();

    const ROOT: &str = "pkg:cargo/polar@1.0.0";
    const ITOA: &str = "pkg:cargo/itoa@1.0.18";
    const RYU: &str = "pkg:cargo/ryu@1.0.20";
    const SERDE: &str = "pkg:cargo/serde@1.0.228";
    let package = |purl: &str| PackageRef {
        purl: purl.into(),
        name: String::new(),
        version: String::new(),
        component_type: "library".into(),
        license: None,
        source: None,
    };
    let sbom = |hash: &str, root: &str, components: &[&str], edges: Vec<(&str, Vec<&str>)>| {
        ProvenanceEvent::SbomAnalyzed(SbomGraphFragment {
            artifact_content_hash: hash.into(),
            filename: format!("{hash}.cdx.json"),
            root: Some(package(root)),
            components: components.iter().map(|c| package(*c)).collect(),
            edges: edges
                .into_iter()
                .map(|(from, to)| DependencyEdge {
                    from_ref: from.into(),
                    to_refs: to.into_iter().map(Into::into).collect(),
                })
                .collect(),
        })
    };
    let polar = |hash: &str, components: &[&str]| {
        sbom(
            hash,
            ROOT,
            components,
            vec![(ROOT, vec![ITOA, RYU]), (ITOA, vec![SERDE])],
        )
    };

    // One SBOM delivered twice, and another build's SBOM of the same tree, listed in another order.
    apply(
        &graph,
        polar("sha256:one", &[ITOA, RYU, SERDE]),
        "2026-11-11T00:00:00Z",
    )
    .await;
    apply(
        &graph,
        polar("sha256:one", &[ITOA, RYU, SERDE]),
        "2026-11-11T00:00:01Z",
    )
    .await;
    apply(
        &graph,
        polar("sha256:two", &[SERDE, RYU, ITOA]),
        "2026-11-11T01:00:00Z",
    )
    .await;

    assert_eq!(
        count(&graph, "MATCH (t:DependencyTree) RETURN count(t) AS n").await,
        1
    );
    assert_eq!(
        count(
            &graph,
            "MATCH (:Sbom)-[r:ASSERTS]->(:DependencyTree) RETURN count(r) AS n"
        )
        .await,
        2
    );
    assert_eq!(
        count(
            &graph,
            "MATCH (:DependencyTree)-[r:INCLUDES]->(:Package) RETURN count(r) AS n"
        )
        .await,
        3
    );
    assert_eq!(
        count(
            &graph,
            "MATCH (:DependencyTree)-[r:INCLUDES {direct: true}]->(:Package) RETURN count(r) AS n"
        )
        .await,
        2
    );
    assert_eq!(
        count(
            &graph,
            "MATCH (t:DependencyTree {complete: true}) \
             WHERE size(t.edges_from) = 3 AND size(t.edges_to) = 3 AND size(t.gaps) = 0 \
             RETURN count(t) AS n"
        )
        .await,
        1
    );
    // The pairs read back from the two aligned lists, as a reader takes them.
    assert_eq!(
        count(
            &graph,
            "MATCH (t:DependencyTree) UNWIND range(0, size(t.edges_from) - 1) AS i \
             WITH t.edges_from[i] AS from, t.edges_to[i] AS to \
             WHERE (from = 'pkg:cargo/polar@1.0.0' AND to IN ['pkg:cargo/itoa@1.0.18', 'pkg:cargo/ryu@1.0.20']) \
                OR (from = 'pkg:cargo/itoa@1.0.18' AND to = 'pkg:cargo/serde@1.0.228') \
             RETURN count(*) AS n"
        )
        .await,
        3
    );

    // A root with no entry of its own: an incomplete tree, whose direct dependencies are unknown, and no flat edges.
    let other = "pkg:cargo/other@1.0.0";
    apply(
        &graph,
        sbom(
            "sha256:three",
            other,
            &[ITOA, SERDE],
            vec![(ITOA, vec![SERDE])],
        ),
        "2026-11-11T02:00:00Z",
    )
    .await;
    assert_eq!(
        count(
            &graph,
            "MATCH (:Sbom {artifact_content_hash: 'sha256:three'})-[:ASSERTS]->(t:DependencyTree {complete: false}) \
             WHERE t.gaps = ['no-root-entry'] \
             MATCH (t)-[r:INCLUDES]->(:Package) WHERE r.direct IS NULL \
             RETURN count(r) AS n"
        )
        .await,
        2
    );
    assert_eq!(
        count(&graph, "MATCH ()-[r:DEPENDS_ON]->() RETURN count(r) AS n").await,
        0
    );
}

/// A fact is one node by its content: the same fact from two builds, one of them delivered twice, is one Fact, reported
/// by each build once, about the binary it names and naming the layer it names.
#[tokio::test]
async fn a_fact_is_one_node_reported_by_each_build() {
    let container = Neo4j::default()
        .with_version("5.26.2")
        .start()
        .await
        .unwrap();
    let config = neo4rs::ConfigBuilder::new()
        .uri(format!(
            "bolt://{}:{}",
            container.get_host().await.unwrap(),
            container.image().bolt_port_ipv4().unwrap()
        ))
        .user(container.image().user().unwrap())
        .password(container.image().password().unwrap())
        .build()
        .unwrap();
    let graph = Graph::connect(config).unwrap();

    const BINARY: &str = "sha256:0101010101010101010101010101010101010101010101010101010101010101";
    const LAYER: &str = "sha256:0202020202020202020202020202020202020202020202020202020202020202";
    let fact = |build_id: &str| {
        ProvenanceEvent::FactReported(FactReportedPayload {
            build_id: build_id.into(),
            subject: FactRef {
                label: FactLabel::Binary,
                key: BINARY.into(),
            },
            name: "polar.image/found-at".into(),
            object: Some(FactRef {
                label: FactLabel::OCILayerDiffId,
                key: LAYER.into(),
            }),
            value: Some("/nix/store/x-cassini-server/bin/cassini-server".into()),
            tool: "polar-pipeline/oci.nu".into(),
            tool_version: "3.0.0".into(),
        })
    };
    apply(&graph, fact("b1"), "2026-11-11T00:00:00Z").await;
    apply(&graph, fact("b1"), "2026-11-11T00:00:01Z").await;
    apply(&graph, fact("b2"), "2026-11-11T01:00:00Z").await;

    assert_eq!(
        count(&graph, "MATCH (f:Fact) RETURN count(f) AS n").await,
        1
    );
    assert_eq!(
        count(
            &graph,
            "MATCH (:BuildJob)-[r:REPORTED]->(:Fact {name: 'polar.image/found-at'}) RETURN count(r) AS n"
        )
        .await,
        2
    );
    assert_eq!(
        count(
            &graph,
            "MATCH (:BuildJob {build_id: 'b1'})-[r:REPORTED]->(:Fact) WHERE r.at = '2026-11-11T00:00:00Z' RETURN count(r) AS n"
        )
        .await,
        1,
        "a redelivery moved when b1 reported it"
    );
    assert_eq!(
        count(
            &graph,
            "MATCH (b:Binary {content_hash: 'sha256:0101010101010101010101010101010101010101010101010101010101010101'})<-[:ABOUT]-(f:Fact)-[:NAMES]->(l:OCILayerDiffId {diff_id: 'sha256:0202020202020202020202020202020202020202020202020202020202020202'}) \
             WHERE f.value = '/nix/store/x-cassini-server/bin/cassini-server' RETURN count(*) AS n"
        )
        .await,
        1
    );
}
