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

//! What the GitLab pair's graph holds, held to what the seed said it should (`gitlab-seed check`): every node and edge expected is
//! there, by the names people use; what is there besides is said, and is no failure.

use gitlab_seed::check::{Graph, Neo4j, compare, graph_from, statements};
use gitlab_seed::dataset::{Size, dataset};
use gitlab_seed::expected::{Expected, expected};
use proptest::prelude::*;
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORIGIN: &str = "https://gitlab.gitlab-test.svc.cluster.local";

/// The graph that holds exactly what `e` expects.
fn holding(e: &Expected) -> Graph {
    Graph {
        nodes: e
            .nodes
            .iter()
            .flat_map(|(l, ns)| ns.iter().map(move |n| (l.clone(), n.clone())))
            .collect(),
        edges: e.edges.clone(),
    }
}

proptest! {
    /// A graph that holds what was expected passes; take any one node or edge away and that one, and only that, is missing.
    #[test]
    fn what_is_missing_is_exactly_what_the_graph_lacks(
        users in 1usize..6, projects in 1usize..8, which in any::<prop::sample::Index>(),
    ) {
        let e = expected(&dataset(&Size { users, projects, ci_projects: 2.min(projects) }), ORIGIN, "polar-test");
        let full = holding(&e);
        let r = compare(&e, &full);
        prop_assert!(r.passed() && r.beyond.is_empty());
        let node = which.get(&full.nodes.iter().cloned().collect::<Vec<_>>()).clone();
        let mut less = full.clone();
        less.nodes.remove(&node);
        prop_assert_eq!(compare(&e, &less).missing_nodes, vec![node]);
        let edge = which.get(&full.edges.iter().cloned().collect::<Vec<_>>()).clone();
        let mut fewer = full.clone();
        fewer.edges.remove(&edge);
        let r = compare(&e, &fewer);
        prop_assert!(!r.passed());
        prop_assert_eq!(r.missing_edges, vec![edge]);
    }
}

#[test]
fn what_the_graph_holds_besides_is_said_and_is_no_failure() {
    let e = expected(&dataset(&Size::default()), ORIGIN, "polar-test");
    let mut g = holding(&e);
    g.nodes.insert(("GitlabUser".into(), "root".into()));
    let r = compare(&e, &g);
    assert!(r.passed());
    assert_eq!(
        r.beyond,
        vec![("GitlabUser".to_string(), "root".to_string())]
    );
}

#[test]
fn rows_of_two_are_nodes_and_rows_of_three_are_edges() {
    let answer = json!({ "results": [
        { "columns": ["l", "n"], "data": [{ "row": ["GitlabUser", "seed-user-01"] }, { "row": ["GitlabUser", null] }] },
        { "columns": ["t", "a", "b"], "data": [{ "row": ["HAS_MEMBER", "polar-seed", "seed-user-01"] }] },
    ], "errors": [] });
    let g = graph_from(&answer).unwrap();
    assert_eq!(
        g.nodes.into_iter().collect::<Vec<_>>(),
        vec![("GitlabUser".to_string(), "seed-user-01".to_string())]
    );
    assert_eq!(g.edges.len(), 1);
    let refused = json!({ "results": [], "errors": [{ "code": "Neo.ClientError.Security.Unauthorized", "message": "no" }] });
    assert!(
        graph_from(&refused)
            .unwrap_err()
            .to_string()
            .contains("Unauthorized")
    );
}

#[test]
fn every_label_and_edge_the_mapping_draws_is_asked_for() {
    let asked = statements().join("\n");
    for name in [
        "GitlabUser",
        "GitlabGroup",
        "GitlabProject",
        "GitlabRunner",
        "GitlabInstance",
        "GitlabPipeline",
        "GitlabJob",
        "GitlabContainerRepository",
        "GitlabPackage",
        "SUBGROUP_OF",
        "HAS_MEMBER",
        "HAS_PIPELINE",
        "HAS_JOB",
        "EXECUTED_BY",
        "HAS_CONTAINER_REPOSITORY",
        "HAS_PACKAGE",
    ] {
        assert!(asked.contains(name), "{name}");
    }
}

#[tokio::test]
async fn neo4j_is_asked_as_neo4j_with_the_password_it_is_given() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/db/neo4j/tx/commit"))
        .and(header("authorization", "Basic bmVvNGo6cGFzcw=="))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "results": [], "errors": [] })),
        )
        .expect(1)
        .mount(&server)
        .await;
    let neo4j = Neo4j::new(
        server.uri().parse().unwrap(),
        "pass".into(),
        None,
        None,
        None,
    )
    .unwrap();
    let g = neo4j.graph().await.unwrap();
    assert!(g.nodes.is_empty() && g.edges.is_empty());
}

#[test]
fn a_client_certificate_is_taken_as_neo4j_asks_for_one() {
    // Polar's Neo4j asks for a client certificate: an administrator's, a PEM of the certificate and its key.
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["djshepard".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let pem = format!("{}{}", cert.pem(), key.serialize_pem());
    Neo4j::new(
        ORIGIN.parse().unwrap(),
        "pass".into(),
        Some(cert.pem().as_bytes()),
        Some(pem.as_bytes()),
        None,
    )
    .expect("a client built with the certificate");
}
