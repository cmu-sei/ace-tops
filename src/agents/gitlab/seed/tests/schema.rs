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

//! GitLab's schema from the test GitLab (`gitlab-seed schema`): asked by introspection, written as SDL with the license banner and the
//! version it came from, so what the G3 tests hold queries and samples to is the GitLab the pair is run against.

use gitlab_seed::gitlab::Gitlab;
use gitlab_seed::schema::{introspection_body, schema_file};
use serde_json::json;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn the_file_says_where_it_came_from_under_the_banner_and_then_is_the_schema() {
    let file = schema_file("19.5.3", "abc123", "type Query {\n  a: Int\n}\n");
    let lines: Vec<&str> = file.lines().collect();
    assert_eq!(lines[0], "# ACE Tool");
    assert!(file.contains("# DM26-0670"));
    assert!(file.contains(
        "# GitLab 19.5.3 (abc123), by introspection of the test GitLab (gitlab-seed schema)"
    ));
    assert!(file.ends_with("type Query {\n  a: Int\n}\n"));
}

#[test]
fn the_introspection_asked_for_is_a_query_of_the_schema() {
    let body = introspection_body();
    let query = body["query"].as_str().unwrap();
    assert!(
        query.contains("__schema") && query.contains("queryType"),
        "{query}"
    );
}

#[tokio::test]
async fn graphql_is_posted_with_the_token_and_its_data_returned() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/graphql"))
        .and(header("PRIVATE-TOKEN", "glpat-test"))
        .and(body_partial_json(
            json!({ "query": "{ metadata { version } }" }),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "data": { "metadata": { "version": "19.5.3" } } })),
        )
        .expect(1)
        .mount(&server)
        .await;
    let g = Gitlab::new(
        server.uri().parse().unwrap(),
        "glpat-test".into(),
        None,
        None,
    )
    .unwrap();
    let data = g
        .graphql(json!({ "query": "{ metadata { version } }" }))
        .await
        .unwrap();
    assert_eq!(data["metadata"]["version"], "19.5.3");
    let failing = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "errors": [{ "message": "no" }] })),
        )
        .mount(&failing)
        .await;
    let g = Gitlab::new(
        failing.uri().parse().unwrap(),
        "glpat-test".into(),
        None,
        None,
    )
    .unwrap();
    assert!(g.graphql(json!({ "query": "{ a }" })).await.is_err());
}
