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

//! The GitLab pair's tests: those every kind has, and GitLab's own. Its queries and samples are held to GitLab's GraphQL
//! schema, so a hand-written sample and the mapping cannot agree on a field GitLab does not have; its sources are read as a
//! deployment reads them, page by page, over TLS, with a token bound to the host.

use super::*;
use gitlab_http_observer::agent::GitlabObserver;
use polar_http_observer::graphql::GraphQl;
use polar_http_observer::paging::{Paging, Style};
use polar_http_testkit::graphql_schema::GraphQlSchema;
use polar_http_testkit::{Observed, Pair, block_on, signed_in_force};
use polar_projection::Write;
use serde_json::json;
use std::path::PathBuf;
use std::sync::OnceLock;

polar_agent_builder::polar_agent_tests!(GitlabProcessor);

polar_http_testkit::polar_http_tests! {
    observer: GitlabObserver,
    processor: GitlabProcessor,
    mapping: "examples/gitlab.dhall",
    samples: "examples/samples",
}

const TOKEN: &str = "glpat-a-token-found-nowhere-else";

fn here() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// GitLab's schema, as the older GitLab agents were written against it.
fn gitlab() -> &'static GraphQlSchema {
    static SCHEMA: OnceLock<GraphQlSchema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        GraphQlSchema::read(&here().join("../../gitlab/schema/src/gitlab.graphql")).unwrap()
    })
}

fn query(name: &str) -> String {
    let path = here().join("../queries").join(format!("{name}.graphql"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Each sample, and the query it is an answer to.
const ANSWERS: &[(&str, &str)] = &[("projects-1", "projects"), ("projects-2", "projects")];

fn sample(name: &str) -> serde_json::Value {
    let path = here().join("examples/samples").join(format!("{name}.json"));
    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
}

#[test]
fn every_query_is_one_gitlab_answers() {
    let dir = here().join("../queries");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) == Some("graphql") {
            let text = std::fs::read_to_string(&path).unwrap();
            gitlab()
                .check_query(&text)
                .unwrap_or_else(|p| panic!("{}: {p:#?}", path.display()));
            seen += 1;
        }
    }
    assert!(seen > 0);
}

/// Every sample is what its query brings back from GitLab, and none escapes being held to one.
#[test]
fn every_sample_is_what_its_query_brings_back() {
    for (name, q) in ANSWERS {
        gitlab()
            .check_answer(&query(q), &sample(name))
            .unwrap_or_else(|p| panic!("{name} as an answer to {q}: {p:#?}"));
    }
    for entry in std::fs::read_dir(here().join("examples/samples")).unwrap() {
        let file = entry.unwrap().file_name().into_string().unwrap();
        if let Some(name) = file
            .strip_suffix(".json")
            .filter(|n| !n.ends_with(".expected"))
        {
            assert!(
                ANSWERS.iter().any(|(s, _)| *s == name),
                "{name} says which query it answers in ANSWERS"
            );
        }
    }
}

fn nodes(observed: &[Observed], label: &str) -> Vec<polar_projection::NodeId> {
    observed
        .iter()
        .flat_map(|o| &o.writes)
        .filter_map(|w| match w {
            Write::Node { id, .. } if id.label == label => Some(id.clone()),
            _ => None,
        })
        .collect()
}

/// Projects as a deployment reads them: page by page by GitLab's cursor, over TLS, every page with the token, each page
/// published and written as it is read, each project keyed by the GitLab it came from.
#[test]
fn projects_are_read_page_by_page_by_their_cursor_with_their_token() {
    block_on(async {
        let kit = kit();
        let mapping = signed_in_force::<GitlabProcessor>(&kit).await;
        let mut pair =
            Pair::<GitlabObserver>::credentialed(PROCESSOR_NAME, mapping, "gitlab", TOKEN).await;
        let observed = pair
            .read_graphql(
                "projects",
                GraphQl {
                    query: query("projects"),
                    each: None,
                },
                Some(Paging {
                    style: Style::GraphQl {
                        connection: "/data/projects".to_string(),
                    },
                    max_pages: 10,
                }),
                &[
                    (
                        json!({ "after": null }),
                        std::fs::read(here().join("examples/samples/projects-1.json")).unwrap(),
                    ),
                    (
                        json!({ "after": "eyJpZCI6IjIifQ" }),
                        std::fs::read(here().join("examples/samples/projects-2.json")).unwrap(),
                    ),
                ],
            )
            .await;
        assert_eq!(observed.len(), 2, "one observation a page");
        let projects = nodes(&observed, "GitlabProject");
        assert_eq!(projects.len(), 3);
        let origin = &observed[0].observation.origin;
        assert!(origin.starts_with("https://localhost:"), "{origin}");
        assert!(projects.iter().all(|id| id.keys[0]
            == (
                "origin".to_string(),
                polar_projection::Scalar::Text(origin.clone())
            )));
        assert_eq!(
            pair.authorizations().await,
            vec![Some(format!("Bearer {TOKEN}")); 2],
            "every page with the token"
        );
    });
}
