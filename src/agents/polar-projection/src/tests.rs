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

use super::*;
use proptest::prelude::*;
use serde_json::json;

const BOUNDS: Bounds = Bounds {
    shapes: &[
        Shape {
            label: "OpenApiApplication",
            keys: &["source"],
        },
        Shape {
            label: "OpenApiEndpoint",
            keys: &["source", "method", "path"],
        },
    ],
    edges: &["HAS_ENDPOINT"],
};

fn stamp() -> Stamp<'static> {
    Stamp {
        workload: "openapi-processor",
        version: 7,
        observed_at_unix_secs: 1_000,
    }
}

/// `examples/openapi.dhall`, against the schema, imports off, as `polar-sign` reads an author's file.
pub(crate) fn openapi_body() -> Value {
    // Evaluated once: Dhall in a debug build takes long enough to be felt across thousands of property cases.
    static BODY: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    BODY.get_or_init(|| {
        let ty: serde_dhall::SimpleType = serde_dhall::from_str(SCHEMA)
            .imports(false)
            .parse()
            .unwrap();
        let simple: serde_dhall::SimpleValue =
            serde_dhall::from_str(include_str!("../examples/openapi.dhall"))
                .imports(false)
                .type_annotation(&ty)
                .parse()
                .unwrap();
        serde_json::to_value(&simple).unwrap()
    })
    .clone()
}

fn openapi() -> Projection {
    Projection::judged(&openapi_body(), BOUNDS).unwrap()
}

fn prop<'a>(props: &'a [(String, Scalar)], name: &str) -> Option<&'a Scalar> {
    props.iter().find(|(n, _)| n == name).map(|(_, v)| v)
}

fn text(s: &str) -> Scalar {
    Scalar::Text(s.to_string())
}

fn nodes(projected: &Projected, label: &str) -> Vec<(NodeId, Vec<(String, Scalar)>)> {
    projected
        .writes
        .iter()
        .filter_map(|w| match w {
            Write::Node { id, props } if id.label == label => Some((id.clone(), props.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn each_of_the_three_versions_becomes_an_application_and_its_endpoints() {
    for (field, version) in [
        ("swagger", "2.0"),
        ("openapi", "3.0.3"),
        ("openapi", "3.1.0"),
    ] {
        let document = json!({
            field: version,
            "info": { "title": "Pets", "version": "1.2", "license": { "name": "MIT" } },
            "paths": {
                "/pets": {
                    "get": { "operationId": "list", "deprecated": true },
                    "post": { "summary": "add" },
                    "parameters": [ { "name": "not an operation" } ]
                }
            }
        });
        let projected = openapi().project("shop", &document, &stamp()).unwrap();
        let apps = nodes(&projected, "OpenApiApplication");
        assert_eq!(apps.len(), 1, "{version}");
        assert_eq!(apps[0].0.keys, vec![("source".to_string(), text("shop"))]);
        assert_eq!(prop(&apps[0].1, "title"), Some(&text("Pets")));
        assert_eq!(prop(&apps[0].1, "license"), Some(&text("MIT")));
        assert_eq!(prop(&apps[0].1, field), Some(&text(version)));

        let endpoints = nodes(&projected, "OpenApiEndpoint");
        assert_eq!(endpoints.len(), 2, "`parameters` is not an operation");
        let get = endpoints
            .iter()
            .find(|(id, _)| id.keys.contains(&("method".to_string(), text("get"))))
            .unwrap();
        assert_eq!(
            get.0.keys,
            vec![
                ("source".to_string(), text("shop")),
                ("method".to_string(), text("get")),
                ("path".to_string(), text("/pets")),
            ]
        );
        assert_eq!(prop(&get.1, "deprecated"), Some(&Scalar::Bool(true)));
        assert_eq!(prop(&get.1, "operation_id"), Some(&text("list")));
        let edges = projected
            .writes
            .iter()
            .filter(|w| matches!(w, Write::Edge { kind, from, .. } if kind == "HAS_ENDPOINT" && from == &apps[0].0))
            .count();
        assert_eq!(edges, 2);
    }
}

#[test]
fn an_operation_with_no_id_keeps_its_own_node_and_a_new_description_keeps_the_same_one() {
    let one =
        json!({ "paths": { "/a": { "get": { "description": "old" } }, "/b": { "get": {} } } });
    let two =
        json!({ "paths": { "/a": { "get": { "description": "new" } }, "/b": { "get": {} } } });
    let first = nodes(
        &openapi().project("s", &one, &stamp()).unwrap(),
        "OpenApiEndpoint",
    );
    let second = nodes(
        &openapi().project("s", &two, &stamp()).unwrap(),
        "OpenApiEndpoint",
    );
    assert_eq!(first.len(), 2, "no operationId, still two");
    let ids = |n: &[(NodeId, Vec<(String, Scalar)>)]| {
        n.iter().map(|(i, _)| i.clone()).collect::<Vec<_>>()
    };
    assert_eq!(ids(&first), ids(&second), "what changed is a property");
}

#[test]
fn an_entry_that_cannot_be_identified_is_skipped_and_counted_and_the_rest_are_written() {
    let body = {
        let mut b = openapi_body();
        b["rules"][1]["keys"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "name": "op", "from": "operation.operationId" }));
        b
    };
    let projection = Projection::well_formed(&body).unwrap();
    let document = json!({ "paths": { "/a": { "get": { "operationId": "x" }, "put": {} } } });
    let projected = projection.project("s", &document, &stamp()).unwrap();
    assert_eq!(nodes(&projected, "OpenApiEndpoint").len(), 1);
    assert_eq!(projected.skipped, 1);
}

#[test]
fn every_write_carries_where_it_came_from() {
    let document = json!({ "paths": { "/a": { "get": {} } } });
    let projected = openapi().project("shop", &document, &stamp()).unwrap();
    assert_eq!(projected.writes.len(), 3);
    for write in &projected.writes {
        let props = match write {
            Write::Node { props, .. } | Write::Edge { props, .. } => props,
        };
        assert_eq!(prop(props, "polar_source"), Some(&text("shop")));
        assert_eq!(
            prop(props, "polar_workload"),
            Some(&text("openapi-processor"))
        );
        assert_eq!(
            prop(props, "polar_projection_version"),
            Some(&Scalar::Integer(7))
        );
        assert_eq!(
            prop(props, "polar_observed_at"),
            Some(&Scalar::Integer(1_000))
        );
    }
}

#[test]
fn a_document_over_the_bound_is_refused_whole() {
    let mut paths = serde_json::Map::new();
    for i in 0..=MAX_WRITES / 2 {
        paths.insert(format!("/{i}"), json!({ "get": {} }));
    }
    let document = json!({ "paths": paths });
    assert_eq!(
        openapi().project("s", &document, &stamp()),
        Err(Refused::TooLarge)
    );
}

/// One change to the good body, and what the refusal must mention.
fn refused_for(change: impl Fn(&mut Value), says: &str) {
    let mut body = openapi_body();
    change(&mut body);
    let problems = Projection::judged(&body, BOUNDS).unwrap_err();
    assert!(
        problems.iter().any(|p| p.contains(says)),
        "{says}: {problems:?}"
    );
}

#[test]
fn a_label_outside_the_workload_s_part_of_the_graph_is_refused() {
    for label in ["Pod", "JiraIssue", "Credential", "OpenApiAnythingElse"] {
        refused_for(
            |b| b["rules"][0]["label"] = json!(label),
            "this workload's part of the graph",
        );
    }
}

#[test]
fn a_signed_mapping_cannot_widen_what_the_workload_was_built_to_write() {
    // Other keys would make a parallel set of nodes, under a constraint made for the old ones.
    refused_for(
        |b| b["rules"][0]["keys"][0]["name"] = json!("id"),
        "is identified by",
    );
    refused_for(
        |b| {
            b["rules"][1]["keys"].as_array_mut().unwrap().pop();
        },
        "is identified by",
    );
    refused_for(
        |b| b["rules"][1]["edge"] = json!("OWNS"),
        "this workload's part of the graph",
    );
}

#[test]
fn inside_the_schema_a_signed_mapping_chooses_the_data() {
    let mut body = openapi_body();
    body["rules"][0]["set"][0]["from"] = json!("body.info.contact.name");
    body["rules"][1]["set"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "name": "tag_count", "from": "operation.x-count" }));
    body["rules"][1]["each"][1]["only"] = json!(["get"]);
    Projection::judged(&body, BOUNDS).unwrap();
}

#[test]
fn what_a_mapping_may_not_say_is_refused() {
    refused_for(|b| b["rules"] = json!([]), "no rules");
    refused_for(
        |b| b["rules"][0]["label"] = json!("OpenApi`x"),
        "not an identifier",
    );
    refused_for(
        |b| b["rules"][1]["edge"] = json!("HAS ENDPOINT"),
        "edge type",
    );
    refused_for(
        |b| b["rules"][0]["set"][0]["name"] = json!("a b"),
        "not an identifier",
    );
    refused_for(
        |b| b["rules"][1]["label"] = json!("OpenApi`x"),
        "not an identifier",
    );
    refused_for(
        |b| b["rules"][0]["set"][0]["name"] = json!("polar_source"),
        "engine's stamp",
    );
    refused_for(|b| b["rules"][0]["keys"] = json!([]), "no keys");
    refused_for(
        |b| b["rules"][1]["parent"] = json!("nowhere"),
        "not an earlier rule",
    );
    refused_for(|b| b["rules"][0]["edge"] = json!("X"), "needs a parent");
    refused_for(
        |b| b["rules"][1]["name"] = json!("application"),
        "another rule has that name",
    );
    refused_for(
        |b| b["rules"][1]["keys"][0]["from"] = json!("nothing.here"),
        "nothing it can see",
    );
    refused_for(
        |b| b["rules"][1]["each"][1]["over"] = json!("item[0]"),
        "not a path",
    );
    refused_for(
        |b| b["rules"][1]["each"][0]["key"] = json!("body"),
        "already in use",
    );
    refused_for(
        |b| b["rules"][0]["set"][0]["name"] = json!("source"),
        "written twice",
    );
    refused_for(
        |b| b["rules"][1]["label"] = json!("OpenApiApplication"),
        "other keys",
    );
    refused_for(|b| b["extra"] = json!(1), "not a projection");
    refused_for(|b| b["rules"][0]["extra"] = json!(1), "not a projection");
}

#[test]
fn a_parent_must_come_first_so_rules_cannot_form_a_cycle() {
    let mut body = openapi_body();
    let rules = body["rules"].as_array_mut().unwrap();
    rules.reverse();
    let problems = Projection::judged(&body, BOUNDS).unwrap_err();
    assert!(
        problems.iter().any(|p| p.contains("not an earlier rule")),
        "{problems:?}"
    );
}

#[test]
fn a_rule_cannot_read_what_only_its_sibling_bound() {
    let mut body = openapi_body();
    body["rules"][0]["set"][0]["from"] = json!("operation.summary");
    let problems = Projection::judged(&body, BOUNDS).unwrap_err();
    assert!(
        problems.iter().any(|p| p.contains("nothing it can see")),
        "{problems:?}"
    );
}

#[test]
fn a_child_sees_what_its_parent_bound() {
    let mut body = openapi_body();
    body["rules"].as_array_mut().unwrap().push(json!({
        "name": "tag", "parent": "endpoint",
        "each": [{ "key": "i", "value": "tag", "over": "operation.tags", "only": [] }],
        "label": "OpenApiTag",
        "keys": [{ "name": "name", "from": "tag" }],
        "set": [{ "name": "seen_at_path", "from": "path" }],
        "edge": "TAGGED"
    }));
    let projection = Projection::well_formed(&body).unwrap();
    let document = json!({ "paths": { "/a": { "get": { "tags": ["x", "y"] } } } });
    let projected = projection.project("s", &document, &stamp()).unwrap();
    let tags = nodes(&projected, "OpenApiTag");
    assert_eq!(tags.len(), 2);
    assert_eq!(prop(&tags[0].1, "seen_at_path"), Some(&text("/a")));
}

fn any_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::from),
        any::<i64>().prop_map(Value::from),
        "[ -~]{0,12}".prop_map(Value::from),
    ];
    leaf.prop_recursive(5, 64, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::from),
            prop::collection::btree_map(
                prop_oneof![
                    Just("paths".to_string()),
                    Just("info".to_string()),
                    Just("get".to_string()),
                    Just("title".to_string()),
                    "[ -~]{0,8}",
                ],
                inner,
                0..6
            )
            .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    /// Whatever a document says: structure from the mapping, the stamps on everything, and it ends.
    #[test]
    fn any_document_writes_only_what_the_mapping_says(document in any_json()) {
        let projected = openapi().project("s", &document, &stamp()).unwrap();
        let shapes = openapi();
        let shapes = shapes.shapes();
        for write in &projected.writes {
            match write {
                Write::Node { id, props } => {
                    let keys: Vec<&str> = id.keys.iter().map(|(k, _)| k.as_str()).collect();
                    prop_assert_eq!(shapes.get(id.label.as_str()), Some(&keys));
                    prop_assert!(props.iter().any(|(n, _)| n == "polar_workload"));
                    for (name, _) in props {
                        prop_assert!(
                            name.starts_with(STAMP_PREFIX)
                                || openapi().rules().iter().any(|r| r.label == id.label && r.set.iter().any(|f| &f.name == name)),
                            "{}", name
                        );
                    }
                }
                Write::Edge { kind, from, to, .. } => {
                    prop_assert_eq!(kind, "HAS_ENDPOINT");
                    prop_assert_eq!(&from.label, "OpenApiApplication");
                    prop_assert_eq!(&to.label, "OpenApiEndpoint");
                }
            }
        }
    }

    #[test]
    fn the_same_document_always_becomes_the_same_writes(document in any_json()) {
        let first = openapi().project("s", &document, &stamp()).unwrap();
        let second = openapi().project("s", &document, &stamp()).unwrap();
        prop_assert_eq!(first, second);
    }

    /// Judging never panics, and nothing it lets by names a label outside the bound.
    #[test]
    fn any_body_is_judged_and_a_passed_one_stays_in_bounds(body in any_json()) {
        if let Ok(projection) = Projection::judged(&body, BOUNDS) {
            prop_assert!(projection.rules().iter().all(|r| BOUNDS.shapes.iter().any(|s| s.label == r.label)));
        }
    }

    #[test]
    fn only_a_label_the_workload_declares_passes(label in "[A-Za-z_][A-Za-z0-9_]{0,12}|OpenApiApplication") {
        let mut body = openapi_body();
        body["rules"][0]["label"] = json!(label);
        prop_assert_eq!(Projection::judged(&body, BOUNDS).is_ok(), label == "OpenApiApplication");
    }

    #[test]
    fn only_a_plain_path_is_a_path(path in "[ -~]{0,16}") {
        if path_parts(&path).is_some() {
            prop_assert!(path.chars().all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c)));
            prop_assert!(!path.contains(".."));
        }
    }
}
