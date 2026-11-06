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

const BOUNDS: Bounds<'static> = Bounds {
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
    edges: &[Edge {
        from: "OpenApiApplication",
        kind: "HAS_ENDPOINT",
        to: "OpenApiEndpoint",
    }],
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

/// A document the example's guard lets by, with these paths.
fn doc(paths: Value) -> Value {
    json!({ "openapi": "3.0.3", "info": { "title": "t" }, "paths": paths })
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
    let one = doc(json!({ "/a": { "get": { "description": "old" } }, "/b": { "get": {} } }));
    let two = doc(json!({ "/a": { "get": { "description": "new" } }, "/b": { "get": {} } }));
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
    let document = doc(json!({ "/a": { "get": { "operationId": "x" }, "put": {} } }));
    let projected = projection.project("s", &document, &stamp()).unwrap();
    assert_eq!(nodes(&projected, "OpenApiEndpoint").len(), 1);
    assert_eq!(projected.skipped, 1);
}

/// A document is a snapshot: what it no longer has must not stay on the node beside what it now says. Seen live, when a source
/// moved from a 3.0 document to a 2.0 one and its node held both versions.
#[test]
fn a_value_the_document_no_longer_has_is_cleared_and_not_left_behind() {
    let document = json!({ "swagger": "2.0", "paths": {}, "info": { "title": "t", "license": ["not a value"] } });
    let projected = openapi().project("s", &document, &stamp()).unwrap();
    let apps = nodes(&projected, "OpenApiApplication");
    assert_eq!(prop(&apps[0].1, "swagger"), Some(&text("2.0")));
    assert_eq!(prop(&apps[0].1, "openapi"), Some(&Scalar::Null), "absent");
    assert_eq!(
        prop(&apps[0].1, "license"),
        Some(&Scalar::Null),
        "not a value"
    );
    assert_eq!(prop(&apps[0].1, "title"), Some(&text("t")));
}

#[test]
fn a_key_is_never_null_it_skips_the_node() {
    let mut body = openapi_body();
    body["rules"][1]["keys"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "name": "op", "from": "operation.operationId" }));
    let projection = Projection::well_formed(&body).unwrap();
    let projected = projection
        .project("s", &doc(json!({ "/a": { "get": {} } })), &stamp())
        .unwrap();
    assert!(nodes(&projected, "OpenApiEndpoint").is_empty());
    assert_eq!(projected.skipped, 1);
}

/// The case the guard exists for: this would otherwise have cleared every value the application holds.
#[test]
fn a_response_that_is_not_the_document_writes_and_clears_nothing() {
    for response in [
        json!({ "error": "the database is down" }),
        json!({}),
        json!([]),
        json!(null),
        json!("maintenance"),
        // Close, but not what it was written for.
        json!({ "openapi": "4.0.0", "info": { "title": "t" }, "paths": {} }),
        json!({ "swagger": "1.2", "info": { "title": "t" }, "paths": {} }),
        json!({ "openapi": 3, "info": { "title": "t" }, "paths": {} }),
        json!({ "openapi": "3.0.3", "info": { "title": "t" } }),
        json!({ "openapi": "3.0.3", "paths": {} }),
        json!({ "openapi": "3.0.3", "info": { "title": null }, "paths": {} }),
    ] {
        assert!(
            matches!(
                openapi().project("s", &response, &stamp()),
                Err(Refused::Guard(_))
            ),
            "{response}"
        );
    }
}

#[test]
fn a_refusal_names_the_paths_and_never_what_the_document_said() {
    let response = json!({ "error": "password=hunter2", "openapi": "hunter2" });
    let refused = openapi()
        .project("s", &response, &stamp())
        .unwrap_err()
        .to_string();
    assert!(
        refused.contains("body.openapi or body.swagger"),
        "{refused}"
    );
    assert!(!refused.contains("hunter2"), "{refused}");
}

#[test]
fn a_guard_is_required_and_must_be_able_to_mean_something() {
    refused_for(|b| b["guard"] = json!([]), "no guard");
    refused_for(
        |b| b["guard"][0]["any_of"] = json!([]),
        "1 to 8 alternatives",
    );
    refused_for(
        |b| b["guard"][0]["any_of"][0]["path"] = json!("operation.id"),
        "from `source` or `body`",
    );
    refused_for(
        |b| b["guard"][0]["any_of"][0]["path"] = json!("body[0]"),
        "from `source` or `body`",
    );
    refused_for(
        |b| b["guard"][0]["any_of"][0]["prefixes"] = json!([""]),
        "empty prefix",
    );
    refused_for(
        |b| {
            b.as_object_mut().unwrap().remove("guard");
        },
        "not a projection",
    );
    refused_for(
        |b| b["guard"] = json!(vec![b["guard"][0].clone(); MAX_CHECKS + 1]),
        "at most",
    );
}

#[test]
fn every_write_carries_where_it_came_from() {
    let document = doc(json!({ "/a": { "get": {} } }));
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
    let document = doc(json!(paths));
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
fn an_edge_of_a_type_the_workload_writes_between_labels_it_does_not_join_is_refused() {
    // `HAS_ENDPOINT` from an endpoint to an endpoint: the type is in the schema, the edge is not.
    let mut body = openapi_body();
    let mut again = body["rules"][1].clone();
    again["name"] = json!("again");
    again["parent"] = json!("endpoint");
    again["each"] = json!([]);
    again["set"] = json!([]);
    body["rules"].as_array_mut().unwrap().push(again);
    Projection::well_formed(&body).unwrap();
    let problems = Projection::judged(&body, BOUNDS).unwrap_err();
    assert_eq!(
        problems,
        [
            "rule `again`: the edge `HAS_ENDPOINT` from `OpenApiEndpoint` to `OpenApiEndpoint` is not in this workload's part of the graph"
        ]
    );
}

/// Cypher's own rule, the one the graph controller holds every query to, is a mapping's rule before it is signed, so the
/// tool that signs one and the agent that takes it refuse the same names.
#[test]
fn a_name_cypher_would_refuse_is_refused_before_signing() {
    for (change, says) in [
        (
            &(|b: &mut Value| b["rules"][0]["set"][0]["name"] = json!("merge"))
                as &dyn Fn(&mut Value),
            "the property",
        ),
        (
            &|b: &mut Value| b["rules"][0]["label"] = json!("Delete"),
            "the label",
        ),
        (
            &|b: &mut Value| b["rules"][1]["edge"] = json!("DETACH"),
            "the edge type",
        ),
    ] {
        let mut body = openapi_body();
        change(&mut body);
        let problems = Projection::well_formed(&body).unwrap_err();
        assert!(
            problems
                .iter()
                .any(|p| p.contains(says) && p.contains("reserved Cypher keyword")),
            "{says}: {problems:?}"
        );
    }
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
    let document = doc(json!({ "/a": { "get": { "tags": ["x", "y"] } } }));
    let projected = projection.project("s", &document, &stamp()).unwrap();
    let tags = nodes(&projected, "OpenApiTag");
    assert_eq!(tags.len(), 2);
    assert_eq!(prop(&tags[0].1, "seen_at_path"), Some(&text("/a")));
}

/// Whether a guard lets a document by, read from what the language says rather than from the engine: a path finds a value
/// through objects' fields alone, a null is nothing, and a prefix asks for text that starts with it.
fn guard_holds(guard: &Value, source: &str, document: &Value) -> bool {
    let source = Value::String(source.to_string());
    guard.as_array().unwrap().iter().all(|check| {
        check["any_of"]
            .as_array()
            .unwrap()
            .iter()
            .any(|alternative| {
                let mut parts = alternative["path"].as_str().unwrap().split('.');
                let root = match parts.next() {
                    Some("source") => &source,
                    _ => document,
                };
                let found = parts.try_fold(root, |at, segment| match at {
                    Value::Object(fields) => fields.get(segment),
                    _ => None,
                });
                let prefixes = alternative["prefixes"].as_array().unwrap();
                match found {
                    None | Some(Value::Null) => false,
                    Some(_) if prefixes.is_empty() => true,
                    Some(found) => found.as_str().is_some_and(|text| {
                        prefixes
                            .iter()
                            .any(|p| text.starts_with(p.as_str().unwrap()))
                    }),
                }
            })
    })
}

/// A guarded mapping, and a document built against its guard: each path it reads from `body` is, at random, left as it
/// was, absent, null, text starting with one of its prefixes, text with the prefix later, or a number. So every way a check
/// can go is common, not only the ones a random document happens on.
fn guarded_case() -> impl Strategy<Value = (testing::Generated, Value)> {
    testing::guarded()
        .prop_flat_map(|generated| {
            let alternatives = generated.body["guard"]
                .as_array()
                .unwrap()
                .iter()
                .map(|check| check["any_of"].as_array().unwrap().len())
                .sum::<usize>();
            (
                Just(generated),
                prop::collection::vec(0..6usize, alternatives),
                testing::document(),
            )
        })
        .prop_map(|(generated, kinds, document)| {
            let mut document = if document.is_object() {
                document
            } else {
                json!({})
            };
            let alternatives = generated.body["guard"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|check| check["any_of"].as_array().unwrap().clone());
            for (alternative, kind) in alternatives.zip(kinds) {
                let path = alternative["path"].as_str().unwrap();
                let Some(rest) = path.strip_prefix("body.") else {
                    continue;
                };
                let prefix = alternative["prefixes"][0].as_str().unwrap_or("");
                let value = match kind {
                    0 => continue,
                    1 => None,
                    2 => Some(Value::Null),
                    3 => Some(json!(format!("{prefix}z{}", testing::MARK))),
                    4 => Some(json!(format!("z{prefix}{}", testing::MARK))),
                    _ => Some(json!(1)),
                };
                let segments: Vec<&str> = rest.split('.').collect();
                let (last, parents) = segments.split_last().unwrap();
                let mut at = &mut document;
                for segment in parents {
                    if !at[*segment].is_object() {
                        at[*segment] = json!({});
                    }
                    at = &mut at[*segment];
                }
                match value {
                    Some(value) => at[*last] = value,
                    None => {
                        at.as_object_mut().unwrap().remove(*last);
                    }
                }
            }
            (generated, document)
        })
}

/// Exactly the four stamps, saying where the write came from.
fn is_stamped(stamps: &[&(String, Scalar)], source: &str) -> bool {
    let mut got: Vec<(&str, &Scalar)> = stamps.iter().map(|(n, v)| (n.as_str(), v)).collect();
    got.sort_by_key(|(n, _)| *n);
    got == [
        ("polar_observed_at", &Scalar::Integer(1_000)),
        ("polar_projection_version", &Scalar::Integer(7)),
        ("polar_source", &text(source)),
        ("polar_workload", &text("openapi-processor")),
    ]
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
        let Ok(projected) = openapi().project("s", &document, &stamp()) else {
            return Ok(());
        };
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

    /// It holds exactly when each check does, whatever else the document says.
    #[test]
    fn the_guard_passes_exactly_when_its_checks_do(
        version in "[ -~]{0,6}|3\\.[0-9]\\.[0-9]",
        field in prop_oneof![Just("openapi"), Just("swagger"), Just("other")],
        title in prop::option::of("[ -~]{0,6}"),
        has_paths in any::<bool>(),
        extra in any_json(),
    ) {
        let mut document = json!({ "extra": extra, field: version });
        if let Some(title) = &title {
            document["info"] = json!({ "title": title });
        }
        if has_paths {
            document["paths"] = json!({});
        }
        let versioned = (field == "openapi" && version.starts_with("3."))
            || (field == "swagger" && version.starts_with("2."));
        let expected = versioned && title.is_some() && has_paths;
        let got = openapi().project("s", &document, &stamp());
        prop_assert_eq!(got.is_ok(), expected, "{}", document);
        if expected {
            prop_assert!(!got.unwrap().writes.is_empty());
        }
    }

    #[test]
    fn the_same_document_always_becomes_the_same_writes(document in any_json()) {
        let first = openapi().project("s", &document, &stamp());
        let second = openapi().project("s", &document, &stamp());
        prop_assert_eq!(first, second);
    }

    /// A document as a service returns it is what the mapping makes of it as JSON, and anything that is not JSON is refused
    /// as that and writes nothing.
    #[test]
    fn a_document_s_bytes_become_what_its_json_does(document in any_json(), junk in proptest::collection::vec(any::<u8>(), 0..64)) {
        let bytes = serde_json::to_vec(&document).unwrap();
        let expected = match openapi().project("s", &document, &stamp()) {
            Ok(projected) => Outcome::Write { writes: projected.writes, skipped: projected.skipped },
            Err(refused) => Outcome::Refused(refused.to_string()),
        };
        prop_assert_eq!(openapi().outcome("s", &bytes, &stamp()), expected);
        if serde_json::from_slice::<Value>(&junk).is_err() {
            let got = openapi().outcome("s", &junk, &stamp());
            prop_assert!(matches!(&got, Outcome::Refused(why) if why.starts_with("it is not JSON")), "{got:?}");
        }
    }

    /// Judging never panics, and nothing it lets by names a label, or an edge between two labels, outside the bound.
    #[test]
    fn any_body_is_judged_and_a_passed_one_stays_in_bounds(body in any_json()) {
        if let Ok(projection) = Projection::judged(&body, BOUNDS) {
            let rules = projection.rules();
            prop_assert!(rules.iter().all(|r| BOUNDS.shapes.iter().any(|s| s.label == r.label)));
            for rule in rules.iter().filter(|r| !r.edge.is_empty()) {
                let from = rules.iter().find(|p| p.name == rule.parent).map(|p| p.label.as_str());
                prop_assert!(BOUNDS.edges.iter().any(|e| Some(e.from) == from && e.kind == rule.edge && e.to == rule.label));
            }
        }
    }

    #[test]
    fn only_a_label_the_workload_declares_passes(label in "[A-Za-z_][A-Za-z0-9_]{0,12}|OpenApiApplication") {
        let mut body = openapi_body();
        body["rules"][0]["label"] = json!(label);
        prop_assert_eq!(Projection::judged(&body, BOUNDS).is_ok(), label == "OpenApiApplication");
    }

    /// The generator makes only what an author could sign, inside the schema it says, so what follows holds of mappings.
    #[test]
    fn every_generated_mapping_is_judged_inside_its_schema(generated in testing::mapping()) {
        let judged = generated.with_bounds(|bounds| Projection::judged(&generated.body, bounds));
        prop_assert!(judged.is_ok(), "{:?}\n{}", judged, generated.body);
    }

    /// A guard alone, with no way to pass that every document has: it refuses exactly when a reading of the language says a
    /// check fails, a null counting as nothing and a prefix as how text starts.
    #[test]
    fn a_guard_refuses_exactly_when_one_of_its_checks_fails(
        (generated, document) in guarded_case(),
        source in testing::source(),
    ) {
        let projection = generated
            .with_bounds(|bounds| Projection::judged(&generated.body, bounds))
            .unwrap();
        let refused = matches!(projection.project(&source, &document, &stamp()), Err(Refused::Guard(_)));
        prop_assert_eq!(
            refused,
            !guard_holds(&generated.body["guard"], &source, &document),
            "{}\n{}", generated.body["guard"], document
        );
    }

    /// For any mapping an author could sign and any document: the same writes each time, only what the mapping names,
    /// every write stamped, never a null key, and nothing at all on a failed guard.
    #[test]
    fn any_mapping_and_any_document_write_only_what_the_mapping_says(
        generated in testing::mapping(),
        source in testing::source(),
        document in testing::document(),
    ) {
        let projection = generated
            .with_bounds(|bounds| Projection::judged(&generated.body, bounds))
            .unwrap();
        let first = projection.project(&source, &document, &stamp());
        prop_assert_eq!(&first, &projection.project(&source, &document, &stamp()));
        let passes = guard_holds(&generated.body["guard"], &source, &document);
        let projected = match first {
            Err(Refused::Guard(_)) => {
                prop_assert!(!passes, "refused, though every check holds: {}", document);
                return Ok(());
            }
            Err(Refused::TooLarge) => panic!("a small document is never too large"),
            Ok(projected) => projected,
        };
        prop_assert!(passes, "let by, though a check fails: {}", document);
        let rules = projection.rules();
        let shapes = projection.shapes();
        for write in &projected.writes {
            match write {
                Write::Node { id, props } => {
                    let keys: Vec<&str> = id.keys.iter().map(|(k, _)| k.as_str()).collect();
                    prop_assert_eq!(shapes.get(id.label.as_str()), Some(&keys));
                    prop_assert!(id.keys.iter().all(|(_, v)| *v != Scalar::Null), "{:?}", id);
                    let (stamps, set): (Vec<_>, Vec<_>) =
                        props.iter().partition(|(name, _)| name.starts_with(STAMP_PREFIX));
                    prop_assert!(is_stamped(&stamps, &source), "{:?}", stamps);
                    for (name, _) in set {
                        prop_assert!(
                            rules.iter().any(|r| r.label == id.label && r.set.iter().any(|f| &f.name == name)),
                            "`{}` is set by no rule of `{}`", name, id.label
                        );
                    }
                }
                Write::Edge { from, to, kind, props } => {
                    prop_assert!(
                        rules.iter().any(|r| &r.edge == kind
                            && r.label == to.label
                            && rules.iter().any(|p| p.name == r.parent && p.label == from.label)),
                        "{} -{}-> {}", from.label, kind, to.label
                    );
                    let stamps: Vec<&(String, Scalar)> = props.iter().collect();
                    prop_assert!(is_stamped(&stamps, &source), "{:?}", props);
                }
            }
        }
    }

    #[test]
    fn only_a_plain_path_is_a_path(path in "[ -~]{0,16}") {
        if path_parts(&path).is_some() {
            prop_assert!(path.chars().all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c)));
            prop_assert!(!path.contains(".."));
        }
    }
}
