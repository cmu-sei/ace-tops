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

//! A source read as a GraphQL query (docs/architecture/http-observers.md, "GitLab"): POSTed as JSON to its address, its
//! only variable the cursor its paging sets. An observer only reads, so a query is judged when its section is signed: one
//! operation, a `query`, parsed rather than matched as text.

use crate::paging::{self, Paging, Style};
use serde_json::{Map, Value, json};

/// Longest query a source may sign.
pub const MAX_QUERY: usize = 16 * 1024;
/// The variable a paged query takes its cursor in.
pub const AFTER: &str = "after";
/// Items followed in one read of a source when its `each` does not say, and the most it may say.
pub const DEFAULT_MAX_ITEMS: u32 = 1000;
pub const MAX_ITEMS: u32 = 10_000;

/// A source's GraphQL query, and what it follows each item of its pages with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphQl {
    pub query: String,
    pub each: Option<Each>,
}

/// A query run for each item of a source's pages: a list nested in each item, as a project's pipelines, read whole by a
/// query of its own, paged by its own cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Each {
    /// Where the items are in each page: a JSON pointer.
    pub items: String,
    pub query: String,
    /// Each variable the query takes from the item, besides the cursor.
    pub variables: Vec<Variable>,
    /// GraphQL's paging, or none for a follow-up of one page.
    pub paging: Option<Paging>,
    /// Items followed in one read of the source.
    pub max_items: u32,
}

/// A variable of a follow-up: its name in the query, and a JSON pointer to its value in the item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variable {
    pub name: String,
    pub from: String,
}

/// A source's `graphql`, or every problem with it, each naming its field. `paged` is whether its paging is GraphQL's,
/// which needs the query to declare `$after`.
pub fn parse(value: &Value, paged: bool) -> Result<GraphQl, Vec<String>> {
    let Some(object) = value.as_object() else {
        return Err(vec!["`graphql` must be an object".to_string()]);
    };
    let mut problems: Vec<String> = object
        .keys()
        .filter(|k| !["query", "each"].contains(&k.as_str()))
        .map(|k| format!("`graphql`: `{k}` is not a field"))
        .collect();
    let declares: &[&str] = if paged { &[AFTER] } else { &[] };
    let query = query_of(
        object.get("query"),
        "`graphql`: `query`",
        declares,
        &mut problems,
    );
    let each = match object.get("each") {
        None | Some(Value::Null) => None,
        Some(value) => each(value, &mut problems),
    };
    match (problems.is_empty(), query) {
        (true, Some(query)) => Ok(GraphQl { query, each }),
        _ => Err(problems),
    }
}

/// A query, judged: text, not too long, and one `query` operation declaring `declares`.
fn query_of(
    value: Option<&Value>,
    at: &str,
    declares: &[&str],
    problems: &mut Vec<String>,
) -> Option<String> {
    match value.and_then(Value::as_str) {
        None => problems.push(format!("{at} must be text")),
        Some(query) if query.len() > MAX_QUERY => {
            problems.push(format!("{at} is longer than {MAX_QUERY} bytes"))
        }
        Some(query) => match judge(query, declares) {
            Ok(()) => return Some(query.to_string()),
            Err(why) => problems.push(format!("{at} {why}")),
        },
    }
    None
}

/// A source's `each`, or its problems pushed onto `problems`.
fn each(value: &Value, problems: &mut Vec<String>) -> Option<Each> {
    let at = "`graphql`: `each`";
    let Some(object) = value.as_object() else {
        problems.push(format!("{at} must be an object"));
        return None;
    };
    let given = |key: &str| object.get(key).filter(|v| !v.is_null());
    let before = problems.len();
    problems.extend(
        object
            .keys()
            .filter(|k| {
                !["items", "query", "variables", "paging", "max_items"].contains(&k.as_str())
            })
            .map(|k| format!("{at}: `{k}` is not a field")),
    );
    let items = match given("items").and_then(Value::as_str) {
        Some(items) if items.starts_with('/') && paging::is_pointer(items) => {
            Some(items.to_string())
        }
        _ => {
            problems.push(format!(
                "{at}: `items` must be a JSON pointer to the page's list, starting with `/`"
            ));
            None
        }
    };
    let mut variables: Vec<Variable> = Vec::new();
    match given("variables").and_then(Value::as_array) {
        None => problems.push(format!(
            "{at}: `variables` must be a list of {{name, from}}"
        )),
        Some(list) => {
            for v in list {
                let name = v["name"].as_str().unwrap_or_default();
                let from = v["from"].as_str().unwrap_or_default();
                let named = name
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                    && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
                if !named || !paging::is_pointer(from) || !v.is_object() {
                    problems.push(format!(
                        "{at}: `variables` are each {{name: a GraphQL variable's name, from: a JSON pointer into the item}}"
                    ));
                } else if name == AFTER {
                    problems.push(format!(
                        "{at}: `{AFTER}` is the cursor's, which the paging sets"
                    ));
                } else if variables.iter().any(|w| w.name == name) {
                    problems.push(format!("{at}: `variables` names `{name}` twice"));
                } else {
                    variables.push(Variable {
                        name: name.to_string(),
                        from: from.to_string(),
                    });
                }
            }
        }
    }
    let paging = match given("paging") {
        None => None,
        Some(value) => match paging::parse(value) {
            Ok(p) if matches!(p.style, Style::GraphQl { .. }) => Some(p),
            Ok(_) => {
                problems.push(format!(
                    "{at}: `paging` of a follow-up is graphql's or none"
                ));
                None
            }
            Err(these) => {
                problems.extend(these.into_iter().map(|p| format!("{at}: {p}")));
                None
            }
        },
    };
    let mut declares: Vec<&str> = variables.iter().map(|v| v.name.as_str()).collect();
    if paging.is_some() {
        declares.push(AFTER);
    }
    let query = query_of(
        given("query"),
        &format!("{at}: `query`"),
        &declares,
        problems,
    );
    let max_items = match given("max_items") {
        None => Some(DEFAULT_MAX_ITEMS),
        Some(v) => match v.as_u64() {
            Some(n) if (1..=u64::from(MAX_ITEMS)).contains(&n) => Some(n as u32),
            _ => {
                problems.push(format!("{at}: `max_items` must be from 1 to {MAX_ITEMS}"));
                None
            }
        },
    };
    match (problems.len() == before, items, query, max_items) {
        (true, Some(items), Some(query), Some(max_items)) => Some(Each {
            items,
            query,
            variables,
            paging,
            max_items,
        }),
        _ => None,
    }
}

/// Whether a query only reads: one operation, a `query`, declaring each of `declares`.
fn judge(query: &str, declares: &[&str]) -> Result<(), String> {
    let document = cynic_parser::parse_executable_document(query)
        .map_err(|_| "is not a GraphQL document".to_string())?;
    let operations: Vec<_> = document.operations().collect();
    let [operation] = operations[..] else {
        return Err(format!(
            "must hold one operation, and holds {}",
            operations.len()
        ));
    };
    if operation.operation_type() != cynic_parser::common::OperationType::Query {
        return Err("must be a `query`: an observer only reads".to_string());
    }
    for name in declares {
        if !operation.variable_definitions().any(|v| v.name() == *name) {
            return Err(if *name == AFTER {
                format!("must declare `${AFTER}`, which its paging sets to each page's cursor")
            } else {
                format!("must declare `${name}`, which is taken from each item")
            });
        }
    }
    Ok(())
}

/// What is POSTed for a page: the query, an item's variables for a follow-up, and the cursor it starts after, none on the
/// first page.
pub fn request_body(query: &str, after: Option<&str>, variables: &Map<String, Value>) -> Vec<u8> {
    let mut variables = variables.clone();
    variables.insert(AFTER.to_string(), json!(after));
    serde_json::to_vec(&json!({ "query": query, "variables": variables })).expect("JSON is JSON")
}

/// Whether an answer says the query failed: `errors`, and no `data` to publish. Its messages are not repeated.
pub fn failed(body: &[u8]) -> bool {
    let Ok(answer) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    let errors = answer["errors"].as_array().is_some_and(|e| !e.is_empty());
    errors && answer["data"].is_null()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paging::{Paging, Style};
    use proptest::prelude::*;

    const PAGED: &str = "query Projects($after: String) { projects(after: $after) { nodes { id } pageInfo { endCursor hasNextPage } } }";

    fn problems(value: Value, paged: bool) -> Vec<String> {
        parse(&value, paged).unwrap_err()
    }

    #[test]
    fn a_query_is_taken_and_a_paged_one_declares_its_cursor() {
        assert_eq!(
            parse(&json!({ "query": PAGED }), true).unwrap().query,
            PAGED
        );
        let unpaged = "{ metadata { version } }";
        assert_eq!(
            parse(&json!({ "query": unpaged }), false).unwrap().query,
            unpaged
        );
        let p = problems(json!({ "query": unpaged }), true);
        assert!(p.iter().any(|p| p.contains("$after")), "{p:?}");
    }

    /// An observer only reads: what is not one `query` operation is refused, by what the parser says the document is.
    #[test]
    fn anything_but_one_query_operation_is_refused_when_signed() {
        let cases: &[(&str, &str)] = &[
            (
                "mutation { destroyProject(input: {id: \"1\"}) { errors } }",
                "query",
            ),
            ("subscription { issueUpdated { id } }", "query"),
            ("query A { a } query B { b }", "one operation"),
            ("fragment F on Project { id }", "one operation"),
            ("query { unclosed", "GraphQL"),
            ("", "GraphQL"),
            // A mutation spelled in a way a text match would miss is still one.
            ("  mutation\n#{ query\n { x }", "query"),
        ];
        for (query, says) in cases {
            let p = problems(json!({ "query": query }), false);
            assert!(p.iter().any(|p| p.contains(says)), "{query:?}: {p:?}");
        }
        for bad in [
            json!("{ a }"),
            json!({}),
            json!({ "query": 7 }),
            json!({ "query": "{ a }", "variables": {} }),
        ] {
            assert!(parse(&bad, false).is_err(), "{bad}");
        }
        let long = format!("{{ a{} }}", " ".repeat(MAX_QUERY));
        assert!(
            problems(json!({ "query": long }), false)
                .iter()
                .any(|p| p.contains("long"))
        );
    }

    #[test]
    fn a_failed_answer_is_errors_with_no_data_and_partial_data_is_not() {
        assert!(failed(br#"{"errors": [{"message": "no"}]}"#));
        assert!(failed(br#"{"errors": [{"message": "no"}], "data": null}"#));
        assert!(!failed(
            br#"{"errors": [{"message": "partly"}], "data": {"a": 1}}"#
        ));
        assert!(!failed(br#"{"data": {"a": 1}}"#));
        assert!(
            !failed(b"not json"),
            "not GraphQL's to say: the processor's guard is"
        );
    }

    const OUTER: &str = "query($after: String) { projects(after: $after) { nodes { fullPath } pageInfo { endCursor hasNextPage } } }";
    const FOLLOW: &str = "query($fullPath: ID!, $after: String) { project(fullPath: $fullPath) { id pipelines(after: $after) { nodes { id } pageInfo { endCursor hasNextPage } } } }";

    fn each(changes: impl FnOnce(&mut Value)) -> Value {
        let mut each = json!({
            "items": "/data/projects/nodes",
            "query": FOLLOW,
            "variables": [{ "name": "fullPath", "from": "/fullPath" }],
            "paging": { "style": "graphql", "connection": "/data/project/pipelines", "max_pages": 20 },
            "max_items": 50
        });
        changes(&mut each);
        json!({ "query": OUTER, "each": each })
    }

    /// A source may follow each item of its pages with a query of its own, its variables taken from the item.
    #[test]
    fn a_source_may_follow_each_item_with_a_query_of_its_own() {
        let read = parse(&each(|_| {}), true).unwrap();
        let each_read = read.each.expect("each");
        assert_eq!(each_read.items, "/data/projects/nodes");
        assert_eq!(each_read.query, FOLLOW);
        assert_eq!(
            each_read.variables,
            [Variable {
                name: "fullPath".into(),
                from: "/fullPath".into()
            }]
        );
        assert_eq!(
            each_read.paging,
            Some(Paging {
                style: Style::GraphQl {
                    connection: "/data/project/pipelines".into()
                },
                max_pages: 20
            })
        );
        assert_eq!(each_read.max_items, 50);
        let unpaged = parse(
            &each(|e| {
                e.as_object_mut().unwrap().remove("paging");
                e["max_items"] = Value::Null;
                e["query"] = json!("query($fullPath: ID!) { project(fullPath: $fullPath) { id } }");
            }),
            true,
        )
        .unwrap();
        assert_eq!(
            unpaged
                .each
                .as_ref()
                .map(|e| (e.paging.is_none(), e.max_items)),
            Some((true, DEFAULT_MAX_ITEMS))
        );
        assert_eq!(
            parse(&json!({ "query": OUTER, "each": null }), true)
                .unwrap()
                .each,
            None
        );
    }

    #[test]
    fn a_follow_up_that_cannot_work_is_refused_naming_its_field() {
        let cases: Vec<(Value, &str)> = vec![
            (
                each(|e| e["query"] = json!("mutation($fullPath: ID!) { a }")),
                "only reads",
            ),
            (
                each(|e| e["query"] = json!("query($after: String) { project { id } }")),
                "$fullPath",
            ),
            (
                each(|e| {
                    e["query"] =
                        json!("query($fullPath: ID!) { project(fullPath: $fullPath) { id } }")
                }),
                "$after",
            ),
            (
                each(|e| e["paging"] = json!({ "style": "link" })),
                "`paging`",
            ),
            (
                each(|e| e["variables"] = json!([{ "name": "full path", "from": "/fullPath" }])),
                "`variables`",
            ),
            (
                each(|e| e["variables"] = json!([{ "name": "after", "from": "/x" }])),
                "`after`",
            ),
            (
                each(|e| e["variables"] = json!([{ "name": "fullPath", "from": "fullPath" }])),
                "`variables`",
            ),
            (
                each(
                    |e| e["variables"] = json!([{ "name": "fullPath", "from": "/a" }, { "name": "fullPath", "from": "/b" }]),
                ),
                "twice",
            ),
            (each(|e| e["items"] = json!("data.projects")), "`items`"),
            (each(|e| e["max_items"] = json!(0)), "`max_items`"),
            (
                each(|e| e["max_items"] = json!(MAX_ITEMS + 1)),
                "`max_items`",
            ),
            (each(|e| e["then"] = json!("x")), "`then`"),
        ];
        for (value, says) in cases {
            let problems = parse(&value, true).unwrap_err();
            assert!(
                problems.iter().any(|p| p.contains(says)),
                "{says}: {problems:?}"
            );
        }
    }

    proptest! {
        /// What is POSTed is the query and the cursor, whatever they hold, and nothing else.
        #[test]
        fn the_request_is_the_query_and_the_cursor(query in "[ -~]{0,64}", after in prop::option::of("[ -~]{0,32}")) {
            let sent: Value = serde_json::from_slice(&request_body(&query, after.as_deref(), &Map::new())).unwrap();
            prop_assert_eq!(sent, json!({ "query": query, "variables": { "after": after } }));
        }

        /// An item's variables go with its follow-up beside the cursor, as they were taken from the item.
        #[test]
        fn an_item_s_variables_go_beside_the_cursor(
            vars in prop::collection::btree_map("[a-z][a-zA-Z0-9]{0,6}", "[ -~]{0,12}", 0..4),
            after in prop::option::of("[a-z0-9]{1,8}"),
        ) {
            prop_assume!(!vars.contains_key(AFTER));
            let variables: Map<String, Value> = vars.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
            let sent: Value = serde_json::from_slice(&request_body("{ a }", after.as_deref(), &variables)).unwrap();
            let mut expected = variables.clone();
            expected.insert(AFTER.to_string(), json!(after));
            prop_assert_eq!(&sent["variables"], &Value::Object(expected));
        }
    }
}
