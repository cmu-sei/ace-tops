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

use serde_json::{Value, json};

/// Longest query a source may sign.
pub const MAX_QUERY: usize = 16 * 1024;
/// The variable a paged query takes its cursor in.
pub const AFTER: &str = "after";

/// A source's GraphQL query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphQl {
    pub query: String,
}

/// A source's `graphql`, or every problem with it, each naming its field. `paged` is whether its paging is GraphQL's,
/// which needs the query to declare `$after`.
pub fn parse(value: &Value, paged: bool) -> Result<GraphQl, Vec<String>> {
    let Some(object) = value.as_object() else {
        return Err(vec!["`graphql` must be an object".to_string()]);
    };
    let mut problems: Vec<String> = object
        .keys()
        .filter(|k| k.as_str() != "query")
        .map(|k| format!("`graphql`: `{k}` is not a field"))
        .collect();
    match object.get("query").and_then(Value::as_str) {
        None => problems.push("`graphql`: `query` must be text".to_string()),
        Some(query) if query.len() > MAX_QUERY => problems.push(format!(
            "`graphql`: `query` is longer than {MAX_QUERY} bytes"
        )),
        Some(query) => {
            if let Err(why) = judge(query, paged) {
                problems.push(format!("`graphql`: `query` {why}"));
            }
        }
    }
    match (
        problems.is_empty(),
        object.get("query").and_then(Value::as_str),
    ) {
        (true, Some(query)) => Ok(GraphQl {
            query: query.to_string(),
        }),
        _ => Err(problems),
    }
}

/// Whether a query only reads: one operation, a `query`, declaring `$after` when it is paged.
fn judge(query: &str, paged: bool) -> Result<(), String> {
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
    if paged && !operation.variable_definitions().any(|v| v.name() == AFTER) {
        return Err(format!(
            "must declare `${AFTER}`, which its paging sets to each page's cursor"
        ));
    }
    Ok(())
}

/// What is POSTed for a page: the query, and the cursor it starts after, none on the first page.
pub fn request_body(query: &str, after: Option<&str>) -> Vec<u8> {
    serde_json::to_vec(&json!({ "query": query, "variables": { AFTER: after } }))
        .expect("JSON of text is JSON")
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

    proptest! {
        /// What is POSTed is the query and the cursor, whatever they hold, and nothing else.
        #[test]
        fn the_request_is_the_query_and_the_cursor(query in "[ -~]{0,64}", after in prop::option::of("[ -~]{0,32}")) {
            let sent: Value = serde_json::from_slice(&request_body(&query, after.as_deref())).unwrap();
            prop_assert_eq!(sent, json!({ "query": query, "variables": { "after": after } }));
        }
    }
}
