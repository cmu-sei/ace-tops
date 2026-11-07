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

//! A service's GraphQL schema, which a kind's queries and samples are held to (docs/architecture/http-observers.md,
//! "GitLab", G3): a query that asks for a field the service does not have fails, and so does a sample that is not what the
//! query would bring back, so a hand-written sample and its mapping cannot agree on what the service never says.

use apollo_compiler::executable::{Selection, SelectionSet};
use apollo_compiler::schema::{ExtendedType, Type};
use apollo_compiler::validation::{DiagnosticList, Valid};
use apollo_compiler::{ExecutableDocument, Schema};
use serde_json::Value;
use std::path::Path;

/// A schema, validated as the GraphQL spec says.
pub struct GraphQlSchema(Valid<Schema>);

impl GraphQlSchema {
    pub fn parse(sdl: &str, name: &str) -> Result<Self, String> {
        Schema::parse_and_validate(sdl, name)
            .map(Self)
            .map_err(|e| {
                format!(
                    "{name} is not a valid schema: {}",
                    said(&e.errors).join("; ")
                )
            })
    }

    pub fn read(path: &Path) -> Result<Self, String> {
        let sdl = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&sdl, &path.display().to_string())
    }

    /// Every problem with `query` under this schema.
    pub fn check_query(&self, query: &str) -> Result<(), Vec<String>> {
        self.executable(query).map(|_| ())
    }

    fn executable(&self, query: &str) -> Result<Valid<ExecutableDocument>, Vec<String>> {
        ExecutableDocument::parse_and_validate(&self.0, query, "query.graphql")
            .map_err(|e| said(&e.errors))
    }

    /// Every way `answer` is not what `query` brings back: a key it did not select, a selected field missing, a null
    /// where its type says never, a list or object or scalar where the type says otherwise. `errors` beside `data` are
    /// allowed; with no `data`, the answer is a failure, which is a sample's to say.
    pub fn check_answer(&self, query: &str, answer: &Value) -> Result<(), Vec<String>> {
        let document = self.executable(query)?;
        let operation = document
            .operations
            .get(None)
            .map_err(|_| vec!["the query has not exactly one operation".to_string()])?;
        let Some(data) = answer.get("data").filter(|d| !d.is_null()) else {
            return Err(vec!["the answer has no `data`".to_string()]);
        };
        let mut problems = Vec::new();
        self.object(
            &document,
            &operation.selection_set,
            data,
            "data",
            &mut problems,
        );
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }

    /// An object against a selection set: each key a field it selects, each field it selects there.
    fn object(
        &self,
        document: &ExecutableDocument,
        selection: &SelectionSet,
        value: &Value,
        at: &str,
        problems: &mut Vec<String>,
    ) {
        let Some(object) = value.as_object() else {
            problems.push(format!("`{at}` is not an object, and its type is one"));
            return;
        };
        let mut fields = Vec::new();
        flatten(document, selection, &mut fields);
        for key in object.keys() {
            if key != "__typename" && !fields.iter().any(|(f, _)| f.response_key().as_str() == key)
            {
                problems.push(format!("`{at}.{key}` is not a field the query selects"));
            }
        }
        for (field, conditional) in &fields {
            let key = field.response_key().as_str();
            let at = format!("{at}.{key}");
            match object.get(key) {
                // A field of a fragment on another type is absent from an object of this one.
                None if *conditional => {}
                None => problems.push(format!("`{at}` is selected and missing")),
                Some(value) => self.value(
                    document,
                    field.ty(),
                    &field.selection_set,
                    value,
                    &at,
                    problems,
                ),
            }
        }
    }

    /// A value against its type: null only where it may be, a list for a list, an object for an object type, a scalar
    /// for a scalar of its kind.
    fn value(
        &self,
        document: &ExecutableDocument,
        ty: &Type,
        selection: &SelectionSet,
        value: &Value,
        at: &str,
        problems: &mut Vec<String>,
    ) {
        if value.is_null() {
            if ty.is_non_null() {
                problems.push(format!("`{at}` is null, and its type is never"));
            }
            return;
        }
        if ty.is_list() {
            match value.as_array() {
                Some(items) => {
                    for (i, item) in items.iter().enumerate() {
                        self.value(
                            document,
                            ty.item_type(),
                            selection,
                            item,
                            &format!("{at}[{i}]"),
                            problems,
                        );
                    }
                }
                None => problems.push(format!("`{at}` is not a list, and its type is one")),
            }
            return;
        }
        let name = ty.inner_named_type();
        match self.0.types.get(name) {
            Some(ExtendedType::Object(_) | ExtendedType::Interface(_) | ExtendedType::Union(_)) => {
                self.object(document, selection, value, at, problems)
            }
            Some(ExtendedType::Enum(e)) => {
                let named = value
                    .as_str()
                    .is_some_and(|v| e.values.keys().any(|k| k.as_str() == v));
                if !named {
                    problems.push(format!("`{at}` is not one of {name}'s values"));
                }
            }
            Some(ExtendedType::Scalar(_)) => {
                let fits = match name.as_str() {
                    "Boolean" => value.is_boolean(),
                    "Int" => value.is_i64() || value.is_u64(),
                    "Float" => value.is_number(),
                    "String" | "ID" => {
                        value.is_string() || (name.as_str() == "ID" && value.is_number())
                    }
                    // A custom scalar is any JSON that is not a list or an object.
                    _ => !value.is_array() && !value.is_object(),
                };
                if !fits {
                    problems.push(format!("`{at}` is not a {name}"));
                }
            }
            _ => problems.push(format!(
                "`{at}` is of a type the schema does not have: {name}"
            )),
        }
    }
}

/// The fields a selection set selects on its object, fragments spread in; each says whether it comes from a fragment
/// with a type condition, which an object of another type leaves out.
fn flatten<'d>(
    document: &'d ExecutableDocument,
    selection: &'d SelectionSet,
    fields: &mut Vec<(&'d apollo_compiler::executable::Field, bool)>,
) {
    for s in &selection.selections {
        match s {
            Selection::Field(f) => fields.push((f, false)),
            Selection::InlineFragment(f) => {
                let mut inner = Vec::new();
                flatten(document, &f.selection_set, &mut inner);
                let conditional = f.type_condition.is_some();
                fields.extend(inner.into_iter().map(|(f, c)| (f, c || conditional)));
            }
            Selection::FragmentSpread(spread) => {
                if let Some(fragment) = document.fragments.get(&spread.fragment_name) {
                    let mut inner = Vec::new();
                    flatten(document, &fragment.selection_set, &mut inner);
                    fields.extend(inner.into_iter().map(|(f, _)| (f, true)));
                }
            }
        }
    }
}

/// What the compiler said, each a line.
fn said(errors: &DiagnosticList) -> Vec<String> {
    errors
        .iter()
        .map(|d| match d.line_column_range() {
            Some(at) => format!(
                "{} (line {}, column {})",
                d.error, at.start.line, at.start.column
            ),
            None => d.error.to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SDL: &str = r#"
        type Query { projects(first: Int, after: String): ProjectConnection!  project(fullPath: ID!): Project }
        type ProjectConnection { nodes: [Project] pageInfo: PageInfo! }
        type PageInfo { endCursor: String hasNextPage: Boolean! }
        type Project { id: ID! fullPath: ID! name: String! starCount: Int! topics: [String!] lead: User visibility: Visibility }
        enum Visibility { private internal public }
        type User { id: ID! username: String! }
    "#;
    const QUERY: &str = "query($after: String) { projects(first: 10, after: $after) { nodes { id fullPath lead { username } visibility } pageInfo { endCursor hasNextPage } } }";

    fn schema() -> GraphQlSchema {
        GraphQlSchema::parse(SDL, "test.graphql").unwrap()
    }

    fn answer(nodes: Value) -> Value {
        json!({ "data": { "projects": { "nodes": nodes, "pageInfo": { "endCursor": null, "hasNextPage": false } } } })
    }

    #[test]
    fn a_query_the_schema_does_not_have_is_refused_and_one_it_does_is_taken() {
        schema().check_query(QUERY).unwrap();
        for (bad, says) in [
            ("{ projects { nodes { noSuchField } } }", "noSuchField"),
            ("{ projects { nodes } }", "subselection"),
            ("{ project { id } }", "fullPath"),
            ("not graphql", "syntax"),
        ] {
            let problems = schema().check_query(bad).unwrap_err();
            assert!(
                problems.iter().any(|p| p.contains(says)),
                "{bad}: {problems:?}"
            );
        }
    }

    #[test]
    fn an_answer_with_the_query_s_shape_is_taken() {
        let a = answer(json!([
            { "id": "gid://gitlab/Project/1", "fullPath": "g/a", "lead": { "username": "ada" }, "visibility": "private" },
            { "id": "gid://gitlab/Project/2", "fullPath": "g/b", "lead": null, "visibility": null },
            null
        ]));
        schema().check_answer(QUERY, &a).unwrap();
        // Errors beside data are GraphQL's partial answer.
        let mut partial = a.clone();
        partial["errors"] = json!([{ "message": "one field failed" }]);
        schema().check_answer(QUERY, &partial).unwrap();
    }

    #[test]
    fn an_answer_that_is_not_what_the_query_brings_back_is_refused_saying_where() {
        let node = || json!({ "id": "1", "fullPath": "g/a", "lead": null });
        let cases: Vec<(Value, &str)> = vec![
            // A key the query did not select.
            (
                answer(json!([ { "id": "1", "fullPath": "g/a", "lead": null, "name": "A" } ])),
                "name",
            ),
            // A selected field missing.
            (answer(json!([ { "id": "1", "lead": null } ])), "fullPath"),
            // Null where the type is non-null.
            (
                answer(json!([ { "id": null, "fullPath": "g/a", "lead": null } ])),
                "id",
            ),
            // An object where a scalar is, and a scalar where an object is.
            (
                answer(json!([ { "id": { "x": 1 }, "fullPath": "g/a", "lead": null } ])),
                "id",
            ),
            (
                answer(json!([ { "id": "1", "fullPath": "g/a", "lead": "ada" } ])),
                "lead",
            ),
            // A list where an object is, an object where a list is.
            (json!({ "data": { "projects": [] } }), "projects"),
            (
                json!({ "data": { "projects": { "nodes": node(), "pageInfo": { "endCursor": null, "hasNextPage": false } } } }),
                "nodes",
            ),
            // An enum's value that is not one of its values.
            (
                answer(
                    json!([ { "id": "1", "fullPath": "g/a", "lead": null, "visibility": "secret" } ]),
                ),
                "visibility",
            ),
            // A Boolean that is not one.
            (
                json!({ "data": { "projects": { "nodes": [], "pageInfo": { "endCursor": null, "hasNextPage": "no" } } } }),
                "hasNextPage",
            ),
        ];
        for (a, says) in cases {
            let problems = schema().check_answer(QUERY, &a).unwrap_err();
            assert!(
                problems.iter().any(|p| p.contains(says)),
                "{a}: {problems:?}"
            );
        }
    }

    /// The schema GitLab's agents are written against, as it is checked in: a query of the kind GitLab's sources sign is
    /// taken, and one asking for what GitLab does not have is not.
    #[test]
    fn gitlab_s_schema_is_read_and_holds_a_query_to_it() {
        let gitlab = GraphQlSchema::read(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../gitlab-http/schema/gitlab.graphql"),
        )
        .unwrap();
        gitlab
            .check_query("query($after: String) { projects(first: 10, after: $after) { nodes { id fullPath name } pageInfo { endCursor hasNextPage } } }")
            .unwrap();
        assert!(
            gitlab
                .check_query("{ projects { nodes { id noSuchField } } }")
                .is_err()
        );
    }
}
