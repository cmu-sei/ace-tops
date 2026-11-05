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

//! Writes as graph operations. Names were judged when the projection was, and are judged again here against Cypher's own
//! rule, since a name is the one thing Cypher cannot take as a parameter.

use crate::{NodeId, Projection, Scalar, Write};
use polar::graph::controller::{
    GraphNodeKey, GraphOp, GraphValue, IntoGraphKey, NodeIdentity, Property,
    validate_cypher_identifier,
};
use polar::graph::schema::{KeyIndex, KeyIndexKind};

/// Every name a projection would put into Cypher that Cypher's own rule refuses.
pub fn identifier_problems(projection: &Projection) -> Vec<String> {
    let mut problems = Vec::new();
    let mut check = |what: String, name: &str| {
        if let Err(e) = validate_cypher_identifier(name) {
            problems.push(format!("{what}: {e}"));
        }
    };
    for rule in projection.rules() {
        check(format!("rule `{}`: the label", rule.name), &rule.label);
        if !rule.edge.is_empty() {
            check(format!("rule `{}`: the edge", rule.name), &rule.edge);
        }
        for field in rule.keys.iter().chain(&rule.set) {
            check(format!("rule `{}`: a property", rule.name), &field.name);
        }
    }
    problems
}

/// A uniqueness constraint for each label a projection writes, on what identifies it.
pub fn key_indexes(projection: &Projection) -> Vec<KeyIndex> {
    projection
        .shapes()
        .into_iter()
        .map(|(label, keys)| KeyIndex {
            label: label.to_string(),
            keys: keys.into_iter().map(str::to_string).collect(),
            kind: KeyIndexKind::Unique,
        })
        .collect()
}

#[derive(Debug)]
struct ProjectedKey(NodeId);

impl GraphNodeKey for ProjectedKey {
    fn identity(&self) -> NodeIdentity {
        NodeIdentity::runtime(
            vec![self.0.label.clone()],
            self.0
                .keys
                .iter()
                .map(|(name, value)| (name.clone(), value_of(value).into()))
                .collect(),
        )
    }
}

fn value_of(scalar: &Scalar) -> GraphValue {
    match scalar {
        Scalar::Text(s) => GraphValue::String(s.clone()),
        Scalar::Bool(b) => GraphValue::Bool(*b),
        Scalar::Integer(i) => GraphValue::I64(*i),
        Scalar::Real(r) => GraphValue::F64(*r),
    }
}

fn properties(props: Vec<(String, Scalar)>) -> Vec<Property> {
    props
        .into_iter()
        .map(|(name, value)| Property(name, value_of(&value)))
        .collect()
}

/// One document's writes as one transaction, all or nothing. None if it has no writes.
pub fn operation(writes: Vec<Write>) -> Option<GraphOp> {
    if writes.is_empty() {
        return None;
    }
    let ops = writes
        .into_iter()
        .map(|write| match write {
            Write::Node { id, props } => GraphOp::UpsertNode {
                key: ProjectedKey(id).into_key(),
                props: properties(props),
            },
            Write::Edge {
                from,
                to,
                kind,
                props,
            } => GraphOp::EnsureEdge {
                from: ProjectedKey(from).into_key(),
                to: ProjectedKey(to).into_key(),
                rel_type: kind,
                props: properties(props),
            },
        })
        .collect();
    Some(GraphOp::Transaction { ops })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Stamp;
    use serde_json::json;

    fn projection() -> Projection {
        Projection::well_formed(&crate::tests::openapi_body()).unwrap()
    }

    #[test]
    fn the_openapi_projection_passes_cypher_s_own_rule() {
        assert_eq!(identifier_problems(&projection()), Vec::<String>::new());
    }

    #[test]
    fn a_keyword_a_plain_name_check_lets_by_is_refused_for_the_graph() {
        let mut body = crate::tests::openapi_body();
        body["rules"][0]["set"][0]["name"] = json!("merge");
        let judged = Projection::well_formed(&body).unwrap();
        assert_eq!(identifier_problems(&judged).len(), 1);
    }

    #[test]
    fn constraints_are_one_per_label_on_what_identifies_it() {
        let names: Vec<String> = key_indexes(&projection())
            .iter()
            .map(KeyIndex::name)
            .collect();
        assert_eq!(
            names,
            [
                "polar_unique_OpenApiApplication_source",
                "polar_unique_OpenApiEndpoint_source_method_path",
            ]
        );
    }

    /// What reaches Cypher from a document is only ever a parameter.
    #[test]
    fn a_hostile_document_reaches_cypher_only_as_parameters() {
        let hostile = "x\"}) DETACH DELETE n //";
        let body = json!({
            "info": { "title": hostile },
            "paths": { hostile: { "get": { "operationId": hostile, "description": hostile } } }
        });
        let projected = projection()
            .project(
                hostile,
                &body,
                &Stamp {
                    workload: "w",
                    version: 1,
                    observed_at_unix_secs: 1,
                },
            )
            .unwrap();
        assert_eq!(projected.writes.len(), 3);
        for write in projected.writes {
            let ids = match write {
                Write::Node { id, .. } => vec![id],
                Write::Edge { from, to, .. } => vec![from, to],
            };
            for id in ids {
                let (pattern, params) = ProjectedKey(id).cypher_match("n");
                assert!(!pattern.contains("DETACH"), "{pattern}");
                assert!(!params.is_empty());
            }
        }
    }

    #[test]
    fn nothing_to_write_is_no_operation_and_a_document_is_one_transaction() {
        assert!(operation(vec![]).is_none());
        let projected = projection()
            .project(
                "s",
                &json!({}),
                &Stamp {
                    workload: "w",
                    version: 1,
                    observed_at_unix_secs: 1,
                },
            )
            .unwrap();
        assert!(
            matches!(operation(projected.writes), Some(GraphOp::Transaction { ops }) if ops.len() == 1)
        );
    }
}
