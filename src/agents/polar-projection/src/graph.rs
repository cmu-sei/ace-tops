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

//! Writes as graph operations. Names were judged against Cypher's own rule when the projection was (`polar_cypher`), and the
//! graph controller holds every query to the same rule, since a name is the one thing Cypher cannot take as a parameter.

use crate::{NodeId, Scalar, Write};
use polar::graph::controller::{
    GraphNodeKey, GraphOp, GraphValue, IntoGraphKey, NodeIdentity, Property,
};

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
        Scalar::Null => GraphValue::Null,
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
    use crate::{Projection, Stamp};
    use serde_json::json;

    fn projection() -> Projection {
        Projection::well_formed(&crate::tests::openapi_body()).unwrap()
    }

    /// What reaches Cypher from a document is only ever a parameter.
    #[test]
    fn a_hostile_document_reaches_cypher_only_as_parameters() {
        let hostile = "x\"}) DETACH DELETE n //";
        let body = json!({
            "openapi": "3.0.3",
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
                    origin: "https://h.example",
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

    proptest::proptest! {
        /// Under any mapping an author could sign, whatever a document says: the graph controller takes the operation, and
        /// none of the document's text is in the Cypher it runs, only in its parameters.
        #[test]
        fn under_any_mapping_no_document_text_reaches_cypher(
            generated in crate::testing::mapping(),
            source in crate::testing::source(),
            document in crate::testing::document(),
        ) {
            let projection = generated
                .with_bounds(|bounds| Projection::judged(&generated.body, bounds))
                .unwrap();
            let stamp = Stamp { workload: "w", version: 1, observed_at_unix_secs: 1, origin: "https://h.example" };
            let Ok(projected) = projection.project(&source, &document, &stamp) else {
                return Ok(());
            };
            let Some(op) = operation(projected.writes) else {
                return Ok(());
            };
            let queries = polar::graph::controller::compile_graph_op(&op);
            proptest::prop_assert!(queries.is_ok(), "{:?}", queries.err());
            for query in queries.unwrap() {
                proptest::prop_assert!(
                    !query.query().contains(crate::testing::MARK),
                    "{}", query.query()
                );
            }
        }
    }

    #[test]
    fn nothing_to_write_is_no_operation_and_a_document_is_one_transaction() {
        assert!(operation(vec![]).is_none());
        let projected = projection()
            .project(
                "s",
                &json!({ "openapi": "3.1.0", "info": { "title": "t" }, "paths": {} }),
                &Stamp {
                    workload: "w",
                    version: 1,
                    observed_at_unix_secs: 1,
                    origin: "https://h.example",
                },
            )
            .unwrap();
        assert!(
            matches!(operation(projected.writes), Some(GraphOp::Transaction { ops }) if ops.len() == 1)
        );
    }
}
