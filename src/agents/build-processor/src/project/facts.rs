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

//! Facts: what a build's tools found, each about a thing the graph knows by its key (build-orchestrator.md, the
//! `fact_reported` kind). The orchestrator relays one only when the build's mapping names it.
//!
//! ```text
//! (BuildJob)-[:REPORTED {at}]->(Fact {digest, name, value, tool, tool_version})
//! (Fact)-[:ABOUT]->(Binary | OCIArtifact | OCILayerDiffId | Package | BuildArtifact | Sbom)
//! (Fact)-[:NAMES]->(the same labels)                                     when it names an object
//! ```
//!
//! A fact is content-addressed, as a dependency tree is: the same fact from two builds is one node, reported by each.

use super::{edge, upsert};
use neo4rs::BoltType;
use polar::graph::controller::{GraphOp, GraphValue, Property, rel};
use polar::graph::nodes::builds::ArtifactNodeKey;
use polar::{FactLabel, FactRef, FactReportedPayload};
use tracing::trace;

/// The version of the form a fact's digest is taken over: a change to the form is a new version, so a digest never has two
/// meanings.
const FACT_FORM: &str = "polar.fact/1";

/// The label's name in the graph.
fn word(label: FactLabel) -> &'static str {
    match label {
        FactLabel::Binary => "Binary",
        FactLabel::OCIArtifact => "OCIArtifact",
        FactLabel::OCILayerDiffId => "OCILayerDiffId",
        FactLabel::Package => "Package",
        FactLabel::BuildArtifact => "BuildArtifact",
        FactLabel::Sbom => "Sbom",
    }
}

/// A ref as a fact's canonical form writes it: its label's name and its key.
fn ref_form(r: &FactRef) -> (&'static str, &str) {
    (word(r.label), r.key.as_str())
}

/// The graph's node a ref names, merged on its label's key.
fn node(r: &FactRef) -> ArtifactNodeKey {
    let key = r.key.clone();
    match r.label {
        FactLabel::Binary => ArtifactNodeKey::Binary { content_hash: key },
        FactLabel::OCIArtifact => ArtifactNodeKey::OCIArtifact { digest: key },
        FactLabel::OCILayerDiffId => ArtifactNodeKey::OCILayerDiffId { diff_id: key },
        FactLabel::Package => ArtifactNodeKey::Package { purl: key },
        FactLabel::BuildArtifact => ArtifactNodeKey::BuildArtifact { content_hash: key },
        FactLabel::Sbom => ArtifactNodeKey::Sbom {
            artifact_content_hash: key,
        },
    }
}

/// The digest a fact is keyed by: `sha256:` and the hex of the sha256 of the JSON of
/// `[FACT_FORM, subject, name, object, value, tool, tool_version]`, each ref as `[label, key]`. What build reported it is
/// not in it: the same fact from two builds is one node.
pub fn fact_digest(p: &FactReportedPayload) -> String {
    let form = (
        FACT_FORM,
        ref_form(&p.subject),
        &p.name,
        p.object.as_ref().map(ref_form),
        &p.value,
        &p.tool,
        &p.tool_version,
    );
    let canonical = serde_json::to_vec(&form).expect("text and options of text serialize");
    format!("sha256:{}", polar::artifact_uid_from_bytes(&canonical))
}

/// The writes for a fact a build reported: the fact, by its digest; its build's REPORTED edge to it, `at` set when it is
/// first reported; and its ABOUT and NAMES edges to the nodes it names. The raw Cypher must agree with
/// `ArtifactNodeKey::Fact`'s label and key (`Fact {digest}`).
pub fn fact_reported(p: FactReportedPayload, observed_at: &str) -> Vec<GraphOp> {
    trace!(
        "FactReported: {} about {:?} {}",
        p.name, p.subject.label, p.subject.key
    );
    let digest = fact_digest(&p);
    let fact = ArtifactNodeKey::Fact {
        digest: digest.clone(),
    };
    let mut props = vec![
        Property("name".into(), GraphValue::String(p.name)),
        Property("tool".into(), GraphValue::String(p.tool)),
        Property("tool_version".into(), GraphValue::String(p.tool_version)),
    ];
    if let Some(value) = p.value {
        props.push(Property("value".into(), GraphValue::String(value)));
    }
    let mut ops = vec![
        upsert(fact.clone(), props),
        edge(fact.clone(), rel::ABOUT, node(&p.subject), vec![]),
    ];
    if let Some(object) = &p.object {
        ops.push(edge(fact, rel::NAMES, node(object), vec![]));
    }
    ops.push(GraphOp::RawMergeWrite {
        cypher: "MERGE (f:Fact { digest: $digest }) \
                 MERGE (j:BuildJob { build_id: $build_id }) \
                 MERGE (j)-[r:REPORTED]->(f) \
                 SET r.at = coalesce(r.at, $observed_at)"
            .to_string(),
        params: vec![
            ("digest".to_string(), BoltType::from(digest)),
            ("build_id".to_string(), BoltType::from(p.build_id)),
            ("observed_at".to_string(), BoltType::from(observed_at)),
        ],
    });
    ops
}

#[cfg(test)]
mod tests {
    use super::*;
    use neo4rs::BoltType;
    use polar::graph::controller::{GraphValue, Property, compile_graph_op};
    use polar::{FactLabel, FactRef};
    use std::collections::BTreeSet;

    const T0: &str = "2026-11-11T00:00:00Z";
    const BINARY: &str = "sha256:0101010101010101010101010101010101010101010101010101010101010101";
    const LAYER: &str = "sha256:0202020202020202020202020202020202020202020202020202020202020202";

    fn found_at() -> FactReportedPayload {
        FactReportedPayload {
            build_id: "b1".into(),
            subject: FactRef {
                label: FactLabel::Binary,
                key: BINARY.into(),
            },
            name: "polar.image/found-at".into(),
            object: Some(FactRef {
                label: FactLabel::OCILayerDiffId,
                key: LAYER.into(),
            }),
            value: Some("/nix/store/x-cassini-server/bin/cassini-server".into()),
            tool: "polar-pipeline/oci.nu".into(),
            tool_version: "3.0.0".into(),
        }
    }

    /// Each edge written: (from's label, the relationship, to's label, to's key property and value).
    fn edges(ops: &[GraphOp]) -> Vec<(String, String, String, String, String)> {
        ops.iter()
            .filter_map(|op| match op {
                GraphOp::EnsureEdge {
                    from, rel_type, to, ..
                } => {
                    let to = to.identity();
                    let (key, value) = to.keys.first().cloned().expect("a key");
                    let BoltType::String(value) = value else {
                        panic!("a key that is not text: {value:?}");
                    };
                    Some((
                        from.identity().labels.join(":"),
                        rel_type.clone(),
                        to.labels.join(":"),
                        key,
                        value.value,
                    ))
                }
                _ => None,
            })
            .collect()
    }

    /// The props written on the Fact node.
    fn fact_props(ops: &[GraphOp]) -> Vec<(String, GraphValue)> {
        ops.iter()
            .find_map(|op| match op {
                GraphOp::UpsertNode { key, props } if key.identity().labels == ["Fact"] => Some(
                    props
                        .iter()
                        .map(|Property(k, v)| (k.clone(), v.clone()))
                        .collect(),
                ),
                _ => None,
            })
            .expect("no Fact written")
    }

    #[test]
    fn a_fact_is_reported_by_its_build_about_its_subject_naming_its_object() {
        let ops = fact_reported(found_at(), T0);
        let mut props = fact_props(&ops);
        props.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            props,
            [
                (
                    "name".to_string(),
                    GraphValue::String("polar.image/found-at".into())
                ),
                (
                    "tool".to_string(),
                    GraphValue::String("polar-pipeline/oci.nu".into())
                ),
                (
                    "tool_version".to_string(),
                    GraphValue::String("3.0.0".into())
                ),
                (
                    "value".to_string(),
                    GraphValue::String("/nix/store/x-cassini-server/bin/cassini-server".into())
                ),
            ]
        );
        let written = edges(&ops);
        assert!(
            written.contains(&(
                "Fact".into(),
                "ABOUT".into(),
                "Binary".into(),
                "content_hash".into(),
                BINARY.into()
            )),
            "{written:?}"
        );
        assert!(
            written.contains(&(
                "Fact".into(),
                "NAMES".into(),
                "OCILayerDiffId".into(),
                "diff_id".into(),
                LAYER.into()
            )),
            "{written:?}"
        );
        let reported = ops.iter().any(|op| {
            matches!(op, GraphOp::RawMergeWrite { cypher, params }
                if cypher.contains("REPORTED")
                    && cypher.contains("coalesce(r.at, $observed_at)")
                    && params.iter().any(|(k, v)| k == "build_id" && matches!(v, BoltType::String(s) if s.value == "b1")))
        });
        assert!(
            reported,
            "the build is not said to have reported it: {ops:?}"
        );
        for op in &ops {
            compile_graph_op(op).unwrap_or_else(|e| panic!("the controller refuses {op:?}: {e}"));
        }
    }

    #[test]
    fn a_fact_with_no_object_or_value_names_nothing_and_holds_none() {
        let mut fact = found_at();
        fact.object = None;
        fact.value = None;
        let ops = fact_reported(fact, T0);
        assert!(!edges(&ops).iter().any(|e| e.1 == "NAMES"), "{ops:?}");
        assert!(!fact_props(&ops).iter().any(|(k, _)| k == "value"));
    }

    /// The same fact is one node, whichever build reports it; any change to what it says is another.
    #[test]
    fn a_fact_is_one_node_by_its_content() {
        let base = found_at();
        let mut other_build = found_at();
        other_build.build_id = "b2".into();
        assert_eq!(fact_digest(&base), fact_digest(&other_build));
        assert!(fact_digest(&base).starts_with("sha256:") && fact_digest(&base).len() == 7 + 64);

        let changes: [fn(&mut FactReportedPayload); 9] = [
            |f| f.subject.key = LAYER.into(),
            |f| f.subject.label = FactLabel::BuildArtifact,
            |f| f.name = "polar.image/not-found".into(),
            |f| f.object = None,
            |f| f.object.as_mut().unwrap().key = BINARY.into(),
            |f| f.value = None,
            |f| f.value = Some("/bin/a".into()),
            |f| f.tool = "other".into(),
            |f| f.tool_version = "3.0.1".into(),
        ];
        let mut digests = BTreeSet::from([fact_digest(&base)]);
        for change in changes {
            let mut fact = found_at();
            change(&mut fact);
            digests.insert(fact_digest(&fact));
        }
        assert_eq!(digests.len(), 10, "{digests:?}");
    }

    /// A fact's subject is the graph's own node for its label, merged on that label's key.
    #[test]
    fn each_label_is_the_graphs_node_merged_on_its_key() {
        for (label, word, key) in [
            (FactLabel::Binary, "Binary", "content_hash"),
            (FactLabel::OCIArtifact, "OCIArtifact", "digest"),
            (FactLabel::OCILayerDiffId, "OCILayerDiffId", "diff_id"),
            (FactLabel::Package, "Package", "purl"),
            (FactLabel::BuildArtifact, "BuildArtifact", "content_hash"),
            (FactLabel::Sbom, "Sbom", "artifact_content_hash"),
        ] {
            let mut fact = found_at();
            fact.subject.label = label;
            let about: Vec<_> = edges(&fact_reported(fact, T0))
                .into_iter()
                .filter(|e| e.1 == "ABOUT")
                .collect();
            assert_eq!(about.len(), 1, "{label:?}");
            assert_eq!(
                (about[0].2.as_str(), about[0].3.as_str()),
                (word, key),
                "{label:?}"
            );
        }
    }
}
