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

//! The graph labels an agent owns (writes) and reads (docs/architecture/soft-state.md, "The rules it keeps"):
//! declared beside its topics in `PolarAgent::GRAPH`, printed in its scaffold under `graph`, and written by the render
//! into the state agent's floor, as declared topics are written into the issuance floor. Applying the catalog is the
//! sign-off (docs/architecture/policy-enforcement.md, "Decisions"). A read is what the state agent answers for the
//! asker; an owned label is one whose nodes the agent writes, so a read of a label no workload owns has nothing behind
//! it and fails the render's check, like a topic with no other side.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What an agent does with a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphAccess {
    /// The agent writes nodes with the label: it is responsible for them.
    Owns,
    /// The agent asks the state agent about nodes with the label.
    Reads,
}

impl GraphAccess {
    pub fn as_str(self) -> &'static str {
        match self {
            GraphAccess::Owns => "owns",
            GraphAccess::Reads => "reads",
        }
    }
}

/// A label an agent declares it owns or reads, and what for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphDecl {
    pub label: &'static str,
    pub access: GraphAccess,
    pub purpose: &'static str,
}

impl GraphDecl {
    /// The agent writes nodes labelled `label`.
    pub const fn owns(label: &'static str, purpose: &'static str) -> Self {
        Self {
            label,
            access: GraphAccess::Owns,
            purpose,
        }
    }

    /// The agent asks the state agent about nodes labelled `label`.
    pub const fn reads(label: &'static str, purpose: &'static str) -> Self {
        Self {
            label,
            access: GraphAccess::Reads,
            purpose,
        }
    }
}

/// One label of an agent's graph schema, as the scaffold prints it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GraphEntry {
    pub label: String,
    pub access: GraphAccess,
    pub purpose: String,
    /// For a label the agent owns, each set of properties its nodes are merged on ([`PolarAgent::GRAPH_KEYS`]), from which
    /// its constraints are made. Written only when there is one, so a scaffold without keys is as it was.
    ///
    /// [`PolarAgent::GRAPH_KEYS`]: crate::PolarAgent::GRAPH_KEYS
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<Vec<String>>,
}

/// An edge an agent writes: of type `kind`, from a node labelled `from` to one labelled `to`, both labels it owns, and
/// what for. What a workload could touch is the labels it owns and the edges between them; one that declares no edge
/// says nothing about its edges (the agents written before edges were declared).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeDecl {
    pub from: &'static str,
    pub kind: &'static str,
    pub to: &'static str,
    pub purpose: &'static str,
}

impl EdgeDecl {
    pub const fn new(
        from: &'static str,
        kind: &'static str,
        to: &'static str,
        purpose: &'static str,
    ) -> Self {
        Self {
            from,
            kind,
            to,
            purpose,
        }
    }
}

/// One edge of an agent's graph schema, as the scaffold prints it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EdgeEntry {
    pub from: String,
    pub kind: String,
    pub to: String,
    pub purpose: String,
}

/// Whether `name` is a label or a property name the state agent will put in a query: `[A-Za-z_][A-Za-z0-9_]*`.
/// Cypher cannot take either as a parameter, so this is what stands between a name and the query text.
pub fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// An agent's graph schema: each (label, access) once, ordered by label and then access, whatever the order or the
/// repetition of the declarations. A pair declared twice keeps the least of its purposes, so the set does not depend
/// on which was written first (declaring one twice is a problem, [`problems`]).
pub fn graph_set(declared: &[GraphDecl]) -> Vec<GraphEntry> {
    let mut set: BTreeMap<(&str, GraphAccess), &str> = BTreeMap::new();
    for decl in declared {
        set.entry((decl.label, decl.access))
            .and_modify(|purpose| {
                if decl.purpose < *purpose {
                    *purpose = decl.purpose;
                }
            })
            .or_insert(decl.purpose);
    }
    set.into_iter()
        .map(|((label, access), purpose)| GraphEntry {
            label: label.to_string(),
            access,
            purpose: purpose.to_string(),
            keys: Vec::new(),
        })
        .collect()
}

/// An agent's edges: each (from, kind, to) once, in that order, whatever the order or the repetition of the declarations,
/// keeping the least of a repeated one's purposes, as [`graph_set`] does.
pub fn edge_set(declared: &[EdgeDecl]) -> Vec<EdgeEntry> {
    let mut set: BTreeMap<(&str, &str, &str), &str> = BTreeMap::new();
    for decl in declared {
        set.entry((decl.from, decl.kind, decl.to))
            .and_modify(|purpose| {
                if decl.purpose < *purpose {
                    *purpose = decl.purpose;
                }
            })
            .or_insert(decl.purpose);
    }
    set.into_iter()
        .map(|((from, kind, to), purpose)| EdgeEntry {
            from: from.to_string(),
            kind: kind.to_string(),
            to: to.to_string(),
            purpose: purpose.to_string(),
        })
        .collect()
}

/// What is wrong with an agent's edges: a type that is not an identifier, one with no purpose, an edge declared twice, and
/// an end that is not a label the agent owns, since an edge is written with the nodes at its ends.
pub fn edge_problems(edges: &[EdgeDecl], graph: &[GraphDecl]) -> Vec<String> {
    let owned = |label: &str| {
        graph
            .iter()
            .any(|d| d.access == GraphAccess::Owns && d.label == label)
    };
    let mut problems = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for edge in edges {
        let what = format!(
            "the edge `{}` from `{}` to `{}`",
            edge.kind, edge.from, edge.to
        );
        if !is_identifier(edge.kind) {
            problems.push(format!(
                "{what} is not an edge type: it must match [A-Za-z_][A-Za-z0-9_]*"
            ));
        }
        if edge.purpose.trim().is_empty() {
            problems.push(format!(
                "{what} has no purpose: say what the agent writes it for"
            ));
        }
        for end in [edge.from, edge.to] {
            if !owned(end) {
                problems.push(format!(
                    "{what} has `{end}` at one end, which the agent does not own: declare it in GRAPH"
                ));
            }
        }
        if !seen.insert((edge.from, edge.kind, edge.to)) {
            problems.push(format!("{what} is declared twice"));
        }
    }
    problems
}

/// What is wrong with an agent's graph declarations: a label that is not an identifier, one with no purpose, a pair
/// declared twice, and a read by an agent that is not a Cassini client, which has no way to ask.
pub fn problems(declared: &[GraphDecl], cassini_client: bool) -> Vec<String> {
    let mut problems = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for decl in declared {
        let what = format!(
            "the graph label `{}` ({})",
            decl.label,
            decl.access.as_str()
        );
        if !is_identifier(decl.label) {
            problems.push(format!(
                "{what} is not a label: it must match [A-Za-z_][A-Za-z0-9_]*"
            ));
        }
        if decl.purpose.trim().is_empty() {
            problems.push(format!(
                "{what} has no purpose: say what the agent writes or reads it for"
            ));
        }
        if !seen.insert((decl.label, decl.access)) {
            problems.push(format!("{what} is declared twice"));
        }
        if decl.access == GraphAccess::Reads && !cassini_client {
            problems.push(format!(
                "{what} is read, but the agent is not a Cassini client, so it cannot ask the state agent"
            ));
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn a_label_is_a_plain_identifier() {
        for good in ["JiraIssue", "_x", "a1", "A_B_9", "updated_ms"] {
            assert!(is_identifier(good), "{good}");
        }
        for bad in [
            "",
            "1a",
            "a-b",
            "a b",
            "a`b",
            "Jira:Issue",
            "a.b",
            "é",
            "a\n",
            "a)",
            "n})",
        ] {
            assert!(!is_identifier(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_set_is_ordered_and_holds_each_pair_once() {
        let set = graph_set(&[
            GraphDecl::reads("JiraIssue", "the cursor"),
            GraphDecl::owns("JiraIssue", "the issues"),
            GraphDecl::owns("JiraIssue", "again"),
            GraphDecl::owns("JiraUser", "the users"),
        ]);
        let pairs: Vec<(&str, GraphAccess)> =
            set.iter().map(|e| (e.label.as_str(), e.access)).collect();
        assert_eq!(
            pairs,
            [
                ("JiraIssue", GraphAccess::Owns),
                ("JiraIssue", GraphAccess::Reads),
                ("JiraUser", GraphAccess::Owns)
            ]
        );
        assert_eq!(set[0].purpose, "again");
    }

    #[test]
    fn a_bad_declaration_is_named() {
        let found = problems(
            &[
                GraphDecl::owns("Jira Issue", "x"),
                GraphDecl::owns("JiraUser", " "),
                GraphDecl::reads("JiraIssue", "x"),
                GraphDecl::reads("JiraIssue", "y"),
            ],
            false,
        );
        assert!(
            found
                .iter()
                .any(|p| p.contains("`Jira Issue`") && p.contains("not a label"))
        );
        assert!(
            found
                .iter()
                .any(|p| p.contains("`JiraUser`") && p.contains("no purpose"))
        );
        assert!(found.iter().any(|p| p.contains("declared twice")));
        assert!(found.iter().any(|p| p.contains("not a Cassini client")));
        assert!(problems(&[GraphDecl::reads("JiraIssue", "x")], true).is_empty());
    }

    #[test]
    fn an_edge_joins_labels_the_agent_owns_and_says_what_for() {
        let graph = [
            GraphDecl::owns("OpenApiApplication", "x"),
            GraphDecl::owns("OpenApiEndpoint", "x"),
            GraphDecl::reads("Pod", "x"),
        ];
        let good = EdgeDecl::new("OpenApiApplication", "HAS_ENDPOINT", "OpenApiEndpoint", "x");
        assert!(edge_problems(&[good], &graph).is_empty());
        // One type between other labels is another edge, not the same one twice.
        let back = EdgeDecl::new("OpenApiEndpoint", "HAS_ENDPOINT", "OpenApiApplication", "x");
        let to_itself = EdgeDecl::new(
            "OpenApiApplication",
            "HAS_ENDPOINT",
            "OpenApiApplication",
            "x",
        );
        assert!(edge_problems(&[good, back, to_itself], &graph).is_empty());
        let found = edge_problems(
            &[
                EdgeDecl::new("OpenApiApplication", "HAS ENDPOINT", "OpenApiEndpoint", "x"),
                EdgeDecl::new("OpenApiApplication", "RUNS_ON", "Pod", "x"),
                EdgeDecl::new("Nowhere", "FROM", "OpenApiEndpoint", "x"),
                EdgeDecl::new("OpenApiApplication", "HAS_ENDPOINT", "OpenApiEndpoint", " "),
                good,
            ],
            &graph,
        );
        assert!(found.iter().any(|p| p.contains("not an edge type")));
        assert!(
            found
                .iter()
                .any(|p| p.contains("`Pod` at one end") && p.contains("does not own"))
        );
        assert!(found.iter().any(|p| p.contains("`Nowhere` at one end")));
        assert!(found.iter().any(|p| p.contains("no purpose")));
        assert!(found.iter().any(|p| p.contains("declared twice")));
    }

    fn edges() -> impl Strategy<Value = Vec<(String, String, String, String)>> {
        prop::collection::vec(("[A-B]", "[X-Y]", "[A-B]", "[a-c]{1,3}"), 0..10)
    }

    fn leak_edges(raw: &[(String, String, String, String)]) -> Vec<EdgeDecl> {
        let leak = |s: &String| -> &'static str { Box::leak(s.clone().into_boxed_str()) };
        raw.iter()
            .map(|(from, kind, to, purpose)| {
                EdgeDecl::new(leak(from), leak(kind), leak(to), leak(purpose))
            })
            .collect()
    }

    fn decls() -> impl Strategy<Value = Vec<(String, bool, String)>> {
        prop::collection::vec(("[A-C][a-c]{0,2}", any::<bool>(), "[a-c]{1,3}"), 0..12)
    }

    fn leak(raw: &[(String, bool, String)]) -> Vec<GraphDecl> {
        raw.iter()
            .map(|(label, owns, purpose)| {
                let label: &'static str = Box::leak(label.clone().into_boxed_str());
                let purpose: &'static str = Box::leak(purpose.clone().into_boxed_str());
                if *owns {
                    GraphDecl::owns(label, purpose)
                } else {
                    GraphDecl::reads(label, purpose)
                }
            })
            .collect()
    }

    proptest! {
        /// The schema is a function of what is declared: the same however the declarations are ordered or repeated,
        /// the same each time it is computed, each (label, access) once, and exactly the pairs declared.
        #[test]
        fn the_set_is_deterministic_order_independent_and_each_pair_once(
            raw in decls(),
            seed in any::<u64>(),
        ) {
            let declared = leak(&raw);
            let mut shuffled = declared.clone();
            let n = shuffled.len();
            if n > 1 {
                let mut s = seed;
                for i in (1..n).rev() {
                    s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    shuffled.swap(i, (s >> 33) as usize % (i + 1));
                }
            }
            if seed % 3 == 0 {
                shuffled.extend(declared.iter().copied());
            }
            let set = graph_set(&declared);
            prop_assert_eq!(&set, &graph_set(&declared));
            prop_assert_eq!(&set, &graph_set(&shuffled));
            let pairs: Vec<(String, GraphAccess)> =
                set.iter().map(|e| (e.label.clone(), e.access)).collect();
            let mut unique = pairs.clone();
            unique.sort();
            unique.dedup();
            prop_assert_eq!(&pairs, &unique);
            let declared_pairs: std::collections::BTreeSet<(String, GraphAccess)> =
                declared.iter().map(|d| (d.label.to_string(), d.access)).collect();
            prop_assert_eq!(pairs.into_iter().collect::<std::collections::BTreeSet<_>>(), declared_pairs);
        }

        /// The edges are a function of what is declared, as the labels are: the same however they are ordered or
        /// repeated, each (from, kind, to) once, and exactly the edges declared.
        #[test]
        fn the_edges_are_deterministic_order_independent_and_each_once(
            raw in edges(),
            seed in any::<u64>(),
        ) {
            let declared = leak_edges(&raw);
            let mut shuffled = declared.clone();
            let mut s = seed;
            for i in (1..shuffled.len()).rev() {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                shuffled.swap(i, (s >> 33) as usize % (i + 1));
            }
            if seed % 3 == 0 {
                shuffled.extend(declared.iter().copied());
            }
            let set = edge_set(&declared);
            prop_assert_eq!(&set, &edge_set(&shuffled));
            let triples: Vec<(String, String, String)> =
                set.iter().map(|e| (e.from.clone(), e.kind.clone(), e.to.clone())).collect();
            let mut unique = triples.clone();
            unique.sort();
            unique.dedup();
            prop_assert_eq!(&triples, &unique);
            let declared_triples: std::collections::BTreeSet<(String, String, String)> = declared
                .iter()
                .map(|e| (e.from.to_string(), e.kind.to_string(), e.to.to_string()))
                .collect();
            prop_assert_eq!(triples.into_iter().collect::<std::collections::BTreeSet<_>>(), declared_triples);
        }

        /// No name that is not a plain identifier is ever accepted, whatever it holds.
        #[test]
        fn only_plain_identifiers_are_accepted(name in "\\PC{0,8}") {
            let plain = !name.is_empty()
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !name.starts_with(|c: char| c.is_ascii_digit());
            prop_assert_eq!(is_identifier(&name), plain);
        }
    }
}
