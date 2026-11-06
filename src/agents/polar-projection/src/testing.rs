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

//! Strategies for property tests of what takes a projection: any valid mapping, with the schema it fits, and documents
//! in its words, so a property can say what the engine does for every mapping an author could sign, not only the
//! example's. A mapping is made from small choices, each resolved against what is in scope where it is made, so every
//! one is well formed by construction and shrinks to a smaller one.

use crate::{Bounds, Edge, Shape};
use proptest::prelude::*;
use proptest::sample::Index;
use serde_json::{Value, json};

/// The labels a generated mapping may write.
pub const LABELS: [&str; 3] = ["Alpha", "Beta", "Gamma"];
/// What may identify a label, in the order given.
const KEY_SETS: [&[&str]; 4] = [&["k1"], &["k2"], &["k1", "k2"], &["k2", "k1"]];
/// The edge types it may write.
pub const EDGE_TYPES: [&str; 2] = ["LINKS", "HAS_PART"];
/// The properties it may set.
pub const PROPERTIES: [&str; 3] = ["p1", "p2", "p3"];
/// The segments its paths may have, which are also the keys a [`document`] uses most.
pub const SEGMENTS: [&str; 3] = ["x", "y", "z"];
/// What its guard's text may start with.
pub const PREFIXES: [&str; 3] = ["3.", "a", "x"];
/// Every string a [`document`] or [`source`] holds ends with it, and a well-formed mapping cannot hold it: anything with
/// it that reaches Cypher's text is a document's text there.
pub const MARK: char = '‡';

/// A path: a root and segments.
type PathChoice = (Index, Vec<usize>);

#[derive(Debug, Clone)]
struct RuleChoice {
    parent: Option<Index>,
    edge: Option<usize>,
    label: usize,
    /// What a step goes over, and the keys it keeps. None, half the time, is the last value bound, or `body`, so steps
    /// find entries often enough to be tested.
    steps: Vec<(Option<PathChoice>, Vec<usize>)>,
    /// None, two times in three, is `source`, which every document has, so nodes and the edges between them are written
    /// often enough to be tested; otherwise any path in scope.
    keys: [Option<PathChoice>; 2],
    set: Vec<(usize, PathChoice)>,
}

/// A valid mapping, and the schema it is inside: each label it writes with what identifies it, and each edge it writes.
#[derive(Debug, Clone)]
pub struct Generated {
    pub body: Value,
    pub shapes: Vec<(String, Vec<String>)>,
    pub edges: Vec<(String, String, String)>,
}

impl Generated {
    /// `f`, given the mapping's schema as the bounds a workload is built with.
    pub fn with_bounds<R>(&self, f: impl FnOnce(Bounds<'_>) -> R) -> R {
        let keys: Vec<Vec<&str>> = self
            .shapes
            .iter()
            .map(|(_, keys)| keys.iter().map(String::as_str).collect())
            .collect();
        let shapes: Vec<Shape<'_>> = self
            .shapes
            .iter()
            .zip(&keys)
            .map(|((label, _), keys)| Shape { label, keys })
            .collect();
        let edges: Vec<Edge<'_>> = self
            .edges
            .iter()
            .map(|(from, kind, to)| Edge { from, kind, to })
            .collect();
        f(Bounds {
            shapes: &shapes,
            edges: &edges,
        })
    }
}

fn path_choice() -> impl Strategy<Value = PathChoice> {
    (
        any::<Index>(),
        prop::collection::vec(0..SEGMENTS.len(), 0..=2),
    )
}

fn key_choice() -> impl Strategy<Value = Option<PathChoice>> {
    prop_oneof![2 => Just(None), 1 => path_choice().prop_map(Some)]
}

fn rule_choice() -> impl Strategy<Value = RuleChoice> {
    (
        prop::option::weighted(0.75, any::<Index>()),
        prop::option::weighted(0.75, 0..EDGE_TYPES.len()),
        0..LABELS.len(),
        prop::collection::vec(
            (
                prop_oneof![Just(None), path_choice().prop_map(Some)],
                prop_oneof![
                    3 => Just(vec![]),
                    1 => prop::collection::vec(0..SEGMENTS.len(), 1..=2),
                ],
            ),
            0..=2,
        ),
        [key_choice(), key_choice()],
        prop::collection::vec((0..PROPERTIES.len(), path_choice()), 0..=3),
    )
        .prop_map(|(parent, edge, label, steps, keys, set)| RuleChoice {
            parent,
            edge,
            label,
            steps,
            keys,
            set,
        })
}

/// A guard's checks, each with its ways to pass: from `body` or `source`, a path, and prefixes.
type GuardChoice = Vec<Vec<(bool, Vec<usize>, Vec<usize>)>>;

/// With `passable`, half the ways to pass are `source` alone, which every document has, so enough documents pass to be
/// written; without, a guard decides as often as documents let it.
fn guard_choice(passable: bool) -> impl Strategy<Value = GuardChoice> {
    let any_alternative = (
        any::<bool>(),
        prop::collection::vec(0..SEGMENTS.len(), 0..=2),
        prop_oneof![
            Just(vec![]),
            prop::collection::vec(0..PREFIXES.len(), 1..=2),
        ],
    );
    let weight = u32::from(passable);
    let alternative = prop_oneof![
        weight => Just((false, vec![], vec![])),
        1 => any_alternative,
    ];
    prop::collection::vec(prop::collection::vec(alternative, 1..=2), 1..=2)
}

/// Any mapping an author could sign, of one to four rules.
pub fn mapping() -> impl Strategy<Value = Generated> {
    (
        [0..KEY_SETS.len(), 0..KEY_SETS.len(), 0..KEY_SETS.len()],
        guard_choice(true),
        prop::collection::vec(rule_choice(), 1..=4),
    )
        .prop_map(|(key_sets, guard, rules)| build(key_sets, guard, rules))
}

/// A mapping of one rule whose guard has no way to pass that every document has, for properties of the guard: what
/// [`mapping`] is biased toward writing, this is not.
pub fn guarded() -> impl Strategy<Value = Generated> {
    (
        [0..KEY_SETS.len(), 0..KEY_SETS.len(), 0..KEY_SETS.len()],
        guard_choice(false),
        rule_choice(),
    )
        .prop_map(|(key_sets, guard, rule)| build(key_sets, guard, vec![rule]))
}

fn path(scope: &[String], (root, segments): &PathChoice) -> String {
    let mut path = scope[root.index(scope.len())].clone();
    for segment in segments {
        path.push('.');
        path.push_str(SEGMENTS[*segment]);
    }
    path
}

fn build(key_sets: [usize; 3], guard: GuardChoice, choices: Vec<RuleChoice>) -> Generated {
    let guard: Vec<Value> = guard
        .into_iter()
        .map(|alternatives| {
            let any_of: Vec<Value> = alternatives
                .into_iter()
                .map(|(from_body, segments, prefixes)| {
                    let root = if from_body { "body" } else { "source" };
                    let path = std::iter::once(root)
                        .chain(segments.iter().map(|s| SEGMENTS[*s]))
                        .collect::<Vec<_>>()
                        .join(".");
                    let prefixes: Vec<&str> = prefixes.iter().map(|p| PREFIXES[*p]).collect();
                    json!({ "path": path, "prefixes": prefixes })
                })
                .collect();
            json!({ "any_of": any_of })
        })
        .collect();

    // What each rule leaves in scope for its children, and its label.
    let mut scopes: Vec<Vec<String>> = Vec::new();
    let mut labels: Vec<&str> = Vec::new();
    let mut rules = Vec::new();
    let mut shapes: Vec<(String, Vec<String>)> = Vec::new();
    let mut edges: Vec<(String, String, String)> = Vec::new();
    for (i, choice) in choices.into_iter().enumerate() {
        let parent = choice.parent.filter(|_| i > 0).map(|pick| pick.index(i));
        let edge = match (parent, choice.edge) {
            (Some(_), Some(e)) => EDGE_TYPES[e],
            _ => "",
        };
        let label = LABELS[choice.label];
        let keys: &[&str] = KEY_SETS[key_sets[choice.label]];

        let mut scope: Vec<String> = vec!["source".to_string(), "body".to_string()];
        if let Some(p) = parent {
            for name in &scopes[p] {
                if !scope.contains(name) {
                    scope.push(name.clone());
                }
            }
        }
        let mut each = Vec::new();
        for (s, (over, only)) in choice.steps.iter().enumerate() {
            let over = match over {
                Some(over) => path(&scope, over),
                None => scope
                    .iter()
                    .rev()
                    .find(|name| name.starts_with('v'))
                    .cloned()
                    .unwrap_or_else(|| "body".to_string()),
            };
            let (key, value) = (format!("e{i}{s}"), format!("v{i}{s}"));
            let only: Vec<&str> = only.iter().map(|o| SEGMENTS[*o]).collect();
            each.push(json!({ "key": key, "value": value, "over": over, "only": only }));
            scope.push(key);
            scope.push(value);
        }
        let key_fields: Vec<Value> = keys
            .iter()
            .zip(&choice.keys)
            .map(|(name, from)| {
                let from = from
                    .as_ref()
                    .map_or_else(|| "source".to_string(), |from| path(&scope, from));
                json!({ "name": name, "from": from })
            })
            .collect();
        let mut set = Vec::new();
        let mut named: Vec<&str> = Vec::new();
        for (p, from) in &choice.set {
            let name = PROPERTIES[*p];
            if !named.contains(&name) {
                named.push(name);
                set.push(json!({ "name": name, "from": path(&scope, from) }));
            }
        }
        let parent_name = parent.map(|p| format!("r{p}")).unwrap_or_default();
        rules.push(json!({
            "name": format!("r{i}"),
            "parent": parent_name,
            "each": each,
            "label": label,
            "keys": key_fields,
            "set": set,
            "edge": edge,
        }));
        if !shapes.iter().any(|(l, _)| l == label) {
            shapes.push((
                label.to_string(),
                keys.iter().map(|k| k.to_string()).collect(),
            ));
        }
        if let (Some(p), false) = (parent, edge.is_empty()) {
            let triple = (labels[p].to_string(), edge.to_string(), label.to_string());
            if !edges.contains(&triple) {
                edges.push(triple);
            }
        }
        scopes.push(scope);
        labels.push(label);
    }
    Generated {
        body: json!({ "guard": guard, "rules": rules }),
        shapes,
        edges,
    }
}

/// Text a document holds: sometimes starting as a guard asks, always ending with [`MARK`].
fn marked_text() -> impl Strategy<Value = String> {
    (
        prop_oneof![Just(""), Just("3."), Just("a"), Just("x")],
        "[a-z0-9.\"`]{0,3}",
    )
        .prop_map(|(start, rest)| format!("{start}{rest}{MARK}"))
}

/// A source's name, marked as a document's text is: it reaches the graph as a value.
pub fn source() -> impl Strategy<Value = String> {
    "[a-z]{1,3}".prop_map(|s| format!("{s}{MARK}"))
}

/// A document in a generated mapping's words: objects keyed mostly by [`SEGMENTS`], so its paths find things, and every
/// string marked.
pub fn document() -> impl Strategy<Value = Value> {
    let key = || {
        prop_oneof![
            4 => prop::sample::select(&SEGMENTS[..]).prop_map(str::to_string),
            1 => marked_text(),
        ]
    };
    // Nulls are common: a null is nothing to a guard and clears a property, which is where an engine goes wrong.
    let leaf = prop_oneof![
        3 => Just(Value::Null),
        1 => any::<bool>().prop_map(Value::from),
        1 => (-3i64..3).prop_map(Value::from),
        2 => marked_text().prop_map(Value::from),
    ];
    let tree = leaf.prop_recursive(4, 48, 4, move |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::from),
            prop::collection::btree_map(key(), inner, 0..4)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    });
    // Mostly an object, as a service's document is, so paths find things; sometimes anything at all.
    prop_oneof![
        4 => prop::collection::btree_map(key(), tree.clone(), 1..4)
            .prop_map(|m| Value::Object(m.into_iter().collect())),
        1 => tree,
    ]
}

/// A node's properties, by name.
pub type Props = std::collections::BTreeMap<String, crate::Scalar>;
/// An edge by the node at each end and its type, written out.
pub type EdgeKey = (String, String, String);

/// A node in a [`MemoryGraph`]: its label and its properties, which include what identifies it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Node {
    pub label: String,
    pub props: Props,
}

/// What the graph controller's writes do to Neo4j, in memory: a node or edge is found by what identifies it or made
/// (MERGE), its properties are added to (`SET += `), a null removes one, and an edge makes the nodes at its ends if they
/// are not there. A kind's tests hold real Neo4j to it (`polar-http-testkit`), so a model built on it is a model of the
/// graph.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MemoryGraph {
    pub nodes: std::collections::BTreeMap<String, Node>,
    pub edges: std::collections::BTreeMap<EdgeKey, Props>,
}

impl MemoryGraph {
    /// A node by its label and keys, written out: what [`MemoryGraph::nodes`] is keyed by.
    pub fn key(id: &crate::NodeId) -> String {
        format!("{}{:?}", id.label, id.keys)
    }

    fn set(props: &mut Props, set: &[(String, crate::Scalar)]) {
        for (name, value) in set {
            match value {
                crate::Scalar::Null => {
                    props.remove(name);
                }
                value => {
                    props.insert(name.clone(), value.clone());
                }
            }
        }
    }

    fn merge(&mut self, id: &crate::NodeId) -> &mut Node {
        self.nodes.entry(Self::key(id)).or_insert_with(|| Node {
            label: id.label.clone(),
            props: id.keys.iter().cloned().collect(),
        })
    }

    /// One document's writes, in order.
    pub fn apply(&mut self, writes: &[crate::Write]) {
        for write in writes {
            match write {
                crate::Write::Node { id, props } => Self::set(&mut self.merge(id).props, props),
                crate::Write::Edge {
                    from,
                    to,
                    kind,
                    props,
                } => {
                    self.merge(from);
                    self.merge(to);
                    let edge = (Self::key(from), kind.clone(), Self::key(to));
                    Self::set(self.edges.entry(edge).or_default(), props);
                }
            }
        }
    }

    /// Every node and edge as one line, sorted, in the form `polar_test_graph::dump` gives for Neo4j: so the two can be
    /// compared as they are.
    pub fn dump(&self) -> Vec<String> {
        let node = |key: &String| {
            let node = &self.nodes[key];
            (format!("[{:?}]", node.label), canonical(&node.props))
        };
        let mut lines: Vec<String> = self
            .nodes
            .values()
            .map(|n| format!("[{:?}] {}", n.label, canonical(&n.props)))
            .collect();
        for ((from, kind, to), props) in &self.edges {
            let (from_label, from_props) = node(from);
            let (to_label, to_props) = node(to);
            lines.push(format!(
                "{from_label} {from_props} {kind:?} {} {to_label} {to_props}",
                canonical(props)
            ));
        }
        lines.sort();
        lines
    }
}

fn canonical(props: &Props) -> String {
    let mut pairs: Vec<String> = props
        .iter()
        .map(|(name, value)| {
            let value = match value {
                crate::Scalar::Text(s) => format!("{s:?}"),
                crate::Scalar::Bool(b) => b.to_string(),
                crate::Scalar::Integer(i) => i.to_string(),
                crate::Scalar::Real(r) => format!("{r:?}"),
                crate::Scalar::Null => "null".to_string(),
            };
            format!("{name}: {value}")
        })
        .collect();
    pairs.sort();
    format!("{{{}}}", pairs.join(", "))
}
