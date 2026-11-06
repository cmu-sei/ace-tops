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

//! A projection: how one kind of document becomes nodes and edges in the graph, as data (docs/architecture/http-observers.md).
//!
//! The rule that matters: **structure comes from the signed mapping, values from the document.** Labels, key names and edge
//! types are written in the projection and nothing in a document can choose one, so what a hostile document can do is give
//! values, which reach Cypher only as parameters. The language walks a finite document and has no arithmetic, recursion or
//! calls, so it always ends.
//!
//! This crate has no graph and no runtime, so the tool that signs a mapping can check it; `graph` turns writes into
//! operations.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "graph")]
pub mod graph;
pub mod samples;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// The Dhall type of a projection, for an author's file.
pub const SCHEMA: &str = include_str!("../projection.dhall");
/// How an agent's scaffold says a runtime section holds a projection: the type its body's `rules` field is described by
/// begins with this (`polar_http_processor::SECTION_BODY`). A tool that judges a deployment finds its projections by it.
pub const SECTION_TYPE: &str = "a projection: polar-projection/projection.dhall";

/// The most rules a projection may have.
pub const MAX_RULES: usize = 32;
/// The most steps a rule may have.
pub const MAX_STEPS: usize = 4;
/// The most properties a rule may write.
pub const MAX_FIELDS: usize = 64;
/// The most writes one document may become. Over it, the document is refused whole.
pub const MAX_WRITES: usize = 200_000;
/// The most checks a guard may have, and the most ways one may pass.
pub const MAX_CHECKS: usize = 16;
pub const MAX_ALTERNATIVES: usize = 8;
/// What a property the engine stamps starts with. No rule may write one.
pub const STAMP_PREFIX: &str = "polar_";
/// What a path may start from, whatever a rule binds: the source's name, the origin it was read from, the document.
const ROOTS: [&str; 3] = ["source", "origin", "body"];

/// A property: its name in the graph, and the path its value comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub name: String,
    pub from: String,
}

/// For each entry at `over`, binding its key and its value. `only`, if any, keeps the keys named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub key: String,
    pub value: String,
    pub over: String,
    pub only: Vec<String>,
}

/// One way a check can pass: the path has a value, and if `prefixes` names any, it is text starting with one of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alternative {
    pub path: String,
    pub prefixes: Vec<String>,
}

/// What a document must say to be the document this mapping was written for: any one of these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub any_of: Vec<Alternative>,
}

/// One kind of node a document becomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    /// The rule this one runs inside, once per node it wrote. Empty for none.
    pub parent: String,
    pub each: Vec<Step>,
    /// Which entries are this rule's: every check must hold, read where the rule's keys are, with what its steps bound.
    /// One that does not is another rule's: this one writes nothing for it, and it is not skipped. Left out, every entry.
    #[serde(default)]
    pub when: Vec<Check>,
    pub label: String,
    pub keys: Vec<Field>,
    pub set: Vec<Field>,
    /// The type of the edge from the parent's node to this one. Empty for none.
    pub edge: String,
}

/// A projection, judged: only [`Projection::well_formed`] and [`Projection::judged`] make one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Projection {
    guard: Vec<Check>,
    rules: Vec<Rule>,
}

/// A label a workload may write and what identifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape<'a> {
    pub label: &'a str,
    pub keys: &'a [&'a str],
}

/// An edge a workload may write: of this type, from a node of one label to a node of another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edge<'a> {
    pub from: &'a str,
    pub kind: &'a str,
    pub to: &'a str,
}

/// What the workload was built to write, which no signed mapping can widen: the schema its scaffold gives, from which its
/// constraints and the state agent's first schema come. A signed mapping says which data goes where inside it. Built into a
/// workload as a constant, and read back from its scaffold by the tool that signs a mapping, which judges by the same rule.
#[derive(Debug, Clone, Copy)]
pub struct Bounds<'a> {
    pub shapes: &'a [Shape<'a>],
    pub edges: &'a [Edge<'a>],
}

/// A value in the graph.
#[derive(Debug, Clone, PartialEq)]
pub enum Scalar {
    Text(String),
    Bool(bool),
    Integer(i64),
    Real(f64),
    /// What a document does not have, which clears the property: a document is a snapshot.
    Null,
}

/// A node, by what identifies it.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeId {
    pub label: String,
    pub keys: Vec<(String, Scalar)>,
}

/// What a document becomes.
#[derive(Debug, Clone, PartialEq)]
pub enum Write {
    Node {
        id: NodeId,
        props: Vec<(String, Scalar)>,
    },
    Edge {
        from: NodeId,
        to: NodeId,
        kind: String,
        props: Vec<(String, Scalar)>,
    },
}

/// Where a write came from, stamped on all of them: what the graph knows, from which workload, under which mapping.
#[derive(Debug, Clone)]
pub struct Stamp<'a> {
    pub workload: &'a str,
    pub version: u64,
    pub observed_at_unix_secs: i64,
    /// The origin of the source it was read from (scheme, host and port), which a mapping may read as `origin`.
    pub origin: &'a str,
}

/// A document's writes, and how many of its entries could not be identified and were skipped.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Projected {
    pub writes: Vec<Write>,
    pub skipped: usize,
}

/// What became of a document as a service returned it.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// What to write, and how many entries could not be identified and were skipped.
    Write { writes: Vec<Write>, skipped: usize },
    /// Nothing is written, and why.
    Refused(String),
}

/// Why a document was refused whole.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    #[error("the document would become more than {MAX_WRITES} writes")]
    TooLarge,
    /// It is not the document this mapping was written for. Names the paths and never what the document said.
    #[error("it is not what the mapping was written for: nothing was as it expects at {0}")]
    Guard(String),
}

/// A name that can stand in Cypher, or a variable. A name that goes into Cypher is held to Cypher's own rule as well
/// (`polar_cypher`), the one the graph controller holds every query to.
fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `root.segment.segment`: where a value is found. Nothing else is a path: no wildcards, no indexes, no expressions.
fn path_parts(path: &str) -> Option<Vec<&str>> {
    let parts: Vec<&str> = path.split('.').collect();
    let segment = |s: &&str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    };
    (is_identifier(parts[0]) && parts.iter().all(segment)).then_some(parts)
}

impl Projection {
    /// Judges a body as it arrives at the agent: that it is well formed, and inside what the workload was built to write.
    /// Every problem, by name. Nothing about it is believed until this says so.
    pub fn judged(body: &Value, bounds: Bounds<'_>) -> Result<Projection, Vec<String>> {
        let projection = Self::well_formed(body)?;
        let mut problems = Vec::new();
        let label_of: BTreeMap<&str, &str> = projection
            .rules
            .iter()
            .map(|r| (r.name.as_str(), r.label.as_str()))
            .collect();
        for rule in &projection.rules {
            let at = format!("rule `{}`", rule.name);
            match bounds.shapes.iter().find(|s| s.label == rule.label) {
                None => problems.push(format!(
                    "{at}: the label `{}` is not in this workload's part of the graph",
                    rule.label
                )),
                Some(shape) => {
                    if !rule
                        .keys
                        .iter()
                        .map(|k| k.name.as_str())
                        .eq(shape.keys.iter().copied())
                    {
                        problems.push(format!(
                            "{at}: `{}` is identified by {:?} in this workload's schema",
                            rule.label, shape.keys
                        ));
                    }
                }
            }
            // A well-formed edge has a parent, which is an earlier rule.
            if !rule.edge.is_empty() {
                let from = label_of
                    .get(rule.parent.as_str())
                    .copied()
                    .unwrap_or_default();
                let edge = Edge {
                    from,
                    kind: &rule.edge,
                    to: &rule.label,
                };
                if !bounds.edges.contains(&edge) {
                    problems.push(format!(
                        "{at}: the edge `{}` from `{from}` to `{}` is not in this workload's part of the graph",
                        rule.edge, rule.label
                    ));
                }
            }
        }
        if problems.is_empty() {
            Ok(projection)
        } else {
            Err(problems)
        }
    }

    /// Whether a body is a projection at all, whichever workload it is for: what the tool that signs one can tell.
    pub fn well_formed(body: &Value) -> Result<Projection, Vec<String>> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            guard: Vec<Check>,
            rules: Vec<Rule>,
        }
        let body: Body = serde_json::from_value(body.clone())
            .map_err(|e| vec![format!("this is not a projection: {e}")])?;
        let mut problems = Vec::new();
        if body.rules.is_empty() {
            problems.push("it has no rules, so it would write nothing".to_string());
        }
        // Required: a value a document does not have is cleared, so with no guard an error answered with a 200 would empty
        // every node it reached.
        if body.guard.is_empty() {
            problems.push(
                "it has no guard, so a response that is not the document would clear what is written"
                    .to_string(),
            );
        }
        if body.guard.len() > MAX_CHECKS {
            problems.push(format!(
                "its guard has {} checks, and at most {MAX_CHECKS} are taken",
                body.guard.len()
            ));
        }
        for (i, check) in body.guard.iter().enumerate() {
            let at = format!("`guard[{i}]`");
            judge_check(&at, check, &mut problems, |path| match path_parts(path) {
                Some(parts) if ROOTS.contains(&parts[0]) => None,
                _ => Some(format!("`{path}` must be a path from `source` or `body`")),
            });
        }
        if body.rules.len() > MAX_RULES {
            problems.push(format!(
                "it has {} rules, and at most {MAX_RULES} are taken",
                body.rules.len()
            ));
        }
        // What each rule before this one leaves in scope for its children.
        let mut scopes: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        let mut keys_of: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for rule in &body.rules {
            let at = format!("rule `{}`", rule.name);
            if !is_identifier(&rule.name) {
                problems.push(format!("{at}: its name is not an identifier"));
            }
            if scopes.contains_key(rule.name.as_str()) {
                problems.push(format!("{at}: another rule has that name"));
            }
            if !is_identifier(&rule.label) {
                problems.push(format!("{at}: the label is not an identifier"));
            } else if let Err(e) = polar_cypher::validate_cypher_identifier(&rule.label) {
                problems.push(format!("{at}: the label: {e}"));
            }
            let mut scope: BTreeSet<&str> = ROOTS.into_iter().collect();
            match (rule.parent.as_str(), rule.edge.as_str()) {
                ("", "") => {}
                ("", _) => problems.push(format!("{at}: an edge needs a parent to come from")),
                (parent, edge) => {
                    match scopes.get(parent) {
                        Some(theirs) => scope.extend(theirs),
                        None => problems.push(format!(
                            "{at}: its parent `{parent}` is not an earlier rule"
                        )),
                    }
                    if !edge.is_empty() && !is_identifier(edge) {
                        problems.push(format!("{at}: the edge type is not an identifier"));
                    } else if !edge.is_empty()
                        && let Err(e) = polar_cypher::validate_cypher_identifier(edge)
                    {
                        problems.push(format!("{at}: the edge type: {e}"));
                    }
                }
            }
            if rule.each.len() > MAX_STEPS {
                problems.push(format!(
                    "{at}: it has {} steps, and at most {MAX_STEPS} are taken",
                    rule.each.len()
                ));
            }
            let mut read = |what: &str, path: &str, scope: &BTreeSet<&str>| match path_parts(path) {
                None => problems.push(format!("{at}: {what}: `{path}` is not a path")),
                Some(parts) if !scope.contains(parts[0]) => problems.push(format!(
                    "{at}: {what}: `{path}` starts from nothing it can see"
                )),
                Some(_) => {}
            };
            let mut bound: Vec<&str> = Vec::new();
            for step in &rule.each {
                read("a step", &step.over, &scope);
                for name in [step.key.as_str(), step.value.as_str()] {
                    if is_identifier(name) && !scope.contains(name) {
                        scope.insert(name);
                        bound.push(name);
                    } else {
                        bound.push("");
                    }
                }
            }
            for field in rule.keys.iter().chain(&rule.set) {
                read(&format!("`{}`", field.name), &field.from, &scope);
            }
            if rule.when.len() > MAX_CHECKS {
                problems.push(format!(
                    "{at}: its `when` has {} checks, and at most {MAX_CHECKS} are taken",
                    rule.when.len()
                ));
            }
            for (i, check) in rule.when.iter().enumerate() {
                judge_check(
                    &format!("{at}: `when[{i}]`"),
                    check,
                    &mut problems,
                    |path| match path_parts(path) {
                        None => Some(format!("`{path}` is not a path")),
                        Some(parts) if !scope.contains(parts[0]) => {
                            Some(format!("`{path}` starts from nothing it can see"))
                        }
                        Some(_) => None,
                    },
                );
            }
            if bound.contains(&"") {
                problems.push(format!(
                    "{at}: a step binds a name that is not an identifier or is already in use"
                ));
            }
            if rule.keys.is_empty() {
                problems.push(format!(
                    "{at}: it has no keys, so nothing identifies a node"
                ));
            }
            if rule.keys.len() + rule.set.len() > MAX_FIELDS {
                problems.push(format!("{at}: it writes more than {MAX_FIELDS} properties"));
            }
            let mut names = BTreeSet::new();
            for field in rule.keys.iter().chain(&rule.set) {
                if !is_identifier(&field.name) {
                    problems.push(format!(
                        "{at}: the property `{}` is not an identifier",
                        field.name
                    ));
                } else if let Err(e) = polar_cypher::validate_cypher_identifier(&field.name) {
                    problems.push(format!("{at}: the property: {e}"));
                }
                if field.name.starts_with(STAMP_PREFIX) {
                    problems.push(format!(
                        "{at}: the property `{}` starts with `{STAMP_PREFIX}`, which is the engine's stamp",
                        field.name
                    ));
                }
                if !names.insert(field.name.as_str()) {
                    problems.push(format!(
                        "{at}: the property `{}` is written twice",
                        field.name
                    ));
                }
            }
            let keys: Vec<&str> = rule.keys.iter().map(|k| k.name.as_str()).collect();
            match keys_of.get(rule.label.as_str()) {
                Some(theirs) if *theirs != keys => problems.push(format!(
                    "{at}: another rule identifies `{}` by other keys, which would make two nodes of one",
                    rule.label
                )),
                _ => {
                    keys_of.insert(rule.label.as_str(), keys);
                }
            }
            scopes.insert(rule.name.as_str(), scope);
        }
        if problems.is_empty() {
            Ok(Projection {
                guard: body.guard,
                rules: body.rules,
            })
        } else {
            Err(problems)
        }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Each label it writes, once, with what identifies it: what the graph's constraints are made from.
    pub fn shapes(&self) -> BTreeMap<&str, Vec<&str>> {
        self.rules
            .iter()
            .map(|r| {
                (
                    r.label.as_str(),
                    r.keys.iter().map(|k| k.name.as_str()).collect(),
                )
            })
            .collect()
    }

    /// A document as a service returned it, read as JSON and then [`Projection::project`]ed: what the processor does with
    /// each, and what a sample is held to.
    pub fn outcome(&self, source: &str, body: &[u8], stamp: &Stamp<'_>) -> Outcome {
        let body: Value = match serde_json::from_slice(body) {
            Ok(body) => body,
            Err(e) => return Outcome::Refused(format!("it is not JSON: {e}")),
        };
        match self.project(source, &body, stamp) {
            Ok(projected) => Outcome::Write {
                writes: projected.writes,
                skipped: projected.skipped,
            },
            Err(refused) => Outcome::Refused(refused.to_string()),
        }
    }

    /// What a document says, as writes. A document can skip its own entries, by leaving out what identifies them, and
    /// can be refused for its size, and can do nothing else: any JSON at all comes back as one of those.
    pub fn project(
        &self,
        source: &str,
        body: &Value,
        stamp: &Stamp<'_>,
    ) -> Result<Projected, Refused> {
        let mut out = Walked {
            projected: Projected::default(),
            reach: None,
        };
        self.walk(source, body, stamp, &mut out)?;
        Ok(out.projected)
    }

    /// Every read the mapping makes, each named by the mapping alone: `guard <path>` for each way a check can pass,
    /// `<rule> each <path>` for each step, and `<rule>.<name> from <path>` for each key and property. Nothing of a
    /// document is in a name.
    pub fn reads(&self) -> BTreeSet<String> {
        let guard = self
            .guard
            .iter()
            .flat_map(|c| c.any_of.iter().map(|a| guard_read(&a.path)));
        let rules = self.rules.iter().flat_map(|r| {
            r.each
                .iter()
                .map(|s| step_read(r, s))
                .chain(
                    r.when
                        .iter()
                        .flat_map(|c| c.any_of.iter().map(|a| when_read(r, &a.path))),
                )
                .chain(r.keys.iter().chain(&r.set).map(|f| field_read(r, f)))
        });
        guard.chain(rules).collect()
    }

    /// The reads of [`Projection::reads`] that found something in this document: a guard's path that holds, a step over
    /// at least one entry, a key or property with a value. Past a guard that refuses, nothing of a rule.
    pub fn reached(&self, source: &str, origin: &str, body: &Value) -> BTreeSet<String> {
        let mut out = Walked {
            projected: Projected::default(),
            reach: Some(BTreeSet::new()),
        };
        let stamp = Stamp {
            workload: "",
            version: 0,
            observed_at_unix_secs: 0,
            origin,
        };
        // A refusal for size still reached what it read on the way.
        let _ = self.walk(source, body, &stamp, &mut out);
        out.reach.unwrap_or_default()
    }

    fn walk(
        &self,
        source: &str,
        body: &Value,
        stamp: &Stamp<'_>,
        out: &mut Walked,
    ) -> Result<(), Refused> {
        let source = Value::String(source.to_string());
        let origin = Value::String(stamp.origin.to_string());
        let stamps = vec![
            (
                "polar_source".to_string(),
                value_scalar(&source).expect("text"),
            ),
            (
                "polar_workload".to_string(),
                Scalar::Text(stamp.workload.to_string()),
            ),
            (
                "polar_projection_version".to_string(),
                Scalar::Integer(i64::try_from(stamp.version).unwrap_or(i64::MAX)),
            ),
            (
                "polar_observed_at".to_string(),
                Scalar::Integer(stamp.observed_at_unix_secs),
            ),
            (
                "polar_origin".to_string(),
                Scalar::Text(stamp.origin.to_string()),
            ),
        ];
        let mut scope = Scope::default();
        scope.bind("source", Bound::Ref(&source));
        scope.bind("origin", Bound::Ref(&origin));
        scope.bind("body", Bound::Ref(body));
        if let Some(reached) = &mut out.reach {
            for alternative in self.guard.iter().flat_map(|c| &c.any_of) {
                if alternative.holds(&scope) {
                    reached.insert(guard_read(&alternative.path));
                }
            }
        }
        // Before anything is written or cleared.
        if let Some(check) = self.guard.iter().find(|check| !check.holds(&scope)) {
            let paths: Vec<&str> = check.any_of.iter().map(|a| a.path.as_str()).collect();
            return Err(Refused::Guard(paths.join(" or ")));
        }
        for rule in self.rules.iter().filter(|r| r.parent.is_empty()) {
            self.rule(rule, None, &mut scope, &stamps, out)?;
        }
        Ok(())
    }

    fn rule<'v>(
        &'v self,
        rule: &'v Rule,
        parent: Option<&NodeId>,
        scope: &mut Scope<'v>,
        stamps: &[(String, Scalar)],
        out: &mut Walked,
    ) -> Result<(), Refused> {
        self.steps(rule, &rule.each, parent, scope, stamps, out)
    }

    fn steps<'v>(
        &'v self,
        rule: &'v Rule,
        steps: &'v [Step],
        parent: Option<&NodeId>,
        scope: &mut Scope<'v>,
        stamps: &[(String, Scalar)],
        out: &mut Walked,
    ) -> Result<(), Refused> {
        let Some((step, rest)) = steps.split_first() else {
            return self.node(rule, parent, scope, stamps, out);
        };
        let entries: Vec<(Value, Bound<'v>)> = match scope.read(&step.over) {
            Some(Bound::Ref(Value::Object(map))) => map
                .iter()
                .map(|(k, v)| (Value::String(k.clone()), Bound::Ref(v)))
                .collect(),
            Some(Bound::Ref(Value::Array(items))) => items
                .iter()
                .enumerate()
                .map(|(i, v)| (Value::from(i as u64), Bound::Ref(v)))
                .collect(),
            _ => Vec::new(),
        };
        if let (Some(reached), false) = (out.reach.as_mut(), entries.is_empty()) {
            reached.insert(step_read(rule, step));
        }
        for (key, value) in entries {
            if !step.only.is_empty()
                && !key
                    .as_str()
                    .is_some_and(|k| step.only.iter().any(|o| o == k))
            {
                continue;
            }
            let depth = scope.depth();
            scope.bind(&step.key, Bound::Owned(key));
            scope.bind(&step.value, value);
            let result = self.steps(rule, rest, parent, scope, stamps, out);
            scope.truncate(depth);
            result?;
        }
        Ok(())
    }

    fn node<'v>(
        &'v self,
        rule: &'v Rule,
        parent: Option<&NodeId>,
        scope: &mut Scope<'v>,
        stamps: &[(String, Scalar)],
        out: &mut Walked,
    ) -> Result<(), Refused> {
        if let Some(reached) = out.reach.as_mut() {
            for alternative in rule.when.iter().flat_map(|c| &c.any_of) {
                if alternative.holds(scope) {
                    reached.insert(when_read(rule, &alternative.path));
                }
            }
        }
        // Another rule's entry: nothing of this one, and not a miss.
        if !rule.when.iter().all(|check| check.holds(scope)) {
            return Ok(());
        }
        let mut keys = Vec::with_capacity(rule.keys.len());
        for field in &rule.keys {
            match scope.scalar(&field.from) {
                Some(value) => {
                    if let Some(reached) = out.reach.as_mut() {
                        reached.insert(field_read(rule, field));
                    }
                    keys.push((field.name.clone(), value))
                }
                None => {
                    out.projected.skipped += 1;
                    return Ok(());
                }
            }
        }
        let id = NodeId {
            label: rule.label.clone(),
            keys,
        };
        let mut props: Vec<(String, Scalar)> = rule
            .set
            .iter()
            .map(|f| {
                let value = scope.scalar(&f.from).unwrap_or(Scalar::Null);
                if let (Some(reached), false) = (out.reach.as_mut(), value == Scalar::Null) {
                    reached.insert(field_read(rule, f));
                }
                (f.name.clone(), value)
            })
            .collect();
        props.extend_from_slice(stamps);
        push(
            &mut out.projected,
            Write::Node {
                id: id.clone(),
                props,
            },
        )?;
        if let (Some(from), false) = (parent, rule.edge.is_empty()) {
            push(
                &mut out.projected,
                Write::Edge {
                    from: from.clone(),
                    to: id.clone(),
                    kind: rule.edge.clone(),
                    props: stamps.to_vec(),
                },
            )?;
        }
        for child in self.rules.iter().filter(|c| c.parent == rule.name) {
            self.rule(child, Some(&id), scope, stamps, out)?;
        }
        Ok(())
    }
}

/// The reads a walk found something at, when it is asked to note them ([`Projection::reached`]).
type Reach = Option<BTreeSet<String>>;

/// What a walk makes: the writes, and the reads it found something at when asked.
struct Walked {
    projected: Projected,
    reach: Reach,
}

fn guard_read(path: &str) -> String {
    format!("guard {path}")
}

fn when_read(rule: &Rule, path: &str) -> String {
    format!("{} when {path}", rule.name)
}

/// A check, a guard's or a rule's: its alternatives, each a path `readable` takes and no prefix that would match anything.
fn judge_check(
    at: &str,
    check: &Check,
    problems: &mut Vec<String>,
    readable: impl Fn(&str) -> Option<String>,
) {
    if check.any_of.is_empty() || check.any_of.len() > MAX_ALTERNATIVES {
        problems.push(format!(
            "{at}: `any_of` must have 1 to {MAX_ALTERNATIVES} alternatives"
        ));
    }
    for alternative in &check.any_of {
        if let Some(problem) = readable(&alternative.path) {
            problems.push(format!("{at}: {problem}"));
        }
        if alternative.prefixes.iter().any(String::is_empty) {
            problems.push(format!(
                "{at}: an empty prefix would match anything: leave `prefixes` empty to ask only that it is there"
            ));
        }
    }
}

fn step_read(rule: &Rule, step: &Step) -> String {
    format!("{} each {}", rule.name, step.over)
}

fn field_read(rule: &Rule, field: &Field) -> String {
    format!("{}.{} from {}", rule.name, field.name, field.from)
}

fn push(out: &mut Projected, write: Write) -> Result<(), Refused> {
    if out.writes.len() >= MAX_WRITES {
        return Err(Refused::TooLarge);
    }
    out.writes.push(write);
    Ok(())
}

fn value_scalar(value: &Value) -> Option<Scalar> {
    match value {
        Value::String(s) => Some(Scalar::Text(s.clone())),
        Value::Bool(b) => Some(Scalar::Bool(*b)),
        Value::Number(n) => n
            .as_i64()
            .map(Scalar::Integer)
            .or_else(|| n.as_f64().map(Scalar::Real)),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

impl Check {
    fn holds(&self, scope: &Scope<'_>) -> bool {
        self.any_of
            .iter()
            .any(|alternative| alternative.holds(scope))
    }
}

impl Alternative {
    fn holds(&self, scope: &Scope<'_>) -> bool {
        match scope.read(&self.path) {
            None | Some(Bound::Ref(Value::Null)) | Some(Bound::Owned(Value::Null)) => false,
            Some(_) if self.prefixes.is_empty() => true,
            Some(found) => {
                let text = match &found {
                    Bound::Ref(value) => value.as_str(),
                    Bound::Owned(value) => value.as_str(),
                };
                text.is_some_and(|text| self.prefixes.iter().any(|p| text.starts_with(p.as_str())))
            }
        }
    }
}

/// A value a name stands for: in the document, or made by a step (an entry's key).
#[derive(Clone)]
enum Bound<'v> {
    Ref(&'v Value),
    Owned(Value),
}

/// What is bound where a rule runs, innermost last.
#[derive(Default)]
struct Scope<'v> {
    names: Vec<(&'v str, Bound<'v>)>,
}

impl<'v> Scope<'v> {
    fn bind(&mut self, name: &'v str, value: Bound<'v>) {
        self.names.push((name, value));
    }

    fn depth(&self) -> usize {
        self.names.len()
    }

    fn truncate(&mut self, depth: usize) {
        self.names.truncate(depth);
    }

    /// What a path finds. The projection was judged, so it starts from something bound; nothing else is assumed of the
    /// document, and a path that leaves it finds nothing.
    fn read(&self, path: &str) -> Option<Bound<'v>> {
        let mut parts = path.split('.');
        let root = parts.next()?;
        let (_, start) = self.names.iter().rev().find(|(name, _)| *name == root)?;
        parts.try_fold(start.clone(), |at, segment| match at {
            Bound::Ref(value) => value.get(segment).map(Bound::Ref),
            Bound::Owned(_) => None,
        })
    }

    fn scalar(&self, path: &str) -> Option<Scalar> {
        match self.read(path)? {
            Bound::Ref(value) => value_scalar(value),
            Bound::Owned(value) => value_scalar(&value),
        }
    }
}

#[cfg(test)]
mod tests;
