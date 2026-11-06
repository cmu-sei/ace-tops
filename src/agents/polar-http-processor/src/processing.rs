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

//! What the processor decides, apart from the actor that carries it out: given a mapping or a document, what to write and
//! what health should say. The actor reads the section in force, hands writes to the graph controller and tells health;
//! this says what, so a property can hold it to a simple model, the last good document under the mapping in force, over
//! any sequence of mappings, refusals, documents and restarts (docs/architecture/http-observers.md, "Evidence").

use polar_http_observer::Observation;
use polar_http_observer::problems::{HealthChange, Reported, SourceProblems};
use polar_projection::{Projection, Stamp, Write};
use tracing::{error, info, warn};

pub(crate) const NO_MAPPING: &str = "no projection is signed yet, so what the observer publishes is not written. Sign one: \
                                     polar-sign runtime --section projection --projection <file>";

pub use polar_projection::Outcome;

/// A document, through a mapping, into writes.
pub fn process(
    projection: &Projection,
    version: u64,
    workload: &str,
    observation: &Observation,
) -> Outcome {
    let stamp = Stamp {
        workload,
        version,
        observed_at_unix_secs: observation.observed_at_unix_secs,
    };
    projection.outcome(&observation.source, &observation.body, &stamp)
}

/// What standing problem a document's outcome leaves its source with. A document was read and refused, so one is enough:
/// nothing here is a blip of the network, and nothing of it was written.
pub fn note_outcome(problems: &mut SourceProblems, source: &str, outcome: &Outcome) {
    match outcome {
        Outcome::Write { skipped: 0, .. } => problems.succeeded(source),
        Outcome::Write { skipped, .. } => problems.failed(
            source,
            format!("{skipped} entries could not be identified and were skipped"),
        ),
        Outcome::Refused(why) => problems.failed(source, format!("not written: {why}")),
    }
}

/// What should stand: having no mapping says more than anything a source could say. A source taken out of the observer's list
/// is not known here, so its problem stands until the next rejuvenation, which is about an hour.
fn wanted(has_mapping: bool, problems: &SourceProblems) -> Option<String> {
    if has_mapping {
        problems.standing()
    } else {
        Some(NO_MAPPING.to_string())
    }
}

/// What happened.
#[derive(Debug)]
pub enum Event {
    /// The processor started, and holds no mapping.
    Started,
    /// The section in force was read: a mapping with its version, none, or what was wrong with it.
    Mapping(Result<Option<(u64, Projection)>, Vec<String>>),
    /// A document came from the observer.
    Observed(Observation),
}

/// What to do next.
#[derive(Debug, PartialEq)]
pub enum Step {
    /// Write these, as one transaction.
    Write {
        source: String,
        writes: Vec<Write>,
    },
    Health(HealthChange),
}

/// A processor's decisions.
#[derive(Debug)]
pub struct Processing {
    workload: &'static str,
    projection: Option<(u64, Projection)>,
    problems: SourceProblems,
    reported: Reported,
}

impl Processing {
    pub fn new(workload: &'static str) -> Self {
        Self {
            workload,
            projection: None,
            problems: SourceProblems::new(1),
            reported: Reported::default(),
        }
    }

    pub fn on(&mut self, event: Event) -> Vec<Step> {
        let mut steps = Vec::new();
        match event {
            Event::Started => {}
            Event::Mapping(Ok(Some((version, projection)))) => {
                info!("projection version {version} in force");
                self.projection = Some((version, projection));
            }
            Event::Mapping(Ok(None)) => info!("{NO_MAPPING}"),
            // Judged when it arrived, so this is not expected. What is in force stays.
            Event::Mapping(Err(problems)) => error!("the projection in force: {problems:?}"),
            Event::Observed(observation) => {
                let source = observation.source.clone();
                let Some((version, projection)) = &self.projection else {
                    warn!("what `{source}` said is not written: {NO_MAPPING}");
                    return steps;
                };
                let outcome = process(projection, *version, self.workload, &observation);
                note_outcome(&mut self.problems, &source, &outcome);
                match outcome {
                    Outcome::Write { writes, skipped } => {
                        info!(
                            "`{source}`: written under projection {version}, {skipped} entries skipped"
                        );
                        if !writes.is_empty() {
                            steps.push(Step::Write { source, writes });
                        }
                    }
                    Outcome::Refused(why) => warn!("what `{source}` said is not written: {why}"),
                }
            }
        }
        if let Some(change) = self
            .reported
            .next(wanted(self.projection.is_some(), &self.problems))
        {
            steps.push(Step::Health(change));
        }
        steps
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_projection::testing::{EdgeKey, MemoryGraph, Props};
    use polar_projection::{Bounds, Edge, Scalar, Shape};
    use proptest::prelude::*;
    use serde_json::{Value, json};
    use std::collections::{BTreeMap, BTreeSet};

    const BOUNDS: Bounds<'static> = Bounds {
        shapes: &[
            Shape {
                label: "TestDoc",
                keys: &["source"],
            },
            Shape {
                label: "TestPart",
                keys: &["source", "n"],
            },
        ],
        edges: &[Edge {
            from: "TestDoc",
            kind: "HAS_PART",
            to: "TestPart",
        }],
    };

    fn body() -> Value {
        json!({ "guard": [{ "any_of": [{ "path": "body.title", "prefixes": [] }] }], "rules": [{
            "name": "doc", "parent": "", "each": [], "label": "TestDoc",
            "keys": [{ "name": "source", "from": "source" }],
            "set": [{ "name": "title", "from": "body.title" }],
            "edge": ""
        }]})
    }

    fn observation(document: &[u8]) -> Observation {
        Observation {
            source: "s".to_string(),
            observed_at_unix_secs: 1,
            body: document.to_vec(),
        }
    }

    #[test]
    fn a_document_becomes_its_writes_and_what_is_not_json_is_refused() {
        let projection = Projection::judged(&body(), BOUNDS).unwrap();
        match process(&projection, 3, "w", &observation(br#"{"title":"t"}"#)) {
            Outcome::Write { writes, skipped: 0 } => assert_eq!(writes.len(), 1),
            other => panic!("{other:?}"),
        }
        for not_json in [&b"openapi: 3.0.0\n"[..], b"", b"{"] {
            assert!(matches!(
                process(&projection, 3, "w", &observation(not_json)),
                Outcome::Refused(_)
            ));
        }
    }

    #[test]
    fn a_document_that_fails_its_guard_stands_as_a_problem_until_a_good_one_comes() {
        let projection = Projection::judged(&body(), BOUNDS).unwrap();
        let mut problems = SourceProblems::new(1);
        let refused = process(
            &projection,
            1,
            "w",
            &observation(br#"{"error":"password=hunter2"}"#),
        );
        assert!(
            matches!(&refused, Outcome::Refused(_)),
            "nothing is written"
        );
        note_outcome(&mut problems, "s", &refused);
        let standing = wanted(true, &problems).unwrap();
        assert!(
            standing.contains("`s`") && standing.contains("body.title"),
            "{standing}"
        );
        assert!(!standing.contains("hunter2"), "{standing}");
        let good = process(&projection, 1, "w", &observation(br#"{"title":"t"}"#));
        note_outcome(&mut problems, "s", &good);
        assert_eq!(wanted(true, &problems), None);
    }

    #[test]
    fn entries_that_could_not_be_identified_stand_as_a_problem_though_the_rest_are_written() {
        let mut problems = SourceProblems::new(1);
        note_outcome(
            &mut problems,
            "s",
            &Outcome::Write {
                writes: vec![],
                skipped: 2,
            },
        );
        assert!(wanted(true, &problems).unwrap().contains("2 entries"));
    }

    #[test]
    fn having_no_mapping_says_more_than_any_source_can() {
        let mut problems = SourceProblems::new(1);
        problems.failed("s", "no");
        assert_eq!(wanted(false, &problems).as_deref(), Some(NO_MAPPING));
        assert!(wanted(true, &problems).unwrap().contains("`s`"));
    }

    #[test]
    fn until_a_mapping_is_in_force_nothing_is_written_and_health_says_why() {
        let mut processing = Processing::new("w");
        assert_eq!(
            processing.on(Event::Started),
            [Step::Health(HealthChange::Hold(NO_MAPPING.to_string()))]
        );
        assert!(
            processing
                .on(Event::Observed(observation(br#"{"title":"t"}"#)))
                .is_empty()
        );
        let projection = Projection::judged(&body(), BOUNDS).unwrap();
        assert_eq!(
            processing.on(Event::Mapping(Ok(Some((1, projection))))),
            [Step::Health(HealthChange::Release)]
        );
        let steps = processing.on(Event::Observed(observation(br#"{"title":"t"}"#)));
        assert!(
            matches!(&steps[..], [Step::Write { source, writes }] if source == "s" && writes.len() == 1),
            "{steps:?}"
        );
    }

    proptest! {
        #[test]
        fn any_bytes_are_written_or_refused_and_never_panic(document in prop::collection::vec(any::<u8>(), 0..128)) {
            let projection = Projection::judged(&body(), BOUNDS).unwrap();
            let _ = process(&projection, 1, "w", &observation(&document));
        }
    }

    // The model. Two mappings over one schema, each choosing other data; a graph that does what MERGE and SET do; and
    // documents described plainly, so what each should leave in the graph is said without the engine.

    /// The mappings the model knows: `doc` takes its title from `title` in the first and from `name` in the second; a
    /// part has its `size` in the first and its `color` in the second. Each part is identified by its `id`.
    fn mapping(which: usize) -> Value {
        let (title, part_field, part_from) = [
            ("body.title", "size", "part.size"),
            ("body.name", "color", "part.color"),
        ][which];
        json!({ "guard": [{ "any_of": [{ "path": "body.kind", "prefixes": ["doc"] }] }], "rules": [
            { "name": "doc", "parent": "", "each": [], "label": "TestDoc",
              "keys": [{ "name": "source", "from": "source" }],
              "set": [{ "name": "title", "from": title }], "edge": "" },
            { "name": "part", "parent": "doc",
              "each": [{ "key": "i", "value": "part", "over": "body.parts", "only": [] }],
              "label": "TestPart",
              "keys": [{ "name": "source", "from": "source" }, { "name": "n", "from": "part.id" }],
              "set": [{ "name": part_field, "from": part_from }], "edge": "HAS_PART" },
        ]})
    }

    #[derive(Debug, Clone)]
    struct Part {
        id: Option<String>,
        size: Option<i64>,
        color: Option<String>,
    }

    #[derive(Debug, Clone)]
    struct Document {
        title: Option<String>,
        name: Option<String>,
        parts: Vec<Part>,
    }

    impl Document {
        /// As the observer would publish it: `kind` says whether it is the document the mapping was written for.
        fn json(&self, kind: &str) -> Vec<u8> {
            let mut body = json!({ "kind": kind, "parts": self.parts.iter().map(|p| {
                let mut part = json!({});
                if let Some(id) = &p.id { part["id"] = json!(id) }
                if let Some(size) = p.size { part["size"] = json!(size) }
                if let Some(color) = &p.color { part["color"] = json!(color) }
                part
            }).collect::<Vec<_>>() });
            if let Some(title) = &self.title {
                body["title"] = json!(title);
            }
            if let Some(name) = &self.name {
                body["name"] = json!(name);
            }
            serde_json::to_vec(&body).unwrap()
        }

        fn unidentified(&self) -> usize {
            self.parts.iter().filter(|p| p.id.is_none()).count()
        }
    }

    /// The graph: what Neo4j does with the writes, as a kind's tests hold real Neo4j to (`polar-http-testkit`).
    type Graph = MemoryGraph;

    fn doc_key(source: &str) -> String {
        format!(
            "TestDoc{:?}",
            [("source".to_string(), Scalar::Text(source.to_string()))]
        )
    }

    fn part_key(source: &str, n: &str) -> String {
        format!(
            "TestPart{:?}",
            [
                ("source".to_string(), Scalar::Text(source.to_string())),
                ("n".to_string(), Scalar::Text(n.to_string()))
            ]
        )
    }

    /// The last good document of a source, the mapping and version it was written under, and when it was read.
    #[derive(Debug, Clone)]
    struct Written {
        document: Document,
        mapping: usize,
        version: u64,
        at: i64,
    }

    impl Written {
        fn stamps(&self, source: &str) -> Props {
            [
                ("polar_source", Scalar::Text(source.to_string())),
                ("polar_workload", Scalar::Text("w".to_string())),
                (
                    "polar_projection_version",
                    Scalar::Integer(self.version as i64),
                ),
                ("polar_observed_at", Scalar::Integer(self.at)),
            ]
            .into_iter()
            .map(|(n, v)| (n.to_string(), v))
            .collect()
        }

        /// What it says, as the mapping it was written under would put it: each node with the properties that mapping
        /// sets, and each edge, with the stamps. A property it does not have is not there.
        fn expected(&self, source: &str) -> (BTreeMap<String, Props>, BTreeSet<EdgeKey>) {
            let mut nodes = BTreeMap::new();
            let mut doc = self.stamps(source);
            let title = [&self.document.title, &self.document.name][self.mapping];
            if let Some(title) = title {
                doc.insert("title".to_string(), Scalar::Text(title.clone()));
            }
            nodes.insert(doc_key(source), doc);
            let mut edges = BTreeSet::new();
            for part in &self.document.parts {
                let Some(id) = &part.id else { continue };
                let mut props = self.stamps(source);
                match self.mapping {
                    0 => part
                        .size
                        .map(|s| props.insert("size".to_string(), Scalar::Integer(s))),
                    _ => part
                        .color
                        .clone()
                        .map(|c| props.insert("color".to_string(), Scalar::Text(c))),
                };
                // The last part with an id is the one that stands.
                nodes.insert(part_key(source, id), props);
                edges.insert((
                    doc_key(source),
                    "HAS_PART".to_string(),
                    part_key(source, id),
                ));
            }
            (nodes, edges)
        }
    }

    #[derive(Debug, Clone)]
    enum Kind {
        Good,
        NotTheDocument,
        NotJson,
    }

    #[derive(Debug, Clone)]
    enum Happens {
        Accept(usize),
        Refuse,
        /// The section in force is read again, as at start.
        Reread,
        Restart,
        Observed(usize, Document, Kind),
    }

    fn document() -> impl Strategy<Value = Document> {
        let text = || prop::option::of("[a-c]{0,2}");
        let part = (prop::option::of("[ab]"), prop::option::of(0i64..3), text())
            .prop_map(|(id, size, color)| Part { id, size, color });
        (text(), text(), prop::collection::vec(part, 0..4))
            .prop_map(|(title, name, parts)| Document { title, name, parts })
    }

    fn happens() -> impl Strategy<Value = Happens> {
        prop_oneof![
            2 => (0usize..2).prop_map(Happens::Accept),
            1 => Just(Happens::Refuse),
            1 => Just(Happens::Reread),
            1 => Just(Happens::Restart),
            8 => (0usize..2, document(), prop_oneof![
                6 => Just(Kind::Good),
                2 => Just(Kind::NotTheDocument),
                1 => Just(Kind::NotJson),
            ]).prop_map(|(s, d, k)| Happens::Observed(s, d, k)),
        ]
    }

    proptest! {
        /// Held to a model over any sequence of mappings, refusals, documents and restarts: for each source, the graph
        /// holds what its last good document says under the mapping in force when it came, stamped with that mapping's
        /// version and when it was read; anything else of that source is from an earlier good document of it; a document
        /// that is refused, or comes when no mapping is held, changes nothing; and health says there is no mapping exactly
        /// when none is held, and otherwise names exactly the sources whose last document was refused or had entries
        /// skipped. What the model leaves out: a property an earlier mapping set and the one in force does not set stays
        /// on its node, as an entry a document dropped does.
        #[test]
        fn the_graph_holds_the_last_good_document_under_the_mapping_in_force(
            events in prop::collection::vec(happens(), 1..30)
        ) {
            const SOURCES: [&str; 2] = ["a", "b"];
            let mut processing = Processing::new("w");
            let mut graph = Graph::default();
            // The model.
            let mut in_force: Option<(usize, u64)> = None;
            let mut held: Option<(usize, u64)> = None;
            let mut last: BTreeMap<&str, Written> = BTreeMap::new();
            let mut good_times: BTreeMap<&str, BTreeSet<i64>> = BTreeMap::new();
            let mut problem: BTreeSet<&str> = BTreeSet::new();
            let mut told: Option<String> = None;
            let mut versions = 0u64;
            let mut clock = 0i64;

            let judged = |which: usize, version: u64| {
                Some((version, Projection::judged(&mapping(which), BOUNDS).unwrap()))
            };
            let mut steps = processing.on(Event::Started);
            for happened in events {
                let before = graph.clone();
                match &happened {
                    Happens::Accept(which) => {
                        versions += 1;
                        in_force = Some((*which, versions));
                        held = in_force;
                        steps.extend(processing.on(Event::Mapping(Ok(judged(*which, versions)))));
                    }
                    Happens::Refuse => {
                        steps.extend(processing.on(Event::Mapping(Err(vec!["not a projection".to_string()]))));
                    }
                    Happens::Reread => {
                        let read = in_force.and_then(|(which, version)| judged(which, version));
                        steps.extend(processing.on(Event::Mapping(Ok(read))));
                        held = in_force;
                    }
                    Happens::Restart => {
                        processing = Processing::new("w");
                        held = None;
                        problem.clear();
                        told = None;
                        steps.extend(processing.on(Event::Started));
                    }
                    Happens::Observed(s, document, kind) => {
                        clock += 1;
                        let source = SOURCES[*s];
                        let body = match kind {
                            Kind::Good => document.json("doc-1"),
                            Kind::NotTheDocument => document.json("other"),
                            Kind::NotJson => b"kind: doc-1\n".to_vec(),
                        };
                        steps.extend(processing.on(Event::Observed(Observation {
                            source: source.to_string(),
                            observed_at_unix_secs: clock,
                            body,
                        })));
                        if let Some((which, version)) = held {
                            if matches!(kind, Kind::Good) {
                                last.insert(source, Written { document: document.clone(), mapping: which, version, at: clock });
                                good_times.entry(source).or_default().insert(clock);
                                if document.unidentified() > 0 {
                                    problem.insert(source);
                                } else {
                                    problem.remove(source);
                                }
                            } else {
                                problem.insert(source);
                            }
                        }
                    }
                }
                for step in steps.drain(..) {
                    match step {
                        Step::Write { source, writes } => {
                            prop_assert!(matches!(happened, Happens::Observed(s, _, Kind::Good) if SOURCES[s] == source));
                            graph.apply(&writes);
                        }
                        Step::Health(HealthChange::Hold(message)) => told = Some(message),
                        Step::Health(HealthChange::Release) => told = None,
                    }
                }
                let changes = matches!(happened, Happens::Observed(_, _, Kind::Good)) && held.is_some();
                if !changes {
                    prop_assert_eq!(&graph, &before, "{:?} changed the graph", happened);
                }
                for (source, written) in &last {
                    let (nodes, edges) = written.expected(source);
                    for (key, props) in &nodes {
                        let got = graph.nodes.get(key);
                        let got: Option<Props> = got.map(|node| {
                            let p = &node.props;
                            // Only what the mapping in force when it came sets, and the stamps.
                            p.iter()
                                .filter(|(n, _)| n.starts_with("polar_") || ["title", ["size", "color"][written.mapping]].contains(&n.as_str()))
                                .map(|(n, v)| (n.clone(), v.clone()))
                                .collect()
                        });
                        prop_assert_eq!(got.as_ref(), Some(props), "{}", key);
                    }
                    for edge in &edges {
                        let got = graph.edges.get(edge);
                        prop_assert_eq!(got, Some(&written.stamps(source)), "{:?}", edge);
                    }
                    for (key, node) in &graph.nodes {
                        let props = &node.props;
                        if props.get("polar_source") != Some(&Scalar::Text(source.to_string())) {
                            continue;
                        }
                        let Some(Scalar::Integer(at)) = props.get("polar_observed_at") else {
                            prop_assert!(false, "{} is not stamped", key);
                            continue;
                        };
                        if *at == written.at {
                            prop_assert!(nodes.contains_key(key), "{} is not in the last document", key);
                        } else {
                            prop_assert!(good_times[source].contains(at) && *at < written.at, "{}", key);
                        }
                    }
                }
                match held {
                    None => prop_assert_eq!(told.as_deref(), Some(NO_MAPPING)),
                    Some(_) => {
                        prop_assert_eq!(told.is_some(), !problem.is_empty(), "{:?} {:?}", told, problem);
                        for source in SOURCES {
                            let named = told.as_deref().is_some_and(|t| t.contains(&format!("`{source}`")));
                            prop_assert_eq!(named, problem.contains(source), "{:?} {:?}", told, problem);
                        }
                    }
                }
            }
        }
    }
}
