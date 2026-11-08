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

//! What the OpenAPI processor is, as the infrastructure asks to be told: see `polar_agent_builder::PolarAgent`.

use openapi_common::{OBSERVATIONS_TOPIC, OBSERVER_NAME, PROCESSOR_NAME};
use polar::graph::controller::NodeShape;
use polar_agent_builder::runtime::SectionAuthority;
use polar_agent_builder::{
    Capability, Configured, EdgeDecl, GraphDecl, PolarAgent, Role, RuntimeSection, StartError,
    TopicDecl,
};
use polar_http_processor::{Kind, SECTION_BODY, SECTION_NAME, judge, node_shapes};
use polar_projection::Bounds;
use serde_json::Value;
use std::time::Duration;

polar_http_processor::schema! {
    labels {
        OpenApiApplication [source] "each source's application",
        OpenApiEndpoint [source, method, path] "each operation of each application",
    }
    edges {
        OpenApiApplication HAS_ENDPOINT OpenApiEndpoint "each operation of an application",
    }
}

fn validate(body: &Value) -> Result<(), Vec<String>> {
    judge(body, SCHEMA)
}

pub static PROJECTION: RuntimeSection = RuntimeSection {
    authority: SectionAuthority::Runtime,
    name: SECTION_NAME,
    doc: "How a document the observer read becomes nodes and edges, inside this workload's schema. Replaced whole by each version.",
    body: SECTION_BODY,
    validate,
};

fn shapes() -> Vec<NodeShape> {
    node_shapes(SCHEMA)
}

pub struct OpenApiProcessor;

impl Kind for OpenApiProcessor {
    const NAME: &'static str = PROCESSOR_NAME;
    const OBSERVER: &'static str = OBSERVER_NAME;
    const TOPIC: &'static str = OBSERVATIONS_TOPIC;
    const BOUNDS: Bounds<'static> = SCHEMA;
}

impl PolarAgent for OpenApiProcessor {
    const NAME: &'static str = PROCESSOR_NAME;
    const ROLE: Role = Role::Processor;
    const PURPOSE: &'static str = "Writes the applications and endpoints the OpenAPI documents describe into the graph, by a signed projection";
    const NEEDS: &'static [Capability] = &[Capability::GraphWrite];
    const SHUTDOWN_BUDGET: Duration = polar_http_processor::SHUTDOWN_BUDGET;
    const TOPICS: &'static [TopicDecl] = &[TopicDecl::subscribe(
        OBSERVATIONS_TOPIC,
        "the documents the observer read, written to the graph",
    )];
    const RUNTIME: &'static [&'static RuntimeSection] = &[&PROJECTION];
    const GRAPH: &'static [GraphDecl] = LABELS;
    const GRAPH_KEYS: &'static [fn() -> Vec<NodeShape>] = &[shapes];
    const GRAPH_EDGES: &'static [EdgeDecl] = EDGES;
    const HELP: Option<&'static str> = Some(
        "The processor writes each document the observer publishes into the graph, by its signed `projection` section. Until \
         one is signed it holds and writes nothing. A projection chooses which data goes where inside this workload's schema, \
         and cannot name another label, key or edge.",
    );

    async fn start(configured: Configured) -> Result<(), StartError> {
        polar_http_processor::start::<OpenApiProcessor>(configured).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_sign::scaffold::Scaffold;
    use proptest::prelude::*;
    use serde_json::json;

    polar_agent_builder::polar_agent_tests!(OpenApiProcessor);

    polar_http_testkit::polar_http_tests! {
        observer: openapi_observer::agent::OpenApiObserver,
        processor: OpenApiProcessor,
        mapping: "../../polar-projection/examples/openapi.dhall",
        samples: "../../polar-projection/examples/openapi",
    }

    const EXAMPLE: &str = include_str!("../../../polar-projection/examples/openapi.dhall");

    /// The mapping shipped beside the engine, as `polar-sign` reads it.
    fn example() -> Value {
        static BODY: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
        BODY.get_or_init(|| polar_sign::projection_body(EXAMPLE).unwrap())
            .clone()
    }

    /// What `openapi-processor --scaffold` prints, as the tool that signs a mapping reads it.
    fn scaffold() -> Scaffold {
        let json =
            polar_agent_builder::agent::scaffold_json::<OpenApiProcessor>(None, |_: &str| None)
                .unwrap();
        Scaffold::parse(&json).unwrap()
    }

    #[test]
    fn the_example_mapping_is_inside_the_schema() {
        (PROJECTION.validate)(&example()).unwrap();
        polar_sign::projection_for(&scaffold(), SECTION_NAME, EXAMPLE).unwrap();
    }

    /// The scaffold is the contract: what it says this workload writes is what the workload was built with.
    #[test]
    fn the_schema_read_back_from_the_scaffold_is_the_one_it_was_built_with() {
        let scaffold = scaffold();
        let owns: Vec<(&str, Vec<Vec<&str>>)> = scaffold
            .owns
            .iter()
            .map(|o| {
                (
                    o.label.as_str(),
                    o.keys
                        .iter()
                        .map(|k| k.iter().map(String::as_str).collect())
                        .collect(),
                )
            })
            .collect();
        let built: Vec<(&str, Vec<Vec<&str>>)> = SCHEMA
            .shapes
            .iter()
            .map(|s| (s.label, vec![s.keys.to_vec()]))
            .collect();
        assert_eq!(owns, built);
        let edges: Vec<(&str, &str, &str)> = scaffold
            .edges
            .iter()
            .map(|e| (e.from.as_str(), e.kind.as_str(), e.to.as_str()))
            .collect();
        let built: Vec<(&str, &str, &str)> = SCHEMA
            .edges
            .iter()
            .map(|e| (e.from, e.kind, e.to))
            .collect();
        assert_eq!(edges, built);
    }

    /// One change to the example: the names a mapping chooses, drawn from this workload's and others', Cypher's keywords
    /// and the engine's stamp, and the shape of its rules.
    fn changed() -> impl Strategy<Value = Value> {
        let label = prop_oneof![
            Just("OpenApiApplication"),
            Just("OpenApiEndpoint"),
            Just("Pod"),
            Just("Merge"),
        ];
        let name = prop_oneof![
            Just("source"),
            Just("method"),
            Just("path"),
            Just("id"),
            Just("title"),
            Just("delete"),
            Just("polar_source"),
        ];
        let edge = prop_oneof![Just(""), Just("HAS_ENDPOINT"), Just("OWNS"), Just("SET")];
        let parent = prop_oneof![Just(""), Just("application"), Just("endpoint")];
        (0usize..2, label, name.clone(), name, edge, parent, 0u8..5).prop_map(
            |(rule, label, key, set, edge, parent, what)| {
                let mut body = example();
                let r = &mut body["rules"][rule];
                match what {
                    0 => r["label"] = json!(label),
                    1 => r["keys"][0]["name"] = json!(key),
                    2 => r["set"][0]["name"] = json!(set),
                    3 => r["edge"] = json!(edge),
                    _ => r["parent"] = json!(parent),
                }
                body
            },
        )
    }

    proptest! {
        /// Nothing is signed that this agent would refuse, and nothing it would take is refused for signing: the tool,
        /// judging by the scaffold, and the agent, judging by what it was built with, decide alike.
        #[test]
        fn the_signing_tool_and_the_agent_refuse_the_same_mappings(body in changed()) {
            let scaffold = scaffold();
            prop_assert_eq!(
                scaffold.judge_projection(&body).is_ok(),
                (PROJECTION.validate)(&body).is_ok(),
                "{}", body
            );
        }
    }

    #[test]
    fn every_label_it_owns_gets_a_uniqueness_constraint_on_its_key() {
        let names: Vec<String> =
            polar_agent_builder::agent::graph_key_indexes::<OpenApiProcessor>()
                .iter()
                .map(|i| i.name())
                .collect();
        assert_eq!(
            names,
            [
                "polar_unique_OpenApiApplication_source",
                "polar_unique_OpenApiEndpoint_source_method_path",
            ]
        );
    }

    #[test]
    fn a_mapping_cannot_be_signed_for_another_workload_s_part_of_the_graph() {
        let mut body: Value = serde_json::json!({ "guard": [{ "any_of": [{ "path": "body", "prefixes": [] }] }], "rules": [{
            "name": "x", "parent": "", "each": [], "label": "JiraIssue",
            "keys": [{ "name": "key", "from": "source" }], "set": [], "edge": ""
        }]});
        assert!((PROJECTION.validate)(&body).is_err());
        body["rules"][0]["label"] = serde_json::json!("OpenApiApplication");
        assert!(
            (PROJECTION.validate)(&body).is_err(),
            "not the key it was built with"
        );
    }
}
