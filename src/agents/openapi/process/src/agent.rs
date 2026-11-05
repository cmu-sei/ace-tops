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
    Capability, Configured, GraphDecl, PolarAgent, RuntimeSection, StartError, TopicDecl,
};
use polar_http_processor::{Kind, SECTION_BODY, SECTION_NAME, judge, node_shapes};
use polar_projection::{Bounds, Shape};
use serde_json::Value;
use std::time::Duration;

/// What this workload was built to write. A signed mapping chooses data inside it, and cannot widen it.
pub const SCHEMA: Bounds = Bounds {
    shapes: &[
        Shape {
            label: "OpenApiApplication",
            keys: &["source"],
        },
        Shape {
            label: "OpenApiEndpoint",
            keys: &["source", "method", "path"],
        },
    ],
    edges: &["HAS_ENDPOINT"],
};

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
    const BOUNDS: Bounds = SCHEMA;
}

impl PolarAgent for OpenApiProcessor {
    const NAME: &'static str = PROCESSOR_NAME;
    const PURPOSE: &'static str = "Writes the applications and endpoints the OpenAPI documents describe into the graph, by a signed projection";
    const NEEDS: &'static [Capability] = &[Capability::GraphWrite];
    const SHUTDOWN_BUDGET: Duration = polar_http_processor::SHUTDOWN_BUDGET;
    const TOPICS: &'static [TopicDecl] = &[TopicDecl::subscribe(
        OBSERVATIONS_TOPIC,
        "the documents the observer read, written to the graph",
    )];
    const RUNTIME: &'static [&'static RuntimeSection] = &[&PROJECTION];
    const GRAPH: &'static [GraphDecl] = &[
        GraphDecl::owns("OpenApiApplication", "each source's application"),
        GraphDecl::owns("OpenApiEndpoint", "each operation of each application"),
    ];
    const GRAPH_KEYS: &'static [fn() -> Vec<NodeShape>] = &[shapes];
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

    polar_agent_builder::polar_agent_tests!(OpenApiProcessor);

    /// The mapping shipped beside the engine, as `polar-sign` reads it, is inside this workload's schema.
    #[test]
    fn the_example_mapping_is_inside_the_schema() {
        let ty: serde_dhall::SimpleType = serde_dhall::from_str(polar_projection::SCHEMA)
            .imports(false)
            .parse()
            .unwrap();
        let simple: serde_dhall::SimpleValue = serde_dhall::from_str(include_str!(
            "../../../polar-projection/examples/openapi.dhall"
        ))
        .imports(false)
        .type_annotation(&ty)
        .parse()
        .unwrap();
        (PROJECTION.validate)(&serde_json::to_value(&simple).unwrap()).unwrap();
    }

    /// Declared once for the scaffold and once for the bound, so they are held to each other.
    #[test]
    fn what_it_declares_it_owns_is_what_its_schema_says() {
        let declared: Vec<&str> = OpenApiProcessor::GRAPH.iter().map(|g| g.label).collect();
        let schema: Vec<&str> = SCHEMA.shapes.iter().map(|s| s.label).collect();
        assert_eq!(declared, schema);
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
