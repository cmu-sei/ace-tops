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

//! What the GitLab processor is, as the infrastructure asks to be told: see `polar_agent_builder::PolarAgent`.

use gitlab_http_common::{OBSERVATIONS_TOPIC, OBSERVER_NAME, PROCESSOR_NAME};
use polar::graph::controller::NodeShape;
use polar_agent_builder::runtime::SectionAuthority;
use polar_agent_builder::{
    Capability, Configured, EdgeDecl, GraphDecl, PolarAgent, RuntimeSection, StartError, TopicDecl,
};
use polar_http_processor::{Kind, SECTION_BODY, SECTION_NAME, judge, node_shapes};
use polar_projection::Bounds;
use serde_json::Value;
use std::time::Duration;

// Each node is keyed by the origin of the GitLab it came from and GitLab's own id, which is unique only within one GitLab.
polar_http_processor::schema! {
    labels {
        GitlabInstance [origin] "each GitLab instance read",
        GitlabProject [origin, id] "each project",
        GitlabUser [origin, id] "each user",
        GitlabGroup [origin, id] "each group",
        GitlabRunner [origin, id] "each runner",
        GitlabPipeline [origin, id] "each pipeline of a project",
        GitlabJob [origin, id] "each job of a pipeline",
        GitlabContainerRepository [origin, id] "each container repository of a project",
        GitlabPackage [origin, id] "each package of a project",
    }
    edges {
        GitlabGroup SUBGROUP_OF GitlabGroup "a group within its parent group",
        GitlabGroup HAS_MEMBER GitlabUser "a group's member",
        GitlabProject HAS_PIPELINE GitlabPipeline "a project's pipeline",
        GitlabPipeline HAS_JOB GitlabJob "a pipeline's job",
        GitlabJob EXECUTED_BY GitlabRunner "the runner that ran a job",
        GitlabProject HAS_CONTAINER_REPOSITORY GitlabContainerRepository "a project's container repository",
        GitlabProject HAS_PACKAGE GitlabPackage "a project's package",
    }
}

fn validate(body: &Value) -> Result<(), Vec<String>> {
    judge(body, SCHEMA)
}

pub static PROJECTION: RuntimeSection = RuntimeSection {
    authority: SectionAuthority::Runtime,
    name: SECTION_NAME,
    doc: "How a page the GitLab observer read becomes nodes and edges, inside this workload's schema. Replaced whole by each version.",
    body: SECTION_BODY,
    validate,
};

fn shapes() -> Vec<NodeShape> {
    node_shapes(SCHEMA)
}

pub struct GitlabProcessor;

impl Kind for GitlabProcessor {
    const NAME: &'static str = PROCESSOR_NAME;
    const OBSERVER: &'static str = OBSERVER_NAME;
    const TOPIC: &'static str = OBSERVATIONS_TOPIC;
    const BOUNDS: Bounds<'static> = SCHEMA;
}

impl PolarAgent for GitlabProcessor {
    const NAME: &'static str = PROCESSOR_NAME;
    const PURPOSE: &'static str =
        "Writes what GitLab's pages say into the graph, by a signed projection";
    const NEEDS: &'static [Capability] = &[Capability::GraphWrite];
    const SHUTDOWN_BUDGET: Duration = polar_http_processor::SHUTDOWN_BUDGET;
    const TOPICS: &'static [TopicDecl] = &[TopicDecl::subscribe(
        OBSERVATIONS_TOPIC,
        "the pages the observer read, written to the graph",
    )];
    const RUNTIME: &'static [&'static RuntimeSection] = &[&PROJECTION];
    const GRAPH: &'static [GraphDecl] = LABELS;
    const GRAPH_KEYS: &'static [fn() -> Vec<NodeShape>] = &[shapes];
    const GRAPH_EDGES: &'static [EdgeDecl] = EDGES;
    const HELP: Option<&'static str> = Some(
        "The processor writes each page the observer publishes into the graph, by its signed `projection` section, each \
         node keyed by the origin of the GitLab it came from and GitLab's own id. Until one is signed it holds and writes \
         nothing. A projection chooses which data goes where inside this workload's schema, and cannot name another \
         label, key or edge.",
    );

    async fn start(configured: Configured) -> Result<(), StartError> {
        polar_http_processor::start::<GitlabProcessor>(configured).await
    }
}

#[cfg(test)]
mod tests;
