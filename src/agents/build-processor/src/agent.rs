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

//! What build-processor is, as the infrastructure asks to be told: see `polar_agent_builder::PolarAgent`.

use crate::AGENT_NAME;
use crate::supervisor::{ProcessorSupervisor, SHUTDOWN_BUDGET};
use polar::graph::controller::{NodeShape, shapes_of};
use polar::graph::nodes::builds::{ArtifactNodeKey, BuildNodeKey};
use polar_agent_builder::{Capability, Configured, GraphDecl, PolarAgent, StartError, TopicDecl};
use ractor::Actor;
use std::time::Duration;

pub struct BuildProcessor;

impl PolarAgent for BuildProcessor {
    const NAME: &'static str = AGENT_NAME;
    const PURPOSE: &'static str = "Projects the provenance stream (builds, what they produced, findings, what registries serve) into the graph";
    const NEEDS: &'static [Capability] = &[Capability::GraphWrite];
    const SHUTDOWN_BUDGET: Duration = SHUTDOWN_BUDGET;
    const TOPICS: &'static [TopicDecl] = &[TopicDecl::subscribe(
        polar::topics::PROVENANCE_EVENTS,
        "the provenance stream: builds, their outputs and findings, and what the resolver verified",
    )];
    // The labels it writes (`project`). Not `State`, the taxonomy anchor every state instance is OF_TYPE, which
    // kube-consumer writes too and which has no key; not a backend job's node or a `GitCommit`, which their observers
    // own and it only refers to.
    const GRAPH: &'static [GraphDecl] = &[
        GraphDecl::owns("BuildJob", "each build, by its id"),
        GraphDecl::owns("BuildJobState", "each state a build was seen in"),
        GraphDecl::owns("BuildStage", "each stage of a build"),
        GraphDecl::owns("BuildExecution", "the anchor every build IS"),
        GraphDecl::owns("BuildArtifact", "what a build produced, by content hash"),
        GraphDecl::owns("Artifact", "the anchor every artifact IS"),
        GraphDecl::owns("Binary", "each binary, by content hash"),
        GraphDecl::owns("Sbom", "each SBOM, by the artifact it describes"),
        GraphDecl::owns("Package", "each package, by purl"),
        GraphDecl::owns("OCIArtifact", "each image manifest, by digest"),
        GraphDecl::owns(
            "OCILayer",
            "each layer blob a registry serves, by compressed digest",
        ),
        GraphDecl::owns(
            "OCILayerDiffId",
            "each layer as a built image's config names it, by uncompressed diff ID",
        ),
        GraphDecl::owns("OCIRegistry", "each registry, by host"),
        GraphDecl::owns("SecurityAdvisory", "each advisory a scanner reported"),
        GraphDecl::owns("PackageStatus", "each package status a scanner reported"),
        GraphDecl::owns("Finding", "the anchor every finding IS"),
    ];
    // The constraints for the labels above come from here, on what each is merged on.
    const GRAPH_KEYS: &'static [fn() -> Vec<NodeShape>] =
        &[shapes_of::<ArtifactNodeKey>, shapes_of::<BuildNodeKey>];
    const HELP: Option<&'static str> = Some(
        "build-processor subscribes to the provenance stream on Cassini and writes each event into the graph: the \
         builds the orchestrator and CI report, what they produced, what scanners found, and what the resolver \
         verified a registry serves. It is the only writer of those labels. It needs the graph (GRAPH_*).",
    );

    async fn start(configured: Configured) -> Result<(), StartError> {
        configured.init_logging(AGENT_NAME);

        rustls::crypto::ring::default_provider()
            .install_default()
            .map_err(|_| "a rustls crypto provider was already installed")?;

        let name = format!("{AGENT_NAME}.supervisor");
        let (_, handle) = Actor::spawn(Some(name.clone()), ProcessorSupervisor, configured)
            .await
            .map_err(|e| format!("{name} failed to start: {e}"))?;
        handle
            .await
            .map_err(|e| format!("{name} task failed: {e}"))?;

        // A processor that is no longer processing must be restarted.
        Err(format!("{name} stopped").into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    polar_agent_builder::polar_agent_tests!(BuildProcessor);

    /// Every label it owns is merged on a key its vocabulary names, so each gets its constraint at start, and two
    /// writers of one node race to one node, not two.
    #[test]
    fn every_label_it_owns_gets_a_constraint() {
        let indexes = polar_agent_builder::agent::graph_key_indexes::<BuildProcessor>();
        for decl in BuildProcessor::GRAPH {
            assert!(
                indexes.iter().any(|i| i.label == decl.label),
                "{} has none",
                decl.label
            );
        }
    }

    /// It reads the provenance stream and nothing else: the legacy linker topic has had no publisher since the old
    /// GitLab consumer went.
    #[test]
    fn it_subscribes_to_the_provenance_stream_alone() {
        use polar_agent_builder::Access;
        let topics: Vec<(&str, bool)> = BuildProcessor::TOPICS
            .iter()
            .map(|t| (t.name, t.access == Access::Subscribe))
            .collect();
        assert_eq!(topics, [(polar::topics::PROVENANCE_EVENTS, true)]);
    }
}
