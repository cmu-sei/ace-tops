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

//! What build-orchestrator is, as the infrastructure asks to be told: see `polar_agent_builder::PolarAgent`.

use crate::AGENT_NAME;
use crate::supervisor::{OrchestratorSupervisor, SHUTDOWN_BUDGET};
use polar::topics::{GIT_REPOSITORY_EVENTS, PROVENANCE_EVENTS, PROVENANCE_EXECUTIONS};
use polar_agent_builder::protocol::OperationDecl;
use polar_agent_builder::worker::WorkerDecl;
use polar_agent_builder::{Capability, Cause, Configured, PolarAgent, Role, StartError, TopicDecl};
use ractor::Actor;
use std::time::Duration;

pub struct BuildOrchestrator;

impl PolarAgent for BuildOrchestrator {
    const NAME: &'static str = AGENT_NAME;
    const ROLE: Role = Role::Controller;
    const PURPOSE: &'static str = "Builds a mapped repository when a ref of it moves, as a Job in the build namespace, and \
                                   relays what the build reports once judged";
    // Its Kubernetes calls are its operations; `job-run` is computed from their writes.
    const NEEDS: &'static [Capability] = &[];
    const SHUTDOWN_BUDGET: Duration = SHUTDOWN_BUDGET;
    const OPERATIONS: &'static [OperationDecl] = orchestrator_backend_k8s::backend::OPERATIONS;
    const WORKERS: &'static [WorkerDecl] = &[crate::reader::DECL];
    const TOPICS: &'static [TopicDecl] = &[
        TopicDecl::subscribe(
            GIT_REPOSITORY_EVENTS,
            "a ref of an observed repository moved: built if a mapping names the repository",
        ),
        TopicDecl::publish(
            PROVENANCE_EVENTS,
            "what a build reported, judged and re-encoded, each in a BuildReport envelope stamped with the build's id",
        )
        .because(&[Cause::Topic(GIT_REPOSITORY_EVENTS)]),
        TopicDecl::publish(
            PROVENANCE_EXECUTIONS,
            "what it observed of a build it ran: started, completed, failed or cancelled",
        )
        .because(&[Cause::Topic(GIT_REPOSITORY_EVENTS)]),
    ];
    const SECTIONS: &'static [&'static polar_env::Section] = &[&crate::settings::SECTION];
    const RUNTIME: &'static [&'static polar_agent_builder::RuntimeSection] =
        &[&crate::mappings::MAPPINGS];
    const HELP: Option<&'static str> = Some(
        "build-orchestrator builds a repository when the git observer reports that a ref of it moved and the `mappings` \
         runtime section (a signed document) names it: a Job made from the build workload's PodTemplate \
         (POLAR_ORCHESTRATOR_TEMPLATE, in POLAR_ORCHESTRATOR_NAMESPACE), on the mapping's pinned image, with the \
         privileges the mapping signs and no more. A build holds no Polar identity: it prints its reports, and the \
         orchestrator reads them with a locked-down worker once the pod ends, judges each and relays it. How many builds \
         run at once, what a pipeline may use, how long a Job is kept and how much a build may report are its run-time \
         settings.",
    );

    async fn start(configured: Configured) -> Result<(), StartError> {
        configured.init_logging(AGENT_NAME);

        let name = format!("{AGENT_NAME}.supervisor");
        let (_, handle) = Actor::spawn(Some(name.clone()), OrchestratorSupervisor, configured)
            .await
            .map_err(|e| format!("{name} failed to start: {e}"))?;
        handle
            .await
            .map_err(|e| format!("{name} task failed: {e}"))?;

        // An orchestrator that is no longer orchestrating must be restarted.
        Err(format!("{name} stopped").into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    polar_agent_builder::polar_agent_tests!(BuildOrchestrator);

    #[test]
    fn it_runs_jobs_and_reads_with_a_worker() {
        let scaffold = polar_agent_builder::agent::scaffold_document::<BuildOrchestrator>();
        assert!(
            scaffold
                .operations
                .iter()
                .all(|o| o.protocol == "kubernetes" && o.location == "cluster"),
            "{:?}",
            scaffold.operations
        );
        assert_eq!(
            scaffold.operations.len(),
            orchestrator_backend_k8s::backend::OPERATIONS.len()
        );
        // Computed from its writes, and nothing more: no read of the whole cluster.
        assert_eq!(scaffold.requires, ["cassini", "job-run"]);
    }
}
