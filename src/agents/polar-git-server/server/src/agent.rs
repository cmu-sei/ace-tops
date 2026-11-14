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

use crate::supervisor::{GitServerSupervisor, SERVICE_NAME, SHUTDOWN_BUDGET};
use polar_agent_builder::{Capability, Cause, Configured, PolarAgent, Role, StartError, TopicDecl};
use polar_env::Section;
use ractor::Actor;
use std::time::Duration;

pub struct GitServer;

impl PolarAgent for GitServer {
    const NAME: &'static str = SERVICE_NAME;
    const ROLE: Role = Role::Service;
    const PURPOSE: &'static str = "Hosts Polar's configuration repositories over git smart HTTP, authenticating users and agents by their mTLS certificates";
    // Its logs' checkpoints are signed with a key its crypto actor keeps and has certified (docs/architecture/record-store.md).
    const NEEDS: &'static [Capability] = &[Capability::Checkpoints];
    // It runs on its own or in a cluster: a Cassini client when its deployment provides Cassini.
    const OPTIONAL: &'static [Capability] = &[Capability::Cassini];
    const CASSINI_CLIENT: bool = false;
    const SHUTDOWN_BUDGET: Duration = SHUTDOWN_BUDGET;
    const TOPICS: &'static [TopicDecl] = &[
        TopicDecl::publish(
            polar_git_server_common::POLAR_GIT_REPO_CHANGED_TOPIC,
            "each push it accepted, and each evidence record it added (repository, ref, old and new commit, pusher), when it has a broker",
        )
        .because(&[
            Cause::Http(polar_git_server_common::RECEIVE_PACK_ROUTE),
            Cause::Topic(polar_git_server_common::EVIDENCE_REQUESTS_TOPIC),
        ]),
        TopicDecl::subscribe(
            polar_git_server_common::EVIDENCE_REQUESTS_TOPIC,
            "a signed evidence record to add to polar-evidence, from a collector that is a workload",
        ),
        TopicDecl::publish(
            polar_git_server_common::ATTESTATION_AGENT_EVIDENCE_REPLIES_TOPIC,
            "what became of the attestation agent's record, on its own topic",
        )
        .because(&[Cause::Topic(polar_git_server_common::EVIDENCE_REQUESTS_TOPIC)]),
        TopicDecl::subscribe(
            polar_git_server_common::READ_REQUESTS_TOPIC,
            "a request for what a repository's main holds, from an agent that may read it",
        ),
        TopicDecl::publish(
            polar_git_server_common::SCHEDULER_OBSERVER_READ_REPLIES_TOPIC,
            "what a repository's main holds, for the scheduler observer, on its own topic",
        )
        .because(&[Cause::Topic(polar_git_server_common::READ_REQUESTS_TOPIC)]),
    ];
    const SECTIONS: &'static [&'static Section] = &[&crate::settings::SECTION];
    const HELP: Option<&'static str> = Some(
        "The git server serves the repositories its configuration file declares to the user's own \
         git client. Every connection presents a certificate chaining to its CA; the \
         identity in it decides what that caller may read or push, per repository. After a push \
         is accepted it logs it and, in a Polar cluster, publishes the change on Cassini. It keeps signed logs beside the \
         repositories, each checkpoint signed by its crypto actor, and serves them to people as C2SP tiles. In a cluster \
         it also takes signed evidence records on polar-git-evidence-requests from workloads that may write \
         polar-evidence, verifies each, appends it to the evidence log, commits it there itself and answers on the \
         sender's own topic, so no agent pushes with git; and it answers requests on \
         polar-git-read-requests for what a repository's main holds, from agents that may read it, on each reader's own \
         topic, so no agent reads with git. Repositories are created and seeded from the configuration the first time, and \
         never overwritten after that.",
    );

    async fn start(configured: Configured) -> Result<(), StartError> {
        configured.init_logging(SERVICE_NAME);
        let (_supervisor, handle) = Actor::spawn(
            Some(format!("{SERVICE_NAME}.supervisor")),
            GitServerSupervisor,
            configured,
        )
        .await
        .map_err(|e| format!("the git server supervisor did not start: {e}"))?;
        handle
            .await
            .map_err(|e| format!("the git server supervisor task failed: {e}"))?;
        Err("the git server supervisor stopped".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    polar_agent_builder::polar_agent_tests!(GitServer);

    // docs/architecture/git-server.md, "Inside the boundary": it answers reads on one topic, each reader on its own named
    // topic.
    #[test]
    fn it_answers_reads_and_each_reader_on_its_own_topic() {
        use polar_agent_builder::Access;
        use polar_git_server_common::{READ_REQUESTS_TOPIC, SCHEDULER_OBSERVER_READ_REPLIES_TOPIC};
        let scaffold = polar_agent_builder::agent::scaffold_document::<GitServer>();
        let has = |name: &str, access: Access| {
            scaffold
                .topics
                .iter()
                .any(|t| t.name == name && t.access == access)
        };
        assert!(has(READ_REQUESTS_TOPIC, Access::Subscribe));
        assert!(has(SCHEDULER_OBSERVER_READ_REPLIES_TOPIC, Access::Publish));
    }

    // docs/architecture/git-server.md, "Inside the boundary": it takes evidence records on one topic, answers each sender
    // on its own named topic, and announces what it adds as it announces a push.
    #[test]
    fn it_takes_evidence_records_and_answers_each_sender_on_its_own_topic() {
        use polar_agent_builder::Access;
        use polar_git_server_common::{
            ATTESTATION_AGENT_EVIDENCE_REPLIES_TOPIC, EVIDENCE_REQUESTS_TOPIC,
            POLAR_GIT_REPO_CHANGED_TOPIC,
        };
        let scaffold = polar_agent_builder::agent::scaffold_document::<GitServer>();
        let has = |name: &str, access: Access| {
            scaffold
                .topics
                .iter()
                .any(|t| t.name == name && t.access == access)
        };
        assert!(has(EVIDENCE_REQUESTS_TOPIC, Access::Subscribe));
        assert!(has(
            ATTESTATION_AGENT_EVIDENCE_REPLIES_TOPIC,
            Access::Publish
        ));
        assert!(has(POLAR_GIT_REPO_CHANGED_TOPIC, Access::Publish));
        assert!(scaffold.topic_families.is_empty());
    }
}
