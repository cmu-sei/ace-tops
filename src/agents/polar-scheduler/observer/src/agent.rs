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

use crate::supervisor::{SERVICE_NAME, SHUTDOWN_BUDGET, SchedulerObserverSupervisor};
use polar_agent_builder::{
    Capability, Cause, Configured, PolarAgent, Role, StartError, TopicDecl, topics::FamilyDecl,
};
use polar_env::Section;
use ractor::Actor;
use std::time::Duration;

pub struct SchedulerObserver;

/// The observer's own configuration topic, `polar_scheduler_common::configuration_topic(SERVICE_NAME)`, spelled out
/// because a topic declaration is a const; a test holds the two equal. Its signed settings arriving there (its keys,
/// changed) start a read of the schedules log.
pub const OWN_CONFIGURATION_TOPIC: &str = "agent.polar-scheduler-observer.configuration";

impl PolarAgent for SchedulerObserver {
    const NAME: &'static str = SERVICE_NAME;
    const ROLE: Role = Role::Observer;
    const PURPOSE: &'static str = "Keeps a checkout of the schedules repository current, read from Polar's git server over Cassini, and publishes each schedule change on Cassini";
    const NEEDS: &'static [Capability] = &[];
    const SHUTDOWN_BUDGET: Duration = SHUTDOWN_BUDGET;
    const TOPICS: &'static [TopicDecl] = &[
        TopicDecl::subscribe(
            polar_git_server_common::POLAR_GIT_REPO_CHANGED_TOPIC,
            "a push to the schedules repository, which starts a read",
        ),
        TopicDecl::publish(
            polar_git_server_common::READ_REQUESTS_TOPIC,
            "a read of the deployment record from Polar's git server",
        )
        .because(&[Cause::Timer("reading the deployment repository")]),
        TopicDecl::subscribe(
            polar_git_server_common::SCHEDULER_OBSERVER_READ_REPLIES_TOPIC,
            "the git server's answer to a read, on this observer's own topic",
        )
        .answers(&[Cause::Timer("reading the deployment repository")]),
        TopicDecl::subscribe(
            polar_git_server_common::LOG_WITNESSED_TOPIC,
            "that a log's co-signed checkpoint grew, which starts a read of the schedules log",
        ),
        TopicDecl::publish(
            polar_git_server_common::LOG_READ_REQUESTS_TOPIC,
            "a read of the schedules log's leaves past those held, from the store (record-store.md, \"Bite 6\")",
        )
        .because(&[
            Cause::Topic(polar_git_server_common::POLAR_GIT_REPO_CHANGED_TOPIC),
            Cause::Topic(polar_git_server_common::LOG_WITNESSED_TOPIC),
            Cause::Topic(OWN_CONFIGURATION_TOPIC),
            Cause::Registered,
            Cause::Timer("read"),
        ]),
        TopicDecl::subscribe(
            polar_git_server_common::SCHEDULER_OBSERVER_LOG_READ_REPLIES_TOPIC,
            "the store's answer to a read of the schedules log, on this observer's own topic",
        )
        // A read an announcement or the observer's own settings started answers that one's own entry.
        .answers(&[Cause::Registered, Cause::Timer("read")]),
        TopicDecl::subscribe(
            polar_scheduler_common::CONFIGURATION_REPLAY_TOPIC,
            "an agent asking for the documents held for it",
        ),
        TopicDecl::publish(
            polar_scheduler_common::SCHEDULER_IN_TOPIC,
            "each schedule created, changed or deleted in the checkout",
        )
        .because(&[
            Cause::Topic(polar_git_server_common::POLAR_GIT_REPO_CHANGED_TOPIC),
            Cause::Topic(polar_git_server_common::LOG_WITNESSED_TOPIC),
            Cause::Topic(OWN_CONFIGURATION_TOPIC),
            Cause::Registered,
            Cause::Timer("read"),
        ]),
        TopicDecl::publish(
            polar_scheduler_common::DEPLOYMENT_RECORD_TOPIC,
            "the deployment's signed record, as the deployment repository holds it",
        )
        .because(&[Cause::Timer("reading the deployment repository")]),
    ];
    const TOPIC_FAMILIES: &'static [FamilyDecl] = &[FamilyDecl::publish(
        "agent.{workload}.configuration",
        "the documents held for the workload, replayed when it asks",
    )
    .because(&[Cause::Topic(
        polar_scheduler_common::CONFIGURATION_REPLAY_TOPIC,
    )])];
    const SECTIONS: &'static [&'static Section] = &[&crate::settings::SECTION];
    const HELP: Option<&'static str> = Some(
        "The observer reads the schedules repository from the store's log of it over Cassini into its \
         checkout, held to the store's checkpoint and the witness's co-signature under the keys its own \
         signed settings pin, watches the checkout, evaluates each changed Dhall schedule and \
         publishes the change to the scheduler. It reads when it joins Cassini, when the git server \
         announces a change to that repository or a further co-signature of the log, when its keys \
         change, and on an interval if one is set; the server answers on this observer's own topic, \
         judging by the identity the broker stamped whether it may read. It runs no git and holds no \
         key file.",
    );

    async fn start(configured: Configured) -> Result<(), StartError> {
        configured.init_logging(SERVICE_NAME);
        let (_supervisor, handle) = Actor::spawn(
            Some(format!("{SERVICE_NAME}.supervisor")),
            SchedulerObserverSupervisor,
            configured,
        )
        .await
        .map_err(|e| format!("the scheduler observer supervisor did not start: {e}"))?;
        handle
            .await
            .map_err(|e| format!("the scheduler observer supervisor task failed: {e}"))?;
        Err("the scheduler observer supervisor stopped".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    polar_agent_builder::polar_agent_tests!(SchedulerObserver);

    #[test]
    fn its_family_is_the_topic_the_code_publishes_each_workloads_configuration_on() {
        for workload in ["kube-observer", "credentials-agent", "polar-scheduler"] {
            for family in SchedulerObserver::TOPIC_FAMILIES {
                assert_eq!(
                    family.topic_for(workload),
                    polar_scheduler_common::configuration_topic(workload)
                );
            }
        }
        assert_eq!(SchedulerObserver::TOPIC_FAMILIES.len(), 1);
    }

    #[test]
    fn its_own_configuration_topic_is_the_one_the_scheduler_names_for_it() {
        assert_eq!(
            OWN_CONFIGURATION_TOPIC,
            polar_scheduler_common::configuration_topic(SERVICE_NAME)
        );
    }

    // runtime-attestation.md, slice C, C2, O2: it reads Polar's git server over Cassini, and is answered on its own topic,
    // the one the server publishes it on.
    #[test]
    fn it_asks_the_git_server_for_reads_and_is_answered_on_its_own_topic() {
        use polar_agent_builder::Access;
        let scaffold = polar_agent_builder::agent::scaffold_document::<SchedulerObserver>();
        let has = |name: &str, access: Access| {
            scaffold
                .topics
                .iter()
                .any(|t| t.name == name && t.access == access)
        };
        assert!(has(
            polar_git_server_common::READ_REQUESTS_TOPIC,
            Access::Publish
        ));
        assert!(has(
            polar_git_server_common::SCHEDULER_OBSERVER_READ_REPLIES_TOPIC,
            Access::Subscribe
        ));
        assert_eq!(
            polar_git_server_common::read_replies_topic(SERVICE_NAME),
            polar_git_server_common::SCHEDULER_OBSERVER_READ_REPLIES_TOPIC,
            "the server answers it on the topic named for this workload"
        );
    }
}
