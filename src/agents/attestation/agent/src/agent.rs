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

//! What the attestation agent is, as the infrastructure asks to be told: see `polar_agent_builder::PolarAgent`.

use crate::supervisor::{AttestationSupervisor, SHUTDOWN_BUDGET};
use attestation_common::{
    AGENT_NAME, CERT_ISSUER_REPLIES_TOPIC, CREDENTIALS_AGENT_REPLIES_TOPIC, REPORTS_TOPIC,
    REQUESTS_TOPIC,
};
use polar_agent_builder::protocol::OperationDecl;
use polar_agent_builder::{Capability, Cause, Configured, PolarAgent, StartError, TopicDecl};
use polar_env::Section;
use ractor::Actor;
use std::time::Duration;

pub struct AttestationAgent;

impl PolarAgent for AttestationAgent {
    const NAME: &'static str = AGENT_NAME;
    const PURPOSE: &'static str =
        "Answers whether an instance is what the deployment made, from what it sees of the cluster";
    const NEEDS: &'static [Capability] = &[Capability::PodRead];
    const OPERATIONS: &'static [OperationDecl] = &[crate::watch::WATCH];
    const SHUTDOWN_BUDGET: Duration = SHUTDOWN_BUDGET;
    const TOPICS: &'static [TopicDecl] = &[
        TopicDecl::subscribe(
            REQUESTS_TOPIC,
            "a question about an instance, from who vouches for certificates",
        ),
        TopicDecl::subscribe(
            polar_scheduler_common::DEPLOYMENT_RECORD_TOPIC,
            "the deployment's signed record, which it verifies itself",
        ),
        TopicDecl::publish(
            CERT_ISSUER_REPLIES_TOPIC,
            "the verdict, on cert-issuer's own topic",
        )
        .because(&[Cause::Topic(REQUESTS_TOPIC)]),
        TopicDecl::publish(
            CREDENTIALS_AGENT_REPLIES_TOPIC,
            "the verdict, on the credentials agent's own topic",
        )
        .because(&[Cause::Topic(REQUESTS_TOPIC)]),
        TopicDecl::publish(
            REPORTS_TOPIC,
            "what it finds of its own accord: a pod that is not what its owner made, a container that died by a signal",
        )
        .because(&[
            Cause::Outside("the pods it watches"),
            Cause::Timer("each minute, what still stands"),
        ]),
    ];
    const SECTIONS: &'static [&'static Section] = &[&crate::settings::SECTION];
    const HELP: Option<&'static str> = Some(
        "attestation-agent watches the pods of Polar's namespaces and what owns them, with get, list and watch and nothing else, and \
         answers the questions published on attestation-instance-requests: is the pod this token was bound to what the deployment \
         made? It judges a pod against its owner (its owner chain, by UID, and each container's image against the digest its owner \
         pins), then against the signed record of the workload the identity runs as. It sees and reports; it never acts, and what \
         follows from a verdict is the asker's. Of its own accord it reports on attestation-reports a pod that is not what its owner made \
         and a container that died by a signal. Its verdicts stand only while it has proved itself: it holds what it needs, it passes its \
         own judgement, it does not condemn most of what is running, and it says no to real pods altered. Otherwise it answers that it \
         cannot say, and says why in an ERROR. Each verdict goes to the asker's own topic, attestation-instance-replies.<workload>. \
         docs/architecture/runtime-attestation.md.",
    );

    async fn start(configured: Configured) -> Result<(), StartError> {
        configured.init_logging(AGENT_NAME);
        let (_supervisor, handle) = Actor::spawn(
            Some(format!("{AGENT_NAME}.supervisor")),
            AttestationSupervisor,
            configured,
        )
        .await
        .map_err(|e| format!("the attestation agent's supervisor did not start: {e}"))?;
        handle
            .await
            .map_err(|e| format!("the attestation agent's supervisor task failed: {e}"))?;
        Err("the attestation agent's supervisor stopped".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    polar_agent_builder::polar_agent_tests!(AttestationAgent);

    #[test]
    fn it_asks_for_the_narrow_read_and_writes_no_graph() {
        let scaffold = polar_agent_builder::agent::scaffold_document::<AttestationAgent>();
        assert_eq!(scaffold.requires, ["cassini", "pod-read"]);
        assert!(scaffold.graph.is_empty());
        assert_eq!(scaffold.operations.len(), 1);
        assert_eq!(scaffold.operations[0].protocol, "kubernetes");
        assert_eq!(scaffold.operations[0].location, "cluster");
    }

    // docs/architecture/runtime-attestation.md: those who vouch are the only askers, so its certificate names their topics and no others.
    #[test]
    fn it_answers_on_the_topics_of_those_who_ask_and_no_others() {
        let scaffold = polar_agent_builder::agent::scaffold_document::<AttestationAgent>();
        assert!(scaffold.topic_families.is_empty());
        for asker in ["cert-issuer", "credentials-agent"] {
            let topic = attestation_common::replies_topic(asker);
            assert!(
                scaffold
                    .topics
                    .iter()
                    .any(|t| t.name == topic && t.access == polar_agent_builder::Access::Publish),
                "{asker} is answered"
            );
        }
    }
}
