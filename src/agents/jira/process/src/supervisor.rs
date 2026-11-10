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

use crate::BROKER_CLIENT_NAME;
use crate::{groups, issues, projects, users};
use cassini_types::ClientEvent;
use jira_common::types::JiraData;
use jira_common::{
    JIRA_GROUPS_CONSUMER_TOPIC, JIRA_ISSUES_CONSUMER_TOPIC, JIRA_PROJECTS_CONSUMER_TOPIC,
    JIRA_USERS_CONSUMER_TOPIC,
};
use polar::cassini::{CassiniClient, TcpClient};
use polar::graph::controller::GraphController;
use polar_agent_builder::{
    AgentBuilder, Configured, GraphHandle, HealthClient, HealthHandle,
    InfrastructureSupervisorMessage, Subscription,
};
use ractor::Actor;
use ractor::ActorProcessingErr;
use ractor::ActorRef;
use ractor::SupervisionEvent;
use ractor::async_trait;
use ractor::concurrency::Duration;
use tracing::{debug, error, info, warn};

/// Every topic this agent consumes. One Subscription each; all of them
/// deliver to the supervisor, which decodes and writes to the graph.
pub(crate) const JIRA_TOPICS: [&str; 4] = [
    JIRA_PROJECTS_CONSUMER_TOPIC,
    JIRA_GROUPS_CONSUMER_TOPIC,
    JIRA_USERS_CONSUMER_TOPIC,
    JIRA_ISSUES_CONSUMER_TOPIC,
];

/// What this agent needs to drain beyond the graph controller, whose drain the
/// builder counts: letting go of its topics, and a margin. If it is not done by
/// then the process exits 1 regardless.
pub const SHUTDOWN_BUDGET: Duration = Duration::from_secs(10);

/// This supervisor's own message type. polar::SupervisorMessage cannot
/// carry the two infrastructure signals without polar-agent-builder
/// depending back on lib, so the builder is generic over the message and
/// each supervisor defines what it needs (see kube-observer).
pub enum ConsumerSupervisorMessage {
    ClientEvent {
        event: ClientEvent,
    },
    /// The agent is ending. Finish this supervisor's own work, then send
    /// InfrastructureSupervisorMessage::ProceedWithShutdown.
    PrepareShutdown,
}

pub struct ConsumerSupervisor;

pub struct ConsumerSupervisorState {
    broker_client: TcpClient,
    /// The builder's: it reports the graph's health and drains it at the end.
    graph: GraphHandle,
    healthcheck: HealthHandle,
    /// Sent ProceedWithShutdown once this agent has let go of its topics.
    infrastructure: ActorRef<InfrastructureSupervisorMessage>,
    /// True once PrepareShutdown has been received. Messages that still
    /// arrive are logged, not written.
    shutting_down: bool,
}

/// Decodes what an observer published: the payload of the event is the
/// serialized JiraData. Anything that does not decode is logged and
/// dropped, never fatal.
pub fn decode_payload(payload: &[u8]) -> Option<JiraData> {
    match rkyv::from_bytes::<JiraData, rkyv::rancor::Error>(payload) {
        Ok(data) => Some(data),
        Err(e) => {
            warn!("Failed to deserialize jira data: {e:?}");
            None
        }
    }
}

impl ConsumerSupervisor {
    fn dispatch(
        topic: &str,
        payload: &[u8],
        graph_controller: &GraphController,
    ) -> Result<(), ActorProcessingErr> {
        let Some(data) = decode_payload(payload) else {
            warn!("Dropping undecodable message on topic '{topic}'");
            return Ok(());
        };
        match data {
            JiraData::Projects(items) => projects::handle_projects(&items, graph_controller),
            JiraData::Groups(items) => groups::handle_groups(&items, graph_controller),
            JiraData::Users(items) => users::handle_users(&items, graph_controller),
            JiraData::Issues(issue) => issues::handle_issue(&issue.json, graph_controller),
            #[allow(unreachable_patterns)]
            _ => {
                warn!("Ignoring unexpected jira data on topic '{topic}'");
                Ok(())
            }
        }
    }

    /// One Subscription per topic. Each deliver closure rebuilds the
    /// ClientEvent::MessagePublished the supervisor's handle() expects and
    /// forwards it. AgentBuilder fires the wire-level Subscribe for every
    /// one of them when the client registers, and again after a reconnect.
    fn jira_subscriptions(supervisor: &ActorRef<ConsumerSupervisorMessage>) -> Vec<Subscription> {
        JIRA_TOPICS
            .iter()
            .map(|topic| {
                let supervisor = supervisor.clone();
                Subscription::new(*topic, move |incoming| {
                    let event = ClientEvent::MessagePublished {
                        topic: incoming.topic,
                        payload: incoming.payload,
                        trace_ctx: incoming.trace_ctx,
                        published_by: incoming.published_by,
                        published_instance: incoming.published_instance,
                    };
                    if let Err(e) =
                        supervisor.send_message(ConsumerSupervisorMessage::ClientEvent { event })
                    {
                        warn!("AgentBuilder: failed to deliver routed message to supervisor: {e}");
                    }
                })
            })
            .collect()
    }
}

#[async_trait]
impl Actor for ConsumerSupervisor {
    type Msg = ConsumerSupervisorMessage;
    type State = ConsumerSupervisorState;
    /// The configuration `run` judged; the builder is made from it.
    type Arguments = Configured;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        configured: Configured,
    ) -> Result<Self::State, ActorProcessingErr> {
        debug!("{myself:?} starting");

        // HealthCheckActor, RouterActor, the four topic subscriptions and
        // the TcpClient in one composed call. The builder checks that the
        // deployment provides graph-write (POLAR_CAPABILITIES) before
        // spawning anything, and reads the dependency endpoints from
        // POLAR_HEALTH_DEP_ENDPOINTS. This agent never encrypts a payload,
        // so it does not declare encryption.
        let mut builder = AgentBuilder::new(myself.clone(), BROKER_CLIENT_NAME);
        for subscription in Self::jira_subscriptions(&myself) {
            builder = builder.with_subscription(subscription);
        }
        let resources = builder
            .with_lifecycle_handler(|event| Some(ConsumerSupervisorMessage::ClientEvent { event }))
            .with_drain(|| ConsumerSupervisorMessage::PrepareShutdown)
            .into_configured(configured)
            .build()
            .await?;

        // The infrastructure half of the respawn and shutdown protocol.

        Ok(ConsumerSupervisorState {
            broker_client: resources.tcp_client,
            graph: resources
                .graph
                .ok_or("the builder started no graph controller for a graph-write agent")?,
            healthcheck: resources.healthcheck,
            infrastructure: resources.infrastructure,
            shutting_down: false,
        })
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            ConsumerSupervisorMessage::PrepareShutdown => {
                info!(
                    "CONSUMER_SUPERVISOR: PrepareShutdown received -- unsubscribing, then \
                     proceeding; the infrastructure drains the graph controller"
                );
                state.shutting_down = true;

                for topic in JIRA_TOPICS {
                    if let Err(e) =
                        state
                            .broker_client
                            .unsubscribe(polar::cassini::UnsubscribeRequest {
                                topic: topic.to_string(),
                                trace_ctx: None,
                            })
                    {
                        warn!(
                            "CONSUMER_SUPERVISOR: unsubscribe from '{topic}' failed (continuing): {e}"
                        );
                    }
                }

                let _ = state
                    .infrastructure
                    .cast(InfrastructureSupervisorMessage::ProceedWithShutdown);
            }
            ConsumerSupervisorMessage::ClientEvent { event } => match event {
                ClientEvent::Registered { .. } => {
                    // AgentBuilder already fired the wire-level Subscribe
                    // for every topic when this event fired.
                    let _ = state.healthcheck.cassini_connected();
                }
                ClientEvent::MessagePublished { topic, payload, .. } => {
                    if state.shutting_down {
                        warn!(
                            "CONSUMER_SUPERVISOR: shutting down -- logging message on topic \
                             '{topic}' ({} bytes) instead of writing; will be lost on exit",
                            payload.len()
                        );
                        // TODO: publish to dead-letter queue once Cassini supports one.
                    } else {
                        Self::dispatch(&topic, &payload, state.graph.actor())?;
                    }
                }
                ClientEvent::TransportError { reason } => {
                    warn!("Transport error occurred (non-fatal, awaiting reconnect): {reason}");
                    let _ = state.healthcheck.cassini_disconnected();
                }
                _ => (),
            },
        }
        Ok(())
    }

    async fn handle_supervisor_evt(
        &self,
        _myself: ActorRef<Self::Msg>,
        msg: SupervisionEvent,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match msg {
            SupervisionEvent::ActorStarted(actor_cell) => {
                info!(
                    "CONSUMER_SUPERVISOR: {0:?}:{1:?} started",
                    actor_cell.get_name(),
                    actor_cell.get_id()
                );
            }
            SupervisionEvent::ActorTerminated(actor_cell, _, reason) => {
                info!(
                    "CONSUMER_SUPERVISOR: {0:?}:{1:?} terminated. {reason:?}",
                    actor_cell.get_name(),
                    actor_cell.get_id()
                );
                // Any other linked actor stopping outside a shutdown is
                // unexpected.
                if !state.shutting_down {
                    error!("CONSUMER_SUPERVISOR: a linked actor terminated unexpectedly; exiting");
                    std::process::exit(1);
                }
            }
            SupervisionEvent::ActorFailed(actor_cell, e) => {
                error!(
                    "CONSUMER_SUPERVISOR: {0:?}:{1:?} failed! {e:?}",
                    actor_cell.get_name(),
                    actor_cell.get_id()
                );
                // Any linked actor failing is fatal: exit so the Job
                // controller creates a new pod.
                std::process::exit(1);
            }
            SupervisionEvent::ProcessGroupChanged(..) => {}
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jira_common::types::JiraProject;

    /// What an observer puts on the wire for this agent: the serialized
    /// JiraData, nothing else.
    fn as_published(data: &JiraData) -> Vec<u8> {
        rkyv::to_bytes::<rkyv::rancor::Error>(data)
            .unwrap()
            .into_vec()
    }

    #[test]
    fn decodes_what_an_observer_publishes() {
        let data = JiraData::Projects(vec![JiraProject {
            id: "10042".to_string(),
            key: "PLAT".to_string(),
            name: "Platform".to_string(),
            project_type_key: "software".to_string(),
        }]);

        let decoded = decode_payload(&as_published(&data));

        assert!(matches!(
            decoded,
            Some(JiraData::Projects(ref p)) if p.len() == 1 && p[0].id == "10042"
        ));
    }

    #[test]
    fn a_payload_that_does_not_decode_is_dropped_not_fatal() {
        assert!(decode_payload(&[0u8; 3]).is_none());
    }

    #[test]
    fn every_consumed_topic_is_subscribed_exactly_once() {
        let mut topics = JIRA_TOPICS.to_vec();
        topics.sort();
        topics.dedup();
        assert_eq!(topics.len(), 4);
    }
}
