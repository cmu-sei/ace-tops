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

//! Supervisor for the scheduler processor, on the agent builder: health check, router, the Cassini
//! client and the subscriptions come from `AgentBuilder`.
//!
//! The processor receives schedule changes (from the observer) and ad-hoc agent announcements,
//! records them in the graph and notifies the agents they concern. Its one child is the processor,
//! linked, so its failure asks the infrastructure for an orderly shutdown. The graph controller is
//! the builder's.
//!
//! Shutdown, in order:
//!
//! 1. `InfrastructureEvent::PrepareShutdown` reaches this supervisor, which drains the processor of
//!    what it was handed.
//! 2. `ProceedWithShutdown` goes to the infrastructure supervisor, which drains the graph
//!    controller and stops its children.
//! 3. When the infrastructure has ended the builder stops this supervisor and `run` exits non-zero,
//!    so the workload is restarted with fresh certificates.

use crate::processor::ScheduleInfoProcessor;
use crate::types::ProcessorMsg;
use cassini_types::ClientEvent;
use polar_agent_builder::{
    AgentBuilder, Configured, HealthClient, HealthHandle, InfrastructureEvent,
    InfrastructureSupervisorMessage, Subscription,
};
use polar_scheduler_common::{
    CONFIGURATION_OUTCOME_TOPIC, ConfigurationOutcome, GitScheduleChange, SCHEDULER_IN_TOPIC,
};
use ractor::concurrency::Duration;
use ractor::{Actor, ActorProcessingErr, ActorRef, SupervisionEvent, async_trait};
use tracing::{debug, error, info, warn};

pub const SERVICE_NAME: &str = "polar-scheduler";

/// How long the processor has to handle what it was handed before the supervisor proceeds.
const PROCESSOR_DRAIN: Duration = Duration::from_secs(10);

/// What this agent needs to drain beyond the graph controller, whose drain the builder counts: the
/// processor's drain and a margin. Past it the process exits 1 regardless.
pub const SHUTDOWN_BUDGET: Duration = Duration::from_secs(15);

pub enum SchedulerSupervisorMessage {
    ClientEvent {
        event: ClientEvent,
    },
    /// A schedule changed in the repository.
    ScheduleChanged(GitScheduleChange),
    /// An agent says what it did with a signed configuration document.
    Outcome {
        outcome: ConfigurationOutcome,
        reported_by: Option<String>,
    },
    /// The agent is ending; the infrastructure waits for `ProceedWithShutdown`.
    PrepareShutdown,
}

/// The processor's two subscriptions. Each payload is decoded where it arrives, so the supervisor
/// only sees values; one that does not decode is logged and dropped.
pub fn subscriptions(supervisor: &ActorRef<SchedulerSupervisorMessage>) -> Vec<Subscription> {
    let for_changes = supervisor.clone();
    let for_outcomes = supervisor.clone();
    vec![
        Subscription::new(SCHEDULER_IN_TOPIC, move |incoming| {
            match rkyv::from_bytes::<GitScheduleChange, rkyv::rancor::Error>(&incoming.payload) {
                Ok(change) => {
                    if let Err(e) =
                        for_changes.cast(SchedulerSupervisorMessage::ScheduleChanged(change))
                    {
                        error!("failed to hand a schedule change to the supervisor: {e}");
                    }
                }
                Err(e) => error!("failed to deserialize a GitScheduleChange: {e:?}"),
            }
        }),
        Subscription::new(
            CONFIGURATION_OUTCOME_TOPIC,
            move |incoming| match rkyv::from_bytes::<ConfigurationOutcome, rkyv::rancor::Error>(
                &incoming.payload,
            ) {
                Ok(outcome) => {
                    if let Err(e) = for_outcomes.cast(SchedulerSupervisorMessage::Outcome {
                        outcome,
                        reported_by: incoming.published_by,
                    }) {
                        error!("failed to hand a configuration outcome to the supervisor: {e}");
                    }
                }
                Err(e) => error!("failed to deserialize a configuration outcome: {e:?}"),
            },
        ),
    ]
}

pub struct SchedulerSupervisor;

pub struct SchedulerSupervisorState {
    healthcheck: HealthHandle,
    infrastructure: ActorRef<InfrastructureSupervisorMessage>,
    /// Until the agent ends.
    processor: Option<ActorRef<ProcessorMsg>>,
}

#[async_trait]
impl Actor for SchedulerSupervisor {
    type Msg = SchedulerSupervisorMessage;
    type State = SchedulerSupervisorState;
    type Arguments = Configured;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        configured: Configured,
    ) -> Result<Self::State, ActorProcessingErr> {
        debug!("{myself:?} starting");

        let mut builder =
            AgentBuilder::new(myself.clone(), SERVICE_NAME).with_lifecycle_handler(|event| {
                Some(SchedulerSupervisorMessage::ClientEvent { event })
            });
        for subscription in subscriptions(&myself) {
            builder = builder.with_subscription(subscription);
        }
        let resources = builder.into_configured(configured).build().await?;

        resources
            .infrastructure_events
            .subscribe(myself.clone(), |event| match event {
                InfrastructureEvent::PrepareShutdown => {
                    Some(SchedulerSupervisorMessage::PrepareShutdown)
                }
            });

        let graph = resources
            .graph
            .ok_or("the builder started no graph controller for a graph-write agent")?;
        let tcp_client = resources.tcp_client.as_actor_ref().clone();
        let (processor, _) = Actor::spawn_linked(
            Some(format!("{SERVICE_NAME}.processor")),
            ScheduleInfoProcessor,
            (tcp_client, graph.actor().clone()),
            myself.get_cell(),
        )
        .await?;

        Ok(SchedulerSupervisorState {
            healthcheck: resources.healthcheck,
            infrastructure: resources.infrastructure,
            processor: Some(processor),
        })
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            SchedulerSupervisorMessage::ClientEvent { event } => match event {
                // Fires on every registration, a reconnect included, and the builder has already
                // subscribed to the topics, so it only reports health.
                ClientEvent::Registered { .. } => {
                    let _ = state.healthcheck.cassini_connected();
                }
                ClientEvent::TransportError { reason } => {
                    warn!("Transport error (non-fatal, awaiting reconnect): {reason}");
                    let _ = state.healthcheck.cassini_disconnected();
                }
                _ => {}
            },
            SchedulerSupervisorMessage::ScheduleChanged(change) => match &state.processor {
                Some(processor) => processor.cast(ProcessorMsg::GitChange(change))?,
                None => warn!("ending: a schedule change is lost"),
            },
            SchedulerSupervisorMessage::Outcome {
                outcome,
                reported_by,
            } => match &state.processor {
                Some(processor) => processor.cast(ProcessorMsg::Outcome {
                    outcome,
                    reported_by,
                })?,
                None => warn!("ending: a configuration outcome is lost"),
            },
            SchedulerSupervisorMessage::PrepareShutdown => {
                info!("PrepareShutdown received; draining the processor, then proceeding");
                if let Some(processor) = state.processor.take()
                    && let Err(e) = processor.drain_and_wait(Some(PROCESSOR_DRAIN)).await
                {
                    error!("the processor did not drain in time ({e:?}); proceeding");
                }
                if let Err(e) = state
                    .infrastructure
                    .cast(InfrastructureSupervisorMessage::ProceedWithShutdown)
                {
                    error!("could not tell the infrastructure to proceed ({e}); exiting now");
                    std::process::exit(1);
                }
            }
        }
        Ok(())
    }

    async fn handle_supervisor_evt(
        &self,
        _myself: ActorRef<Self::Msg>,
        event: SupervisionEvent,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match event {
            SupervisionEvent::ActorTerminated(actor, _, reason) => {
                warn!("Actor {:?} terminated: {reason:?}", actor.get_name());
            }
            SupervisionEvent::ActorFailed(actor, err) => {
                error!("Actor {:?} failed: {err:?}", actor.get_name());
                // The processor: the agent cannot go on, so it ends in order.
                if let Err(e) =
                    state
                        .infrastructure
                        .cast(InfrastructureSupervisorMessage::BeginShutdown {
                            reason: format!("{:?} failed: {err}", actor.get_name()),
                        })
                {
                    error!("could not ask the infrastructure to end ({e}); exiting now");
                    std::process::exit(1);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_router::IncomingMessage;
    use polar_scheduler_common::GitScheduleChange;
    use std::sync::{Arc, Mutex};
    use std::time::Duration as StdDuration;

    /// Collects what the subscriptions hand to the supervisor.
    struct Sink {
        got: Arc<Mutex<Vec<&'static str>>>,
    }

    #[async_trait]
    impl Actor for Sink {
        type Msg = SchedulerSupervisorMessage;
        type State = Arc<Mutex<Vec<&'static str>>>;
        type Arguments = ();
        async fn pre_start(
            &self,
            _: ActorRef<Self::Msg>,
            _: (),
        ) -> Result<Self::State, ActorProcessingErr> {
            Ok(self.got.clone())
        }
        async fn handle(
            &self,
            _: ActorRef<Self::Msg>,
            message: Self::Msg,
            state: &mut Self::State,
        ) -> Result<(), ActorProcessingErr> {
            let kind = match message {
                SchedulerSupervisorMessage::ScheduleChanged(_) => "change",
                SchedulerSupervisorMessage::Outcome { reported_by, .. } => {
                    if reported_by.as_deref() == Some("the-broker-says") {
                        "outcome from the broker's identity"
                    } else {
                        "outcome"
                    }
                }
                _ => "other",
            };
            state.lock().unwrap().push(kind);
            Ok(())
        }
    }

    fn message(topic: &str, payload: Vec<u8>) -> IncomingMessage {
        IncomingMessage {
            topic: topic.into(),
            payload,
            published_by: None,
            published_instance: None,
            trace_ctx: None,
        }
    }

    #[tokio::test]
    async fn every_topic_it_subscribes_to_is_in_its_declared_set() {
        let got = Arc::new(Mutex::new(Vec::new()));
        let (sink, _) = Actor::spawn(None, Sink { got }, ()).await.unwrap();
        let set = polar_agent_builder::agent::topic_set::<crate::agent::SchedulerProcessor>();
        for subscription in subscriptions(&sink) {
            assert!(
                set.allows(&subscription.topic, polar_agent_builder::Access::Subscribe),
                "{} is not declared",
                subscription.topic
            );
        }
    }

    #[tokio::test]
    async fn each_topic_reaches_the_supervisor_as_its_own_message_and_garbage_is_dropped() {
        let got = Arc::new(Mutex::new(Vec::new()));
        let (sink, _) = Actor::spawn(None, Sink { got: got.clone() }, ())
            .await
            .unwrap();
        let subs = subscriptions(&sink);
        let topics: Vec<&str> = subs.iter().map(|s| s.topic.as_str()).collect();
        assert_eq!(topics, [SCHEDULER_IN_TOPIC, CONFIGURATION_OUTCOME_TOPIC]);

        let change = rkyv::to_bytes::<rkyv::rancor::Error>(&GitScheduleChange::Delete {
            path: "a.dhall".into(),
        })
        .unwrap()
        .to_vec();
        (subs[0].deliver)(message(SCHEDULER_IN_TOPIC, change));
        (subs[0].deliver)(message(SCHEDULER_IN_TOPIC, vec![1, 2, 3]));

        // An outcome keeps the identity the broker gave for whoever published it.
        let outcome = rkyv::to_bytes::<rkyv::rancor::Error>(&ConfigurationOutcome {
            agent: "a".into(),
            id: None,
            version: None,
            status: "applied".into(),
            changed: vec![],
            detail: vec![],
            signer: None,
            at_unix_secs: 1,
            sequence: 1,
        })
        .unwrap()
        .to_vec();
        let mut from_broker = message(CONFIGURATION_OUTCOME_TOPIC, outcome);
        from_broker.published_by = Some("the-broker-says".into());
        (subs[1].deliver)(from_broker);
        (subs[1].deliver)(message(CONFIGURATION_OUTCOME_TOPIC, vec![7, 7]));

        tokio::time::sleep(StdDuration::from_millis(100)).await;
        assert_eq!(
            *got.lock().unwrap(),
            ["change", "outcome from the broker's identity"]
        );
    }
}
