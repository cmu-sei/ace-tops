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

//! The build processor's supervisor: it receives the provenance stream through the builder's subscription, projects
//! each event (`project`) and hands the writes to its graph controller, and tells health what the graph and the broker
//! say. An event it cannot read, or cannot project, is dropped with a warning and the next is read: the broker keeps
//! no log, so what is dropped is gone, and nothing here claims otherwise.

use crate::{AGENT_NAME, project};
use chrono::Utc;
use polar::ProvenanceEvent;
use polar::graph::controller::{
    GraphControllerActor, GraphControllerArgs, GraphControllerMsg, GraphSignal,
};
use polar_agent_builder::{
    AgentBuilder, Configured, Drain, HealthClient, HealthHandle, InfrastructureEvent,
    InfrastructureSupervisorMessage, Subscription, stop_graph_controller,
};
use ractor::concurrency::Duration;
use ractor::{Actor, ActorProcessingErr, ActorRef, OutputPort, SupervisionEvent, async_trait};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

const DRAIN_WINDOW_SECS: u64 = 5;
const GRAPH_STOP_SECS: u64 = 30;
/// The drain window, then the graph controller's queue run to its end, with room to spare.
pub const SHUTDOWN_BUDGET: std::time::Duration =
    std::time::Duration::from_secs(DRAIN_WINDOW_SECS + GRAPH_STOP_SECS + 10);

pub enum ProcessorMessage {
    ClientEvent { event: cassini_types::ClientEvent },
    Received(ProvenanceEvent),
    GraphSignal(GraphSignal),
    PrepareShutdown,
    DrainElapsed,
}

pub struct ProcessorSupervisor;

pub struct ProcessorState {
    healthcheck: HealthHandle,
    infrastructure: ActorRef<InfrastructureSupervisorMessage>,
    graph_controller: Option<ActorRef<GraphControllerMsg>>,
    drain: Drain,
}

impl ProcessorSupervisor {
    /// An event as it came: archived by a Rust agent, or JSON from a pipeline's nushell stages. `None` if it is
    /// neither, and why is logged.
    pub fn decode(payload: &[u8]) -> Option<ProvenanceEvent> {
        let archived = match rkyv::from_bytes::<ProvenanceEvent, rkyv::rancor::Error>(payload) {
            Ok(event) => return Some(event),
            Err(e) => e,
        };
        match serde_json::from_slice::<ProvenanceEvent>(payload) {
            Ok(event) => Some(event),
            Err(json) => {
                warn!(rkyv_error = %archived, json_error = %json, "not a provenance event -- dropped");
                None
            }
        }
    }

    /// Projects one event and hands its writes to the graph controller as one transaction, all or none. An event that
    /// cannot be projected (a manifest that is not OCI JSON) writes nothing and is dropped with a warning.
    fn write(state: &ProcessorState, event: ProvenanceEvent) -> Result<(), ActorProcessingErr> {
        let Some(controller) = &state.graph_controller else {
            warn!("the graph controller has ended -- event not written");
            return Ok(());
        };
        let op = match project::transaction(event, &Utc::now().to_rfc3339()) {
            Ok(Some(op)) => op,
            Ok(None) => return Ok(()),
            Err(e) => {
                warn!(error = %e, "event could not be projected -- dropped");
                return Ok(());
            }
        };
        controller
            .cast(GraphControllerMsg::Op(op))
            .map_err(|e| format!("could not hand a write to the graph controller: {e}"))?;
        Ok(())
    }
}

#[async_trait]
impl Actor for ProcessorSupervisor {
    type Msg = ProcessorMessage;
    type State = ProcessorState;
    type Arguments = Configured;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        configured: Configured,
    ) -> Result<Self::State, ActorProcessingErr> {
        debug!("{myself:?} starting");
        let key_indexes = configured.graph_key_indexes();
        let to = myself.clone();
        let stream = Subscription::new(polar::topics::PROVENANCE_EVENTS, move |incoming| {
            if let Some(event) = Self::decode(&incoming.payload)
                && let Err(e) = to.cast(ProcessorMessage::Received(event))
            {
                error!("failed to hand an event to the supervisor: {e}");
            }
        });
        let resources = AgentBuilder::new(myself.clone(), AGENT_NAME)
            .with_subscription(stream)
            .with_lifecycle_handler(|event| Some(ProcessorMessage::ClientEvent { event }))
            .into_configured(configured)
            .build()
            .await?;
        resources
            .infrastructure_events
            .subscribe(myself.clone(), |event| match event {
                InfrastructureEvent::PrepareShutdown => Some(ProcessorMessage::PrepareShutdown),
            });
        let signals = Arc::new(OutputPort::<GraphSignal>::default());
        signals.subscribe(myself.clone(), |signal| {
            Some(ProcessorMessage::GraphSignal(signal))
        });
        let (graph_controller, _) = GraphControllerActor::spawn_linked(
            Some(format!("{AGENT_NAME}.graph_controller")),
            GraphControllerActor,
            GraphControllerArgs::new(signals)
                .with_settings(
                    polar::graph::environment::GraphSettings::from_env(&*resources.config)
                        .map_err(ActorProcessingErr::from)?,
                )
                .with_key_indexes(key_indexes),
            myself.get_cell(),
        )
        .await
        .map_err(ActorProcessingErr::from)?;

        Ok(ProcessorState {
            healthcheck: resources.healthcheck,
            infrastructure: resources.infrastructure,
            graph_controller: Some(graph_controller),
            drain: Drain::default(),
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            ProcessorMessage::GraphSignal(signal) => match signal {
                GraphSignal::Available => {
                    let _ = state.healthcheck.graph_available();
                }
                GraphSignal::OpFailed(reason) => {
                    let _ = state.healthcheck.graph_op_failed(reason);
                }
            },
            ProcessorMessage::ClientEvent { event } => match event {
                cassini_types::ClientEvent::Registered { .. } => {
                    let _ = state.healthcheck.cassini_connected();
                    let _ = state.healthcheck.graph_connected();
                }
                cassini_types::ClientEvent::TransportError { reason } => {
                    warn!("Transport error (non-fatal, awaiting reconnect): {reason}");
                    let _ = state.healthcheck.cassini_disconnected();
                }
                _ => {}
            },
            ProcessorMessage::Received(event) => {
                if state.drain.is_draining() {
                    warn!("draining -- event not written");
                    return Ok(());
                }
                Self::write(state, event)?;
            }
            ProcessorMessage::PrepareShutdown => {
                if state.drain.begin(
                    &myself,
                    Duration::from_secs(DRAIN_WINDOW_SECS),
                    true,
                    || ProcessorMessage::DrainElapsed,
                ) {
                    info!("PrepareShutdown received; entering the drain window");
                }
            }
            ProcessorMessage::DrainElapsed => {
                if let Some(controller) = state.graph_controller.take() {
                    stop_graph_controller(controller, Duration::from_secs(GRAPH_STOP_SECS)).await;
                }
                state.drain.complete(&state.infrastructure);
            }
        }
        Ok(())
    }

    async fn handle_supervisor_evt(
        &self,
        myself: ActorRef<Self::Msg>,
        event: SupervisionEvent,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match event {
            SupervisionEvent::ActorStarted(actor) => debug!("{actor:?} started"),
            SupervisionEvent::ActorTerminated(actor, _, reason) => {
                info!("{actor:?} terminated: {reason:?}");
                if actor.get_id() == state.infrastructure.get_id() {
                    std::process::exit(1);
                }
                if state
                    .graph_controller
                    .as_ref()
                    .is_some_and(|c| c.get_id() == actor.get_id())
                    && state.drain.begin(
                        &myself,
                        Duration::from_secs(DRAIN_WINDOW_SECS),
                        false,
                        || ProcessorMessage::DrainElapsed,
                    )
                {
                    state.graph_controller = None;
                    warn!("the graph controller ended; draining before exit");
                }
            }
            SupervisionEvent::ActorFailed(actor, reason) => {
                error!("{actor:?} failed: {reason:?}");
                if state
                    .graph_controller
                    .as_ref()
                    .is_some_and(|c| c.get_id() == actor.get_id())
                {
                    state.graph_controller = None;
                }
                if !state.drain.begin(
                    &myself,
                    Duration::from_secs(DRAIN_WINDOW_SECS),
                    false,
                    || ProcessorMessage::DrainElapsed,
                ) {
                    warn!("already draining");
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ProcessorSupervisor;
    use polar::ProvenanceEvent;

    #[test]
    fn an_event_a_rust_agent_archived_is_read() {
        let event = ProvenanceEvent::ExecutionCompleted {
            build_id: "b1".into(),
            duration_secs: 3,
        };
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&event).unwrap();
        match ProcessorSupervisor::decode(&bytes) {
            Some(ProvenanceEvent::ExecutionCompleted {
                build_id,
                duration_secs,
            }) => {
                assert_eq!((build_id.as_str(), duration_secs), ("b1", 3))
            }
            other => panic!("expected the build's completion, got {other:?}"),
        }
    }

    #[test]
    fn an_event_a_pipeline_wrote_as_json_is_read() {
        let event = ProvenanceEvent::ExecutionCompleted {
            build_id: "b1".into(),
            duration_secs: 3,
        };
        let json = serde_json::to_vec(&event).unwrap();
        assert!(matches!(
            ProcessorSupervisor::decode(&json),
            Some(ProvenanceEvent::ExecutionCompleted { .. })
        ));
    }

    #[test]
    fn what_is_not_an_event_is_dropped_not_fatal() {
        assert!(ProcessorSupervisor::decode(b"not an event").is_none());
        assert!(ProcessorSupervisor::decode(&[]).is_none());
    }
}
