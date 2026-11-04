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

//! The agent around the watches: health, the Cassini client and the shutdown handshake come from `AgentBuilder`. The watches begin once it is
//! registered, in their own actor, since waiting to publish must not hold what hears of the client and of shutting down.

use crate::TCP_CLIENT_NAME;
use crate::watches::{ClusterWatcher, ClusterWatcherArgs, WAITS, WatcherMsg};
use cassini_types::ClientEvent;
use polar::cassini::TcpClient;
use polar_agent_builder::protocol::ProtocolHandle;
use polar_agent_builder::{
    AgentBuilder, Configured, HealthClient, HealthHandle, InfrastructureEvent,
    InfrastructureSupervisorMessage,
};
use ractor::concurrency::Duration;
use ractor::{Actor, ActorProcessingErr, ActorRef, SupervisionEvent, async_trait};
use std::sync::Arc;
use tracing::{info, warn};

/// How long the actor of the watches has to stop. A publish it is waiting on may never finish, so it is ended then regardless.
const WATCHES_STOP: Duration = Duration::from_secs(10);

/// How long the infrastructure supervisor gives this agent to drain: its watches being stopped, plus a margin. If it is not done by then the
/// process exits 1 regardless.
pub const SHUTDOWN_BUDGET: Duration = Duration::from_secs(10 + 10);

/// This supervisor's own, real, local message type -- the shared,
/// core polar::SupervisorMessage can't structurally carry either of
/// the two, new, real signals this migration needs
/// (InfrastructureRespawned, PrepareShutdown) without
/// polar-agent-builder depending back on lib, a genuine circular
/// dependency. AgentBuilder<M> only requires M: ractor::Message
/// (automatically satisfied by any Send + 'static type), so a
/// smaller, local type matching exactly what this supervisor
/// genuinely needs is the correct, clean fix, not a workaround.
pub enum ObserverSupervisorMessage {
    ClientEvent {
        event: ClientEvent,
    },
    /// InfrastructureSupervisor's own InfrastructureEvent::PrepareShutdown,
    /// forwarded here -- HealthCheckActor (now InfrastructureSupervisor's
    /// own, direct child, not this supervisor's) has genuinely,
    /// cleanly terminated for rejuvenation. Stop the watches first,
    /// then send InfrastructureSupervisorMessage::ProceedWithShutdown.
    PrepareShutdown,
}

pub struct ClusterObserverSupervisor;

pub struct ClusterObserverSupervisorState {
    protocols: ProtocolHandle,
    tcp_client: TcpClient,
    healthcheck: HealthHandle,
    /// Sent InfrastructureSupervisorMessage::ProceedWithShutdown once
    /// the watches have stopped -- see PrepareShutdown's own doc comment above.
    infrastructure: ActorRef<InfrastructureSupervisorMessage>,
    watches: Option<ActorRef<WatcherMsg>>,
}

#[async_trait]
impl Actor for ClusterObserverSupervisor {
    type Msg = ObserverSupervisorMessage;
    type State = ClusterObserverSupervisorState;
    /// The configuration `run` judged; the builder is made from it.
    type Arguments = Configured;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        configured: Configured,
    ) -> Result<Self::State, ActorProcessingErr> {
        info!("{myself:?} starting");

        // The real, entire, formerly hand-rolled sequence --
        // HealthCheckActor, RouterActor, TcpClient -- collapsed into
        // one, real, composed call. No with_encryption(): this agent
        // only publishes observations, it never encrypts a payload.
        // It does need the Kubernetes API, which the deployment
        // provisions (ClusterRole, binding, token); the builder checks
        // that against POLAR_CAPABILITIES before anything starts.
        let resources = AgentBuilder::new(myself.clone(), TCP_CLIENT_NAME)
            .with_lifecycle_handler(|event| Some(ObserverSupervisorMessage::ClientEvent { event }))
            .into_configured(configured)
            .build()
            .await?;

        // The real "infra → domain" half of InfrastructureSupervisor's
        // own, real respawn/shutdown protocol -- subscribed directly,
        // the same, established pattern every other real port in this
        // codebase already uses.
        resources
            .infrastructure_events
            .subscribe(myself.clone(), |event| match event {
                InfrastructureEvent::PrepareShutdown => {
                    Some(ObserverSupervisorMessage::PrepareShutdown)
                }
            });

        let protocols = resources.protocols.clone().ok_or(
            "the builder started no protocol handler, though the agent declares an operation",
        )?;
        Ok(ClusterObserverSupervisorState {
            protocols,
            tcp_client: resources.tcp_client,
            healthcheck: resources.healthcheck,
            infrastructure: resources.infrastructure,
            watches: None,
        })
    }

    async fn handle_supervisor_evt(
        &self,
        _myself: ActorRef<Self::Msg>,
        msg: SupervisionEvent,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match msg {
            SupervisionEvent::ActorStarted(_) => (),
            SupervisionEvent::ActorTerminated(actor_cell, _, reason) => {
                let actor_name = actor_cell.get_name().unwrap_or_default();
                info!(
                    "CLUSTER_SUPERVISOR: {0:?}:{1:?} terminated. {reason:?}",
                    actor_name,
                    actor_cell.get_id()
                );

                // InfrastructureSupervisor itself -- this supervisor's
                // one, real, direct, linked child from AgentBuilder's
                // own build() call. Its own termination is the real,
                // genuine signal this supervisor's own graceful
                // shutdown sequence (see PrepareShutdown's own handler
                // in handle(), below) is now fully, completely done --
                // exit so the Job controller creates a new pod with
                // fresh certs. Matched by real, genuine actor id, not
                // name (InfrastructureSupervisor is spawned unnamed).
                if actor_cell.get_id() == state.infrastructure.get_id() {
                    info!(
                        "CLUSTER_SUPERVISOR: infrastructure shutdown complete, exiting for rejuvenation"
                    );
                    std::process::exit(1);
                }
            }
            SupervisionEvent::ActorFailed(actor_cell, e) => {
                warn!(
                    "CLUSTER_SUPERVISOR: {0:?}:{1:?} failed! {e:?}",
                    actor_cell.get_name(),
                    actor_cell.get_id()
                );
                // Any child actor failure is fatal -- exit so the Job
                // controller creates a new pod. This is a deliberately blunt
                // fail-fast policy for now: we want a visible Job restart
                // event as the signal something needs investigating, rather
                // than silently degrading.
                std::process::exit(1);
            }
            SupervisionEvent::ProcessGroupChanged(..) => {}
        }

        Ok(())
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            ObserverSupervisorMessage::PrepareShutdown => {
                info!("CLUSTER_SUPERVISOR: PrepareShutdown received -- stopping the watches");
                if let Some(watches) = state.watches.take() {
                    let stopping = watches.stop_and_wait(None, Some(WATCHES_STOP)).await;
                    if let Err(why) = stopping {
                        warn!("the watches did not stop in time, so they are ended: {why}");
                        watches.kill();
                    }
                }
                let _ = state
                    .infrastructure
                    .cast(InfrastructureSupervisorMessage::ProceedWithShutdown);
            }
            ObserverSupervisorMessage::ClientEvent { event } => match event {
                ClientEvent::Registered { .. } => {
                    let _ = state.healthcheck.cassini_connected();
                    if state.watches.is_none() {
                        let (watches, _) = Actor::spawn_linked(
                            Some("cluster.watches".into()),
                            ClusterWatcher,
                            ClusterWatcherArgs {
                                protocols: state.protocols.clone(),
                                publisher: Arc::new(state.tcp_client.clone()),
                                waits: WAITS,
                            },
                            myself.get_cell(),
                        )
                        .await?;
                        state.watches = Some(watches);
                    }
                }
                ClientEvent::MessagePublished { .. } => {
                    todo!("Handle incoming messages")
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
}
