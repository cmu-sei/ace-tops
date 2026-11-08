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

//! build-orchestrator's supervisor. It holds what the orchestrator is configured with (the deployment's facts, the
//! run-time settings, followed, and the signed mappings, followed) and its reader; it builds nothing yet. A ref update
//! that arrives is noted and dropped.

use crate::AGENT_NAME;
use crate::mappings::{self, Mapping};
use crate::reader::READER;
use crate::settings::{self, Deployment, Tuning};
use orchestrator_report::Bounds;
use polar_agent_builder::configuration::ConfigurationHandle;
use polar_agent_builder::{
    AgentBuilder, Configured, Drain, HealthClient, HealthHandle, InfrastructureEvent,
    InfrastructureSupervisorMessage, Subscription,
};
use ractor::concurrency::Duration;
use ractor::{Actor, ActorProcessingErr, ActorRef, SupervisionEvent, async_trait};
use tracing::{debug, error, info, warn};

const DRAIN_WINDOW_SECS: u64 = 5;
/// The drain window, with room to spare: nothing of a build is in this process to wait for.
pub const SHUTDOWN_BUDGET: std::time::Duration =
    std::time::Duration::from_secs(DRAIN_WINDOW_SECS + 10);

pub enum OrchestratorMessage {
    ClientEvent {
        event: cassini_types::ClientEvent,
    },
    /// A ref of an observed repository moved.
    RefUpdated,
    /// The run-time settings, changed by a signed update.
    TuningChanged(Tuning),
    /// A runtime section was replaced.
    RuntimeChanged {
        section: String,
    },
    PrepareShutdown,
    DrainElapsed,
}

pub struct OrchestratorSupervisor;

/// What the orchestrator is configured with, as its build actors will be given it.
pub struct OrchestratorState {
    pub healthcheck: HealthHandle,
    pub infrastructure: ActorRef<InfrastructureSupervisorMessage>,
    pub configuration: ConfigurationHandle,
    pub drain: Drain,
    pub deployment: Deployment,
    pub tuning: Tuning,
    /// The bounds the reader was forked with: a line is read to no more than these, whatever is signed later.
    pub forked_reader: Bounds,
    /// The mappings in force; none until a signed version arrives.
    pub mappings: Vec<Mapping>,
}

impl OrchestratorSupervisor {
    /// Reads the mappings in force. A body was validated before it was accepted, so one that does not read now is the
    /// code's fault, said, and the mappings in force stay.
    async fn read_mappings(state: &mut OrchestratorState) {
        match state.configuration.runtime(mappings::SECTION_NAME).await {
            Ok(Some(value)) => match mappings::parse(&value.body) {
                Ok(parsed) => {
                    info!(
                        version = value.version,
                        signer = %value.signer,
                        repositories = parsed.len(),
                        "the mappings in force"
                    );
                    state.mappings = parsed;
                }
                Err(problems) => error!(
                    version = value.version,
                    ?problems,
                    "an accepted mappings section does not read; the mappings in force stay"
                ),
            },
            Ok(None) => debug!("no mappings section yet: nothing is mapped"),
            Err(e) => warn!("the mappings section could not be read: {e}"),
        }
    }
}

#[async_trait]
impl Actor for OrchestratorSupervisor {
    type Msg = OrchestratorMessage;
    type State = OrchestratorState;
    type Arguments = Configured;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        configured: Configured,
    ) -> Result<Self::State, ActorProcessingErr> {
        debug!("{myself:?} starting");
        let to = myself.clone();
        let resources = AgentBuilder::new(myself.clone(), AGENT_NAME)
            .with_subscription(Subscription::new(
                polar::topics::GIT_REPOSITORY_EVENTS,
                move |_| {
                    let _ = to.cast(OrchestratorMessage::RefUpdated);
                },
            ))
            .with_lifecycle_handler(|event| Some(OrchestratorMessage::ClientEvent { event }))
            .into_configured(configured)
            .build()
            .await?;
        resources
            .infrastructure_events
            .subscribe(myself.clone(), |event| match event {
                InfrastructureEvent::PrepareShutdown => Some(OrchestratorMessage::PrepareShutdown),
            });
        if resources.workers.get(READER).is_none() {
            return Err(format!("the {READER} worker was not started").into());
        }
        let deployment =
            settings::deployment(&resources.config).map_err(ActorProcessingErr::from)?;
        let forked_reader =
            settings::reader_bounds(&resources.config).map_err(ActorProcessingErr::from)?;
        let tuning = resources
            .configuration
            .follow_group(
                settings::TUNING,
                settings::tuning,
                &myself,
                OrchestratorMessage::TuningChanged,
            )
            .await
            .map_err(|e| format!("the run-time settings are not followed: {e}"))?;
        resources
            .configuration
            .runtime_changes()
            .subscribe(myself.clone(), |changed| {
                Some(OrchestratorMessage::RuntimeChanged {
                    section: changed.section,
                })
            });
        let _ = myself.cast(OrchestratorMessage::RuntimeChanged {
            section: mappings::SECTION_NAME.to_string(),
        });
        info!(
            namespace = %deployment.namespace,
            template = %deployment.template,
            "builds run from the template in the namespace"
        );

        Ok(OrchestratorState {
            healthcheck: resources.healthcheck,
            infrastructure: resources.infrastructure,
            configuration: resources.configuration,
            drain: Drain::default(),
            deployment,
            tuning,
            forked_reader,
            mappings: Vec::new(),
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            OrchestratorMessage::ClientEvent { event } => match event {
                cassini_types::ClientEvent::Registered { .. } => {
                    let _ = state.healthcheck.cassini_connected();
                }
                cassini_types::ClientEvent::TransportError { reason } => {
                    warn!("Transport error (non-fatal, awaiting reconnect): {reason}");
                    let _ = state.healthcheck.cassini_disconnected();
                }
                _ => {}
            },
            OrchestratorMessage::RefUpdated => {
                debug!(
                    mapped = state.mappings.len(),
                    "a ref moved; nothing is built yet"
                );
            }
            OrchestratorMessage::TuningChanged(tuning) => {
                let reads_at = settings::narrowed(&state.forked_reader, &tuning.reader);
                if reads_at != tuning.reader {
                    warn!(
                        signed = ?tuning.reader,
                        ?reads_at,
                        "the reader's signed bounds are wider than it was started with: it reads at the narrower \
                         until a restart"
                    );
                }
                info!(?tuning, "the run-time settings in force");
                state.tuning = tuning;
            }
            OrchestratorMessage::RuntimeChanged { section } => {
                if section == mappings::SECTION_NAME {
                    Self::read_mappings(state).await;
                }
            }
            OrchestratorMessage::PrepareShutdown => {
                if state.drain.begin(
                    &myself,
                    Duration::from_secs(DRAIN_WINDOW_SECS),
                    true,
                    || OrchestratorMessage::DrainElapsed,
                ) {
                    info!("PrepareShutdown received; entering the drain window");
                }
            }
            OrchestratorMessage::DrainElapsed => state.drain.complete(&state.infrastructure),
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
            }
            SupervisionEvent::ActorFailed(actor, reason) => {
                error!("{actor:?} failed: {reason:?}");
                if !state.drain.begin(
                    &myself,
                    Duration::from_secs(DRAIN_WINDOW_SECS),
                    false,
                    || OrchestratorMessage::DrainElapsed,
                ) {
                    warn!("already draining");
                }
            }
            _ => {}
        }
        Ok(())
    }
}
