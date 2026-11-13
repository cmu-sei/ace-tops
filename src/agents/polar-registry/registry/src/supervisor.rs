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

//! The registry's supervisor, on the agent builder: its infrastructure (health, the Cassini client, its protocol
//! handler), the content store and the Nix cache on its volume, faults through the handler, and the server.
//!
//! Shutdown, in order, when the health check ends the pod's life:
//!
//! 1. Its `PrepareShutdown`, registered with the builder (`with_drain`), reaches this supervisor.
//! 2. The server stops accepting; requests in flight are given up to `DRAIN_TIMEOUT`.
//! 3. `ProceedWithShutdown` goes to the infrastructure supervisor, which stops its children.

use crate::agent::AGENT_NAME;
use crate::blobs::{Blobs, DEFAULT_LEVEL};
use crate::faults::Faults;
use crate::nix_cache::{NixCache, PRIORITY, router};
use crate::settings::{self, Tuning};
use crate::upstream::Handled;
use cassini_types::ClientEvent;
use polar_agent_builder::{
    AgentBuilder, Configured, HealthClient, HealthHandle, InfrastructureSupervisorMessage,
};
use polar_registry_nix::signature::SecretKey;
use ractor::{Actor, ActorProcessingErr, ActorRef, SupervisionEvent, async_trait};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tracing::{error, info, warn};

/// How long requests in flight may keep the process alive once shutdown has begun: a fault fetches an archive.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(120);
/// The infrastructure supervisor's allowance for this agent: the drain plus a margin.
pub const SHUTDOWN_BUDGET: Duration = Duration::from_secs(DRAIN_TIMEOUT.as_secs() + 10);

pub enum RegistryMessage {
    ClientEvent { event: ClientEvent },
    TuningChanged(Tuning),
    PrepareShutdown,
}

pub struct RegistrySupervisor;

pub struct RegistryState {
    healthcheck: HealthHandle,
    infrastructure: ActorRef<InfrastructureSupervisorMessage>,
    faults: Arc<Faults>,
    stop: Arc<Notify>,
    server: Option<tokio::task::JoinHandle<()>>,
}

/// The key the Nix cache signs with, from its file.
fn signing_key(path: &str) -> Result<SecretKey, String> {
    std::fs::read_to_string(path)
        .map_err(|e| format!("the Nix cache's key could not be read from {path}: {e}"))?
        .parse()
        .map_err(|e| format!("{path} does not hold a key as Nix writes one: {e}"))
}

#[async_trait]
impl Actor for RegistrySupervisor {
    type Msg = RegistryMessage;
    type State = RegistryState;
    type Arguments = Configured;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        configured: Configured,
    ) -> Result<Self::State, ActorProcessingErr> {
        let resources = AgentBuilder::new(myself.clone(), AGENT_NAME)
            .with_lifecycle_handler(|event| Some(RegistryMessage::ClientEvent { event }))
            .with_drain(|| RegistryMessage::PrepareShutdown)
            .into_configured(configured)
            .build()
            .await?;
        let protocols = resources
            .protocols
            .clone()
            .ok_or("the builder gave no protocol handle, which this agent's operations need")?;
        let deployment =
            settings::deployment(&resources.config).map_err(ActorProcessingErr::from)?;
        let tuning = resources
            .configuration
            .follow_group(
                settings::TUNING,
                settings::tuning,
                &myself,
                RegistryMessage::TuningChanged,
            )
            .await
            .map_err(|e| format!("the run-time settings are not followed: {e}"))?;

        let root = Path::new(&deployment.root);
        let blobs = Arc::new(
            Blobs::open(root, DEFAULT_LEVEL).map_err(|e| format!("the content store: {e}"))?,
        );
        let key = signing_key(&deployment.nix_key)?;
        info!(key = %key.public(), "the Nix cache signs with this key");
        let cache = Arc::new(
            NixCache::open(root, blobs, key, PRIORITY)
                .map_err(|e| format!("the Nix cache: {e}"))?,
        );
        let faults = Arc::new(
            Faults::new(
                cache,
                root,
                vec![deployment.upstream.clone()],
                Arc::new(Handled(protocols)),
                tuning.faults,
                tuning.max_archive,
            )
            .map_err(|e| format!("the record of faults: {e}"))?,
        );

        let listener = tokio::net::TcpListener::bind(&deployment.listen)
            .await
            .map_err(|e| format!("cannot listen on {}: {e}", deployment.listen))?;
        info!(
            listen = %deployment.listen,
            upstream = %deployment.upstream.url,
            faults = tuning.faults,
            "the Nix cache is serving"
        );
        let stop = Arc::new(Notify::new());
        let app = router(faults.clone()).into_make_service_with_connect_info::<SocketAddr>();
        let stopped = stop.clone();
        let ended = myself.clone();
        let server = tokio::spawn(async move {
            let served = axum::serve(listener, app)
                .with_graceful_shutdown(async move { stopped.notified().await })
                .await;
            if let Err(e) = served {
                error!("the server ended: {e}");
                ended.stop(Some(format!("the server ended: {e}")));
            }
        });
        Ok(RegistryState {
            healthcheck: resources.healthcheck,
            infrastructure: resources.infrastructure,
            faults,
            stop,
            server: Some(server),
        })
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            RegistryMessage::ClientEvent { event } => match event {
                ClientEvent::Registered { .. } => {
                    let _ = state.healthcheck.cassini_connected();
                }
                ClientEvent::TransportError { reason } => {
                    warn!("Transport error (non-fatal, awaiting reconnect): {reason}");
                    let _ = state.healthcheck.cassini_disconnected();
                }
                _ => {}
            },
            RegistryMessage::TuningChanged(tuning) => {
                info!(
                    faults = tuning.faults,
                    max_archive = tuning.max_archive,
                    "the run-time settings changed"
                );
                state.faults.set_on(tuning.faults);
                state.faults.set_max_archive(tuning.max_archive);
            }
            RegistryMessage::PrepareShutdown => {
                info!("PrepareShutdown received: draining the server before infrastructure");
                if let Some(server) = state.server.take() {
                    state.stop.notify_one();
                    if tokio::time::timeout(DRAIN_TIMEOUT, server).await.is_err() {
                        warn!(
                            "requests did not finish within {DRAIN_TIMEOUT:?}; continuing shutdown"
                        );
                    }
                }
                let _ = state
                    .infrastructure
                    .cast(InfrastructureSupervisorMessage::ProceedWithShutdown);
            }
        }
        Ok(())
    }

    async fn handle_supervisor_evt(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: SupervisionEvent,
        _state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        if let SupervisionEvent::ActorFailed(actor, err) = message {
            error!("Child actor {actor:?} failed: {err}; exiting");
            std::process::exit(1);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shutdown_budget_is_the_drain_and_a_margin() {
        assert_eq!(SHUTDOWN_BUDGET, DRAIN_TIMEOUT + Duration::from_secs(10));
    }
}
