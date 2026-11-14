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

//! Supervisor for polar-git, on the agent builder: health, the Cassini client its events go out on, and the policy actor
//! its edge asks come from `AgentBuilder`; the mTLS listener runs under it.
//!
//! Shutdown, in order, when the health check ends the pod's life: its `PrepareShutdown` reaches this supervisor; the
//! listener stops accepting and connections in flight (a push can take a while) are given up to `DRAIN_TIMEOUT`; then
//! `ProceedWithShutdown` goes to the infrastructure supervisor.

use crate::edge::PolicyAsker;
use crate::events::CassiniReporter;
use crate::http::{PolarGitState, router};
use crate::settings::PolarGitSettings;
use cassini_types::ClientEvent;
use polar_agent_builder::{
    AgentBuilder, Configured, HealthClient, HealthHandle, InfrastructureSupervisorMessage,
};
use polar_git_server::git::GitRunner;
use polar_git_server::store::RepoStore;
use polar_git_server::tls::{ClientIdentities, serve_tls, server_config};
use ractor::{Actor, ActorProcessingErr, ActorRef, SupervisionEvent, async_trait};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

pub const SERVICE_NAME: &str = "polar-git";

/// How long connections in flight may keep the process alive once shutdown has begun.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// The infrastructure supervisor's allowance for this agent: the drain plus a margin.
pub const SHUTDOWN_BUDGET: Duration = Duration::from_secs(DRAIN_TIMEOUT.as_secs() + 10);

/// The largest request body accepted, compressed or inflated: what a single push may cost.
const MAX_BODY: usize = 512 * 1024 * 1024;

pub enum PolarGitMessage {
    ClientEvent { event: ClientEvent },
    PrepareShutdown,
}

struct Listener {
    stop: Arc<Notify>,
    active: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

pub struct PolarGitSupervisorState {
    healthcheck: HealthHandle,
    infrastructure: ActorRef<InfrastructureSupervisorMessage>,
    listener: Option<Listener>,
}

pub struct PolarGitSupervisor;

#[async_trait]
impl Actor for PolarGitSupervisor {
    type Msg = PolarGitMessage;
    type State = PolarGitSupervisorState;
    type Arguments = Configured;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        configured: Configured,
    ) -> Result<Self::State, ActorProcessingErr> {
        info!("{myself:?} starting");
        let settings = PolarGitSettings::read(configured.config())?;
        let resources = AgentBuilder::new(myself.clone(), SERVICE_NAME)
            .with_lifecycle_handler(|event| Some(PolarGitMessage::ClientEvent { event }))
            .with_drain(|| PolarGitMessage::PrepareShutdown)
            .into_configured(configured)
            .build()
            .await?;
        std::fs::create_dir_all(&settings.repo_root)
            .map_err(|e| format!("cannot create {}: {e}", settings.repo_root))?;
        let app = router(PolarGitState {
            store: RepoStore::new(&settings.repo_root),
            runner: GitRunner::default(),
            asker: Arc::new(PolicyAsker(Some(resources.authority.policy()))),
            reporter: Arc::new(CassiniReporter(resources.tcp_client.as_actor_ref().clone())),
            max_body: MAX_BODY,
        });
        // Its TLS is its crypto actor's, from the server key its deployment gives it (docs/plans/crypto-actor.md).
        let tls = server_config(&resources.tls, Path::new(&settings.ca_cert), None).await?;
        let identities = Arc::new(ClientIdentities::new(None)?);
        let tcp = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", settings.port))
            .await
            .map_err(|e| format!("cannot listen on port {}: {e}", settings.port))?;
        info!("{SERVICE_NAME} listening on 0.0.0.0:{}", settings.port);
        let stop = Arc::new(Notify::new());
        let active = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(serve_tls(
            tcp,
            TlsAcceptor::from(tls),
            app,
            stop.clone(),
            active.clone(),
            identities,
        ));
        Ok(PolarGitSupervisorState {
            healthcheck: resources.healthcheck,
            infrastructure: resources.infrastructure,
            listener: Some(Listener { stop, active, task }),
        })
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            PolarGitMessage::ClientEvent { event } => match event {
                ClientEvent::Registered { .. } => {
                    let _ = state.healthcheck.cassini_connected();
                }
                ClientEvent::TransportError { reason } => {
                    warn!("Transport error (non-fatal, awaiting reconnect): {reason}");
                    let _ = state.healthcheck.cassini_disconnected();
                }
                _ => {}
            },
            PolarGitMessage::PrepareShutdown => {
                info!("PrepareShutdown received: draining the listener before infrastructure");
                if let Some(listener) = state.listener.take() {
                    listener.stop.notify_one();
                    let _ = listener.task.await;
                    let drained = tokio::time::timeout(DRAIN_TIMEOUT, async {
                        while listener.active.load(Ordering::SeqCst) > 0 {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    })
                    .await;
                    if drained.is_err() {
                        warn!(
                            "connections did not finish within {DRAIN_TIMEOUT:?}; continuing shutdown"
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
