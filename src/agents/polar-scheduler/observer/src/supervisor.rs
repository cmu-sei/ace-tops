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

//! Supervisor for the scheduler observer, on the agent builder: health check, router and the
//! Cassini client come from `AgentBuilder`.
//!
//! Children: the sync actor (when there is a repository to read), which reads it from Polar's git
//! server over Cassini on an interval, whenever the server announces a change to it, and when the
//! observer joins Cassini; and the watcher, which publishes each schedule change in the checkout,
//! started once the first read is answered. Both are linked, so a failure of either ends the process
//! and the Job starts a fresh one.
//!
//! `Registered` fires on every registration, a reconnect included, so it only reports health, asks
//! for a read, and with no repository to read starts the watcher if there is none.
//!
//! Shutdown, in order, when the health check ends the pod's life:
//!
//! 1. Its `PrepareShutdown`, registered with the builder (`with_drain`), reaches this supervisor.
//! 2. The sync actor and the watcher are stopped.
//! 3. `ProceedWithShutdown` goes to the infrastructure supervisor, which stops its children.
//! 4. When the infrastructure has ended the builder stops this supervisor and `run` exits non-zero,
//!    so the workload is restarted with fresh certificates.

use crate::deployment_record::{DeploymentRecordActor, DeploymentRecordArgs};
use crate::reads::{
    READ_TIMEOUT, ReadsLog, ReadsMain, ServerLogReads, ServerReads, log_replies_subscription,
    replies_subscription,
};
use crate::settings::ObserverSettings;
use crate::sync_actor::{GitSyncActor, GitSyncArgs, OwnConfiguration, SyncMessage};
use crate::watcher::{GitWatcherActor, GitWatcherMsg};
use cassini_client::TcpClientMessage;
use cassini_types::ClientEvent;
use polar::request_reply::ReplyRouter;
use polar_agent_builder::{
    AgentBuilder, Configured, HealthClient, HealthHandle, InfrastructureSupervisorMessage,
    Subscription,
};
use polar_git_server_common::{
    LOG_WITNESSED_TOPIC, LogRead, LogWitnessed, MainRead, POLAR_GIT_REPO_CHANGED_TOPIC,
    RepoChangedEvent, decode_witnessed,
};
use polar_scheduler_common::{CONFIGURATION_REPLAY_TOPIC, ConfigurationReplayRequest};
use ractor::{Actor, ActorProcessingErr, ActorRef, SupervisionEvent, async_trait};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

pub const SERVICE_NAME: &str = "polar-scheduler-observer";

/// Stopping two small actors is all there is to drain; the rest is margin.
pub const SHUTDOWN_BUDGET: Duration = Duration::from_secs(10);

pub enum SchedulerObserverMessage {
    ClientEvent {
        event: ClientEvent,
    },
    /// The Polar git server says a ref of one of its repositories moved.
    RepoChanged(RepoChangedEvent),
    /// The store says a log's co-signed checkpoint grew.
    LogWitnessed(LogWitnessed),
    /// An agent that has just registered asks for the signed configuration held for it.
    ReplayRequested(String),
    /// A read brought the checkout up to date: what changed is read and published.
    Pulled,
    PrepareShutdown,
}

/// A change announced for another repository is not about this checkout.
pub fn concerns(event: &RepoChangedEvent, watched: Option<&str>) -> bool {
    watched == Some(event.repo.as_str())
}

/// The subscription to the git server's announcements: each is handed to the supervisor, which
/// decides whether it concerns this checkout.
pub fn repo_changed_subscription(supervisor: ActorRef<SchedulerObserverMessage>) -> Subscription {
    Subscription::new(
        POLAR_GIT_REPO_CHANGED_TOPIC,
        move |incoming| match rkyv::from_bytes::<RepoChangedEvent, rkyv::rancor::Error>(
            &incoming.payload,
        ) {
            Ok(event) => {
                let _ = supervisor.cast(SchedulerObserverMessage::RepoChanged(event));
            }
            Err(e) => warn!("failed to deserialize a repository change: {e}"),
        },
    )
}

/// The subscription to the store's word that a log's co-signature grew: each is handed to the supervisor, which decides
/// whether it is the log read.
pub fn log_witnessed_subscription(supervisor: ActorRef<SchedulerObserverMessage>) -> Subscription {
    Subscription::new(
        LOG_WITNESSED_TOPIC,
        move |incoming| match decode_witnessed(&incoming.payload) {
            Ok(event) => {
                let _ = supervisor.cast(SchedulerObserverMessage::LogWitnessed(event));
            }
            Err(e) => warn!("dropped a witnessed log: {e}"),
        },
    )
}

/// The subscription to agents' requests for the configuration held for them. The checkout is what
/// answers, so the request comes here and not to the processor, which only writes the ledger. One that
/// does not decode is dropped.
pub fn replay_request_subscription(supervisor: ActorRef<SchedulerObserverMessage>) -> Subscription {
    Subscription::new(
        CONFIGURATION_REPLAY_TOPIC,
        move |incoming| match rkyv::from_bytes::<ConfigurationReplayRequest, rkyv::rancor::Error>(
            &incoming.payload,
        ) {
            Ok(request) => {
                let _ = supervisor.cast(SchedulerObserverMessage::ReplayRequested(request.agent));
            }
            Err(e) => warn!("failed to deserialize a configuration replay request: {e}"),
        },
    )
}

pub struct SchedulerObserverSupervisor;

/// Starts the watcher on the checkout, its first scan, and the replays asked for before it was there.
async fn start_watcher(
    myself: &ActorRef<SchedulerObserverMessage>,
    state: &mut SchedulerObserverSupervisorState,
) -> Result<(), ActorProcessingErr> {
    let (watcher, _) = Actor::spawn_linked(
        Some("git-watcher".to_string()),
        GitWatcherActor,
        (state.repo_path.clone(), state.tcp_client.clone()),
        myself.get_cell(),
    )
    .await?;
    info!("triggering the watcher's initial scan");
    watcher.cast(GitWatcherMsg::PerformInitialScan)?;
    for agent in std::mem::take(&mut state.waiting_replays) {
        watcher.cast(GitWatcherMsg::Replay { agent })?;
    }
    state.watcher = Some(watcher);
    Ok(())
}

pub struct SchedulerObserverSupervisorState {
    healthcheck: HealthHandle,
    infrastructure: ActorRef<InfrastructureSupervisorMessage>,
    tcp_client: ActorRef<TcpClientMessage>,
    repo_path: String,
    /// The repository this checkout is of, when it has a remote.
    watched_repo: Option<String>,
    /// The log the checkout is read from: the one the store keeps beside that repository.
    watched_log: Option<String>,
    sync: Option<ActorRef<SyncMessage>>,
    watcher: Option<ActorRef<GitWatcherMsg>>,
    /// Agents that asked before the watcher existed; handed to it when it does.
    waiting_replays: Vec<String>,
}

#[async_trait]
impl Actor for SchedulerObserverSupervisor {
    type Msg = SchedulerObserverMessage;
    type State = SchedulerObserverSupervisorState;
    type Arguments = Configured;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        configured: Configured,
    ) -> Result<Self::State, ActorProcessingErr> {
        info!("{myself:?} starting");

        let settings = ObserverSettings::read(configured.config())?;
        let read_router = Arc::new(ReplyRouter::<MainRead>::new());
        let log_router = Arc::new(ReplyRouter::<LogRead>::new());
        let resources = AgentBuilder::new(myself.clone(), SERVICE_NAME)
            .with_lifecycle_handler(|event| Some(SchedulerObserverMessage::ClientEvent { event }))
            .with_subscription(repo_changed_subscription(myself.clone()))
            .with_subscription(replay_request_subscription(myself.clone()))
            .with_subscription(replies_subscription(read_router.clone()))
            .with_subscription(log_replies_subscription(log_router.clone()))
            .with_subscription(log_witnessed_subscription(myself.clone()))
            .with_drain(|| SchedulerObserverMessage::PrepareShutdown)
            .into_configured(configured)
            .build()
            .await?;
        // The git server, asked over Cassini: the schedules and the deployment's record are read through it.
        let reads: Arc<dyn ReadsMain> = Arc::new(ServerReads::new(
            resources.tcp_client.as_actor_ref().clone(),
            read_router,
            READ_TIMEOUT,
        ));

        // The schedules are read from the store's log of the repository (docs/architecture/record-store.md, "Bite 6").
        let log_reads: Arc<dyn ReadsLog> = Arc::new(ServerLogReads::new(
            resources.tcp_client.as_actor_ref().clone(),
            log_router,
            READ_TIMEOUT,
        ));

        let mut sync = None;
        let watched_repo = settings.schedules_repo.clone();
        let watched_log = match &settings.schedules_repo {
            Some(repo) => Some(
                polar_git_server_common::log_of_repo(repo)
                    .ok_or_else(|| {
                        format!("the store keeps no log of {repo} to read schedules from")
                    })?
                    .to_string(),
            ),
            None => None,
        };
        if let Some(log) = &watched_log {
            // The first read is asked once the observer has joined Cassini (`Registered`), and the watcher starts once it
            // is answered, so its first scan is the repository's word.
            let interval = settings
                .sync_interval_secs
                .filter(|secs| *secs > 0)
                .map(Duration::from_secs);
            let (actor, _) = Actor::spawn_linked(
                Some(format!("{SERVICE_NAME}.sync")),
                GitSyncActor,
                GitSyncArgs {
                    repo_path: PathBuf::from(&settings.local_path),
                    log: log.clone(),
                    reads: log_reads,
                    interval,
                    pulled: Some({
                        let supervisor = myself.clone();
                        std::sync::Arc::new(move || {
                            let _ = supervisor.cast(SchedulerObserverMessage::Pulled);
                        })
                    }),
                    own: Arc::new(OwnConfiguration {
                        agent: SERVICE_NAME.to_string(),
                        configuration: resources.configuration.clone(),
                    }),
                },
                myself.get_cell(),
            )
            .await?;
            sync = Some(actor);
        } else {
            info!("No repository configured; watching local directory only.");
        }

        if let Some(repo) = &settings.deployment_repo {
            Actor::spawn_linked(
                Some(format!("{SERVICE_NAME}.deployment_record")),
                DeploymentRecordActor,
                DeploymentRecordArgs {
                    repo: repo.clone(),
                    reads: reads.clone(),
                    tcp_client: resources.tcp_client.as_actor_ref().clone(),
                    configuration: resources.configuration.clone(),
                },
                myself.get_cell(),
            )
            .await?;
        }

        Ok(SchedulerObserverSupervisorState {
            healthcheck: resources.healthcheck,
            infrastructure: resources.infrastructure,
            tcp_client: resources.tcp_client.as_actor_ref().clone(),
            repo_path: settings.local_path,
            watched_repo,
            watched_log,
            sync,
            watcher: None,
            waiting_replays: Vec::new(),
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            SchedulerObserverMessage::ClientEvent { event } => match event {
                ClientEvent::Registered { .. } => {
                    let _ = state.healthcheck.cassini_connected();
                    match &state.sync {
                        // Read now: the first read, or what a reconnect may have missed. The watcher starts once
                        // the first is answered.
                        Some(sync) => sync.cast(SyncMessage::Now)?,
                        None if state.watcher.is_none() => start_watcher(&myself, state).await?,
                        None => {
                            debug!("Watcher already running; not starting another on reconnect")
                        }
                    }
                }
                ClientEvent::TransportError { reason } => {
                    warn!("Transport error (non-fatal, awaiting reconnect): {reason}");
                    let _ = state.healthcheck.cassini_disconnected();
                }
                _ => {}
            },
            SchedulerObserverMessage::RepoChanged(event) => {
                if !concerns(&event, state.watched_repo.as_deref()) {
                    debug!(repo = %event.repo, "change is for another repository");
                } else if let Some(sync) = &state.sync {
                    info!(repo = %event.repo, refname = %event.refname, pusher = %event.pusher, "repository changed; reading it");
                    sync.cast(SyncMessage::Now)?;
                }
            }
            SchedulerObserverMessage::LogWitnessed(event) => {
                if state.watched_log.as_deref() != Some(event.log.as_str()) {
                    debug!(log = %event.log, "witnessed is another log");
                } else if let Some(sync) = &state.sync {
                    info!(log = %event.log, size = event.size, "the log is witnessed further; reading it");
                    sync.cast(SyncMessage::Now)?;
                }
            }
            // The watcher reads the checkout again after each read, and does not depend on noticing the files change. The
            // first read starts it.
            SchedulerObserverMessage::Pulled => match &state.watcher {
                Some(watcher) => watcher.cast(GitWatcherMsg::Rescan)?,
                None => start_watcher(&myself, state).await?,
            },
            SchedulerObserverMessage::ReplayRequested(agent) => match &state.watcher {
                Some(watcher) => watcher.cast(GitWatcherMsg::Replay { agent })?,
                None => state.waiting_replays.push(agent),
            },
            SchedulerObserverMessage::PrepareShutdown => {
                info!(
                    "PrepareShutdown received: stopping the watcher and the sync before infrastructure"
                );
                if let Some(sync) = state.sync.take() {
                    sync.stop(None);
                }
                if let Some(watcher) = state.watcher.take() {
                    watcher.stop(None);
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

    fn event(repo: &str) -> RepoChangedEvent {
        RepoChangedEvent {
            repo: repo.into(),
            refname: "refs/heads/main".into(),
            old: "a".repeat(40),
            new: "b".repeat(40),
            pusher: "alice".into(),
        }
    }

    #[test]
    fn only_a_change_to_the_watched_repository_concerns_the_checkout() {
        assert!(concerns(&event("polar-schedules"), Some("polar-schedules")));
        assert!(!concerns(&event("other"), Some("polar-schedules")));
        assert!(!concerns(&event("polar-schedules"), None));
    }

    #[test]
    fn subscribes_to_the_git_servers_topic() {
        struct Sink;
        #[ractor::async_trait]
        impl Actor for Sink {
            type Msg = SchedulerObserverMessage;
            type State = ();
            type Arguments = ();
            async fn pre_start(
                &self,
                _: ActorRef<Self::Msg>,
                _: (),
            ) -> Result<(), ActorProcessingErr> {
                Ok(())
            }
        }
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let (sink, _) = Actor::spawn(None, Sink, ()).await.unwrap();
            let sub = repo_changed_subscription(sink);
            assert_eq!(sub.topic, POLAR_GIT_REPO_CHANGED_TOPIC);
            // A payload that is not an event is dropped without a panic.
            (sub.deliver)(polar_router::IncomingMessage {
                topic: sub.topic.clone(),
                payload: vec![1, 2, 3],
                published_by: None,
                published_instance: None,
                trace_ctx: None,
            });
        });
    }

    #[test]
    fn a_replay_request_reaches_the_supervisor_as_the_agent_that_asked_and_garbage_is_dropped() {
        use std::sync::{Arc, Mutex};
        struct Sink;
        #[ractor::async_trait]
        impl Actor for Sink {
            type Msg = SchedulerObserverMessage;
            type State = Arc<Mutex<Vec<String>>>;
            type Arguments = Self::State;
            async fn pre_start(
                &self,
                _: ActorRef<Self::Msg>,
                seen: Self::State,
            ) -> Result<Self::State, ActorProcessingErr> {
                Ok(seen)
            }
            async fn handle(
                &self,
                _: ActorRef<Self::Msg>,
                message: Self::Msg,
                seen: &mut Self::State,
            ) -> Result<(), ActorProcessingErr> {
                if let SchedulerObserverMessage::ReplayRequested(agent) = message {
                    seen.lock().unwrap().push(agent);
                }
                Ok(())
            }
        }
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let (sink, _) = Actor::spawn(None, Sink, seen.clone()).await.unwrap();
            let sub = replay_request_subscription(sink);
            assert_eq!(sub.topic, CONFIGURATION_REPLAY_TOPIC);
            let message = |payload: Vec<u8>| polar_router::IncomingMessage {
                topic: CONFIGURATION_REPLAY_TOPIC.to_string(),
                payload,
                published_by: None,
                published_instance: None,
                trace_ctx: None,
            };
            let request = rkyv::to_bytes::<rkyv::rancor::Error>(&ConfigurationReplayRequest {
                agent: "agent-a".into(),
            })
            .unwrap()
            .to_vec();
            (sub.deliver)(message(request));
            (sub.deliver)(message(vec![9, 9]));
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(*seen.lock().unwrap(), ["agent-a"]);
        });
    }
}
