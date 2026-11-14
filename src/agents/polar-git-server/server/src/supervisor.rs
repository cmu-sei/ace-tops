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

//! Supervisor for the git server, on the agent builder like the other migrated agents. It runs
//! as part of a Polar cluster or on its own, with the same binary: when its deployment provides
//! the Cassini capability, health, the router and the Cassini client come from `AgentBuilder`
//! and an accepted push is published on Cassini; otherwise `ServiceBuilder` gives it the health
//! check and the shutdown handshake and a push is only logged. The mTLS listener runs under this
//! supervisor either way, and the store's signed logs beside the repositories (`crate::logs`), served to people as tiles.
//! With Cassini it also answers reads (`crate::read`) and takes evidence records (`crate::evidence`).
//!
//! Shutdown, in order, when the health check ends the pod's life:
//!
//! 1. Its `PrepareShutdown`, registered with the builder (`with_drain`), reaches this supervisor.
//! 2. The listener stops accepting; connections in flight (a push can take a while) are given up
//!    to `DRAIN_TIMEOUT`.
//! 3. `ProceedWithShutdown` goes to the infrastructure supervisor, which stops its children.
//! 4. When the infrastructure has ended the builder stops this supervisor and `run` exits non-zero,
//!    so the workload is restarted with fresh certificates.

use crate::access::RuntimeAcl;
use crate::config::ServerFile;
use crate::evidence::{Intake, IntakeActor, IntakeMessage, IntakeState};
use crate::git::GitRunner;
use crate::http::{ServerState, router};
use crate::notify::{CassiniNotifier, Notifier, PushLog, Tee};
use crate::read::{READ_LIMIT, ReadActor, ReadMessage, ReadState, Reader};
use crate::settings::GitServerSettings;
use crate::store::RepoStore;
use crate::tls::{ClientIdentities, serve_tls, server_config};
use cassini_types::ClientEvent;
use polar_agent_builder::{
    AgentBuilder, Configured, HealthClient, HealthHandle, InfrastructureSupervisorMessage,
    ServiceBuilder, Subscription,
};
use ractor::{Actor, ActorProcessingErr, ActorRef, SupervisionEvent, async_trait};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

pub const SERVICE_NAME: &str = "polar-git-server";

/// How long connections in flight may keep the process alive once shutdown has begun.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// The infrastructure supervisor's allowance for this agent: the drain plus a margin.
pub const SHUTDOWN_BUDGET: Duration = Duration::from_secs(DRAIN_TIMEOUT.as_secs() + 10);

/// The largest request body accepted, compressed or inflated. A configuration repository is
/// small; this bounds what a single push may cost.
const MAX_BODY: usize = 256 * 1024 * 1024;

pub enum GitServerSupervisorMessage {
    ClientEvent {
        event: ClientEvent,
    },
    PrepareShutdown,
    /// An evidence record sent on Cassini, for the intake.
    EvidenceRecord {
        payload: Vec<u8>,
        published_by: Option<String>,
    },
    /// A read sent on Cassini, for the reader.
    Read {
        payload: Vec<u8>,
        published_by: Option<String>,
    },
    /// A signed section sent on Cassini, for the section intake.
    Section {
        payload: Vec<u8>,
        published_by: Option<String>,
    },
    /// A read of a log sent on Cassini, for the log reader.
    LogRead {
        payload: Vec<u8>,
        published_by: Option<String>,
    },
    /// The witness's answer to a checkpoint the store submitted.
    WitnessAnswer {
        payload: Vec<u8>,
        published_by: Option<String>,
    },
}

pub struct GitServerSupervisor;

struct Listener {
    stop: Arc<Notify>,
    active: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

pub struct GitServerSupervisorState {
    healthcheck: HealthHandle,
    infrastructure: ActorRef<InfrastructureSupervisorMessage>,
    listener: Option<Listener>,
    /// Takes evidence records; only with Cassini.
    intake: Option<ractor::ActorRef<IntakeMessage>>,
    /// Answers reads; only with Cassini.
    reader: Option<ractor::ActorRef<ReadMessage>>,
    /// Answers reads of a log; only with Cassini.
    log_reader: Option<ractor::ActorRef<crate::log_read::LogReadMessage>>,
    /// Takes signed sections people's tools send; only with Cassini.
    sections: Option<ractor::ActorRef<crate::schedules::SectionMessage>>,
    /// Brings each log's checkpoints to the witness; only with Cassini.
    witness: Option<ractor::ActorRef<crate::witness::WitnessMessage>>,
}

#[async_trait]
impl Actor for GitServerSupervisor {
    type Msg = GitServerSupervisorMessage;
    type State = GitServerSupervisorState;
    type Arguments = Configured;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        configured: Configured,
    ) -> Result<Self::State, ActorProcessingErr> {
        info!("{myself:?} starting");

        let settings = GitServerSettings::read(configured.config())?;
        // In a cluster the deployment provides Cassini and the server is a client of the broker;
        // on its own it has the health check and the shutdown handshake and no broker.
        let (healthcheck, infrastructure, tcp_client, tls, checkpoints, policy, configuration) =
            if configured.cassini_enabled() {
                let deliver_to = myself.clone();
                let records = Subscription::new(
                    polar_git_server_common::EVIDENCE_REQUESTS_TOPIC,
                    move |incoming| {
                        if let Err(e) =
                            deliver_to.cast(GitServerSupervisorMessage::EvidenceRecord {
                                payload: incoming.payload,
                                published_by: incoming.published_by,
                            })
                        {
                            warn!("failed to hand an evidence record to the supervisor: {e}");
                        }
                    },
                );
                let deliver_to = myself.clone();
                let reads = Subscription::new(
                    polar_git_server_common::READ_REQUESTS_TOPIC,
                    move |incoming| {
                        if let Err(e) = deliver_to.cast(GitServerSupervisorMessage::Read {
                            payload: incoming.payload,
                            published_by: incoming.published_by,
                        }) {
                            warn!("failed to hand a read to the supervisor: {e}");
                        }
                    },
                );
                let deliver_to = myself.clone();
                let log_reads = Subscription::new(
                    polar_git_server_common::LOG_READ_REQUESTS_TOPIC,
                    move |incoming| {
                        if let Err(e) = deliver_to.cast(GitServerSupervisorMessage::LogRead {
                            payload: incoming.payload,
                            published_by: incoming.published_by,
                        }) {
                            warn!("failed to hand a log read to the supervisor: {e}");
                        }
                    },
                );
                let deliver_to = myself.clone();
                let sections = Subscription::new(
                    polar_git_server_common::SCHEDULES_REQUESTS_TOPIC,
                    move |incoming| {
                        if let Err(e) = deliver_to.cast(GitServerSupervisorMessage::Section {
                            payload: incoming.payload,
                            published_by: incoming.published_by,
                        }) {
                            warn!("failed to hand a section to the supervisor: {e}");
                        }
                    },
                );
                let deliver_to = myself.clone();
                let witnessed = Subscription::new(
                    attestation_common::witness::STORE_WITNESS_REPLIES_TOPIC,
                    move |incoming| {
                        if let Err(e) = deliver_to.cast(GitServerSupervisorMessage::WitnessAnswer {
                            payload: incoming.payload,
                            published_by: incoming.published_by,
                        }) {
                            warn!("failed to hand the witness's answer to the supervisor: {e}");
                        }
                    },
                );
                let resources = AgentBuilder::new(myself.clone(), SERVICE_NAME)
                    .with_lifecycle_handler(|event| {
                        Some(GitServerSupervisorMessage::ClientEvent { event })
                    })
                    .with_subscription(records)
                    .with_subscription(reads)
                    .with_subscription(log_reads)
                    .with_subscription(sections)
                    .with_subscription(witnessed)
                    .with_drain(|| GitServerSupervisorMessage::PrepareShutdown)
                    .into_configured(configured)
                    .build()
                    .await?;
                (
                    resources.healthcheck,
                    resources.infrastructure,
                    Some(resources.tcp_client),
                    resources.tls,
                    resources.checkpoints,
                    Some(resources.authority.policy()),
                    Some(resources.configuration),
                )
            } else {
                info!("{SERVICE_NAME} is running on its own: pushes are logged, not published");
                let resources = ServiceBuilder::new(myself.clone(), SERVICE_NAME)
                    .with_drain(|| GitServerSupervisorMessage::PrepareShutdown)
                    .into_configured(configured)
                    .build()
                    .await?;
                (
                    resources.healthcheck,
                    resources.infrastructure,
                    None,
                    resources.tls,
                    resources.checkpoints,
                    None,
                    None,
                )
            };

        let file = ServerFile::parse(&settings.repos)?.with_admins(settings.admins.clone());

        let store = RepoStore::new(&settings.repo_root);
        std::fs::create_dir_all(&settings.repo_root)
            .map_err(|e| format!("cannot create {}: {e}", settings.repo_root))?;
        file.provision(&store, Path::new(&settings.seed_root))
            .await
            .map_err(|e| format!("cannot provision the declared repositories: {e}"))?;

        // The access lists of repositories created while running are kept beside the repositories,
        // as is the record of pushes.
        let root = Path::new(&settings.repo_root);
        let acl = Arc::new(RuntimeAcl::new(
            file.acl(),
            Some(root.join("runtime-acl.json")),
        )?);
        // The store's logs, beside the repositories (docs/architecture/record-store.md). Their checkpoints are signed by
        // the crypto actor with the store's checkpoint key, under the store's identity, which each log's origin names.
        let checkpoints = checkpoints.ok_or_else(|| {
            format!("{SERVICE_NAME} keeps signed logs, and its deployment gives it no checkpoint key (the `checkpoints` capability)")
        })?;
        let verifier = checkpoints
            .key()
            .await
            .map_err(|e| format!("the store's checkpoint key cannot be had: {e}"))?
            .0;
        let origin = crate::logs::origin_of(&verifier)
            .ok_or_else(|| format!("the store's checkpoint key {verifier} names no identity"))?;
        let (logs, _) = Actor::spawn_linked(
            Some(format!("{SERVICE_NAME}.logs")),
            crate::logs::LogsActor,
            crate::logs::LogsArgs {
                root: std::path::PathBuf::from(&settings.log_root),
                origin: origin.clone(),
                signer: Arc::new(checkpoints),
            },
            myself.get_cell(),
        )
        .await
        .map_err(|e| format!("the store's logs did not open: {e}"))?;
        // The evidence log holds every record polar-evidence holds: what a push took while the server kept no log is
        // brought in now, as the store's.
        crate::evidence::catch_up(&store, &logs, &origin).await?;
        // Before anything is served or pushed: the schedules log holds what polar-schedules' main holds.
        crate::schedules::catch_up(&store, &logs, &origin)
            .await
            .map_err(|e| format!("the schedules log cannot be brought to polar-schedules: {e}"))?;
        let mut notifiers: Vec<Arc<dyn Notifier>> =
            vec![Arc::new(PushLog::new(root.join("push-log.jsonl")))];
        if let Some(client) = &tcp_client {
            notifiers.push(Arc::new(CassiniNotifier::new(
                client.as_actor_ref().clone(),
            )));
        }
        let signed = crate::signed::SignedRepos::from_specs(&file.repos)?;
        let notifier: Arc<dyn Notifier> = Arc::new(Tee(notifiers));
        // Evidence records are verified under the CA the server's clients chain to.
        let intake = match &tcp_client {
            Some(client) => {
                let pem = std::fs::read_to_string(&settings.ca_cert)
                    .map_err(|e| format!("cannot read the CA at {}: {e}", settings.ca_cert))?;
                let trust = polar_signing::Trust::from_pem(&[pem])
                    .map_err(|e| format!("the CA at {} cannot be used: {e}", settings.ca_cert))?;
                let (intake, _) = Actor::spawn_linked(
                    Some(format!("{SERVICE_NAME}.evidence")),
                    IntakeActor,
                    IntakeState {
                        intake: Intake {
                            store: store.clone(),
                            authorizer: acl.clone(),
                            trust,
                            notifier: notifier.clone(),
                            policy: policy.clone(),
                            logs: Some(logs.clone()),
                        },
                        client: client.as_actor_ref().clone(),
                    },
                    myself.get_cell(),
                )
                .await
                .map_err(|e| format!("the evidence intake did not start: {e}"))?;
                Some(intake)
            }
            None => None,
        };
        let reader = match &tcp_client {
            Some(client) => {
                let (reader, _) = Actor::spawn_linked(
                    Some(format!("{SERVICE_NAME}.read")),
                    ReadActor,
                    ReadState {
                        reader: Reader {
                            store: store.clone(),
                            authorizer: acl.clone(),
                            limit: READ_LIMIT,
                        },
                        client: client.as_actor_ref().clone(),
                    },
                    myself.get_cell(),
                )
                .await
                .map_err(|e| format!("the reader did not start: {e}"))?;
                Some(reader)
            }
            None => None,
        };
        let log_reader = match &tcp_client {
            Some(client) => {
                let (log_reader, _) = Actor::spawn_linked(
                    Some(format!("{SERVICE_NAME}.log-read")),
                    crate::log_read::LogReadActor,
                    crate::log_read::LogReadState {
                        reader: crate::log_read::LogReader {
                            logs: logs.clone(),
                            authorizer: acl.clone(),
                            limit: READ_LIMIT,
                        },
                        client: client.as_actor_ref().clone(),
                    },
                    myself.get_cell(),
                )
                .await
                .map_err(|e| format!("the log reader did not start: {e}"))?;
                Some(log_reader)
            }
            None => None,
        };
        let sections = match &tcp_client {
            Some(client) => {
                let (sections, _) = Actor::spawn_linked(
                    Some(format!("{SERVICE_NAME}.sections")),
                    crate::schedules::SectionActor,
                    crate::schedules::SectionState {
                        intake: crate::schedules::SectionIntake {
                            store: store.clone(),
                            authorizer: acl.clone(),
                            logs: logs.clone(),
                            notifier: notifier.clone(),
                        },
                        client: client.as_actor_ref().clone(),
                    },
                    myself.get_cell(),
                )
                .await
                .map_err(|e| format!("the section intake did not start: {e}"))?;
                Some(sections)
            }
            None => None,
        };
        let witness = match (&tcp_client, configuration) {
            (Some(client), Some(configuration)) => {
                let (witness, _) = Actor::spawn_linked(
                    Some(format!("{SERVICE_NAME}.witness")),
                    crate::witness::WitnessActor,
                    crate::witness::WitnessArgs {
                        origin,
                        logs: logs.clone(),
                        client: client.as_actor_ref().clone(),
                        configuration,
                    },
                    myself.get_cell(),
                )
                .await
                .map_err(|e| format!("the witness client did not start: {e}"))?;
                Some(witness)
            }
            _ => None,
        };
        let app = router(ServerState {
            store,
            authorizer: acl.clone(),
            runtime: acl,
            runner: GitRunner::default(),
            notifier,
            max_body: MAX_BODY,
            signed: Arc::new(signed),
            logs: Some(logs.clone()),
        });

        let tls = server_config(
            &tls,
            Path::new(&settings.ca_cert),
            settings.deployment_ca.as_deref().map(Path::new),
        )
        .await?;
        let identities = Arc::new(ClientIdentities::new(
            settings.deployment_ca.as_deref().map(Path::new),
        )?);
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

        Ok(GitServerSupervisorState {
            healthcheck,
            infrastructure,
            listener: Some(Listener { stop, active, task }),
            intake,
            reader,
            log_reader,
            sections,
            witness,
        })
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            GitServerSupervisorMessage::ClientEvent { event } => match event {
                // Fires on every registration, including a resume: health only.
                ClientEvent::Registered { .. } => {
                    let _ = state.healthcheck.cassini_connected();
                }
                ClientEvent::TransportError { reason } => {
                    warn!("Transport error (non-fatal, awaiting reconnect): {reason}");
                    let _ = state.healthcheck.cassini_disconnected();
                }
                _ => {}
            },
            GitServerSupervisorMessage::PrepareShutdown => {
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
            GitServerSupervisorMessage::EvidenceRecord {
                payload,
                published_by,
            } => match &state.intake {
                Some(intake) => {
                    if let Err(e) = intake.cast(IntakeMessage::Take {
                        payload,
                        published_by,
                    }) {
                        warn!("failed to hand an evidence record to the intake: {e}");
                    }
                }
                None => warn!("an evidence record arrived with no intake to take it"),
            },
            GitServerSupervisorMessage::Read {
                payload,
                published_by,
            } => match &state.reader {
                Some(reader) => {
                    if let Err(e) = reader.cast(ReadMessage::Take {
                        payload,
                        published_by,
                    }) {
                        warn!("failed to hand a read to the reader: {e}");
                    }
                }
                None => warn!("a read arrived with no reader to answer it"),
            },
            GitServerSupervisorMessage::Section {
                payload,
                published_by,
            } => match &state.sections {
                Some(sections) => {
                    if let Err(e) = sections.cast(crate::schedules::SectionMessage::Take {
                        payload,
                        published_by,
                    }) {
                        warn!("failed to hand a section to the section intake: {e}");
                    }
                }
                None => warn!("a section arrived with no intake to take it"),
            },
            GitServerSupervisorMessage::LogRead {
                payload,
                published_by,
            } => match &state.log_reader {
                Some(reader) => {
                    if let Err(e) = reader.cast(crate::log_read::LogReadMessage::Take {
                        payload,
                        published_by,
                    }) {
                        warn!("failed to hand a log read to the log reader: {e}");
                    }
                }
                None => warn!("a log read arrived with no reader to answer it"),
            },
            GitServerSupervisorMessage::WitnessAnswer {
                payload,
                published_by,
            } => match &state.witness {
                Some(witness) => {
                    if let Err(e) = witness.cast(crate::witness::WitnessMessage::Answer {
                        payload,
                        published_by,
                    }) {
                        warn!("failed to hand the witness's answer to the witness client: {e}");
                    }
                }
                None => warn!("a witness's answer arrived with no witness client to take it"),
            },
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
