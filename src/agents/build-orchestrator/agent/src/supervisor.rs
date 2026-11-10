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
//! run-time settings, followed, and the signed mappings, followed), turns a ref update of a mapped repository into a
//! build, admits it (`admission`), and starts an actor for each build admitted (`build`), which reads its reports with the
//! agent's reader once its Job ends. At start it adopts the Jobs it
//! finds running (docs/architecture/build-orchestrator.md, O2e2); every few minutes it removes the Jobs past their
//! retention.

use crate::AGENT_NAME;
use crate::admission::{Admission, Admitted};
use crate::build::{BuildActor, BuildArgs, Start, actor_name, build_of};
use crate::logs::{KeepLog, RegistryLogs};
use crate::mappings::{self, Mapping};
use crate::observed::Observed;
use crate::publish::Publish;
use crate::reader::{READER, Read};
use crate::registry::{BuildRegistry, RegistryMessage};
use crate::settings::{self, Deployment, Tuning};
use crate::source::{GitSource, Source};
use chrono::Utc;
use git_agent_common::GitRepositoryMessage;
use orchestrator_backend_k8s::backend::KubernetesBackend;
use orchestrator_backend_k8s::job::JobOptions;
use orchestrator_core::backend::{BuildBackend, InFlight};
use orchestrator_core::types::{BuildRequest, BuildState, SourceRef};
use orchestrator_report::Bounds;
use polar::graph::nodes::git::RepoId;
use polar_agent_builder::configuration::ConfigurationHandle;
use polar_agent_builder::protocol::ProtocolHandle;
use polar_agent_builder::{
    AgentBuilder, Configured, Drain, HealthClient, HealthHandle, InfrastructureSupervisorMessage,
    Subscription,
};
use ractor::concurrency::Duration;
use ractor::{Actor, ActorProcessingErr, ActorRef, SupervisionEvent, async_trait};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

const DRAIN_WINDOW_SECS: u64 = 5;
/// The drain window, with room to spare: a build's Job outlives the orchestrator, and the next one adopts it.
pub const SHUTDOWN_BUDGET: std::time::Duration =
    std::time::Duration::from_secs(DRAIN_WINDOW_SECS + 10);
/// How often a build's Job is asked how it is doing.
const POLL_EVERY: Duration = Duration::from_secs(5);
/// How often the Jobs past their retention are looked for.
const SWEEP_EVERY: Duration = Duration::from_secs(300);
/// How many commits are remembered as taken for a build (`observed`).
const OBSERVED_COMMITS: usize = 1024;

pub enum OrchestratorMessage {
    ClientEvent {
        event: cassini_types::ClientEvent,
    },
    /// A message on the git topic, with who the broker says published it.
    RefUpdate {
        payload: Vec<u8>,
        published_by: Option<String>,
    },
    /// The run-time settings, changed by a signed update.
    TuningChanged(Tuning),
    /// A runtime section was replaced.
    RuntimeChanged {
        section: String,
    },
    /// Time to adopt the Jobs found running.
    Adopt,
    /// Time to remove the Jobs past their retention.
    Sweep,
    PrepareShutdown,
    DrainElapsed,
}

pub struct OrchestratorSupervisor;

/// What the orchestrator is configured with, and the builds it holds.
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
    pub protocols: ProtocolHandle,
    pub publish: Arc<dyn Publish>,
    pub reader: Arc<dyn Read>,
    pub source: Arc<dyn Source>,
    /// Where each build's log is kept.
    pub logs: Arc<dyn KeepLog>,
    pub registry: ActorRef<RegistryMessage>,
    pub admission: Admission,
    pub observed: Observed,
    /// How each build waiting to start begins, by its id.
    pub starts: HashMap<Uuid, Start>,
}

/// The build a ref update asks for, if any: a moved ref of a mapped repository, at a commit that is one. `Ok(None)` for
/// an update that is no build (a ref reported unchanged, a commit discovered, an unmapped repository); `Err` for one
/// that cannot be read, with why.
pub fn build_for(
    payload: &[u8],
    mappings: &[Mapping],
) -> Result<Option<(BuildRequest, Mapping, String)>, String> {
    let message = rkyv::from_bytes::<GitRepositoryMessage, rkyv::rancor::Error>(payload)
        .map_err(|e| format!("not a git repository message: {e}"))?;
    let GitRepositoryMessage::RefUpdated {
        repo,
        ref_name,
        old,
        new,
        observed_at,
    } = message
    else {
        return Ok(None);
    };
    // The observer reports every ref each time it looks, moved or not.
    if old.as_deref() == Some(new.as_str()) {
        return Ok(None);
    }
    let Some(mapping) = mapping_of(mappings, &repo) else {
        return Ok(None);
    };
    let source = SourceRef::Git {
        url: mapping.url.clone(),
        commit_sha: new,
    };
    source.validate().map_err(|e| e.to_string())?;
    let request = BuildRequest {
        build_id: Uuid::new_v4(),
        source,
        pipeline_image: Some(mapping.pipeline_image.clone()),
        requested_at: Utc::now(),
        metadata: HashMap::from([
            ("git_ref".to_string(), ref_name.clone()),
            ("observed_at".to_string(), observed_at),
        ]),
        command: Vec::new(),
    };
    Ok(Some((request, mapping.clone(), ref_name)))
}

fn mapping_of<'a>(mappings: &'a [Mapping], repo: &RepoId) -> Option<&'a Mapping> {
    mappings.iter().find(|m| &m.repo == repo)
}

impl OrchestratorSupervisor {
    /// A backend as the settings in force say: what a build started now is made with.
    fn backend(state: &OrchestratorState) -> Arc<dyn BuildBackend> {
        let options = JobOptions {
            namespace: state.deployment.namespace.clone(),
            template: state.deployment.template.clone(),
            resources: state.tuning.resources.clone(),
            workspace_size_limit: Some(state.tuning.workspace_limit.clone()),
            retention: state.tuning.retention,
        };
        Arc::new(KubernetesBackend::new(state.protocols.clone(), options))
    }

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

    async fn ref_update(
        myself: &ActorRef<OrchestratorMessage>,
        state: &mut OrchestratorState,
        payload: &[u8],
        published_by: Option<String>,
    ) {
        let (request, mapping, ref_name) = match build_for(payload, &state.mappings) {
            Ok(Some(build)) => build,
            Ok(None) => return,
            Err(why) => {
                warn!(publisher = ?published_by, "a ref update is not built: {why}");
                return;
            }
        };
        let SourceRef::Git { url, commit_sha } = &request.source else {
            return;
        };
        // A restarted observer reports each ref from nothing, so a commit already taken arrives again with no `old`.
        if !state.observed.first_sight(url, commit_sha) {
            info!(%ref_name, commit = %commit_sha, "this commit was already taken for a build");
            return;
        }
        let build_id = request.build_id;
        info!(%build_id, repo = %url, commit = %commit_sha, %ref_name, "a ref moved: a build");
        state.starts.insert(
            build_id,
            Start::New {
                mapping,
                ref_name,
                triggered_by: published_by,
                default_command: state.tuning.default_command.clone(),
            },
        );
        if let Err(e) = state
            .registry
            .cast(RegistryMessage::Insert(request.clone()))
        {
            warn!(%build_id, "the registry was not told of a build: {e}");
        }
        match state.admission.request(request) {
            Admitted::Now(request) => Self::start(myself, state, request).await,
            Admitted::Waiting(place) => {
                info!(%build_id, place, "every place is taken; the build waits")
            }
            Admitted::Duplicate => {}
        }
    }

    /// Starts the actor of a build that has a place. A build waiting when the settings changed starts with those in force
    /// when it starts.
    async fn start(
        myself: &ActorRef<OrchestratorMessage>,
        state: &mut OrchestratorState,
        request: BuildRequest,
    ) {
        let build_id = request.build_id;
        let Some(start) = state.starts.remove(&build_id) else {
            error!(%build_id, "a build admitted with no way to begin");
            return;
        };
        let start = match start {
            Start::New {
                mapping,
                ref_name,
                triggered_by,
                ..
            } => Start::New {
                mapping,
                ref_name,
                triggered_by,
                default_command: state.tuning.default_command.clone(),
            },
            adopted => adopted,
        };
        let args = BuildArgs {
            request,
            start,
            backend: Self::backend(state),
            source: Arc::clone(&state.source),
            registry: state.registry.clone(),
            publish: Arc::clone(&state.publish),
            reader: Arc::clone(&state.reader),
            bounds: settings::narrowed(&state.forked_reader, &state.tuning.reader),
            relay: state.tuning.relay,
            max_source: state.tuning.max_source,
            max_dependencies: state.tuning.max_dependencies,
            logs: Arc::clone(&state.logs),
            max_log: state.tuning.max_log,
            poll_every: POLL_EVERY,
        };
        if let Err(e) = Actor::spawn_linked(
            Some(actor_name(build_id)),
            BuildActor,
            args,
            myself.get_cell(),
        )
        .await
        {
            error!(%build_id, "the build's actor did not start: {e}");
            for next in state.admission.finished(build_id) {
                Box::pin(Self::start(myself, state, next)).await;
            }
        }
    }

    /// Adopts the Jobs found running: each watched to its end by an actor of its own.
    async fn adopt(myself: &ActorRef<OrchestratorMessage>, state: &mut OrchestratorState) {
        let found = match Self::backend(state).in_flight().await {
            Ok(found) => found,
            Err(e) => {
                warn!("the Jobs running could not be listed, and none is adopted: {e}");
                return;
            }
        };
        for InFlight {
            build_id,
            source,
            handle,
            made_at,
        } in found
        {
            if !state.admission.adopt(build_id) {
                continue;
            }
            if let SourceRef::Git { url, commit_sha } = &source {
                state.observed.first_sight(url, commit_sha);
            }
            let request = BuildRequest {
                build_id,
                source,
                pipeline_image: None,
                requested_at: Utc::now(),
                metadata: HashMap::new(),
                command: Vec::new(),
            };
            if let Err(e) = state.registry.cast(RegistryMessage::Adopt(request.clone())) {
                warn!(%build_id, "the registry was not told of an adopted build: {e}");
            }
            state
                .starts
                .insert(build_id, Start::Adopted { handle, made_at });
            Self::start(myself, state, request).await;
        }
    }

    /// A build's actor ended, however it did: a commit whose build did not succeed may be built again, and its place goes
    /// to the next waiting.
    async fn ended(
        myself: &ActorRef<OrchestratorMessage>,
        state: &mut OrchestratorState,
        build_id: Uuid,
    ) {
        if let Ok(Some(record)) = ractor::call!(state.registry, RegistryMessage::Get, build_id)
            && record.state != BuildState::Succeeded
            && let SourceRef::Git { url, commit_sha } = &record.request.source
        {
            state.observed.forget(url, commit_sha);
        }
        if state.drain.is_draining() {
            return;
        }
        for next in state.admission.finished(build_id) {
            info!(build_id = %next.build_id, "a place is free; the next build starts");
            Self::start(myself, state, next).await;
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
                move |incoming| {
                    let _ = to.cast(OrchestratorMessage::RefUpdate {
                        payload: incoming.payload,
                        published_by: incoming.published_by,
                    });
                },
            ))
            .with_lifecycle_handler(|event| Some(OrchestratorMessage::ClientEvent { event }))
            .with_drain(|| OrchestratorMessage::PrepareShutdown)
            .into_configured(configured)
            .build()
            .await?;
        let reader = resources
            .workers
            .get(READER)
            .cloned()
            .ok_or_else(|| format!("the {READER} worker was not started"))?;
        let protocols = resources
            .protocols
            .clone()
            .ok_or("the builder gave no protocol handle, which this agent's operations need")?;
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
        myself.cast(OrchestratorMessage::RuntimeChanged {
            section: mappings::SECTION_NAME.to_string(),
        })?;
        myself.cast(OrchestratorMessage::Adopt)?;
        myself.send_interval(SWEEP_EVERY, || OrchestratorMessage::Sweep);
        let (registry, _) = Actor::spawn_linked(
            Some(format!("{AGENT_NAME}.registry")),
            BuildRegistry,
            (),
            myself.get_cell(),
        )
        .await
        .map_err(|e| format!("the registry did not start: {e}"))?;
        info!(
            namespace = %deployment.namespace,
            template = %deployment.template,
            cap = tuning.concurrent_builds,
            "builds run from the template in the namespace"
        );

        let source: Arc<dyn Source> = Arc::new(GitSource::new(
            protocols.clone(),
            deployment.clones.clone(),
            deployment.registry.clone(),
        ));
        let logs: Arc<dyn KeepLog> = Arc::new(RegistryLogs::new(protocols.clone()));
        Ok(OrchestratorState {
            healthcheck: resources.healthcheck,
            infrastructure: resources.infrastructure,
            configuration: resources.configuration,
            drain: Drain::default(),
            deployment,
            admission: Admission::new(tuning.concurrent_builds),
            tuning,
            forked_reader,
            mappings: Vec::new(),
            protocols,
            publish: Arc::new(resources.tcp_client),
            reader: Arc::new(reader),
            source,
            logs,
            registry,
            observed: Observed::new(OBSERVED_COMMITS),
            starts: HashMap::new(),
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
            OrchestratorMessage::RefUpdate {
                payload,
                published_by,
            } => {
                if state.drain.is_draining() {
                    warn!("draining: a ref update is not built");
                    return Ok(());
                }
                Self::ref_update(&myself, state, &payload, published_by).await;
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
                let released = state.admission.set_cap(tuning.concurrent_builds);
                state.tuning = tuning;
                for next in released {
                    Self::start(&myself, state, next).await;
                }
            }
            OrchestratorMessage::RuntimeChanged { section } => {
                if section == mappings::SECTION_NAME {
                    Self::read_mappings(state).await;
                }
            }
            OrchestratorMessage::Adopt => Self::adopt(&myself, state).await,
            OrchestratorMessage::Sweep => {
                if state.drain.is_draining() {
                    return Ok(());
                }
                // Off the mailbox: listing and deleting are the cluster's to answer.
                let backend = Self::backend(state);
                let retention = state.tuning.retention;
                tokio::spawn(async move {
                    match backend.reap(&retention).await {
                        Ok(removed) if removed.is_empty() => {}
                        Ok(removed) => info!(
                            removed = removed.len(),
                            "Jobs past their retention were removed"
                        ),
                        Err(e) => warn!("the Jobs past their retention could not be removed: {e}"),
                    }
                });
            }
            OrchestratorMessage::PrepareShutdown => {
                if state.drain.begin(
                    &myself,
                    Duration::from_secs(DRAIN_WINDOW_SECS),
                    true,
                    || OrchestratorMessage::DrainElapsed,
                ) {
                    info!(
                        running = state.admission.running(),
                        waiting = state.admission.waiting(),
                        "PrepareShutdown received; the running builds' Jobs go on, for the next orchestrator to adopt, \
                         and the waiting are given up"
                    );
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
                if let Some(build_id) = actor.get_name().as_deref().and_then(build_of) {
                    debug!(%build_id, ?reason, "a build's actor ended");
                    Self::ended(&myself, state, build_id).await;
                    return Ok(());
                }
                info!("{actor:?} terminated: {reason:?}");
                if actor.get_id() == state.registry.get_id() {
                    Self::essential_lost(&myself, state);
                }
            }
            SupervisionEvent::ActorFailed(actor, reason) => {
                if let Some(build_id) = actor.get_name().as_deref().and_then(build_of) {
                    // A build's actor fails only on a fault of its own; its record keeps its last state.
                    error!(%build_id, "a build's actor failed: {reason:?}");
                    Self::ended(&myself, state, build_id).await;
                    return Ok(());
                }
                error!("{actor:?} failed: {reason:?}");
                Self::essential_lost(&myself, state);
            }
            _ => {}
        }
        Ok(())
    }
}

impl OrchestratorSupervisor {
    /// The registry, or a child of the builder's, is gone: the orchestrator cannot do its work, and ends.
    fn essential_lost(myself: &ActorRef<OrchestratorMessage>, state: &mut OrchestratorState) {
        if !state.drain.begin(
            myself,
            Duration::from_secs(DRAIN_WINDOW_SECS),
            false,
            || OrchestratorMessage::DrainElapsed,
        ) {
            warn!("already draining");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchestrator_core::types::Privileges;

    const URL: &str = "https://git.example.org/a/b.git";

    fn mapped() -> Vec<Mapping> {
        vec![Mapping {
            url: URL.into(),
            repo: RepoId::from_url(URL),
            pipeline_image: format!("registry.polar/ci@sha256:{}", "c".repeat(64)),
            command: None,
            privileges: Privileges::default(),
            credential: None,
            locks: vec![],
        }]
    }

    fn moved(url: &str, old: Option<&str>, new: &str) -> Vec<u8> {
        rkyv::to_bytes::<rkyv::rancor::Error>(&GitRepositoryMessage::RefUpdated {
            repo: RepoId::from_url(url),
            ref_name: "refs/heads/main".into(),
            old: old.map(str::to_string),
            new: new.into(),
            observed_at: "2026-11-08T00:00:00Z".into(),
        })
        .unwrap()
        .to_vec()
    }

    #[test]
    fn a_moved_ref_of_a_mapped_repository_is_a_build_of_its_mapping() {
        let new = "b".repeat(40);
        let (request, mapping, ref_name) =
            build_for(&moved(URL, Some(&"a".repeat(40)), &new), &mapped())
                .unwrap()
                .unwrap();
        assert_eq!(
            request.source,
            SourceRef::Git {
                url: URL.into(),
                commit_sha: new
            }
        );
        assert_eq!(
            request.pipeline_image,
            Some(mapped()[0].pipeline_image.clone())
        );
        assert_eq!(mapping, mapped()[0]);
        assert_eq!(ref_name, "refs/heads/main");
        assert_eq!(request.metadata["git_ref"], "refs/heads/main");
        // A ref seen for the first time, as a restarted observer reports it, is a build too.
        assert!(
            build_for(&moved(URL, None, &"b".repeat(40)), &mapped())
                .unwrap()
                .is_some()
        );
    }

    /// A repository as the controller tells the observer of it, and so as the observer reports it, is the one a mapping
    /// for the same URL names, `.git` and all (found live 2026-11-08: the gitea's `…/SEI/ACE.git` was never built, the
    /// mapping keyed on its URL as written and the observer reporting its normalised id).
    #[test]
    fn an_update_as_the_observer_reports_it_is_a_build_of_the_mapping_for_that_url() {
        let url = "ssh://52.235.181.217/SEI/ACE.git";
        let mappings = crate::mappings::parse(&serde_json::json!({"repositories": [
            {"url": url, "credential": "gitea",
             "pipeline_image": format!("registry.polar/ci@sha256:{}", "c".repeat(64))}
        ]}))
        .unwrap();
        let reported = rkyv::to_bytes::<rkyv::rancor::Error>(&GitRepositoryMessage::RefUpdated {
            repo: git_agent_common::remote::repo_id_of(url),
            ref_name: "refs/heads/main".into(),
            old: None,
            new: "b".repeat(40),
            observed_at: "2026-11-08T00:00:00Z".into(),
        })
        .unwrap()
        .to_vec();
        let (request, mapping, _) = build_for(&reported, &mappings).unwrap().expect("a build");
        assert_eq!(mapping.url, url);
        assert_eq!(request.source.locator(), url);
    }

    #[test]
    fn what_is_no_build_is_none_and_what_cannot_be_read_says_why() {
        let a = "a".repeat(40);
        assert!(
            build_for(&moved(URL, Some(&a), &a), &mapped())
                .unwrap()
                .is_none(),
            "not moved"
        );
        assert!(
            build_for(&moved("https://other.example/x.git", None, &a), &mapped())
                .unwrap()
                .is_none(),
            "not mapped"
        );
        assert!(
            build_for(&moved(URL, None, &a), &[]).unwrap().is_none(),
            "nothing mapped"
        );
        let discovered =
            rkyv::to_bytes::<rkyv::rancor::Error>(&GitRepositoryMessage::CommitDiscovered {
                repo: RepoId::from_url(URL),
                ref_name: "refs/heads/main".into(),
                oid: a.clone(),
                committer: "c".into(),
                time: 0,
                message: "m".into(),
                parents: vec![],
                observed_at: "t".into(),
            })
            .unwrap();
        assert!(
            build_for(&discovered, &mapped()).unwrap().is_none(),
            "a commit, not a ref"
        );
        assert!(
            build_for(&moved(URL, None, "main"), &mapped())
                .unwrap_err()
                .contains("commit")
        );
        assert!(build_for(b"not rkyv", &mapped()).is_err());
    }
}
