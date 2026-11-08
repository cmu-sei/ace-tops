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

//! A build's actor (Vaughn's `BuildJobActor`, in shape): it takes one build from its source to its Job's end and says
//! what it saw, in its own word, on `polar.provenance.executions` (docs/architecture/build-orchestrator.md, "Settled with
//! it", two topics).
//!
//! A new build: its source prepared (`Source`), its Job made from the template on the mapping's image, command and
//! privileges, then polled to its end. A build adopted at start: its Job polled to its end. Everything it acts on is fixed
//! when it starts (the mapping, the settings, through the backend it was given), so a build runs as the configuration said
//! when it began.
//!
//! What it publishes: `ExecutionStarted` once its Job is made, then `ExecutionCompleted` or `ExecutionFailed` with the
//! stage it failed at. A publish that fails is logged and the build goes on: its outcome is in the registry already.

use crate::mappings::Mapping;
use crate::publish::Publish;
use crate::registry::RegistryMessage;
use crate::source::Source;
use chrono::{DateTime, Utc};
use orchestrator_core::backend::{BackendJobHandle, BuildBackend, JobStatus};
use orchestrator_core::types::{BuildRequest, BuildSpec, BuildState, SourceRef};
use polar::topics::PROVENANCE_EXECUTIONS;
use polar::{BackendIdentity, ProvenanceEvent};
use ractor::{Actor, ActorProcessingErr, ActorRef};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

/// The stages a build fails at, as `ExecutionFailed` names them.
pub const AT_SOURCE: &str = "source";
pub const AT_SCHEDULING: &str = "scheduling";
pub const AT_EXECUTION: &str = "execution";

/// How a build begins.
pub enum Start {
    /// Admitted: its source to prepare and its Job to make, as its mapping says.
    New {
        mapping: Mapping,
        ref_name: String,
        /// Who reported the ref moved, as the broker stamped it.
        triggered_by: Option<String>,
        /// The command when the mapping names none.
        default_command: Vec<String>,
    },
    /// Found running at start: its Job, and when it was made (seconds since the epoch), if the API said.
    Adopted {
        handle: BackendJobHandle,
        made_at: Option<i64>,
    },
}

pub struct BuildArgs {
    pub request: BuildRequest,
    pub start: Start,
    pub backend: Arc<dyn BuildBackend>,
    pub source: Arc<dyn Source>,
    pub registry: ActorRef<RegistryMessage>,
    pub publish: Arc<dyn Publish>,
    pub poll_every: Duration,
}

pub enum BuildMessage {
    Begin,
    Poll,
}

pub struct BuildActorState {
    request: BuildRequest,
    start: Option<Start>,
    backend: Arc<dyn BuildBackend>,
    source: Arc<dyn Source>,
    registry: ActorRef<RegistryMessage>,
    publish: Arc<dyn Publish>,
    poll_every: Duration,
    handle: Option<BackendJobHandle>,
    began: DateTime<Utc>,
    /// Whether the registry has been told it runs.
    running: bool,
}

pub struct BuildActor;

/// An actor's name for a build: what the supervisor knows it by when it ends.
pub fn actor_name(build_id: uuid::Uuid) -> String {
    format!("build-{build_id}")
}

/// The build a name is the actor of, if it is one.
pub fn build_of(name: &str) -> Option<uuid::Uuid> {
    name.strip_prefix("build-")?.parse().ok()
}

fn now() -> String {
    Utc::now().to_rfc3339()
}

impl BuildActor {
    fn transition(
        state: &BuildActorState,
        next_state: BuildState,
        backend_handle: Option<String>,
        resolved_image: Option<String>,
        failure_reason: Option<String>,
    ) {
        if let Err(e) = state.registry.cast(RegistryMessage::Transition {
            build_id: state.request.build_id,
            next_state,
            backend_handle,
            resolved_image,
            failure_reason,
        }) {
            warn!(build_id = %state.request.build_id, "the registry was not told of a transition: {e}");
        }
    }

    async fn say(state: &BuildActorState, event: ProvenanceEvent) {
        if let Err(e) = state.publish.publish(PROVENANCE_EXECUTIONS, &event).await {
            error!(build_id = %state.request.build_id, "an execution event was not published: {e}");
        }
    }

    /// The build failed at `stage`: recorded, said, and the actor ends.
    async fn fail(
        myself: &ActorRef<BuildMessage>,
        state: &BuildActorState,
        stage: &str,
        reason: String,
    ) {
        warn!(build_id = %state.request.build_id, %stage, %reason, "the build failed");
        Self::transition(state, BuildState::Failed, None, None, Some(reason.clone()));
        Self::say(
            state,
            ProvenanceEvent::ExecutionFailed {
                build_id: state.request.build_id.to_string(),
                reason,
                stage: Some(stage.to_string()),
                at: now(),
            },
        )
        .await;
        myself.stop(Some(format!("failed at {stage}")));
    }

    async fn begin(myself: &ActorRef<BuildMessage>, state: &mut BuildActorState) {
        match state.start.take() {
            Some(Start::Adopted { handle, made_at }) => {
                if let Some(made) = made_at.and_then(|at| DateTime::from_timestamp(at, 0)) {
                    state.began = made;
                }
                info!(build_id = %state.request.build_id, job = %handle.name, "watching an adopted build to its end");
                state.handle = Some(handle);
                myself.send_after(state.poll_every, || BuildMessage::Poll);
            }
            Some(Start::New {
                mapping,
                ref_name,
                triggered_by,
                default_command,
            }) => {
                Self::transition(state, BuildState::PreparingSource, None, None, None);
                let archive = match state.source.prepare(&state.request.source).await {
                    Ok(archive) => archive,
                    Err(why) => return Self::fail(myself, state, AT_SOURCE, why).await,
                };
                let command = mapping.command.clone().unwrap_or(default_command);
                let spec = BuildSpec::with_pipeline_runner(
                    state.request.build_id,
                    state.request.source.clone(),
                    archive,
                    mapping.pipeline_image.clone(),
                    command,
                    mapping.privileges.clone(),
                );
                let job = match state.backend.submit(&spec).await {
                    Ok(job) => job,
                    Err(e) => return Self::fail(myself, state, AT_SCHEDULING, e.to_string()).await,
                };
                info!(build_id = %state.request.build_id, job = %job.handle.name, "the build's Job is made");
                Self::transition(
                    state,
                    BuildState::Scheduled,
                    Some(job.handle.name.clone()),
                    Some(mapping.pipeline_image.clone()),
                    None,
                );
                let (repo_url, commit_sha) = match &state.request.source {
                    SourceRef::Git { url, commit_sha } => (url.clone(), commit_sha.clone()),
                    SourceRef::RegistryArchive { download_url, .. } => {
                        (download_url.clone(), String::new())
                    }
                };
                Self::say(
                    state,
                    ProvenanceEvent::ExecutionStarted {
                        build_id: state.request.build_id.to_string(),
                        commit_sha,
                        ref_name,
                        repo_url,
                        triggered_by,
                        backend: Some(BackendIdentity {
                            node_label: job.graph_identity.node_label.clone(),
                            identity_props: job.graph_identity.identity_props.clone(),
                        }),
                        at: now(),
                    },
                )
                .await;
                state.handle = Some(job.handle);
                myself.send_after(state.poll_every, || BuildMessage::Poll);
            }
            None => warn!(build_id = %state.request.build_id, "begun twice; the second is ignored"),
        }
    }

    async fn poll(myself: &ActorRef<BuildMessage>, state: &mut BuildActorState) {
        let Some(handle) = state.handle.clone() else {
            error!(build_id = %state.request.build_id, "polled with no Job");
            return;
        };
        let status = match state.backend.poll(&handle).await {
            Ok(status) => status,
            Err(e) => {
                warn!(build_id = %state.request.build_id, "the Job could not be polled, and is again later: {e}");
                myself.send_after(state.poll_every, || BuildMessage::Poll);
                return;
            }
        };
        match status {
            JobStatus::Pending => {
                myself.send_after(state.poll_every, || BuildMessage::Poll);
            }
            JobStatus::Running => {
                Self::runs(state);
                myself.send_after(state.poll_every, || BuildMessage::Poll);
            }
            JobStatus::Succeeded => {
                // A build quicker than a poll is never seen running: it ran.
                Self::runs(state);
                Self::transition(state, BuildState::Succeeded, None, None, None);
                let duration_secs =
                    u64::try_from((Utc::now() - state.began).num_seconds()).unwrap_or(0);
                info!(build_id = %state.request.build_id, duration_secs, "the build succeeded");
                Self::say(
                    state,
                    ProvenanceEvent::ExecutionCompleted {
                        build_id: state.request.build_id.to_string(),
                        duration_secs,
                        at: now(),
                    },
                )
                .await;
                myself.stop(Some("succeeded".into()));
            }
            JobStatus::Failed { reason } => {
                let reason =
                    reason.unwrap_or_else(|| "the Job failed and the API said no more".into());
                Self::fail(myself, state, AT_EXECUTION, reason).await;
            }
            JobStatus::Unknown => {
                Self::fail(
                    myself,
                    state,
                    AT_EXECUTION,
                    "the build's Job is gone".into(),
                )
                .await;
            }
        }
    }

    fn runs(state: &mut BuildActorState) {
        if !state.running {
            Self::transition(state, BuildState::Running, None, None, None);
            state.running = true;
        }
    }
}

#[ractor::async_trait]
impl Actor for BuildActor {
    type Msg = BuildMessage;
    type State = BuildActorState;
    type Arguments = BuildArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: BuildArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        myself.cast(BuildMessage::Begin)?;
        Ok(BuildActorState {
            request: args.request,
            start: Some(args.start),
            backend: args.backend,
            source: args.source,
            registry: args.registry,
            publish: args.publish,
            poll_every: args.poll_every,
            handle: None,
            began: Utc::now(),
            running: false,
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            BuildMessage::Begin => Self::begin(&myself, state).await,
            BuildMessage::Poll => Self::poll(&myself, state).await,
        }
        Ok(())
    }
}
