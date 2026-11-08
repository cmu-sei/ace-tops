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
//! Once its Job ends, however it ended, it reads the Job's log, once (docs/architecture/build-orchestrator.md, "How a
//! report is read"): each report line, at the reader's bounds as they were when the build started, through the locked-down
//! worker and back (`Report::read_answer`), judged and stamped by the relay, and published in its `BuildReport` envelope
//! on `polar.provenance.events`. What the relay or the reader refuses is counted and logged. A read that kills the worker
//! fails the build at the stage of reading its reports, and the agent ends: the crash is evidence (O2e2).
//!
//! What it publishes of itself: `ExecutionStarted` once its Job is made, then `ExecutionCompleted` or `ExecutionFailed`
//! with the stage it failed at, after its reports. A publish that fails is logged and the build goes on: its outcome is in
//! the registry already.

use crate::lines::{Line, Lines};
use crate::mappings::Mapping;
use crate::publish::Publish;
use crate::reader::{Read, request};
use crate::registry::RegistryMessage;
use crate::source::Source;
use chrono::{DateTime, Utc};
use orchestrator_core::backend::{BackendJobHandle, BuildBackend, JobStatus};
use orchestrator_core::relay::{Relay, RelayBounds};
use orchestrator_core::types::{BuildRequest, BuildSpec, BuildState, SourceRef};
use orchestrator_report::{Bounds, Report};
use polar::topics::{PROVENANCE_EVENTS, PROVENANCE_EXECUTIONS};
use polar::{BackendIdentity, ProvenanceEvent};
use ractor::{Actor, ActorProcessingErr, ActorRef};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// The stages a build fails at, as `ExecutionFailed` names them.
pub const AT_SOURCE: &str = "source";
pub const AT_SCHEDULING: &str = "scheduling";
pub const AT_EXECUTION: &str = "execution";
pub const AT_REPORTS: &str = "reports";

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
    pub reader: Arc<dyn Read>,
    /// The reader's bounds for this build: the narrower of the worker's and those signed when it started.
    pub bounds: Bounds,
    pub relay: RelayBounds,
    pub poll_every: Duration,
}

/// What came of reading a build's reports.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReportsRead {
    pub relayed: usize,
    pub refused: usize,
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
    reader: Arc<dyn Read>,
    bounds: Bounds,
    relay: RelayBounds,
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
        let sent = match rkyv::to_bytes::<rkyv::rancor::Error>(&event) {
            Ok(payload) => {
                state
                    .publish
                    .publish(PROVENANCE_EXECUTIONS, payload.to_vec())
                    .await
            }
            Err(e) => Err(e.to_string()),
        };
        if let Err(e) = sent {
            error!(build_id = %state.request.build_id, "an execution event was not published: {e}");
        }
    }

    /// Reads the ended Job's log for its reports, relaying each the reader and the relay take. `Err` is the reader's death,
    /// with why; a log that cannot be had, or that ends in an error, leaves what was read relayed and the rest unread.
    async fn read_reports(state: &BuildActorState) -> Result<ReportsRead, String> {
        let build_id = state.request.build_id;
        let Some(handle) = &state.handle else {
            return Ok(ReportsRead::default());
        };
        let mut log = match state.backend.log(handle).await {
            Ok(log) => log,
            Err(e) => {
                warn!(%build_id, "the build's log could not be had, and its reports are not read: {e}");
                return Ok(ReportsRead::default());
            }
        };
        let mut lines = Lines::new(state.bounds.line);
        let mut relay = Relay::new(build_id.to_string(), state.relay);
        let mut relayed = 0;
        while let Some(piece) = log.next().await {
            let piece = match piece {
                Ok(piece) => piece,
                Err(e) => {
                    warn!(%build_id, "the build's log ended in an error; what came after is not read: {e}");
                    break;
                }
            };
            for line in lines.feed(&piece) {
                relayed += Self::report(state, &mut relay, line).await?;
            }
        }
        if let Some(line) = lines.finish() {
            relayed += Self::report(state, &mut relay, line).await?;
        }
        let read = ReportsRead {
            relayed,
            refused: relay.refused(),
        };
        if read.refused > 0 {
            warn!(%build_id, relayed = read.relayed, refused = read.refused, "the build said something refused");
        } else {
            info!(%build_id, relayed = read.relayed, "the build's reports are relayed");
        }
        Ok(read)
    }

    /// One report line: counted against the build's bounds, read by the worker, judged and stamped, and published; 1 if it
    /// was relayed. `Err` is the worker's death.
    async fn report(
        state: &BuildActorState,
        relay: &mut Relay,
        line: Line,
    ) -> Result<usize, String> {
        let build_id = state.request.build_id;
        let len = match &line {
            Line::Report(bytes) => bytes.len(),
            Line::TooLong(len) => *len,
        };
        if let Err(why) = relay.take(len) {
            debug!(%build_id, "a report not read: {why}");
            return Ok(0);
        }
        let Line::Report(bytes) = line else {
            relay.refuse();
            debug!(%build_id, len, "a report longer than its bound, refused unread");
            return Ok(0);
        };
        let answer = state
            .reader
            .read(request(&state.bounds, &bytes))
            .await
            .map_err(|e| format!("the reader died reading the build's report: {e}"))?;
        let report = match Report::read_answer(&bytes, &answer, &state.bounds) {
            Ok(report) => report,
            Err(why) => {
                relay.refuse();
                debug!(%build_id, "a report refused: {why}");
                return Ok(0);
            }
        };
        let envelope = match relay.relay(report) {
            Ok(envelope) => envelope,
            Err(why) => {
                debug!(%build_id, "a report refused: {why}");
                return Ok(0);
            }
        };
        let sent = match rkyv::to_bytes::<rkyv::rancor::Error>(&envelope) {
            Ok(payload) => {
                state
                    .publish
                    .publish(PROVENANCE_EVENTS, payload.to_vec())
                    .await
            }
            Err(e) => Err(e.to_string()),
        };
        match sent {
            Ok(()) => Ok(1),
            Err(e) => {
                error!(%build_id, "a report was not published: {e}");
                Ok(0)
            }
        }
    }

    /// The Job ended: its reports read, then how it ended said. The reader dying fails the build at its reports.
    async fn ended(
        myself: &ActorRef<BuildMessage>,
        state: &mut BuildActorState,
        status: JobStatus,
    ) {
        if let Err(why) = Self::read_reports(state).await {
            error!(build_id = %state.request.build_id, "{why}");
            Self::runs(state);
            return Self::fail(myself, state, AT_REPORTS, why).await;
        }
        match status {
            JobStatus::Failed { reason } => {
                let reason =
                    reason.unwrap_or_else(|| "the Job failed and the API said no more".into());
                Self::fail(myself, state, AT_EXECUTION, reason).await;
            }
            _ => {
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
            status @ (JobStatus::Succeeded | JobStatus::Failed { .. }) => {
                Self::ended(myself, state, status).await;
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
            reader: args.reader,
            bounds: args.bounds,
            relay: args.relay,
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
