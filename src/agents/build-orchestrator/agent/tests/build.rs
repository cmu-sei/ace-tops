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

//! A build's actor, against a stand-in backend, source, reader and broker: what it makes, what it records, what it
//! relays of its log, and what it says, at each way a build can go. The stand-in reader is the agent's own reader's work,
//! run in process: the same answer the worker gives, without the fork.

use build_orchestrator::build::{
    AT_EXECUTION, AT_REPORTS, AT_SCHEDULING, AT_SOURCE, BuildActor, BuildArgs, Start,
};
use build_orchestrator::mappings::Mapping;
use build_orchestrator::publish::Publish;
use build_orchestrator::reader::{Read, Reader};
use build_orchestrator::registry::{BuildRegistry, RegistryMessage};
use build_orchestrator::source::Source;
use orchestrator_core::backend::{
    BackendJobHandle, BuildBackend, JobGraphIdentity, JobStatus, LogPieces, SubmittedJob,
};
use orchestrator_core::error::BackendError;
use orchestrator_core::relay::RelayBounds;
use orchestrator_core::types::{
    BuildRequest, BuildSpec, BuildState, Privileges, SourceArchive, SourceRef,
};
use orchestrator_report::Bounds;
use polar::ProvenanceEvent;
use polar::events::BuildReport;
use polar::graph::nodes::git::RepoId;
use polar::topics::{PROVENANCE_EVENTS, PROVENANCE_EXECUTIONS};
use polar_agent_builder::worker::{Work, WorkerError};
use ractor::{Actor, ActorRef};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const URL: &str = "https://git.example.org/a/b.git";

/// A backend that makes the Job it is told to, or refuses, answers each poll from a script, and gives the Job's log in
/// the pieces it is told to, or none.
#[derive(Default)]
struct Backend {
    refuse: bool,
    polls: Mutex<VecDeque<Result<JobStatus, BackendError>>>,
    submitted: Mutex<Vec<BuildSpec>>,
    log: Option<Vec<Result<Vec<u8>, String>>>,
}

struct Pieces(VecDeque<Result<Vec<u8>, String>>);

#[async_trait::async_trait]
impl LogPieces for Pieces {
    async fn next(&mut self) -> Option<Result<Vec<u8>, String>> {
        self.0.pop_front()
    }
}

#[async_trait::async_trait]
impl BuildBackend for Backend {
    async fn submit(&self, spec: &BuildSpec) -> Result<SubmittedJob, BackendError> {
        if self.refuse {
            return Err(BackendError::SubmissionFailed(
                "the stand-in refuses".into(),
            ));
        }
        self.submitted.lock().unwrap().push(spec.clone());
        Ok(SubmittedJob {
            handle: BackendJobHandle {
                name: "build-runner-x".into(),
                uid: "u-x".into(),
            },
            graph_identity: JobGraphIdentity {
                node_label: "KubernetesJob".into(),
                identity_props: vec![("uid".into(), "u-x".into())],
                display_name: "build-runner-x".into(),
            },
        })
    }
    async fn poll(&self, _: &BackendJobHandle) -> Result<JobStatus, BackendError> {
        self.polls
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(JobStatus::Running))
    }
    async fn cancel(&self, _: &BackendJobHandle) -> Result<(), BackendError> {
        Ok(())
    }
    async fn log(&self, _: &BackendJobHandle) -> Result<Box<dyn LogPieces>, BackendError> {
        match &self.log {
            Some(pieces) => Ok(Box::new(Pieces(pieces.clone().into()))),
            None => Err(BackendError::Unreachable("no log in the stand-in".into())),
        }
    }
    fn name(&self) -> &'static str {
        "stand-in"
    }
}

/// A source step that gives an archive or refuses, and keeps the credential and bound it was asked with.
struct Archive(Result<(), String>, Mutex<Vec<(Option<String>, usize)>>);

#[ractor::async_trait]
impl Source for Archive {
    async fn prepare(
        &self,
        _: &SourceRef,
        credential: Option<&str>,
        bound: usize,
    ) -> Result<SourceArchive, String> {
        self.1
            .lock()
            .unwrap()
            .push((credential.map(str::to_string), bound));
        self.0.clone()?;
        Ok(SourceArchive::new(format!("registry.polar/build-sources@sha256:{HEX}")).unwrap())
    }
}

/// The bound a build's source is held to in these tests.
const MAX_SOURCE: usize = 1234;

/// What was published, read back as its topic's subscriber reads it.
#[derive(Default)]
struct Said(Mutex<Vec<(String, Vec<u8>)>>);

#[ractor::async_trait]
impl Publish for Said {
    async fn publish(&self, topic: &str, payload: Vec<u8>) -> Result<(), String> {
        self.0.lock().unwrap().push((topic.to_string(), payload));
        Ok(())
    }
}

/// The reader's work in process, counting what it is asked; or a reader that dies.
struct InProcess {
    reader: Option<Mutex<Reader>>,
    asked: Mutex<usize>,
}

#[ractor::async_trait]
impl Read for InProcess {
    async fn read(&self, request: Vec<u8>) -> Result<Vec<u8>, WorkerError> {
        *self.asked.lock().unwrap() += 1;
        let Some(reader) = &self.reader else {
            return Err(WorkerError::Died("killed by SIGSYS".into()));
        };
        let mut reader = reader.lock().unwrap();
        assert!(request.len() <= reader.max_request());
        let mut out = vec![0u8; reader.max_answer()];
        let n = reader.answer(&request, &mut out);
        out.truncate(n);
        Ok(out)
    }
}

const FORKED: Bounds = Bounds {
    line: 64 * 1024,
    string: 4096,
    depth: 6,
    tokens: 4096,
    items: 1024,
};

fn reader() -> InProcess {
    InProcess {
        reader: Some(Mutex::new(Reader::new(FORKED))),
        asked: Mutex::new(0),
    }
}

fn mapping(command: Option<Vec<String>>) -> Mapping {
    mapping_with(command, None)
}

fn mapping_with(command: Option<Vec<String>>, credential: Option<&str>) -> Mapping {
    Mapping {
        url: URL.into(),
        repo: RepoId::from_url(URL),
        pipeline_image: format!("registry.polar/pipelines/ci@sha256:{HEX}"),
        command,
        privileges: Privileges {
            run_as_root: true,
            allow_privilege_escalation: false,
            add_capabilities: vec!["SETUID".into()],
        },
        credential: credential.map(str::to_string),
    }
}

fn request() -> BuildRequest {
    BuildRequest {
        build_id: Uuid::new_v4(),
        source: SourceRef::Git {
            url: URL.into(),
            commit_sha: "a".repeat(40),
        },
        pipeline_image: None,
        requested_at: chrono::Utc::now(),
        metadata: Default::default(),
        command: vec![],
    }
}

fn new_build(command: Option<Vec<String>>) -> Start {
    Start::New {
        mapping: mapping(command),
        ref_name: "refs/heads/main".into(),
        triggered_by: Some("git-repo-observer".into()),
        default_command: vec!["/bin/default".into()],
    }
}

struct Ran {
    id: Uuid,
    state: BuildState,
    failure: Option<String>,
    /// What it said of itself, in order.
    said: Vec<(String, ProvenanceEvent)>,
    /// What it relayed, in order.
    relayed: Vec<BuildReport>,
    /// Whether every report was published before the build's end was said.
    reports_first: bool,
    submitted: Vec<BuildSpec>,
    asked: usize,
    /// The credential and bound the source step was asked with, each time.
    prepared: Vec<(Option<String>, usize)>,
}

async fn run(start: Start, backend: Backend, source: Result<(), String>, adopted: bool) -> Ran {
    run_with(
        start,
        backend,
        source,
        adopted,
        reader(),
        FORKED,
        RelayBounds::default(),
    )
    .await
}

/// Runs a build to its actor's end and says what came of it.
async fn run_with(
    start: Start,
    backend: Backend,
    source: Result<(), String>,
    adopted: bool,
    reader: InProcess,
    bounds: Bounds,
    relay: RelayBounds,
) -> Ran {
    let (registry, _) = Actor::spawn(None, BuildRegistry, ()).await.unwrap();
    let request = request();
    let id = request.build_id;
    registry
        .cast(if adopted {
            RegistryMessage::Adopt(request.clone())
        } else {
            RegistryMessage::Insert(request.clone())
        })
        .unwrap();
    let backend = Arc::new(backend);
    let said = Arc::new(Said::default());
    let reader = Arc::new(reader);
    let source_step = Arc::new(Archive(source, Mutex::new(Vec::new())));
    let (_, ended) = Actor::spawn(
        None,
        BuildActor,
        BuildArgs {
            request,
            start,
            backend: backend.clone(),
            source: source_step.clone(),
            registry: registry.clone(),
            publish: said.clone(),
            reader: reader.clone(),
            bounds,
            relay,
            max_source: MAX_SOURCE,
            poll_every: Duration::from_millis(5),
        },
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(10), ended)
        .await
        .expect("the build's actor ends")
        .unwrap();
    let record = get(&registry, id).await;
    registry.stop(None);
    let published = std::mem::take(&mut *said.0.lock().unwrap());
    let last_report = published.iter().rposition(|(t, _)| t == PROVENANCE_EVENTS);
    let first_end = published.iter().position(|(t, p)| {
        t == PROVENANCE_EXECUTIONS
            && !matches!(
                rkyv::from_bytes::<ProvenanceEvent, rkyv::rancor::Error>(p),
                Ok(ProvenanceEvent::ExecutionStarted { .. })
            )
    });
    let mut said = Vec::new();
    let mut relayed = Vec::new();
    for (topic, payload) in published {
        if topic == PROVENANCE_EVENTS {
            relayed.push(rkyv::from_bytes::<BuildReport, rkyv::rancor::Error>(&payload).unwrap());
        } else {
            said.push((
                topic,
                rkyv::from_bytes::<ProvenanceEvent, rkyv::rancor::Error>(&payload).unwrap(),
            ));
        }
    }
    let submitted = backend.submitted.lock().unwrap().clone();
    let asked = *reader.asked.lock().unwrap();
    let prepared = std::mem::take(&mut *source_step.1.lock().unwrap());
    Ran {
        id,
        state: record.state,
        failure: record.failure_reason,
        said,
        relayed,
        reports_first: match (last_report, first_end) {
            (Some(r), Some(e)) => r < e,
            _ => true,
        },
        submitted,
        asked,
        prepared,
    }
}

async fn get(
    registry: &ActorRef<RegistryMessage>,
    id: Uuid,
) -> orchestrator_core::types::BuildRecord {
    ractor::call!(registry, RegistryMessage::Get, id)
        .unwrap()
        .unwrap()
}

fn scripted(polls: Vec<Result<JobStatus, BackendError>>) -> Backend {
    Backend {
        polls: Mutex::new(polls.into()),
        ..Backend::default()
    }
}

fn failed_at(said: &[(String, ProvenanceEvent)]) -> Option<(String, String)> {
    said.iter().find_map(|(_, e)| match e {
        ProvenanceEvent::ExecutionFailed { stage, reason, .. } => {
            Some((stage.clone().unwrap_or_default(), reason.clone()))
        }
        _ => None,
    })
}

#[tokio::test]
async fn a_build_that_succeeds_says_it_started_and_completed_on_its_own_topic() {
    let ran = run(
        new_build(Some(vec!["/bin/ci".into()])),
        scripted(vec![
            Ok(JobStatus::Pending),
            Ok(JobStatus::Running),
            Ok(JobStatus::Succeeded),
        ]),
        Ok(()),
        false,
    )
    .await;
    assert_eq!(ran.state, BuildState::Succeeded);
    assert!(
        ran.said
            .iter()
            .all(|(topic, _)| topic == PROVENANCE_EXECUTIONS)
    );
    let kinds: Vec<&str> = ran
        .said
        .iter()
        .map(|(_, e)| match e {
            ProvenanceEvent::ExecutionStarted { .. } => "started",
            ProvenanceEvent::ExecutionCompleted { .. } => "completed",
            _ => "other",
        })
        .collect();
    assert_eq!(kinds, ["started", "completed"]);
    let ProvenanceEvent::ExecutionStarted {
        repo_url,
        commit_sha,
        ref_name,
        triggered_by,
        backend,
        ..
    } = &ran.said[0].1
    else {
        unreachable!()
    };
    assert_eq!(
        (repo_url.as_str(), commit_sha.as_str(), ref_name.as_str()),
        (URL, "a".repeat(40).as_str(), "refs/heads/main")
    );
    assert_eq!(triggered_by.as_deref(), Some("git-repo-observer"));
    assert_eq!(backend.as_ref().unwrap().node_label, "KubernetesJob");
    // What ran is the mapping's, and nothing else's.
    let spec = &ran.submitted[0];
    assert_eq!(spec.pipeline_image, mapping(None).pipeline_image);
    assert_eq!(spec.privileges, mapping(None).privileges);
    assert_eq!(spec.entrypoint, Some(vec!["/bin/ci".to_string()]));
}

#[tokio::test]
async fn a_mapping_that_names_no_command_runs_the_default() {
    let ran = run(
        new_build(None),
        scripted(vec![Ok(JobStatus::Succeeded)]),
        Ok(()),
        false,
    )
    .await;
    assert_eq!(
        ran.submitted[0].entrypoint,
        Some(vec!["/bin/default".to_string()])
    );
}

#[tokio::test]
async fn a_build_quicker_than_a_poll_ran_all_the_same() {
    let ran = run(
        new_build(None),
        scripted(vec![Ok(JobStatus::Succeeded)]),
        Ok(()),
        false,
    )
    .await;
    assert_eq!(ran.state, BuildState::Succeeded);
}

#[tokio::test]
async fn a_build_whose_source_is_not_had_fails_at_its_source_and_makes_no_job() {
    let ran = run(
        new_build(None),
        Backend::default(),
        Err("not fetched".into()),
        false,
    )
    .await;
    assert_eq!(ran.state, BuildState::Failed);
    assert!(ran.submitted.is_empty());
    assert_eq!(
        failed_at(&ran.said),
        Some((AT_SOURCE.into(), "not fetched".into()))
    );
    assert_eq!(
        ran.said.len(),
        1,
        "no start is said of a build that never started"
    );
}

#[tokio::test]
async fn a_job_the_backend_will_not_make_fails_at_scheduling() {
    let backend = Backend {
        refuse: true,
        ..Backend::default()
    };
    let ran = run(new_build(None), backend, Ok(()), false).await;
    assert_eq!(ran.state, BuildState::Failed);
    let (stage, reason) = failed_at(&ran.said).unwrap();
    assert_eq!(stage, AT_SCHEDULING);
    assert!(reason.contains("the stand-in refuses"), "{reason}");
    assert_eq!(ran.failure.as_deref(), Some(reason.as_str()));
}

#[tokio::test]
async fn a_job_that_fails_or_is_gone_fails_at_execution() {
    for (status, why) in [
        (
            JobStatus::Failed {
                reason: Some("exit 2".into()),
            },
            "exit 2",
        ),
        (JobStatus::Failed { reason: None }, "the Job failed"),
        (JobStatus::Unknown, "the build's Job is gone"),
    ] {
        let ran = run(
            new_build(None),
            scripted(vec![Ok(JobStatus::Running), Ok(status)]),
            Ok(()),
            false,
        )
        .await;
        assert_eq!(ran.state, BuildState::Failed);
        let (stage, reason) = failed_at(&ran.said).unwrap();
        assert_eq!(stage, AT_EXECUTION);
        assert!(reason.contains(why), "{reason}");
    }
}

#[tokio::test]
async fn a_poll_that_fails_is_asked_again() {
    let ran = run(
        new_build(None),
        scripted(vec![
            Err(BackendError::PollFailed("the API is away".into())),
            Ok(JobStatus::Running),
            Err(BackendError::PollFailed("again".into())),
            Ok(JobStatus::Succeeded),
        ]),
        Ok(()),
        false,
    )
    .await;
    assert_eq!(ran.state, BuildState::Succeeded);
}

#[tokio::test]
async fn an_adopted_build_is_watched_to_its_end_and_counted_from_its_jobs_making() {
    let made_at = chrono::Utc::now().timestamp() - 600;
    let ran = run(
        Start::Adopted {
            handle: BackendJobHandle {
                name: "build-runner-y".into(),
                uid: "u-y".into(),
            },
            made_at: Some(made_at),
        },
        scripted(vec![Ok(JobStatus::Running), Ok(JobStatus::Succeeded)]),
        Err("an adopted build's source is never asked for".into()),
        true,
    )
    .await;
    assert_eq!(ran.state, BuildState::Succeeded);
    assert!(ran.submitted.is_empty(), "an adopted build makes no Job");
    match &ran.said[..] {
        [(_, ProvenanceEvent::ExecutionCompleted { duration_secs, .. })] => {
            assert!((600..700).contains(duration_secs), "{duration_secs}")
        }
        other => panic!("{other:?}"),
    }
}

fn seed(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../report/fuzz/seeds")
        .join(name);
    let mut line = std::fs::read(path).unwrap();
    while line.last() == Some(&b'\n') {
        line.pop();
    }
    line
}

/// A log: the build's own output, its reports, and lines that only look like them, split where it falls.
fn log(lines: &[&[u8]], piece: usize) -> Vec<Result<Vec<u8>, String>> {
    let mut whole = Vec::new();
    for line in lines {
        whole.extend_from_slice(line);
        whole.push(b'\n');
    }
    whole.chunks(piece).map(|p| Ok(p.to_vec())).collect()
}

fn report(seed_name: &str) -> Vec<u8> {
    let mut line = b"polar-report ".to_vec();
    line.extend(seed(seed_name));
    line
}

fn with_log(
    polls: Vec<Result<JobStatus, BackendError>>,
    log: Vec<Result<Vec<u8>, String>>,
) -> Backend {
    Backend {
        log: Some(log),
        ..scripted(polls)
    }
}

#[tokio::test]
async fn a_builds_reports_are_read_once_it_ends_relayed_stamped_and_said_before_its_end() {
    let lines: Vec<Vec<u8>> = vec![
        b"cargo build --release".to_vec(),
        report("stage.json"),
        b"polar-reportno space".to_vec(),
        report("started.json"),
        // Its digests are not digests: the relay refuses it.
        report("artifact.json"),
        b"polar-report {\"type\": \"execution_completed\", \"build_id\": \"b\"}".to_vec(),
        b"polar-report {not json".to_vec(),
        report("status.json"),
    ];
    let lines: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
    for piece in [7, 4096] {
        let ran = run(
            new_build(None),
            with_log(vec![Ok(JobStatus::Succeeded)], log(&lines, piece)),
            Ok(()),
            false,
        )
        .await;
        assert_eq!(ran.state, BuildState::Succeeded);
        assert_eq!(ran.relayed.len(), 3, "stage, started and status; {piece}");
        assert_eq!(
            ran.asked, 6,
            "every report line within its bound is read, and none else"
        );
        for envelope in &ran.relayed {
            assert_eq!(
                envelope.build_id,
                ran.id.to_string(),
                "the orchestrator's id, not the line's"
            );
        }
        assert!(matches!(
            ran.relayed[0].report,
            ProvenanceEvent::StageCompleted { .. }
        ));
        assert!(matches!(
            ran.relayed[2].report,
            ProvenanceEvent::PackageStatusFound(_)
        ));
        assert!(ran.reports_first, "the reports, then the end");
    }
}

#[tokio::test]
async fn a_failed_builds_reports_are_read_too() {
    let lines = [report("stage.json")];
    let lines: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
    let ran = run(
        new_build(None),
        with_log(
            vec![Ok(JobStatus::Failed {
                reason: Some("exit 1".into()),
            })],
            log(&lines, 64),
        ),
        Ok(()),
        false,
    )
    .await;
    assert_eq!(ran.relayed.len(), 1);
    assert_eq!(failed_at(&ran.said).unwrap().0, AT_EXECUTION);
    assert!(ran.reports_first);
}

#[tokio::test]
async fn a_report_that_kills_the_reader_fails_the_build_at_its_reports() {
    let lines = [report("stage.json"), report("status.json")];
    let lines: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
    let dead = InProcess {
        reader: None,
        asked: Mutex::new(0),
    };
    let ran = run_with(
        new_build(None),
        with_log(vec![Ok(JobStatus::Succeeded)], log(&lines, 64)),
        Ok(()),
        false,
        dead,
        FORKED,
        RelayBounds::default(),
    )
    .await;
    assert_eq!(ran.state, BuildState::Failed);
    assert_eq!(ran.asked, 1, "nothing more is asked of a dead reader");
    let (stage, reason) = failed_at(&ran.said).unwrap();
    assert_eq!(stage, AT_REPORTS);
    assert!(reason.contains("SIGSYS"), "{reason}");
    assert!(
        !ran.said
            .iter()
            .any(|(_, e)| matches!(e, ProvenanceEvent::ExecutionCompleted { .. })),
        "a build whose reports killed the reader is not said to have completed"
    );
}

#[tokio::test]
async fn a_log_that_cannot_be_had_leaves_the_build_as_it_ended() {
    let ran = run(
        new_build(None),
        scripted(vec![Ok(JobStatus::Succeeded)]),
        Ok(()),
        false,
    )
    .await;
    assert_eq!(ran.state, BuildState::Succeeded);
    assert!(ran.relayed.is_empty());
}

#[tokio::test]
async fn a_log_that_ends_in_an_error_keeps_what_was_read() {
    let mut pieces = log(&[report("stage.json").as_slice()], 4096);
    pieces.push(Err("the API went away".into()));
    pieces.extend(log(&[report("status.json").as_slice()], 4096));
    let ran = run(
        new_build(None),
        with_log(vec![Ok(JobStatus::Succeeded)], pieces),
        Ok(()),
        false,
    )
    .await;
    assert_eq!(ran.relayed.len(), 1);
    assert_eq!(ran.state, BuildState::Succeeded);
}

#[tokio::test]
async fn a_build_is_read_to_its_bounds_and_no_further() {
    let lines = [
        report("stage.json"),
        report("started.json"),
        report("status.json"),
        report("stage.json"),
    ];
    let lines: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
    // A line bound under a stage report's: each is refused unread.
    let narrow = Bounds {
        line: seed("stage.json").len() - 1,
        ..FORKED
    };
    let ran = run_with(
        new_build(None),
        with_log(vec![Ok(JobStatus::Succeeded)], log(&lines, 64)),
        Ok(()),
        false,
        reader(),
        narrow,
        RelayBounds::default(),
    )
    .await;
    assert_eq!(ran.relayed.len(), 2, "started and status fit the bound");
    assert_eq!(
        ran.asked, 2,
        "the reader is never asked a line past the bound"
    );
    // Two report lines at most: the rest refused unread.
    let ran = run_with(
        new_build(None),
        with_log(vec![Ok(JobStatus::Succeeded)], log(&lines, 64)),
        Ok(()),
        false,
        reader(),
        FORKED,
        RelayBounds {
            reports: 2,
            bytes: u64::MAX,
        },
    )
    .await;
    assert_eq!((ran.relayed.len(), ran.asked), (2, 2));
}

#[tokio::test]
async fn the_source_is_fetched_with_the_mappings_credential_and_held_to_the_builds_bound() {
    for credential in [None, Some("git-a")] {
        let start = Start::New {
            mapping: mapping_with(None, credential),
            ref_name: "refs/heads/main".into(),
            triggered_by: None,
            default_command: vec![],
        };
        let ran = run(
            start,
            scripted(vec![Ok(JobStatus::Succeeded)]),
            Ok(()),
            false,
        )
        .await;
        assert_eq!(ran.prepared, [(credential.map(str::to_string), MAX_SOURCE)]);
    }
    // An adopted build's source was prepared by the orchestrator that started it.
    let ran = run(
        Start::Adopted {
            handle: BackendJobHandle {
                name: "j".into(),
                uid: "u".into(),
            },
            made_at: None,
        },
        scripted(vec![Ok(JobStatus::Succeeded)]),
        Ok(()),
        true,
    )
    .await;
    assert!(ran.prepared.is_empty());
}
