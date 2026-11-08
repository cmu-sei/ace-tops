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

//! A build's actor, against a stand-in backend, source and broker: what it makes, what it records, and what it says, at
//! each way a build can go.

use build_orchestrator::build::{
    AT_EXECUTION, AT_SCHEDULING, AT_SOURCE, BuildActor, BuildArgs, Start,
};
use build_orchestrator::mappings::Mapping;
use build_orchestrator::publish::Publish;
use build_orchestrator::registry::{BuildRegistry, RegistryMessage};
use build_orchestrator::source::Source;
use orchestrator_core::backend::{
    BackendJobHandle, BuildBackend, JobGraphIdentity, JobStatus, SubmittedJob,
};
use orchestrator_core::error::BackendError;
use orchestrator_core::types::{
    BuildRequest, BuildSpec, BuildState, Privileges, SourceArchive, SourceRef,
};
use polar::ProvenanceEvent;
use polar::graph::nodes::git::RepoId;
use polar::topics::PROVENANCE_EXECUTIONS;
use ractor::{Actor, ActorRef};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const URL: &str = "https://git.example.org/a/b.git";

/// A backend that makes the Job it is told to, or refuses, and answers each poll from a script.
#[derive(Default)]
struct Backend {
    refuse: bool,
    polls: Mutex<VecDeque<Result<JobStatus, BackendError>>>,
    submitted: Mutex<Vec<BuildSpec>>,
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
    fn name(&self) -> &'static str {
        "stand-in"
    }
}

struct Archive(Result<(), String>);

#[ractor::async_trait]
impl Source for Archive {
    async fn prepare(&self, _: &SourceRef) -> Result<SourceArchive, String> {
        self.0.clone()?;
        Ok(SourceArchive::new(format!("registry.polar/build-sources@sha256:{HEX}")).unwrap())
    }
}

#[derive(Default)]
struct Said(Mutex<Vec<(String, ProvenanceEvent)>>);

#[ractor::async_trait]
impl Publish for Said {
    async fn publish(&self, topic: &str, event: &ProvenanceEvent) -> Result<(), String> {
        // Not Clone: kept as it would travel.
        let event = serde_json::from_value(serde_json::to_value(event).unwrap()).unwrap();
        self.0.lock().unwrap().push((topic.to_string(), event));
        Ok(())
    }
}

fn mapping(command: Option<Vec<String>>) -> Mapping {
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
        credentials: vec![],
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
    state: BuildState,
    failure: Option<String>,
    said: Vec<(String, ProvenanceEvent)>,
    submitted: Vec<BuildSpec>,
}

/// Runs a build to its actor's end and says what came of it.
async fn run(start: Start, backend: Backend, source: Result<(), String>, adopted: bool) -> Ran {
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
    let (_, ended) = Actor::spawn(
        None,
        BuildActor,
        BuildArgs {
            request,
            start,
            backend: backend.clone(),
            source: Arc::new(Archive(source)),
            registry: registry.clone(),
            publish: said.clone(),
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
    let said = std::mem::take(&mut *said.0.lock().unwrap());
    let submitted = backend.submitted.lock().unwrap().clone();
    Ran {
        state: record.state,
        failure: record.failure_reason,
        said,
        submitted,
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
