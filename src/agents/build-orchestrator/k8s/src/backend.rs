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

//! The Kubernetes backend: a build's Job made, watched over and removed through the builder's Kubernetes protocol, each
//! call an operation that declares what it may do, judged and recorded (docs/architecture/build-orchestrator.md, 5a). It
//! holds no client of its own and no credential: the protocol goes with the pod's ServiceAccount token.

use crate::job::{JobOptions, build_job, departures, expired};
use async_trait::async_trait;
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::{Event, Pod, PodTemplate};
use orchestrator_core::backend::{
    BackendJobHandle, BuildBackend, InFlight, JobGraphIdentity, JobStatus, LogPieces, Retention,
    SubmittedJob,
};
use orchestrator_core::error::BackendError;
use orchestrator_core::types::{BuildSpec, SourceRef};
use polar_agent_builder::protocol::kubernetes::{
    Answer, ApiAnswer, Call, Kubernetes, POD_LOG, Propagation, Resource,
};
use polar_agent_builder::protocol::{
    Delivery, Location, Operation, OperationDecl, ProtocolHandle, ProtocolKind, ReadFailure,
    Streaming, Verb,
};
use ractor::{Actor, ActorProcessingErr, ActorRef};
use serde_json::Value;
use tracing::{info, instrument, warn};

const JOB: Resource = Resource::of::<Job>();
const EVENT: Resource = Resource::of::<Event>();
const POD_TEMPLATE: Resource = Resource::of::<PodTemplate>();
const POD: Resource = Resource::of::<Pod>();

/// The label every Job the orchestrator makes carries (job.rs, `standard_metadata`), by which it finds its own.
const MANAGED_BY: &str = "app.kubernetes.io/managed-by=build-orchestrator";

macro_rules! calls {
    ($( $kind:ident $decl:ident $name:literal $doc:literal [$( $access:expr ),+] ),+ $(,)?) => {
        $(
            pub const $decl: OperationDecl = OperationDecl {
                name: $name,
                doc: $doc,
                protocol: ProtocolKind::KUBERNETES,
                location: Location::Cluster { access: &[$( $access ),+] },
            };

            struct $kind(Call);

            impl Operation for $kind {
                type Protocol = Kubernetes;
                type Output = Answer;
                const DECL: OperationDecl = $decl;
                fn request(&self) -> Call {
                    self.0.clone()
                }
                fn read(&self, reply: &Answer) -> Result<Answer, ReadFailure> {
                    Ok(reply.clone())
                }
            }
        )+

        /// What the backend asks of the Kubernetes API, as the agent declares it.
        pub const OPERATIONS: &[OperationDecl] = &[$( $decl ),+];
    };
}

calls! {
    GetPodTemplate GET_POD_TEMPLATE "build.podtemplates.get" "the build workload's pod, which each build's Job is made from" [POD_TEMPLATE.access(Verb::Get)],
    CreateJob CREATE_JOB "build.jobs.create" "a build's Job, in the build namespace" [JOB.access(Verb::Create)],
    GetJob GET_JOB "build.jobs.get" "a build's Job, to see how it is doing" [JOB.access(Verb::Get)],
    DeleteJob DELETE_JOB "build.jobs.delete" "a build's Job, cancelled or past its retention" [JOB.access(Verb::Delete)],
    ListJobs LIST_JOBS "build.jobs.list" "the orchestrator's own Jobs, to remove those past their retention" [JOB.access(Verb::List)],
    ListEvents LIST_EVENTS "build.events.list" "why a build's pod could not be made" [EVENT.access(Verb::List)],
    ListPods LIST_PODS "build.pods.list" "a build's pods, whose log is read once its Job ends" [POD.access(Verb::List)],
    ReadLog READ_LOG "build.pods.log" "the log of a build's pipeline, read once, for what the build reports" [POD_LOG],
}

pub struct KubernetesBackend {
    protocols: ProtocolHandle,
    /// Deployment-level job settings: namespace, template, resources, retention.
    options: JobOptions,
}

impl KubernetesBackend {
    pub fn new(protocols: ProtocolHandle, options: JobOptions) -> Self {
        Self { protocols, options }
    }

    fn namespace(&self) -> String {
        self.options.namespace.clone()
    }

    /// The build workload's PodTemplate, read for each build, so that a catalog applied since is the one a build runs in
    /// (build-orchestrator.md, 5b).
    async fn template(&self) -> Result<PodTemplate, BackendError> {
        let call = Call::Get {
            resource: POD_TEMPLATE,
            namespace: self.namespace(),
            name: self.options.template.clone(),
        };
        match self.protocols.ask(GetPodTemplate(call)).await {
            Ok(Answer::Object(object)) => serde_json::from_value(object).map_err(|e| {
                BackendError::SubmissionFailed(format!(
                    "the build workload's PodTemplate is not one: {e}"
                ))
            }),
            Ok(Answer::Said(answer)) => Err(BackendError::SubmissionFailed(format!(
                "the build workload's PodTemplate could not be read: {}",
                said(&answer)
            ))),
            Ok(other) => Err(BackendError::SubmissionFailed(format!(
                "the API answered a get of the PodTemplate {other:?}"
            ))),
            Err(e) => Err(BackendError::SubmissionFailed(e.to_string())),
        }
    }
}

/// An object's metadata field, as text.
fn meta(object: &Value, field: &str) -> Option<String> {
    object["metadata"][field].as_str().map(str::to_string)
}

fn said(answer: &ApiAnswer) -> String {
    format!("{} {}: {}", answer.code, answer.reason, answer.message)
}

#[async_trait]
impl BuildBackend for KubernetesBackend {
    #[instrument(skip(self, spec), fields(build_id = %spec.build_id))]
    async fn submit(&self, spec: &BuildSpec) -> Result<SubmittedJob, BackendError> {
        let template = self.template().await?;
        let manifest =
            build_job(&template, spec, &self.options).map_err(BackendError::SubmissionFailed)?;
        // What the Job may differ from its template in is said once, and held to before it is made.
        let departed = departures(&template, &manifest, &spec.privileges);
        if !departed.is_empty() {
            return Err(BackendError::SubmissionFailed(format!(
                "the Job departs from the build workload's template: {}",
                departed.join("; ")
            )));
        }
        let call =
            Call::create(self.namespace(), &manifest).map_err(BackendError::SubmissionFailed)?;
        let made = match self.protocols.ask(CreateJob(call)).await {
            Ok(Answer::Object(made)) => made,
            Ok(Answer::Said(answer)) => {
                return Err(BackendError::SubmissionFailed(format!(
                    "the API did not make the Job: {}",
                    said(&answer)
                )));
            }
            Ok(other) => {
                return Err(BackendError::SubmissionFailed(format!(
                    "the API answered a create {other:?}"
                )));
            }
            Err(e) => return Err(BackendError::SubmissionFailed(e.to_string())),
        };
        let (Some(name), Some(uid)) = (meta(&made, "name"), meta(&made, "uid")) else {
            return Err(BackendError::SubmissionFailed(
                "the Job made has no name or uid".into(),
            ));
        };
        info!(build_id = %spec.build_id, job_name = %name, "pipeline Job created");
        let handle = BackendJobHandle {
            name: name.clone(),
            uid,
        };
        let graph_identity = JobGraphIdentity {
            node_label: "KubernetesJob".into(),
            display_name: name,
            identity_props: vec![("uid".into(), handle.uid.clone())],
        };
        Ok(SubmittedJob {
            handle,
            graph_identity,
        })
    }

    #[instrument(skip(self), fields(handle = %handle))]
    async fn poll(&self, handle: &BackendJobHandle) -> Result<JobStatus, BackendError> {
        let call = Call::Get {
            resource: JOB,
            namespace: self.namespace(),
            name: handle.name.clone(),
        };
        let job: Job = match self.protocols.ask(GetJob(call)).await {
            Ok(Answer::Object(object)) => serde_json::from_value(object)
                .map_err(|e| BackendError::PollFailed(format!("the Job is not one: {e}")))?,
            Ok(Answer::Said(ApiAnswer { code: 404, .. })) => return Ok(JobStatus::Unknown),
            Ok(other) => {
                return Err(BackendError::PollFailed(format!(
                    "the API answered a get {other:?}"
                )));
            }
            Err(e) => return Err(BackendError::PollFailed(e.to_string())),
        };
        let status = interpret_job_status(&job);
        if status != JobStatus::Pending {
            return Ok(status);
        }
        // A Job whose pod is refused at admission (LimitRange, PodSecurity, ...) never leaves Pending: the Job controller
        // just retries making the pod forever. Its FailedCreate events say why; a full quota is only a wait for room.
        match self.pod_creation_refusals(&handle.name).await {
            Ok(messages) => match permanent_refusal(&messages) {
                Some(reason) => {
                    tracing::error!(handle = %handle, reason = %reason, "Job's pod was refused; failing the build");
                    if let Err(e) = self.cancel(handle).await {
                        warn!(handle = %handle, error = %e, "could not delete refused Job");
                    }
                    Ok(JobStatus::Failed {
                        reason: Some(format!("pod creation refused: {reason}")),
                    })
                }
                None => Ok(status),
            },
            // Not being able to read events is no reason to fail the build.
            Err(e) => {
                warn!(handle = %handle, error = %e, "could not read Job events");
                Ok(status)
            }
        }
    }

    #[instrument(skip(self), fields(handle = %handle))]
    async fn cancel(&self, handle: &BackendJobHandle) -> Result<(), BackendError> {
        let call = Call::Delete {
            resource: JOB,
            namespace: self.namespace(),
            name: handle.name.clone(),
            propagation: Propagation::Foreground,
            uid: Some(handle.uid.clone()),
        };
        match self.protocols.ask(DeleteJob(call)).await {
            // Gone, going, or already not there (or another Job under its name, which is not this build's): done.
            Ok(Answer::Gone | Answer::Object(_))
            | Ok(Answer::Said(ApiAnswer {
                code: 404 | 409, ..
            })) => {
                info!(handle = %handle, "kubernetes Job deleted for cancellation");
                Ok(())
            }
            Ok(other) => Err(BackendError::CancellationFailed(format!(
                "the API answered a delete {other:?}"
            ))),
            Err(e) => Err(BackendError::CancellationFailed(e.to_string())),
        }
    }

    #[instrument(skip(self), fields(handle = %handle))]
    async fn log(&self, handle: &BackendJobHandle) -> Result<Box<dyn LogPieces>, BackendError> {
        let call = Call::List {
            resource: POD,
            namespace: self.namespace(),
            labels: Some(format!("job-name={}", handle.name)),
            fields: None,
        };
        let items = match self.protocols.ask(ListPods(call)).await {
            Ok(Answer::Objects(items)) => items,
            Ok(other) => {
                return Err(BackendError::Unreachable(format!(
                    "the API answered a list of pods {other:?}"
                )));
            }
            Err(e) => return Err(BackendError::Unreachable(e.to_string())),
        };
        let pods = pods_of(items, &handle.uid);
        if pods.is_empty() {
            return Err(BackendError::Unreachable(
                "the build's Job has no pod to read the log of".into(),
            ));
        }
        Ok(Box::new(PodLogs {
            protocols: self.protocols.clone(),
            namespace: self.namespace(),
            pods: pods.into(),
            reading: None,
        }))
    }

    #[instrument(skip(self))]
    async fn in_flight(&self) -> Result<Vec<InFlight>, BackendError> {
        let mut found = Vec::new();
        for job in self.own_jobs().await? {
            match in_flight_of(&job) {
                Ok(Some(job)) => found.push(job),
                Ok(None) => {}
                Err(why) => warn!(
                    job = ?job.metadata.name,
                    "a Job of the orchestrator's that has not ended is not adopted: {why}"
                ),
            }
        }
        Ok(found)
    }

    #[instrument(skip(self))]
    async fn reap(&self, retention: &Retention) -> Result<Vec<String>, BackendError> {
        let listed = self.own_jobs().await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or_default();
        let mut removed = Vec::new();
        for job in expired(&listed, now, retention) {
            let (Some(name), Some(uid)) = (&job.metadata.name, &job.metadata.uid) else {
                continue;
            };
            // Background, so that the Job's pods go with it, and the uid, so that a Job made again under the same name
            // is not the one removed.
            let call = Call::Delete {
                resource: JOB,
                namespace: self.namespace(),
                name: name.clone(),
                propagation: Propagation::Background,
                uid: Some(uid.clone()),
            };
            match self.protocols.ask(DeleteJob(call)).await {
                Ok(Answer::Gone | Answer::Object(_)) => {
                    info!(job = %name, "removed a finished job that is past its retention");
                    removed.push(name.clone());
                }
                // Something else removed it first, which is the outcome wanted.
                Ok(Answer::Said(ApiAnswer {
                    code: 404 | 409, ..
                })) => {}
                other => warn!(job = %name, outcome = ?other, "could not remove a finished job"),
            }
        }
        Ok(removed)
    }

    fn name(&self) -> &'static str {
        "kubernetes"
    }
}

impl KubernetesBackend {
    /// This orchestrator's own Jobs: whatever else is in the namespace is not its to adopt or remove.
    async fn own_jobs(&self) -> Result<Vec<Job>, BackendError> {
        let call = Call::List {
            resource: JOB,
            namespace: self.namespace(),
            labels: Some(MANAGED_BY.into()),
            fields: None,
        };
        match self.protocols.ask(ListJobs(call)).await {
            Ok(Answer::Objects(items)) => Ok(items
                .into_iter()
                .filter_map(|item| serde_json::from_value(item).ok())
                .collect()),
            Ok(other) => Err(BackendError::Unreachable(format!(
                "the API answered a list {other:?}"
            ))),
            Err(e) => Err(BackendError::Unreachable(format!(
                "could not list the orchestrator's jobs: {e}"
            ))),
        }
    }

    /// Messages of the Job's FailedCreate events, oldest first.
    async fn pod_creation_refusals(&self, job_name: &str) -> Result<Vec<String>, String> {
        let call = Call::List {
            resource: EVENT,
            namespace: self.namespace(),
            labels: None,
            fields: Some(format!(
                "involvedObject.kind=Job,involvedObject.name={job_name},reason=FailedCreate"
            )),
        };
        let items = match self.protocols.ask(ListEvents(call)).await {
            Ok(Answer::Objects(items)) => items,
            Ok(other) => return Err(format!("the API answered a list {other:?}")),
            Err(e) => return Err(e.to_string()),
        };
        let mut events: Vec<Event> = items
            .into_iter()
            .filter_map(|item| serde_json::from_value(item).ok())
            .collect();
        events.sort_by_key(|e| e.last_timestamp.clone().map(|t| t.0));
        Ok(events.into_iter().filter_map(|e| e.message).collect())
    }
}

/// The reason a Job's pod can never be created, if the latest refusal is
/// permanent. A quota refusal ("exceeded quota") is not: the namespace is
/// full and the pod is created once something else finishes.
fn permanent_refusal(messages: &[String]) -> Option<String> {
    messages
        .last()
        .filter(|m| !m.contains("exceeded quota"))
        .cloned()
}

/// Interpret the k8s Job status conditions into our JobStatus enum.
/// The k8s Job status model is unfortunately not a clean state machine —
/// conditions are a list of booleans that must be read carefully.
/// The pods of the Job whose uid is `job_uid`, oldest first: those it owns, so that no pod of another Job under the same
/// labels is read as the build's. With no retries (`backoffLimit: 0`) there is one; a pod the Job made again is read
/// after the one it replaced, each its own claims.
fn pods_of(items: Vec<Value>, job_uid: &str) -> Vec<String> {
    let mut pods: Vec<Pod> = items
        .into_iter()
        .filter_map(|item| serde_json::from_value(item).ok())
        .filter(|pod: &Pod| {
            pod.metadata
                .owner_references
                .iter()
                .flatten()
                .any(|owner| owner.kind == "Job" && owner.uid == job_uid)
        })
        .collect();
    pods.sort_by_key(|pod| pod.metadata.creation_timestamp.as_ref().map(|t| t.0));
    pods.into_iter()
        .filter_map(|pod| pod.metadata.name)
        .collect()
}

/// The pipeline's log of each of a build's pods in turn, a piece at a time.
struct PodLogs {
    protocols: ProtocolHandle,
    namespace: String,
    pods: std::collections::VecDeque<String>,
    reading: Option<Reading>,
}

/// A pod's log being read: the pieces as the tap hands them on, and the stream, which ends when this is dropped.
struct Reading {
    pieces: tokio::sync::mpsc::Receiver<Result<Vec<u8>, String>>,
    tap: ActorRef<Tapped>,
    _stream: Streaming,
}

impl Drop for Reading {
    fn drop(&mut self) {
        self.tap.stop(None);
    }
}

#[async_trait]
impl LogPieces for PodLogs {
    async fn next(&mut self) -> Option<Result<Vec<u8>, String>> {
        loop {
            if let Some(reading) = &mut self.reading {
                match reading.pieces.recv().await {
                    Some(piece) => return Some(piece),
                    // This pod's log has ended: the next pod's, if there is one.
                    None => self.reading = None,
                }
            }
            let pod = self.pods.pop_front()?;
            match self.open(pod).await {
                Ok(reading) => self.reading = Some(reading),
                Err(why) => return Some(Err(why)),
            }
        }
    }
}

impl PodLogs {
    async fn open(&self, pod: String) -> Result<Reading, String> {
        // One piece held at a time: the handler reads the next only once this one is taken.
        let (to, pieces) = tokio::sync::mpsc::channel(1);
        let (tap, _) = Actor::spawn(None, Tap, to)
            .await
            .map_err(|e| format!("the log's tap did not start: {e}"))?;
        let call = Call::Log {
            namespace: self.namespace.clone(),
            pod,
            container: Some(crate::job::PIPELINE.to_string()),
            follow: false,
        };
        let stream = self
            .protocols
            .stream(ReadLog(call), tap.clone(), Tapped)
            .map_err(|e| {
                tap.stop(None);
                e.to_string()
            })?;
        Ok(Reading {
            pieces,
            tap,
            _stream: stream,
        })
    }
}

/// Hands each piece of a streamed log on, holding the handler's delivery until the reader has taken it, so that the log
/// is read no faster than its reports are.
struct Tap;

struct Tapped(Delivery<Answer>);

#[async_trait]
impl Actor for Tap {
    type Msg = Tapped;
    type State = tokio::sync::mpsc::Sender<Result<Vec<u8>, String>>;
    type Arguments = tokio::sync::mpsc::Sender<Result<Vec<u8>, String>>;

    async fn pre_start(
        &self,
        _: ActorRef<Tapped>,
        to: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(to)
    }

    async fn handle(
        &self,
        myself: ActorRef<Tapped>,
        Tapped(delivery): Tapped,
        to: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        let piece = match &delivery.result {
            Ok(Answer::Log(piece)) => Ok(piece.clone()),
            Ok(Answer::LogEnded) => {
                myself.stop(None);
                return Ok(());
            }
            Ok(Answer::Said(answer)) => {
                Err(format!("the API did not give the log: {}", said(answer)))
            }
            Ok(other) => Err(format!("the API answered a log {other:?}")),
            Err(failure) => Err(format!("the log could not be read: {failure}")),
        };
        let last = piece.is_err();
        // Gone if the reader has stopped reading: so does the tap.
        if to.send(piece).await.is_err() || last {
            myself.stop(None);
        }
        drop(delivery);
        Ok(())
    }
}

/// A Job of the orchestrator's that a poll would find pending or running, as a restarted orchestrator adopts it: what it
/// builds, from the labels and annotations the Job was made with (`job::standard_metadata`), and how to reach it.
/// `Ok(None)` for one a poll would find ended, by the same reading, so that a Job adopted is one no orchestrator has seen
/// end; `Err` for one not ended that does not say what it builds.
fn in_flight_of(job: &Job) -> Result<Option<InFlight>, String> {
    if !matches!(
        interpret_job_status(job),
        JobStatus::Pending | JobStatus::Running
    ) {
        return Ok(None);
    }
    let metadata = &job.metadata;
    let (Some(name), Some(uid)) = (&metadata.name, &metadata.uid) else {
        return Err("it has no name or uid".into());
    };
    let label = |key: &str| metadata.labels.as_ref().and_then(|l| l.get(key));
    let annotation = |key: &str| {
        metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(key))
            .cloned()
            .ok_or(format!("it has no {key} annotation"))
    };
    let build_id = label("cyclops.build/id")
        .and_then(|id| id.parse().ok())
        .ok_or("its build id label is missing or not a UUID")?;
    let source = match annotation("cyclops.build/source-kind")?.as_str() {
        "git" => SourceRef::Git {
            url: annotation("cyclops.build/repo")?,
            commit_sha: annotation("cyclops.build/commit")?,
        },
        "archive" => SourceRef::RegistryArchive {
            purl: annotation("cyclops.build/purl")?,
            download_url: annotation("cyclops.build/archive")?,
            sha256: annotation("cyclops.build/archive-sha256")?,
        },
        _ => return Err("its source kind is not one".into()),
    };
    source.validate().map_err(|e| e.to_string())?;
    Ok(Some(InFlight {
        build_id,
        source,
        handle: BackendJobHandle {
            name: name.clone(),
            uid: uid.clone(),
        },
        made_at: metadata
            .creation_timestamp
            .as_ref()
            .map(|t| t.0.as_second()),
    }))
}

fn interpret_job_status(job: &Job) -> JobStatus {
    let status = match &job.status {
        Some(s) => s,
        None => return JobStatus::Pending,
    };
    // succeeded > 0 means at least one pod completed with exit 0.
    if status.succeeded.unwrap_or(0) > 0 {
        return JobStatus::Succeeded;
    }
    // failed > 0 and active == 0 means no more retries.
    if status.failed.unwrap_or(0) > 0 && status.active.unwrap_or(0) == 0 {
        let reason = status.conditions.as_ref().and_then(|conditions| {
            conditions
                .iter()
                .find(|c| c.type_ == "Failed")
                .and_then(|c| c.message.clone())
        });
        return JobStatus::Failed { reason };
    }
    // active > 0 means a pod is currently running.
    if status.active.unwrap_or(0) > 0 {
        return JobStatus::Running;
    }
    JobStatus::Pending
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::tests::template;
    use orchestrator_core::types::{Privileges, SourceArchive, SourceRef};
    use polar_agent_builder::protocol::testing::{KubeApi, kubernetes_handle};
    use proptest::prelude::*;
    use serde_json::json;
    use uuid::Uuid;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const JOBS: &str = "/apis/batch/v1/namespaces/builds/jobs";

    fn spec() -> BuildSpec {
        BuildSpec::with_pipeline_runner(
            Uuid::nil(),
            SourceRef::Git {
                url: "https://github.com/cmu-sei/Polar.git".into(),
                commit_sha: "a".repeat(40),
            },
            SourceArchive::new(format!("localhost:30500/build-sources@sha256:{HEX}")).unwrap(),
            format!("registry.example.com/pipeline@sha256:{HEX}"),
            vec![],
            Privileges::default(),
        )
    }

    fn options() -> JobOptions {
        JobOptions::new("builds", "build-runner")
    }

    async fn backend(api: &KubeApi) -> KubernetesBackend {
        let site = kubernetes_handle(OPERATIONS, api).await;
        KubernetesBackend::new(site.handle, options())
    }

    fn handle() -> BackendJobHandle {
        BackendJobHandle {
            name: "build-1".into(),
            uid: "u-1".into(),
        }
    }

    fn job(status: Value) -> Value {
        json!({"apiVersion": "batch/v1", "kind": "Job",
               "metadata": {"name": "build-1", "namespace": "builds", "uid": "u-1"}, "status": status})
    }

    fn status(code: u16) -> Value {
        json!({"kind": "Status", "apiVersion": "v1", "metadata": {}, "status": "Failure",
               "message": "the stand-in says so", "reason": "Whatever", "code": code})
    }

    const TEMPLATE: &str = "/api/v1/namespaces/builds/podtemplates/build-runner";

    /// A build is its Job made from the build workload's PodTemplate, read as the build is submitted, and nothing else:
    /// no Secret, no account to find; what was made is its handle.
    #[tokio::test]
    async fn a_build_is_its_job_made_from_the_template_and_nothing_else() {
        let api = KubeApi::start().await;
        api.answers(
            "GET",
            TEMPLATE,
            200,
            serde_json::to_value(template()).unwrap(),
        );
        api.answers("POST", JOBS, 201, job(json!({})));
        let submitted = backend(&api).await.submit(&spec()).await.unwrap();
        assert_eq!(
            (
                submitted.handle.name.as_str(),
                submitted.handle.uid.as_str()
            ),
            ("build-1", "u-1")
        );
        let received = api.received().await;
        let asked: Vec<(&str, &str)> = received
            .iter()
            .map(|(method, path, ..)| (method.as_str(), path.as_str()))
            .collect();
        assert_eq!(asked, [("GET", TEMPLATE), ("POST", JOBS)]);
        let sent: Value = serde_json::from_slice(&received[1].3).unwrap();
        assert_eq!(
            sent["metadata"]["name"],
            format!("build-runner-{}", Uuid::nil())
        );
        assert_eq!(
            sent["spec"]["template"]["spec"]["serviceAccountName"],
            "build-runner"
        );
    }

    /// No Job is made without the build workload's template, or from one that is not the build workload's.
    #[tokio::test]
    async fn without_its_template_no_job_is_made_and_the_build_says_why() {
        let api = KubeApi::start().await;
        api.answers("GET", TEMPLATE, 404, status(404));
        let mut not_ours = template();
        not_ours
            .template
            .as_mut()
            .unwrap()
            .spec
            .as_mut()
            .unwrap()
            .init_containers = None;
        api.answers(
            "GET",
            TEMPLATE,
            200,
            serde_json::to_value(not_ours).unwrap(),
        );
        let backend = backend(&api).await;
        for why in ["404", "fetch"] {
            match backend.submit(&spec()).await {
                Err(BackendError::SubmissionFailed(said)) => assert!(said.contains(why), "{said}"),
                other => panic!("not refused as a submission: {:?}", other.map(|s| s.handle)),
            }
        }
        assert!(
            api.received()
                .await
                .iter()
                .all(|(method, ..)| method == "GET"),
            "no Job was asked for"
        );
    }

    #[tokio::test]
    async fn a_job_the_api_would_not_make_fails_the_submission_and_says_why() {
        let api = KubeApi::start().await;
        api.answers(
            "GET",
            TEMPLATE,
            200,
            serde_json::to_value(template()).unwrap(),
        );
        api.answers("POST", JOBS, 409, status(409));
        let failed = backend(&api).await.submit(&spec()).await;
        match failed {
            Err(BackendError::SubmissionFailed(why)) => assert!(why.contains("409"), "{why}"),
            _ => panic!("not refused as a submission"),
        }
    }

    #[tokio::test]
    async fn a_job_is_polled_for_how_it_is_doing_and_one_not_there_is_unknown() {
        let api = KubeApi::start().await;
        let path = format!("{JOBS}/build-1");
        api.answers("GET", &path, 200, job(json!({"succeeded": 1})));
        api.answers("GET", &path, 200, job(json!({"active": 1})));
        api.answers("GET", &path, 404, status(404));
        let backend = backend(&api).await;
        assert_eq!(backend.poll(&handle()).await.unwrap(), JobStatus::Succeeded);
        assert_eq!(backend.poll(&handle()).await.unwrap(), JobStatus::Running);
        assert_eq!(backend.poll(&handle()).await.unwrap(), JobStatus::Unknown);
    }

    /// A pending Job whose pod the API refuses for good fails the build, and its Job is removed; a full quota is a wait.
    #[tokio::test]
    async fn a_pod_refused_for_good_fails_the_build_and_a_full_quota_waits() {
        let events = "/api/v1/namespaces/builds/events";
        let refused = |message: &str| {
            json!({"apiVersion": "v1", "kind": "EventList", "metadata": {},
                   "items": [{"metadata": {"name": "e"}, "involvedObject": {}, "message": message}]})
        };
        let api = KubeApi::start().await;
        let path = format!("{JOBS}/build-1");
        api.answers("GET", &path, 200, job(json!({})));
        api.answers(
            "GET",
            events,
            200,
            refused("forbidden: maximum cpu usage per Container is 1"),
        );
        api.answers(
            "DELETE",
            &path,
            200,
            json!({"kind": "Status", "apiVersion": "v1", "metadata": {}, "status": "Success"}),
        );
        api.answers("GET", &path, 200, job(json!({})));
        api.answers(
            "GET",
            events,
            200,
            refused("forbidden: exceeded quota: jobs-quota"),
        );
        let backend = backend(&api).await;
        assert!(matches!(
            backend.poll(&handle()).await.unwrap(),
            JobStatus::Failed { reason: Some(why) } if why.contains("maximum cpu")
        ));
        assert_eq!(backend.poll(&handle()).await.unwrap(), JobStatus::Pending);
        let received = api.received().await;
        let deletes: Vec<&Vec<u8>> = received
            .iter()
            .filter(|(m, ..)| m == "DELETE")
            .map(|(.., b)| b)
            .collect();
        assert_eq!(deletes.len(), 1);
        let sent: Value = serde_json::from_slice(deletes[0]).unwrap();
        assert_eq!(sent["preconditions"]["uid"], "u-1");
        let queries: Vec<&String> = received
            .iter()
            .filter(|(_, p, ..)| p == events)
            .map(|(_, _, q, _)| q)
            .collect();
        assert!(queries[0].contains("reason%3DFailedCreate"), "{queries:?}");
    }

    /// Cancelling a Job that is already gone, or was made again under its name, is done: it is not this build's.
    #[tokio::test]
    async fn cancelling_a_job_already_gone_is_done() {
        for code in [404, 409] {
            let api = KubeApi::start().await;
            api.answers("DELETE", &format!("{JOBS}/build-1"), code, status(code));
            assert!(
                backend(&api).await.cancel(&handle()).await.is_ok(),
                "{code}"
            );
        }
    }

    /// A Job as the API holds it: made from `spec`, with the uid the API gives and `status`.
    fn held(spec: &BuildSpec, status: Value) -> Value {
        let job = crate::job::build_job(&template(), spec, &options()).unwrap();
        let mut job = serde_json::to_value(job).unwrap();
        job["metadata"]["uid"] = json!(format!("u-{}", spec.build_id));
        job["metadata"]["creationTimestamp"] = json!("2027-01-15T08:00:00Z");
        job["status"] = status;
        job
    }

    fn any_source() -> impl Strategy<Value = SourceRef> {
        prop_oneof![
            ("[a-z]{1,8}", "[a-z0-9/]{1,16}", "[0-9a-f]{40}").prop_map(
                |(host, path, commit_sha)| {
                    SourceRef::Git {
                        url: format!("https://{host}.example/{path}"),
                        commit_sha,
                    }
                }
            ),
            ("[a-z]{1,8}", "[0-9a-f]{64}").prop_map(|(name, sha256)| SourceRef::RegistryArchive {
                purl: format!("pkg:cargo/{name}@1.0.0"),
                download_url: format!("https://static.example/{name}.crate"),
                sha256,
            }),
        ]
    }

    proptest! {
        /// A Job not ended says what it builds and how to reach it, as it was made, whatever the build; one ended, by the
        /// reading a poll makes, is never adopted.
        #[test]
        fn a_job_in_flight_reads_back_as_made_and_an_ended_one_is_not_adopted(
            id in any::<u128>(),
            source in any_source(),
            status in prop_oneof![
                Just((json!({}), true)),
                Just((json!({"active": 1}), true)),
                Just((json!({"active": 1, "failed": 1}), true)),
                Just((json!({"succeeded": 1}), false)),
                Just((json!({"failed": 1}), false)),
                Just((json!({"succeeded": 1, "active": 1}), false)),
            ],
        ) {
            let mut build = spec();
            build.build_id = Uuid::from_u128(id);
            build.source = source.clone();
            let (status, in_flight) = status;
            let job: Job = serde_json::from_value(held(&build, status)).unwrap();
            let found = in_flight_of(&job).unwrap();
            if in_flight {
                prop_assert_eq!(found, Some(InFlight {
                    build_id: build.build_id,
                    source,
                    handle: BackendJobHandle {
                        name: crate::job::job_name_for_build("build-runner", build.build_id),
                        uid: format!("u-{}", build.build_id),
                    },
                    made_at: Some(1_800_000_000),
                }));
            } else {
                prop_assert_eq!(found, None);
            }
        }
    }

    /// At start, the orchestrator's own Jobs not ended are found, by the label it makes them with; one ended is not, and
    /// one that does not say what it builds is passed over, not guessed at.
    #[tokio::test]
    async fn the_jobs_in_flight_are_its_own_not_ended() {
        let api = KubeApi::start().await;
        let build = |n: u128| {
            let mut build = spec();
            build.build_id = Uuid::from_u128(n);
            build
        };
        let mut unsaid = held(&build(4), json!({"active": 1}));
        unsaid["metadata"]["annotations"]
            .as_object_mut()
            .unwrap()
            .remove("cyclops.build/commit");
        api.answers(
            "GET",
            JOBS,
            200,
            json!({"apiVersion": "batch/v1", "kind": "JobList", "metadata": {},
                   "items": [held(&build(1), json!({"active": 1})), held(&build(2), json!({"succeeded": 1})),
                             held(&build(3), json!({})), unsaid]}),
        );
        let found = backend(&api).await.in_flight().await.unwrap();
        let ids: Vec<u128> = found.iter().map(|f| f.build_id.as_u128()).collect();
        assert_eq!(ids, [1, 3]);
        let received = api.received().await;
        assert_eq!(received.len(), 1);
        assert!(
            received[0]
                .2
                .contains("app.kubernetes.io%2Fmanaged-by%3Dbuild-orchestrator"),
            "{}",
            received[0].2
        );
    }

    const PODS: &str = "/api/v1/namespaces/builds/pods";

    fn pod(name: &str, owner_uid: &str, made: &str) -> Value {
        json!({"apiVersion": "v1", "kind": "Pod",
               "metadata": {"name": name, "creationTimestamp": made,
                            "ownerReferences": [{"apiVersion": "batch/v1", "kind": "Job", "name": "build-1", "uid": owner_uid}]},
               "spec": {"containers": []}})
    }

    async fn read_all(mut log: Box<dyn LogPieces>) -> Result<Vec<u8>, String> {
        let mut read = Vec::new();
        while let Some(piece) = log.next().await {
            read.extend(piece?);
        }
        Ok(read)
    }

    /// A build's log is its pipeline's, of the pods its Job owns, oldest first, all of it however long; a pod another Job
    /// owns is not read.
    #[tokio::test]
    async fn a_builds_log_is_its_own_pods_pipeline_read_whole() {
        let api = KubeApi::start().await;
        api.answers(
            "GET",
            PODS,
            200,
            json!({"apiVersion": "v1", "kind": "PodList", "metadata": {},
                   "items": [pod("second", "u-1", "2026-11-08T10:00:00Z"), pod("foreign", "u-other", "2026-11-08T08:00:00Z"),
                             pod("first", "u-1", "2026-11-08T09:00:00Z")]}),
        );
        let long: Vec<u8> = (0..300_000u32).map(|i| b'a' + (i % 26) as u8).collect();
        api.logs(&format!("{PODS}/first/log"), long.clone());
        api.logs(&format!("{PODS}/second/log"), b"polar-report {}\n".to_vec());
        api.logs(&format!("{PODS}/foreign/log"), b"not this build's".to_vec());
        let read = read_all(backend(&api).await.log(&handle()).await.unwrap())
            .await
            .unwrap();
        let mut expected = long;
        expected.extend_from_slice(b"polar-report {}\n");
        assert_eq!(read.len(), expected.len());
        assert!(read == expected, "the two pods' logs, in order");
        let received = api.received().await;
        assert!(
            received[0].2.contains("labelSelector=job-name%3Dbuild-1"),
            "{}",
            received[0].2
        );
        let logs: Vec<(&str, &str)> = received[1..]
            .iter()
            .map(|(_, path, query, _)| (path.as_str(), query.as_str()))
            .collect();
        assert_eq!(logs.len(), 2, "{logs:?}");
        assert!(
            logs[0].0.ends_with("/first/log") && logs[1].0.ends_with("/second/log"),
            "{logs:?}"
        );
        assert!(
            logs.iter().all(|(_, q)| q.contains("container=pipeline")),
            "{logs:?}"
        );
    }

    #[tokio::test]
    async fn a_job_with_no_pod_has_no_log() {
        let api = KubeApi::start().await;
        api.answers(
            "GET",
            PODS,
            200,
            json!({"apiVersion": "v1", "kind": "PodList", "metadata": {}, "items": [pod("foreign", "u-other", "2026-11-08T08:00:00Z")]}),
        );
        assert!(matches!(
            backend(&api).await.log(&handle()).await,
            Err(BackendError::Unreachable(_))
        ));
    }

    /// Only the orchestrator's own Jobs are looked over, and only those past their retention are removed, each by its uid.
    #[tokio::test]
    async fn reaping_removes_only_its_own_jobs_past_their_retention() {
        let api = KubeApi::start().await;
        let ended = |name: &str, uid: &str, at: &str| {
            json!({"metadata": {"name": name, "uid": uid},
                   "status": {"conditions": [{"type": "Complete", "status": "True", "lastTransitionTime": at}]}})
        };
        api.answers(
            "GET",
            JOBS,
            200,
            json!({"apiVersion": "batch/v1", "kind": "JobList", "metadata": {},
                   "items": [ended("old", "u-old", "2020-01-01T00:00:00Z"), ended("new", "u-new", "2999-01-01T00:00:00Z")]}),
        );
        api.answers(
            "DELETE",
            &format!("{JOBS}/old"),
            200,
            json!({"kind": "Status", "apiVersion": "v1", "metadata": {}, "status": "Success"}),
        );
        let removed = backend(&api)
            .await
            .reap(&Retention::default())
            .await
            .unwrap();
        assert_eq!(removed, ["old"]);
        let received = api.received().await;
        assert!(
            received[0]
                .2
                .contains("labelSelector=app.kubernetes.io%2Fmanaged-by%3Dbuild-orchestrator"),
            "{received:?}"
        );
        let deletes: Vec<_> = received.iter().filter(|(m, ..)| m == "DELETE").collect();
        assert_eq!(deletes.len(), 1);
        assert_eq!(
            serde_json::from_slice::<Value>(&deletes[0].3).unwrap()["preconditions"]["uid"],
            "u-old"
        );
    }

    /// Each operation may do one thing to one kind, and none of them touches a Secret or a ServiceAccount.
    #[test]
    fn each_operation_declares_one_access_and_none_is_of_a_secret() {
        for decl in OPERATIONS {
            let Location::Cluster { access } = decl.location else {
                panic!("{} goes elsewhere", decl.name)
            };
            assert_eq!(access.len(), 1, "{}", decl.name);
            assert!(
                !["secrets", "serviceaccounts"].contains(&access[0].resource),
                "{}",
                decl.name
            );
        }
    }

    #[test]
    fn limit_range_refusal_is_permanent() {
        let msg = "Error creating: pods \"build-x\" is forbidden: [maximum cpu usage per Container is 1, but limit is 2]".to_string();
        assert_eq!(permanent_refusal(std::slice::from_ref(&msg)), Some(msg));
    }

    #[test]
    fn quota_refusal_is_a_wait() {
        let msg = "Error creating: pods \"build-x\" is forbidden: exceeded quota: jobs-quota, requested: pods=1, used: pods=4, limited: pods=4".to_string();
        assert_eq!(permanent_refusal(&[msg]), None);
    }

    #[test]
    fn only_the_latest_refusal_counts() {
        let quota = "forbidden: exceeded quota: jobs-quota".to_string();
        let limit = "forbidden: maximum memory usage per Container is 2Gi".to_string();
        assert_eq!(permanent_refusal(&[limit.clone(), quota.clone()]), None);
        assert_eq!(permanent_refusal(&[quota, limit.clone()]), Some(limit));
        assert_eq!(permanent_refusal(&[]), None);
    }
}
