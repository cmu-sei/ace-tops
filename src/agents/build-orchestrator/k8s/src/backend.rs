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

use crate::job::{JobOptions, build_job_manifest, expired, job_name_for_build};
use async_trait::async_trait;
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::Event;
use orchestrator_core::backend::{
    BackendJobHandle, BuildBackend, JobGraphIdentity, JobStatus, Retention, SubmittedJob,
};
use orchestrator_core::error::BackendError;
use orchestrator_core::types::BuildSpec;
use polar_agent_builder::protocol::kubernetes::{
    Answer, ApiAnswer, Call, Kubernetes, Propagation, Resource,
};
use polar_agent_builder::protocol::{
    Location, Operation, OperationDecl, ProtocolHandle, ProtocolKind, ReadFailure, Verb,
};
use serde_json::Value;
use tracing::{info, instrument, warn};

const JOB: Resource = Resource::of::<Job>();
const EVENT: Resource = Resource::of::<Event>();

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
    CreateJob CREATE_JOB "build.jobs.create" "a build's Job, in the build namespace" [JOB.access(Verb::Create)],
    GetJob GET_JOB "build.jobs.get" "a build's Job, to see how it is doing" [JOB.access(Verb::Get)],
    DeleteJob DELETE_JOB "build.jobs.delete" "a build's Job, cancelled or past its retention" [JOB.access(Verb::Delete)],
    ListJobs LIST_JOBS "build.jobs.list" "the orchestrator's own Jobs, to remove those past their retention" [JOB.access(Verb::List)],
    ListEvents LIST_EVENTS "build.events.list" "why a build's pod could not be made" [EVENT.access(Verb::List)],
}

pub struct KubernetesBackend {
    protocols: ProtocolHandle,
    /// Deployment-level job settings: namespace, account, identity, fetch image, resources.
    options: JobOptions,
}

impl KubernetesBackend {
    pub fn new(protocols: ProtocolHandle, options: JobOptions) -> Self {
        Self { protocols, options }
    }

    fn namespace(&self) -> String {
        self.options.namespace.clone()
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
        let manifest = build_job_manifest(spec, &self.options);
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
        info!(
            build_id = %spec.build_id,
            job_name = %job_name_for_build(spec.build_id),
            "pipeline Job created"
        );
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

    #[instrument(skip(self))]
    async fn reap(&self, retention: &Retention) -> Result<Vec<String>, BackendError> {
        // Only this orchestrator's own jobs: whatever else is in the namespace is not its to remove.
        let call = Call::List {
            resource: JOB,
            namespace: self.namespace(),
            labels: Some(MANAGED_BY.into()),
            fields: None,
        };
        let listed: Vec<Job> = match self.protocols.ask(ListJobs(call)).await {
            Ok(Answer::Objects(items)) => items
                .into_iter()
                .filter_map(|item| serde_json::from_value(item).ok())
                .collect(),
            Ok(other) => {
                return Err(BackendError::Unreachable(format!(
                    "the API answered a list {other:?}"
                )));
            }
            Err(e) => {
                return Err(BackendError::Unreachable(format!(
                    "could not list the jobs to remove the old ones: {e}"
                )));
            }
        };
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
    use crate::job::JobIdentity;
    use orchestrator_core::types::{Privileges, SourceArchive, SourceRef};
    use polar_agent_builder::protocol::testing::{KubeApi, kubernetes_handle};
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
        JobOptions::new(
            "builds",
            "build-job",
            JobIdentity::default(),
            format!("localhost:30500/build-fetch@sha256:{HEX}"),
        )
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

    /// A build is its Job made, and nothing else: no Secret, no account to find; what was made is its handle.
    #[tokio::test]
    async fn a_build_is_its_job_made_and_nothing_else() {
        let api = KubeApi::start().await;
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
        assert_eq!(received.len(), 1, "{received:?}");
        let (method, path, _, body) = &received[0];
        assert_eq!((method.as_str(), path.as_str()), ("POST", JOBS));
        let sent: Value = serde_json::from_slice(body).unwrap();
        assert_eq!(sent["metadata"]["name"], format!("build-{}", Uuid::nil()));
        assert_eq!(
            sent["spec"]["template"]["spec"]["serviceAccountName"],
            "build-job"
        );
    }

    #[tokio::test]
    async fn a_job_the_api_would_not_make_fails_the_submission_and_says_why() {
        let api = KubeApi::start().await;
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
