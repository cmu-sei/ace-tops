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

//! A build's Kubernetes Job, made from the build workload's PodTemplate (docs/architecture/build-orchestrator.md, 5b, 5c and
//! revised 3).
//!
//! # Job anatomy
//!
//! The catalog renders the build workload as a PodTemplate (`build-runner`, `infra/schema/pod-template.dhall`), and each
//! build's Job is that pod, changed only where a build differs:
//!
//! ```text
//! initContainers:
//!   - name: fetch          ← told the source archive's blob and digest; it checks the digest and unpacks into /workspace
//! containers:
//!   - name: pipeline       ← the repository's pipeline image, pinned by its signed mapping, in place of the template's
//! volumes:
//!   - name: workspace      ← the template's, shared by the fetch and the pipeline
//!   - name: tmp            ← scratch, since root filesystems are read-only
//! ```
//!
//! The fetch runs to completion before the pipeline starts. If it fails, or the archive does not have its digest, the
//! Job fails and the pipeline never starts: a build that cannot have its source does not proceed.
//!
//! # Nothing of Polar's, and no credential
//!
//! A build pod holds no Polar identity: no certificate, no custody daemon, no polar-init, no Cassini client (revised 3).
//! It reports what it did by printing, and the orchestrator reads its log, judges and relays it. The orchestrator fetched
//! the source through its own protocol handlers, which hold any credential, and put it in the registry by digest
//! (decision 1): the pod is told only that blob and its digest. No Secret, no token, no credential in any environment.
//!
//! # Security posture
//!
//! - Every container hardened: non-root under the template's user, no privilege escalation, every capability dropped,
//!   the default seccomp profile, a read-only root filesystem writing only its workspace and /tmp. The pipeline gets
//!   only what the repository's signed mapping asks for beyond that (`Privileges`, decision 4), and is never privileged.
//! - What the Job may differ from its template in is said once, here, and checked before every create (`departures`);
//!   whatever a Job asks of its node, the builder's judge refuses (`Denial::ReachesTheNode`).
//! - restartPolicy=Never: retries are the orchestrator's decision, not Kubernetes's.

use k8s_openapi::{
    api::{
        batch::v1::{Job, JobSpec},
        core::v1::{
            Capabilities, Container, EmptyDirVolumeSource, EnvVar, PodSpec, PodTemplate,
            PodTemplateSpec, ResourceRequirements, SeccompProfile, SecurityContext, Volume,
            VolumeMount,
        },
    },
    apimachinery::pkg::{api::resource::Quantity, apis::meta::v1::ObjectMeta},
};
use orchestrator_core::WORKSPACE_PATH;
use orchestrator_core::backend::Retention;
use orchestrator_core::types::{BuildSpec, Privileges, SourceRef, pinned_by_digest, source_env};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

/// The template's init container that fetches the source, and its one container that runs the pipeline.
pub const FETCH: &str = "fetch";
pub const PIPELINE: &str = "pipeline";
/// The template's volume shared by the fetch and the pipeline.
const WORKSPACE_VOLUME: &str = "workspace";
/// Scratch emptyDir mounted at /tmp, since root filesystems are read-only.
const TMP_VOLUME: &str = "tmp";
const TMP_PATH: &str = "/tmp";

/// How a finished Job ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    Succeeded,
    Failed,
}

/// How a Job ended and when (seconds since the epoch), if it has: its Complete or Failed condition, once true. A
/// Job that has not finished, or whose condition has no time, has no end.
pub fn ended(job: &Job) -> Option<(Ended, i64)> {
    job.status
        .as_ref()?
        .conditions
        .as_ref()?
        .iter()
        .find_map(|c| {
            let how = match c.type_.as_str() {
                "Complete" => Ended::Succeeded,
                "Failed" => Ended::Failed,
                _ => return None,
            };
            if c.status != "True" {
                return None;
            }
            Some((how, c.last_transition_time.as_ref()?.0.as_second()))
        })
}

/// The Jobs that finished longer ago than `retention` allows for how they ended. A Job still running is never one.
pub fn expired<'a>(jobs: &'a [Job], now: i64, retention: &Retention) -> Vec<&'a Job> {
    jobs.iter()
        .filter(|job| {
            let Some((how, at)) = ended(job) else {
                return false;
            };
            let keep = match how {
                Ended::Succeeded => retention.succeeded,
                Ended::Failed => retention.failed,
            };
            now.saturating_sub(at) > i64::try_from(keep.as_secs()).unwrap_or(i64::MAX)
        })
        .collect()
}

/// A build's Job name: its template's, then the build's ID, so that the attestation agent takes the Job as the build
/// workload's (it holds a Job named `<workload>-...` to be its workload's; build-orchestrator.md, 7b). Kubernetes names
/// are at most 63 characters; `build-runner-` and a UUID are 49.
pub fn job_name_for_build(template: &str, build_id: Uuid) -> String {
    format!("{template}-{build_id}")
}

// ── Pipeline job ──────────────────────────────────────────────────────────────

/// Everything about a job that comes from the deployment rather than from the build request or the template.
#[derive(Debug, Clone)]
pub struct JobOptions {
    /// Namespace jobs are created in: the template's.
    pub namespace: String,
    /// The PodTemplate a build's Job is made from: the build workload's name.
    pub template: String,
    /// Requests and limits for the pipeline container.
    pub resources: PipelineResources,
    /// Size limit of the workspace emptyDir, e.g. "2Gi". None means no limit,
    /// so a large repo or archive can fill the node's disk.
    pub workspace_size_limit: Option<String>,
    /// How long finished jobs are kept. The orchestrator applies it by outcome (`expired`); Kubernetes' own expiry
    /// on each Job is set to the longest of them, so that jobs are still collected if the orchestrator is not
    /// running to apply it.
    pub retention: Retention,
}

impl JobOptions {
    /// Options with the default pipeline resources and no workspace limit.
    pub fn new(namespace: impl Into<String>, template: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            template: template.into(),
            resources: PipelineResources::default(),
            workspace_size_limit: None,
            retention: Retention::default(),
        }
    }
}

/// Pipeline container requests and limits, as Kubernetes quantities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineResources {
    pub cpu_limit: String,
    pub memory_limit: String,
    pub cpu_request: String,
    pub memory_request: String,
}

impl Default for PipelineResources {
    /// Sized for a real CI build. Lower them for analysis on a laptop.
    fn default() -> Self {
        Self {
            cpu_limit: "2".into(),
            memory_limit: "4Gi".into(),
            cpu_request: "500m".into(),
            memory_request: "512Mi".into(),
        }
    }
}

/// A build's Job, made from `template`: its pod, with the fetch told the build's blob and digest, the pipeline on the
/// mapping's image with the build's variables and the hardening its privileges allow, scratch space, resources, and the
/// Job's name and labels. A template without its `fetch` init container or its `pipeline` container is not the build
/// workload's, and no Job is made from it.
pub fn build_job(
    template: &PodTemplate,
    spec: &BuildSpec,
    options: &JobOptions,
) -> Result<Job, String> {
    let pod_template = template
        .template
        .as_ref()
        .ok_or("the PodTemplate has no pod")?;
    let mut pod = pod_template
        .spec
        .clone()
        .ok_or("the PodTemplate has no pod spec")?;

    let fetch = pod
        .init_containers
        .iter_mut()
        .flatten()
        .find(|c| c.name == FETCH)
        .ok_or("the PodTemplate has no `fetch` init container")?;
    fetch.env.get_or_insert_with(Vec::new).extend(
        spec.archive
            .fetch_env()
            .into_iter()
            .map(|(name, value)| plain(name, value)),
    );
    fetch.resources = Some(fetch_resources());
    harden(fetch, &Privileges::default());

    let pipeline = pod
        .containers
        .iter_mut()
        .find(|c| c.name == PIPELINE)
        .ok_or("the PodTemplate has no `pipeline` container")?;
    pipeline.image = Some(spec.pipeline_image.clone());
    // None runs the image's own CMD/ENTRYPOINT; otherwise it overrides it.
    pipeline.command = spec.entrypoint.clone();
    pipeline
        .env
        .get_or_insert_with(Vec::new)
        .extend(pipeline_env_vars(spec));
    pipeline.resources = Some(pipeline_resources(&options.resources));
    // A git build's pipeline writes beside its source (its artifacts, its build directory); only an archive, which is
    // third-party code under analysis, gets the source read-only.
    if matches!(spec.source, SourceRef::RegistryArchive { .. }) {
        for mount in pipeline.volume_mounts.iter_mut().flatten() {
            if mount.name == WORKSPACE_VOLUME {
                mount.read_only = Some(true);
            }
        }
    }
    harden(pipeline, &spec.privileges);

    let volumes = pod.volumes.get_or_insert_with(Vec::new);
    if let Some(limit) = &options.workspace_size_limit {
        for volume in volumes.iter_mut().filter(|v| v.name == WORKSPACE_VOLUME) {
            if let Some(empty_dir) = volume.empty_dir.as_mut() {
                empty_dir.size_limit = Some(Quantity(limit.clone()));
            }
        }
    }
    volumes.push(tmp_volume());

    let (labels, annotations) = standard_metadata(spec);
    let mut pod_metadata = pod_template.metadata.clone().unwrap_or_default();
    pod_metadata
        .labels
        .get_or_insert_with(BTreeMap::new)
        .extend(labels.clone());
    pod_metadata.name = None;

    Ok(Job {
        metadata: ObjectMeta {
            name: Some(job_name_for_build(&options.template, spec.build_id)),
            namespace: Some(options.namespace.clone()),
            labels: Some(labels),
            annotations: Some(annotations),
            ..Default::default()
        },
        spec: Some(JobSpec {
            template: PodTemplateSpec {
                metadata: Some(pod_metadata),
                spec: Some(pod),
            },
            backoff_limit: Some(0),
            ttl_seconds_after_finished: Some(
                i32::try_from(options.retention.longest().as_secs()).unwrap_or(i32::MAX),
            ),
            ..Default::default()
        }),
        ..Default::default()
    })
}

fn plain(name: impl Into<String>, value: impl Into<String>) -> EnvVar {
    EnvVar {
        name: name.into(),
        value: Some(value.into()),
        ..Default::default()
    }
}

fn pipeline_env_vars(spec: &BuildSpec) -> Vec<EnvVar> {
    [
        plain("POLAR_BUILD_ID", spec.build_id.to_string()),
        plain("BUILD_WORKSPACE", WORKSPACE_PATH),
    ]
    .into_iter()
    .chain(
        spec.source
            .pipeline_env()
            .into_iter()
            .map(|(name, value)| plain(name, value)),
    )
    .chain(spec.env.iter().map(|(k, v)| plain(k.clone(), v.clone())))
    .collect()
}

/// A container's security context: hardened, with only what `privileges` asks for beyond that, and never privileged. It
/// runs as the template's user and group, unless its mapping runs it as root, when it runs as its image's.
fn security_context(
    template: Option<&SecurityContext>,
    privileges: &Privileges,
) -> SecurityContext {
    let (user, group) = match (privileges.run_as_root, template) {
        (false, Some(t)) => (t.run_as_user, t.run_as_group),
        _ => (None, None),
    };
    SecurityContext {
        privileged: Some(false),
        run_as_non_root: Some(!privileges.run_as_root),
        run_as_user: user,
        run_as_group: group,
        read_only_root_filesystem: Some(true),
        allow_privilege_escalation: Some(privileges.allow_privilege_escalation),
        capabilities: Some(Capabilities {
            drop: Some(vec!["ALL".to_string()]),
            add: (!privileges.add_capabilities.is_empty())
                .then(|| privileges.add_capabilities.clone()),
        }),
        seccomp_profile: Some(SeccompProfile {
            type_: "RuntimeDefault".to_string(),
            localhost_profile: None,
        }),
        ..Default::default()
    }
}

fn harden(container: &mut Container, privileges: &Privileges) {
    container.security_context = Some(security_context(
        container.security_context.as_ref(),
        privileges,
    ));
    container
        .volume_mounts
        .get_or_insert_with(Vec::new)
        .push(tmp_volume_mount());
}

fn tmp_volume() -> Volume {
    Volume {
        name: TMP_VOLUME.to_string(),
        empty_dir: Some(EmptyDirVolumeSource {
            medium: None,
            size_limit: Some(Quantity("256Mi".to_string())),
        }),
        ..Default::default()
    }
}

fn tmp_volume_mount() -> VolumeMount {
    VolumeMount {
        name: TMP_VOLUME.to_string(),
        mount_path: TMP_PATH.to_string(),
        read_only: Some(false),
        ..Default::default()
    }
}

fn pipeline_resources(r: &PipelineResources) -> ResourceRequirements {
    resource_requirements(
        &r.cpu_limit,
        &r.memory_limit,
        &r.cpu_request,
        &r.memory_request,
    )
}

fn fetch_resources() -> ResourceRequirements {
    resource_requirements("200m", "256Mi", "100m", "128Mi")
}

fn resource_requirements(
    cpu_limit: &str,
    memory_limit: &str,
    cpu_request: &str,
    memory_request: &str,
) -> ResourceRequirements {
    let mut limits = BTreeMap::new();
    limits.insert("cpu".to_string(), Quantity(cpu_limit.to_string()));
    limits.insert("memory".to_string(), Quantity(memory_limit.to_string()));
    let mut requests = BTreeMap::new();
    requests.insert("cpu".to_string(), Quantity(cpu_request.to_string()));
    requests.insert("memory".to_string(), Quantity(memory_request.to_string()));
    ResourceRequirements {
        limits: Some(limits),
        requests: Some(requests),
        ..Default::default()
    }
}

/// The Job's labels (what selects it) and annotations (what it built, for whoever reads the cluster).
fn standard_metadata(spec: &BuildSpec) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "build-orchestrator".to_string(),
    );
    labels.insert("cyclops.build/id".to_string(), spec.build_id.to_string());
    labels.insert("cyclops.build/type".to_string(), "pipeline".to_string());

    let mut annotations = BTreeMap::new();
    annotations.insert(
        "cyclops.build/source-kind".to_string(),
        spec.source.kind().to_string(),
    );
    annotations.insert(
        "cyclops.build/source-blob".to_string(),
        spec.archive.reference().to_string(),
    );
    match &spec.source {
        SourceRef::Git { url, commit_sha } => {
            annotations.insert("cyclops.build/repo".to_string(), url.clone());
            annotations.insert("cyclops.build/commit".to_string(), commit_sha.clone());
        }
        SourceRef::RegistryArchive {
            purl,
            download_url,
            sha256,
        } => {
            annotations.insert("cyclops.build/purl".to_string(), purl.clone());
            annotations.insert("cyclops.build/archive".to_string(), download_url.clone());
            annotations.insert("cyclops.build/archive-sha256".to_string(), sha256.clone());
        }
    }
    (labels, annotations)
}

// ── What a Job may differ from its template in ──────────────────────────────────

/// Where a build's Job departs from its template beyond what a build may change, each said in a sentence; none, for a Job
/// that is its template's pod changed only where a build differs (build-orchestrator.md, O2c). Said independently of
/// `build_job`, and checked before every create, so that a Job made otherwise, or changed after, is not made. What a
/// build may change:
///
/// - the pod: its volumes, by a scratch volume added and the workspace's size; its labels, by labels added; nothing else;
/// - the fetch: environment added (the blob and its digest, as plain values), its resources, its hardening, the scratch
///   mount;
/// - the pipeline: its image, pinned by digest, and command; environment added, as plain values; its resources; its
///   hardening, within what `privileges` signs; the scratch mount, and the workspace made read-only.
///
/// A hardening is within `privileges` when the container is not privileged, drops every capability and adds only those
/// signed, escalates or runs as root only if signed, has a read-only root filesystem and the runtime's default seccomp
/// profile, and sets nothing else.
pub fn departures(template: &PodTemplate, job: &Job, privileges: &Privileges) -> Vec<String> {
    let Some(want) = template.template.as_ref() else {
        return vec!["the template has no pod".into()];
    };
    let Some(got) = job.spec.as_ref().map(|s| &s.template) else {
        return vec!["the Job has no pod".into()];
    };
    let (Some(want_pod), Some(got_pod)) = (want.spec.as_ref(), got.spec.as_ref()) else {
        return vec!["the template or the Job has no pod spec".into()];
    };
    let mut found = Vec::new();

    let mut want_meta = to_value(&want.metadata.clone().unwrap_or_default());
    let mut got_meta = to_value(&got.metadata.clone().unwrap_or_default());
    let want_labels = take(&mut want_meta, "labels");
    let got_labels = take(&mut got_meta, "labels");
    take(&mut want_meta, "name");
    if want_meta != got_meta {
        found.push("the pod's metadata is not its template's, beyond its labels".into());
    }
    if !extends(&want_labels, &got_labels) {
        found.push("the pod's labels change or drop one of its template's".into());
    }

    let mut want_spec = to_value(want_pod);
    let mut got_spec = to_value(got_pod);
    for field in ["containers", "initContainers", "volumes"] {
        take(&mut want_spec, field);
        take(&mut got_spec, field);
    }
    if want_spec != got_spec {
        found.push(format!(
            "the pod departs from its template's in {}",
            differing(&want_spec, &got_spec).join(", ")
        ));
    }

    volumes_depart(want_pod, got_pod, &mut found);
    containers_depart(
        "init container",
        want_pod.init_containers.as_deref().unwrap_or_default(),
        got_pod.init_containers.as_deref().unwrap_or_default(),
        privileges,
        &mut found,
    );
    containers_depart(
        "container",
        &want_pod.containers,
        &got_pod.containers,
        privileges,
        &mut found,
    );
    found
}

fn to_value<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

/// Takes `field` out of an object, as null when it has none.
fn take(object: &mut Value, field: &str) -> Value {
    object
        .as_object_mut()
        .and_then(|o| o.remove(field))
        .unwrap_or(Value::Null)
}

/// The fields two objects differ in, sorted.
fn differing(a: &Value, b: &Value) -> Vec<String> {
    let empty = serde_json::Map::new();
    let (a, b) = (
        a.as_object().unwrap_or(&empty),
        b.as_object().unwrap_or(&empty),
    );
    let mut fields: Vec<String> = a
        .keys()
        .chain(b.keys())
        .filter(|k| a.get(*k) != b.get(*k))
        .cloned()
        .collect();
    fields.sort();
    fields.dedup();
    fields
}

/// Whether the map `got` holds every entry of `want` unchanged (and may hold more).
fn extends(want: &Value, got: &Value) -> bool {
    let empty = serde_json::Map::new();
    let want = want.as_object().unwrap_or(&empty);
    let got = got.as_object().unwrap_or(&empty);
    want.iter().all(|(k, v)| got.get(k) == Some(v))
}

fn volumes_depart(want: &PodSpec, got: &PodSpec, found: &mut Vec<String>) {
    let mut expected = want.volumes.clone().unwrap_or_default();
    expected.push(tmp_volume());
    let mut got = got.volumes.clone().unwrap_or_default();
    // The workspace's size is the deployment's to set.
    for volume in expected.iter_mut().chain(got.iter_mut()) {
        if volume.name == WORKSPACE_VOLUME
            && let Some(empty_dir) = volume.empty_dir.as_mut()
        {
            empty_dir.size_limit = None;
        }
    }
    if expected != got {
        found.push("the pod's volumes are not its template's and the scratch volume".into());
    }
}

fn containers_depart(
    what: &str,
    want: &[Container],
    got: &[Container],
    privileges: &Privileges,
    found: &mut Vec<String>,
) {
    let names = |list: &[Container]| list.iter().map(|c| c.name.clone()).collect::<Vec<_>>();
    if names(want) != names(got) {
        found.push(format!(
            "its {what}s are {:?}, and its template's {:?}",
            names(got),
            names(want)
        ));
        return;
    }
    for (want, got) in want.iter().zip(got) {
        let name = want.name.as_str();
        let (may_change, privileges) = match name {
            FETCH => (
                &["env", "resources", "securityContext", "volumeMounts"][..],
                Privileges::default(),
            ),
            PIPELINE => (
                &[
                    "image",
                    "command",
                    "env",
                    "resources",
                    "securityContext",
                    "volumeMounts",
                ][..],
                privileges.clone(),
            ),
            _ => (&[][..], Privileges::default()),
        };
        let mut want_value = to_value(want);
        let mut got_value = to_value(got);
        for field in may_change {
            take(&mut want_value, field);
            take(&mut got_value, field);
        }
        if want_value != got_value {
            found.push(format!(
                "{what} {name} departs from its template's in {}",
                differing(&want_value, &got_value).join(", ")
            ));
        }
        if may_change.is_empty() {
            continue;
        }
        env_departs(name, want, got, found);
        mounts_depart(name, want, got, found);
        if let Some(why) = hardening_departs(got.security_context.as_ref(), &privileges) {
            found.push(format!("{what} {name}: {why}"));
        }
        if name == PIPELINE && !got.image.as_deref().is_some_and(|i| i.contains("@sha256:")) {
            found.push("the pipeline's image is not pinned by digest".into());
        }
    }
}

/// A container's environment may only grow, by plain values: a value read from elsewhere (a Secret, a field) is not one a
/// build may add, and the fetch is told only its blob and digest.
fn env_departs(name: &str, want: &Container, got: &Container, found: &mut Vec<String>) {
    let want_env = want.env.clone().unwrap_or_default();
    let got_env = got.env.clone().unwrap_or_default();
    if got_env.len() < want_env.len() || got_env[..want_env.len()] != want_env[..] {
        found.push(format!(
            "{name}'s environment changes or drops its template's"
        ));
        return;
    }
    for added in &got_env[want_env.len()..] {
        if added.value_from.is_some() {
            found.push(format!(
                "{name} is given {} from elsewhere than a value",
                added.name
            ));
        }
        if name == FETCH
            && added.name != source_env::SOURCE_BLOB
            && added.name != source_env::SOURCE_SHA256
            && !(added.name == source_env::REGISTRY_INSECURE
                && added.value.as_deref() == Some("true"))
            && !(added.name == source_env::DEPENDENCIES
                && added.value.as_deref().is_some_and(pinned_by_digest))
        {
            found.push(format!(
                "the fetch is told {}, beyond its blob, its digest, whether its registry is plain http and its \
                 dependencies' index",
                added.name
            ));
        }
    }
}

/// A container's mounts are its template's, the workspace perhaps read-only, then the scratch mount.
fn mounts_depart(name: &str, want: &Container, got: &Container, found: &mut Vec<String>) {
    let mut expected = want.volume_mounts.clone().unwrap_or_default();
    expected.push(tmp_volume_mount());
    let mut got = got.volume_mounts.clone().unwrap_or_default();
    // Whether the workspace is read-only is the build's: an archive's source is.
    for mount in expected.iter_mut().chain(got.iter_mut()) {
        if mount.name == WORKSPACE_VOLUME {
            mount.read_only = None;
        }
    }
    if expected != got {
        found.push(format!(
            "{name}'s mounts are not its template's and the scratch mount"
        ));
    }
}

/// Why a container's security context is not within `privileges`, if it is not.
fn hardening_departs(context: Option<&SecurityContext>, privileges: &Privileges) -> Option<String> {
    let Some(sc) = context else {
        return Some("it has no security context".into());
    };
    if sc.privileged != Some(false) {
        return Some("it is not said to be unprivileged".into());
    }
    let caps = sc.capabilities.clone().unwrap_or_default();
    if caps.drop != Some(vec!["ALL".to_string()]) {
        return Some("it does not drop every capability".into());
    }
    if let Some(extra) = caps
        .add
        .unwrap_or_default()
        .into_iter()
        .find(|c| !privileges.add_capabilities.contains(c))
    {
        return Some(format!("it adds {extra}, which its mapping does not sign"));
    }
    if sc.allow_privilege_escalation != Some(privileges.allow_privilege_escalation) {
        return Some("its privilege escalation is not what its mapping signs".into());
    }
    if sc.run_as_non_root != Some(!privileges.run_as_root)
        || (!privileges.run_as_root && sc.run_as_user == Some(0))
    {
        return Some("it runs as root, which its mapping does not sign".into());
    }
    if sc.read_only_root_filesystem != Some(true) {
        return Some("its root filesystem is writable".into());
    }
    if sc.seccomp_profile
        != Some(SeccompProfile {
            type_: "RuntimeDefault".to_string(),
            localhost_profile: None,
        })
    {
        return Some("it is not under the runtime's default seccomp profile".into());
    }
    let mut rest = sc.clone();
    for field in [
        &mut rest.privileged,
        &mut rest.run_as_non_root,
        &mut rest.read_only_root_filesystem,
        &mut rest.allow_privilege_escalation,
    ] {
        *field = None;
    }
    rest.capabilities = None;
    rest.seccomp_profile = None;
    rest.run_as_user = None;
    rest.run_as_group = None;
    (rest != SecurityContext::default()).then(|| "it sets more than its hardening".into())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use orchestrator_core::types::SourceArchive;
    use proptest::prelude::*;
    use serde_json::json;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const FETCH_IMAGE: &str = "localhost:30500/build-fetch@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// The build workload's PodTemplate as the catalog renders it (infra/schema/pod-template.dhall).
    pub(crate) fn template() -> PodTemplate {
        let hardened = json!({"allowPrivilegeEscalation": false, "capabilities": {"drop": ["ALL"]},
            "runAsGroup": 1000, "runAsNonRoot": true, "runAsUser": 1000, "seccompProfile": {"type": "RuntimeDefault"}});
        let workspace = json!([{"mountPath": "/workspace", "name": "workspace"}]);
        serde_json::from_value(json!({
            "apiVersion": "v1", "kind": "PodTemplate",
            "metadata": {"name": "build-runner", "namespace": "polar-builds"},
            "template": {
                "metadata": {"labels": {"name": "build-runner"}, "name": "build-runner"},
                "spec": {
                    "automountServiceAccountToken": false,
                    "serviceAccountName": "build-runner",
                    "restartPolicy": "Never",
                    "terminationGracePeriodSeconds": 30,
                    "imagePullSecrets": [],
                    "nodeSelector": {"polar.dev/pool": "observers"},
                    "tolerations": [{"effect": "NoSchedule", "key": "polar.dev/pool", "operator": "Equal", "value": "observers"}],
                    "initContainers": [{"name": "fetch", "image": FETCH_IMAGE, "imagePullPolicy": "Always",
                        "env": [{"name": "CYCLOPS_WORKSPACE", "value": "/workspace"}],
                        "securityContext": hardened, "terminationMessagePolicy": "FallbackToLogsOnError",
                        "volumeMounts": workspace}],
                    "containers": [{"name": "pipeline", "image": FETCH_IMAGE, "imagePullPolicy": "Always", "env": [],
                        "securityContext": hardened, "terminationMessagePolicy": "FallbackToLogsOnError",
                        "volumeMounts": workspace}],
                    "volumes": [{"emptyDir": {}, "name": "workspace"}]
                }
            }
        }))
        .unwrap()
    }

    fn git() -> SourceRef {
        SourceRef::Git {
            url: "https://github.com/cmu-sei/Polar.git".into(),
            commit_sha: "a".repeat(40),
        }
    }

    fn archive() -> SourceRef {
        SourceRef::RegistryArchive {
            purl: "pkg:cargo/serde@1.0.219".into(),
            download_url: "https://static.crates.io/crates/serde/serde-1.0.219.crate".into(),
            sha256: "b".repeat(64),
        }
    }

    fn spec(source: SourceRef) -> BuildSpec {
        BuildSpec::with_pipeline_runner(
            Uuid::nil(),
            source,
            SourceArchive::new(format!("localhost:30500/build-sources@sha256:{HEX}")).unwrap(),
            format!("registry.example.com/pipeline@sha256:{HEX}"),
            vec![],
            Privileges::default(),
        )
    }

    fn options() -> JobOptions {
        JobOptions::new("polar-builds", "build-runner")
    }

    fn built(spec: &BuildSpec) -> Job {
        build_job(&template(), spec, &options()).unwrap()
    }

    fn pod(job: &Job) -> &PodSpec {
        job.spec.as_ref().unwrap().template.spec.as_ref().unwrap()
    }

    fn container<'a>(job: &'a Job, name: &str) -> &'a Container {
        let pod = pod(job);
        pod.init_containers
            .iter()
            .flatten()
            .chain(&pod.containers)
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no {name} container"))
    }

    fn env(c: &Container) -> Vec<(String, Option<String>)> {
        c.env
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|e| (e.name, e.value))
            .collect()
    }

    /// The fetch is told the blob and its digest, beside where to unpack it, which its template says, and nothing else:
    /// not the origin, and no credential (decision 1). Its image is the template's.
    #[test]
    fn the_fetch_is_told_the_blob_its_digest_and_where_to_unpack_it() {
        for source in [git(), archive()] {
            let job = built(&spec(source));
            let fetch = container(&job, FETCH);
            let mut names: Vec<String> = env(fetch).into_iter().map(|(k, _)| k).collect();
            names.sort();
            assert_eq!(
                names,
                [
                    source_env::SOURCE_BLOB,
                    source_env::SOURCE_SHA256,
                    "CYCLOPS_WORKSPACE"
                ],
            );
            assert!(env(fetch).contains(&(source_env::SOURCE_SHA256.into(), Some(HEX.into()))));
            assert_eq!(fetch.image.as_deref(), Some(FETCH_IMAGE));
        }
    }

    /// An archive in a registry spoken to over plain http (the registry in the cluster, as a pod reaches it) tells the fetch so,
    /// and nothing else is added (O3c).
    #[test]
    fn an_archive_over_http_tells_the_fetch_so_and_no_more() {
        let mut build = spec(git());
        build.archive = build.archive.clone().over_http();
        let job = built(&build);
        let fetch = container(&job, FETCH);
        assert!(env(fetch).contains(&(source_env::REGISTRY_INSECURE.into(), Some("true".into()))));
        assert_eq!(env(fetch).len(), 4, "{:?}", env(fetch));
        assert_eq!(
            departures(&template(), &job, &build.privileges),
            Vec::<String>::new()
        );
    }

    /// An archive with dependencies tells the fetch where their index is, pinned by its digest, and nothing else is added
    /// (D3b).
    #[test]
    fn an_archive_with_dependencies_tells_the_fetch_their_index() {
        let mut build = spec(git());
        let index = format!("registry.polar:5000/build-dependencies@sha256:{HEX}");
        build.archive = build
            .archive
            .clone()
            .with_dependencies(index.clone())
            .unwrap();
        let job = built(&build);
        let fetch = container(&job, FETCH);
        assert!(env(fetch).contains(&(source_env::DEPENDENCIES.into(), Some(index))));
        assert_eq!(env(fetch).len(), 4, "{:?}", env(fetch));
        assert_eq!(
            departures(&template(), &job, &build.privileges),
            Vec::<String>::new()
        );
    }

    /// No part of a build's Job holds a credential, a Secret or anything of Polar's identity (revised 3).
    #[test]
    fn no_part_of_the_job_holds_a_credential_or_an_identity() {
        for source in [git(), archive()] {
            let job = built(&spec(source));
            let pod = pod(&job);
            assert!(
                pod.volumes
                    .iter()
                    .flatten()
                    .all(|v| v.secret.is_none() && v.projected.is_none())
            );
            let manifest = serde_json::to_string(&job).unwrap().to_lowercase();
            for word in [
                "password",
                "credential",
                "client-tls",
                "polar-init",
                "polar-custody",
                "tls_client",
            ] {
                assert!(!manifest.contains(word), "{word} in {manifest}");
            }
            assert_eq!(pod.automount_service_account_token, Some(false));
        }
    }

    /// A build's Job is its template's pod, under its account and on its node pool, named for the template so that the
    /// attestation agent takes it as the build workload's; the pipeline runs the mapping's image in place of the
    /// template's.
    #[test]
    fn a_build_is_its_templates_pod_named_for_it() {
        let job = built(&spec(git()));
        assert_eq!(
            job.metadata.name,
            Some(format!("build-runner-{}", Uuid::nil()))
        );
        assert_eq!(job.metadata.namespace.as_deref(), Some("polar-builds"));
        let pod = pod(&job);
        assert_eq!(pod.service_account_name.as_deref(), Some("build-runner"));
        assert_eq!(pod.restart_policy.as_deref(), Some("Never"));
        assert_eq!(
            pod.node_selector.clone().unwrap()["polar.dev/pool"],
            "observers"
        );
        let inits: Vec<&str> = pod
            .init_containers
            .iter()
            .flatten()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(inits, [FETCH]);
        assert_eq!(
            container(&job, PIPELINE).image,
            Some(format!("registry.example.com/pipeline@sha256:{HEX}"))
        );
        let labels = job
            .spec
            .as_ref()
            .unwrap()
            .template
            .metadata
            .as_ref()
            .unwrap()
            .labels
            .clone()
            .unwrap();
        assert_eq!(
            labels["name"], "build-runner",
            "the template's own labels stay"
        );
        assert_eq!(labels["app.kubernetes.io/managed-by"], "build-orchestrator");
        assert!(departures(&template(), &job, &Privileges::default()).is_empty());
    }

    #[test]
    fn a_template_that_is_not_the_build_workloads_makes_no_job() {
        let mut no_fetch = template();
        no_fetch
            .template
            .as_mut()
            .unwrap()
            .spec
            .as_mut()
            .unwrap()
            .init_containers = None;
        assert!(
            build_job(&no_fetch, &spec(git()), &options())
                .unwrap_err()
                .contains("fetch")
        );
        let mut no_pipeline = template();
        no_pipeline
            .template
            .as_mut()
            .unwrap()
            .spec
            .as_mut()
            .unwrap()
            .containers[0]
            .name = "other".into();
        assert!(
            build_job(&no_pipeline, &spec(git()), &options())
                .unwrap_err()
                .contains("pipeline")
        );
        assert!(build_job(&PodTemplate::default(), &spec(git()), &options()).is_err());
    }

    #[test]
    fn a_git_build_writes_beside_its_source_and_an_archive_build_reads_it_only() {
        for (source, read_only) in [(git(), None), (archive(), Some(true))] {
            let job = built(&spec(source));
            let mounts = container(&job, PIPELINE).volume_mounts.clone().unwrap();
            let workspace = mounts.iter().find(|m| m.name == WORKSPACE_VOLUME).unwrap();
            assert_eq!(workspace.read_only, read_only);
        }
    }

    /// A git build is hardened as an archive build is, the fetch always (decision 4), under the template's user.
    #[test]
    fn every_container_of_every_build_runs_hardened_under_the_templates_user() {
        for source in [git(), archive()] {
            let job = built(&spec(source));
            for name in [FETCH, PIPELINE] {
                let c = container(&job, name);
                let sc = c.security_context.as_ref().unwrap();
                assert_eq!(sc.run_as_non_root, Some(true), "{name}");
                assert_eq!(
                    (sc.run_as_user, sc.run_as_group),
                    (Some(1000), Some(1000)),
                    "{name}"
                );
                assert_eq!(sc.allow_privilege_escalation, Some(false), "{name}");
                assert_eq!(sc.privileged, Some(false), "{name}");
                assert_eq!(sc.read_only_root_filesystem, Some(true), "{name}");
                let caps = sc.capabilities.as_ref().unwrap();
                assert_eq!(
                    caps.drop.as_deref(),
                    Some(["ALL".to_string()].as_slice()),
                    "{name}"
                );
                assert!(caps.add.is_none(), "{name}");
                assert!(
                    c.volume_mounts
                        .iter()
                        .flatten()
                        .any(|m| m.mount_path == TMP_PATH),
                    "{name} has no scratch space"
                );
            }
        }
    }

    #[test]
    fn configured_resources_and_workspace_limit_apply() {
        let job = build_job(
            &template(),
            &spec(git()),
            &JobOptions {
                resources: PipelineResources {
                    cpu_limit: "1".into(),
                    memory_limit: "1Gi".into(),
                    cpu_request: "100m".into(),
                    memory_request: "128Mi".into(),
                },
                workspace_size_limit: Some("2Gi".into()),
                ..options()
            },
        )
        .unwrap();
        let limits = container(&job, PIPELINE)
            .resources
            .as_ref()
            .unwrap()
            .limits
            .clone()
            .unwrap();
        assert_eq!(limits["memory"], Quantity("1Gi".into()));
        let workspace = pod(&job)
            .volumes
            .iter()
            .flatten()
            .find(|v| v.name == WORKSPACE_VOLUME)
            .unwrap();
        assert_eq!(
            workspace.empty_dir.as_ref().unwrap().size_limit,
            Some(Quantity("2Gi".into()))
        );
        assert!(departures(&template(), &job, &Privileges::default()).is_empty());
    }

    #[test]
    fn an_empty_command_runs_the_images_entrypoint_and_a_configured_one_overrides_it() {
        assert_eq!(container(&built(&spec(git())), PIPELINE).command, None);
        let mut build = spec(git());
        build.entrypoint = Some(vec!["/bin/analyze".into(), "--deep".into()]);
        assert_eq!(
            container(&built(&build), PIPELINE).command,
            Some(vec!["/bin/analyze".to_string(), "--deep".to_string()])
        );
    }

    #[test]
    fn job_env_and_the_source_reach_the_pipeline() {
        let mut build = spec(git());
        build.env.insert("EXTRA".into(), "1".into());
        let job = built(&build);
        let e = env(container(&job, PIPELINE));
        assert!(e.contains(&("EXTRA".into(), Some("1".into()))));
        assert!(e.contains(&("POLAR_BUILD_ID".into(), Some(Uuid::nil().to_string()))));
        assert!(e.contains(&(source_env::SOURCE_KIND.into(), Some("git".into()))));
        let annotations = job.metadata.annotations.unwrap();
        assert_eq!(annotations["cyclops.build/commit"], "a".repeat(40));
        assert_eq!(
            annotations["cyclops.build/source-blob"],
            format!("localhost:30500/build-sources@sha256:{HEX}")
        );
    }

    fn any_privileges() -> impl Strategy<Value = Privileges> {
        (
            any::<bool>(),
            any::<bool>(),
            proptest::collection::vec("[A-Z][A-Z_]{0,12}", 0..4),
        )
            .prop_map(
                |(run_as_root, allow_privilege_escalation, add_capabilities)| Privileges {
                    run_as_root,
                    allow_privilege_escalation,
                    add_capabilities,
                },
            )
    }

    fn any_build() -> impl Strategy<Value = BuildSpec> {
        (
            any_privileges(),
            any::<bool>(),
            proptest::collection::hash_map("[A-Z][A-Z_]{0,8}", "[a-z0-9]{0,8}", 0..3),
            proptest::option::of(proptest::collection::vec("[a-z/]{1,8}", 1..3)),
            any::<bool>(),
            any::<bool>(),
        )
            .prop_map(
                |(privileges, archived, env, entrypoint, over_http, with_dependencies)| {
                    let mut build = spec(if archived { archive() } else { git() });
                    if over_http {
                        build.archive = build.archive.clone().over_http();
                    }
                    if with_dependencies {
                        build.archive = build
                            .archive
                            .clone()
                            .with_dependencies(format!(
                                "registry.polar:5000/build-dependencies@sha256:{HEX}"
                            ))
                            .unwrap();
                    }
                    build.privileges = privileges;
                    build.env = env;
                    build.entrypoint = entrypoint;
                    build
                },
            )
    }

    /// One change to a built Job that no build may make: each is something a template does not say and a mapping does
    /// not sign.
    #[derive(Debug, Clone, Copy)]
    enum Departure {
        AnotherAccount,
        TokenMounted,
        AnotherNode,
        HostPathVolume,
        SecretVolume,
        ExtraContainer,
        ExtraInitContainer,
        FetchImage,
        FetchToldMore,
        SecretInEnv,
        TemplateEnvChanged,
        UnsignedCapability,
        Privileged,
        RootFlipped,
        WritableRoot,
        UnconfinedSeccomp,
        ExtraMount,
        UnpinnedImage,
        AnnotationAdded,
        TemplateLabelChanged,
        ProbeAdded,
    }

    const DEPARTURES: [Departure; 21] = [
        Departure::AnotherAccount,
        Departure::TokenMounted,
        Departure::AnotherNode,
        Departure::HostPathVolume,
        Departure::SecretVolume,
        Departure::ExtraContainer,
        Departure::ExtraInitContainer,
        Departure::FetchImage,
        Departure::FetchToldMore,
        Departure::SecretInEnv,
        Departure::TemplateEnvChanged,
        Departure::UnsignedCapability,
        Departure::Privileged,
        Departure::RootFlipped,
        Departure::WritableRoot,
        Departure::UnconfinedSeccomp,
        Departure::ExtraMount,
        Departure::UnpinnedImage,
        Departure::AnnotationAdded,
        Departure::TemplateLabelChanged,
        Departure::ProbeAdded,
    ];

    fn depart(job: &mut Job, how: Departure) {
        let template = &mut job.spec.as_mut().unwrap().template;
        let pod = template.spec.as_mut().unwrap();
        let fetch = pod
            .init_containers
            .as_mut()
            .unwrap()
            .iter_mut()
            .find(|c| c.name == FETCH)
            .unwrap();
        match how {
            Departure::FetchImage => fetch.image = Some("evil@sha256:00".into()),
            Departure::FetchToldMore => fetch.env.as_mut().unwrap().push(plain("TOKEN", "x")),
            _ => {}
        }
        let pipeline = pod
            .containers
            .iter_mut()
            .find(|c| c.name == PIPELINE)
            .unwrap();
        let sc = pipeline.security_context.as_mut().unwrap();
        match how {
            Departure::SecretInEnv => pipeline.env.as_mut().unwrap().push(EnvVar {
                name: "T".into(),
                value_from: Some(
                    serde_json::from_value(json!({"secretKeyRef": {"name": "s", "key": "k"}}))
                        .unwrap(),
                ),
                ..Default::default()
            }),
            Departure::UnsignedCapability => {
                sc.capabilities.as_mut().unwrap().add = Some(vec!["SYS_ADMIN_UNSIGNED".into()])
            }
            Departure::Privileged => sc.privileged = Some(true),
            // Whichever the mapping signs, the other.
            Departure::RootFlipped => {
                sc.run_as_non_root = sc.run_as_non_root.map(|non_root| !non_root)
            }
            Departure::WritableRoot => sc.read_only_root_filesystem = Some(false),
            Departure::UnconfinedSeccomp => {
                sc.seccomp_profile = Some(SeccompProfile {
                    type_: "Unconfined".into(),
                    localhost_profile: None,
                })
            }
            Departure::ExtraMount => pipeline.volume_mounts.as_mut().unwrap().push(VolumeMount {
                name: "workspace".into(),
                mount_path: "/etc".into(),
                ..Default::default()
            }),
            Departure::UnpinnedImage => {
                pipeline.image = Some("registry.example.com/pipeline:latest".into())
            }
            Departure::ProbeAdded => {
                pipeline.liveness_probe = Some(Default::default());
            }
            _ => {}
        }
        match how {
            Departure::TemplateEnvChanged => {
                pod.init_containers.as_mut().unwrap()[0]
                    .env
                    .as_mut()
                    .unwrap()[0]
                    .value = Some("/".into())
            }
            Departure::AnotherAccount => pod.service_account_name = Some("polar".into()),
            Departure::TokenMounted => pod.automount_service_account_token = Some(true),
            Departure::AnotherNode => {
                pod.node_selector = Some(BTreeMap::from([("pool".into(), "core".into())]))
            }
            Departure::HostPathVolume => pod.volumes.as_mut().unwrap().push(
                serde_json::from_value(json!({"name": "h", "hostPath": {"path": "/"}})).unwrap(),
            ),
            Departure::SecretVolume => pod.volumes.as_mut().unwrap().push(
                serde_json::from_value(json!({"name": "s", "secret": {"secretName": "s"}}))
                    .unwrap(),
            ),
            Departure::ExtraContainer => pod.containers.push(Container {
                name: "sidecar".into(),
                ..Default::default()
            }),
            Departure::ExtraInitContainer => {
                pod.init_containers.as_mut().unwrap().push(Container {
                    name: "first".into(),
                    ..Default::default()
                })
            }
            Departure::AnnotationAdded => {
                template.metadata.as_mut().unwrap().annotations =
                    Some(BTreeMap::from([("a".into(), "b".into())]))
            }
            Departure::TemplateLabelChanged => {
                template
                    .metadata
                    .as_mut()
                    .unwrap()
                    .labels
                    .as_mut()
                    .unwrap()
                    .insert("name".into(), "other".into());
            }
            _ => {}
        }
    }

    proptest! {
        /// The pipeline gets exactly what its mapping asks beyond hardened, and never a privileged container; the fetch
        /// gets none of it, whatever the mapping asks.
        #[test]
        fn a_mappings_privileges_reach_the_pipeline_alone_and_exactly(privileges in any_privileges()) {
            let mut build = spec(git());
            build.privileges = privileges.clone();
            let job = built(&build);
            let pipeline = container(&job, PIPELINE).security_context.clone().unwrap();
            prop_assert_eq!(pipeline.privileged, Some(false));
            prop_assert_eq!(pipeline.run_as_non_root, Some(!privileges.run_as_root));
            prop_assert_eq!(pipeline.run_as_user, (!privileges.run_as_root).then_some(1000));
            prop_assert_eq!(pipeline.allow_privilege_escalation, Some(privileges.allow_privilege_escalation));
            let caps = pipeline.capabilities.unwrap();
            prop_assert_eq!(caps.drop, Some(vec!["ALL".to_string()]));
            prop_assert_eq!(caps.add.unwrap_or_default(), privileges.add_capabilities);
            let template_fetch = template().template.unwrap().spec.unwrap().init_containers.unwrap().remove(0);
            let fetch = container(&job, FETCH).security_context.clone().unwrap();
            prop_assert_eq!(fetch, security_context(template_fetch.security_context.as_ref(), &Privileges::default()));
        }

        /// Whatever a build is (its source, its mapping's privileges, its variables, its command), the Job made from the
        /// template departs from it nowhere a build may not change it.
        #[test]
        fn a_job_made_from_its_template_departs_from_it_nowhere(build in any_build()) {
            let job = built(&build);
            prop_assert_eq!(departures(&template(), &job, &build.privileges), Vec::<String>::new());
        }

        /// Any one change a build may not make is found, whatever the build.
        #[test]
        fn any_change_a_build_may_not_make_is_found(
            build in any_build(),
            how in proptest::sample::select(DEPARTURES.to_vec()),
        ) {
            let mut job = built(&build);
            depart(&mut job, how);
            prop_assert!(!departures(&template(), &job, &build.privileges).is_empty(), "{how:?} was not found");
        }
    }

    /// A Job whose one condition became true at `at` (seconds since the epoch).
    fn a_job_that_ended(condition: &str, status: &str, at: Option<i64>) -> Job {
        use k8s_openapi::api::batch::v1::{JobCondition, JobStatus};
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
        let mut job = built(&spec(git()));
        job.status = Some(JobStatus {
            conditions: Some(vec![JobCondition {
                type_: condition.to_string(),
                status: status.to_string(),
                last_transition_time: at
                    .map(|at| Time(k8s_openapi::jiff::Timestamp::from_second(at).unwrap())),
                ..Default::default()
            }]),
            ..Default::default()
        });
        job
    }

    const HOUR: i64 = 60 * 60;

    #[test]
    fn a_job_is_kept_for_as_long_as_its_outcome_is_retained() {
        let retention = Retention::default();
        let now = 100 * 24 * HOUR;
        let jobs = [
            a_job_that_ended("Complete", "True", Some(now - 2 * HOUR)),
            a_job_that_ended("Complete", "True", Some(now - HOUR / 2)),
            a_job_that_ended("Failed", "True", Some(now - 2 * HOUR)),
            a_job_that_ended("Failed", "True", Some(now - 25 * HOUR)),
        ];
        let gone: Vec<usize> = expired(&jobs, now, &retention)
            .iter()
            .map(|j| jobs.iter().position(|k| std::ptr::eq(k, *j)).unwrap())
            .collect();
        assert_eq!(
            gone,
            vec![0, 3],
            "an old success and a very old failure; a recent one of each stays"
        );
    }

    #[test]
    fn a_job_that_has_not_finished_is_never_expired() {
        let now = 100 * 24 * HOUR;
        let running = built(&spec(git()));
        let not_true = a_job_that_ended("Failed", "False", Some(now - 25 * HOUR));
        // A finished one with no time on its condition cannot be shown to be old.
        let untimed = a_job_that_ended("Complete", "True", None);
        assert!(expired(&[running, not_true, untimed], now, &Retention::default()).is_empty());
    }

    #[test]
    fn kubernetes_keeps_a_finished_job_as_long_as_the_longest_retention() {
        let mut options = options();
        options.retention = Retention {
            succeeded: std::time::Duration::from_secs(600),
            failed: std::time::Duration::from_secs(7200),
        };
        let job = build_job(&template(), &spec(git()), &options).unwrap();
        assert_eq!(job.spec.unwrap().ttl_seconds_after_finished, Some(7200));
    }
}
