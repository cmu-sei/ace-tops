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

//! Kubernetes Job manifest construction for a build (docs/architecture/build-orchestrator.md).
//!
//! # Job anatomy
//!
//! ```text
//! initContainers:
//!   - <the identity's>     ← the pod's own certificate, before anything else runs
//!   - name: fetch          ← the source archive from Polar's registry, checked against its digest, into /workspace
//! containers:
//!   - name: pipeline       ← runs the pipeline image against /workspace
//! volumes:
//!   - name: workspace      ← emptyDir shared between the fetch and the pipeline
//! ```
//!
//! The fetch runs to completion before the pipeline starts. If it fails, or the archive does not have its digest, the
//! Job fails and the pipeline never starts: a build that cannot have its source does not proceed.
//!
//! # No credential
//!
//! The orchestrator fetched the source from where the request said, through its own protocol handlers, which hold any
//! credential, and put it in the registry as an archive by digest (decision 1). The pod is told only that blob and its
//! digest: no Secret, no credential volume, no token in any environment. The certificate the pod is issued is its
//! own, as an instance of the build workload (decision 3).
//!
//! # Security posture
//!
//! - Every container hardened: non-root, no privilege escalation, every capability dropped, the default seccomp
//!   profile, a read-only root filesystem writing only its workspace and /tmp. The pipeline container gets only what
//!   the repository's signed mapping asks for beyond that (`Privileges`, decision 4), and is never privileged.
//! - No ServiceAccount token mounted: no container has Kubernetes API access.
//! - restartPolicy=Never: retries are the orchestrator's decision, not Kubernetes's.

use k8s_openapi::{
    api::{
        batch::v1::{Job, JobSpec},
        core::v1::{
            Capabilities, Container, EmptyDirVolumeSource, EnvVar, PodSecurityContext, PodSpec,
            PodTemplateSpec, ResourceRequirements, SeccompProfile, SecretVolumeSource,
            SecurityContext, Volume, VolumeMount,
        },
    },
    apimachinery::pkg::{api::resource::Quantity, apis::meta::v1::ObjectMeta},
};
use orchestrator_core::WORKSPACE_PATH;
use orchestrator_core::backend::Retention;
use orchestrator_core::types::{BuildSpec, Privileges, SourceRef};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Name of the emptyDir volume shared between the fetch and the pipeline.
const WORKSPACE_VOLUME: &str = "workspace";
/// Scratch emptyDir mounted at /tmp, since root filesystems are read-only. The cassini daemon's socket and queue live
/// here.
const TMP_VOLUME: &str = "tmp";

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

/// The pod additions that give each job a certificate of its own, as an instance of the build workload: the
/// `polar-init` init container with its projected token, the volume the certificate is written to, and what the
/// pipeline container is told. Kubernetes' own camelCase JSON.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobIdentity {
    /// Run before the fetch, with the token the pod's ServiceAccount is given.
    #[serde(default)]
    pub init_containers: Vec<Container>,
    #[serde(default)]
    pub volumes: Vec<Volume>,
    /// Where the pipeline container finds its certificate.
    #[serde(default)]
    pub pipeline_mounts: Vec<VolumeMount>,
    #[serde(default)]
    pub pipeline_env: Vec<EnvVar>,
}

impl JobIdentity {
    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }
}

/// Derives a deterministic, DNS-safe Job name from a build ID.
/// Kubernetes names must be <= 63 chars, lowercase alphanumeric and hyphens.
/// A UUID is 36 chars; with the prefix "build-" that is 42.
pub fn job_name_for_build(build_id: Uuid) -> String {
    format!("build-{}", build_id)
}

// ── Pipeline job ──────────────────────────────────────────────────────────────

/// Everything about a job that comes from the deployment rather than from the build request.
#[derive(Debug, Clone)]
pub struct JobOptions {
    /// Namespace jobs are created in.
    pub namespace: String,
    /// The build workload's ServiceAccount, which every build pod runs under: one workload of many instances, each
    /// pod a certificate and a broker session of its own (decision 3).
    pub account: String,
    /// The certificate each pod is issued, as an instance of that workload.
    pub identity: JobIdentity,
    /// The fetch container's image, pinned by digest: it reads the source archive from the registry, checks its
    /// digest and unpacks it.
    pub fetch_image: String,
    /// Secret whose `ca-bundle.crt` becomes both containers' trust store
    /// (see `trust_ca_bundle`). For TLS-inspecting proxies.
    pub ca_bundle_secret: Option<String>,
    /// Requests and limits for the pipeline container.
    pub resources: PipelineResources,
    /// Size limit of the workspace emptyDir, e.g. "2Gi". None means no limit,
    /// so a large repo or archive can fill the node's disk.
    pub workspace_size_limit: Option<String>,
    /// `Always`, `IfNotPresent` or `Never` for the fetch and pipeline images.
    pub image_pull_policy: Option<String>,
    /// How long finished jobs are kept. The orchestrator applies it by outcome (`expired`); Kubernetes' own expiry
    /// on each Job is set to the longest of them, so that jobs are still collected if the orchestrator is not
    /// running to apply it.
    pub retention: Retention,
}

impl JobOptions {
    /// Options with the default pipeline resources and no CA bundle or workspace limit.
    pub fn new(
        namespace: impl Into<String>,
        account: impl Into<String>,
        identity: JobIdentity,
        fetch_image: impl Into<String>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            account: account.into(),
            identity,
            fetch_image: fetch_image.into(),
            ca_bundle_secret: None,
            resources: PipelineResources::default(),
            workspace_size_limit: None,
            image_pull_policy: None,
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

/// Constructs a batch/v1 Job manifest for a build: the identity's init containers, the fetch of the source archive,
/// and the pipeline, under the build workload's account.
pub fn build_job_manifest(spec: &BuildSpec, options: &JobOptions) -> Job {
    let (labels, annotations) = standard_metadata(spec);
    let identity = &options.identity;

    let mut fetch = fetch_init_container(spec);
    fetch.image = Some(options.fetch_image.clone());
    fetch.image_pull_policy = options.image_pull_policy.clone();
    harden(&mut fetch, &Privileges::default());

    let mut pipeline = Container {
        name: "pipeline".to_string(),
        image: Some(spec.pipeline_image.clone()),
        image_pull_policy: options.image_pull_policy.clone(),
        // None runs the image's own CMD/ENTRYPOINT; otherwise it overrides it.
        command: spec.entrypoint.clone(),
        env: Some(
            pipeline_env_vars(spec)
                .into_iter()
                .chain(identity.pipeline_env.iter().cloned())
                .collect(),
        ),
        resources: Some(pipeline_resources(&options.resources)),
        volume_mounts: Some(
            identity
                .pipeline_mounts
                .iter()
                .cloned()
                // A git build's pipeline writes beside its source (its artifacts, its build directory); only an
                // archive, which is third-party code under analysis, gets the source read-only.
                .chain([workspace_volume_mount(matches!(
                    spec.source,
                    SourceRef::RegistryArchive { .. }
                ))])
                .collect(),
        ),
        ..Default::default()
    };
    harden(&mut pipeline, &spec.privileges);

    let mut volumes = vec![
        workspace_volume(options.workspace_size_limit.as_deref()),
        tmp_volume(),
    ];
    volumes.extend(identity.volumes.iter().cloned());
    if let Some(secret_name) = options.ca_bundle_secret.as_deref() {
        volumes.push(ca_bundle_volume(secret_name));
        for container in [&mut fetch, &mut pipeline] {
            trust_ca_bundle(container);
        }
    }

    // The certificate is obtained before anything else runs, and before the source is fetched.
    let init_containers: Vec<Container> = identity
        .init_containers
        .iter()
        .cloned()
        .chain([fetch])
        .collect();

    let pod_spec = PodSpec {
        init_containers: Some(init_containers),
        service_account_name: Some(options.account.clone()),
        containers: vec![pipeline],
        volumes: Some(volumes),
        // The fetch runs as non-root, so the workspace it unpacks into is the group's.
        security_context: Some(PodSecurityContext {
            fs_group: Some(65532),
            ..Default::default()
        }),
        restart_policy: Some("Never".to_string()),
        // No ServiceAccount token: no container has Kubernetes API access.
        automount_service_account_token: Some(false),
        ..Default::default()
    };

    assemble_job(
        job_name_for_build(spec.build_id),
        &options.namespace,
        labels,
        annotations,
        pod_spec,
        options.retention.longest(),
    )
}

// ── Fetch container ─────────────────────────────────────────────────────────────

/// The source-fetch init container. It reads the source archive from Polar's registry, checks it against its digest
/// (`CYCLOPS_SOURCE_SHA256`), and only then unpacks it into WORKSPACE_PATH. It is told the blob and its digest and
/// nothing of where the source came from, and holds no credential: the registry is read anonymously from inside the
/// cluster.
fn fetch_init_container(spec: &BuildSpec) -> Container {
    let env: Vec<EnvVar> = spec
        .archive
        .fetch_env()
        .into_iter()
        .chain([("CYCLOPS_WORKSPACE".to_string(), WORKSPACE_PATH.to_string())])
        .map(|(name, value)| EnvVar {
            name,
            value: Some(value),
            ..Default::default()
        })
        .collect();
    Container {
        name: "fetch".to_string(),
        env: Some(env),
        resources: Some(fetch_resources()),
        volume_mounts: Some(vec![VolumeMount {
            name: WORKSPACE_VOLUME.to_string(),
            mount_path: WORKSPACE_PATH.to_string(),
            read_only: Some(false),
            ..Default::default()
        }]),
        ..Default::default()
    }
}

fn pipeline_env_vars(spec: &BuildSpec) -> Vec<EnvVar> {
    let var = |name: &str, value: String| EnvVar {
        name: name.to_string(),
        value: Some(value),
        ..Default::default()
    };
    [
        var("POLAR_BUILD_ID", spec.build_id.to_string()),
        var("BUILD_WORKSPACE", WORKSPACE_PATH.to_string()),
    ]
    .into_iter()
    .chain(
        spec.source
            .pipeline_env()
            .into_iter()
            .map(|(name, value)| var(&name, value)),
    )
    .chain(spec.env.iter().map(|(k, v)| var(k, v.clone())))
    .collect()
}

fn workspace_volume(size_limit: Option<&str>) -> Volume {
    Volume {
        name: WORKSPACE_VOLUME.to_string(),
        empty_dir: Some(EmptyDirVolumeSource {
            medium: None,
            size_limit: size_limit.map(|q| Quantity(q.to_string())),
        }),
        ..Default::default()
    }
}

fn workspace_volume_mount(read_only: bool) -> VolumeMount {
    VolumeMount {
        name: WORKSPACE_VOLUME.to_string(),
        mount_path: WORKSPACE_PATH.to_string(),
        read_only: Some(read_only),
        ..Default::default()
    }
}

/// A container's security context: hardened, with only what `privileges` asks for beyond that, and never privileged.
fn security_context(privileges: &Privileges) -> SecurityContext {
    SecurityContext {
        privileged: Some(false),
        run_as_non_root: Some(!privileges.run_as_root),
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
    container.security_context = Some(security_context(privileges));
    container
        .volume_mounts
        .get_or_insert_with(Vec::new)
        .push(tmp_volume_mount());
}

const CA_BUNDLE_VOLUME: &str = "ca-bundle";
const CA_BUNDLE_DIR: &str = "/etc/build-orchestrator/ca";
const CA_BUNDLE_KEY: &str = "ca-bundle.crt";

fn ca_bundle_volume(secret_name: &str) -> Volume {
    Volume {
        name: CA_BUNDLE_VOLUME.to_string(),
        secret: Some(SecretVolumeSource {
            secret_name: Some(secret_name.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Points each tool's trust store at the CA bundle: git, curl, Nix and Cargo each read their own variable.
fn trust_ca_bundle(container: &mut Container) {
    let bundle = format!("{CA_BUNDLE_DIR}/{CA_BUNDLE_KEY}");
    let env = container.env.get_or_insert_with(Vec::new);
    for name in [
        "SSL_CERT_FILE",
        "GIT_SSL_CAINFO",
        "CURL_CA_BUNDLE",
        "NIX_SSL_CERT_FILE",
        "CARGO_HTTP_CAINFO",
    ] {
        env.push(EnvVar {
            name: name.to_string(),
            value: Some(bundle.clone()),
            ..Default::default()
        });
    }
    container
        .volume_mounts
        .get_or_insert_with(Vec::new)
        .push(VolumeMount {
            name: CA_BUNDLE_VOLUME.to_string(),
            mount_path: CA_BUNDLE_DIR.to_string(),
            read_only: Some(true),
            ..Default::default()
        });
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
        mount_path: "/tmp".to_string(),
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

fn assemble_job(
    job_name: String,
    namespace: &str,
    labels: BTreeMap<String, String>,
    annotations: BTreeMap<String, String>,
    pod_spec: PodSpec,
    keep_finished: std::time::Duration,
) -> Job {
    let pod_template = PodTemplateSpec {
        metadata: Some(ObjectMeta {
            labels: Some(labels.clone()),
            ..Default::default()
        }),
        spec: Some(pod_spec),
    };
    Job {
        metadata: ObjectMeta {
            name: Some(job_name),
            namespace: Some(namespace.to_string()),
            labels: Some(labels),
            annotations: Some(annotations),
            ..Default::default()
        },
        spec: Some(JobSpec {
            template: pod_template,
            backoff_limit: Some(0),
            ttl_seconds_after_finished: Some(
                i32::try_from(keep_finished.as_secs()).unwrap_or(i32::MAX),
            ),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchestrator_core::types::{SourceArchive, source_env};
    use proptest::prelude::*;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const IDENTITY: &str = r#"{"initContainers":[{"name":"polar-init","image":"polar-init:latest","command":["polar-init"],"args":["--cert","client:/home/polar/certs:ecdsa-p256"],"volumeMounts":[{"name":"sa-token","mountPath":"/var/run/polar/token","readOnly":true},{"name":"polar-certs","mountPath":"/home/polar/certs"}]}],"volumes":[{"name":"sa-token","projected":{"sources":[{"serviceAccountToken":{"audience":"a","expirationSeconds":3600,"path":"token"}}]}},{"name":"polar-certs","emptyDir":{}}],"pipelineMounts":[{"name":"polar-certs","mountPath":"/home/polar/certs","readOnly":true}],"pipelineEnv":[{"name":"TLS_CLIENT_CERT","value":"/home/polar/certs/cert.pem"}]}"#;

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
        JobOptions::new(
            "polar-builds",
            "build-job",
            JobIdentity::from_json(IDENTITY).unwrap(),
            format!("localhost:30500/build-fetch@sha256:{HEX}"),
        )
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

    /// The fetch is told the blob and its digest and where to unpack it, and nothing else: not the origin, and no
    /// credential (decision 1).
    #[test]
    fn the_fetch_is_told_the_blob_its_digest_and_where_to_unpack_it() {
        for source in [git(), archive()] {
            let job = build_job_manifest(&spec(source), &options());
            let fetch = container(&job, "fetch");
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
            assert_eq!(
                fetch.image.as_deref(),
                Some(format!("localhost:30500/build-fetch@sha256:{HEX}").as_str())
            );
        }
    }

    /// No part of a build's Job holds a credential or a Secret of one: the only Secret a pod mounts is a CA bundle,
    /// and only when the deployment names one.
    #[test]
    fn no_part_of_the_job_holds_a_credential() {
        for source in [git(), archive()] {
            let job = build_job_manifest(&spec(source), &options());
            let pod = pod(&job);
            assert!(
                pod.volumes.iter().flatten().all(|v| v.secret.is_none()),
                "{:?}",
                pod.volumes
            );
            let manifest = serde_json::to_string(&job).unwrap().to_lowercase();
            for word in [
                "password",
                "credential",
                "git-credentials",
                "client-tls",
                "imagepullsecrets",
            ] {
                assert!(!manifest.contains(word), "{word} in {manifest}");
            }
            assert_eq!(pod.automount_service_account_token, Some(false));
        }
    }

    /// Every build runs under the build workload's account, with the certificate its pod is issued obtained before the
    /// source is fetched (decision 3).
    #[test]
    fn a_build_runs_under_the_build_workload_and_gets_its_certificate_first() {
        let job = build_job_manifest(&spec(git()), &options());
        let pod = pod(&job);
        assert_eq!(pod.service_account_name.as_deref(), Some("build-job"));
        let inits: Vec<&str> = pod
            .init_containers
            .iter()
            .flatten()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(inits, ["polar-init", "fetch"]);
        let pipeline = container(&job, "pipeline");
        assert!(env(pipeline).contains(&(
            "TLS_CLIENT_CERT".into(),
            Some("/home/polar/certs/cert.pem".into())
        )));
        let mounts = pipeline.volume_mounts.as_ref().unwrap();
        assert!(
            mounts
                .iter()
                .any(|m| m.name == "polar-certs" && m.read_only == Some(true))
        );
        assert!(
            mounts
                .iter()
                .any(|m| m.name == WORKSPACE_VOLUME && m.read_only == Some(false)),
            "a git build's pipeline writes beside its source"
        );
    }

    #[test]
    fn an_archive_build_reads_its_source_read_only() {
        let job = build_job_manifest(&spec(archive()), &options());
        let mounts = container(&job, "pipeline").volume_mounts.clone().unwrap();
        assert!(
            mounts
                .iter()
                .any(|m| m.name == WORKSPACE_VOLUME && m.read_only == Some(true))
        );
    }

    /// A git build is hardened as an archive build is, the fetch always (decision 4).
    #[test]
    fn every_container_of_every_build_runs_hardened() {
        for source in [git(), archive()] {
            let job = build_job_manifest(&spec(source), &options());
            for name in ["fetch", "pipeline"] {
                let c = container(&job, name);
                let sc = c.security_context.as_ref().unwrap();
                assert_eq!(sc.run_as_non_root, Some(true), "{name}");
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
                        .any(|m| m.mount_path == "/tmp"),
                    "{name} has no scratch space"
                );
            }
        }
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

    proptest! {
        /// The pipeline gets exactly what its mapping asks beyond hardened, and never a privileged container; the fetch
        /// gets none of it, whatever the mapping asks.
        #[test]
        fn a_mappings_privileges_reach_the_pipeline_alone_and_exactly(privileges in any_privileges()) {
            let mut build = spec(git());
            build.privileges = privileges.clone();
            let job = build_job_manifest(&build, &options());
            let pipeline = container(&job, "pipeline").security_context.clone().unwrap();
            prop_assert_eq!(pipeline.privileged, Some(false));
            prop_assert_eq!(pipeline.run_as_non_root, Some(!privileges.run_as_root));
            prop_assert_eq!(pipeline.allow_privilege_escalation, Some(privileges.allow_privilege_escalation));
            let caps = pipeline.capabilities.unwrap();
            prop_assert_eq!(caps.drop, Some(vec!["ALL".to_string()]));
            prop_assert_eq!(caps.add.unwrap_or_default(), privileges.add_capabilities);
            let fetch = container(&job, "fetch").security_context.clone().unwrap();
            prop_assert_eq!(fetch, security_context(&Privileges::default()));
        }
    }

    #[test]
    fn ca_bundle_secret_becomes_both_containers_trust_store() {
        let job = build_job_manifest(
            &spec(git()),
            &JobOptions {
                ca_bundle_secret: Some("proxy-ca".into()),
                ..options()
            },
        );
        assert!(
            pod(&job)
                .volumes
                .iter()
                .flatten()
                .any(|v| v.name == CA_BUNDLE_VOLUME
                    && v.secret.as_ref().unwrap().secret_name.as_deref() == Some("proxy-ca"))
        );
        for name in ["fetch", "pipeline"] {
            let c = container(&job, name);
            assert!(
                env(c).contains(&(
                    "GIT_SSL_CAINFO".into(),
                    Some("/etc/build-orchestrator/ca/ca-bundle.crt".into())
                )),
                "{name}"
            );
            assert!(
                c.volume_mounts
                    .iter()
                    .flatten()
                    .any(|m| m.mount_path == CA_BUNDLE_DIR),
                "{name}"
            );
        }
    }

    #[test]
    fn configured_resources_workspace_limit_and_pull_policy_apply() {
        let job = build_job_manifest(
            &spec(git()),
            &JobOptions {
                resources: PipelineResources {
                    cpu_limit: "1".into(),
                    memory_limit: "1Gi".into(),
                    cpu_request: "100m".into(),
                    memory_request: "128Mi".into(),
                },
                workspace_size_limit: Some("2Gi".into()),
                image_pull_policy: Some("IfNotPresent".into()),
                ..options()
            },
        );
        let pipeline = container(&job, "pipeline");
        let limits = pipeline
            .resources
            .as_ref()
            .unwrap()
            .limits
            .as_ref()
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
        for name in ["fetch", "pipeline"] {
            assert_eq!(
                container(&job, name).image_pull_policy.as_deref(),
                Some("IfNotPresent"),
                "{name}"
            );
        }
    }

    #[test]
    fn an_empty_command_runs_the_images_entrypoint_and_a_configured_one_overrides_it() {
        let job = build_job_manifest(&spec(git()), &options());
        assert_eq!(container(&job, "pipeline").command, None);
        let mut build = spec(git());
        build.entrypoint = Some(vec!["/bin/analyze".into(), "--deep".into()]);
        let job = build_job_manifest(&build, &options());
        assert_eq!(
            container(&job, "pipeline").command,
            Some(vec!["/bin/analyze".to_string(), "--deep".to_string()])
        );
    }

    #[test]
    fn job_env_and_the_source_reach_the_pipeline() {
        let mut build = spec(git());
        build.env.insert("EXTRA".into(), "1".into());
        let job = build_job_manifest(&build, &options());
        let e = env(container(&job, "pipeline"));
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

    /// A Job whose one condition became true at `at` (seconds since the epoch).
    fn a_job_that_ended(condition: &str, status: &str, at: Option<i64>) -> Job {
        use k8s_openapi::api::batch::v1::{JobCondition, JobStatus};
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
        let mut job = build_job_manifest(&spec(git()), &options());
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
        let running = build_job_manifest(&spec(git()), &options());
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
        let job = build_job_manifest(&spec(git()), &options);
        assert_eq!(job.spec.unwrap().ttl_seconds_after_finished, Some(7200));
    }
}
