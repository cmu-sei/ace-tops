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

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Cassini subjects the orchestrator agents are interested in
/// Mirrors the subject constants defined in build-orchestrator-core.
pub mod subjects {
    pub const BUILD_REQUESTS_TOPIC: &str = "polar.orchestrator.builds.requests";
}

// ── Source references ─────────────────────────────────────────────────────────

/// Env var names shared between the orchestrator, the source-fetch init container and the pipeline. Both sides must
/// agree on these.
pub mod source_env {
    /// For the fetch: the source archive in Polar's registry, a blob reference pinned by digest.
    pub const SOURCE_BLOB: &str = "CYCLOPS_SOURCE_BLOB";
    /// For the fetch: the archive's sha256, lower-case hex, which it is checked against before it is unpacked.
    pub const SOURCE_SHA256: &str = "CYCLOPS_SOURCE_SHA256";
    /// For the pipeline: "git" or "archive", what the source was.
    pub const SOURCE_KIND: &str = "CYCLOPS_SOURCE_KIND";
    pub const ARCHIVE_SHA256: &str = "CYCLOPS_ARCHIVE_SHA256";
    pub const SOURCE_PURL: &str = "CYCLOPS_SOURCE_PURL";
}

/// What source a job runs against, and how to verify it.
///
/// Every variant pins content immutably — a commit SHA or a content hash,
/// never a branch, tag, or version string alone. The init container refuses
/// to populate the workspace if the fetched content does not match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceRef {
    /// A git repository at a specific commit. The CI path: triggered by
    /// repository events, the orchestrator acting as the authoritative builder.
    Git {
        /// Full HTTPS or SSH URL to the source repository.
        url: String,
        /// Full 40-character commit SHA. Never a branch name or tag — those are mutable.
        commit_sha: String,
    },
    /// A published package archive (e.g. a `.crate` from crates.io). The
    /// dependency-analysis path: this is the code that was actually compiled
    /// into downstream artifacts, which is not necessarily what is in the
    /// package's declared git repository.
    ///
    /// The archive must be a gzipped tarball with a single top-level
    /// directory (the layout used by crates.io, npm, and PyPI sdists).
    RegistryArchive {
        /// Package URL. Join key to the `Package` node in the graph.
        purl: String,
        /// HTTPS URL the archive is downloaded from.
        download_url: String,
        /// Lowercase hex sha256 of the archive bytes, e.g. the `checksum`
        /// from Cargo.lock.
        sha256: String,
    },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SourceRefError {
    #[error("commit_sha is not a valid 40-character hex SHA: {0}")]
    InvalidCommitSha(String),
    #[error("sha256 is not a valid 64-character lowercase hex digest: {0}")]
    InvalidSha256(String),
    #[error("archive download_url must be https: {0}")]
    InsecureDownloadUrl(String),
    #[error("purl must start with \"pkg:\": {0}")]
    InvalidPurl(String),
}

impl SourceRef {
    /// Check that the reference pins content immutably and can be fetched
    /// safely. Called at the request boundary so a bad reference fails the
    /// request, not the init container.
    pub fn validate(&self) -> Result<(), SourceRefError> {
        fn is_hex(s: &str, len: usize) -> bool {
            s.len() == len && s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
        }
        match self {
            SourceRef::Git { commit_sha, .. } => {
                if !is_hex(commit_sha, 40) {
                    return Err(SourceRefError::InvalidCommitSha(commit_sha.clone()));
                }
            }
            SourceRef::RegistryArchive {
                purl,
                download_url,
                sha256,
            } => {
                if !purl.starts_with("pkg:") {
                    return Err(SourceRefError::InvalidPurl(purl.clone()));
                }
                if !download_url.starts_with("https://") {
                    return Err(SourceRefError::InsecureDownloadUrl(download_url.clone()));
                }
                if !is_hex(sha256, 64) {
                    return Err(SourceRefError::InvalidSha256(sha256.clone()));
                }
            }
        }
        Ok(())
    }

    /// Where the source comes from, for logs and annotations.
    pub fn locator(&self) -> &str {
        match self {
            SourceRef::Git { url, .. } => url,
            SourceRef::RegistryArchive { download_url, .. } => download_url,
        }
    }

    /// The immutable content pin: commit SHA or archive sha256.
    pub fn revision(&self) -> &str {
        match self {
            SourceRef::Git { commit_sha, .. } => commit_sha,
            SourceRef::RegistryArchive { sha256, .. } => sha256,
        }
    }

    /// The `SOURCE_KIND` value for this reference.
    pub fn kind(&self) -> &'static str {
        match self {
            SourceRef::Git { .. } => "git",
            SourceRef::RegistryArchive { .. } => "archive",
        }
    }

    /// Source identity env vars for the pipeline container, so the job can
    /// attribute what it emits to the right source.
    pub fn pipeline_env(&self) -> Vec<(String, String)> {
        let mut env = vec![(source_env::SOURCE_KIND.to_string(), self.kind().to_string())];
        match self {
            SourceRef::Git { commit_sha, .. } => {
                env.push(("CI_COMMIT_SHORT_SHA".to_string(), commit_sha.clone()));
            }
            SourceRef::RegistryArchive { purl, sha256, .. } => {
                env.push((source_env::SOURCE_PURL.to_string(), purl.clone()));
                env.push((source_env::ARCHIVE_SHA256.to_string(), sha256.clone()));
            }
        }
        env
    }
}

/// Whether an image reference is pinned by digest: a name, then `@sha256:` and 64 lower-case hex digits. A tag can
/// move, so what a job runs is named this way; runtime attestation also refuses a container whose image is not.
pub fn pinned_by_digest(image: &str) -> bool {
    let Some((name, digest)) = image.rsplit_once('@') else {
        return false;
    };
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return false;
    };
    !name.is_empty() && hex.len() == 64 && hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

/// A build's source as its pod gets it: an archive in Polar's registry, a blob pinned by its digest. The orchestrator
/// fetched it from where the request said, through its own protocol handlers, which hold any credential; the pod
/// fetches only this, checks it against its digest, and unpacks it (docs/architecture/build-orchestrator.md,
/// decision 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceArchive {
    reference: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error(
    "a source archive is a registry blob pinned by its full sha256 digest (name@sha256:<64 hex>), got: {0}"
)]
pub struct UnpinnedArchive(pub String);

impl SourceArchive {
    pub fn new(reference: String) -> Result<Self, UnpinnedArchive> {
        if pinned_by_digest(&reference) {
            Ok(Self { reference })
        } else {
            Err(UnpinnedArchive(reference))
        }
    }

    /// The blob, `name@sha256:<hex>`.
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Its sha256, lower-case hex.
    pub fn sha256(&self) -> &str {
        self.reference
            .rsplit_once("@sha256:")
            .map(|(_, hex)| hex)
            .unwrap_or_default()
    }

    /// Env vars for the source-fetch init container: the blob and its digest, and nothing of where it came from.
    pub fn fetch_env(&self) -> Vec<(String, String)> {
        vec![
            (source_env::SOURCE_BLOB.to_string(), self.reference.clone()),
            (
                source_env::SOURCE_SHA256.to_string(),
                self.sha256().to_string(),
            ),
        ]
    }
}

/// What a build's pipeline container may do beyond running hardened (non-root, no privilege escalation, every
/// capability dropped, the default seccomp profile, writing only its workspace). None of it unless the repository's
/// signed mapping asks, so every exception is signed and on the record (decision 4). A privileged container is not
/// one of them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Privileges {
    #[serde(default)]
    pub run_as_root: bool,
    #[serde(default)]
    pub allow_privilege_escalation: bool,
    /// Linux capabilities added back, by their Kubernetes names (`SETUID`, not `CAP_SETUID`).
    #[serde(default)]
    pub add_capabilities: Vec<String>,
}

impl Privileges {
    /// What is wrong with them: a capability that is not a Kubernetes capability name, or `ALL`.
    pub fn problems(&self) -> Vec<String> {
        self.add_capabilities
            .iter()
            .filter(|c| {
                c.is_empty()
                    || c.as_str() == "ALL"
                    || c.starts_with("CAP_")
                    || !c.chars().all(|ch| ch.is_ascii_uppercase() || ch == '_')
            })
            .map(|c| format!("{c:?} is not a capability to add: a Kubernetes name, such as SETUID, and not ALL"))
            .collect()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BuildRequestError {
    #[error(transparent)]
    InvalidSource(#[from] SourceRefError),
    /// The graph records which analyzer image analyzed which package, so the
    /// image must identify immutable content — a tag can move.
    #[error("archive analysis requires an image pinned by digest (…@sha256:…), got: {0:?}")]
    UnpinnedAnalyzerImage(Option<String>),
}

impl BuildRequest {
    pub fn validate(&self) -> Result<(), BuildRequestError> {
        self.source.validate()?;
        if let SourceRef::RegistryArchive { .. } = self.source {
            let pinned = self.pipeline_image.as_deref().is_some_and(pinned_by_digest);
            if !pinned {
                return Err(BuildRequestError::UnpinnedAnalyzerImage(
                    self.pipeline_image.clone(),
                ));
            }
        }
        Ok(())
    }
}

/// The inbound payload published by Polar's scheduler onto the Cassini broker.
/// This is the authoritative wire format — do not add fields without versioning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildRequest {
    /// Stable identifier for this build. Generated by the scheduler.
    pub build_id: Uuid,

    /// The source to run against.
    pub source: SourceRef,

    /// Image to run, pinned by digest. When None, the orchestrator resolves
    /// the image from its repo mappings, which only exist for git sources —
    /// analysis requests against archives must name their analyzer image.
    #[serde(default)]
    pub pipeline_image: Option<String>,

    /// Wall-clock time the scheduler emitted this request.
    pub requested_at: DateTime<Utc>,

    /// Arbitrary key-value metadata forwarded from the scheduler.
    /// Used for forward-compatibility — do not rely on specific keys in core logic.
    #[serde(default)]
    pub metadata: HashMap<String, String>,

    pub command: Vec<String>,
}

/// The state machine for a single build lifecycle:
///   Pending
///     └─► PreparingSource   ← the orchestrator fetches the source and puts its archive in the registry
///           └─► Scheduled   ← the job is submitted to the backend
///                 └─► Running
///                       ├─► Succeeded
///                       └─► Failed
/// Cancelled is reachable from any state that has not ended, and Failed from any active one. Unreconciled is where a
/// job's record ends when the backend was lost while it was in flight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildState {
    /// Received and validated.
    Pending,

    /// Fetching the source through the orchestrator's protocol handlers and putting its archive in the registry.
    PreparingSource,

    /// The job is submitted to the backend.
    Scheduled,

    /// Backend has confirmed the job is actively running.
    Running,

    /// Job completed successfully.
    Succeeded,

    /// Job terminated with a failure at any stage.
    Failed,

    /// Cancelled before reaching a terminal state.
    Cancelled,
    /// Connectivity to the backend was lost while the job was in-flight.
    /// Terminal state of the record in this orchestrator instance.
    /// Requires reconciliation against backend state on reconnect
    /// before a new BuildRecord can be authoritatively issued.
    Unreconciled,
}

impl BuildState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }

    pub fn can_transition_to(&self, next: &BuildState) -> bool {
        use BuildState::*;
        matches!(
            (self, next),
            // Normal forward path
            (Pending, PreparingSource)
            | (PreparingSource, Scheduled)
            | (Scheduled, Running)
            | (Running, Succeeded)
            // Failure from any active state
            | (PreparingSource, Failed)
            | (Scheduled, Failed)
            | (Running, Failed)
            // Cancellation from any non-terminal state
            | (Pending, Cancelled)
            | (PreparingSource, Cancelled)
            | (Scheduled, Cancelled)
            | (Running, Cancelled)
            // Job actor loses connection to the backend, putting it in an unreconciled state
            | (Scheduled, Unreconciled)
            | (Running, Unreconciled)
        )
    }
}

impl std::fmt::Display for BuildState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            BuildState::Pending => "pending",
            BuildState::PreparingSource => "preparing_source",
            BuildState::Scheduled => "scheduled",
            BuildState::Running => "running",
            BuildState::Succeeded => "succeeded",
            BuildState::Failed => "failed",
            BuildState::Cancelled => "cancelled",
            BuildState::Unreconciled => "unreconciled",
        };
        write!(f, "{}", s)
    }
}

/// Operational record maintained in the registry actor for the duration of a build.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildRecord {
    pub build_id: Uuid,
    pub state: BuildState,
    pub request: BuildRequest,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Opaque handle returned by the backend on submission.
    /// None until Scheduled.
    pub backend_handle: Option<String>,
    /// Digest of the resolved pipeline image.
    /// Populated once the job is scheduled.
    pub resolved_image: Option<String>,
    /// Human-readable reason for failure or cancellation, if applicable.
    pub failure_reason: Option<String>,
}

impl BuildRecord {
    pub fn new(request: BuildRequest) -> Self {
        let now = Utc::now();
        Self {
            build_id: request.build_id,
            state: BuildState::Pending,
            request,
            created_at: now,
            updated_at: now,
            backend_handle: None,
            resolved_image: None,
            failure_reason: None,
        }
    }

    pub fn transition(&mut self, next: BuildState) -> Result<(), crate::error::CyclopsError> {
        if self.state.can_transition_to(&next) {
            tracing::debug!(
                build_id = %self.build_id,
                from = %self.state,
                to = %next,
                "build state transition"
            );
            self.state = next;
            self.updated_at = Utc::now();
            Ok(())
        } else {
            Err(crate::error::CyclopsError::InvalidStateTransition {
                from: self.state.clone(),
                to: next,
            })
        }
    }
}

/// Fully resolved specification handed to the backend for a pipeline job: the pipeline image is pinned by digest by
/// the repository's signed mapping, and the source is an archive in the registry, by digest.
///
/// Source code is NOT baked into the image. An init container fetches the source archive into a shared emptyDir volume
/// at /workspace before the pipeline container starts; it holds no credential (job.rs).
#[derive(Debug, Clone)]
pub struct BuildSpec {
    pub build_id: Uuid,
    /// What the source is, for the pipeline to say what it built.
    pub source: SourceRef,
    /// Where the pod gets it.
    pub archive: SourceArchive,

    /// Fully qualified pipeline image reference, pinned by digest.
    /// e.g. "registry.internal.example.com/builds/myapp@sha256:abc123..."
    /// The image must have /bin/pipeline-runner as its entrypoint.
    pub pipeline_image: String,

    /// Entrypoint override. None means the image's own CMD is used, which
    /// must be /bin/pipeline-runner. Only set this in tests.
    pub entrypoint: Option<Vec<String>>,

    /// What the pipeline container may do beyond running hardened, as the repository's signed mapping says.
    pub privileges: Privileges,

    /// Additional env vars injected into the pipeline container.
    /// Standard build-orchestrator vars (build ID, repo, commit, registry) are always
    /// injected by the manifest builder and should not be duplicated here.
    pub env: HashMap<String, String>,
}

impl BuildSpec {
    pub fn with_pipeline_runner(
        build_id: Uuid,
        source: SourceRef,
        archive: SourceArchive,
        pipeline_image: String,
        command: Vec<String>,
        privileges: Privileges,
    ) -> Self {
        Self {
            build_id,
            source,
            archive,
            pipeline_image,
            // An empty command means "run the image's own entrypoint" —
            // analyzer images define their own, unlike CI pipeline images.
            entrypoint: (!command.is_empty()).then_some(command),
            privileges,
            env: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod source_ref_tests {
    use super::*;
    use proptest::prelude::*;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

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

    fn blob() -> SourceArchive {
        SourceArchive::new(format!("localhost:30500/build-sources@sha256:{HEX}")).unwrap()
    }

    fn env_value(env: &[(String, String)], key: &str) -> Option<String> {
        env.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    }

    #[test]
    fn valid_refs_pass() {
        assert_eq!(git().validate(), Ok(()));
        assert_eq!(archive().validate(), Ok(()));
    }

    #[test]
    fn git_rejects_short_or_uppercase_sha() {
        for sha in ["abc123".to_string(), "A".repeat(40)] {
            let r = SourceRef::Git {
                url: "https://example.com/r.git".into(),
                commit_sha: sha,
            };
            assert!(matches!(
                r.validate(),
                Err(SourceRefError::InvalidCommitSha(_))
            ));
        }
    }

    #[test]
    fn archive_rejects_plain_http() {
        let mut r = archive();
        if let SourceRef::RegistryArchive { download_url, .. } = &mut r {
            *download_url = "http://static.crates.io/crates/serde/serde-1.0.219.crate".into();
        }
        assert!(matches!(
            r.validate(),
            Err(SourceRefError::InsecureDownloadUrl(_))
        ));
    }

    #[test]
    fn archive_rejects_bad_digest_and_purl() {
        let mut r = archive();
        if let SourceRef::RegistryArchive { sha256, .. } = &mut r {
            *sha256 = "z".repeat(64);
        }
        assert!(matches!(
            r.validate(),
            Err(SourceRefError::InvalidSha256(_))
        ));

        let mut r = archive();
        if let SourceRef::RegistryArchive { purl, .. } = &mut r {
            *purl = "serde@1.0.219".into();
        }
        assert!(matches!(r.validate(), Err(SourceRefError::InvalidPurl(_))));
    }

    /// The pod is told where its source is in the registry and what its digest is, and nothing of where it came from:
    /// it never reaches the origin (docs/architecture/build-orchestrator.md, decision 1).
    #[test]
    fn the_fetch_is_of_the_registry_blob_by_its_digest_alone() {
        let env = blob().fetch_env();
        assert_eq!(
            env_value(&env, source_env::SOURCE_BLOB),
            Some(format!("localhost:30500/build-sources@sha256:{HEX}"))
        );
        assert_eq!(
            env_value(&env, source_env::SOURCE_SHA256),
            Some(HEX.to_string())
        );
        assert_eq!(env.len(), 2, "{env:?}");
    }

    #[test]
    fn a_source_archive_is_a_blob_pinned_by_its_full_digest() {
        assert_eq!(blob().sha256(), HEX);
        for reference in [
            "localhost:30500/build-sources".to_string(),
            "localhost:30500/build-sources:latest".to_string(),
            "localhost:30500/build-sources@sha256:abc".to_string(),
            format!(
                "localhost:30500/build-sources@sha256:{}",
                HEX.to_uppercase()
            ),
        ] {
            assert!(
                SourceArchive::new(reference.clone()).is_err(),
                "{reference}"
            );
        }
    }

    #[test]
    fn the_pipeline_is_told_which_source_it_builds() {
        let env = git().pipeline_env();
        assert_eq!(
            env_value(&env, source_env::SOURCE_KIND).as_deref(),
            Some("git")
        );
        assert_eq!(env_value(&env, "CI_COMMIT_SHORT_SHA"), Some("a".repeat(40)));
        let env = archive().pipeline_env();
        assert_eq!(
            env_value(&env, source_env::SOURCE_PURL).as_deref(),
            Some("pkg:cargo/serde@1.0.219")
        );
    }

    fn request(source: SourceRef, pipeline_image: Option<&str>) -> BuildRequest {
        BuildRequest {
            build_id: Uuid::nil(),
            source,
            pipeline_image: pipeline_image.map(Into::into),
            requested_at: Utc::now(),
            metadata: HashMap::new(),
            command: vec![],
        }
    }

    #[test]
    fn archive_request_requires_digest_pinned_image() {
        for image in [
            None,
            Some("reg/analyzer:latest".to_string()),
            Some("reg/analyzer@sha256:abc".to_string()),
        ] {
            assert!(matches!(
                request(archive(), image.as_deref()).validate(),
                Err(BuildRequestError::UnpinnedAnalyzerImage(_))
            ));
        }
        assert_eq!(
            request(archive(), Some(&format!("reg/analyzer@sha256:{HEX}"))).validate(),
            Ok(())
        );
    }

    #[test]
    fn only_a_full_sha256_digest_pins_an_image() {
        assert!(pinned_by_digest(&format!("reg/x@sha256:{HEX}")));
        assert!(pinned_by_digest(&format!("reg/x:1.0@sha256:{HEX}")));
        for image in [
            "reg/x".to_string(),
            "reg/x:latest".to_string(),
            "reg/x@sha256:abc".to_string(),
            format!("reg/x@sha256:{}", HEX.to_uppercase()),
            format!("reg/x@sha512:{HEX}"),
            format!("@sha256:{HEX}"),
        ] {
            assert!(!pinned_by_digest(&image), "{image}");
        }
    }

    #[test]
    fn git_request_may_rely_on_repo_mapping() {
        assert_eq!(request(git(), None).validate(), Ok(()));
    }

    /// Who asked for a build is the broker-stamped publisher of its request, not a field of it.
    #[test]
    fn a_request_does_not_say_who_made_it() {
        let json = serde_json::to_value(request(git(), None)).unwrap();
        assert!(json.get("requested_by").is_none(), "{json}");
        let mut with_claim = json.clone();
        with_claim["requested_by"] = "someone else".into();
        let back: BuildRequest = serde_json::from_value(with_claim).unwrap();
        assert!(!format!("{back:?}").contains("someone else"));
    }

    #[test]
    fn serde_round_trip_is_tagged() {
        let json = serde_json::to_value(archive()).unwrap();
        assert_eq!(json["kind"], "registry_archive");
        let back: SourceRef = serde_json::from_value(json).unwrap();
        assert_eq!(back, archive());
    }

    /// A build runs hardened unless its signed mapping says what more it needs (decision 4).
    #[test]
    fn privileges_are_none_unless_asked_for() {
        let none = Privileges::default();
        assert!(
            !none.run_as_root
                && !none.allow_privilege_escalation
                && none.add_capabilities.is_empty()
        );
        assert!(none.problems().is_empty());
        let asked = Privileges {
            run_as_root: true,
            allow_privilege_escalation: false,
            add_capabilities: vec!["SETUID".into(), "SETGID".into()],
        };
        assert!(asked.problems().is_empty());
        for bad in ["setuid", "CAP_SETUID", "", "SYS ADMIN", "ALL"] {
            let p = Privileges {
                add_capabilities: vec![bad.into()],
                ..Privileges::default()
            };
            assert!(!p.problems().is_empty(), "{bad:?}");
        }
    }

    fn any_state() -> impl Strategy<Value = BuildState> {
        prop_oneof![
            Just(BuildState::Pending),
            Just(BuildState::PreparingSource),
            Just(BuildState::Scheduled),
            Just(BuildState::Running),
            Just(BuildState::Succeeded),
            Just(BuildState::Failed),
            Just(BuildState::Cancelled),
            Just(BuildState::Unreconciled),
        ]
    }

    proptest! {
        /// Whatever transitions are asked for, in whatever order, a build that has ended stays ended, one that is not
        /// may always be cancelled, and a refused transition leaves the record as it was.
        #[test]
        fn an_ended_build_stays_ended(asked in proptest::collection::vec(any_state(), 0..24)) {
            let mut record = BuildRecord::new(request(git(), None));
            for next in asked {
                let before = record.state.clone();
                if before.is_terminal() || before == BuildState::Unreconciled {
                    prop_assert!(record.transition(next.clone()).is_err(), "{before} -> {next}");
                    prop_assert_eq!(&record.state, &before);
                    continue;
                }
                prop_assert!(before.can_transition_to(&BuildState::Cancelled), "{before}");
                if record.transition(next.clone()).is_err() {
                    prop_assert_eq!(&record.state, &before);
                }
            }
        }
    }
}
