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

//! What the orchestrator relays of what a build printed (docs/architecture/build-orchestrator.md, revised 3, O2d3): a report
//! the reader has read (`orchestrator_report`, the gate, the parser and the check, proved), judged for what its values
//! mean, held to the build's bounds, and re-encoded as Polar's event, inside a [`BuildReport`] that names the build by the
//! orchestrator's own `build_id`. What is relayed is what Polar built from the report's values, never the bytes the build
//! wrote.

use orchestrator_report::Report;
use polar::events::{
    ArtifactProducedPayload, BinaryLinkedPayload, BuildReport, ContainerImageCreatedPayload,
    DependencyEdge, OciLayerEntry, PackageRef, PackageStatusFoundPayload, ProvenanceEvent,
    SbomGraphFragment, SecurityAdvisoryFoundPayload, StageOutcome,
};

/// How much one build may report: Dynamic signed settings, with these defaults (build-orchestrator.md, "Settled with it").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayBounds {
    /// Report lines, read or refused.
    pub reports: usize,
    /// Bytes of report lines, read or refused.
    pub bytes: u64,
}

impl Default for RelayBounds {
    fn default() -> Self {
        Self {
            reports: 10_000,
            bytes: 64 * 1024 * 1024,
        }
    }
}

/// Why a report line is not relayed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotRelayed {
    #[error("the build has reported as many lines as it may ({0})")]
    TooMany(usize),
    #[error("the build has reported as many bytes as it may ({0})")]
    TooMuch(u64),
    #[error("the report's {0} is not a sha256 digest (`sha256:` and 64 lower-case hex digits)")]
    NotADigest(&'static str),
    /// A fact whose name the build's mapping does not list, or one the orchestrator cannot tell the mapping of.
    #[error("the report is a fact its pipeline's mapping does not allow")]
    FactNotAllowed,
}

/// What one build has reported so far, and what it may still.
#[derive(Debug)]
pub struct Relay {
    build_id: String,
    bounds: RelayBounds,
    reports: usize,
    bytes: u64,
    refused: usize,
}

impl Relay {
    /// The relay for the build the orchestrator started as `build_id`.
    pub fn new(build_id: impl Into<String>, bounds: RelayBounds) -> Self {
        Self {
            build_id: build_id.into(),
            bounds,
            reports: 0,
            bytes: 0,
            refused: 0,
        }
    }

    /// Counts one report line of `len` bytes against the build's bounds, before it is read: a build past them has every
    /// further line refused unread.
    pub fn take(&mut self, len: usize) -> Result<(), NotRelayed> {
        if self.reports >= self.bounds.reports {
            self.refused += 1;
            return Err(NotRelayed::TooMany(self.bounds.reports));
        }
        let bytes = self.bytes.saturating_add(len as u64);
        if bytes > self.bounds.bytes {
            self.refused += 1;
            return Err(NotRelayed::TooMuch(self.bounds.bytes));
        }
        self.reports += 1;
        self.bytes = bytes;
        Ok(())
    }

    /// Notes a line the reader refused, for the build's tally.
    pub fn refuse(&mut self) {
        self.refused += 1;
    }

    /// How many of the build's report lines were not relayed.
    pub fn refused(&self) -> usize {
        self.refused
    }

    /// A report the reader read, judged for what its values mean and re-encoded for relaying, stamped with this build.
    pub fn relay(&mut self, report: Report) -> Result<BuildReport, NotRelayed> {
        if let Err(why) = judge(&report) {
            self.refused += 1;
            return Err(why);
        }
        Ok(BuildReport {
            build_id: self.build_id.clone(),
            report: event(report, &self.build_id),
        })
    }
}

/// Whether `value` is a sha256 digest as the pipeline writes one (`content-hash-file`): `sha256:` and 64 lower-case hex.
pub fn is_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// What a report's values must mean before it is relayed: every hash a graph key is made from a sha256 digest (an optional
/// one, when given). A purl is not judged here: an SBOM may name a component by none, and build-processor writes only those
/// that have one.
fn judge(report: &Report) -> Result<(), NotRelayed> {
    let digest = |field: &'static str, value: &str| {
        if is_digest(value) {
            Ok(())
        } else {
            Err(NotRelayed::NotADigest(field))
        }
    };
    let maybe = |field: &'static str, value: &str| {
        if value.is_empty() {
            Ok(())
        } else {
            digest(field, value)
        }
    };
    match report {
        Report::ArtifactProduced {
            artifact_content_hash,
            ..
        } => digest("artifact_content_hash", artifact_content_hash),
        Report::SbomAnalyzed(s) => digest("artifact_content_hash", &s.artifact_content_hash),
        Report::BinaryLinked {
            binary_content_hash,
            sbom_content_hash,
            binding_digest,
            ..
        } => {
            digest("binary_content_hash", binary_content_hash)?;
            digest("sbom_content_hash", sbom_content_hash)?;
            maybe("binding_digest", binding_digest)
        }
        Report::ContainerImageCreated(c) => {
            digest("tarball_hash", &c.tarball_hash)?;
            digest("config_digest", &c.config_digest)?;
            for layer in &c.layers {
                digest("diff_id", &layer.diff_id)?;
            }
            maybe("digest", &c.digest)
        }
        Report::StageStarted { .. }
        | Report::StageCompleted { .. }
        | Report::SecurityAdvisoryFound(_)
        | Report::PackageStatusFound(_) => Ok(()),
        // No mapping names a fact yet: every one is refused.
        Report::FactReported(_) => Err(NotRelayed::FactNotAllowed),
    }
}

fn package(p: orchestrator_report::PackageRef) -> PackageRef {
    PackageRef {
        purl: p.purl,
        name: p.name,
        version: p.version,
        component_type: p.component_type,
        license: p.license,
        source: p.source,
    }
}

/// The report as Polar's event, with `build_id` wherever the event has one.
fn event(report: Report, build_id: &str) -> ProvenanceEvent {
    let build_id = build_id.to_string();
    match report {
        Report::StageStarted {
            stage_name,
            stage_id,
            at,
        } => ProvenanceEvent::StageStarted {
            build_id,
            stage_name,
            stage_id,
            at,
        },
        Report::StageCompleted {
            stage_name,
            stage_id,
            duration_secs,
            outcome,
            at,
        } => ProvenanceEvent::StageCompleted {
            build_id,
            stage_name,
            stage_id,
            duration_secs,
            outcome: match outcome {
                orchestrator_report::StageOutcome::Succeeded => StageOutcome::Succeeded,
                orchestrator_report::StageOutcome::Failed => StageOutcome::Failed,
                orchestrator_report::StageOutcome::Skipped => StageOutcome::Skipped,
                orchestrator_report::StageOutcome::Cancelled => StageOutcome::Cancelled,
            },
            at,
        },
        Report::SecurityAdvisoryFound(a) => {
            ProvenanceEvent::SecurityAdvisoryFound(SecurityAdvisoryFoundPayload {
                build_id,
                severity: a.severity,
                identifier: a.identifier,
                in_artifact: a.in_artifact,
                kind: a.kind,
                scanner: a.scanner,
                affected_package: a.affected_package,
                cve_id: a.cve_id,
                ghsa_id: a.ghsa_id,
                fix_version: a.fix_version,
                unaffected_constraint: a.unaffected_constraint,
                advisory_url: a.advisory_url,
            })
        }
        Report::PackageStatusFound(p) => {
            ProvenanceEvent::PackageStatusFound(PackageStatusFoundPayload {
                build_id,
                kind: p.kind,
                identifier: p.identifier,
                package_name: p.package_name,
                package_version: p.package_version,
                in_artifact: p.in_artifact,
                affected_package: p.affected_package,
                advisory_url: p.advisory_url,
                scanner: p.scanner,
            })
        }
        Report::ArtifactProduced {
            artifact_content_hash,
            artifact_type,
            name,
            content_type,
        } => ProvenanceEvent::ArtifactProduced(ArtifactProducedPayload {
            artifact_content_hash,
            artifact_type,
            name,
            content_type,
            build_id: Some(build_id),
        }),
        Report::SbomAnalyzed(s) => ProvenanceEvent::SbomAnalyzed(SbomGraphFragment {
            artifact_content_hash: s.artifact_content_hash,
            filename: s.filename,
            root: s.root.map(package),
            components: s.components.into_iter().map(package).collect(),
            edges: s
                .edges
                .into_iter()
                .map(|e| DependencyEdge {
                    from_ref: e.from_ref,
                    to_refs: e.to_refs,
                })
                .collect(),
        }),
        Report::BinaryLinked {
            binary_content_hash,
            binary_name,
            root_purl,
            sbom_content_hash,
            binding_digest,
        } => ProvenanceEvent::BinaryLinked(BinaryLinkedPayload {
            binary_content_hash,
            binary_name,
            root_purl,
            sbom_content_hash,
            binding_digest,
        }),
        Report::ContainerImageCreated(c) => {
            ProvenanceEvent::ContainerImageCreated(ContainerImageCreatedPayload {
                image_name: c.image_name,
                tarball_hash: c.tarball_hash,
                config_digest: c.config_digest,
                layers: c
                    .layers
                    .into_iter()
                    .map(|l| OciLayerEntry {
                        order: l.order,
                        diff_id: l.diff_id,
                        tar_path: l.tar_path,
                    })
                    .collect(),
                os: c.os,
                arch: c.arch,
                created: c.created,
                entrypoint: c.entrypoint,
                cmd: c.cmd,
                repo_tags: c.repo_tags,
                digest: c.digest,
                uri: c.uri,
            })
        }
        Report::FactReported(_) => unreachable!("a fact is refused before it is re-encoded"),
    }
}
