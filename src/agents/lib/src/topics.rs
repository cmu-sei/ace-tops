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

//! Canonical Cassini topic names for the Polar system.
//!
//! Topics are named after the data they carry, not the agents that consume them.
//! A topic is a logical channel — its name should describe what flows through it,
//! not which supervisor happens to be subscribed today.
//!
//! All topic strings follow the `polar.<domain>.<subject>` convention.
//! Agents must use these constants rather than hardcoding strings — a typo
//! in a topic name produces a silent failure that is very hard to debug.
//!
//! ## Current topology
//!
//! ```text
//! polar.provenance.events       ← what builds report, build-processor subscribes
//! polar.provenance.resolutions  ← the resolver alone publishes, build-processor subscribes
//! polar.provenance.discovery    ← observer agents publish, resolver subscribes
//! polar.git.repositories      ← git observer publishes, git processor subscribes
//! ```

// ── Provenance ─────────────────────────────────────────────────────────────────

/// What builds report: executions and stages, what they produced, what scanners found. Build pipelines
/// (nushell and Rust) publish here; build-processor subscribes. What a registry serves is not said here:
/// that is the resolver's word, on [`PROVENANCE_RESOLUTIONS`], and build-processor believes it nowhere else.
///
/// Wire formats accepted on this topic:
/// - rkyv-serialized [`ProvenanceEvent`] (Rust agents)
/// - JSON-serialized [`ProvenanceEvent`] (nushell pipeline stages)
pub const PROVENANCE_EVENTS: &str = "polar.provenance.events";

/// What the build orchestrator observed of a build it ran: that it started, completed, failed or was cancelled. Its own
/// word, not a build's claim, so its own topic: the orchestrator alone declares it, and a build that prints an execution
/// event has it refused (docs/architecture/build-orchestrator.md, "Settled with it", two topics). build-processor is to
/// believe executions only here (O2e3).
pub const PROVENANCE_EXECUTIONS: &str = "polar.provenance.executions";

/// Provenance discovery requests.
///
/// Observer agents publish [`ProvenanceEvent::OCIArtifactDiscovered`] and
/// [`ProvenanceEvent::ImageRefDiscovered`] here to trigger resolution.
/// The resolver subscribes exclusively to this topic, fetches manifests,
/// and publishes what it verified on [`PROVENANCE_RESOLUTIONS`].
pub const PROVENANCE_DISCOVERY: &str = "polar.provenance.discovery";

/// What the OCI resolver verified a registry serves ([`ProvenanceEvent::OCIArtifactResolved`]). Its own topic so that
/// who may say it is decided as for any topic, by the broker's policy and the certificate floor on the publisher's
/// broker-stamped identity: the resolver alone declares it. build-processor subscribes, and believes registry facts
/// only from here.
pub const PROVENANCE_RESOLUTIONS: &str = "polar.provenance.resolutions";

// ── Git ────────────────────────────────────────────────────────────────────────

/// Git repository observation events.
///
/// The git observer publishes [`GitRepositoryUpdatedEvent`] and
/// [`GitRepositoryDiscoveredEvent`] here. The git processor and any
/// agent that triggers on new commits subscribes here.
pub const GIT_REPOSITORY_DISCOVERED: &str = "polar.git.repositories.discovery";

pub const GIT_REPOSITORY_EVENTS: &str = "polar.git.repositories.events";

// TODO: Replace "cluster" with a cluster id. Chances are we won't get away wtih constants the moment someone wants to observe multiple clusters
pub const KUBERNETES_RESOLUTION_EVENTS: &str = "polar.kubernetes.cluster.resolution";
