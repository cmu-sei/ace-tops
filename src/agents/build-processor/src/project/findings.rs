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

//! Findings: facts about packages and artifacts, reported in a run's context.
//!
//! Reported by scanners (`scanning.nu`: cargo-audit and friends).
//!
//! ```text
//! (BuildJob)-[:REPORTED {at}]->(SecurityAdvisory)-[:IS]->(Finding)
//!                               (SecurityAdvisory)-[:AFFECTS {at}]->(Package)
//! (BuildJob)-[:REPORTED {at}]->(PackageStatus)-[:IS]->(Finding)
//!                               (PackageStatus)-[:CONCERNS {at}]->(Package)
//! (SecurityAdvisory | PackageStatus)-[:FOUND_IN {at}]->(BuildArtifact)   no package resolved
//! ```
//!
//! Each event is one RawQuery, so each finding is written atomically. Edges
//! are MERGEd on their endpoints and `at` is set only on creation, so a
//! replayed event never adds a second edge.

use neo4rs::BoltType;
use polar::graph::controller::GraphOp;
use polar::{PackageStatusFoundPayload, SecurityAdvisoryFoundPayload};
use tracing::trace;

/// Collect `(key, value)` pairs into the map a Cypher `SET n += $props` takes.
/// Absent optionals are left out rather than written as nulls.
fn props_map(props: Vec<(&str, BoltType)>) -> BoltType {
    BoltType::Map(props.into_iter().map(|(k, v)| (k.into(), v)).collect())
}

fn push_present(
    props: &mut Vec<(&'static str, BoltType)>,
    fields: Vec<(&'static str, Option<String>)>,
) {
    for (key, value) in fields {
        if let Some(value) = value {
            props.push((key, value.into()));
        }
    }
}

/// A known vulnerability or soundness advisory (RUSTSEC, GHSA, ...).
///
/// The AFFECTS edge is only written when the scanner's (name, version)
/// resolved to an SBOM purl in scanning.nu. Writing it with a null purl would
/// MERGE a garbage `Package {purl: null}` node.
pub fn security_advisory(p: SecurityAdvisoryFoundPayload, observed_at: &str) -> Vec<GraphOp> {
    trace!("SecurityAdvisoryFound: {} ({})", p.identifier, p.severity);

    let mut cypher = String::from(
        "MERGE (a:SecurityAdvisory { identifier: $identifier }) \
         SET a += $props \
         MERGE (f:Finding { type: \"Finding\" }) \
         MERGE (a)-[:IS]->(f) \
         MERGE (j:BuildJob { build_id: $build_id }) \
         MERGE (j)-[r:REPORTED]->(a) \
         SET r.at = coalesce(r.at, $observed_at)",
    );

    let mut props: Vec<(&str, BoltType)> = vec![
        ("identifier", p.identifier.clone().into()),
        ("severity", p.severity.into()),
    ];
    // NB: fix_version carries a semver constraint (">=x"), not a concrete
    // version; it is stored under the wire field's name.
    push_present(
        &mut props,
        vec![
            ("kind", p.kind),
            ("scanner", p.scanner),
            ("cve_id", p.cve_id),
            ("ghsa_id", p.ghsa_id),
            ("fix_version", p.fix_version),
            ("unaffected_constraint", p.unaffected_constraint),
            ("advisory_url", p.advisory_url),
        ],
    );

    let mut params: Vec<(String, BoltType)> = vec![
        ("identifier".into(), p.identifier.into()),
        ("build_id".into(), p.build_id.into()),
        ("observed_at".into(), observed_at.into()),
        ("props".into(), props_map(props)),
    ];
    if let Some(purl) = p.affected_package {
        cypher.push_str(
            " MERGE (p:Package { purl: $affected_purl }) \
              MERGE (a)-[af:AFFECTS]->(p) \
              SET af.at = coalesce(af.at, $observed_at)",
        );
        params.push(("affected_purl".into(), purl.into()));
    } else {
        found_in(&mut cypher, &mut params, "a", p.in_artifact);
    }
    vec![GraphOp::RawMergeWrite { cypher, params }]
}

/// A state-of-being fact about a package rather than a flaw: cargo-audit's
/// `unmaintained` today. Same shape as an advisory, but the package edge is
/// CONCERNS, not AFFECTS, and there is no severity.
pub fn package_status(p: PackageStatusFoundPayload, observed_at: &str) -> Vec<GraphOp> {
    trace!("PackageStatusFound: {} ({})", p.identifier, p.kind);

    let mut cypher = String::from(
        "MERGE (s:PackageStatus { identifier: $identifier }) \
         SET s += $props \
         MERGE (f:Finding { type: \"Finding\" }) \
         MERGE (s)-[:IS]->(f) \
         MERGE (j:BuildJob { build_id: $build_id }) \
         MERGE (j)-[r:REPORTED]->(s) \
         SET r.at = coalesce(r.at, $observed_at)",
    );

    let mut props: Vec<(&str, BoltType)> = vec![
        ("identifier", p.identifier.clone().into()),
        ("kind", p.kind.into()),
        ("package_name", p.package_name.into()),
        ("package_version", p.package_version.into()),
    ];
    push_present(
        &mut props,
        vec![("scanner", p.scanner), ("advisory_url", p.advisory_url)],
    );

    let mut params: Vec<(String, BoltType)> = vec![
        ("identifier".into(), p.identifier.into()),
        ("build_id".into(), p.build_id.into()),
        ("observed_at".into(), observed_at.into()),
        ("props".into(), props_map(props)),
    ];
    if let Some(purl) = p.affected_package {
        cypher.push_str(
            " MERGE (p:Package { purl: $affected_purl }) \
              MERGE (s)-[c:CONCERNS]->(p) \
              SET c.at = coalesce(c.at, $observed_at)",
        );
        params.push(("affected_purl".into(), purl.into()));
    } else {
        found_in(&mut cypher, &mut params, "s", p.in_artifact);
    }
    vec![GraphOp::RawMergeWrite { cypher, params }]
}

/// The fallback when a finding resolved to no package (pipeline-design-reference.md, 4.4): it is FOUND_IN the build
/// artifact it was found in, by content hash, when the scanner says which. `finding` is the Cypher variable bound to it.
fn found_in(
    cypher: &mut String,
    params: &mut Vec<(String, BoltType)>,
    finding: &str,
    in_artifact: Option<String>,
) {
    let Some(content_hash) = in_artifact.filter(|h| !h.is_empty()) else {
        return;
    };
    cypher.push_str(&format!(
        " MERGE (art:BuildArtifact {{ content_hash: $in_artifact }}) \
          MERGE ({finding})-[fi:FOUND_IN]->(art) \
          SET fi.at = coalesce(fi.at, $observed_at)"
    ));
    params.push(("in_artifact".into(), content_hash.into()));
}
