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

//! Builds whose end never came. A build whose latest state is `started`, and that nothing has been heard of (its
//! state or any of its stages) for longer than the bound in force (`settings::LOST_AFTER_SECS`), is judged lost:
//! `lost_at`, `lost_after_secs` and `lost_by` are set on its BuildJob, plainly this processor's inference, and the
//! state history keeps only what reporters said. Any later event of the build clears the judgement
//! (`project::execution`), so a late end wins. Whether a build is still doing anything is a monitoring signal (CPU,
//! network, disk); until that is read, a bounded time ends it.

use crate::AGENT_NAME;
use chrono::{DateTime, Utc};
use polar::graph::controller::{GraphOp, GraphValue, IntoGraphKey, Property};
use polar::graph::nodes::builds::BuildNodeKey;
use std::time::Duration;

/// The query for builds started and not heard of since `cutoff` (a time kept as `project` keeps one), and not yet
/// judged lost. It reads only this processor's own labels.
pub fn stale_builds(cutoff: &str) -> neo4rs::Query {
    neo4rs::query(
        "MATCH (j:BuildJob)-[:TRANSITIONED_TO]->(s:BuildJobState) \
         WHERE j.lost_at IS NULL \
         WITH j, s ORDER BY s.valid_from DESC \
         WITH j, collect(s)[0] AS latest \
         WHERE latest.phase = 'started' \
         OPTIONAL MATCH (j)-[:HAS_STAGE]->(st:BuildStage) \
         WITH j, latest, collect(st.started_at) + collect(st.completed_at) AS stage_times \
         WITH j, reduce(last = latest.valid_from, t IN stage_times | CASE WHEN t > last THEN t ELSE last END) AS last_heard \
         WHERE last_heard < $cutoff \
         RETURN j.build_id AS build_id",
    )
    .param("cutoff", cutoff)
}

/// The time before which a build not heard of is lost, kept as `project` keeps a time.
pub fn cutoff(now: DateTime<Utc>, lost_after: Duration) -> String {
    let lost_after = chrono::Duration::from_std(lost_after).unwrap_or(chrono::Duration::MAX);
    now.checked_sub_signed(lost_after)
        .unwrap_or(DateTime::<Utc>::MIN_UTC)
        .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

/// The judgement that `build_ids` are lost, made `now` under `lost_after`: one transaction, `None` for none.
pub fn judged_lost(
    build_ids: Vec<String>,
    now: DateTime<Utc>,
    lost_after: Duration,
) -> Option<GraphOp> {
    let at = now.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    let ops: Vec<GraphOp> = build_ids
        .into_iter()
        .map(|build_id| GraphOp::UpsertNode {
            key: BuildNodeKey::BuildJob { build_id }.into_key(),
            props: vec![
                Property("lost_at".into(), GraphValue::String(at.clone())),
                Property(
                    "lost_after_secs".into(),
                    GraphValue::I64(lost_after.as_secs() as i64),
                ),
                Property("lost_by".into(), GraphValue::String(AGENT_NAME.into())),
            ],
        })
        .collect();
    (!ops.is_empty()).then_some(GraphOp::Transaction { ops })
}

/// What clears the judgement: any event of the build that comes after it.
pub fn heard_from() -> Vec<Property> {
    ["lost_at", "lost_after_secs", "lost_by"]
        .into_iter()
        .map(|name| Property(name.into(), GraphValue::Null))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar::graph::controller::compile_graph_op;

    fn instant(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    #[test]
    fn the_cutoff_is_the_bound_before_now_kept_as_a_time_is() {
        assert_eq!(
            cutoff(instant("2026-11-08T12:00:00Z"), Duration::from_secs(86_400)),
            "2026-11-07T12:00:00.000000000Z"
        );
        // A bound beyond any time judges nothing lost, rather than wrapping.
        assert_eq!(
            cutoff(instant("2026-11-08T12:00:00Z"), Duration::MAX),
            DateTime::<Utc>::MIN_UTC.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
        );
    }

    #[test]
    fn a_judgement_names_when_under_which_bound_and_whose_it_is() {
        assert!(
            judged_lost(
                vec![],
                instant("2026-11-08T12:00:00Z"),
                Duration::from_secs(60)
            )
            .is_none()
        );
        let op = judged_lost(
            vec!["b1".into(), "b2".into()],
            instant("2026-11-08T12:00:00Z"),
            Duration::from_secs(86_400),
        )
        .unwrap();
        let written = format!("{op:?}");
        for expected in [
            r#"build_id: "b1""#,
            r#"build_id: "b2""#,
            r#"Property("lost_at", String("2026-11-08T12:00:00.000000000Z"))"#,
            r#"Property("lost_after_secs", I64(86400))"#,
            r#"Property("lost_by", String("build-processor"))"#,
        ] {
            assert!(written.contains(expected), "{expected} not in {written}");
        }
        compile_graph_op(&op).unwrap();
    }
}
