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

//! The attestation agent's evidence records (docs/architecture/record-store.md, "Attestation verdicts as records", bite B), as
//! pure functions of what it found and what it judges. Two kinds:
//!
//! - [`REPORT`], one for each finding as it is published on `attestation-reports`: an alteration, a crash by a signal, a
//!   panic. Crashes are the most valuable evidence there is: counter-evidence to the case that admitted the agent, to be
//!   explained.
//! - [`STANDING`], the cluster's standing, three verdicts with their witnesses: the agent has proved itself, the pods are
//!   genuine, what is deployed matches the signed record. Recorded when a verdict changes, and once a day regardless, so a
//!   reader sees it is fresh ([`StandingLog`]).
//!
//! Each is said in the envelope the other collectors' records share (`polar-sign`'s instance check): a `subject` whose values
//! name its place in the evidence repository, `verdicts` of `holds`, `violated` or `cannot-say` for a standing, and a
//! `result`. What a record says is the agent's own observation, never content it received (`polar_agent_builder::signer`).

use attestation_common::{Doubt, Drift, Finding, Proved, Report};
use polar_agent_builder::EvidenceRecord;
use serde_json::{Map, Value, json};

/// A finding, as a record.
pub const REPORT: &str = "attestation-report";
/// The cluster's standing, as a record.
pub const STANDING: &str = "attestation";
/// The types the agent records: its certificate's `c:record-evidence` names.
pub const RECORDS: &[&str] = &[STANDING, REPORT];

/// The longest a standing goes unrecorded while nothing changes.
pub const DAY_SECS: i64 = 24 * 60 * 60;

fn fields(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(fields) => fields,
        _ => unreachable!("a record's fields are an object"),
    }
}

/// What a finding is, by name, and what it says of the pod.
fn finding_of(finding: &Finding) -> (&'static str, Value) {
    match finding {
        Finding::Altered(why) => ("altered", json!({ "why": format!("{why:?}") })),
        Finding::Crashed {
            container,
            signal,
            exit_code,
            finished_at,
            image_id,
        } => (
            "crashed",
            json!({
                "container": container,
                "signal": format!("{signal:?}"),
                "exit_code": exit_code,
                "finished_at": finished_at,
                "image_id": image_id,
            }),
        ),
        Finding::Panicked {
            container,
            exit_code,
            finished_at,
            image_id,
        } => (
            "panicked",
            json!({
                "container": container,
                "exit_code": exit_code,
                "finished_at": finished_at,
                "image_id": image_id,
            }),
        ),
    }
}

/// `report`, found at `found_at` (seconds) in the cluster the deployment record names `target`, as a record: its subject the
/// target and the pod, the finding with what it says, whether the pod is under test, and a result that did not pass, since a
/// finding is something to explain.
pub fn report_record(target: &str, report: &Report, found_at: i64) -> EvidenceRecord {
    let (kind, says) = finding_of(&report.finding);
    let record = json!({
        "subject": { "target": target, "namespace": report.namespace, "pod": report.pod },
        "pod_uid": report.pod_uid,
        "finding": { "kind": kind, "says": says },
        "under_test": report.under_test,
        "result": {
            "passed": false,
            "problems": [format!("{}/{}: {kind}", report.namespace, report.pod)],
        },
        "found_at_unix_secs": found_at,
    });
    EvidenceRecord::new(REPORT, fields(record))
        .expect("a report record has a type and no `type` field")
}

/// What a standing verdict says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Said {
    Holds,
    Violated,
    /// The agent cannot say yet: it has not listed what it watches, or holds no record to compare with.
    CannotSay,
}

impl Said {
    pub fn as_str(self) -> &'static str {
        match self {
            Said::Holds => "holds",
            Said::Violated => "violated",
            Said::CannotSay => "cannot-say",
        }
    }
}

/// One verdict of the standing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub id: &'static str,
    pub statement: &'static str,
    pub said: Said,
    pub witness: Vec<String>,
}

pub const PROVED_ITSELF: &str = "agent-proved-itself";
pub const PODS_GENUINE: &str = "pods-genuine";
pub const MATCHES_RECORD: &str = "deployments-match-record";

/// The cluster's standing: whether the agent has proved itself (`proved`); whether the pods are genuine, by the alterations that
/// stand (`standing`, as `Reporting` holds it), which it judges only once it has proved itself; and whether what is deployed
/// matches the signed record, by the differences that have lasted (`lasting`), or none when it cannot compare (no record held, or
/// not everything listed). What is under test is said apart, and counts against neither.
pub fn standing(
    proved: &Result<Proved, Doubt>,
    standing: &[Report],
    lasting: Option<&[(Drift, bool)]>,
) -> Vec<Verdict> {
    let proved_itself = match proved {
        Ok(p) => (
            Said::Holds,
            vec![format!(
                "judged {} pods, condemned {}, {}",
                p.judged,
                p.condemned,
                if p.with_record {
                    "with the signed record"
                } else {
                    "with no signed record"
                }
            )],
        ),
        Err(Doubt::NotYet | Doubt::NotListed) => (Said::CannotSay, Vec::new()),
        Err(doubt) => (Said::Violated, vec![format!("{doubt:?}")]),
    };
    let genuine = if proved.is_ok() {
        let altered: Vec<String> = standing
            .iter()
            .filter(|r| !r.under_test && matches!(r.finding, Finding::Altered(_)))
            .map(|r| format!("{}/{} ({}): {:?}", r.namespace, r.pod, r.pod_uid, r.finding))
            .collect();
        if altered.is_empty() {
            (Said::Holds, Vec::new())
        } else {
            (Said::Violated, altered)
        }
    } else {
        (Said::CannotSay, Vec::new())
    };
    let matches = match lasting {
        None => (Said::CannotSay, Vec::new()),
        Some(lasting) => {
            let differing: Vec<String> = lasting
                .iter()
                .filter(|(_, under_test)| !under_test)
                .map(|(d, _)| format!("{d:?}"))
                .collect();
            if differing.is_empty() {
                (Said::Holds, Vec::new())
            } else {
                (Said::Violated, differing)
            }
        }
    };
    vec![
        Verdict {
            id: PROVED_ITSELF,
            statement: "the attestation agent holds what it needs, passes its own judgement, condemns no more than it should, and says no to real pods altered",
            said: proved_itself.0,
            witness: proved_itself.1,
        },
        Verdict {
            id: PODS_GENUINE,
            statement: "every pod in Polar's namespaces is what its owner made",
            said: genuine.0,
            witness: genuine.1,
        },
        Verdict {
            id: MATCHES_RECORD,
            statement: "what is deployed is what the deployment's signed record says, with no difference that has lasted",
            said: matches.0,
            witness: matches.1,
        },
    ]
}

/// `verdicts`, judged at `judged_at` (seconds) of the cluster the deployment record names `target`, as a record: passed when
/// every verdict holds, each that does not a problem.
pub fn standing_record(target: &str, verdicts: &[Verdict], judged_at: i64) -> EvidenceRecord {
    let record = json!({
        "subject": { "target": target },
        "verdicts": verdicts.iter().map(|v| json!({
            "id": v.id,
            "statement": v.statement,
            "verdict": v.said.as_str(),
            "witness": v.witness,
        })).collect::<Vec<_>>(),
        "result": {
            "passed": verdicts.iter().all(|v| v.said == Said::Holds),
            "problems": verdicts
                .iter()
                .filter(|v| v.said != Said::Holds)
                .map(|v| format!("{}: {}", v.id, v.said.as_str()))
                .collect::<Vec<_>>(),
        },
        "judged_at_unix_secs": judged_at,
    });
    EvidenceRecord::new(STANDING, fields(record))
        .expect("a standing record has a type and no `type` field")
}

/// When a standing is next to be recorded: when a verdict says other than it did when last recorded, or a day after that, so a
/// reader sees the standing is fresh. Its witnesses change with every look (how many pods were judged), so only what the verdicts
/// say is compared.
#[derive(Debug, Default)]
pub struct StandingLog {
    last: Option<(Vec<(&'static str, Said)>, i64)>,
}

impl StandingLog {
    fn said(verdicts: &[Verdict]) -> Vec<(&'static str, Said)> {
        verdicts.iter().map(|v| (v.id, v.said)).collect()
    }

    /// Whether `verdicts`, judged at `now`, are to be recorded.
    pub fn due(&self, verdicts: &[Verdict], now: i64) -> bool {
        match &self.last {
            None => true,
            Some((said, at)) => *said != Self::said(verdicts) || now - at >= DAY_SECS,
        }
    }

    /// `verdicts` were recorded at `now`.
    pub fn recorded(&mut self, verdicts: &[Verdict], now: i64) {
        self.last = Some((Self::said(verdicts), now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attestation_common::{CrashSignal, NotGenuine};
    use proptest::prelude::*;

    const PROVED: Result<Proved, Doubt> = Ok(Proved {
        judged: 4,
        condemned: 0,
        with_record: true,
    });

    fn report(finding: Finding, under_test: bool) -> Report {
        Report {
            namespace: "polar".into(),
            pod: "kube-observer-7f9c".into(),
            pod_uid: "uid-1".into(),
            finding,
            under_test,
        }
    }

    fn altered() -> Finding {
        Finding::Altered(NotGenuine::EphemeralContainer {
            container: "debugger".into(),
        })
    }

    fn crashed() -> Finding {
        Finding::Crashed {
            container: "agent".into(),
            signal: CrashSignal::Segv,
            exit_code: 139,
            finished_at: "2026-11-10T12:00:00Z".into(),
            image_id: "registry/agent@sha256:0".into(),
        }
    }

    fn panicked() -> Finding {
        Finding::Panicked {
            container: "agent".into(),
            exit_code: 101,
            finished_at: "2026-11-10T12:00:00Z".into(),
            image_id: "registry/agent@sha256:0".into(),
        }
    }

    #[test]
    fn a_report_is_a_record_of_the_pod_naming_what_was_found_and_did_not_pass() {
        for (finding, kind) in [
            (altered(), "altered"),
            (crashed(), "crashed"),
            (panicked(), "panicked"),
        ] {
            let record = report_record("u7c", &report(finding, true), 1_800_000_000);
            let p = record.payload();
            assert_eq!(p["type"], REPORT);
            assert_eq!(
                p["subject"],
                json!({ "target": "u7c", "namespace": "polar", "pod": "kube-observer-7f9c" })
            );
            assert_eq!(p["pod_uid"], "uid-1");
            assert_eq!(p["finding"]["kind"], kind);
            assert_eq!(p["under_test"], true);
            assert_eq!(p["result"]["passed"], false);
            assert_eq!(p["found_at_unix_secs"], 1_800_000_000);
        }
        let crash = report_record("u7c", &report(crashed(), false), 0);
        assert_eq!(crash.payload()["finding"]["says"]["signal"], "Segv");
        assert_eq!(crash.payload()["finding"]["says"]["exit_code"], 139);
        let panic = report_record("u7c", &report(panicked(), false), 0);
        assert_eq!(panic.payload()["finding"]["says"]["exit_code"], 101);
    }

    fn said(verdicts: &[Verdict]) -> Vec<(&'static str, Said)> {
        verdicts.iter().map(|v| (v.id, v.said)).collect()
    }

    #[test]
    fn a_proved_agent_with_nothing_found_and_no_lasting_difference_holds_everything() {
        let verdicts = standing(&PROVED, &[report(crashed(), false)], Some(&[]));
        assert_eq!(
            said(&verdicts),
            [
                (PROVED_ITSELF, Said::Holds),
                (PODS_GENUINE, Said::Holds),
                (MATCHES_RECORD, Said::Holds)
            ],
            "a crash is no alteration"
        );
        let record = standing_record("u7c", &verdicts, 7);
        assert_eq!(record.payload()["type"], STANDING);
        assert_eq!(record.payload()["subject"], json!({ "target": "u7c" }));
        assert_eq!(record.payload()["result"]["passed"], true);
        assert_eq!(record.payload()["verdicts"][1]["id"], PODS_GENUINE);
        assert_eq!(record.payload()["verdicts"][1]["verdict"], "holds");
    }

    #[test]
    fn an_alteration_or_a_lasting_difference_violates_and_what_is_under_test_does_not() {
        let difference = Drift::NotDeployed {
            workload: "kube-observer".into(),
        };
        let verdicts = standing(
            &PROVED,
            &[report(altered(), false)],
            Some(&[(difference.clone(), false)]),
        );
        assert_eq!(verdicts[1].said, Said::Violated);
        assert!(verdicts[1].witness[0].contains("kube-observer-7f9c"));
        assert_eq!(verdicts[2].said, Said::Violated);
        assert!(verdicts[2].witness[0].contains("kube-observer"));
        let record = standing_record("u7c", &verdicts, 7);
        assert_eq!(record.payload()["result"]["passed"], false);
        assert_eq!(
            record.payload()["result"]["problems"],
            json!([
                "pods-genuine: violated",
                "deployments-match-record: violated"
            ])
        );

        let under_test = standing(
            &PROVED,
            &[report(altered(), true)],
            Some(&[(difference, true)]),
        );
        assert_eq!(under_test[1].said, Said::Holds);
        assert_eq!(under_test[2].said, Said::Holds);
    }

    #[test]
    fn until_it_has_proved_itself_it_says_nothing_of_the_pods_and_a_doubt_violates() {
        let verdicts = standing(&Err(Doubt::NotListed), &[report(altered(), false)], None);
        assert_eq!(
            said(&verdicts),
            [
                (PROVED_ITSELF, Said::CannotSay),
                (PODS_GENUINE, Said::CannotSay),
                (MATCHES_RECORD, Said::CannotSay)
            ]
        );
        let doubted = standing(&Err(Doubt::CannotSeeItself), &[], Some(&[]));
        assert_eq!(doubted[0].said, Said::Violated);
        assert_eq!(doubted[0].witness, ["CannotSeeItself"]);
        assert_eq!(doubted[1].said, Said::CannotSay);
        assert_eq!(
            doubted[2].said,
            Said::Holds,
            "the record is compared all the same"
        );
    }

    #[test]
    fn the_types_it_records_are_record_types() {
        for t in RECORDS {
            assert!(cert_issuer_common::evidence::is_record_type(t), "{t}");
        }
    }

    fn a_doubt() -> impl Strategy<Value = Result<Proved, Doubt>> {
        prop_oneof![
            Just(PROVED),
            Just(Err(Doubt::NotYet)),
            Just(Err(Doubt::NotListed)),
            Just(Err(Doubt::CannotSeeItself)),
            Just(Err(Doubt::CondemnsMost {
                condemned: 3,
                judged: 4
            })),
        ]
    }

    fn a_report() -> impl Strategy<Value = Report> {
        (
            prop_oneof![Just(altered()), Just(crashed()), Just(panicked())],
            any::<bool>(),
        )
            .prop_map(|(finding, under_test)| report(finding, under_test))
    }

    fn lasting() -> impl Strategy<Value = Option<Vec<(Drift, bool)>>> {
        prop::option::of(prop::collection::vec(
            ("[a-z]{1,4}", any::<bool>())
                .prop_map(|(workload, under_test)| (Drift::NotDeployed { workload }, under_test)),
            0..3,
        ))
    }

    proptest! {
        // For every input: the standing passes exactly when every verdict holds; the pods are judged only once the agent has
        // proved itself; and a verdict is violated only with a witness.
        #[test]
        fn a_standing_follows_its_rules(
            proved in a_doubt(),
            reports in prop::collection::vec(a_report(), 0..4),
            lasting in lasting(),
        ) {
            let verdicts = standing(&proved, &reports, lasting.as_deref());
            prop_assert_eq!(verdicts.iter().map(|v| v.id).collect::<Vec<_>>(), [PROVED_ITSELF, PODS_GENUINE, MATCHES_RECORD]);
            if proved.is_err() {
                prop_assert_eq!(verdicts[1].said, Said::CannotSay);
            } else {
                let altered = reports.iter().any(|r| !r.under_test && matches!(r.finding, Finding::Altered(_)));
                prop_assert_eq!(verdicts[1].said == Said::Violated, altered);
            }
            let differs = lasting.as_ref().map(|l| l.iter().any(|(_, t)| !t));
            prop_assert_eq!(
                verdicts[2].said,
                match differs { None => Said::CannotSay, Some(true) => Said::Violated, Some(false) => Said::Holds }
            );
            for v in verdicts.iter().filter(|v| v.said == Said::Violated) {
                prop_assert!(!v.witness.is_empty(), "{} violated with no witness", v.id);
            }
            let record = standing_record("t", &verdicts, 0);
            prop_assert_eq!(
                record.payload()["result"]["passed"].as_bool(),
                Some(verdicts.iter().all(|v| v.said == Said::Holds))
            );
        }

        // Over any sequence of looks, in time order: a standing is recorded exactly when what a verdict says has changed since
        // the last record, or a day has passed since it, and the first look is always recorded.
        #[test]
        fn a_standing_is_recorded_on_a_change_or_a_day(
            looks in prop::collection::vec((0i64..(2 * DAY_SECS / 3), a_doubt(), lasting()), 1..20),
        ) {
            let mut log = StandingLog::default();
            let mut last: Option<(Vec<(&'static str, Said)>, i64)> = None;
            let mut now = 0;
            for (step, proved, lasting) in looks {
                now += step;
                let verdicts = standing(&proved, &[], lasting.as_deref());
                let expected = match &last {
                    None => true,
                    Some((s, at)) => *s != said(&verdicts) || now - at >= DAY_SECS,
                };
                prop_assert_eq!(log.due(&verdicts, now), expected);
                if expected {
                    log.recorded(&verdicts, now);
                    last = Some((said(&verdicts), now));
                }
            }
        }
    }
}
