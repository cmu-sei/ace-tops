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

//! What the attestation agent reports of its own accord (docs/architecture/runtime-attestation.md, "Slice B"): a pod that is not what its owner
//! made, and a container that died by a signal. It reports and acts on nothing, and what is done about a report is someone's choice. A report is
//! published again each minute while it stands, since the credentials agent, which records it, restarts too; it keeps one of each.

use crate::protocol::AGENT_NAME;
use crate::record::DeploymentRecord;
use crate::verdict::{NotGenuine, PodFacts, Verdict, judge};
use rkyv::{Archive, Deserialize, Serialize};

/// Where the attestation agent publishes what it finds.
pub const REPORTS_TOPIC: &str = "attestation-reports";

/// A signal that a process does not get from someone stopping it: what a fault, a failed exploit, a hardened allocator or a seccomp filter leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub enum CrashSignal {
    Ill,
    Abort,
    Bus,
    Fpe,
    Segv,
    Sys,
}

impl CrashSignal {
    fn of(number: i32) -> Option<Self> {
        match number {
            4 => Some(Self::Ill),
            6 => Some(Self::Abort),
            7 => Some(Self::Bus),
            8 => Some(Self::Fpe),
            11 => Some(Self::Segv),
            31 => Some(Self::Sys),
            _ => None,
        }
    }
}

/// The crash in how a container ended, if it was one: the signal as the runtime says it, or else an exit code of 128 and its number.
pub fn crash_signal(exit_code: i32, signal: Option<i32>) -> Option<CrashSignal> {
    signal
        .filter(|s| *s != 0)
        .or(exit_code.checked_sub(128))
        .and_then(CrashSignal::of)
}

/// Whether a container that ended with `exit_code` (and `signal`, as the runtime says it) panicked: a Rust panic that is not caught exits
/// 101 (docs/architecture/record-store.md, "Attestation verdicts as records", bite B), and nothing of Polar's exits so on purpose. A signal the
/// runtime names is a crash, not this.
pub fn panicked(exit_code: i32, signal: Option<i32>) -> bool {
    exit_code == 101 && crash_signal(exit_code, signal).is_none() && signal.unwrap_or(0) == 0
}

/// How a container ended, as the platform says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Termination {
    pub container: String,
    pub exit_code: i32,
    pub signal: Option<i32>,
    pub finished_at: String,
    pub image_id: String,
}

/// A pod as the agent holds it, for reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedPod {
    pub namespace: String,
    pub name: String,
    pub uid: String,
    pub facts: PodFacts,
    pub terminations: Vec<Termination>,
}

/// What was found about a pod.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub enum Finding {
    /// It is not what its owner made.
    Altered(NotGenuine),
    /// A container of it died by a signal.
    Crashed {
        container: String,
        signal: CrashSignal,
        exit_code: i32,
        finished_at: String,
        image_id: String,
    },
    /// A container of it panicked: Polar's own code said an invariant it checks was broken.
    Panicked {
        container: String,
        exit_code: i32,
        finished_at: String,
        image_id: String,
    },
}

/// One thing found about one pod.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct Report {
    pub namespace: String,
    pub pod: String,
    pub pod_uid: String,
    pub finding: Finding,
    /// The record claims the pod for a workload a configuration under test made (docs/architecture/configurations-under-test.md,
    /// CT2): what is found of it is said apart.
    pub under_test: bool,
}

impl Report {
    /// Whether it is how a container ended, which the platform saw: said when seen, and never the agent's judgement.
    pub fn crashed(&self) -> bool {
        matches!(
            self.finding,
            Finding::Crashed { .. } | Finding::Panicked { .. }
        )
    }
}

/// What stands against `pods`, in the order of their UIDs. `believed` is whether the agent has proved itself: until then what it judges is not said, but
/// a crash is, since that is what the platform saw and no judgement of the agent's. `record`, when it holds one, says which pods are under test.
pub fn findings(
    pods: &[ObservedPod],
    believed: bool,
    record: Option<&DeploymentRecord>,
) -> Vec<Report> {
    let mut pods: Vec<&ObservedPod> = pods.iter().collect();
    pods.sort_by(|a, b| a.uid.cmp(&b.uid));
    let mut found = Vec::new();
    for pod in pods {
        let under_test = record
            .and_then(|r| r.claimed(&pod.namespace, &pod.facts.service_account))
            .is_some_and(|w| w.under_test);
        let report = |finding| Report {
            namespace: pod.namespace.clone(),
            pod: pod.name.clone(),
            pod_uid: pod.uid.clone(),
            finding,
            under_test,
        };
        // With no record this holds the pod to its owner alone, and says it cannot say of one that holds up. That needs no identity, so it is every pod's.
        if believed && let Verdict::NotGenuine(why) = judge(None, Some(&pod.facts)) {
            found.push(report(Finding::Altered(why)));
        }
        for ended in &pod.terminations {
            let finding = match crash_signal(ended.exit_code, ended.signal) {
                Some(signal) => Finding::Crashed {
                    container: ended.container.clone(),
                    signal,
                    exit_code: ended.exit_code,
                    finished_at: ended.finished_at.clone(),
                    image_id: ended.image_id.clone(),
                },
                None if panicked(ended.exit_code, ended.signal) => Finding::Panicked {
                    container: ended.container.clone(),
                    exit_code: ended.exit_code,
                    finished_at: ended.finished_at.clone(),
                    image_id: ended.image_id.clone(),
                },
                None => continue,
            };
            let crash = report(finding);
            // A container that has just ended can show the same ending as its state and its last state.
            if !found.contains(&crash) {
                found.push(crash);
            }
        }
    }
    found
}

/// What has been reported and what stands. A crash is a fact and is reported when it is seen. A pod's watch and its owner's are separate streams, so a new
/// pod can come before the owner that explains it: an alteration has to stand at two checks running.
#[derive(Debug, Default)]
pub struct Reporting {
    standing: Vec<Report>,
    suspected: Vec<Report>,
}

impl Reporting {
    /// Something changed: the crashes in `now` that were not reported yet, which it returns.
    pub fn changed(&mut self, now: &[Report]) -> Vec<Report> {
        let new: Vec<Report> = now
            .iter()
            .filter(|r| r.crashed() && !self.standing.contains(r))
            .cloned()
            .collect();
        self.standing.extend(new.iter().cloned());
        new
    }

    /// The regular check: what stands is now what `now` says, apart from an alteration seen for the first time. Returns what is new.
    pub fn check(&mut self, now: &[Report]) -> Vec<Report> {
        let standing: Vec<Report> = now
            .iter()
            .filter(|r| r.crashed() || self.suspected.contains(r) || self.standing.contains(r))
            .cloned()
            .collect();
        let new = standing
            .iter()
            .filter(|r| !self.standing.contains(r))
            .cloned()
            .collect();
        self.suspected = now.iter().filter(|r| !r.crashed()).cloned().collect();
        self.standing = standing;
        new
    }

    /// Everything that stands, to publish again.
    pub fn standing(&self) -> &[Report] {
        &self.standing
    }
}

/// The bytes of a report, as it is published.
pub fn encode_report(report: &Report) -> Vec<u8> {
    rkyv::to_bytes::<rkyv::rancor::Error>(report)
        .expect("a report of owned strings always serializes")
        .into_vec()
}

/// The report in `payload`, or why it is not one. The bytes are validated before anything is read from them.
pub fn decode_report(payload: &[u8]) -> Result<Report, String> {
    let mut aligned = rkyv::util::AlignedVec::<16>::new();
    aligned.extend_from_slice(payload);
    rkyv::from_bytes::<Report, rkyv::rancor::Error>(&aligned)
        .map_err(|e| format!("not a report: {e}"))
}

/// The report in `payload`, if it is the attestation agent's: published, the broker says, by `agent`, and readable.
pub fn accepted_report(
    payload: &[u8],
    published_by: Option<&str>,
    agent: &str,
) -> Result<Report, String> {
    match published_by {
        Some(who) if who == agent => decode_report(payload),
        Some(who) => Err(format!("{who} reported for {AGENT_NAME}")),
        None => Err("a report with no verified publisher".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{ContainerFacts, Owner, OwnerKind};
    use std::collections::BTreeMap;

    const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn genuine(uid: &str) -> ObservedPod {
        let image = format!("registry/agent@{DIGEST}");
        ObservedPod {
            namespace: "polar".into(),
            name: format!("pod-{uid}"),
            uid: uid.into(),
            facts: PodFacts {
                service_account: "agent".into(),
                owner: Some(Owner {
                    kind: OwnerKind::Deployment,
                    name: "agent".into(),
                    pins: BTreeMap::from([("agent".to_string(), image.clone())]),
                }),
                containers: vec![ContainerFacts {
                    name: "agent".into(),
                    image: image.clone(),
                    image_id: Some(image),
                    hardening: Default::default(),
                }],
                ephemeral: vec![],
            },
            terminations: vec![],
        }
    }

    fn ended(exit_code: i32, signal: Option<i32>) -> Termination {
        Termination {
            container: "agent".into(),
            exit_code,
            signal,
            finished_at: "2026-11-03T12:00:00Z".into(),
            image_id: "registry/agent@sha256:0".into(),
        }
    }

    #[test]
    fn a_crash_is_a_signal_a_process_does_not_get_from_being_stopped() {
        for (exit_code, signal) in [
            (132, CrashSignal::Ill),
            (134, CrashSignal::Abort),
            (135, CrashSignal::Bus),
            (136, CrashSignal::Fpe),
            (139, CrashSignal::Segv),
            (159, CrashSignal::Sys),
        ] {
            assert_eq!(crash_signal(exit_code, None), Some(signal));
        }
        // Stopped, killed, or an ordinary failure: what every rollout and every refused polar-init leaves.
        for exit_code in [0, 1, 2, 127, 128, 137, 143] {
            assert_eq!(crash_signal(exit_code, None), None, "{exit_code}");
        }
    }

    #[test]
    fn the_signal_the_runtime_names_comes_before_the_exit_code() {
        assert_eq!(crash_signal(1, Some(11)), Some(CrashSignal::Segv));
        assert_eq!(crash_signal(139, Some(9)), None);
        // Some runtimes say 0 where there was no signal.
        assert_eq!(crash_signal(139, Some(0)), Some(CrashSignal::Segv));
    }

    // docs/architecture/record-store.md, "Attestation verdicts as records", bite B: a Rust panic that is not caught exits 101, where
    // Polar's own code says an invariant it checks was broken. It is said as a crash is, when seen and whether or not the agent is
    // believed; a signal the runtime names comes first.
    #[test]
    fn a_panic_is_an_exit_of_101_and_is_said_as_a_crash_is() {
        assert!(panicked(101, None));
        assert!(panicked(101, Some(0)));
        assert!(!panicked(101, Some(11)), "a signal named comes first");
        for exit_code in [0, 1, 100, 102, 134, 139] {
            assert!(!panicked(exit_code, None), "{exit_code}");
        }
        let mut pod = genuine("a");
        pod.terminations = vec![ended(101, None)];
        for believed in [true, false] {
            let found = findings(std::slice::from_ref(&pod), believed, None);
            assert_eq!(found.len(), 1, "{found:?}");
            assert_eq!(
                found[0].finding,
                Finding::Panicked {
                    container: "agent".into(),
                    exit_code: 101,
                    finished_at: "2026-11-03T12:00:00Z".into(),
                    image_id: "registry/agent@sha256:0".into(),
                }
            );
            assert!(found[0].crashed());
        }
        let mut reporting = Reporting::default();
        let now = findings(&[pod], true, None);
        assert_eq!(reporting.changed(&now), now, "said when seen");
    }

    #[test]
    fn nothing_stands_against_a_genuine_pod_that_has_only_been_restarted() {
        let mut pod = genuine("a");
        pod.terminations = vec![ended(137, None), ended(0, None), ended(1, None)];
        assert_eq!(findings(&[pod], true, None), vec![]);
    }

    #[test]
    fn a_debugged_pod_is_altered_and_a_crash_is_said_even_while_it_doubts_itself() {
        let mut pod = genuine("a");
        pod.facts.ephemeral = vec!["debugger".into()];
        pod.terminations = vec![ended(139, None)];
        let found = findings(std::slice::from_ref(&pod), true, None);
        assert_eq!(found.len(), 2);
        assert!(matches!(
            found[0].finding,
            Finding::Altered(NotGenuine::EphemeralContainer { .. })
        ));
        assert!(found[1].crashed());
        let unbelieved = findings(&[pod], false, None);
        assert_eq!(unbelieved.len(), 1);
        assert!(unbelieved[0].crashed());
    }

    #[test]
    fn one_ending_shown_as_state_and_as_last_state_is_one_crash() {
        let mut pod = genuine("a");
        pod.terminations = vec![ended(139, None), ended(139, None)];
        assert_eq!(findings(&[pod], true, None).len(), 1);
    }

    #[test]
    fn a_crash_is_reported_when_seen_and_an_alteration_at_its_second_check() {
        let mut crashed = genuine("c");
        crashed.terminations = vec![ended(134, None)];
        let mut debugged = genuine("d");
        debugged.facts.ephemeral = vec!["debugger".into()];
        let now = findings(&[crashed, debugged], true, None);

        let mut reporting = Reporting::default();
        let at_once = reporting.changed(&now);
        assert_eq!(at_once.len(), 1);
        assert!(at_once[0].crashed());
        assert_eq!(reporting.changed(&now), vec![]);

        assert_eq!(reporting.check(&now), vec![]);
        let second = reporting.check(&now);
        assert_eq!(second.len(), 1);
        assert!(!second[0].crashed());
        assert_eq!(reporting.standing().len(), 2);
        assert_eq!(reporting.check(&now), vec![]);

        assert_eq!(reporting.check(&[]), vec![]);
        assert!(reporting.standing().is_empty());
    }

    #[test]
    fn a_new_pod_seen_before_its_owner_is_never_reported() {
        let mut orphan = genuine("a");
        orphan.facts.owner = None;
        let mut reporting = Reporting::default();
        assert_eq!(
            reporting.changed(&findings(&[orphan.clone()], true, None)),
            vec![]
        );
        assert_eq!(reporting.check(&findings(&[orphan], true, None)), vec![]);
        // By the next check its owner has arrived.
        assert_eq!(
            reporting.check(&findings(&[genuine("a")], true, None)),
            vec![]
        );
        assert!(reporting.standing().is_empty());
    }

    /// A record whose one workload runs as the service account `agent` in `polar`, marked under test or not.
    fn record_of_agent(under_test: bool) -> DeploymentRecord {
        DeploymentRecord::from_payload(&serde_json::json!({
            "schema": 2, "target": "t", "version": 1,
            "workloads": [{
                "identity": "agent.polar.serviceaccount.cluster.local",
                "owner_kind": "Deployment", "owner_name": "agent", "namespace": "polar",
                "service_account": "agent", "under_test": under_test,
                "containers": [{ "name": "agent", "image": "registry/agent@sha256:0" }]
            }]
        }))
        .unwrap()
    }

    #[test]
    fn what_is_found_of_a_pod_the_record_claims_for_a_workload_under_test_says_so() {
        let mut pod = genuine("a");
        pod.facts.ephemeral = vec!["debugger".into()];
        pod.terminations = vec![ended(139, None)];
        let pods = [pod];
        let tested = findings(&pods, true, Some(&record_of_agent(true)));
        assert_eq!(tested.len(), 2);
        assert!(tested.iter().all(|r| r.under_test));
        for not in [
            findings(&pods, true, Some(&record_of_agent(false))),
            findings(&pods, true, None),
        ] {
            assert!(not.iter().all(|r| !r.under_test));
        }
        // The mark survives the wire.
        let bytes = encode_report(&tested[0]);
        assert!(
            accepted_report(&bytes, Some("agent"), "agent")
                .unwrap()
                .under_test
        );
    }

    #[test]
    fn a_report_is_taken_only_from_the_agent_as_the_broker_stamped_it() {
        let report = findings(
            &[{
                let mut pod = genuine("a");
                pod.terminations = vec![ended(159, None)];
                pod
            }],
            true,
            None,
        )
        .remove(0);
        let bytes = encode_report(&report);
        assert_eq!(
            accepted_report(&bytes, Some("agent"), "agent").unwrap(),
            report
        );
        assert!(accepted_report(&bytes, Some("intruder"), "agent").is_err());
        assert!(accepted_report(&bytes, None, "agent").is_err());
        assert!(accepted_report(b"nonsense", Some("agent"), "agent").is_err());
    }
}
