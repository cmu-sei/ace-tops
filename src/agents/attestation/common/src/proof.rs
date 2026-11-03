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

//! Whether the attestation agent's own verdicts are to be believed, on this cluster, now (docs/architecture/attestation-when-it-cannot-answer.md,
//! "The agent proves itself"). A shadow run proves only the code that ran in it, and a later image of the agent, or a Kubernetes upgrade under it,
//! reaches refusing unproved. So before its `NotGenuine` counts, the agent holds its judgement up to what is running. It takes the judgement as an
//! argument so that a wrong rule can be shown to fail here; the agent passes the real one.

use crate::protocol::AGENT_NAME;
use crate::record::{DeploymentRecord, RecordedWorkload};
use crate::verdict::{NotGenuine, Owner, PodFacts, Verdict, WorkloadFacts, digest_of};

/// A pod the agent holds, with the namespace it is in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldPodFacts {
    pub namespace: String,
    pub facts: PodFacts,
}

/// Why its verdicts are not to be believed. It answers `CannotSay` until this has gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Doubt {
    /// It has not looked yet.
    NotYet,
    /// It has not yet listed everything it watches.
    NotListed,
    /// It holds no signed record, so it has nothing to hold anything to.
    NoRecord,
    /// The record does not name the agent's own workload, or names it twice.
    NotInItsRecord,
    /// It holds no pod of its own workload, which is impossible for an agent that sees what it should.
    CannotSeeItself,
    /// A pod of its own workload is not genuine by its own judgement.
    NotGenuineItself(NotGenuine),
    /// No pod of its own workload runs the images the record names for it.
    NotTheImageRecorded,
    /// It would call most of what is running not genuine, which says more about the agent than about the deployment.
    CondemnsMost { condemned: usize, judged: usize },
    /// It does not call a real pod, altered in this way, not genuine.
    CannotSayNo { altered: &'static str },
}

/// What a proof looked at, for its log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proved {
    pub judged: usize,
    pub condemned: usize,
}

/// The workload the record says runs in this namespace under this service account. Two workloads that share one say nothing about a pod.
fn claimed_by<'a>(
    record: &'a DeploymentRecord,
    pod: &HeldPodFacts,
) -> Option<&'a RecordedWorkload> {
    let mut named = record
        .workloads
        .iter()
        .filter(|w| w.namespace == pod.namespace && w.service_account == pod.facts.service_account);
    let workload = named.next()?;
    named.next().is_none().then_some(workload)
}

fn facts_of(workload: &RecordedWorkload) -> WorkloadFacts {
    WorkloadFacts {
        owner_kind: workload.owner_kind,
        owner_name: workload.owner_name.clone(),
        service_account: workload.service_account.clone(),
    }
}

/// Whether `pod` runs every image the record names for `workload`.
fn runs_what_is_recorded(workload: &RecordedWorkload, pod: &PodFacts) -> bool {
    workload.containers.iter().all(|recorded| {
        pod.containers.iter().any(|c| {
            c.name == recorded.name
                && digest_of(&c.image).is_some()
                && digest_of(&c.image) == digest_of(&recorded.image)
        })
    })
}

const ZEROS: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// `pod`, altered in each way a verdict knows. Each still claims to be what it was.
fn altered(pod: &PodFacts) -> Vec<(&'static str, PodFacts)> {
    let change = |change: &dyn Fn(&mut PodFacts)| {
        let mut altered = pod.clone();
        change(&mut altered);
        altered
    };
    vec![
        (
            "another image",
            change(&|p| {
                if let Some(c) = p.containers.first_mut() {
                    // Never the digest it has, or it would not be altered.
                    let digit = if digest_of(&c.image) == Some(ZEROS) {
                        "f"
                    } else {
                        "0"
                    };
                    c.image = format!("altered@sha256:{}", digit.repeat(64));
                }
            }),
        ),
        (
            "another owner",
            change(&|p| {
                p.owner = p.owner.take().map(|owner| Owner {
                    name: format!("{}-altered", owner.name),
                    ..owner
                });
            }),
        ),
        ("no owner", change(&|p| p.owner = None)),
        (
            "another service account",
            change(&|p| p.service_account.push_str("-altered")),
        ),
        (
            "an ephemeral container",
            change(&|p| p.ephemeral.push("altered".to_string())),
        ),
        (
            "a container its owner does not have",
            change(&|p| {
                let mut extra = p.containers.first().cloned();
                if let Some(c) = extra.as_mut() {
                    c.name = "altered".to_string();
                }
                p.containers.extend(extra);
            }),
        ),
    ]
}

/// Whether the agent's verdicts are to be believed: it holds what it needs, it passes its own judgement, it does not condemn most of what is
/// running, and it still says no to real pods altered. A single tampered pod, or a few, does not make it doubt itself, and is reported in the
/// ordinary way when it asks.
pub fn prove(
    judge: impl Fn(Option<&WorkloadFacts>, Option<&PodFacts>) -> Verdict,
    listed: bool,
    record: Option<&DeploymentRecord>,
    pods: &[HeldPodFacts],
) -> Result<Proved, Doubt> {
    if !listed {
        return Err(Doubt::NotListed);
    }
    let record = record.ok_or(Doubt::NoRecord)?;
    let mut own_workloads = record
        .workloads
        .iter()
        .filter(|w| w.owner_name == AGENT_NAME);
    let own = own_workloads.next().ok_or(Doubt::NotInItsRecord)?;
    if own_workloads.next().is_some() {
        return Err(Doubt::NotInItsRecord);
    }

    let (mut judged, mut condemned, mut own_pods) = (0, 0, 0);
    let mut own_recorded = false;
    let mut genuine = Vec::new();
    for pod in pods {
        let Some(workload) = claimed_by(record, pod) else {
            continue;
        };
        let facts = facts_of(workload);
        let verdict = judge(Some(&facts), Some(&pod.facts));
        judged += 1;
        if std::ptr::eq(workload, own) {
            own_pods += 1;
            if let Verdict::NotGenuine(why) = &verdict {
                return Err(Doubt::NotGenuineItself(why.clone()));
            }
            own_recorded |= runs_what_is_recorded(workload, &pod.facts);
        }
        match verdict {
            Verdict::Genuine => genuine.push((facts, &pod.facts)),
            Verdict::NotGenuine(_) => condemned += 1,
            Verdict::CannotSay => {}
        }
    }
    if own_pods == 0 {
        return Err(Doubt::CannotSeeItself);
    }
    // During its own rollout a pod of the old revision is still its workload's, so one pod running what is recorded is enough.
    if !own_recorded {
        return Err(Doubt::NotTheImageRecorded);
    }
    if condemned * 2 > judged {
        return Err(Doubt::CondemnsMost { condemned, judged });
    }
    for (facts, pod) in genuine {
        for (how, altered) in altered(pod) {
            if !matches!(judge(Some(&facts), Some(&altered)), Verdict::NotGenuine(_)) {
                return Err(Doubt::CannotSayNo { altered: how });
            }
        }
    }
    if !matches!(judge(None, None), Verdict::NotGenuine(_)) {
        return Err(Doubt::CannotSayNo {
            altered: "no such pod",
        });
    }
    Ok(Proved { judged, condemned })
}
