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
    /// The record does not name the agent's own workload, or names it twice.
    NotInItsRecord,
    /// It holds no pod of its own workload, which is impossible for an agent that sees what it should.
    CannotSeeItself,
    /// A pod of its own workload is not genuine by its own judgement.
    NotGenuineItself(NotGenuine),
    /// It would call most of what is running not genuine, which says more about the agent than about the deployment.
    CondemnsMost { condemned: usize, judged: usize },
    /// It does not call a real pod, altered in this way, not genuine.
    CannotSayNo { altered: &'static str },
}

/// What a proof looked at, for its log line. With no record it could hold pods only to their owners, so its verdicts stand only as far as that goes:
/// `judge` still calls a pod not genuine against its owner, and cannot say of one that holds up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proved {
    pub judged: usize,
    pub condemned: usize,
    pub with_record: bool,
}

/// The workload the record says runs in this namespace under this service account. Two workloads that share one say nothing about a pod.
fn claimed_by<'a>(
    record: &'a DeploymentRecord,
    pod: &HeldPodFacts,
) -> Option<&'a RecordedWorkload> {
    record.claimed(&pod.namespace, &pod.facts.service_account)
}

fn facts_of(workload: &RecordedWorkload) -> WorkloadFacts {
    WorkloadFacts {
        owner_kind: workload.owner_kind,
        owner_name: workload.owner_name.clone(),
        service_account: workload.service_account.clone(),
        hardening: crate::record::hardening_of(workload),
    }
}

const ZEROS: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// `pod`, altered in each way a verdict knows against its owner. Each still claims to be what it was.
fn altered_against_its_owner(pod: &PodFacts) -> Vec<(&'static str, PodFacts)> {
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
        ("no owner", change(&|p| p.owner = None)),
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

/// `pod`, altered in the ways only the record can tell.
fn altered_against_the_record(pod: &PodFacts) -> Vec<(&'static str, PodFacts)> {
    let mut another_owner = pod.clone();
    another_owner.owner = another_owner.owner.take().map(|owner| Owner {
        name: format!("{}-altered", owner.name),
        ..owner
    });
    let mut another_account = pod.clone();
    another_account.service_account.push_str("-altered");
    vec![
        ("another owner", another_owner),
        ("another service account", another_account),
    ]
}

/// Whether the agent's verdicts are to be believed: it has listed what it watches, it passes its own judgement, it does not condemn most of what is
/// running, and it still says no to real pods altered. A single tampered pod, or a few, does not make it doubt itself, and is reported in the ordinary
/// way when it asks.
///
/// A record comes through the configuration agent and Polar's git server, so in a rollout there can be none for over a minute, just as most pods are
/// asking. It does not wait for one. Holding a pod to its owner needs no record, so with none it proves that much, and those verdicts stand.
pub fn prove(
    judge: impl Fn(Option<&WorkloadFacts>, Option<&PodFacts>) -> Verdict,
    listed: bool,
    record: Option<&DeploymentRecord>,
    pods: &[HeldPodFacts],
) -> Result<Proved, Doubt> {
    if !listed {
        return Err(Doubt::NotListed);
    }
    let own = match record {
        Some(record) => {
            let mut own_workloads = record
                .workloads
                .iter()
                .filter(|w| w.owner_name == AGENT_NAME);
            let own = own_workloads.next().ok_or(Doubt::NotInItsRecord)?;
            if own_workloads.next().is_some() {
                return Err(Doubt::NotInItsRecord);
            }
            Some(own)
        }
        None => None,
    };

    let (mut judged, mut condemned, mut own_pods) = (0, 0, 0);
    let mut holding_up = Vec::new();
    for pod in pods {
        // With a record, only what it says runs here is weighed. With none there is nothing to tell a stranger by.
        let claim = match record {
            Some(record) => match claimed_by(record, pod) {
                Some(workload) => Some(workload),
                None => continue,
            },
            None => None,
        };
        let facts = claim.map(facts_of);
        let verdict = judge(facts.as_ref(), Some(&pod.facts));
        judged += 1;
        let is_own = match (claim, own) {
            (Some(workload), Some(own)) => std::ptr::eq(workload, own),
            _ => pod
                .facts
                .owner
                .as_ref()
                .is_some_and(|o| o.name == AGENT_NAME),
        };
        if is_own {
            own_pods += 1;
            if let Verdict::NotGenuine(why) = &verdict {
                return Err(Doubt::NotGenuineItself(why.clone()));
            }
        }
        match verdict {
            Verdict::NotGenuine(_) => condemned += 1,
            Verdict::Genuine | Verdict::CannotSay => holding_up.push((facts, &pod.facts)),
        }
    }
    if own_pods == 0 {
        return Err(Doubt::CannotSeeItself);
    }
    if condemned * 2 > judged {
        return Err(Doubt::CondemnsMost { condemned, judged });
    }
    for (facts, pod) in holding_up {
        let mut alterations = altered_against_its_owner(pod);
        if facts.is_some() {
            alterations.extend(altered_against_the_record(pod));
        }
        for (how, altered) in alterations {
            if !matches!(
                judge(facts.as_ref(), Some(&altered)),
                Verdict::NotGenuine(_)
            ) {
                return Err(Doubt::CannotSayNo { altered: how });
            }
        }
    }
    if !matches!(judge(None, None), Verdict::NotGenuine(_)) {
        return Err(Doubt::CannotSayNo {
            altered: "no such pod",
        });
    }
    Ok(Proved {
        judged,
        condemned,
        with_record: record.is_some(),
    })
}
