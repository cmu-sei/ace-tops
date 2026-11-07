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

//! The instance check's rule, over every way a pod can differ from the genuine one
//! (docs/architecture/runtime-attestation.md, "Slice A"): the genuine pod passes, and each difference, alone, does not.

use attestation_common::{
    AGENT_NAME, ContainerFacts, Deployed, DeploymentRecord, Doubt, Drift, DriftWatch, Envelope,
    HeldPodFacts, InstanceQuestion, NotGenuine, Owner, OwnerKind, PodFacts, Proved,
    RecordedContainer, RecordedWorkload, Verdict, WorkloadFacts, decode_question, decode_verdict,
    digest_of, drift, encode_question, encode_verdict, judge, prove, replies_topic,
};
use attestation_common::{
    ObservedPod, Report, Reporting, Termination, accepted_report, crash_signal, decode_report,
    encode_report, findings,
};
use proptest::prelude::*;
use std::collections::BTreeMap;

fn digest() -> impl Strategy<Value = String> {
    "[0-9a-f]{64}".prop_map(|hex| format!("sha256:{hex}"))
}

fn kind() -> impl Strategy<Value = OwnerKind> {
    prop_oneof![
        Just(OwnerKind::Deployment),
        Just(OwnerKind::StatefulSet),
        Just(OwnerKind::Job)
    ]
}

/// A genuine pod and the record that names it: containers named `c0..`, the first few started.
fn genuine() -> impl Strategy<Value = (WorkloadFacts, PodFacts)> {
    (
        kind(),
        "[a-z]{1,8}",
        "[a-z]{1,8}",
        prop::collection::vec(digest(), 1..5),
        0usize..5,
    )
        .prop_map(|(kind, name, account, digests, started)| {
            let image = |d: &String| format!("registry:5000/image:latest@{d}");
            let pins: BTreeMap<String, String> = digests
                .iter()
                .enumerate()
                .map(|(i, d)| (format!("c{i}"), image(d)))
                .collect();
            let containers = digests
                .iter()
                .enumerate()
                .map(|(i, d)| ContainerFacts {
                    name: format!("c{i}"),
                    image: image(d),
                    image_id: (i < started).then(|| format!("registry:5000/image@{d}")),
                })
                .collect();
            (
                WorkloadFacts {
                    owner_kind: kind,
                    owner_name: name.clone(),
                    service_account: account.clone(),
                },
                PodFacts {
                    service_account: account,
                    owner: Some(Owner { kind, name, pins }),
                    containers,
                    ephemeral: vec![],
                },
            )
        })
}

fn another_owner(verdict: &Verdict) -> bool {
    matches!(
        verdict,
        Verdict::NotGenuine(NotGenuine::AnotherOwner { .. })
    )
}

fn another_account(verdict: &Verdict) -> bool {
    matches!(
        verdict,
        Verdict::NotGenuine(NotGenuine::AnotherServiceAccount { .. })
    )
}

fn another_image(verdict: &Verdict) -> bool {
    matches!(
        verdict,
        Verdict::NotGenuine(NotGenuine::AnotherImage { .. })
    )
}

proptest! {
    #[test]
    fn a_genuine_pod_is_genuine((record, pod) in genuine()) {
        prop_assert_eq!(judge(Some(&record), Some(&pod)), Verdict::Genuine);
    }

    #[test]
    fn the_order_of_its_containers_does_not_matter((record, mut pod) in genuine()) {
        pod.containers.reverse();
        prop_assert_eq!(judge(Some(&record), Some(&pod)), Verdict::Genuine);
    }

    #[test]
    fn a_pod_is_never_genuine_on_an_identity_the_record_does_not_name((_, pod) in genuine()) {
        prop_assert_eq!(judge(None, Some(&pod)), Verdict::CannotSay);
    }

    #[test]
    fn no_such_pod_whatever_the_record_says((record, _) in genuine()) {
        prop_assert_eq!(judge(Some(&record), None), Verdict::NotGenuine(NotGenuine::NoSuchPod));
        prop_assert_eq!(judge(None, None), Verdict::NotGenuine(NotGenuine::NoSuchPod));
    }

    #[test]
    fn a_pod_with_no_owner_is_refused((record, mut pod) in genuine()) {
        pod.owner = None;
        prop_assert_eq!(judge(Some(&record), Some(&pod)), Verdict::NotGenuine(NotGenuine::NoOwner));
        prop_assert_eq!(judge(None, Some(&pod)), Verdict::NotGenuine(NotGenuine::NoOwner));
    }

    #[test]
    fn another_owners_name_is_refused((record, mut pod) in genuine()) {
        pod.owner.as_mut().unwrap().name.push('x');
        prop_assert!(another_owner(&judge(Some(&record), Some(&pod))));
    }

    #[test]
    fn another_owners_kind_is_refused((record, mut pod) in genuine()) {
        let owner = pod.owner.as_mut().unwrap();
        owner.kind = match owner.kind {
            OwnerKind::Deployment => OwnerKind::StatefulSet,
            _ => OwnerKind::Deployment,
        };
        prop_assert!(another_owner(&judge(Some(&record), Some(&pod))));
    }

    #[test]
    fn another_service_account_is_refused((record, mut pod) in genuine()) {
        pod.service_account.push('x');
        prop_assert!(another_account(&judge(Some(&record), Some(&pod))));
    }

    #[test]
    fn an_ephemeral_container_is_refused_even_on_an_identity_not_named((record, mut pod) in genuine()) {
        pod.ephemeral.push("debugger".into());
        let refused = Verdict::NotGenuine(NotGenuine::EphemeralContainer { container: "debugger".into() });
        prop_assert_eq!(judge(Some(&record), Some(&pod)), refused.clone());
        prop_assert_eq!(judge(None, Some(&pod)), refused);
    }

    #[test]
    fn a_container_the_owner_does_not_have_is_refused((record, mut pod) in genuine(), d in digest()) {
        pod.containers.push(ContainerFacts {
            name: "extra".into(),
            image: format!("registry:5000/other@{d}"),
            image_id: None,
        });
        prop_assert_eq!(
            judge(Some(&record), Some(&pod)),
            Verdict::NotGenuine(NotGenuine::UnexpectedContainer { container: "extra".into() })
        );
    }

    #[test]
    fn a_container_the_owner_has_and_the_pod_does_not_is_refused((record, mut pod) in genuine()) {
        let gone = pod.containers.remove(0).name;
        prop_assert_eq!(
            judge(Some(&record), Some(&pod)),
            Verdict::NotGenuine(NotGenuine::MissingContainer { container: gone })
        );
    }

    /// The spec's image alone, and what is really running alone, each decide.
    #[test]
    fn another_image_is_refused_in_the_spec_and_as_it_runs((record, pod) in genuine(), d in digest()) {
        prop_assume!(!pod.containers.iter().any(|c| c.image.contains(&d)));
        let mut in_spec = pod.clone();
        in_spec.containers[0].image = format!("registry:5000/image@{d}");
        prop_assert!(another_image(&judge(Some(&record), Some(&in_spec))));
        let mut running = pod;
        running.containers[0].image_id = Some(format!("registry:5000/image@{d}"));
        prop_assert!(another_image(&judge(Some(&record), Some(&running))));
        prop_assert!(another_image(&judge(None, Some(&running))));
    }

    /// A tag says nothing about what runs: an owner that pins one has pinned nothing.
    #[test]
    fn an_owner_that_pins_no_digest_is_refused((record, mut pod) in genuine()) {
        let c0 = "c0".to_string();
        pod.owner.as_mut().unwrap().pins.insert(c0.clone(), "registry:5000/image:latest".into());
        pod.containers[0].image = "registry:5000/image:latest".into();
        prop_assert_eq!(
            judge(Some(&record), Some(&pod)),
            Verdict::NotGenuine(NotGenuine::NotPinned { container: c0 })
        );
    }

    #[test]
    fn a_question_survives_the_wire(id in "[ -~]{0,20}", identity in "[ -~]{0,40}", pod_uid in "[ -~]{0,40}") {
        let envelope = Envelope {
            correlation_id: id,
            payload: InstanceQuestion { identity, pod_uid },
        };
        let back = decode_question(&encode_question(&envelope)).unwrap();
        prop_assert_eq!(back.correlation_id, envelope.correlation_id);
        prop_assert_eq!(back.payload, envelope.payload);
    }

    #[test]
    fn a_verdict_survives_the_wire(id in "[ -~]{0,20}", found in "[ -~]{0,40}", expected in "[ -~]{0,40}") {
        for verdict in [
            Verdict::Genuine,
            Verdict::CannotSay,
            Verdict::NotGenuine(NotGenuine::AnotherOwner { expected: expected.clone(), found: found.clone() }),
        ] {
            let envelope = Envelope { correlation_id: id.clone(), payload: verdict };
            let back = decode_verdict(&encode_verdict(&envelope)).unwrap();
            prop_assert_eq!(back.correlation_id, envelope.correlation_id);
            prop_assert_eq!(back.payload, envelope.payload);
        }
    }

    #[test]
    fn what_is_not_a_question_is_refused(junk in prop::collection::vec(any::<u8>(), 0..64)) {
        // It may decode by chance only if it is valid; it must never panic.
        let _ = decode_question(&junk);
        let _ = decode_verdict(&junk);
    }

    #[test]
    fn a_digest_is_found_in_either_form(d in digest(), name in "[a-z]{1,8}") {
        let pinned = format!("registry:5000/{name}:latest@{d}");
        let running = format!("registry:5000/{name}@{d}");
        prop_assert_eq!(digest_of(&pinned), Some(d.as_str()));
        prop_assert_eq!(digest_of(&running), Some(d.as_str()));
    }

    #[test]
    fn what_is_not_a_digest_is_not_taken_for_one(junk in "[a-zA-Z0-9:/@._-]{0,40}") {
        prop_assume!(junk.rsplit_once('@').is_none_or(|(_, d)| {
            d.strip_prefix("sha256:").is_none_or(|h| h.len() != 64)
        }));
        prop_assert_eq!(digest_of(&junk), None);
    }
}

#[test]
fn each_asker_has_its_own_reply_topic() {
    assert_eq!(
        replies_topic("credentials-agent"),
        "attestation-instance-replies.credentials-agent"
    );
}

#[test]
fn a_tag_or_a_short_digest_is_not_a_digest() {
    assert_eq!(digest_of("registry:5000/image:latest"), None);
    assert_eq!(digest_of("registry:5000/image@sha256:abc"), None);
    assert_eq!(digest_of(""), None);
    let upper = format!("image@sha256:{}", "A".repeat(64));
    assert_eq!(digest_of(&upper), None);
}

/// A harness run's Jobs are copies of the workload's, named after it (`infra/load-harness.nu`): a Job is its workload's by
/// that prefix, and only a Job.
#[test]
fn a_jobs_name_may_extend_its_workloads_and_a_deployments_may_not() {
    let pins = BTreeMap::from([("c".to_string(), format!("r/i@sha256:{}", "a".repeat(64)))]);
    let pod = |kind, name: &str| PodFacts {
        service_account: "sa".into(),
        owner: Some(Owner {
            kind,
            name: name.into(),
            pins: pins.clone(),
        }),
        containers: vec![ContainerFacts {
            name: "c".into(),
            image: format!("r/i@sha256:{}", "a".repeat(64)),
            image_id: None,
        }],
        ephemeral: vec![],
    };
    let record = |kind| WorkloadFacts {
        owner_kind: kind,
        owner_name: "harness-producer".into(),
        service_account: "sa".into(),
    };
    let job = record(OwnerKind::Job);
    assert_eq!(
        judge(
            Some(&job),
            Some(&pod(OwnerKind::Job, "harness-producer-run1-0"))
        ),
        Verdict::Genuine
    );
    assert_eq!(
        judge(Some(&job), Some(&pod(OwnerKind::Job, "harness-producer"))),
        Verdict::Genuine
    );
    assert!(matches!(
        judge(Some(&job), Some(&pod(OwnerKind::Job, "harness-producerx"))),
        Verdict::NotGenuine(NotGenuine::AnotherOwner { .. })
    ));
    let deployment = record(OwnerKind::Deployment);
    assert!(matches!(
        judge(
            Some(&deployment),
            Some(&pod(OwnerKind::Deployment, "harness-producer-run1-0"))
        ),
        Verdict::NotGenuine(NotGenuine::AnotherOwner { .. })
    ));
}

// ── The deployment's record, against what is deployed ──────────────────────────────────────────────────────────────

fn workload() -> impl Strategy<Value = RecordedWorkload> {
    (
        "[a-c]{1,2}",
        prop_oneof![Just(OwnerKind::Deployment), Just(OwnerKind::StatefulSet)],
        prop::collection::btree_map("[a-c]{1,2}", digest(), 1..4),
        any::<bool>(),
    )
        .prop_map(|(name, owner_kind, images, under_test)| RecordedWorkload {
            identity: format!("{name}.polar.serviceaccount.cluster.local"),
            owner_kind,
            owner_name: name.clone(),
            namespace: "polar".into(),
            service_account: name,
            containers: images
                .into_iter()
                .map(|(name, image)| RecordedContainer { name, image })
                .collect(),
            under_test,
        })
}

fn record() -> impl Strategy<Value = DeploymentRecord> {
    prop::collection::btree_map("[a-c]{1,2}", workload(), 0..5).prop_map(|named| DeploymentRecord {
        schema: 2,
        target: "t".into(),
        version: 1,
        workloads: named.into_values().collect(),
    })
}

/// What the cluster holds when it is exactly what `record` says.
fn as_recorded(record: &DeploymentRecord) -> Vec<Deployed> {
    record
        .workloads
        .iter()
        .map(|w| Deployed {
            kind: w.owner_kind,
            namespace: w.namespace.clone(),
            name: w.owner_name.clone(),
            pins: w
                .containers
                .iter()
                .map(|c| (c.name.clone(), c.image.clone()))
                .collect(),
        })
        .collect()
}

/// Keeps one workload of each kind and name, which is all a cluster can hold.
fn distinct(mut record: DeploymentRecord) -> DeploymentRecord {
    let mut seen = std::collections::BTreeSet::new();
    record
        .workloads
        .retain(|w| seen.insert((format!("{:?}", w.owner_kind), w.owner_name.clone())));
    record
}

fn watched() -> Vec<String> {
    vec!["polar".to_string()]
}

proptest! {
    /// What is deployed as recorded differs in nothing, whatever order it is seen in.
    #[test]
    fn what_is_deployed_as_recorded_does_not_drift(record in record().prop_map(distinct)) {
        let mut deployed = as_recorded(&record);
        prop_assert!(drift(&record, &deployed, &watched()).is_empty());
        deployed.reverse();
        prop_assert!(drift(&record, &deployed, &watched()).is_empty());
    }

    /// Each way a workload can be changed is found, and is the only thing found.
    #[test]
    fn one_change_is_found_as_itself(record in record().prop_map(distinct), other in digest(), which in any::<prop::sample::Index>()) {
        let deployed = as_recorded(&record);
        prop_assume!(!deployed.is_empty());
        let at = which.index(deployed.len());
        let target = deployed[at].clone();
        let workload = format!("{:?} {}/{}", target.kind, target.namespace, target.name);
        let container = target.pins.keys().next().unwrap().clone();

        let mut repinned = deployed.clone();
        prop_assume!(repinned[at].pins[&container] != other);
        repinned[at].pins.insert(container.clone(), other.clone());
        let found = drift(&record, &repinned, &watched());
        prop_assert_eq!(found.len(), 1);
        let is_another_image = matches!(found.iter().next(), Some(Drift::AnotherImage { .. }));
        prop_assert!(is_another_image);

        let mut gone = deployed.clone();
        gone.remove(at);
        prop_assert_eq!(drift(&record, &gone, &watched()), [Drift::NotDeployed { workload: workload.clone() }].into_iter().collect());

        let mut sidecar = deployed.clone();
        sidecar[at].pins.insert("zz-added".into(), other.clone());
        prop_assert_eq!(drift(&record, &sidecar, &watched()), [Drift::ContainerNotInRecord { workload: workload.clone(), container: "zz-added".into() }].into_iter().collect());

        let mut made = deployed;
        made.push(Deployed { kind: OwnerKind::Deployment, namespace: "polar".into(), name: "zz-by-hand".into(), pins: Default::default() });
        prop_assert_eq!(drift(&record, &made, &watched()), [Drift::NotInRecord { workload: "Deployment polar/zz-by-hand".into() }].into_iter().collect());
    }

    /// Over any sequence of looks: nothing is reported before it has lasted the grace, nothing twice while it lasts, and only what was
    /// reported is said to be gone.
    #[test]
    fn a_difference_is_reported_once_it_has_lasted_and_only_then(
        looks in prop::collection::vec((1u64..120, prop::collection::btree_set(0u8..4, 0..4)), 1..40)
    ) {
        const GRACE: u64 = 300;
        let as_drift = |n: u8| Drift::NotDeployed { workload: n.to_string() };
        let mut watch = DriftWatch::new(GRACE);
        let (mut now, mut began, mut open) = (0u64, std::collections::BTreeMap::new(), std::collections::BTreeSet::new());
        for (step, present) in looks {
            now += step;
            began.retain(|n, _| present.contains(n));
            for n in &present {
                began.entry(*n).or_insert(now);
            }
            let current = present.iter().map(|n| as_drift(*n)).collect();
            let changes = watch.observe(now, &current);
            for d in &changes.gone {
                prop_assert!(open.remove(d), "said to be gone without being reported");
            }
            for d in &changes.lasting {
                prop_assert!(open.insert(d.clone()), "reported twice while it lasts");
            }
            for (n, at) in &began {
                let due = now - at >= GRACE;
                prop_assert_eq!(open.contains(&as_drift(*n)), due, "reported exactly once it has lasted");
            }
        }
    }
}

// ---- The agent proving itself (docs/architecture/attestation-when-it-cannot-answer.md, "The agent proves itself") ----

/// A deployment of the agent and `others` more workloads, each with one genuine pod, and the record that names them.
fn deployment(others: usize) -> (DeploymentRecord, Vec<HeldPodFacts>) {
    let image = |n: usize| format!("registry:5000/image:latest@sha256:{n:064x}");
    let names: Vec<String> = std::iter::once(AGENT_NAME.to_string())
        .chain((0..others).map(|n| format!("workload-{n}")))
        .collect();
    let workloads = names
        .iter()
        .enumerate()
        .map(|(n, name)| RecordedWorkload {
            identity: format!("{name}.polar.serviceaccount.cluster.local"),
            owner_kind: OwnerKind::Deployment,
            owner_name: name.clone(),
            namespace: "polar".to_string(),
            service_account: name.clone(),
            containers: vec![RecordedContainer {
                name: "main".to_string(),
                image: image(n),
            }],
            under_test: false,
        })
        .collect();
    let pods = names
        .iter()
        .enumerate()
        .map(|(n, name)| HeldPodFacts {
            namespace: "polar".to_string(),
            facts: PodFacts {
                service_account: name.clone(),
                owner: Some(Owner {
                    kind: OwnerKind::Deployment,
                    name: name.clone(),
                    pins: BTreeMap::from([("main".to_string(), image(n))]),
                }),
                containers: vec![ContainerFacts {
                    name: "main".to_string(),
                    image: image(n),
                    image_id: Some(format!("registry:5000/image@sha256:{n:064x}")),
                }],
                ephemeral: vec![],
            },
        })
        .collect();
    (
        DeploymentRecord {
            schema: 1,
            target: "t".to_string(),
            version: 1,
            workloads,
        },
        pods,
    )
}

/// A pod some other image was put into.
fn tampered(pod: &mut HeldPodFacts) {
    pod.facts.containers[0].image = format!("registry:5000/other@sha256:{}", "f".repeat(64));
}

#[test]
fn it_believes_nothing_until_it_has_listed_what_it_watches() {
    let (record, pods) = deployment(2);
    assert_eq!(
        prove(judge, false, Some(&record), &pods),
        Err(Doubt::NotListed)
    );
    assert_eq!(prove(judge, false, None, &pods), Err(Doubt::NotListed));
}

// In a rollout there can be no record for over a minute, just as most pods are asking. Holding a pod to its owner needs none.
#[test]
fn with_no_record_it_proves_what_it_can_against_each_pods_owner() {
    let (_, pods) = deployment(5);
    assert_eq!(
        prove(judge, true, None, &pods),
        Ok(Proved {
            judged: 6,
            condemned: 0,
            with_record: false
        })
    );
}

#[test]
fn with_no_record_it_still_has_to_see_itself_and_pass_its_own_judgement() {
    let (_, mut pods) = deployment(5);
    let own = pods.remove(0);
    assert_eq!(prove(judge, true, None, &pods), Err(Doubt::CannotSeeItself));
    let mut debugged = own;
    debugged.facts.ephemeral.push("debug".to_string());
    pods.push(debugged);
    assert_eq!(
        prove(judge, true, None, &pods),
        Err(Doubt::NotGenuineItself(NotGenuine::EphemeralContainer {
            container: "debug".to_string()
        }))
    );
}

#[test]
fn with_no_record_a_rule_blind_to_what_an_owner_tells_cannot_say_no() {
    let (_, pods) = deployment(3);
    assert!(matches!(
        prove(|_, _| Verdict::CannotSay, true, None, &pods),
        Err(Doubt::CannotSayNo { .. })
    ));
}

#[test]
fn with_no_record_a_rule_that_condemns_everything_doubts_itself() {
    let (_, pods) = deployment(5);
    let wrong = |_: Option<&WorkloadFacts>, pod: Option<&PodFacts>| match pod
        .and_then(|p| p.owner.as_ref())
    {
        Some(o) if o.name == AGENT_NAME => Verdict::CannotSay,
        _ => Verdict::NotGenuine(NotGenuine::NoOwner),
    };
    assert_eq!(
        prove(wrong, true, None, &pods),
        Err(Doubt::CondemnsMost {
            condemned: 5,
            judged: 6
        })
    );
}

#[test]
fn a_record_that_does_not_name_it_once_is_not_believed() {
    let (mut record, pods) = deployment(2);
    let own = record.workloads.remove(0);
    assert_eq!(
        prove(judge, true, Some(&record), &pods),
        Err(Doubt::NotInItsRecord)
    );
    record.workloads.push(own.clone());
    record.workloads.push(own);
    assert_eq!(
        prove(judge, true, Some(&record), &pods),
        Err(Doubt::NotInItsRecord)
    );
}

#[test]
fn it_has_to_see_itself() {
    let (record, mut pods) = deployment(2);
    pods.remove(0);
    assert_eq!(
        prove(judge, true, Some(&record), &pods),
        Err(Doubt::CannotSeeItself)
    );
}

#[test]
fn it_has_to_pass_its_own_judgement() {
    let (record, mut pods) = deployment(5);
    pods[0].facts.ephemeral.push("debug".to_string());
    assert_eq!(
        prove(judge, true, Some(&record), &pods),
        Err(Doubt::NotGenuineItself(NotGenuine::EphemeralContainer {
            container: "debug".to_string()
        }))
    );
}

// A record can reach it before the new pod exists, in its own rollout, and a pod of the old revision is still its workload's. An image that differs
// from the record is the comparison's to report, after its grace (`Drift`), and not a reason to doubt its verdicts.
#[test]
fn an_image_that_differs_from_the_record_is_not_a_reason_to_doubt_itself() {
    let (mut record, pods) = deployment(5);
    record.workloads[0].containers[0].image =
        format!("registry:5000/image:latest@sha256:{}", "e".repeat(64));
    assert!(prove(judge, true, Some(&record), &pods).is_ok());
}

#[test]
fn a_rule_that_condemns_everything_doubts_itself() {
    let (record, pods) = deployment(5);
    // Its own pod passes, or it would stop there: the rule is wrong about everyone else.
    let wrong = |facts: Option<&WorkloadFacts>, pod: Option<&PodFacts>| match facts {
        Some(f) if f.owner_name == AGENT_NAME => judge(facts, pod),
        _ => Verdict::NotGenuine(NotGenuine::NoOwner),
    };
    assert_eq!(
        prove(wrong, true, Some(&record), &pods),
        Err(Doubt::CondemnsMost {
            condemned: 5,
            judged: 6
        })
    );
}

// Passing everything else proves nothing about an agent that says yes to everything.
#[test]
fn a_rule_that_says_yes_to_everything_cannot_say_no() {
    let (record, pods) = deployment(5);
    assert!(matches!(
        prove(|_, _| Verdict::Genuine, true, Some(&record), &pods),
        Err(Doubt::CannotSayNo { .. })
    ));
}

/// A way of altering a pod, and how to tell a pod altered in that way.
type Blindness = (&'static str, fn(&PodFacts) -> bool);

// One altered in a way this cannot see is one the rule is blind to, whichever it is.
#[test]
fn a_rule_blind_to_any_one_alteration_cannot_say_no() {
    let blind_to: [Blindness; 4] = [
        ("an ephemeral container", |p| !p.ephemeral.is_empty()),
        ("another service account", |p| {
            p.service_account.ends_with("-altered")
        }),
        ("no owner", |p| p.owner.is_none()),
        ("another owner", |p| {
            p.owner
                .as_ref()
                .is_some_and(|o| o.name.ends_with("-altered"))
        }),
    ];
    for (how, is_it) in blind_to {
        let (record, pods) = deployment(3);
        let rule = |facts: Option<&WorkloadFacts>, pod: Option<&PodFacts>| {
            if pod.is_some_and(is_it) {
                Verdict::Genuine
            } else {
                judge(facts, pod)
            }
        };
        assert_eq!(
            prove(rule, true, Some(&record), &pods),
            Err(Doubt::CannotSayNo { altered: how }),
        );
    }
}

proptest! {
    #[test]
    fn a_deployment_as_recorded_is_proved(others in 0usize..12) {
        let (record, pods) = deployment(others);
        prop_assert_eq!(
            prove(judge, true, Some(&record), &pods),
            Ok(Proved { judged: others + 1, condemned: 0, with_record: true })
        );
    }

    // A tampered pod cannot switch the check off for everything: it doubts itself only once most of what it judges is condemned.
    #[test]
    fn it_doubts_itself_exactly_when_most_is_condemned(others in 1usize..12, tampered_n in 0usize..12) {
        let tampered_n = tampered_n.min(others);
        let (record, mut pods) = deployment(others);
        for pod in pods.iter_mut().skip(1).take(tampered_n) {
            tampered(pod);
        }
        let judged = others + 1;
        let proved = prove(judge, true, Some(&record), &pods);
        if tampered_n * 2 > judged {
            prop_assert_eq!(proved, Err(Doubt::CondemnsMost { condemned: tampered_n, judged }));
        } else {
            prop_assert_eq!(proved, Ok(Proved { judged, condemned: tampered_n, with_record: true }));
        }
    }

    // A pod that no workload in the record runs as is not the agent's to weigh here, however many of them there are.
    #[test]
    fn a_pod_the_record_does_not_claim_counts_for_nothing(others in 0usize..6, strangers in 0usize..12) {
        let (record, mut pods) = deployment(others);
        for n in 0..strangers {
            let mut stranger = pods[0].clone();
            stranger.facts.service_account = format!("stranger-{n}");
            tampered(&mut stranger);
            pods.push(stranger);
        }
        prop_assert_eq!(
            prove(judge, true, Some(&record), &pods),
            Ok(Proved { judged: others + 1, condemned: 0, with_record: true })
        );
    }

    // With no record, what fails against its owner is still condemned and the proof still stands, up to the same majority.
    #[test]
    fn with_no_record_a_tampered_pod_is_condemned_and_the_proof_stands(others in 1usize..12, tampered_n in 0usize..12) {
        let tampered_n = tampered_n.min(others);
        let (_, mut pods) = deployment(others);
        for pod in pods.iter_mut().skip(1).take(tampered_n) {
            tampered(pod);
        }
        let judged = others + 1;
        let proved = prove(judge, true, None, &pods);
        if tampered_n * 2 > judged {
            prop_assert_eq!(proved, Err(Doubt::CondemnsMost { condemned: tampered_n, judged }));
        } else {
            prop_assert_eq!(proved, Ok(Proved { judged, condemned: tampered_n, with_record: false }));
        }
    }
}

fn ending() -> impl Strategy<Value = Termination> {
    (
        "[a-z]{1,4}",
        prop_oneof![
            Just(0),
            Just(1),
            Just(137),
            Just(143),
            Just(134),
            Just(139),
            Just(159),
            0i32..256
        ],
        prop::option::of(prop_oneof![Just(0), Just(9), Just(11), Just(31), 0i32..65]),
        0u8..3,
    )
        .prop_map(|(container, exit_code, signal, at)| Termination {
            container,
            exit_code,
            signal,
            finished_at: format!("2026-11-03T12:00:0{at}Z"),
            image_id: "registry/agent@sha256:0".to_string(),
        })
}

/// Pods with distinct UIDs, some genuine, some altered, each with how its containers ended.
fn observed() -> impl Strategy<Value = Vec<ObservedPod>> {
    prop::collection::vec(
        (
            genuine(),
            any::<bool>(),
            prop::collection::vec(ending(), 0..4),
        ),
        0..6,
    )
    .prop_map(|pods| {
        pods.into_iter()
            .enumerate()
            .map(|(i, ((_, mut facts), debugged, terminations))| {
                if debugged {
                    facts.ephemeral = vec!["debugger".to_string()];
                }
                ObservedPod {
                    namespace: "polar".to_string(),
                    name: format!("pod-{i}"),
                    uid: format!("uid-{i}"),
                    facts,
                    terminations,
                }
            })
            .collect()
    })
}

fn is_crash(report: &Report) -> bool {
    matches!(report.finding, attestation_common::Finding::Crashed { .. })
}

proptest! {
    /// Every crash among a pod's endings is said, whether or not the agent is believed, and nothing else is said of an ending.
    #[test]
    fn every_crash_is_said_and_nothing_else_of_an_ending(pods in observed(), believed: bool) {
        let crashes = findings(&pods, believed, None).iter().filter(|r| is_crash(r)).count();
        let mut expected: Vec<(String, String, i32, String)> = Vec::new();
        for pod in &pods {
            for e in &pod.terminations {
                let key = (pod.uid.clone(), e.container.clone(), e.exit_code, e.finished_at.clone());
                if crash_signal(e.exit_code, e.signal).is_some() && !expected.contains(&key) {
                    expected.push(key);
                }
            }
        }
        // The same ending can differ only in how the signal was said, which comes to the same crash or another named one.
        prop_assert!(crashes >= expected.len());
        prop_assert_eq!(crashes == 0, expected.is_empty());
    }

    /// While the agent is not believed, it says nothing it judged.
    #[test]
    fn what_it_judged_is_said_only_while_it_is_believed(pods in observed()) {
        prop_assert!(findings(&pods, false, None).iter().all(is_crash));
        let debugged = pods.iter().filter(|p| !p.facts.ephemeral.is_empty()).count();
        let altered = findings(&pods, true, None).iter().filter(|r| !is_crash(r)).count();
        prop_assert_eq!(altered, debugged);
    }

    /// What it finds does not depend on the order it holds pods in.
    #[test]
    fn findings_do_not_depend_on_the_order_of_pods(pods in observed(), believed: bool) {
        let mut reversed = pods.clone();
        reversed.reverse();
        prop_assert_eq!(findings(&pods, believed, None), findings(&reversed, believed, None));
    }

    /// Over any sequence: a thing is new once while it stands, an alteration is never reported before its second check running, and what stands after a
    /// check is within what that check was told.
    #[test]
    fn reporting_says_each_thing_once_while_it_stands(
        rounds in prop::collection::vec((observed(), any::<bool>()), 1..8),
    ) {
        let mut reporting = Reporting::default();
        let mut reported: Vec<Report> = Vec::new();
        let mut suspected: Vec<Report> = Vec::new();
        for (pods, checking) in rounds {
            let now = findings(&pods, true, None);
            let before: Vec<Report> = reporting.standing().to_vec();
            let new = if checking { reporting.check(&now) } else { reporting.changed(&now) };
            for report in &new {
                prop_assert!(!before.contains(report), "said twice: {report:?}");
                prop_assert!(now.contains(report));
                prop_assert!(is_crash(report) || suspected.contains(report), "too soon: {report:?}");
            }
            reported.extend(new);
            if checking {
                suspected = now.iter().filter(|r| !is_crash(r)).cloned().collect();
                prop_assert!(reporting.standing().iter().all(|r| now.contains(r)));
            }
        }
    }

    /// A report reads back whole, and is taken only from the agent.
    #[test]
    fn a_report_round_trips_and_only_the_agent_may_send_one(pods in observed(), other in "[a-z]{1,8}x") {
        for report in findings(&pods, true, None) {
            let bytes = encode_report(&report);
            prop_assert_eq!(decode_report(&bytes).unwrap(), report.clone());
            prop_assert_eq!(accepted_report(&bytes, Some(AGENT_NAME), AGENT_NAME).unwrap(), report);
            prop_assert!(accepted_report(&bytes, Some(&other), AGENT_NAME).is_err());
            prop_assert!(accepted_report(&bytes, None, AGENT_NAME).is_err());
        }
    }

    /// A record's marks change nothing found but the mark (docs/architecture/configurations-under-test.md, CT2), and a finding is under test exactly
    /// when the record claims its pod, by namespace and service account and for one workload alone, for a workload it marks.
    #[test]
    fn a_finding_is_under_test_exactly_when_its_pods_workload_is_marked(
        pods in observed(),
        marks in prop::collection::vec(any::<bool>(), 6),
        believed: bool,
    ) {
        let workloads = pods.iter().zip(&marks).map(|(pod, marked)| RecordedWorkload {
            identity: format!("{}.polar.serviceaccount.cluster.local", pod.facts.service_account),
            owner_kind: OwnerKind::Deployment,
            owner_name: pod.name.clone(),
            namespace: pod.namespace.clone(),
            service_account: pod.facts.service_account.clone(),
            containers: vec![],
            under_test: *marked,
        }).collect();
        let record = DeploymentRecord { schema: 2, target: "t".into(), version: 1, workloads };
        let marked = findings(&pods, believed, Some(&record));
        let unmarked: Vec<Report> = marked.iter().cloned().map(|r| Report { under_test: false, ..r }).collect();
        prop_assert_eq!(&unmarked, &findings(&pods, believed, None));
        for report in &marked {
            let pod = pods.iter().find(|p| p.uid == report.pod_uid).unwrap();
            let sharing: Vec<&RecordedWorkload> = record.workloads.iter()
                .filter(|w| w.service_account == pod.facts.service_account).collect();
            prop_assert_eq!(report.under_test, sharing.len() == 1 && sharing[0].under_test);
        }
    }

    /// What is not a report is refused, and does not panic.
    #[test]
    fn what_is_not_a_report_is_refused(noise in prop::collection::vec(any::<u8>(), 0..128)) {
        let _ = decode_report(&noise);
    }
}
