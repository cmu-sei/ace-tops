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
    ContainerFacts, Deployed, DeploymentRecord, Drift, DriftWatch, Envelope, InstanceQuestion,
    NotGenuine, Owner, OwnerKind, PodFacts, RecordedContainer, RecordedWorkload, Verdict,
    WorkloadFacts, decode_question, decode_verdict, digest_of, drift, encode_question,
    encode_verdict, judge, replies_topic,
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
    )
        .prop_map(|(name, owner_kind, images)| RecordedWorkload {
            identity: format!("{name}.polar.serviceaccount.cluster.local"),
            owner_kind,
            owner_name: name.clone(),
            namespace: "polar".into(),
            service_account: name,
            containers: images
                .into_iter()
                .map(|(name, image)| RecordedContainer { name, image })
                .collect(),
        })
}

fn record() -> impl Strategy<Value = DeploymentRecord> {
    prop::collection::btree_map("[a-c]{1,2}", workload(), 0..5).prop_map(|named| DeploymentRecord {
        schema: 1,
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
