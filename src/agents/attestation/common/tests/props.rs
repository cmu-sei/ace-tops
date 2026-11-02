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
    ContainerFacts, NotGenuine, Owner, OwnerKind, PodFacts, Verdict, WorkloadFacts, digest_of,
    judge,
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
