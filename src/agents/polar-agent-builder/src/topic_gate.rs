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

//! The check each publish and subscribe passes before it leaves the agent: the agent's own policy first, then its
//! topic set, the same rule the broker applies (docs/architecture/policy-enforcement.md, "Decisions"). A `permit`
//! admits a topic outside the set, a `forbid` refuses one inside it, and where no policy speaks, or there is none
//! yet, the set decides. A policy that cannot be consulted refuses: nothing here fails open. The Cassini client is
//! handed it as a function (`cassini_client::facade::TopicGate`) and decides nothing itself. The broker applies the
//! same [`rule`], with [`ask`], to the floor its client's certificate gives ([`Floor`](crate::Floor)), so the agent and
//! the broker decide alike by construction.

use crate::authority::{LookupError, PolicyLookup};
use crate::policy_authority::entity;
use crate::topics::{Access, TopicSet};
use cassini_client::facade::{TopicGate, TopicUse};
use std::sync::Arc;

pub use polar_topics::gate::{PolicySaid, rule};

/// Asks the agent's policy, as `identity`, about using `topic` this way: `Action::"publish"` or
/// `Action::"subscribe"` on `Topic::"<topic>"`.
pub async fn ask(
    lookup: &PolicyLookup,
    identity: &str,
    certificate_pem: Option<String>,
    topic: &str,
    access: Access,
    facts: polar_policy::TopicFacts,
) -> PolicySaid {
    if lookup.actor().is_none() {
        return PolicySaid::NotRunning;
    }
    let (Some(action), Some(resource)) =
        (entity("Action", access.as_str()), entity("Topic", topic))
    else {
        return PolicySaid::Unavailable(format!(
            "`{topic}` is not a name policy can be asked about"
        ));
    };
    match lookup
        .decide(
            identity,
            certificate_pem,
            &action,
            &resource,
            polar_policy::Facts {
                topic: Some(facts),
                addressed: addressed_to(topic).map(str::to_string),
                ..Default::default()
            },
        )
        .await
    {
        Ok(decision) => PolicySaid::Decided(decision),
        Err(LookupError::NoPolicyLoaded) => PolicySaid::NoPolicyLoaded,
        Err(LookupError::Unavailable(why)) => PolicySaid::Unavailable(why),
    }
}

/// The person `topic` is addressed to: its last segment, when that is a person's identity (an account's UUID,
/// `polar_git_server_common::is_person`); none for any other topic (docs/architecture/record-store.md, "People's tools
/// over Cassini").
pub fn addressed_to(topic: &str) -> Option<&str> {
    topic
        .rsplit_once('.')
        .map(|(_, last)| last)
        .filter(|last| polar_git_server_common::is_person(last))
}

/// The gate for an agent named `service`, whose certificate's identity is `identity` and whose topics are `set`.
/// `certificate_pem` is its own certificate, read when it started, so the groups it carries count (its groups do not
/// change when it is renewed: they are the catalog's).
pub fn gate(
    service: &str,
    identity: String,
    certificate_pem: Option<String>,
    set: Arc<TopicSet>,
) -> TopicGate {
    let lookup = PolicyLookup::for_service(service);
    Arc::new(move |use_, topic: String| {
        let lookup = lookup.clone();
        let identity = identity.clone();
        let certificate_pem = certificate_pem.clone();
        let set = set.clone();
        Box::pin(async move {
            let access = match use_ {
                TopicUse::Publish => Access::Publish,
                TopicUse::Subscribe => Access::Subscribe,
            };
            let said = ask(
                &lookup,
                &identity,
                certificate_pem,
                &topic,
                access,
                set.facts(&topic, access),
            )
            .await;
            rule(&said, set.allows(&topic, access), &topic, access)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topics::{Facts, TopicDecl};
    use polar_policy::Decision;
    use proptest::prelude::*;
    use ractor::Actor;

    const IDENTITY: &str = "kube-observer.polar.serviceaccount.cluster.local";

    fn set() -> Arc<TopicSet> {
        Arc::new(TopicSet::compute(
            &Facts {
                name: "kube-observer",
                cassini_client: true,
                self_test: true,
                encryption: false,
                soft_state: false,
                checkpoints: false,
            },
            &[TopicDecl::publish(
                "kubernetes.cluster.consumer.Pod",
                "what it sees",
            )],
        ))
    }

    /// A policy actor registered for `service`, holding `source` (no rules when it is empty).
    async fn policy_for(service: &str, source: &str) {
        let (permissions, _) = Actor::spawn(None, polar_permissions::PermissionsActor, ())
            .await
            .unwrap();
        let (policy, _) = Actor::spawn(
            Some(format!("{service}.policy")),
            polar_policy::PolicyActor,
            polar_policy::PolicyActorArgs {
                permissions_actor: permissions,
            },
        )
        .await
        .unwrap();
        if !source.is_empty() {
            ractor::call!(policy, |reply| polar_policy::PolicyMessage::UpdatePolicy {
                policy_source: source.to_string(),
                reply,
            })
            .unwrap()
            .unwrap();
        }
    }

    async fn uses(service: &str, use_: TopicUse, topic: &str) -> Result<(), String> {
        gate(service, IDENTITY.to_string(), None, set())(use_, topic.to_string()).await
    }

    #[tokio::test]
    async fn with_no_policy_yet_the_set_decides() {
        let service = format!("gate-none-{}", rand::random::<u64>());
        assert!(
            uses(
                &service,
                TopicUse::Publish,
                "kubernetes.cluster.consumer.Pod"
            )
            .await
            .is_ok()
        );
        let said = uses(&service, TopicUse::Publish, "somebody.elses.topic")
            .await
            .unwrap_err();
        assert!(
            said.contains("not among its declared or implied topics"),
            "{said}"
        );
        // Declared to publish is not declared to subscribe.
        assert!(
            uses(
                &service,
                TopicUse::Subscribe,
                "kubernetes.cluster.consumer.Pod"
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn a_policy_with_no_rules_or_silent_on_topics_leaves_it_to_the_set() {
        let empty = format!("gate-empty-{}", rand::random::<u64>());
        policy_for(&empty, "").await;
        assert!(
            uses(&empty, TopicUse::Publish, "kubernetes.cluster.consumer.Pod")
                .await
                .is_ok()
        );
        assert!(
            uses(&empty, TopicUse::Publish, "somebody.elses.topic")
                .await
                .is_err()
        );

        // The seeded policy speaks only of retrieving secrets.
        let seeded = format!("gate-seeded-{}", rand::random::<u64>());
        policy_for(
            &seeded,
            include_str!("../../../../infra/seeds/signed/policy.cedar"),
        )
        .await;
        assert!(
            uses(
                &seeded,
                TopicUse::Publish,
                "kubernetes.cluster.consumer.Pod"
            )
            .await
            .is_ok()
        );
        assert!(
            uses(&seeded, TopicUse::Publish, "somebody.elses.topic")
                .await
                .is_err()
        );
    }

    #[test]
    fn a_topic_is_addressed_to_the_person_its_name_ends_with_and_no_other_is() {
        let alice = "0a11ce00-0000-4000-8000-000000000001";
        assert_eq!(
            addressed_to(&format!("polar-log-read-replies.{alice}")),
            Some(alice)
        );
        for not_addressed in [
            "polar-log-read-replies.polar-scheduler-observer",
            "polar-log-read-replies",
            alice,
            "agent.kube-observer.configuration",
        ] {
            assert_eq!(addressed_to(not_addressed), None, "{not_addressed}");
        }
    }

    /// record-store.md, "People's tools over Cassini": under the first policy, a person hears what is addressed to
    /// them and nobody else does, and the store publishes it; another workload may not.
    #[tokio::test]
    async fn under_the_first_policy_a_person_hears_what_is_addressed_to_them_and_the_store_says_it()
    {
        let alice = "0a11ce00-0000-4000-8000-000000000001";
        let bob = "0b0b0000-0000-4000-8000-000000000002";
        let topic = format!("polar-log-read-replies.{alice}");
        let service = format!("gate-addressed-{}", rand::random::<u64>());
        policy_for(
            &service,
            include_str!("../../../../infra/seeds/signed/policy.cedar"),
        )
        .await;
        let lookup = PolicyLookup::for_service(&service);
        let said = |identity: &'static str, access: Access| {
            let (lookup, topic) = (lookup.clone(), topic.clone());
            async move {
                ask(
                    &lookup,
                    identity,
                    None,
                    &topic,
                    access,
                    polar_policy::TopicFacts::default(),
                )
                .await
            }
        };
        let allowed = PolicySaid::Decided(Decision::Allow);
        assert_eq!(said(alice, Access::Subscribe).await, allowed);
        assert_ne!(said(bob, Access::Subscribe).await, allowed);
        assert_ne!(said(alice, Access::Publish).await, allowed);
        assert_eq!(
            said(
                "polar-git-server.polar.serviceaccount.cluster.local",
                Access::Publish
            )
            .await,
            allowed
        );
        assert_ne!(
            said(
                "kube-observer.polar.serviceaccount.cluster.local",
                Access::Publish
            )
            .await,
            allowed
        );
    }

    #[tokio::test]
    async fn policy_is_told_whether_the_topic_is_the_agent_s_own() {
        // A policy can keep every agent to what it declared, whatever else it permits.
        let service = format!("gate-facts-{}", rand::random::<u64>());
        policy_for(
            &service,
            r#"forbid (principal, action == Action::"publish", resource) unless { context.declared || context.implied };"#,
        )
        .await;
        assert!(
            uses(
                &service,
                TopicUse::Publish,
                "kubernetes.cluster.consumer.Pod"
            )
            .await
            .is_ok()
        );
        let said = uses(&service, TopicUse::Publish, "somebody.elses.topic")
            .await
            .unwrap_err();
        assert!(said.contains("policy forbids"), "{said}");
    }

    #[tokio::test]
    async fn the_groups_the_agent_s_certificate_carries_count_in_its_own_decisions() {
        let service = format!("gate-groups-{}", rand::random::<u64>());
        policy_for(
            &service,
            r#"forbid (principal, action == Action::"publish", resource) unless { principal in Group::"cassini-client" };"#,
        )
        .await;
        let certificate = crate::own_name::tests::certificate_with(&[IDENTITY, "g:cassini-client"]);
        let with = gate(&service, IDENTITY.to_string(), Some(certificate), set());
        assert!(
            with(TopicUse::Publish, "kubernetes.cluster.consumer.Pod".into())
                .await
                .is_ok()
        );
        let without = gate(&service, IDENTITY.to_string(), None, set());
        assert!(
            without(TopicUse::Publish, "kubernetes.cluster.consumer.Pod".into())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn policy_overrides_the_set_both_ways() {
        let service = format!("gate-policy-{}", rand::random::<u64>());
        policy_for(
            &service,
            &format!(
                r#"permit (principal == Identity::"{IDENTITY}", action == Action::"publish", resource == Topic::"agent.new-workload.configuration");
                   forbid (principal == Identity::"{IDENTITY}", action == Action::"publish", resource == Topic::"kubernetes.cluster.consumer.Pod");"#
            ),
        )
        .await;
        // A permit admits what the set does not hold, and a forbid refuses what it does.
        assert!(
            uses(
                &service,
                TopicUse::Publish,
                "agent.new-workload.configuration"
            )
            .await
            .is_ok()
        );
        let said = uses(
            &service,
            TopicUse::Publish,
            "kubernetes.cluster.consumer.Pod",
        )
        .await
        .unwrap_err();
        assert!(said.contains("policy forbids"), "{said}");
        // Where it says nothing, the set decides.
        assert!(
            uses(&service, TopicUse::Subscribe, "polar-authority-updates")
                .await
                .is_ok()
        );
        assert!(
            uses(&service, TopicUse::Publish, "somebody.elses.topic")
                .await
                .is_err()
        );
    }

    fn said() -> impl Strategy<Value = PolicySaid> {
        prop_oneof![
            Just(PolicySaid::NotRunning),
            Just(PolicySaid::NoPolicyLoaded),
            Just(PolicySaid::Decided(Decision::Allow)),
            Just(PolicySaid::Decided(Decision::Deny)),
            Just(PolicySaid::Decided(Decision::NotDetermined)),
            "[a-z ]{0,12}".prop_map(PolicySaid::Unavailable),
        ]
    }

    proptest! {
        /// Policy first, then the set: an answer decides, silence or no policy leaves it to the set, and no answer
        /// at all refuses, whatever the topic and whichever way it is used.
        #[test]
        fn the_decision_follows_the_rule(
            said in said(),
            in_set in any::<bool>(),
            topic in "[a-z.:-]{1,20}",
            publish in any::<bool>(),
        ) {
            let access = if publish { Access::Publish } else { Access::Subscribe };
            let admitted = rule(&said, in_set, &topic, access).is_ok();
            let expected = match &said {
                PolicySaid::Decided(Decision::Allow) => true,
                PolicySaid::Decided(Decision::Deny) | PolicySaid::Unavailable(_) => false,
                _ => in_set,
            };
            prop_assert_eq!(admitted, expected);
            if let Err(reason) = rule(&said, in_set, &topic, access) {
                prop_assert!(reason.contains(&topic));
                // The client re-registers on this phrase from the broker; a refusal must never carry it.
                prop_assert!(!reason.contains("session mismatch"));
            }
        }
    }
}
