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

//! Who may sign an evidence record of a type: policy first, both ways, and the certificate where policy is silent (the
//! maintainer, 2026-11-10: "update evidence signing permissions for users as policy updates from configuration").
//!
//! A record's signer is asked as `Action::"record-evidence"` on `Evidence::"<type>"`. A rule that permits it admits the
//! signer whatever their certificate carries, so a signed policy update can give a person the right to sign one type, or
//! every type, with no new certificate; a rule that forbids it refuses them whatever their certificate carries, so one can
//! be withdrawn. Where no rule applies, or no policy is loaded, the certificate's evidence names decide
//! (`cert_issuer_common::evidence`: the bare `c:record-evidence` any type, `c:record-evidence:<type>` that type). A rule
//! that cannot be evaluated refuses: nothing here fails open. Every reader of a record asks this (the git server's intake,
//! `polar-eden records`), an agent through its policy actor and a tool through an [`Evaluator`] of the policy as it stood.

use crate::{Decision, Evaluator, Facts, PolicyError, Requester};
use cert_issuer_common::evidence::{MayRecord, is_record_type};

/// The action a record's signer is asked for.
pub const ACTION: &str = "record-evidence";
/// The resource type of a record type.
pub const RESOURCE_TYPE: &str = "Evidence";

/// The verdict, from what policy said of it (`None` when no policy is loaded) and the certificate's evidence names.
pub fn verdict(
    policy: Option<Result<Decision, PolicyError>>,
    certificate: &MayRecord,
    record_type: &str,
) -> bool {
    match policy {
        Some(Ok(Decision::Allow)) => true,
        Some(Ok(Decision::Deny)) => false,
        // Policy does not speak to it, or none is loaded: the certificate decides.
        None | Some(Ok(Decision::NotDetermined)) | Some(Err(PolicyError::NoPolicyLoaded)) => {
            certificate.allows(record_type)
        }
        Some(Err(_)) => false,
    }
}

/// Whether `requester` may sign a record of `record_type` under `policy` (none loaded: `None`), at `now_secs`, given
/// what their certificate says (`certificate`, `cert_issuer_common::evidence::may_record`). A type that is not one is
/// never signed.
pub fn may_sign(
    policy: Option<&Evaluator>,
    requester: &Requester,
    certificate: &MayRecord,
    record_type: &str,
    now_secs: u64,
) -> bool {
    // The type goes into an entity reference: one that is not a record type names nothing, and is never signed.
    if !is_record_type(record_type) {
        return false;
    }
    let answer = policy.map(|policy| {
        policy.decide(
            requester,
            &format!("Action::\"{ACTION}\""),
            &format!("{RESOURCE_TYPE}::\"{record_type}\""),
            &Facts::default(),
            now_secs,
        )
    });
    verdict(answer, certificate, record_type)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cert_issuer_common::capability::Capability;
    use cert_issuer_common::hierarchy::Hierarchy;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    fn evaluator(source: &str) -> Evaluator {
        Evaluator::new(source, &Hierarchy::default()).unwrap()
    }

    fn signer<'a>(identity: &'a str, capabilities: &'a [Capability]) -> Requester<'a> {
        Requester {
            identity,
            groups: &[],
            capabilities,
            permissions: &[],
        }
    }

    fn only(types: &[&str]) -> MayRecord {
        MayRecord::Only(types.iter().map(|t| t.to_string()).collect::<BTreeSet<_>>())
    }

    #[test]
    fn a_policy_update_gives_a_person_a_type_their_certificate_does_not_carry() {
        let policy = evaluator(
            r#"permit(principal == Identity::"alice", action == Action::"record-evidence", resource == Evidence::"mutation");"#,
        );
        let alice = signer("alice", &[]);
        assert!(may_sign(
            Some(&policy),
            &alice,
            &MayRecord::Nothing,
            "mutation",
            0
        ));
        // Silent on the other types: her certificate, which carries nothing, decides.
        assert!(!may_sign(
            Some(&policy),
            &alice,
            &MayRecord::Nothing,
            "attestation",
            0
        ));
        // Silent on someone else.
        assert!(!may_sign(
            Some(&policy),
            &signer("bob", &[]),
            &MayRecord::Nothing,
            "mutation",
            0
        ));
    }

    #[test]
    fn a_policy_update_withdraws_what_a_certificate_carries() {
        let policy = evaluator(
            r#"forbid(principal == Identity::"mallory", action == Action::"record-evidence", resource);"#,
        );
        let mallory = signer("mallory", &[Capability::RecordEvidence]);
        assert!(!may_sign(
            Some(&policy),
            &mallory,
            &MayRecord::Any,
            "mutation",
            0
        ));
        // Without the rule, the certificate's bare name allows any type.
        assert!(may_sign(None, &mallory, &MayRecord::Any, "mutation", 0));
    }

    #[test]
    fn a_rule_can_name_the_bare_capability_and_a_scoped_certificate_holds_its_types() {
        let policy = evaluator(
            r#"permit(principal in Capability::"record-evidence", action == Action::"record-evidence", resource);"#,
        );
        assert!(may_sign(
            Some(&policy),
            &signer("admin", &[Capability::RecordEvidence]),
            &MayRecord::Nothing,
            "kani",
            0
        ));
        let collector = signer("collector.polar.serviceaccount.cluster.local", &[]);
        assert!(may_sign(
            None,
            &collector,
            &only(&["attestation"]),
            "attestation",
            0
        ));
        assert!(!may_sign(
            None,
            &collector,
            &only(&["attestation"]),
            "mutation",
            0
        ));
    }

    #[test]
    fn a_type_that_is_not_one_is_never_signed() {
        let policy =
            evaluator(r#"permit(principal, action == Action::"record-evidence", resource);"#);
        for not_one in ["", "Mutation", "a b", "x\"y", "evidence::\"z\""] {
            assert!(
                !may_sign(
                    Some(&policy),
                    &signer("alice", &[]),
                    &MayRecord::Any,
                    not_one,
                    0
                ),
                "{not_one}"
            );
        }
    }

    #[test]
    fn the_vocabulary_is_the_schema_s() {
        assert!(crate::validate_source(
            r#"permit(principal, action == Action::"record-evidence", resource == Evidence::"mutation");"#
        )
        .is_ok());
        assert!(crate::validate_source(
            r#"permit(principal, action == Action::"record-evidence", resource == Section::"a/b");"#
        )
        .is_err());
    }

    fn policy_answer() -> impl Strategy<Value = Option<Result<Decision, PolicyError>>> {
        (0usize..7).prop_map(|i| match i {
            0 => None,
            1 => Some(Ok(Decision::Allow)),
            2 => Some(Ok(Decision::Deny)),
            3 => Some(Ok(Decision::NotDetermined)),
            4 => Some(Err(PolicyError::NoPolicyLoaded)),
            5 => Some(Err(PolicyError::RequestConstruction("x".into()))),
            _ => Some(Err(PolicyError::PermissionsResolution("x".into()))),
        })
    }

    fn certificate() -> impl Strategy<Value = MayRecord> {
        prop_oneof![
            Just(MayRecord::Nothing),
            Just(MayRecord::Any),
            proptest::collection::btree_set("[a-c]", 1..3).prop_map(MayRecord::Only),
        ]
    }

    proptest! {
        /// Policy first, both ways; the certificate where it is silent or not loaded; refused when it cannot be asked.
        #[test]
        fn policy_decides_first_and_the_certificate_where_it_is_silent(
            policy in policy_answer(),
            certificate in certificate(),
            record_type in "[a-c]",
        ) {
            let expected = match &policy {
                Some(Ok(Decision::Allow)) => true,
                Some(Ok(Decision::Deny)) => false,
                None | Some(Ok(Decision::NotDetermined)) | Some(Err(PolicyError::NoPolicyLoaded)) => certificate.allows(&record_type),
                Some(Err(_)) => false,
            };
            prop_assert_eq!(verdict(policy, &certificate, &record_type), expected);
        }
    }
}
