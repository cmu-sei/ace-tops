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

//! What a certificate may record as evidence (the maintainer's decision of 2026-11-09; evidence records:
//! docs/architecture/http-observers.md, "Evidence"): its
//! `c:record-evidence` names. Alone, any record type, for an administrator or a person who runs collectors; scoped,
//! `c:record-evidence:<type>`, that type only, one name a type, `<type>` being the evidence record's `type` field
//! (`[a-z0-9-]+`), for a collector workload, whose types are computed from its scaffold. Several scoped names add up, and
//! the bare one beside them is any type. A workload that signs records can then forge at most its own kind.
//!
//! Its own type beside [`crate::capability::Capability`], which is closed and archived in grants: a reader of
//! certificates built before this skips a `c:` name it does not know (`extract_capabilities`), so these names can be
//! issued once the readers that judge evidence (the custody daemon's signer, the git server's evidence intake,
//! `polar-eden records`) are deployed.

use crate::permission::{PermissionExtractionError, san_strings};
use std::collections::BTreeSet;

/// The bare name: any record type.
pub const RECORD_EVIDENCE: &str = "c:record-evidence";

/// One `c:record-evidence` name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceCapability {
    /// `c:record-evidence`: any record type.
    Any,
    /// `c:record-evidence:<type>`: records of that type only.
    Type(String),
}

/// Why a name is not a `c:record-evidence` name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "`{0}` is not an evidence capability (c:record-evidence, or c:record-evidence:<type> with <type> of a-z, 0-9 and -)"
)]
pub struct NotAnEvidenceCapability(pub String);

/// Whether `record_type` is a record type a scoped name may carry: one or more of `a-z`, `0-9` and `-`.
pub fn is_record_type(record_type: &str) -> bool {
    !record_type.is_empty()
        && record_type
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

impl EvidenceCapability {
    pub fn to_san_string(&self) -> String {
        match self {
            Self::Any => RECORD_EVIDENCE.to_string(),
            Self::Type(record_type) => format!("{RECORD_EVIDENCE}:{record_type}"),
        }
    }

    /// The inverse of [`to_san_string`](Self::to_san_string), exactly: nothing else is one.
    pub fn from_san_string(name: &str) -> Result<Self, NotAnEvidenceCapability> {
        if name == RECORD_EVIDENCE {
            return Ok(Self::Any);
        }
        name.strip_prefix(RECORD_EVIDENCE)
            .and_then(|rest| rest.strip_prefix(':'))
            .filter(|record_type| is_record_type(record_type))
            .map(|record_type| Self::Type(record_type.to_string()))
            .ok_or_else(|| NotAnEvidenceCapability(name.to_string()))
    }
}

/// What a certificate may record as evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MayRecord {
    /// No `c:record-evidence` name: nothing.
    Nothing,
    /// The bare name: any record type.
    Any,
    /// These types, and no others.
    Only(BTreeSet<String>),
}

impl MayRecord {
    /// What `names` (a certificate's SAN names, any of them) allow. Names that are not evidence capabilities are
    /// skipped, a malformed one among them.
    pub fn of_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Self {
        let mut types = BTreeSet::new();
        for name in names {
            match EvidenceCapability::from_san_string(name) {
                Ok(EvidenceCapability::Any) => return Self::Any,
                Ok(EvidenceCapability::Type(record_type)) => {
                    types.insert(record_type);
                }
                Err(_) => {}
            }
        }
        if types.is_empty() {
            Self::Nothing
        } else {
            Self::Only(types)
        }
    }

    /// Whether a record of `record_type` may be signed with this.
    pub fn allows(&self, record_type: &str) -> bool {
        match self {
            Self::Nothing => false,
            Self::Any => true,
            Self::Only(types) => types.contains(record_type),
        }
    }
}

/// What `certificate_pem` may record as evidence, from its `c:record-evidence` names.
pub fn may_record(certificate_pem: &str) -> Result<MayRecord, PermissionExtractionError> {
    let names = san_strings(certificate_pem)?;
    Ok(MayRecord::of_names(names.iter().map(String::as_str)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn certificate(sans: &[&str]) -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        rcgen::CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .pem()
    }

    fn only(types: &[&str]) -> MayRecord {
        MayRecord::Only(types.iter().map(|t| t.to_string()).collect())
    }

    #[test]
    fn the_names_are_as_decided() {
        assert_eq!(EvidenceCapability::Any.to_san_string(), "c:record-evidence");
        assert_eq!(
            EvidenceCapability::Type("attestation-report".into()).to_san_string(),
            "c:record-evidence:attestation-report"
        );
        assert_eq!(
            EvidenceCapability::from_san_string("c:record-evidence:attestation"),
            Ok(EvidenceCapability::Type("attestation".into()))
        );
    }

    #[test]
    fn what_is_not_exactly_one_is_refused() {
        for name in [
            "c:record-evidence:",
            "c:record-evidence:Attestation",
            "c:record-evidence:a_b",
            "c:record-evidence:a:b",
            "c:record-evidence:a b",
            "c:record-evidences",
            "c:record-evidence-x",
            "c:record",
            "p:record-evidence",
            "record-evidence",
            "c:update-policy",
        ] {
            assert!(EvidenceCapability::from_san_string(name).is_err(), "{name}");
        }
    }

    #[test]
    fn a_certificate_may_record_what_its_names_say() {
        let identity = "kube-observer.polar.serviceaccount.cluster.local";
        assert_eq!(
            may_record(&certificate(&[identity])).unwrap(),
            MayRecord::Nothing
        );
        assert_eq!(
            may_record(&certificate(&[identity, "c:record-evidence"])).unwrap(),
            MayRecord::Any
        );
        let scoped = may_record(&certificate(&[
            identity,
            "c:record-evidence:attestation-report",
            "c:record-evidence:attestation",
            "c:update-policy",
        ]))
        .unwrap();
        assert_eq!(scoped, only(&["attestation", "attestation-report"]));
        assert!(scoped.allows("attestation") && scoped.allows("attestation-report"));
        assert!(!scoped.allows("projection-test"));
        // The bare name beside scoped ones is any type.
        assert_eq!(
            may_record(&certificate(&[
                identity,
                "c:record-evidence:attestation",
                "c:record-evidence"
            ]))
            .unwrap(),
            MayRecord::Any
        );
        // A malformed name gives nothing; it does not widen.
        assert_eq!(
            may_record(&certificate(&[identity, "c:record-evidence:Bad"])).unwrap(),
            MayRecord::Nothing
        );
    }

    #[test]
    fn nothing_allows_nothing_and_any_allows_every_type() {
        assert!(!MayRecord::Nothing.allows("attestation"));
        assert!(MayRecord::Any.allows("attestation"));
        assert!(MayRecord::Any.allows("projection-test"));
    }

    #[test]
    fn a_pem_that_is_not_a_certificate_is_an_error_not_a_panic() {
        assert!(may_record("not a certificate").is_err());
    }

    fn record_type() -> impl Strategy<Value = String> {
        "[a-z0-9-]{1,12}"
    }

    fn capability() -> impl Strategy<Value = EvidenceCapability> {
        prop_oneof![
            Just(EvidenceCapability::Any),
            record_type().prop_map(EvidenceCapability::Type),
        ]
    }

    proptest! {
        /// Every name reads back as itself.
        #[test]
        fn a_name_round_trips(capability in capability()) {
            prop_assert_eq!(
                EvidenceCapability::from_san_string(&capability.to_san_string()),
                Ok(capability)
            );
        }

        /// A record type is exactly one or more of a-z, 0-9 and -.
        #[test]
        fn a_record_type_is_its_rule(s in "\\PC{0,12}") {
            let rule = !s.is_empty()
                && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
            prop_assert_eq!(is_record_type(&s), rule);
            prop_assert_eq!(
                EvidenceCapability::from_san_string(&format!("c:record-evidence:{s}")).is_ok(),
                rule
            );
        }

        /// What names allow follows the rule for every set of them, in any order: any type with a bare name; else the
        /// union of the scoped types; else nothing. Other names change nothing.
        #[test]
        fn what_names_allow_follows_the_rule(
            capabilities in prop::collection::vec(capability(), 0..6),
            others in prop::collection::vec("[a-z:.]{0,10}", 0..4),
            asked in record_type(),
        ) {
            let mut names: Vec<String> = capabilities.iter().map(EvidenceCapability::to_san_string).collect();
            names.extend(others.iter().filter(|o| !o.starts_with("c:record-evidence")).cloned());
            let forward = MayRecord::of_names(names.iter().map(String::as_str));
            names.reverse();
            let backward = MayRecord::of_names(names.iter().map(String::as_str));
            prop_assert_eq!(&forward, &backward);

            let types: BTreeSet<String> = capabilities
                .iter()
                .filter_map(|c| match c {
                    EvidenceCapability::Type(t) => Some(t.clone()),
                    EvidenceCapability::Any => None,
                })
                .collect();
            let expected = if capabilities.contains(&EvidenceCapability::Any) {
                MayRecord::Any
            } else if types.is_empty() {
                MayRecord::Nothing
            } else {
                MayRecord::Only(types.clone())
            };
            prop_assert_eq!(&forward, &expected);
            prop_assert_eq!(
                forward.allows(&asked),
                capabilities.contains(&EvidenceCapability::Any) || types.contains(&asked)
            );
        }
    }
}
