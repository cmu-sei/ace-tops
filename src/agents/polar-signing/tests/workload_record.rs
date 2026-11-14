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

//! A record a workload signed, held to the certificate a workload signs with (docs/architecture/key-custody.md, "Workload
//! signing keys"): a signing certificate, never its mTLS one. What it may record is policy first, the readers' to ask
//! (`polar_policy::evidence`, docs/architecture/credentials-policy.md, "Who may sign evidence").

use polar_signing::testing::{Spec, root, signer};
use polar_signing::{Document, Domain, workload_certificate_refusal};
use proptest::prelude::*;
use rcgen::ExtendedKeyUsagePurpose;
use serde_json::json;

const WORKLOAD: &str = "attestation-agent.polar.serviceaccount.cluster.local";

fn document_signing() -> ExtendedKeyUsagePurpose {
    ExtendedKeyUsagePurpose::Other(cert_issuer_common::OID_DOCUMENT_SIGNING.to_vec())
}

/// A record of `record_type`, signed under a certificate for the workload with `ekus` and `names`.
fn signed(
    record_type: &str,
    ekus: Vec<ExtendedKeyUsagePurpose>,
    names: Vec<&'static str>,
) -> Document {
    let ca = root("Polar test CA");
    let pod = signer(
        &ca,
        Spec {
            identity: WORKLOAD,
            capabilities: names,
            extended_key_usages: ekus,
            ..Spec::default()
        },
    );
    polar_signing::sign_in(
        Domain::EVIDENCE_RECORD,
        json!({ "type": record_type, "subject": { "target": "u7c" } }),
        std::slice::from_ref(&pod.cert_pem),
        &pod.key_pem,
    )
    .unwrap()
}

#[test]
fn a_workload_s_record_is_signed_under_a_signing_certificate_and_never_a_tls_one() {
    for names in [
        vec!["c:record-evidence:attestation"],
        vec!["c:record-evidence"],
        // What it may record is the readers' to judge, policy first (`polar_policy::evidence`): not this rule's.
        vec!["c:record-evidence:projection-test"],
        vec![],
    ] {
        let ok = signed("attestation", vec![document_signing()], names.clone());
        assert_eq!(workload_certificate_refusal(&ok), None, "{names:?}");
    }
    for (why, document, says) in [
        (
            "its mTLS certificate",
            signed(
                "attestation",
                vec![ExtendedKeyUsagePurpose::ClientAuth],
                vec!["c:record-evidence:attestation"],
            ),
            "TLS",
        ),
        (
            "a signing certificate that may also serve TLS",
            signed(
                "attestation",
                vec![document_signing(), ExtendedKeyUsagePurpose::ServerAuth],
                vec!["c:record-evidence:attestation"],
            ),
            "TLS",
        ),
        (
            "no extended key usage, taken for any use",
            signed("attestation", vec![], vec!["c:record-evidence:attestation"]),
            "signing certificate",
        ),
    ] {
        let refusal = workload_certificate_refusal(&document);
        assert!(
            refusal.as_deref().is_some_and(|r| r.contains(says)),
            "{why}: {refusal:?}"
        );
    }
}

fn an_eku() -> impl Strategy<Value = ExtendedKeyUsagePurpose> {
    prop::sample::select(vec![
        document_signing(),
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::Any,
        ExtendedKeyUsagePurpose::EmailProtection,
    ])
}

fn a_name() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec![
        "c:record-evidence",
        "c:record-evidence:attestation",
        "c:record-evidence:attestation-report",
        "c:record-evidence:Bad",
        "c:update-configuration",
    ])
}

proptest! {
    // The rule, for every certificate: a workload's record is refused exactly when its certificate is not for signing
    // documents, or is for a TLS purpose too, whatever names it carries.
    #[test]
    fn a_workload_s_certificate_is_judged_by_its_purpose_alone(
        ekus in prop::collection::vec(an_eku(), 0..3),
        names in prop::collection::btree_set(a_name(), 0..4),
        record_type in prop::sample::select(vec!["attestation", "attestation-report"]),
    ) {
        let names: Vec<_> = names.into_iter().collect();
        let document = signed(record_type, ekus.clone(), names.clone());
        let for_signing = ekus.contains(&document_signing())
            && !ekus.iter().any(|e| matches!(
                e,
                ExtendedKeyUsagePurpose::ClientAuth | ExtendedKeyUsagePurpose::ServerAuth | ExtendedKeyUsagePurpose::Any
            ));
        prop_assert_eq!(workload_certificate_refusal(&document).is_none(), for_signing);
    }
}
