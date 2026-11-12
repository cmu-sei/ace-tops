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

//! Checking a log's checkpoint certificate, the one that makes a checkpoint key its holder's for that purpose alone
//! (docs/architecture/record-store.md, "L2, checkpoints"), against real certificates, and that no other check takes
//! it.

use polar_signing::testing::{
    ESCROW_PUBLIC_KEY_PEM, EscrowSpec, authority_spec, checkpoint_spec, escrow_certificate,
    escrow_certificate_for, now, p256_public_key_pem, root,
};
use polar_signing::{
    Trust, VerifyError, verify_authority_certificate, verify_checkpoint_certificate,
    verify_escrow_certificate,
};
use proptest::prelude::*;
use rcgen::{ExtendedKeyUsagePurpose, KeyUsagePurpose};

const CREDENTIALS: &str = "credentials-agent.polar.serviceaccount.cluster.local";

fn trust(pem: &str) -> Trust {
    Trust::from_pem(&[pem.to_string()]).unwrap()
}

fn same_key(a: &str, b: &str) -> bool {
    let squash = |s: &str| s.split_whitespace().collect::<String>();
    squash(a) == squash(b)
}

fn document_signing() -> ExtendedKeyUsagePurpose {
    ExtendedKeyUsagePurpose::Other(cert_issuer_common::OID_DOCUMENT_SIGNING.to_vec())
}

#[test]
fn the_credentials_agent_s_checkpoint_certificate_gives_its_key() {
    let ca = root("Polar Internal CA");
    let key = p256_public_key_pem();
    let cert = escrow_certificate_for(&ca, checkpoint_spec(CREDENTIALS), &key);
    let certified =
        verify_checkpoint_certificate(&cert, &trust(&ca.pem), now(), CREDENTIALS).unwrap();
    assert!(same_key(&certified, &key), "{certified}");
}

#[test]
fn another_identity_s_or_an_untrusted_ca_s_checkpoint_certificate_is_refused() {
    let ca = root("Polar Internal CA");
    let other = root("Polar Internal CA");
    let key = p256_public_key_pem();
    let cert = escrow_certificate_for(
        &ca,
        checkpoint_spec("polar-git-server.polar.serviceaccount.cluster.local"),
        &key,
    );
    assert!(matches!(
        verify_checkpoint_certificate(&cert, &trust(&ca.pem), now(), CREDENTIALS),
        Err(VerifyError::WrongIdentity { .. })
    ));
    let cert = escrow_certificate_for(&other, checkpoint_spec(CREDENTIALS), &key);
    assert_eq!(
        verify_checkpoint_certificate(&cert, &trust(&ca.pem), now(), CREDENTIALS),
        Err(VerifyError::UntrustedRoot)
    );
}

#[test]
fn a_certificate_for_checkpoints_and_anything_else_is_not_a_checkpoint_certificate() {
    let ca = root("Polar Internal CA");
    let key = p256_public_key_pem();
    for (what, spec, why) in [
        (
            "document signing beside it",
            EscrowSpec {
                extended_key_usages: vec![document_signing()],
                ..checkpoint_spec(CREDENTIALS)
            },
            "it is for more than log checkpoints",
        ),
        (
            "document signing alone, the authority key's",
            authority_spec(CREDENTIALS),
            "it is not for log checkpoints",
        ),
        (
            "a client certificate",
            EscrowSpec {
                extended_key_usages: vec![ExtendedKeyUsagePurpose::ClientAuth],
                log_checkpoint: false,
                ..checkpoint_spec(CREDENTIALS)
            },
            "it may be used for TLS",
        ),
        (
            "an escrow certificate's usage",
            EscrowSpec {
                extended_key_usages: vec![ExtendedKeyUsagePurpose::EmailProtection],
                log_checkpoint: false,
                ..checkpoint_spec(CREDENTIALS)
            },
            "it is not for log checkpoints",
        ),
        (
            "no extended key usage, so any",
            EscrowSpec {
                extended_key_usages: vec![],
                log_checkpoint: false,
                ..checkpoint_spec(CREDENTIALS)
            },
            "it has no extended key usage, so it is taken for any use",
        ),
    ] {
        let cert = escrow_certificate_for(&ca, spec, &key);
        assert_eq!(
            verify_checkpoint_certificate(&cert, &trust(&ca.pem), now(), CREDENTIALS),
            Err(VerifyError::NotACheckpointCertificate(why)),
            "{what}"
        );
    }
}

#[test]
fn a_checkpoint_certificate_is_neither_an_authority_nor_an_escrow_certificate() {
    let ca = root("Polar Internal CA");
    let cert = escrow_certificate(&ca, checkpoint_spec(CREDENTIALS));
    assert_eq!(
        verify_authority_certificate(&cert, &trust(&ca.pem), now(), CREDENTIALS),
        Err(VerifyError::NotASigningCertificate(
            "it is not for signing documents"
        ))
    );
    assert!(
        verify_escrow_certificate(&cert, &trust(&ca.pem), now(), CREDENTIALS).is_err(),
        "nothing is sealed to a checkpoint key"
    );
    // The authority's own certificate is still believed, over the same key.
    let cert = escrow_certificate(&ca, authority_spec(CREDENTIALS));
    let key = verify_authority_certificate(&cert, &trust(&ca.pem), now(), CREDENTIALS).unwrap();
    assert!(same_key(&key, ESCROW_PUBLIC_KEY_PEM));
}

#[test]
fn a_checkpoint_certificate_without_digital_signature_or_out_of_date_or_a_ca_is_refused() {
    let ca = root("Polar Internal CA");
    let key = p256_public_key_pem();
    for (what, spec) in [
        (
            "key agreement",
            EscrowSpec {
                key_usages: vec![KeyUsagePurpose::KeyAgreement],
                ..checkpoint_spec(CREDENTIALS)
            },
        ),
        (
            "out of date",
            EscrowSpec {
                not_before_year: 2020,
                not_after_year: 2025,
                ..checkpoint_spec(CREDENTIALS)
            },
        ),
        (
            "a CA",
            EscrowSpec {
                is_ca: true,
                ..checkpoint_spec(CREDENTIALS)
            },
        ),
    ] {
        let cert = escrow_certificate_for(&ca, spec, &key);
        assert!(
            verify_checkpoint_certificate(&cert, &trust(&ca.pem), now(), CREDENTIALS).is_err(),
            "{what}"
        );
    }
}

/// The certificates cert-issuer makes, by type, as `ca.rs` writes their usages.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Made {
    Client,
    Server,
    Service,
    Signing,
    Checkpoint,
}

fn made(cert_type: Made) -> EscrowSpec {
    let tls = |usages| EscrowSpec {
        extended_key_usages: usages,
        log_checkpoint: false,
        ..checkpoint_spec(CREDENTIALS)
    };
    match cert_type {
        Made::Client => tls(vec![ExtendedKeyUsagePurpose::ClientAuth]),
        Made::Server => tls(vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ]),
        Made::Service => EscrowSpec {
            key_usages: vec![KeyUsagePurpose::KeyAgreement],
            extended_key_usages: vec![ExtendedKeyUsagePurpose::EmailProtection],
            log_checkpoint: false,
            ..checkpoint_spec(CREDENTIALS)
        },
        Made::Signing => authority_spec(CREDENTIALS),
        Made::Checkpoint => checkpoint_spec(CREDENTIALS),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// Of the certificates cert-issuer makes, the checkpoint check believes exactly a checkpoint certificate, and the
    /// authority check exactly a signing certificate: one key, one purpose.
    #[test]
    fn each_check_believes_exactly_its_own_type(
        cert_type in prop_oneof![
            Just(Made::Client),
            Just(Made::Server),
            Just(Made::Service),
            Just(Made::Signing),
            Just(Made::Checkpoint),
        ],
    ) {
        // Each check over the key it is made for: a checkpoint key is P-256, and the authority key is RSA here.
        let ca = root("Polar Internal CA");
        let trust = trust(&ca.pem);
        let over_p256 = escrow_certificate_for(&ca, made(cert_type), &p256_public_key_pem());
        prop_assert_eq!(
            verify_checkpoint_certificate(&over_p256, &trust, now(), CREDENTIALS).is_ok(),
            cert_type == Made::Checkpoint
        );
        let over_rsa = escrow_certificate_for(&ca, made(cert_type), ESCROW_PUBLIC_KEY_PEM);
        prop_assert_eq!(
            verify_authority_certificate(&over_rsa, &trust, now(), CREDENTIALS).is_ok(),
            cert_type == Made::Signing
        );
    }

    /// A certificate makes its key the holder's checkpoint key exactly when it chains to the trusted CA, is valid now,
    /// names the holder, is for log checkpoints alone, permits digital signatures and is not a CA.
    #[test]
    fn a_key_is_the_holder_s_checkpoint_key_exactly_when_every_condition_holds(
        trusted in any::<bool>(),
        current in any::<bool>(),
        named in any::<bool>(),
        checkpoint in any::<bool>(),
        alone in any::<bool>(),
        digital in any::<bool>(),
        leaf in any::<bool>(),
    ) {
        let ca = root("Polar Internal CA");
        let other = root("Polar Internal CA");
        let spec = EscrowSpec {
            identity: if named { CREDENTIALS } else { "polar-git-server.polar.serviceaccount.cluster.local" },
            key_usages: if digital { vec![KeyUsagePurpose::DigitalSignature] } else { vec![KeyUsagePurpose::KeyAgreement] },
            extended_key_usages: if alone { vec![] } else { vec![document_signing()] },
            log_checkpoint: checkpoint,
            not_before_year: if current { 2024 } else { 2020 },
            not_after_year: if current { 2100 } else { 2025 },
            is_ca: !leaf,
        };
        let cert = escrow_certificate_for(if trusted { &ca } else { &other }, spec, &p256_public_key_pem());
        let believed = verify_checkpoint_certificate(&cert, &trust(&ca.pem), now(), CREDENTIALS).is_ok();
        prop_assert_eq!(believed, trusted && current && named && checkpoint && alone && digital && leaf);
    }
}
