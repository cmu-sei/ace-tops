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

//! The credentials ledger's entries (docs/architecture/record-store.md, "The credentials ledger on the log"): every
//! kind read back as written, each in its one encoding, and every version ever written still readable. A sample of
//! each kind's current version is recorded in `tests/ledger-samples` (`<kind>.v<n>.cbor`) and never changed: a run
//! with POLAR_RECORD_LEDGER_SAMPLES=1 writes those that are missing, and only those.

use cert_issuer_common::capability::Capability;
use cert_issuer_common::permission::{Permission, PermissionScope};
use cert_issuer_common::record::IssuePath;
use credentials_agent_common::admin_action::SignedAdminAction;
use credentials_agent_common::escrow_secret::EscrowedSecret;
use credentials_agent_common::events::{
    AuthorityEffect, CredentialsEvent, GrantReason, ReportedCertificate, ReportedTicket,
    RevocationReason,
};
use credentials_agent_common::issuance::WorkloadCertType;
use credentials_agent_common::ledger::{Read, entry_of, mark_of, read};
use proptest::prelude::*;
use std::collections::BTreeMap;
use std::path::PathBuf;

const WRITER: &str = "3.1.0 x86_64-unknown-linux-musl";

/// Which variant `event` is: every variant has its arm, so a new one is not built without being counted here, and
/// [`every_kind_has_an_example`] then wants its example.
fn variant(event: &CredentialsEvent) -> usize {
    use CredentialsEvent::*;
    match event {
        Grant { .. } => 0,
        Revoke { .. } => 1,
        IssuanceCompleted { .. } => 2,
        SecretStored { .. } => 3,
        AgentEscrowIssuanceCompleted { .. } => 4,
        AccountProvisioned { .. } => 5,
        AccountCertificateIssued { .. } => 6,
        InstanceRefused { .. } => 7,
        IssuedUnattested { .. } => 8,
        AuthorityPublished { .. } => 9,
        AuthorityRefused { .. } => 10,
        RevocationRecorded { .. } => 11,
        AdminActionRecorded { .. } => 12,
        CertificatesReported { .. } => 13,
        AttestationReported { .. } => 14,
    }
}
const VARIANTS: usize = 15;

/// A secret as the JSON ledger held one: its fields are the escrow crate's own, and encrypting would make it new each time.
fn secret() -> EscrowedSecret {
    serde_json::from_value(serde_json::json!({
        "suite": "HpkeP256",
        "ciphertext": [1, 2, 3, 4],
        "nonce": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        "encrypted_key": [9, 8, 7],
        "encrypted_to_pem": "-----BEGIN PUBLIC KEY-----\nMFk=\n-----END PUBLIC KEY-----\n",
    }))
    .unwrap()
}

/// One event of every kind, its optional parts given, with text keys of different lengths (whose deterministic order
/// is not `BTreeMap`'s).
fn examples() -> Vec<CredentialsEvent> {
    use CredentialsEvent as E;
    let permission = Permission {
        scope: PermissionScope::ServiceToService,
        target: Some("cassini.polar.svc".into()),
    };
    vec![
        E::Grant {
            target_identity: "git-repo-observer".into(),
            permissions: vec![permission.clone()],
            granted_by: "djshepard".into(),
            timestamp: 1_762_900_000,
            reason: GrantReason::ServiceOnboarding,
        },
        E::Revoke {
            serial: "0a1b".into(),
            reason: RevocationReason::Compromised,
            revoked_by: "djshepard".into(),
            timestamp: 1_762_900_001,
        },
        E::IssuanceCompleted {
            identity: "cassini".into(),
            instance_binding: "pod-uid".into(),
            serial: "0c0d".into(),
            timestamp: 1_762_900_002,
            cert_type: WorkloadCertType::Signing,
            grant_key: Some("cassini".into()),
            certificate_pem: "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n"
                .into(),
        },
        E::SecretStored {
            name: "gitlab-token".into(),
            secret: secret(),
            stored_by: "djshepard".into(),
            timestamp: 1_762_900_003,
            labels: BTreeMap::from([
                ("aa".to_string(), "two".to_string()),
                ("b".to_string(), "one".to_string()),
            ]),
        },
        E::AgentEscrowIssuanceCompleted {
            identity: "git-repo-observer".into(),
            instance_binding: "pod-uid".into(),
            serial: "0e0f".into(),
            timestamp: 1_762_900_004,
            certificate_pem: "pem".into(),
        },
        E::AccountProvisioned {
            account_id: "8f1c".into(),
            username: "djshepard".into(),
            email: "someone@example.org".into(),
            permissions: vec![permission],
            capabilities: vec![Capability::Grant, Capability::RecordEvidence],
            provisioned_by: "bootstrap-admin".into(),
            timestamp: 1_762_900_005,
            reason: GrantReason::UserOnboarding,
            via_bootstrap: true,
            given_name: Some("Given".into()),
            surname: Some("Surname".into()),
            title: None,
            telephone_number: Some("+1 555 0100".into()),
        },
        E::AccountCertificateIssued {
            account_id: "8f1c".into(),
            username: "djshepard".into(),
            serial: "1011".into(),
            timestamp: 1_762_900_006,
            certificate_pem: "pem".into(),
        },
        E::InstanceRefused {
            identity: "kube-observer".into(),
            instance_binding: "pod-uid".into(),
            why: "no such pod".into(),
            timestamp: 1_762_900_007,
        },
        E::IssuedUnattested {
            identity: "kube-observer".into(),
            instance_binding: "pod-uid".into(),
            serial: Some("1213".into()),
            why: "the attestor did not answer".into(),
            timestamp: 1_762_900_008,
        },
        E::AuthorityPublished {
            sequence: 42,
            kind: "policy".into(),
            version: 3,
            timestamp: 1_762_900_009,
            effect: Some(AuthorityEffect {
                gained: vec!["a".into()],
                lost: vec![],
                began_closing: vec!["b".into()],
                stopped_closing: vec![],
                unknown_keys: vec!["c".into()],
            }),
        },
        E::AuthorityRefused {
            section: "groups".into(),
            version: 2,
            signer: "someone".into(),
            reasons: vec!["not an administrator".into()],
            timestamp: 1_762_900_010,
        },
        E::RevocationRecorded {
            serial: "0a1b".into(),
            path: "revocations/0a1b.json".into(),
            timestamp: 1_762_900_011,
        },
        E::AdminActionRecorded {
            payload_hash: "ab".repeat(32),
            signed: SignedAdminAction {
                payload: vec![1, 2, 3],
                author_serial: "1011".into(),
                signature: vec![4, 5, 6],
            },
            author_account_id: "8f1c".into(),
            timestamp: 1_762_900_012,
            account_id: Some("9a2d".into()),
        },
        E::CertificatesReported {
            log: "cert-issuer".into(),
            through: 77,
            certificates: vec![
                ReportedCertificate {
                    seq: 77,
                    identity: "cassini".into(),
                    instance_binding: Some("pod-uid".into()),
                    cert_type: cert_issuer_common::CertType::Server,
                    path: IssuePath::Vouched,
                    serial: "1415".into(),
                    signed_at: 1_762_900_013,
                    not_after: 1_762_990_013,
                    certificate_pem: "pem".into(),
                    unexpected: false,
                },
                ReportedCertificate {
                    seq: 78,
                    identity: "credentials-agent".into(),
                    instance_binding: None,
                    // Version 2's: a type version 1 did not have.
                    cert_type: cert_issuer_common::CertType::Checkpoint,
                    path: IssuePath::Internal,
                    serial: "1416".into(),
                    signed_at: 1_762_900_013,
                    not_after: 1_762_943_213,
                    certificate_pem: "pem".into(),
                    unexpected: false,
                },
            ],
            tickets: vec![ReportedTicket {
                seq: 76,
                identity: "cassini".into(),
                instance_binding: "pod-uid".into(),
                taken_at: 1_762_900_012,
                expires_at: 1_762_900_312,
                issued_at: 1_762_900_013,
            }],
            timestamp: 1_762_900_014,
        },
        E::AttestationReported {
            namespace: "polar".into(),
            pod: "cassini-0".into(),
            pod_uid: "pod-uid".into(),
            kind: "unexpected-process".into(),
            finding: "a shell".into(),
            timestamp: 1_762_900_015,
            under_test: true,
        },
    ]
}

fn samples() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/ledger-samples")
}

#[test]
fn every_kind_has_an_example() {
    let mut seen: Vec<usize> = examples().iter().map(variant).collect();
    seen.sort();
    assert_eq!(seen, (0..VARIANTS).collect::<Vec<_>>());
}

#[test]
fn every_event_is_read_back_as_it_was_written() {
    for event in examples() {
        let entry = entry_of(&event, WRITER);
        assert_eq!(entry.writer, WRITER);
        assert_eq!(read(&entry), Read::Decoded(event));
    }
}

#[test]
fn the_marks_are_the_maintainers() {
    let critical: Vec<&str> = examples()
        .iter()
        .map(mark_of)
        .filter(|m| m.critical)
        .map(|m| m.kind)
        .collect();
    assert_eq!(
        critical,
        [
            "credentials.grant",
            "credentials.revoke",
            "credentials.issuance-completed",
            "credentials.secret-stored",
            "credentials.agent-escrow-issuance-completed",
            "credentials.account-provisioned",
            "credentials.account-certificate-issued",
            "credentials.authority-published",
            "credentials.admin-action-recorded",
            "credentials.certificates-reported",
        ]
    );
    for event in examples() {
        assert!(polar_log::entry::is_kind(mark_of(&event).kind));
    }
}

/// The current writer writes, for each kind's example, exactly the sample of the version it declares; every sample of
/// every version is read by the current code. A change of shape without a new version fails here.
#[test]
fn every_sample_of_every_version_is_read_and_the_writer_writes_its_own() {
    let dir = samples();
    let record = std::env::var("POLAR_RECORD_LEDGER_SAMPLES").as_deref() == Ok("1");
    for event in examples() {
        let m = mark_of(&event);
        let path = dir.join(format!("{}.v{}.cbor", m.kind, m.version));
        let written = entry_of(&event, WRITER).event;
        if record && !path.exists() {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(&path, &written).unwrap();
        }
        let sample = std::fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "no sample of {} v{} at {} ({e}): record it with POLAR_RECORD_LEDGER_SAMPLES=1",
                m.kind,
                m.version,
                path.display()
            )
        });
        assert_eq!(
            written, sample,
            "{} v{} is not written as its sample",
            m.kind, m.version
        );
    }
    let mut read_samples = 0;
    for file in std::fs::read_dir(&dir).unwrap() {
        let path = file.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_string();
        let (kind, version) = name
            .strip_suffix(".cbor")
            .and_then(|n| n.rsplit_once(".v"))
            .unwrap_or_else(|| panic!("{name} is not <kind>.v<n>.cbor"));
        let version: u64 = version.parse().unwrap();
        let critical = examples()
            .iter()
            .map(mark_of)
            .find(|m| m.kind == kind)
            .map(|m| m.critical);
        let entry = polar_log::entry::Entry {
            kind: kind.to_string(),
            version,
            critical: critical.unwrap_or_else(|| panic!("{kind} has no example")),
            writer: WRITER.to_string(),
            event: std::fs::read(&path).unwrap(),
        };
        assert!(
            matches!(read(&entry), Read::Decoded(_)),
            "the sample of {kind} v{version} is not read: {:?}",
            read(&entry)
        );
        read_samples += 1;
    }
    assert!(read_samples >= VARIANTS);
}

#[test]
fn a_kind_or_version_it_does_not_know_is_unknown() {
    let mut entry = entry_of(&examples()[0], WRITER);
    entry.version = 2;
    assert_eq!(read(&entry), Read::Unknown);
    entry.version = 1;
    entry.kind = "credentials.something-new".into();
    assert_eq!(read(&entry), Read::Unknown);
}

#[test]
fn a_certificates_report_holding_a_type_its_version_did_not_have_is_malformed() {
    // Version 2 is version 1's shape with the checkpoint certificate's type, so its bytes under version 1 hold a
    // value version 1 never had: not read as some other value.
    let report = examples()
        .into_iter()
        .find(|e| matches!(e, CredentialsEvent::CertificatesReported { .. }))
        .unwrap();
    let mut entry = entry_of(&report, WRITER);
    assert_eq!(entry.version, 2);
    entry.version = 1;
    assert!(
        matches!(read(&entry), Read::Malformed(ref why) if why.contains("version 1")),
        "{:?}",
        read(&entry)
    );
    // Without one, version 1 and version 2 hold the same bytes, and either is read.
    let CredentialsEvent::CertificatesReported {
        log,
        through,
        mut certificates,
        tickets,
        timestamp,
    } = report
    else {
        unreachable!()
    };
    certificates.retain(|c| c.cert_type != cert_issuer_common::CertType::Checkpoint);
    let older = CredentialsEvent::CertificatesReported {
        log,
        through,
        certificates,
        tickets,
        timestamp,
    };
    let mut entry = entry_of(&older, WRITER);
    assert_eq!(read(&entry), Read::Decoded(older.clone()));
    entry.version = 1;
    assert_eq!(read(&entry), Read::Decoded(older));
}

#[test]
fn an_event_not_in_its_one_encoding_is_malformed() {
    let stored = examples().into_iter().find(|e| variant(e) == 3).unwrap();
    let mut entry = entry_of(&stored, WRITER);
    let written = entry.event.clone();
    // Its labels' keys in BTreeMap's order, "aa" before "b": the same value, not its one encoding.
    let reordered = {
        let aa = minicbor::to_vec("aa").unwrap();
        let b = minicbor::to_vec("b").unwrap();
        let (aa_at, b_at) = (find(&written, &aa), find(&written, &b));
        assert!(
            b_at < aa_at,
            "the deterministic order puts the shorter key first"
        );
        let mut swapped = written[..b_at].to_vec();
        swapped.extend_from_slice(&written[aa_at..aa_at + aa.len() + 4]);
        swapped.extend_from_slice(&written[b_at..b_at + b.len() + 4]);
        swapped.extend_from_slice(&written[aa_at + aa.len() + 4..]);
        swapped
    };
    entry.event = reordered;
    assert!(
        matches!(read(&entry), Read::Malformed(_)),
        "{:?}",
        read(&entry)
    );
    // A byte after the event.
    entry.event = [written.clone(), vec![0]].concat();
    assert!(matches!(read(&entry), Read::Malformed(_)));
    // Bytes that are not the kind at all.
    entry.event = vec![0xff];
    assert!(matches!(read(&entry), Read::Malformed(_)));
}

#[test]
fn an_entry_whose_mark_is_not_its_kinds_is_malformed() {
    for event in examples() {
        let mut entry = entry_of(&event, WRITER);
        entry.critical = !entry.critical;
        assert!(matches!(read(&entry), Read::Malformed(_)));
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap()
}

fn text() -> impl Strategy<Value = String> {
    "[a-z0-9 .:/-]{0,30}"
}

fn event() -> impl Strategy<Value = CredentialsEvent> {
    prop_oneof![
        (
            text(),
            proptest::collection::vec((text(), proptest::option::of(text())), 0..4),
            any::<i64>()
        )
            .prop_map(|(target_identity, permissions, timestamp)| {
                CredentialsEvent::Grant {
                    target_identity,
                    permissions: permissions
                        .into_iter()
                        .map(|(_, target)| Permission {
                            scope: PermissionScope::UserToService,
                            target,
                        })
                        .collect(),
                    granted_by: "djshepard".into(),
                    timestamp,
                    reason: GrantReason::RoleChange,
                }
            }),
        (
            text(),
            proptest::collection::btree_map(text(), text(), 0..6),
            any::<i64>()
        )
            .prop_map(|(name, labels, timestamp)| CredentialsEvent::SecretStored {
                name,
                secret: secret(),
                stored_by: "djshepard".into(),
                timestamp,
                labels,
            }),
        (
            any::<u64>(),
            text(),
            any::<u64>(),
            any::<i64>(),
            proptest::option::of(proptest::collection::vec(text(), 0..3))
        )
            .prop_map(|(sequence, kind, version, timestamp, gained)| {
                CredentialsEvent::AuthorityPublished {
                    sequence,
                    kind,
                    version,
                    timestamp,
                    effect: gained.map(|gained| AuthorityEffect {
                        gained,
                        lost: vec![],
                        began_closing: vec![],
                        stopped_closing: vec![],
                        unknown_keys: vec![],
                    }),
                }
            }),
        (text(), proptest::option::of(text()), text(), any::<i64>()).prop_map(
            |(identity, serial, why, timestamp)| CredentialsEvent::IssuedUnattested {
                identity,
                instance_binding: "pod-uid".into(),
                serial,
                why,
                timestamp,
            }
        ),
    ]
}

proptest! {
    // Whatever is written is read back as it was.
    #[test]
    fn any_event_is_read_back(event in event()) {
        prop_assert_eq!(read(&entry_of(&event, WRITER)), Read::Decoded(event));
    }

    // Whatever bytes are read as an event are that event's one encoding: a byte changed anywhere in a written event
    // is malformed, or is another event's own encoding, never a second encoding of some value.
    #[test]
    fn what_is_read_is_its_one_encoding(event in event(), at in any::<usize>(), bit in 0u8..8) {
        let mut entry = entry_of(&event, WRITER);
        let i = at % entry.event.len();
        entry.event[i] ^= 1 << bit;
        if let Read::Decoded(other) = read(&entry) {
            prop_assert_eq!(entry_of(&other, WRITER).event, entry.event);
        }
    }
}
