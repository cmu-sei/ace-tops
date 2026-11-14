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

//! The credentials ledger's entries (docs/architecture/record-store.md, "The credentials ledger on the log"). Each
//! [`CredentialsEvent`] variant is a kind of entry, written at a version whose shape is frozen once written: a struct of
//! its own here, index-keyed CBOR, which the domain enum converts to and from, so the enum may change while what is on
//! disk stays as it was written. Each kind is marked critical or not (the maintainer, 2026-11-11, as
//! `ledger-evolution.md` proposed): a reader that does not know a critical kind or version must not serve, and passes
//! over the rest. An event is read only in its one encoding: one that does not encode again to the same bytes is
//! malformed, never read as some other value.

use crate::admin_action::SignedAdminAction;
use crate::escrow_secret::EscrowedSecret;
use crate::events::{
    AuthorityEffect, CredentialsEvent, GrantReason, ReportedCertificate, ReportedTicket,
    RevocationReason,
};
use crate::issuance::WorkloadCertType;
use cert_issuer_common::capability::Capability;
use cert_issuer_common::permission::Permission;
use polar_log::entry::Entry;
use std::collections::BTreeMap;

/// What an event is in the ledger: its kind, the version this code writes, and whether a reader that does not know that
/// kind and version must stop rather than pass over it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mark {
    pub kind: &'static str,
    pub version: u64,
    pub critical: bool,
}

const fn mark(kind: &'static str, version: u64, critical: bool) -> Mark {
    Mark {
        kind,
        version,
        critical,
    }
}

/// The mark of `event`. Every variant has its arm, so a new one is not built without its kind and criticality.
pub fn mark_of(event: &CredentialsEvent) -> Mark {
    use CredentialsEvent::*;
    match event {
        // Who may do what, what is issued, revoked and escrowed.
        Grant { .. } => mark("credentials.grant", 1, true),
        Revoke { .. } => mark("credentials.revoke", 1, true),
        IssuanceCompleted { .. } => mark("credentials.issuance-completed", 1, true),
        SecretStored { .. } => mark("credentials.secret-stored", 1, true),
        AgentEscrowIssuanceCompleted { .. } => {
            mark("credentials.agent-escrow-issuance-completed", 1, true)
        }
        AccountProvisioned { .. } => mark("credentials.account-provisioned", 1, true),
        AccountCertificateIssued { .. } => mark("credentials.account-certificate-issued", 1, true),
        AdminActionRecorded { .. } => mark("credentials.admin-action-recorded", 1, true),
        // Its sequence must go on rising across restarts.
        AuthorityPublished { .. } => mark("credentials.authority-published", 1, true),
        // It moves the cursor into cert-issuer's record and the supersessions it implies. Version 2: a certificate's
        // type may be `Checkpoint`.
        CertificatesReported { .. } => mark("credentials.certificates-reported", 2, true),
        // They fold nothing: a record of what was refused or let through.
        AuthorityRefused { .. } => mark("credentials.authority-refused", 1, false),
        InstanceRefused { .. } => mark("credentials.instance-refused", 1, false),
        IssuedUnattested { .. } => mark("credentials.issued-unattested", 1, false),
        // They fold only "already done": one passed over may be reported or recorded again, a duplicate.
        AttestationReported { .. } => mark("credentials.attestation-reported", 1, false),
        RevocationRecorded { .. } => mark("credentials.revocation-recorded", 1, false),
    }
}

/// The entry `event` is written as, by `writer` (the platform version, as the store names its own).
pub fn entry_of(event: &CredentialsEvent, writer: &str) -> Entry {
    let m = mark_of(event);
    Entry {
        kind: m.kind.to_string(),
        version: m.version,
        critical: m.critical,
        writer: writer.to_string(),
        event: encode_at(m.version, event)
            .expect("each kind is written at a version this code has"),
    }
}

/// `event`'s bytes at `version` of its kind; none when its kind has no such version.
fn encode_at(version: u64, event: &CredentialsEvent) -> Option<Vec<u8>> {
    match version {
        1 => Some(v1::encode(event)),
        2 => v2::encode(event),
        _ => None,
    }
}

/// What reading an entry gave.
// Each is made once per entry and its event moved on at once, so boxing the event is not worth it.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum Read {
    Decoded(CredentialsEvent),
    /// A kind or version this code does not know: the entry's own mark says whether it may be passed over.
    Unknown,
    /// A kind and version this code knows whose bytes are not its one encoding of an event.
    Malformed(String),
}

/// Reads `entry`'s event.
pub fn read(entry: &Entry) -> Read {
    let decoded = match entry.version {
        1 => v1::decode(&entry.kind, &entry.event),
        2 => v2::decode(&entry.kind, &entry.event),
        _ => None,
    };
    match decoded {
        None => Read::Unknown,
        Some(Err(why)) => Read::Malformed(why),
        Some(Ok(event)) if encode_at(entry.version, &event).as_ref() != Some(&entry.event) => {
            Read::Malformed(format!(
                "{} v{} is not in its one encoding",
                entry.kind, entry.version
            ))
        }
        // The mark goes with the kind: an entry that says otherwise was not written by this code's rule.
        Some(Ok(event)) if mark_of(&event).critical != entry.critical => Read::Malformed(format!(
            "{} v{} is marked {}critical, which it is not",
            entry.kind,
            entry.version,
            if entry.critical { "" } else { "not " }
        )),
        Some(Ok(event)) => Read::Decoded(event),
    }
}

/// A map keyed by text, written with its keys in RFC 8949's deterministic order (4.2.1: by their encoded bytes, so a
/// shorter key goes first), which is not `BTreeMap`'s.
mod text_map {
    use minicbor::decode::Decoder;
    use minicbor::encode::{Encoder, Error, Write};
    use std::collections::BTreeMap;

    fn encoded(key: &str) -> Vec<u8> {
        minicbor::to_vec(key).expect("a text string encodes")
    }

    pub fn encode<C, W: Write>(
        map: &BTreeMap<String, String>,
        e: &mut Encoder<W>,
        _: &mut C,
    ) -> Result<(), Error<W::Error>> {
        let mut pairs: Vec<(&String, &String)> = map.iter().collect();
        pairs.sort_by_cached_key(|(k, _)| encoded(k));
        e.map(pairs.len() as u64)?;
        for (k, v) in pairs {
            e.str(k)?.str(v)?;
        }
        Ok(())
    }

    pub fn decode<C>(
        d: &mut Decoder<'_>,
        _: &mut C,
    ) -> Result<BTreeMap<String, String>, minicbor::decode::Error> {
        let len = d
            .map()?
            .ok_or_else(|| minicbor::decode::Error::message("a map of indefinite length"))?;
        let mut map = BTreeMap::new();
        for _ in 0..len {
            let k = d.str()?.to_string();
            let v = d.str()?.to_string();
            if map.insert(k, v).is_some() {
                return Err(minicbor::decode::Error::message("a key given twice"));
            }
        }
        Ok(map)
    }
}

/// Version 1 of every kind: the shapes the JSON ledger held, as the copy writes them (frozen 2026-11-11).
mod v1 {
    use super::*;

    #[derive(minicbor::Encode, minicbor::Decode)]
    #[cbor(map)]
    struct Grant {
        #[n(0)]
        target_identity: String,
        #[n(1)]
        permissions: Vec<Permission>,
        #[n(2)]
        granted_by: String,
        #[n(3)]
        timestamp: i64,
        #[n(4)]
        reason: GrantReason,
    }

    #[derive(minicbor::Encode, minicbor::Decode)]
    #[cbor(map)]
    struct Revoke {
        #[n(0)]
        serial: String,
        #[n(1)]
        reason: RevocationReason,
        #[n(2)]
        revoked_by: String,
        #[n(3)]
        timestamp: i64,
    }

    #[derive(minicbor::Encode, minicbor::Decode)]
    #[cbor(map)]
    struct IssuanceCompleted {
        #[n(0)]
        identity: String,
        #[n(1)]
        instance_binding: String,
        #[n(2)]
        serial: String,
        #[n(3)]
        timestamp: i64,
        #[n(4)]
        cert_type: WorkloadCertType,
        #[n(5)]
        grant_key: Option<String>,
        #[n(6)]
        certificate_pem: String,
    }

    #[derive(minicbor::Encode, minicbor::Decode)]
    #[cbor(map)]
    struct SecretStored {
        #[n(0)]
        name: String,
        #[n(1)]
        secret: EscrowedSecret,
        #[n(2)]
        stored_by: String,
        #[n(3)]
        timestamp: i64,
        #[cbor(n(4), with = "text_map")]
        labels: BTreeMap<String, String>,
    }

    #[derive(minicbor::Encode, minicbor::Decode)]
    #[cbor(map)]
    struct AgentEscrowIssuanceCompleted {
        #[n(0)]
        identity: String,
        #[n(1)]
        instance_binding: String,
        #[n(2)]
        serial: String,
        #[n(3)]
        timestamp: i64,
        #[n(4)]
        certificate_pem: String,
    }

    #[derive(minicbor::Encode, minicbor::Decode)]
    #[cbor(map)]
    struct AccountProvisioned {
        #[n(0)]
        account_id: String,
        #[n(1)]
        username: String,
        #[n(2)]
        email: String,
        #[n(3)]
        permissions: Vec<Permission>,
        #[n(4)]
        capabilities: Vec<Capability>,
        #[n(5)]
        provisioned_by: String,
        #[n(6)]
        timestamp: i64,
        #[n(7)]
        reason: GrantReason,
        #[n(8)]
        via_bootstrap: bool,
        #[n(9)]
        given_name: Option<String>,
        #[n(10)]
        surname: Option<String>,
        #[n(11)]
        title: Option<String>,
        #[n(12)]
        telephone_number: Option<String>,
    }

    #[derive(minicbor::Encode, minicbor::Decode)]
    #[cbor(map)]
    struct AccountCertificateIssued {
        #[n(0)]
        account_id: String,
        #[n(1)]
        username: String,
        #[n(2)]
        serial: String,
        #[n(3)]
        timestamp: i64,
        #[n(4)]
        certificate_pem: String,
    }

    #[derive(minicbor::Encode, minicbor::Decode)]
    #[cbor(map)]
    struct InstanceRefused {
        #[n(0)]
        identity: String,
        #[n(1)]
        instance_binding: String,
        #[n(2)]
        why: String,
        #[n(3)]
        timestamp: i64,
    }

    #[derive(minicbor::Encode, minicbor::Decode)]
    #[cbor(map)]
    struct IssuedUnattested {
        #[n(0)]
        identity: String,
        #[n(1)]
        instance_binding: String,
        #[n(2)]
        serial: Option<String>,
        #[n(3)]
        why: String,
        #[n(4)]
        timestamp: i64,
    }

    #[derive(minicbor::Encode, minicbor::Decode)]
    #[cbor(map)]
    struct AuthorityPublished {
        #[n(0)]
        sequence: u64,
        #[n(1)]
        kind: String,
        #[n(2)]
        version: u64,
        #[n(3)]
        timestamp: i64,
        #[n(4)]
        effect: Option<AuthorityEffect>,
    }

    #[derive(minicbor::Encode, minicbor::Decode)]
    #[cbor(map)]
    struct AuthorityRefused {
        #[n(0)]
        section: String,
        #[n(1)]
        version: u64,
        #[n(2)]
        signer: String,
        #[n(3)]
        reasons: Vec<String>,
        #[n(4)]
        timestamp: i64,
    }

    #[derive(minicbor::Encode, minicbor::Decode)]
    #[cbor(map)]
    struct RevocationRecorded {
        #[n(0)]
        serial: String,
        #[n(1)]
        path: String,
        #[n(2)]
        timestamp: i64,
    }

    #[derive(minicbor::Encode, minicbor::Decode)]
    #[cbor(map)]
    struct AdminActionRecorded {
        #[n(0)]
        payload_hash: String,
        #[n(1)]
        signed: SignedAdminAction,
        #[n(2)]
        author_account_id: String,
        #[n(3)]
        timestamp: i64,
        #[n(4)]
        account_id: Option<String>,
    }

    #[derive(minicbor::Encode, minicbor::Decode)]
    #[cbor(map)]
    struct CertificatesReported {
        #[n(0)]
        log: String,
        #[n(1)]
        through: u64,
        #[n(2)]
        certificates: Vec<ReportedCertificate>,
        #[n(3)]
        tickets: Vec<ReportedTicket>,
        #[n(4)]
        timestamp: i64,
    }

    #[derive(minicbor::Encode, minicbor::Decode)]
    #[cbor(map)]
    struct AttestationReported {
        #[n(0)]
        namespace: String,
        #[n(1)]
        pod: String,
        #[n(2)]
        pod_uid: String,
        #[n(3)]
        kind: String,
        #[n(4)]
        finding: String,
        #[n(5)]
        timestamp: i64,
        #[n(6)]
        under_test: bool,
    }

    fn cbor<T: minicbor::Encode<()>>(value: &T) -> Vec<u8> {
        minicbor::to_vec(value).expect("encoding to a vector does not fail")
    }

    /// `event`'s bytes at version 1.
    pub(super) fn encode(event: &CredentialsEvent) -> Vec<u8> {
        use CredentialsEvent as E;
        match event.clone() {
            E::Grant {
                target_identity,
                permissions,
                granted_by,
                timestamp,
                reason,
            } => cbor(&Grant {
                target_identity,
                permissions,
                granted_by,
                timestamp,
                reason,
            }),
            E::Revoke {
                serial,
                reason,
                revoked_by,
                timestamp,
            } => cbor(&Revoke {
                serial,
                reason,
                revoked_by,
                timestamp,
            }),
            E::IssuanceCompleted {
                identity,
                instance_binding,
                serial,
                timestamp,
                cert_type,
                grant_key,
                certificate_pem,
            } => cbor(&IssuanceCompleted {
                identity,
                instance_binding,
                serial,
                timestamp,
                cert_type,
                grant_key,
                certificate_pem,
            }),
            E::SecretStored {
                name,
                secret,
                stored_by,
                timestamp,
                labels,
            } => cbor(&SecretStored {
                name,
                secret,
                stored_by,
                timestamp,
                labels,
            }),
            E::AgentEscrowIssuanceCompleted {
                identity,
                instance_binding,
                serial,
                timestamp,
                certificate_pem,
            } => cbor(&AgentEscrowIssuanceCompleted {
                identity,
                instance_binding,
                serial,
                timestamp,
                certificate_pem,
            }),
            E::AccountProvisioned {
                account_id,
                username,
                email,
                permissions,
                capabilities,
                provisioned_by,
                timestamp,
                reason,
                via_bootstrap,
                given_name,
                surname,
                title,
                telephone_number,
            } => cbor(&AccountProvisioned {
                account_id,
                username,
                email,
                permissions,
                capabilities,
                provisioned_by,
                timestamp,
                reason,
                via_bootstrap,
                given_name,
                surname,
                title,
                telephone_number,
            }),
            E::AccountCertificateIssued {
                account_id,
                username,
                serial,
                timestamp,
                certificate_pem,
            } => cbor(&AccountCertificateIssued {
                account_id,
                username,
                serial,
                timestamp,
                certificate_pem,
            }),
            E::InstanceRefused {
                identity,
                instance_binding,
                why,
                timestamp,
            } => cbor(&InstanceRefused {
                identity,
                instance_binding,
                why,
                timestamp,
            }),
            E::IssuedUnattested {
                identity,
                instance_binding,
                serial,
                why,
                timestamp,
            } => cbor(&IssuedUnattested {
                identity,
                instance_binding,
                serial,
                why,
                timestamp,
            }),
            E::AuthorityPublished {
                sequence,
                kind,
                version,
                timestamp,
                effect,
            } => cbor(&AuthorityPublished {
                sequence,
                kind,
                version,
                timestamp,
                effect,
            }),
            E::AuthorityRefused {
                section,
                version,
                signer,
                reasons,
                timestamp,
            } => cbor(&AuthorityRefused {
                section,
                version,
                signer,
                reasons,
                timestamp,
            }),
            E::RevocationRecorded {
                serial,
                path,
                timestamp,
            } => cbor(&RevocationRecorded {
                serial,
                path,
                timestamp,
            }),
            E::AdminActionRecorded {
                payload_hash,
                signed,
                author_account_id,
                timestamp,
                account_id,
            } => cbor(&AdminActionRecorded {
                payload_hash,
                signed,
                author_account_id,
                timestamp,
                account_id,
            }),
            E::CertificatesReported {
                log,
                through,
                certificates,
                tickets,
                timestamp,
            } => cbor(&CertificatesReported {
                log,
                through,
                certificates,
                tickets,
                timestamp,
            }),
            E::AttestationReported {
                namespace,
                pod,
                pod_uid,
                kind,
                finding,
                timestamp,
                under_test,
            } => cbor(&AttestationReported {
                namespace,
                pod,
                pod_uid,
                kind,
                finding,
                timestamp,
                under_test,
            }),
        }
    }

    fn from<'b, T: minicbor::Decode<'b, ()>>(bytes: &'b [u8]) -> Result<T, String> {
        minicbor::decode(bytes).map_err(|e| e.to_string())
    }

    /// The event `bytes` hold as version 1 of `kind`; none when there is no such kind.
    pub(super) fn decode(kind: &str, bytes: &[u8]) -> Option<Result<CredentialsEvent, String>> {
        use CredentialsEvent as E;
        Some(match kind {
            "credentials.grant" => from::<Grant>(bytes).map(|v| E::Grant {
                target_identity: v.target_identity,
                permissions: v.permissions,
                granted_by: v.granted_by,
                timestamp: v.timestamp,
                reason: v.reason,
            }),
            "credentials.revoke" => from::<Revoke>(bytes).map(|v| E::Revoke {
                serial: v.serial,
                reason: v.reason,
                revoked_by: v.revoked_by,
                timestamp: v.timestamp,
            }),
            "credentials.issuance-completed" => {
                from::<IssuanceCompleted>(bytes).map(|v| E::IssuanceCompleted {
                    identity: v.identity,
                    instance_binding: v.instance_binding,
                    serial: v.serial,
                    timestamp: v.timestamp,
                    cert_type: v.cert_type,
                    grant_key: v.grant_key,
                    certificate_pem: v.certificate_pem,
                })
            }
            "credentials.secret-stored" => from::<SecretStored>(bytes).map(|v| E::SecretStored {
                name: v.name,
                secret: v.secret,
                stored_by: v.stored_by,
                timestamp: v.timestamp,
                labels: v.labels,
            }),
            "credentials.agent-escrow-issuance-completed" => {
                from::<AgentEscrowIssuanceCompleted>(bytes).map(|v| {
                    E::AgentEscrowIssuanceCompleted {
                        identity: v.identity,
                        instance_binding: v.instance_binding,
                        serial: v.serial,
                        timestamp: v.timestamp,
                        certificate_pem: v.certificate_pem,
                    }
                })
            }
            "credentials.account-provisioned" => {
                from::<AccountProvisioned>(bytes).map(|v| E::AccountProvisioned {
                    account_id: v.account_id,
                    username: v.username,
                    email: v.email,
                    permissions: v.permissions,
                    capabilities: v.capabilities,
                    provisioned_by: v.provisioned_by,
                    timestamp: v.timestamp,
                    reason: v.reason,
                    via_bootstrap: v.via_bootstrap,
                    given_name: v.given_name,
                    surname: v.surname,
                    title: v.title,
                    telephone_number: v.telephone_number,
                })
            }
            "credentials.account-certificate-issued" => from::<AccountCertificateIssued>(bytes)
                .map(|v| E::AccountCertificateIssued {
                    account_id: v.account_id,
                    username: v.username,
                    serial: v.serial,
                    timestamp: v.timestamp,
                    certificate_pem: v.certificate_pem,
                }),
            "credentials.instance-refused" => {
                from::<InstanceRefused>(bytes).map(|v| E::InstanceRefused {
                    identity: v.identity,
                    instance_binding: v.instance_binding,
                    why: v.why,
                    timestamp: v.timestamp,
                })
            }
            "credentials.issued-unattested" => {
                from::<IssuedUnattested>(bytes).map(|v| E::IssuedUnattested {
                    identity: v.identity,
                    instance_binding: v.instance_binding,
                    serial: v.serial,
                    why: v.why,
                    timestamp: v.timestamp,
                })
            }
            "credentials.authority-published" => {
                from::<AuthorityPublished>(bytes).map(|v| E::AuthorityPublished {
                    sequence: v.sequence,
                    kind: v.kind,
                    version: v.version,
                    timestamp: v.timestamp,
                    effect: v.effect,
                })
            }
            "credentials.authority-refused" => {
                from::<AuthorityRefused>(bytes).map(|v| E::AuthorityRefused {
                    section: v.section,
                    version: v.version,
                    signer: v.signer,
                    reasons: v.reasons,
                    timestamp: v.timestamp,
                })
            }
            "credentials.revocation-recorded" => {
                from::<RevocationRecorded>(bytes).map(|v| E::RevocationRecorded {
                    serial: v.serial,
                    path: v.path,
                    timestamp: v.timestamp,
                })
            }
            "credentials.admin-action-recorded" => {
                from::<AdminActionRecorded>(bytes).map(|v| E::AdminActionRecorded {
                    payload_hash: v.payload_hash,
                    signed: v.signed,
                    author_account_id: v.author_account_id,
                    timestamp: v.timestamp,
                    account_id: v.account_id,
                })
            }
            "credentials.certificates-reported" => {
                from::<CertificatesReported>(bytes).and_then(|v| {
                    // Version 2 brought the checkpoint certificate's type: in version 1 it is no value at all.
                    if v.certificates
                        .iter()
                        .any(|c| c.cert_type == cert_issuer_common::CertType::Checkpoint)
                    {
                        return Err("a certificate type version 1 did not have".to_string());
                    }
                    Ok(E::CertificatesReported {
                        log: v.log,
                        through: v.through,
                        certificates: v.certificates,
                        tickets: v.tickets,
                        timestamp: v.timestamp,
                    })
                })
            }
            "credentials.attestation-reported" => {
                from::<AttestationReported>(bytes).map(|v| E::AttestationReported {
                    namespace: v.namespace,
                    pod: v.pod,
                    pod_uid: v.pod_uid,
                    kind: v.kind,
                    finding: v.finding,
                    timestamp: v.timestamp,
                    under_test: v.under_test,
                })
            }
            _ => return None,
        })
    }
}

/// Version 2 of the kinds that have one (frozen 2026-11-12): `credentials.certificates-reported`, whose certificates'
/// type may be `Checkpoint` (docs/architecture/record-store.md, "L2, checkpoints"). Its shape is version 1's; what
/// changed is the values it holds, so a reader of version 1 alone finds it unknown, and holds as for any critical
/// kind it does not know, instead of finding a value it never had.
mod v2 {
    use super::*;

    #[derive(minicbor::Encode, minicbor::Decode)]
    #[cbor(map)]
    struct CertificatesReported {
        #[n(0)]
        log: String,
        #[n(1)]
        through: u64,
        #[n(2)]
        certificates: Vec<ReportedCertificate>,
        #[n(3)]
        tickets: Vec<ReportedTicket>,
        #[n(4)]
        timestamp: i64,
    }

    /// `event`'s bytes at version 2; none when its kind has no version 2.
    pub(super) fn encode(event: &CredentialsEvent) -> Option<Vec<u8>> {
        match event.clone() {
            CredentialsEvent::CertificatesReported {
                log,
                through,
                certificates,
                tickets,
                timestamp,
            } => Some(
                minicbor::to_vec(CertificatesReported {
                    log,
                    through,
                    certificates,
                    tickets,
                    timestamp,
                })
                .expect("encoding to a vector does not fail"),
            ),
            _ => None,
        }
    }

    /// The event `bytes` hold as version 2 of `kind`; none when there is no such kind at version 2.
    pub(super) fn decode(kind: &str, bytes: &[u8]) -> Option<Result<CredentialsEvent, String>> {
        match kind {
            "credentials.certificates-reported" => Some(
                minicbor::decode::<CertificatesReported>(bytes)
                    .map(|v| CredentialsEvent::CertificatesReported {
                        log: v.log,
                        through: v.through,
                        certificates: v.certificates,
                        tickets: v.tickets,
                        timestamp: v.timestamp,
                    })
                    .map_err(|e| e.to_string()),
            ),
            _ => None,
        }
    }
}
