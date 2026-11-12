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

//! What the credentials agent publishes when its policy or the data about principals changes, and how a
//! leaf believes it (docs/architecture/authority-distribution.md).
//!
//! The credentials agent signs each update with its authority key, ECDSA over P-256 with SHA-256, over the payload
//! bytes prefixed with a fixed domain line, so a signature made for any other purpose cannot be replayed as an
//! update. The authority key is its own, used for nothing but the credentials agent's signed statements, and not the
//! escrow key that what is sealed to the credentials agent is opened with (docs/architecture/key-custody.md, "The
//! credentials agent's keys, P-256", 2026-11-10). The update carries the **bytes** that were signed, not a structure to be re-encoded: what is verified
//! is exactly what the signer wrote, and only then is it read. It also carries the fingerprint of the key that
//! signed it, so a leaf that pins a key notices at once if it is ever a different one.
//!
//! Each payload is the whole of its kind (the whole policy, the whole membership, the whole set of revoked
//! serials), never a delta, so an update that was missed is repaired by the next of its kind.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding};
use rkyv::{Archive, Deserialize, Serialize};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use std::collections::BTreeMap;

/// Where the credentials agent publishes updates, and every agent listens.
pub const AUTHORITY_UPDATES_TOPIC: &str = "polar-authority-updates";

/// Where an agent asks for the current authority, and the credentials agent answers: a leaf that has just
/// registered, or that saw a jump in the sequence. The answer is also published without being asked every half
/// hour, so a leaf that missed everything is repaired by the next one.
pub const AUTHORITY_SNAPSHOT_REQUESTS_TOPIC: &str = "polar-authority-snapshot-requests";
pub const AUTHORITY_SNAPSHOT_REPLIES_TOPIC: &str = "polar-authority-snapshot-replies";

/// The credentials agent's authority key: P-256, signing its authority updates and nothing it did not write.
pub type AuthorityKey = p256::ecdsa::SigningKey;
/// Its public half, which a leaf pins.
pub type AuthorityPublicKey = p256::ecdsa::VerifyingKey;

/// A new authority key, from the operating system's randomness.
pub fn generate_key() -> Result<AuthorityKey, String> {
    loop {
        let bytes = zeroize::Zeroizing::new(rand::random::<[u8; 32]>());
        if let Ok(key) = AuthorityKey::from_slice(bytes.as_ref()) {
            return Ok(key);
        }
    }
}

/// A public key as PEM (SubjectPublicKeyInfo): what a snapshot carries.
pub fn public_key_pem(key: &AuthorityPublicKey) -> Result<String, AuthorityUpdateError> {
    key.to_public_key_pem(LineEnding::LF)
        .map_err(|e| AuthorityUpdateError::Encoding(e.to_string()))
}

/// A public key read from PEM: a P-256 key, or an error.
pub fn public_key_from_pem(pem: &str) -> Result<AuthorityPublicKey, String> {
    AuthorityPublicKey::from_public_key_pem(pem).map_err(|e| format!("not a P-256 public key: {e}"))
}

/// The line every signed update's bytes begin with.
const DOMAIN: &[u8] = b"polar-authority-update-v1\n";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityUpdateError {
    /// Signed by a key other than the one pinned. Nothing else about the update is believed.
    #[error("signed by key {got}, and the pinned key is {expected}")]
    UnknownKey { expected: String, got: String },
    #[error("the signature does not verify")]
    BadSignature,
    /// Signed correctly and not a payload: the signer wrote something this does not read.
    #[error("the signed payload is not an authority update: {0}")]
    Malformed(String),
    #[error("could not make the update: {0}")]
    Encoding(String),
    /// A snapshot's key is not certified as the credentials agent's: its certificate is missing, is not believed under
    /// the pinned CA, or is for another key (docs/architecture/authority-distribution.md, "Pinning the key to the CA").
    #[error("the snapshot's key is not certified as the credentials agent's: {0}")]
    Uncertified(String),
}

/// What a payload replaces, in full.
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorityBody {
    /// The Cedar rules.
    Policy { source: String },
    /// Who is in which group: for each identity, its groups; and how groups and roles are arranged (left out when
    /// there is no arrangement, so an update signed before there could be one reads back as it was signed).
    Groups {
        memberships: BTreeMap<String, Vec<String>>,
        #[serde(
            default,
            skip_serializing_if = "cert_issuer_common::hierarchy::Hierarchy::is_empty"
        )]
        hierarchy: cert_issuer_common::hierarchy::Hierarchy,
    },
    /// The serials of the certificates that are revoked, and among them those revoked for a compromise (the ledger's
    /// `RevocationReason::Compromised`), which is what starts a rotation (docs/architecture/key-rotation.md); every other
    /// is an ordinary end (superseded, decommissioned, offboarded, ...). Left out when there is none, so an update signed
    /// before reasons travelled reads back as it was signed: every serial ordinary.
    Revoked {
        serials: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        compromised: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityKind {
    Policy,
    Groups,
    Revoked,
}

impl AuthorityBody {
    /// What a `policy` or `groups` runtime section's body says, as an update carries it: the policy's Cedar `source`, or
    /// the groups' `memberships` with how groups and roles are arranged. The credentials agent publishes this, and the
    /// authority model judges a deployment's sections by it.
    pub fn of_section(section: &str, body: &serde_json::Value) -> Result<AuthorityBody, String> {
        match section {
            "policy" => body
                .get("source")
                .and_then(serde_json::Value::as_str)
                .map(|source| AuthorityBody::Policy {
                    source: source.to_string(),
                })
                .ok_or_else(|| "the policy section has no text `source`".to_string()),
            "groups" => {
                let memberships: BTreeMap<String, Vec<String>> = body
                    .get("memberships")
                    .cloned()
                    .ok_or_else(|| "the groups section has no `memberships`".to_string())
                    .and_then(|m| serde_json::from_value(m).map_err(|e| e.to_string()))?;
                let hierarchy: cert_issuer_common::hierarchy::Hierarchy =
                    serde_json::from_value(serde_json::json!({
                        "groups": body.get("groups").cloned().unwrap_or(serde_json::json!({})),
                        "roles": body.get("roles").cloned().unwrap_or(serde_json::json!({})),
                    }))
                    .map_err(|e| e.to_string())?;
                Ok(AuthorityBody::Groups {
                    memberships,
                    hierarchy,
                })
            }
            other => Err(format!("`{other}` is not a section that is published")),
        }
    }
}

impl AuthorityBody {
    pub fn kind(&self) -> AuthorityKind {
        match self {
            AuthorityBody::Policy { .. } => AuthorityKind::Policy,
            AuthorityBody::Groups { .. } => AuthorityKind::Groups,
            AuthorityBody::Revoked { .. } => AuthorityKind::Revoked,
        }
    }
}

/// What the credentials agent signs.
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityPayload {
    /// The credentials agent's own ordering of everything it has published: a consumer that sees a jump knows
    /// it missed one.
    pub sequence: u64,
    /// Rises with each update of this payload's kind. The latest replaces the earlier, whole.
    pub version: u64,
    pub body: AuthorityBody,
    /// Who authored it, when a person did (their username), for the record. Not what makes it believed.
    pub authored_by: Option<String>,
}

/// An authority update as it travels.
#[derive(
    Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize, SerdeSerialize, SerdeDeserialize,
)]
pub struct AuthorityUpdate {
    /// The SHA-256 of the signing key's public half (its SubjectPublicKeyInfo), in hex.
    pub key_fingerprint: String,
    /// The signed bytes: a JSON `AuthorityPayload`.
    pub payload: Vec<u8>,
    /// ECDSA P-256 with SHA-256 over the domain line and `payload`, in its fixed 64-byte form (r || s).
    pub signature: Vec<u8>,
}

/// "Send me the current authority." Anyone may ask: what comes back is public, signed, and the same for
/// everyone.
#[derive(
    Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize, SerdeSerialize, SerdeDeserialize,
)]
pub struct AuthoritySnapshotRequest;

/// The current authority: the key that signs it, and the latest signed update of each kind. A leaf that has
/// no key yet pins the one here (accepted only from the credentials agent's own identity, as the broker names
/// it), and every update in it is checked against that key like any other.
#[derive(
    Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize, SerdeSerialize, SerdeDeserialize,
)]
pub struct AuthoritySnapshot {
    /// The signing key's public half, PEM.
    pub public_key_pem: String,
    /// The key's certificate, then whatever leads to the CA: a `CertType::Signing` certificate for the credentials
    /// agent's identity, over this key, from the CA every pod pins. A leaf pins the key only under it.
    #[serde(default)]
    pub certificate_chain_pem: Vec<String>,
    /// The credentials agent's escrow certificate, then whatever leads to the CA: what is sealed to the credentials agent
    /// is sealed to its key, which a leaf pins only under it (docs/architecture/key-custody.md, "The credentials agent's
    /// keys, P-256"). Empty until it is certified.
    #[serde(default)]
    pub escrow_certificate_chain_pem: Vec<String>,
    /// The latest signed update of each kind, oldest sequence first.
    pub updates: Vec<AuthorityUpdate>,
}

impl AuthoritySnapshot {
    /// The key it carries, parsed.
    pub fn public_key(&self) -> Result<AuthorityPublicKey, AuthorityUpdateError> {
        public_key_from_pem(&self.public_key_pem)
            .map_err(|e| AuthorityUpdateError::Encoding(format!("the snapshot's key: {e}")))
    }

    /// The key it carries, if its certificate makes it `publisher`'s at `now` (Unix seconds) under `trust`, the CA the
    /// leaf pins: the certificate believed (`polar_signing::verify_authority_certificate`), and for this very key.
    pub fn certified_key(
        &self,
        trust: &polar_signing::Trust,
        publisher: &str,
        now: i64,
    ) -> Result<AuthorityPublicKey, AuthorityUpdateError> {
        if self.certificate_chain_pem.is_empty() {
            return Err(AuthorityUpdateError::Uncertified(
                "it carries no certificate".to_string(),
            ));
        }
        let certified = polar_signing::verify_authority_certificate(
            &self.certificate_chain_pem.concat(),
            trust,
            now,
            publisher,
        )
        .map_err(|e| AuthorityUpdateError::Uncertified(e.to_string()))?;
        let certified = public_key_from_pem(&certified).map_err(|e| {
            AuthorityUpdateError::Uncertified(format!("the certificate's key: {e}"))
        })?;
        if certified != self.public_key()? {
            return Err(AuthorityUpdateError::Uncertified(
                "the certificate is for another key than the snapshot names".to_string(),
            ));
        }
        Ok(certified)
    }
}

/// The fingerprint of a public key: what an update says signed it, and what a leaf compares with the key it
/// pinned.
pub fn fingerprint(key: &AuthorityPublicKey) -> Result<String, AuthorityUpdateError> {
    use sha2::{Digest, Sha256};
    let der = key
        .to_public_key_der()
        .map_err(|e| AuthorityUpdateError::Encoding(e.to_string()))?;
    Ok(hex(&Sha256::digest(der.as_bytes())))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn signed_bytes(payload: &[u8]) -> Vec<u8> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend_from_slice(payload);
    bytes
}

/// Signs `payload` with the credentials agent's authority key. The nonce is derived from the key and the message
/// (RFC 6979), so signing needs no randomness and repeats none.
pub fn sign(
    payload: &AuthorityPayload,
    key: &AuthorityKey,
) -> Result<AuthorityUpdate, AuthorityUpdateError> {
    let bytes =
        serde_json::to_vec(payload).map_err(|e| AuthorityUpdateError::Encoding(e.to_string()))?;
    let signature: p256::ecdsa::Signature = key.sign(&signed_bytes(&bytes));
    Ok(AuthorityUpdate {
        key_fingerprint: fingerprint(key.verifying_key())?,
        payload: bytes,
        signature: signature.to_bytes().to_vec(),
    })
}

/// Verifies `update` against the key a leaf pinned, and reads the payload only if it holds. In order: the
/// update says it was signed by the pinned key; the signature holds over the domain line and the bytes; then,
/// and only then, the bytes are read, strictly.
pub fn verify(
    update: &AuthorityUpdate,
    pinned: &AuthorityPublicKey,
) -> Result<AuthorityPayload, AuthorityUpdateError> {
    let expected = fingerprint(pinned)?;
    if update.key_fingerprint != expected {
        return Err(AuthorityUpdateError::UnknownKey {
            expected,
            got: update.key_fingerprint.clone(),
        });
    }
    let signature = p256::ecdsa::Signature::from_slice(&update.signature)
        .map_err(|_| AuthorityUpdateError::BadSignature)?;
    pinned
        .verify(&signed_bytes(&update.payload), &signature)
        .map_err(|_| AuthorityUpdateError::BadSignature)?;
    serde_json::from_slice(&update.payload)
        .map_err(|e| AuthorityUpdateError::Malformed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The revoked set says which serials were revoked for a compromise; with none it is written as it was before it
    /// could say, so an update signed then reads back as signed, every serial an ordinary end.
    #[test]
    fn a_revoked_set_names_its_compromised_serials_and_without_any_is_written_as_before() {
        let plain = AuthorityBody::Revoked {
            serials: vec!["0a".into()],
            compromised: Vec::new(),
        };
        let text = serde_json::to_string(&plain).unwrap();
        assert_eq!(text, r#"{"kind":"revoked","serials":["0a"]}"#);
        assert_eq!(serde_json::from_str::<AuthorityBody>(&text).unwrap(), plain);
        let named = AuthorityBody::Revoked {
            serials: vec!["0a".into(), "0b".into()],
            compromised: vec!["0b".into()],
        };
        let text = serde_json::to_string(&named).unwrap();
        assert_eq!(serde_json::from_str::<AuthorityBody>(&text).unwrap(), named);
    }

    #[test]
    fn a_groups_update_with_no_arrangement_is_written_as_it_was_before_there_could_be_one() {
        // Its signature was made over these bytes, so they must not change.
        let body = AuthorityBody::Groups {
            memberships: [("alice".to_string(), vec!["operators".to_string()])].into(),
            hierarchy: Default::default(),
        };
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"kind":"groups","memberships":{"alice":["operators"]}}"#
        );
        let read: AuthorityBody =
            serde_json::from_str(r#"{"kind":"groups","memberships":{"alice":["operators"]}}"#)
                .unwrap();
        assert_eq!(read, body);
    }

    fn key() -> AuthorityKey {
        use std::sync::OnceLock;
        static KEY: OnceLock<AuthorityKey> = OnceLock::new();
        KEY.get_or_init(|| generate_key().unwrap()).clone()
    }

    fn another_key() -> AuthorityKey {
        use std::sync::OnceLock;
        static KEY: OnceLock<AuthorityKey> = OnceLock::new();
        KEY.get_or_init(|| generate_key().unwrap()).clone()
    }

    fn payload() -> AuthorityPayload {
        AuthorityPayload {
            sequence: 7,
            version: 3,
            body: AuthorityBody::Groups {
                memberships: [("alice".to_string(), vec!["operators".to_string()])].into(),
                hierarchy: Default::default(),
            },
            authored_by: Some("alice".into()),
        }
    }

    #[test]
    fn an_update_signed_by_the_pinned_key_verifies_and_gives_back_what_was_signed() {
        let key = key();
        let update = sign(&payload(), &key).unwrap();
        assert_eq!(
            update.key_fingerprint,
            fingerprint(&key.verifying_key().clone()).unwrap()
        );
        assert_eq!(verify(&update, &key.verifying_key().clone()), Ok(payload()));
    }

    #[test]
    fn every_kind_of_body_travels() {
        let key = key();
        for body in [
            AuthorityBody::Policy {
                source: r#"permit(principal, action, resource);"#.into(),
            },
            AuthorityBody::Groups {
                memberships: BTreeMap::new(),
                hierarchy: Default::default(),
            },
            // With an arrangement of groups and roles too.
            AuthorityBody::Groups {
                memberships: [("alice".to_string(), vec!["operators".to_string()])].into(),
                hierarchy: serde_json::from_value(serde_json::json!({
                    "groups": { "operators": { "groups": ["staff"], "roles": ["policy-author"] } },
                    "roles": { "policy-author": { "capabilities": ["update-policy"] } }
                }))
                .unwrap(),
            },
            AuthorityBody::Revoked {
                serials: vec!["01ab".into(), "02cd".into()],
                compromised: Vec::new(),
            },
        ] {
            let sent = AuthorityPayload {
                sequence: 1,
                version: 1,
                body,
                authored_by: None,
            };
            let update = sign(&sent, &key).unwrap();
            assert_eq!(verify(&update, &key.verifying_key().clone()).unwrap(), sent);
        }
    }

    #[test]
    fn a_payload_or_a_signature_that_was_touched_does_not_verify() {
        let key = key();
        let update = sign(&payload(), &key).unwrap();
        let public = *key.verifying_key();

        let mut altered = update.clone();
        let at = altered.payload.len() / 2;
        altered.payload[at] ^= 1;
        assert_eq!(
            verify(&altered, &public),
            Err(AuthorityUpdateError::BadSignature)
        );

        let mut forged = update.clone();
        forged.signature[0] ^= 1;
        assert_eq!(
            verify(&forged, &public),
            Err(AuthorityUpdateError::BadSignature)
        );

        let mut truncated = update;
        truncated.signature.truncate(10);
        assert_eq!(
            verify(&truncated, &public),
            Err(AuthorityUpdateError::BadSignature)
        );
    }

    #[test]
    fn an_update_from_another_key_is_refused_by_its_fingerprint_before_anything_else() {
        let update = sign(&payload(), &another_key()).unwrap();
        let pinned = *key().verifying_key();
        match verify(&update, &pinned) {
            Err(AuthorityUpdateError::UnknownKey { expected, got }) => {
                assert_eq!(expected, fingerprint(&pinned).unwrap());
                assert_eq!(got, update.key_fingerprint);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_fingerprint_that_lies_about_the_signing_key_does_not_help() {
        // Signed by another key, but says it is the pinned one: the signature is checked against the pinned
        // key and fails.
        let mut update = sign(&payload(), &another_key()).unwrap();
        let pinned = *key().verifying_key();
        update.key_fingerprint = fingerprint(&pinned).unwrap();
        assert_eq!(
            verify(&update, &pinned),
            Err(AuthorityUpdateError::BadSignature)
        );
    }

    #[test]
    fn a_signature_made_for_another_purpose_cannot_be_replayed_as_an_update() {
        // The same key, the same payload bytes, signed without the domain line.
        let key = key();
        let bytes = serde_json::to_vec(&payload()).unwrap();
        let bare: p256::ecdsa::Signature = key.sign(&bytes);
        let update = AuthorityUpdate {
            key_fingerprint: fingerprint(&key.verifying_key().clone()).unwrap(),
            payload: bytes,
            signature: bare.to_bytes().to_vec(),
        };
        assert_eq!(
            verify(&update, &key.verifying_key().clone()),
            Err(AuthorityUpdateError::BadSignature)
        );
    }

    #[test]
    fn a_correctly_signed_payload_that_is_not_an_update_is_malformed_not_believed() {
        let key = key();
        for bytes in [
            br#"{"sequence":1,"version":1,"body":{"kind":"policy","source":"x"},"authored_by":null,"extra":1}"#
                .to_vec(),
            br#"{"sequence":1,"version":1,"body":{"kind":"nothing"},"authored_by":null}"#.to_vec(),
            b"not json".to_vec(),
        ] {
            let signed: p256::ecdsa::Signature = key.sign(&signed_bytes(&bytes));
            let update = AuthorityUpdate {
                key_fingerprint: fingerprint(&key.verifying_key().clone()).unwrap(),
                payload: bytes,
                signature: signed.to_bytes().to_vec(),
            };
            assert!(
                matches!(
                    verify(&update, &key.verifying_key().clone()),
                    Err(AuthorityUpdateError::Malformed(_))
                ),
                "{:?}",
                String::from_utf8_lossy(&update.payload)
            );
        }
    }

    #[test]
    fn a_snapshot_and_a_request_for_one_survive_the_wire() {
        let key = key();
        let snapshot = AuthoritySnapshot {
            certificate_chain_pem: vec![],
            escrow_certificate_chain_pem: vec![],
            public_key_pem: public_key_pem(key.verifying_key()).unwrap(),
            updates: vec![sign(&payload(), &key).unwrap()],
        };
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&snapshot).unwrap();
        let back = rkyv::from_bytes::<AuthoritySnapshot, rkyv::rancor::Error>(&bytes).unwrap();
        assert_eq!(back, snapshot);
        // The key it carries is the key that signed what it carries.
        let carried = back.public_key().unwrap();
        assert_eq!(carried, key.verifying_key().clone());
        assert_eq!(verify(&back.updates[0], &carried), Ok(payload()));

        let request = rkyv::to_bytes::<rkyv::rancor::Error>(&AuthoritySnapshotRequest).unwrap();
        rkyv::from_bytes::<AuthoritySnapshotRequest, rkyv::rancor::Error>(&request).unwrap();
    }

    #[test]
    fn a_snapshot_whose_key_is_not_a_key_says_so() {
        let snapshot = AuthoritySnapshot {
            certificate_chain_pem: vec![],
            escrow_certificate_chain_pem: vec![],
            public_key_pem: "not a key".into(),
            updates: vec![],
        };
        assert!(matches!(
            snapshot.public_key(),
            Err(AuthorityUpdateError::Encoding(_))
        ));
    }

    #[test]
    fn an_update_survives_the_wire() {
        let key = key();
        let update = sign(&payload(), &key).unwrap();
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&update).unwrap();
        let back: AuthorityUpdate =
            rkyv::from_bytes::<AuthorityUpdate, rkyv::rancor::Error>(&bytes).unwrap();
        assert_eq!(back, update);
        assert_eq!(verify(&back, &key.verifying_key().clone()), Ok(payload()));
    }
}
