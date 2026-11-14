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

//! The credentials agent's revocations as evidence (docs/architecture/key-custody.md, "Revocations as evidence"). Each
//! certificate a `Revoke` revokes (every revocation but a supersession, which is routine) is said in a `revocation`
//! record, signed by the record signer the builder hands the agent (its key the crypto actor's, certified for
//! `c:record-evidence:revocation` alone, never the authority key) and sent to the git server for `polar-evidence` over
//! Cassini (`polar_agent_builder::recorder`). The ledger notes each the server holds (`RevocationRecorded`), so what was
//! not recorded before a restart is sent after it, and nothing twice. A reader holds a revoked certificate's records to
//! the revocation.

use crate::ledger::LedgerMessage;
use crate::state::Revocation;
use credentials_agent_common::events::CredentialsEvent;
use polar_agent_builder::EvidenceRecord;
use polar_agent_builder::recorder::{Recorder, RecorderArgs, RecorderMessage};
use ractor::{Actor, ActorProcessingErr, ActorRef};
use serde_json::json;
use std::collections::BTreeSet;
use std::sync::Arc;
use tracing::{error, warn};

/// The record type: the one the agent declares (`agent::REVOCATION_RECORD`).
pub const REVOCATION: &str = crate::agent::REVOCATION_RECORD;

/// `revocation`, as a record: its subject the certificate's serial; the identity it named, when known; why, whether
/// for a compromise, by whom and when.
pub fn record_of(revocation: &Revocation) -> EvidenceRecord {
    let mut record = json!({
        "subject": { "serial": revocation.serial },
        "reason": revocation.reason,
        "compromise": revocation.reason.is_compromise(),
        "revoked_by": revocation.revoked_by,
        "revoked_at_unix_secs": revocation.revoked_at.div_euclid(1000),
    });
    if let Some(identity) = &revocation.identity {
        record["identity"] = json!(identity);
    }
    let serde_json::Value::Object(fields) = record else {
        unreachable!("a record's fields are an object")
    };
    EvidenceRecord::new(REVOCATION, fields)
        .expect("a revocation record has a type and no `type` field")
}

/// The serial a revocation record is of.
fn serial_of(record: &EvidenceRecord) -> Option<String> {
    record.payload()["subject"]["serial"]
        .as_str()
        .map(str::to_string)
}

pub enum RevocationEvidenceMessage {
    /// A certificate was revoked, or the agent started: send what is not recorded.
    Revoked,
    /// The git server holds the record of `serial`'s revocation, at `path`.
    Recorded { serial: String, path: String },
    /// Something arrived on this agent's evidence reply topic, published (the broker says) by `published_by`.
    Answer {
        payload: Vec<u8>,
        published_by: Option<String>,
    },
}

pub struct RevocationEvidence;

pub struct RevocationEvidenceArgs {
    pub ledger: ActorRef<LedgerMessage>,
    /// What the recorder it starts signs with, sends through, and takes answers from.
    pub signer: Arc<dyn polar_agent_builder::RecordSigner>,
    pub publish: polar_agent_builder::recorder::Publish,
    pub server: String,
    pub prefix: String,
    pub clock: fn() -> i64,
}

pub struct RevocationEvidenceState {
    ledger: ActorRef<LedgerMessage>,
    recorder: ActorRef<RecorderMessage>,
    /// Serials handed to the recorder and not yet recorded: none is handed over twice in a run.
    sent: BTreeSet<String>,
}

#[ractor::async_trait]
impl Actor for RevocationEvidence {
    type Msg = RevocationEvidenceMessage;
    type State = RevocationEvidenceState;
    type Arguments = RevocationEvidenceArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: RevocationEvidenceArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        let told = myself.clone();
        let (recorder, _) = Actor::spawn_linked(
            None,
            Recorder,
            RecorderArgs {
                signer: args.signer,
                publish: args.publish,
                server: args.server,
                prefix: args.prefix,
                clock: args.clock,
                taken: Some(Arc::new(move |record, path| {
                    if let Some(serial) = serial_of(&record) {
                        let _ = told.cast(RevocationEvidenceMessage::Recorded { serial, path });
                    }
                })),
            },
            myself.get_cell(),
        )
        .await?;
        let port = ractor::call!(args.ledger, LedgerMessage::Revocations).map_err(|e| {
            ActorProcessingErr::from(format!("the ledger did not give its revocations: {e}"))
        })?;
        port.subscribe(myself.clone(), |_| Some(RevocationEvidenceMessage::Revoked));
        myself.cast(RevocationEvidenceMessage::Revoked)?;
        Ok(RevocationEvidenceState {
            ledger: args.ledger,
            recorder,
            sent: BTreeSet::new(),
        })
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            RevocationEvidenceMessage::Revoked => {
                let unrecorded = ractor::call!(state.ledger, LedgerMessage::UnrecordedRevocations)
                    .map_err(|e| {
                        ActorProcessingErr::from(format!("the ledger did not answer: {e}"))
                    })?;
                for revocation in unrecorded {
                    if state.sent.insert(revocation.serial.clone()) {
                        state
                            .recorder
                            .cast(RecorderMessage::Keep(record_of(&revocation)))?;
                    }
                }
            }
            RevocationEvidenceMessage::Recorded { serial, path } => {
                let event = CredentialsEvent::RevocationRecorded {
                    serial: serial.clone(),
                    path,
                    timestamp: polar::time::now_millis(),
                };
                match ractor::call!(state.ledger, |reply| LedgerMessage::Append { event, reply }) {
                    Ok(Ok(())) => {
                        state.sent.remove(&serial);
                    }
                    // Sent again at the next start, and the server answers that it holds it already.
                    Ok(Err(e)) => error!(
                        serial,
                        "the record of a revocation is not noted in the ledger: {e}"
                    ),
                    Err(e) => error!(serial, "the ledger did not answer: {e}"),
                }
            }
            RevocationEvidenceMessage::Answer {
                payload,
                published_by,
            } => {
                if let Err(e) = state.recorder.cast(RecorderMessage::Answer {
                    payload,
                    published_by,
                }) {
                    warn!("could not pass on the git server's answer: {e}");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::tests::{append, spawn_ledger};
    use credentials_agent_common::events::RevocationReason;
    use polar_git_server_common::{AddRecord, Envelope, RecordAdded};
    use std::sync::Mutex;
    use std::time::Duration;

    const SERVER: &str = "polar-git-server.polar.serviceaccount.cluster.local";

    /// The record key the agent's crypto actor holds, and the signer that signs with it, as the builder hands them:
    /// uncertified until `certify`, so a record asked of it now is not signed yet.
    async fn record_signer(
        dir: &std::path::Path,
    ) -> (
        polar_agent_builder::crypto::RecordKeyHandle,
        polar_agent_builder::SignerHandle,
    ) {
        use crate::workload_issuance::tests::OWN_IDENTITY;
        let own = dir.join("cert.pem");
        let params = rcgen::CertificateParams::new(vec![OWN_IDENTITY.to_string()]).unwrap();
        std::fs::write(
            &own,
            params
                .self_signed(&rcgen::KeyPair::generate().unwrap())
                .unwrap()
                .pem(),
        )
        .unwrap();
        polar_agent_builder::crypto::RecordKeyHandle::for_tests(
            &dir.join("record-key.pem").to_string_lossy(),
            &own.to_string_lossy(),
        )
        .await
        .unwrap()
    }

    /// The record key certified as cert-issuer certifies it: the agent's own documentSigning certificate, naming its
    /// record types.
    async fn certify(record_key: &polar_agent_builder::crypto::RecordKeyHandle) {
        use crate::workload_issuance::tests::the_ca;
        let mut csr =
            rcgen::CertificateSigningRequestParams::from_pem(&record_key.csr().await.unwrap())
                .unwrap();
        let now = time::OffsetDateTime::now_utc();
        csr.params.not_before = now - time::Duration::minutes(1);
        csr.params.not_after = now + time::Duration::hours(12);
        for name in crate::agent::record_names() {
            csr.params
                .subject_alt_names
                .push(rcgen::SanType::URI(name.try_into().unwrap()));
        }
        csr.params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        csr.params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::Other(
            cert_issuer_common::OID_DOCUMENT_SIGNING.to_vec(),
        )];
        let certificate = csr.signed_by(&the_ca().issuer).unwrap().pem();
        record_key
            .keep(format!("{certificate}{}", the_ca().pem))
            .await
            .unwrap();
    }

    fn revoke(serial: &str, reason: RevocationReason) -> CredentialsEvent {
        CredentialsEvent::Revoke {
            serial: serial.to_string(),
            reason,
            revoked_by: "admin".to_string(),
            timestamp: 1_700_000_000_123,
        }
    }

    #[test]
    fn a_revocation_is_said_by_its_serial_why_by_whom_and_when() {
        let record = record_of(&Revocation {
            serial: "0a".to_string(),
            reason: RevocationReason::Compromised,
            revoked_by: "alice".to_string(),
            revoked_at: 1_700_000_000_999,
            identity: Some("kube-consumer.polar.serviceaccount.cluster.local".to_string()),
        });
        assert_eq!(
            record.payload(),
            &json!({
                "type": "revocation",
                "subject": { "serial": "0a" },
                "reason": "Compromised",
                "compromise": true,
                "revoked_by": "alice",
                "revoked_at_unix_secs": 1_700_000_000,
                "identity": "kube-consumer.polar.serviceaccount.cluster.local",
            })
        );
    }

    struct Rig {
        evidence: ActorRef<RevocationEvidenceMessage>,
        sent: Arc<Mutex<Vec<Envelope<AddRecord>>>>,
    }

    async fn rig(
        ledger: &ActorRef<LedgerMessage>,
        signer: polar_agent_builder::SignerHandle,
        clock: fn() -> i64,
    ) -> Rig {
        let sent: Arc<Mutex<Vec<Envelope<AddRecord>>>> = Arc::default();
        let seen = sent.clone();
        let (evidence, _) = Actor::spawn(
            None,
            RevocationEvidence,
            RevocationEvidenceArgs {
                ledger: ledger.clone(),
                signer: Arc::new(signer),
                publish: Arc::new(move |bytes| {
                    seen.lock()
                        .unwrap()
                        .push(polar_git_server_common::decode_add(&bytes).unwrap());
                    Ok(())
                }),
                server: SERVER.to_string(),
                prefix: "test".to_string(),
                clock,
            },
        )
        .await
        .unwrap();
        Rig { evidence, sent }
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    fn serial_sent(envelope: &Envelope<AddRecord>) -> String {
        let document: serde_json::Value = serde_json::from_str(&envelope.payload.record).unwrap();
        document["payload"]["subject"]["serial"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn committed(envelope: &Envelope<AddRecord>, path: &str) -> RevocationEvidenceMessage {
        RevocationEvidenceMessage::Answer {
            payload: polar_git_server_common::encode_added(&Envelope {
                correlation_id: envelope.correlation_id.clone(),
                payload: RecordAdded::Committed {
                    path: path.to_string(),
                    commit: "c".to_string(),
                },
            }),
            published_by: Some(SERVER.to_string()),
        }
    }

    // What was revoked before the start is sent at it, each once the one before is held; what the server holds is noted
    // and not sent again by the next start; a revocation while it runs is sent then.
    #[tokio::test(flavor = "multi_thread")]
    async fn every_revocation_is_recorded_once_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = spawn_ledger(dir.path().join("events.jsonl").to_str().unwrap()).await;
        append(&ledger, revoke("0a", RevocationReason::Compromised))
            .await
            .unwrap();
        append(&ledger, revoke("0b", RevocationReason::Decommissioned))
            .await
            .unwrap();
        // A supersession is routine: no record.
        append(&ledger, revoke("09", RevocationReason::Superseded))
            .await
            .unwrap();
        let (record_key, signer) = record_signer(dir.path()).await;
        certify(&record_key).await;

        let first = rig(&ledger, signer.clone(), || 0).await;
        settle().await;
        let sent = first.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 1, "one in flight");
        assert_eq!(serial_sent(&sent[0]), "0a");
        first
            .evidence
            .cast(committed(&sent[0], "revocation/0a/x.json"))
            .unwrap();
        settle().await;
        let sent = first.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 2);
        assert_eq!(serial_sent(&sent[1]), "0b");
        // Stopped before the server answers about 0b.
        first.evidence.stop(None);
        settle().await;

        let second = rig(&ledger, signer, || 0).await;
        settle().await;
        let sent = second.sent.lock().unwrap().clone();
        assert_eq!(
            sent.iter().map(serial_sent).collect::<Vec<_>>(),
            ["0b"],
            "0a is held; 0b is sent again"
        );
        // Revoked while 0b is in flight: 0c waits behind it, and 0b is not handed over again.
        append(&ledger, revoke("0c", RevocationReason::IssuedInError))
            .await
            .unwrap();
        settle().await;
        second
            .evidence
            .cast(committed(&sent[0], "revocation/0b/x.json"))
            .unwrap();
        settle().await;
        // Revoked again: no second record.
        append(&ledger, revoke("0a", RevocationReason::Compromised))
            .await
            .unwrap();
        settle().await;
        let sent = second.sent.lock().unwrap().clone();
        assert_eq!(
            sent.iter().map(serial_sent).collect::<Vec<_>>(),
            ["0b", "0c"]
        );
        assert!(
            ractor::call!(ledger, LedgerMessage::UnrecordedRevocations)
                .unwrap()
                .iter()
                .map(|r| r.serial.as_str())
                .eq(["0c"]),
            "only the one in flight is not recorded"
        );
        second.evidence.stop(None);
    }

    /// The record key is certified after the agent starts: until then a revocation's record cannot be signed, and it is
    /// kept, never dropped; once the key is certified it is signed with it, as the agent's, and sent.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_revocation_waits_unsigned_until_the_record_key_is_certified_and_is_then_sent() {
        static NOW: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(1_000);
        let dir = tempfile::tempdir().unwrap();
        let ledger = spawn_ledger(dir.path().join("events.jsonl").to_str().unwrap()).await;
        append(&ledger, revoke("0a", RevocationReason::Compromised))
            .await
            .unwrap();
        let (record_key, signer) = record_signer(dir.path()).await;
        let waiting = rig(&ledger, signer, || {
            NOW.load(std::sync::atomic::Ordering::SeqCst)
        })
        .await;
        settle().await;
        assert!(
            waiting.sent.lock().unwrap().is_empty(),
            "nothing is sent unsigned"
        );

        certify(&record_key).await;
        NOW.fetch_add(
            polar_agent_builder::recorder::RETRY_SECS + 1,
            std::sync::atomic::Ordering::SeqCst,
        );
        let mut sent = Vec::new();
        for _ in 0..((polar_agent_builder::recorder::TICK.as_millis() / 100) + 50) {
            sent = waiting.sent.lock().unwrap().clone();
            if !sent.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            sent.iter().map(serial_sent).collect::<Vec<_>>(),
            ["0a"],
            "kept, and sent once signed"
        );
        let document = polar_signing::Document::from_value(
            &serde_json::from_str(&sent[0].payload.record).unwrap(),
        )
        .unwrap();
        let trust = polar_signing::Trust::from_pem(std::slice::from_ref(
            &crate::workload_issuance::tests::the_ca().pem,
        ))
        .unwrap();
        let who = polar_signing::verify_in(
            polar_signing::Domain::EVIDENCE_RECORD,
            &document,
            &trust,
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )
        .unwrap();
        assert_eq!(
            who.identity.as_deref(),
            Some(crate::workload_issuance::tests::OWN_IDENTITY),
            "signed as the credentials agent, by its record key"
        );
    }
}
