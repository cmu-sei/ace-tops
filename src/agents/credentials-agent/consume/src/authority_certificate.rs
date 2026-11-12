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

//! The credentials agent's authority key certified (docs/architecture/authority-distribution.md, "Pinning the key to
//! the CA"). The escrow key, which signs every authority update (decision 4: one key), is given a `CertType::Signing`
//! certificate for this agent's own identity on cert-issuer's `/internal/issue`, and the publisher carries it in every
//! snapshot, so that a leaf pins the key because the CA it pins says it is the credentials agent's, and not merely
//! because the broker said who published it. The ledger key is given a `CertType::Checkpoint` certificate the same way,
//! which the ledger keeps beside it for whoever checks its checkpoints (docs/architecture/record-store.md, "L2,
//! checkpoints"). Renewed at half its life; tried again every few seconds while cert-issuer cannot answer, the publisher
//! publishing no snapshot until the first.

use crate::authority_publisher::PublisherMessage;
use crate::workload_issuance::{SIGNER_RETRY, renewal_delay};
use cert_client::handshake::HandshakeClient;
use cert_issuer_common::{CertType, InternalIssueRequest};
use ractor::{Actor, ActorProcessingErr, ActorRef};
use std::time::Duration;
use tracing::{info, warn};
use zeroize::Zeroizing;

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Asks cert-issuer to certify the key `key_pem` (PKCS#8) as `identity`'s, a certificate of `cert_type`: its
/// certificate as a chain, and how long until it is to be renewed.
pub async fn certify(
    cert_issuer: &HandshakeClient,
    identity: &str,
    key_pem: &str,
    cert_type: CertType,
) -> Result<(Vec<String>, Duration), String> {
    let csr = cert_issuer_common::keypair::csr_for_private_key_pem(identity, &[], key_pem)
        .map_err(|e| format!("cannot make the key's CSR: {e}"))?;
    let issued = cert_issuer
        .issue_internal(InternalIssueRequest {
            instance_binding: None,
            expires_by: None,
            csr_pem: csr,
            identity: identity.to_string(),
            cert_type,
            extra_sans: vec![],
            subject_dn_defaults: None,
            account_subject: None,
        })
        .await
        .map_err(|e| format!("cert-issuer did not certify the key: {e}"))?;
    let now = unix_now();
    let delay = renewal_delay(now, issued.expires_at.unix_timestamp(), now);
    // The certificate alone: the CA that signed it is the one every pod pins.
    Ok((vec![issued.certificate_pem], delay))
}

pub struct AuthorityCertifier;

/// Who is given each certificate.
pub enum Certified {
    /// The publisher, for the key authority updates are signed with.
    Publisher(ActorRef<PublisherMessage>),
    /// The ledger, for its key.
    Ledger(ActorRef<crate::ledger::LedgerMessage>),
}

impl Certified {
    fn tell(&self, chain: Vec<String>) -> Result<(), ActorProcessingErr> {
        match self {
            Certified::Publisher(publisher) => {
                publisher.cast(PublisherMessage::Certified(chain))?
            }
            Certified::Ledger(ledger) => {
                ledger.cast(crate::ledger::LedgerMessage::KeyCertified(chain))?
            }
        }
        Ok(())
    }
}

pub struct AuthorityCertifierArgs {
    pub cert_issuer: HandshakeClient,
    /// This agent's identity as cert-issuer reads it off its connection: what the certificate names.
    pub identity: String,
    /// The key to certify, PKCS#8 PEM, wiped when the certifier ends.
    pub key_pem: Zeroizing<String>,
    pub cert_type: CertType,
    pub certified: Certified,
}

pub enum AuthorityCertifierMessage {
    Renew,
}

#[ractor::async_trait]
impl Actor for AuthorityCertifier {
    type Msg = AuthorityCertifierMessage;
    type State = AuthorityCertifierArgs;
    type Arguments = AuthorityCertifierArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: AuthorityCertifierArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        myself.cast(AuthorityCertifierMessage::Renew)?;
        Ok(args)
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        AuthorityCertifierMessage::Renew: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        let next = match certify(
            &state.cert_issuer,
            &state.identity,
            &state.key_pem,
            state.cert_type.clone(),
        )
        .await
        {
            Ok((chain, delay)) => {
                info!(cert_type = ?state.cert_type, renewed_in = ?delay, "the key is certified");
                state.certified.tell(chain)?;
                delay
            }
            Err(e) => {
                warn!("{e}; trying again in {SIGNER_RETRY:?}");
                SIGNER_RETRY
            }
        };
        drop(myself.send_after(next, || AuthorityCertifierMessage::Renew));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload_issuance::tests::{CertifiesSigning, OWN_IDENTITY, the_ca};
    use std::sync::{Arc, Mutex};
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn key() -> rsa::RsaPrivateKey {
        crate::escrow::tests::test_keypair().private_key().clone()
    }

    fn key_pem() -> Zeroizing<String> {
        use rsa::pkcs8::EncodePrivateKey;
        key().to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap()
    }

    /// A cert-issuer that signs a checkpoint certificate on `/internal/issue` as the real one does: digital signature,
    /// and the one extended key usage `id-polar-kp-logCheckpoint`.
    struct CertifiesCheckpoint;

    impl wiremock::Respond for CertifiesCheckpoint {
        fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
            let asked: InternalIssueRequest = request.body_json().unwrap();
            let mut csr = rcgen::CertificateSigningRequestParams::from_pem(&asked.csr_pem).unwrap();
            let now = time::OffsetDateTime::now_utc();
            csr.params.not_before = now - time::Duration::minutes(1);
            csr.params.not_after = now + time::Duration::hours(12);
            csr.params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
            csr.params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    &[2, 5, 29, 37],
                    cert_issuer_common::log_checkpoint_extended_key_usage(),
                ));
            ResponseTemplate::new(200).set_body_json(cert_issuer_common::IssueResponse {
                certificate_pem: csr.signed_by(&the_ca().issuer).unwrap().pem(),
                ca_chain_pem: the_ca().pem.clone(),
                serial_number: "checkpoint-1".to_string(),
                session_id: "00000000-0000-0000-0000-000000000003".to_string(),
                expires_at: now + time::Duration::hours(12),
            })
        }
    }

    #[tokio::test]
    async fn the_ledger_key_is_certified_as_a_checkpoint_key_and_its_checkpoints_open_under_the_key_certified()
     {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/internal/issue"))
            .and(body_partial_json(serde_json::json!({
                "identity": OWN_IDENTITY,
                "cert_type": "CHECKPOINT",
                "extra_sans": [],
            })))
            .respond_with(CertifiesCheckpoint)
            .expect(1)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let ledger_path = dir.path().join("ledger.log");
        let key = crate::ledger::LedgerKey {
            path: dir.path().join("ledger-key.pem").display().to_string(),
            identity: OWN_IDENTITY.to_string(),
        };
        let (ledger, _) = Actor::spawn(
            None,
            crate::ledger::LedgerActor,
            crate::ledger::LedgerActorArgs {
                log_path: ledger_path.display().to_string(),
                copy_from: None,
                key: key.clone(),
                projection_actor: crate::projection::tests::fake_projection_actor().await,
            },
        )
        .await
        .unwrap();
        let ledger_key = crate::ledger_key::load_or_generate(&key.path).unwrap();
        let (certifier, _) = Actor::spawn(
            None,
            AuthorityCertifier,
            AuthorityCertifierArgs {
                cert_issuer: HandshakeClient::new(server.uri()),
                identity: OWN_IDENTITY.to_string(),
                key_pem: crate::ledger_key::pkcs8_pem(&ledger_key).unwrap(),
                cert_type: CertType::Checkpoint,
                certified: Certified::Ledger(ledger.clone()),
            },
        )
        .await
        .unwrap();
        let kept = dir.path().join("ledger-key.crt");
        for _ in 0..50 {
            if kept.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let trust = polar_signing::Trust::from_pem(&[the_ca().pem.clone()]).unwrap();
        let certified = polar_signing::verify_checkpoint_certificate(
            &std::fs::read_to_string(&kept).unwrap(),
            &trust,
            unix_now(),
            OWN_IDENTITY,
        )
        .unwrap();
        let certified =
            <p256::ecdsa::VerifyingKey as p256::pkcs8::DecodePublicKey>::from_public_key_pem(
                &certified,
            )
            .unwrap();
        assert_eq!(&certified, ledger_key.verifying_key());
        // Not the authority key's certificate: a leaf would never pin it.
        assert!(
            polar_signing::verify_authority_certificate(
                &std::fs::read_to_string(&kept).unwrap(),
                &trust,
                unix_now(),
                OWN_IDENTITY
            )
            .is_err()
        );
        // The checkpoint kept at the ledger's start opens under the key the certificate names.
        let verifier =
            polar_log::checkpoint::NoteVerifier::parse(&polar_log::checkpoint::verifier_key(
                &crate::ledger_checkpoint::key_name(OWN_IDENTITY),
                &certified,
            ))
            .unwrap();
        let note =
            std::fs::read_to_string(crate::ledger_checkpoint::kept_path(&ledger_path)).unwrap();
        assert!(polar_log::checkpoint::open(&note, &[verifier]).is_ok());
        certifier.stop(None);
        ledger.stop(None);
    }

    #[tokio::test]
    async fn the_escrow_key_is_certified_as_this_agent_s_signing_key_and_a_leaf_believes_it() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/internal/issue"))
            .and(body_partial_json(serde_json::json!({
                "identity": OWN_IDENTITY,
                "cert_type": "SIGNING",
                "extra_sans": [],
            })))
            .respond_with(CertifiesSigning)
            .expect(1)
            .mount(&server)
            .await;
        let (chain, delay) = certify(
            &HandshakeClient::new(server.uri()),
            OWN_IDENTITY,
            &key_pem(),
            CertType::Signing,
        )
        .await
        .unwrap();
        // An hour's certificate, renewed at half of it.
        assert!(
            (Duration::from_secs(1800 - 5)..=Duration::from_secs(1800 + 5)).contains(&delay),
            "{delay:?}"
        );
        // The publisher takes it, and a leaf that pins the CA pins the escrow key under it.
        let mut book = credentials_agent_common::authority_book::AuthorityBook::new(key(), 0);
        book.certify(chain).unwrap();
        let trust = polar_signing::Trust::from_pem(&[the_ca().pem.clone()]).unwrap();
        assert_eq!(
            book.snapshot()
                .unwrap()
                .certified_key(&trust, OWN_IDENTITY, unix_now()),
            Ok(key().to_public_key())
        );
    }

    /// Notes each `Certified` the publisher is sent.
    struct Publisher(Arc<Mutex<Vec<Vec<String>>>>);

    #[ractor::async_trait]
    impl Actor for Publisher {
        type Msg = PublisherMessage;
        type State = ();
        type Arguments = ();
        async fn pre_start(&self, _: ActorRef<Self::Msg>, _: ()) -> Result<(), ActorProcessingErr> {
            Ok(())
        }
        async fn handle(
            &self,
            _: ActorRef<Self::Msg>,
            message: Self::Msg,
            _: &mut (),
        ) -> Result<(), ActorProcessingErr> {
            if let PublisherMessage::Certified(chain) = message {
                self.0.lock().unwrap().push(chain);
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn while_cert_issuer_cannot_answer_it_tries_again_and_hands_the_publisher_the_first_it_gets()
     {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/internal/issue"))
            .respond_with(ResponseTemplate::new(503).set_body_string("down"))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/internal/issue"))
            .respond_with(CertifiesSigning)
            .mount(&server)
            .await;
        let certified = Arc::new(Mutex::new(Vec::new()));
        let (publisher, _) = Actor::spawn(None, Publisher(certified.clone()), ())
            .await
            .unwrap();
        let (certifier, _) = Actor::spawn(
            None,
            AuthorityCertifier,
            AuthorityCertifierArgs {
                cert_issuer: HandshakeClient::new(server.uri()),
                identity: OWN_IDENTITY.to_string(),
                key_pem: key_pem(),
                cert_type: CertType::Signing,
                certified: Certified::Publisher(publisher),
            },
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            certified.lock().unwrap().is_empty(),
            "nothing yet: cert-issuer was down"
        );
        tokio::time::sleep(SIGNER_RETRY + Duration::from_secs(1)).await;
        assert_eq!(certified.lock().unwrap().len(), 1, "the second try's");
        certifier.stop(None);
    }
}
