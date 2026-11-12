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

//! The credentials agent's keys certified (docs/architecture/authority-distribution.md, "Pinning the key to the CA";
//! docs/architecture/key-custody.md, "The credentials agent's keys, P-256"). Each is given a certificate for this agent's
//! own identity on cert-issuer's `/internal/issue`: the authority key a `CertType::Signing` one, the escrow key a
//! `CertType::Service` (escrow) one. The publisher carries both in every snapshot, so that a leaf pins each key because
//! the CA it pins says it is the credentials agent's, and not merely because the broker said who published it. The ledger
//! key a `CertType::Checkpoint` one, kept beside it by the ledger for whoever checks its checkpoints
//! (docs/architecture/record-store.md, "L2, checkpoints"). Renewed at half its life; tried again every few seconds while
//! cert-issuer cannot answer, the publisher publishing no snapshot until the authority key's first.
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

/// Asks cert-issuer to certify the key `key_pem` (PKCS#8) as `identity`'s, a certificate of `cert_type` naming
/// `extra_sans` besides: its certificate as a chain, and how long until it is to be renewed.
pub async fn certify(
    cert_issuer: &HandshakeClient,
    identity: &str,
    key_pem: &str,
    cert_type: CertType,
    extra_sans: &[String],
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
            extra_sans: extra_sans.to_vec(),
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
    /// The publisher, told with `message`: `PublisherMessage::Certified` for the authority key,
    /// `PublisherMessage::EscrowCertified` for the escrow key.
    Publisher {
        publisher: ActorRef<PublisherMessage>,
        message: fn(Vec<String>) -> PublisherMessage,
    },
    /// The ledger, for its key.
    Ledger(ActorRef<crate::ledger::LedgerMessage>),
}

impl Certified {
    fn tell(&self, chain: Vec<String>) -> Result<(), ActorProcessingErr> {
        match self {
            Certified::Publisher { publisher, message } => publisher.cast(message(chain))?,
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
    pub extra_sans: Vec<String>,
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
            &state.extra_sans,
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
    use credentials_agent_common::authority_update::AuthorityKey;
    use std::sync::{Arc, Mutex};
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn key() -> AuthorityKey {
        static KEY: std::sync::OnceLock<AuthorityKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| credentials_agent_common::authority_update::generate_key().unwrap())
            .clone()
    }

    fn key_pem() -> Zeroizing<String> {
        crate::authority_key::pkcs8_pem(&key()).unwrap()
    }

    fn escrow_key_pem() -> Zeroizing<String> {
        crate::escrow::tests::test_keypair()
            .private_key_pem()
            .unwrap()
    }

    /// A cert-issuer that signs an escrow certificate on `/internal/issue` as the real one does: the key's own usage, by key
    /// agreement for P-256 and by wrapping for RSA, and the one extended key usage `emailProtection`.
    struct CertifiesEscrow;

    impl wiremock::Respond for CertifiesEscrow {
        fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
            let asked: InternalIssueRequest = request.body_json().unwrap();
            let mut csr = rcgen::CertificateSigningRequestParams::from_pem(&asked.csr_pem).unwrap();
            let now = time::OffsetDateTime::now_utc();
            csr.params.not_before = now - time::Duration::minutes(1);
            csr.params.not_after = now + time::Duration::days(30);
            csr.params.key_usages = vec![if csr.public_key.algorithm()
                == &rcgen::PKCS_ECDSA_P256_SHA256
            {
                rcgen::KeyUsagePurpose::KeyAgreement
            } else {
                rcgen::KeyUsagePurpose::KeyEncipherment
            }];
            csr.params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::EmailProtection];
            ResponseTemplate::new(200).set_body_json(cert_issuer_common::IssueResponse {
                certificate_pem: csr.signed_by(&the_ca().issuer).unwrap().pem(),
                ca_chain_pem: the_ca().pem.clone(),
                serial_number: "escrow-1".to_string(),
                session_id: "00000000-0000-0000-0000-000000000002".to_string(),
                expires_at: now + time::Duration::days(30),
            })
        }
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
        let ledger_key = crate::authority_key::load_or_generate(&key.path).unwrap();
        let (certifier, _) = Actor::spawn(
            None,
            AuthorityCertifier,
            AuthorityCertifierArgs {
                cert_issuer: HandshakeClient::new(server.uri()),
                identity: OWN_IDENTITY.to_string(),
                key_pem: crate::authority_key::pkcs8_pem(&ledger_key).unwrap(),
                cert_type: CertType::Checkpoint,
                extra_sans: Vec::new(),
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
    async fn the_authority_key_is_certified_as_this_agent_s_signing_key_and_a_leaf_believes_it() {
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
            &[],
        )
        .await
        .unwrap();
        // An hour's certificate, renewed at half of it.
        assert!(
            (Duration::from_secs(1800 - 5)..=Duration::from_secs(1800 + 5)).contains(&delay),
            "{delay:?}"
        );
        // The publisher takes it, and a leaf that pins the CA pins the authority key under it.
        let mut book = credentials_agent_common::authority_book::AuthorityBook::new(key(), 0);
        book.certify(chain).unwrap();
        let trust = polar_signing::Trust::from_pem(&[the_ca().pem.clone()]).unwrap();
        assert_eq!(
            book.snapshot()
                .unwrap()
                .certified_key(&trust, OWN_IDENTITY, unix_now()),
            Ok(*key().verifying_key())
        );
    }

    #[tokio::test]
    async fn the_escrow_key_is_certified_as_this_agent_s_escrow_key_and_a_leaf_seals_to_it() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/internal/issue"))
            .and(body_partial_json(serde_json::json!({
                "identity": OWN_IDENTITY,
                "cert_type": "SERVICE",
                "extra_sans": [],
            })))
            .respond_with(CertifiesEscrow)
            .expect(1)
            .mount(&server)
            .await;
        let (chain, _) = certify(
            &HandshakeClient::new(server.uri()),
            OWN_IDENTITY,
            &escrow_key_pem(),
            CertType::Service,
            &[],
        )
        .await
        .unwrap();
        let trust = polar_signing::Trust::from_pem(&[the_ca().pem.clone()]).unwrap();
        assert_eq!(
            polar_signing::verify_escrow_certificate(
                &chain.concat(),
                &trust,
                unix_now(),
                OWN_IDENTITY
            )
            .as_deref(),
            Ok(crate::escrow::tests::test_keypair().public_key_pem())
        );
    }

    /// Each certificate the publisher was sent, with which key it was for.
    type Sent = Arc<Mutex<Vec<(&'static str, Vec<String>)>>>;

    /// Notes each certificate the publisher is sent.
    struct Publisher(Sent);

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
            match message {
                PublisherMessage::Certified(chain) => {
                    self.0.lock().unwrap().push(("authority", chain))
                }
                PublisherMessage::EscrowCertified(chain) => {
                    self.0.lock().unwrap().push(("escrow", chain))
                }
                _ => {}
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn while_cert_issuer_cannot_answer_it_tries_again_and_tells_the_publisher_the_first_it_gets()
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
            .respond_with(CertifiesEscrow)
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
                key_pem: escrow_key_pem(),
                cert_type: CertType::Service,
                extra_sans: Vec::new(),
                certified: Certified::Publisher {
                    publisher,
                    message: PublisherMessage::EscrowCertified,
                },
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
        let certified = certified.lock().unwrap();
        assert_eq!(certified.len(), 1, "the second try's");
        assert_eq!(certified[0].0, "escrow", "as the message it was given says");
        certifier.stop(None);
    }
}
