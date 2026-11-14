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

//! CryptoHandle -- wraps a real, live polar_crypto::CryptoActor's
//! own ActorRef<CryptoMessage>, exposing its messages as
//! direct, ordinary async methods instead of requiring every, real
//! caller to construct a CryptoMessage and call ractor::call! by
//! hand. The real, sole reason this crate exists: hiding every
//! ractor-specific primitive (ActorRef, RpcReplyPort, ractor::call!)
//! behind a real, ordinary Rust API surface.
//!
//! A real trait (CryptoClient), not just an inherent impl -- so a
//! test can implement the same trait with a fake, in-memory version,
//! with no spawned actor, no real Credentials Agent, and no real
//! network connection needed at all.
//!
//! What the domain has of it is deliberately small (docs/architecture/protocol-handlers.md, "No way to the credential from
//! domain code"). It can store a secret, encrypt to another identity, and read a secret that is not a credential:
//!
//! ```
//! # use polar_agent_builder::{CryptoClient, CryptoHandle};
//! async fn what_the_domain_has(crypto: &CryptoHandle) {
//!     let _ = crypto.retrieve_secret("a-name".to_string()).await;
//! }
//! ```
//!
//! No credential, no actor to send messages to, and nothing that registers what it can read of its own section under a binding
//! of its choosing. These do not compile:
//!
//! ```compile_fail
//! # use polar_agent_builder::{CryptoClient, CryptoHandle};
//! async fn a_credential(crypto: &CryptoHandle) {
//!     let _ = crypto.http_credential("jira".to_string(), "jira.example.org".to_string()).await;
//! }
//! ```
//!
//! ```compile_fail
//! # use polar_agent_builder::{CryptoClient, CryptoHandle};
//! async fn a_credential(crypto: &CryptoHandle) {
//!     let _ = crypto.git_credential("github".to_string(), "github.com".to_string()).await;
//! }
//! ```
//!
//! ```compile_fail
//! # use polar_agent_builder::CryptoHandle;
//! fn the_actor(crypto: &CryptoHandle) {
//!     let _ = crypto.as_actor_ref();
//! }
//! ```
//!
//! ```compile_fail
//! # use polar_agent_builder::{CryptoClient, CryptoHandle};
//! async fn a_wider_binding(crypto: &CryptoHandle) {
//!     let _ = crypto.replace_section("credentials".to_string(), Vec::new()).await;
//! }
//! ```

use async_trait::async_trait;
use polar_crypto::CryptoMessage;
use polar_crypto::registry::SecretBinding;
use ractor::ActorRef;

pub use polar_crypto::{CryptoError, Zeroizing};

#[async_trait]
pub trait CryptoClient: Send + Sync {
    /// See CryptoMessage::StoreSecret's own doc comment.
    async fn store_secret(&self, name: String, plaintext: Vec<u8>) -> Result<(), CryptoError>;

    /// See CryptoMessage::EncryptForRecipient's own doc comment.
    async fn encrypt_for_recipient(
        &self,
        recipient_identity: String,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError>;

    /// See CryptoMessage::RetrieveSecret's own doc comment: a credential's record is refused. `Ok(None)` is a name nothing is stored
    /// under; a secret this agent may not have is an error that says policy refused it.
    async fn retrieve_secret(
        &self,
        name: String,
    ) -> Result<Option<polar_crypto::Zeroizing<Vec<u8>>>, CryptoError>;
}

/// What the builder alone does with a `credentials` section: never the domain's, which could otherwise register what it can
/// read of its own section under a wider binding, and have the handler present it there.
#[async_trait]
pub(crate) trait SectionKeeper: Send + Sync {
    /// See CryptoMessage::RegisterSecret's own doc comment.
    async fn register_secret(
        &self,
        name: String,
        section: String,
        secret: Vec<u8>,
        context: Vec<u8>,
        username: Option<polar_crypto::SealedPart>,
        binding: SecretBinding,
    ) -> Result<(), CryptoError>;

    /// See CryptoMessage::ReplaceSection's own doc comment. The names dropped.
    async fn replace_section(
        &self,
        section: String,
        keep: Vec<String>,
    ) -> Result<Vec<String>, CryptoError>;
}

/// The real, live implementation of CryptoClient -- a thin wrapper
/// around a real, already-spawned CryptoActor's own ActorRef.
#[derive(Clone)]
pub struct CryptoHandle {
    actor: ActorRef<CryptoMessage>,
}

impl CryptoHandle {
    pub fn new(actor: ActorRef<CryptoMessage>) -> Self {
        Self { actor }
    }

    /// The actor, for this crate alone: its messages include what only the builder may ask.
    pub(crate) fn actor(&self) -> ActorRef<CryptoMessage> {
        self.actor.clone()
    }
}

/// The agent's TLS, made by its crypto actor from the agent's own keys (docs/plans/crypto-actor.md, step K3): what a
/// component that speaks TLS is given in place of a key. It asks for a configuration and nothing else of the actor.
#[derive(Clone)]
pub struct TlsHandle {
    actor: ActorRef<CryptoMessage>,
}

impl TlsHandle {
    pub(crate) fn new(actor: ActorRef<CryptoMessage>) -> Self {
        Self { actor }
    }

    /// The actor, for this crate alone.
    pub(crate) fn actor(&self) -> ActorRef<CryptoMessage> {
        self.actor.clone()
    }

    /// A client configuration presenting the agent's client key, verifying the server with `verifier`.
    pub async fn client_config(
        &self,
        verifier: std::sync::Arc<dyn rustls::client::danger::ServerCertVerifier>,
    ) -> Result<rustls::ClientConfig, String> {
        ractor::call!(self.actor, |reply| CryptoMessage::ClientTls {
            verifier,
            reply
        })
        .map_err(|e| format!("the crypto actor did not answer: {e}"))?
    }

    /// A server configuration presenting the agent's server key, verifying clients with `verifier`, offering `alpn`.
    pub async fn server_config(
        &self,
        verifier: std::sync::Arc<dyn rustls::server::danger::ClientCertVerifier>,
        alpn: Vec<Vec<u8>>,
    ) -> Result<rustls::ServerConfig, String> {
        ractor::call!(self.actor, |reply| CryptoMessage::ServerTls {
            verifier,
            alpn,
            reply
        })
        .map_err(|e| format!("the crypto actor did not answer: {e}"))?
    }
}

/// The agent's checkpoint key, for an agent with the `checkpoints` capability (docs/plans/record-store/to-main.md): what
/// its domain is given in place of the key. It asks to sign a checkpoint of one of the agent's own logs, and for the
/// key's verifier key and certificate, and nothing else of the actor; the actor judges what it is asked to sign.
#[derive(Clone)]
pub struct CheckpointHandle {
    actor: ActorRef<CryptoMessage>,
}

impl CheckpointHandle {
    pub(crate) fn new(actor: ActorRef<CryptoMessage>) -> Self {
        Self { actor }
    }

    /// `text`'s signature line, if it is a checkpoint of one of the agent's own logs.
    pub async fn sign(&self, text: String) -> Result<String, String> {
        ractor::call!(self.actor, |reply| CryptoMessage::SignCheckpoint {
            text,
            reply
        })
        .map_err(|e| format!("the crypto actor did not answer: {e}"))?
        .map_err(|e| e.to_string())
    }

    /// The key's verifier key, which readers and witnesses pin, and its certificate with its CA chain (PEM) once the
    /// credentials agent has certified it.
    pub async fn key(&self) -> Result<(String, Option<String>), String> {
        ractor::call!(self.actor, |reply| CryptoMessage::CheckpointKey { reply })
            .map_err(|e| format!("the crypto actor did not answer: {e}"))?
            .ok_or_else(|| "the agent keeps no checkpoint key".to_string())
    }
}

/// Flattens ractor::call!'s own, real, outer RactorErr (a genuine
/// messaging/mailbox failure, distinct from CryptoError itself, which
/// only ever describes the real, remote Credentials Agent flow's own
/// failure) into CryptoError::BrokerUnreachable -- the same, real,
/// existing variant CryptoActor's own, internal request/reply
/// helpers already use for an analogous, real failure.
fn flatten_call_result<T>(
    result: Result<Result<T, CryptoError>, ractor::RactorErr<CryptoMessage>>,
) -> Result<T, CryptoError> {
    match result {
        Ok(inner) => inner,
        Err(e) => Err(CryptoError::BrokerUnreachable(e.to_string())),
    }
}

#[async_trait]
impl CryptoClient for CryptoHandle {
    async fn store_secret(&self, name: String, plaintext: Vec<u8>) -> Result<(), CryptoError> {
        let result = ractor::call!(self.actor, |reply| CryptoMessage::StoreSecret {
            name,
            plaintext,
            reply,
        });
        flatten_call_result(result)
    }

    async fn encrypt_for_recipient(
        &self,
        recipient_identity: String,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let result = ractor::call!(self.actor, |reply| CryptoMessage::EncryptForRecipient {
            recipient_identity,
            plaintext,
            reply,
        });
        flatten_call_result(result)
    }

    async fn retrieve_secret(
        &self,
        name: String,
    ) -> Result<Option<polar_crypto::Zeroizing<Vec<u8>>>, CryptoError> {
        let result = ractor::call!(self.actor, |reply| CryptoMessage::RetrieveSecret {
            name,
            reply,
        });
        flatten_call_result(result)
    }
}

#[async_trait]
impl SectionKeeper for CryptoHandle {
    async fn register_secret(
        &self,
        name: String,
        section: String,
        secret: Vec<u8>,
        context: Vec<u8>,
        username: Option<polar_crypto::SealedPart>,
        binding: SecretBinding,
    ) -> Result<(), CryptoError> {
        let result = ractor::call!(self.actor, |reply| CryptoMessage::RegisterSecret {
            name,
            section,
            secret,
            context,
            username,
            binding,
            reply,
        });
        flatten_call_result(result)
    }

    async fn replace_section(
        &self,
        section: String,
        keep: Vec<String>,
    ) -> Result<Vec<String>, CryptoError> {
        let result = ractor::call!(self.actor, |reply| CryptoMessage::ReplaceSection {
            section,
            keep,
            reply
        });
        result.map_err(|e| CryptoError::BrokerUnreachable(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stands in for the CryptoActor: answers RetrieveSecret as it would, so what is checked is that
    /// the handle asks for the right name and passes the answer back.
    struct StubCrypto;

    #[ractor::async_trait]
    impl ractor::Actor for StubCrypto {
        type Msg = CryptoMessage;
        type State = ();
        type Arguments = ();
        async fn pre_start(
            &self,
            _: ActorRef<CryptoMessage>,
            _: (),
        ) -> Result<(), ractor::ActorProcessingErr> {
            Ok(())
        }
        async fn handle(
            &self,
            _: ActorRef<CryptoMessage>,
            message: CryptoMessage,
            _: &mut (),
        ) -> Result<(), ractor::ActorProcessingErr> {
            if let CryptoMessage::RetrieveSecret { name, reply } = message {
                let _ = reply.send(match name.as_str() {
                    "known" => Ok(Some(polar_crypto::Zeroizing::new(b"value".to_vec()))),
                    "forbidden" => Err(CryptoError::RetrieveSecretDenied("no".into())),
                    _ => Ok(None),
                });
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_handle_retrieves_a_secret_by_name() {
        let (actor, _) = ractor::Actor::spawn(None, StubCrypto, ()).await.unwrap();
        let handle = CryptoHandle::new(actor);
        let known = handle.retrieve_secret("known".into()).await.unwrap();
        assert_eq!(known.as_deref().map(|v| v.as_slice()), Some(&b"value"[..]));
        assert!(
            handle
                .retrieve_secret("unknown".into())
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            handle.retrieve_secret("forbidden".into()).await,
            Err(CryptoError::RetrieveSecretDenied(_))
        ));
    }

    use credentials_agent_common::agent_escrow_key::{AgentEscrowKeyReply, AgentEscrowKeyRequest};
    use polar::request_reply::Envelope;
    use ractor::Actor;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

    /// A real, minimal, fake Credentials Agent -- answers
    /// AgentEscrowKeyRequest directly, real enough to prove
    /// CryptoHandle::encrypt_for_recipient genuinely, correctly
    /// delegates through to a real, live CryptoActor, without
    /// needing the full, real Credentials Agent or a real network
    /// connection at all. Mirrors polar-crypto's own, established
    /// FakeCredentialsAgent test pattern, narrowed to just the one,
    /// real flow this test needs.
    struct FakeCredentialsAgent {
        router: ActorRef<polar_router::RouterMessage>,
        recipient_public_key_pem: String,
        /// The recipient's escrow certificate, which the key is believed for.
        recipient_certificate_pem: String,
    }

    #[async_trait]
    impl Actor for FakeCredentialsAgent {
        type Msg = cassini_client::TcpClientMessage;
        type State = ();
        type Arguments = ();

        async fn pre_start(
            &self,
            _myself: ActorRef<Self::Msg>,
            _args: (),
        ) -> Result<Self::State, ractor::ActorProcessingErr> {
            Ok(())
        }

        async fn handle(
            &self,
            _myself: ActorRef<Self::Msg>,
            message: Self::Msg,
            _state: &mut Self::State,
        ) -> Result<(), ractor::ActorProcessingErr> {
            let cassini_client::TcpClientMessage::Publish { topic, payload, .. } = message else {
                return Ok(());
            };
            if topic == credentials_agent_common::CREDENTIALS_AGENT_ESCROW_KEY_REQUESTS_TOPIC
                && let Ok(envelope) = rkyv::from_bytes::<
                    Envelope<AgentEscrowKeyRequest>,
                    rkyv::rancor::Error,
                >(&payload)
            {
                let reply = Envelope {
                    correlation_id: envelope.correlation_id,
                    payload: AgentEscrowKeyReply::Found {
                        public_key_pem: self.recipient_public_key_pem.clone(),
                        certificate_pem: self.recipient_certificate_pem.clone(),
                    },
                };
                let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&reply)
                    .unwrap()
                    .to_vec();
                let _ = self.router.send_message(polar_router::RouterMessage::Route(
                    polar_router::IncomingMessage {
                        topic: credentials_agent_common::CREDENTIALS_AGENT_ESCROW_KEY_REPLIES_TOPIC
                            .to_string(),
                        payload: bytes,
                        published_by: None,
                        published_instance: None,
                        trace_ctx: None,
                    },
                ));
            }
            Ok(())
        }
    }

    fn write_test_agent_certificate() -> tempfile::NamedTempFile {
        let mut rng = rand::rng();
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let private_key_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let key_pair = rcgen::KeyPair::from_pem(&private_key_pem).unwrap();
        let params = rcgen::CertificateParams::new(vec!["test-agent".to_string()]).unwrap();
        let certificate_pem = params.self_signed(&key_pair).unwrap().pem();

        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), certificate_pem).unwrap();
        file
    }

    #[tokio::test]
    async fn encrypt_for_recipient_genuinely_delegates_through_to_a_real_crypto_actor() {
        let mut rng = rand::rng();
        let recipient_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let recipient_public_key_pem = recipient_key
            .to_public_key()
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();

        let (router, _) = Actor::spawn(None, polar_router::RouterActor, ())
            .await
            .unwrap();

        // The recipient's key, in the escrow certificate the CA this agent pins signed for it.
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_pem = ca_params.self_signed(&ca_key).unwrap().pem();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let mut params =
            rcgen::CertificateParams::new(vec!["some-other-agent".to_string()]).unwrap();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::EmailProtection];
        let recipient_certificate_pem = params
            .signed_by(
                &rcgen::SubjectPublicKeyInfo::from_pem(&recipient_public_key_pem).unwrap(),
                &issuer,
            )
            .unwrap()
            .pem();
        let ca_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(ca_file.path(), &ca_pem).unwrap();

        let (fake_agent, _) = Actor::spawn(
            None,
            FakeCredentialsAgent {
                router: router.clone(),
                recipient_public_key_pem,
                recipient_certificate_pem,
            },
            (),
        )
        .await
        .unwrap();

        let own_cert_file = write_test_agent_certificate();

        let (crypto_actor, _) = Actor::spawn(
            None,
            polar_crypto::CryptoActor,
            polar_crypto::CryptoActorArgs::new(fake_agent, router).with_settings(
                polar_crypto::environment::CryptoSettings {
                    own_certificate_path: own_cert_file.path().to_string_lossy().into_owned(),
                    custody_socket: None,
                    ca_cert_path: ca_file.path().to_string_lossy().into_owned(),
                    ..Default::default()
                },
            ),
        )
        .await
        .unwrap();

        drop(own_cert_file);

        let handle = CryptoHandle::new(crypto_actor);

        let plaintext = b"a real secret, via a real CryptoHandle";
        let wire_bytes = handle
            .encrypt_for_recipient("some-other-agent".to_string(), plaintext.to_vec())
            .await
            .expect("encrypt_for_recipient must genuinely succeed");

        let escrowed: credentials_agent_common::escrow_secret::EscrowedSecret =
            rkyv::from_bytes::<_, rkyv::rancor::Error>(&wire_bytes).unwrap();
        let decrypted = escrowed.decrypt(&recipient_key).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }

    #[tokio::test]
    async fn a_recipient_with_no_usable_key_genuinely_fails_through_the_real_handle() {
        // Mirrors polar-crypto's own, established
        // encrypt_for_recipient_fails_with_recipient_key_not_found_when_the_recipient_has_no_usable_key
        // test exactly -- the real, fast-failing NotFound case, not
        // a real, slow timeout (CryptoActor's own REPLY_TIMEOUT is a
        // genuine 30 real seconds -- far too slow for a real, fast
        // unit test to wait out).
        struct FakeCredentialsAgentAnsweringNotFound {
            router: ActorRef<polar_router::RouterMessage>,
        }
        #[async_trait]
        impl Actor for FakeCredentialsAgentAnsweringNotFound {
            type Msg = cassini_client::TcpClientMessage;
            type State = ();
            type Arguments = ();
            async fn pre_start(
                &self,
                _myself: ActorRef<Self::Msg>,
                _args: (),
            ) -> Result<Self::State, ractor::ActorProcessingErr> {
                Ok(())
            }
            async fn handle(
                &self,
                _myself: ActorRef<Self::Msg>,
                message: Self::Msg,
                _state: &mut Self::State,
            ) -> Result<(), ractor::ActorProcessingErr> {
                let cassini_client::TcpClientMessage::Publish { topic, payload, .. } = message
                else {
                    return Ok(());
                };
                if topic == credentials_agent_common::CREDENTIALS_AGENT_ESCROW_KEY_REQUESTS_TOPIC
                    && let Ok(envelope) = rkyv::from_bytes::<
                        Envelope<AgentEscrowKeyRequest>,
                        rkyv::rancor::Error,
                    >(&payload)
                {
                    let reply = Envelope {
                        correlation_id: envelope.correlation_id,
                        payload: AgentEscrowKeyReply::NotFound,
                    };
                    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&reply)
                        .unwrap()
                        .to_vec();
                    let _ = self.router.send_message(polar_router::RouterMessage::Route(
                        polar_router::IncomingMessage {
                            topic:
                                credentials_agent_common::CREDENTIALS_AGENT_ESCROW_KEY_REPLIES_TOPIC
                                    .to_string(),
                            payload: bytes,
                            published_by: None,
                            published_instance: None,
                            trace_ctx: None,
                        },
                    ));
                }
                Ok(())
            }
        }

        let (router, _) = Actor::spawn(None, polar_router::RouterActor, ())
            .await
            .unwrap();

        let (fake_agent, _) = Actor::spawn(
            None,
            FakeCredentialsAgentAnsweringNotFound {
                router: router.clone(),
            },
            (),
        )
        .await
        .unwrap();

        let own_cert_file = write_test_agent_certificate();

        let (crypto_actor, _) = Actor::spawn(
            None,
            polar_crypto::CryptoActor,
            polar_crypto::CryptoActorArgs::new(fake_agent, router).with_settings(
                polar_crypto::environment::CryptoSettings {
                    own_certificate_path: own_cert_file.path().to_string_lossy().into_owned(),
                    custody_socket: None,
                    ca_cert_path: "/nonexistent/ca.pem".to_string(),
                    ..Default::default()
                },
            ),
        )
        .await
        .unwrap();

        drop(own_cert_file);

        let handle = CryptoHandle::new(crypto_actor);

        let result = handle
            .encrypt_for_recipient("never-issued-agent".to_string(), b"irrelevant".to_vec())
            .await;

        match result {
            Err(CryptoError::RecipientKeyNotFound(identity)) => {
                assert_eq!(identity, "never-issued-agent");
            }
            other => panic!("expected Err(RecipientKeyNotFound(_)), got {other:?}"),
        }
    }
}
