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

//! The signer: what an agent with the `signing` capability has its evidence records signed with
//! (docs/architecture/key-custody.md, "Workload signing keys", item 4).
//!
//! The key is the pod's own, in the custody daemon's signer slot: made there, never leaving it, never escrowed. The
//! signer is an infrastructure actor, spawned unnamed (as the crypto actor is), so nothing finds it by name; it takes no
//! topic, so nothing outside the process reaches it; and it outlives the domain, so the infrastructure can still sign a
//! record saying it ended one. The domain has a [`SignerHandle`], which signs an [`EvidenceRecord`] and nothing else:
//! never bytes, never a document of another kind. The signer makes the record's signing input, in the evidence domain,
//! and signs only a record of a type the slot's certificate names (`c:record-evidence:<type>`); the daemon holds the key
//! and signs what it is given. A reader holds every record to its signer's certificate as well, so a record signed
//! outside its types is refused where it is read.
//!
//! A review rule the type cannot hold: what the domain asks to sign is built from its own observations, never from
//! content it received. A record in the agent's name says the agent saw it; signing another's words would make the
//! agent a confused deputy.
//!
//! ```
//! # use polar_agent_builder::signer::{EvidenceRecord, RecordSigner, SignerHandle};
//! async fn what_the_domain_has(signer: &SignerHandle) {
//!     let record = EvidenceRecord::new("attestation", serde_json::Map::new()).unwrap();
//!     let _ = signer.sign(record).await;
//! }
//! ```
//!
//! No actor to send messages to, and nothing that signs bytes. These do not compile:
//!
//! ```compile_fail
//! # use polar_agent_builder::signer::SignerHandle;
//! fn the_actor(signer: &SignerHandle) {
//!     let _ = signer.actor();
//! }
//! ```
//!
//! ```compile_fail
//! # use polar_agent_builder::signer::{RecordSigner, SignerHandle};
//! async fn bytes(signer: &SignerHandle) {
//!     let _ = signer.sign(b"anything".to_vec()).await;
//! }
//! ```

use async_trait::async_trait;
use polar_custody::client::{ClientError, CustodyClient};
use polar_custody::protocol::Slot;
use ractor::{Actor, ActorProcessingErr, ActorRef, RpcReplyPort};
use serde_json::{Map, Value};
use std::sync::Arc;

/// What the signer needs of the environment: the custody daemon's socket, which the Cassini client's section declares
/// (`POLAR_CUSTODY_SOCKET`), since the signing key is the daemon's and there is no key file for it.
pub static SECTION: polar_env::Section = polar_env::Section {
    name: "signer",
    vars: &[],
    relations: |env| match polar_custody::environment::CUSTODY_SOCKET.read(env) {
        Ok(Some(_)) => Vec::new(),
        Ok(None) => vec![format!(
            "{} is required to sign records: the signing key is the custody daemon's",
            polar_custody::environment::CUSTODY_SOCKET.name()
        )],
        Err(e) => vec![e.to_string()],
    },
};

/// An evidence record for the agent to sign: its `type` (`[a-z0-9-]+`, what the signer's certificate must name) and
/// what it says.
#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceRecord {
    payload: Value,
}

/// Why an evidence record cannot be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotARecord {
    #[error("`{0}` is not a record type (a-z, 0-9 and -)")]
    Type(String),
    #[error("a record's `type` is its record type, not one of its fields")]
    TypeField,
}

impl EvidenceRecord {
    /// A record of `record_type` saying `fields`.
    pub fn new(record_type: &str, mut fields: Map<String, Value>) -> Result<Self, NotARecord> {
        if !cert_issuer_common::evidence::is_record_type(record_type) {
            return Err(NotARecord::Type(record_type.to_string()));
        }
        if fields.contains_key("type") {
            return Err(NotARecord::TypeField);
        }
        fields.insert("type".to_string(), Value::String(record_type.to_string()));
        Ok(Self {
            payload: Value::Object(fields),
        })
    }

    /// What is signed: the fields, with the `type`.
    pub fn payload(&self) -> &Value {
        &self.payload
    }
}

/// Why a record was not signed.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// Refused: a type the certificate does not name (the signer's), no signing key yet, a revoked pod (the daemon's).
    #[error("the custody daemon refused to sign the record: {0}")]
    Refused(String),
    /// The daemon or the signer could not be asked.
    #[error("the record could not be signed: {0}")]
    Unavailable(String),
}

/// What the domain signs with. A trait, so that a domain's tests can sign with a fake.
#[async_trait]
pub trait RecordSigner: Send + Sync {
    /// `record`, signed with the pod's signing key, as the evidence document that goes in the evidence repository.
    async fn sign(&self, record: EvidenceRecord) -> Result<polar_signing::Document, SignError>;
}

pub enum SignerMessage {
    Sign {
        record: EvidenceRecord,
        reply: RpcReplyPort<Result<polar_signing::Document, SignError>>,
    },
}

/// The signer actor: one record at a time, through the custody daemon's socket.
pub struct SignerActor;

pub struct SignerArgs {
    pub client: Arc<CustodyClient>,
}

#[async_trait]
impl Actor for SignerActor {
    type Msg = SignerMessage;
    type State = Arc<CustodyClient>;
    type Arguments = SignerArgs;

    async fn pre_start(
        &self,
        _: ActorRef<Self::Msg>,
        args: SignerArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(args.client)
    }

    async fn handle(
        &self,
        _: ActorRef<Self::Msg>,
        message: Self::Msg,
        client: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            SignerMessage::Sign { record, reply } => {
                // The client blocks on the socket: off the runtime's workers.
                let client = client.clone();
                let signed = tokio::task::spawn_blocking(move || sign_record(&client, &record))
                    .await
                    .map_err(|e| SignError::Unavailable(e.to_string()))
                    .and_then(|signed| signed);
                if let Err(e) = &signed {
                    tracing::warn!("a record was not signed: {e}");
                }
                let _ = reply.send(signed);
            }
        }
        Ok(())
    }
}

/// `record` signed with the signer slot's key, as the evidence document it is: refused unless the slot's certificate
/// names its type; signed in the evidence domain, as `polar-signing` reads it; the signature in its fixed form, with the
/// slot's chain.
fn sign_record(
    client: &CustodyClient,
    record: &EvidenceRecord,
) -> Result<polar_signing::Document, SignError> {
    let not_signed = |e: ClientError| match e {
        ClientError::Refused(refusal) => SignError::Refused(refusal.to_string()),
        other => SignError::Unavailable(other.to_string()),
    };
    let chain = client.certificate(Slot::Signer).map_err(not_signed)?;
    let record_type = record
        .payload
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let named = chain
        .first()
        .and_then(|leaf| cert_issuer_common::evidence::may_record(leaf).ok())
        .is_some_and(|may| may.allows(record_type));
    if !named {
        return Err(SignError::Refused(format!(
            "the signer's certificate may not record `{record_type}`"
        )));
    }
    let input = polar_signing::document::signing_input_in(
        polar_signing::Domain::EVIDENCE_RECORD,
        &record.payload,
    )
    .map_err(|e| SignError::Unavailable(format!("the record has no canonical form: {e}")))?;
    let der = client.sign(Slot::Signer, &input).map_err(not_signed)?;
    let fixed = p256::ecdsa::Signature::from_der(&der)
        .map_err(|e| SignError::Unavailable(format!("not a signature: {e}")))?
        .to_bytes()
        .to_vec();
    Ok(polar_signing::Document {
        payload: record.payload.clone(),
        signature: polar_signing::SignatureBlock {
            algorithm: polar_signing::Algorithm::EcdsaP256Sha256,
            value: fixed,
            certificate_chain: chain,
        },
    })
}

/// The domain's way to its signer.
#[derive(Clone)]
pub struct SignerHandle {
    actor: ActorRef<SignerMessage>,
}

impl SignerHandle {
    pub(crate) fn new(actor: ActorRef<SignerMessage>) -> Self {
        Self { actor }
    }

    pub(crate) fn actor(&self) -> &ActorRef<SignerMessage> {
        &self.actor
    }
}

#[async_trait]
impl RecordSigner for SignerHandle {
    async fn sign(&self, record: EvidenceRecord) -> Result<polar_signing::Document, SignError> {
        ractor::call!(self.actor, |reply| SignerMessage::Sign { record, reply })
            .map_err(|e| SignError::Unavailable(e.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cert_issuer_common::custody::{CustodyPermission, custodian_identity};
    use polar_custody::custody::{Custody, Roles};
    use polar_custody::protocol::{Reply, Request, Slot};
    use polar_custody::server::{Callers, bind, serve};
    use proptest::prelude::*;
    use serde_json::json;
    use std::sync::RwLock;

    const IDENTITY: &str = "attestation.polar.serviceaccount.cluster.local";

    fn now() -> i64 {
        polar::time::now_millis() / 1000
    }

    struct Ca {
        issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
        pem: String,
    }

    fn ca() -> Ca {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        let pem = params.self_signed(&key).unwrap().pem();
        Ca {
            issuer: rcgen::Issuer::new(params, key),
            pem,
        }
    }

    /// What cert-issuer signs for a key in the daemon: documentSigning, naming `names`.
    fn certify(ca: &Ca, csr_pem: &str, names: &[String]) -> String {
        let mut csr = rcgen::CertificateSigningRequestParams::from_pem(csr_pem).unwrap();
        for name in names {
            csr.params
                .subject_alt_names
                .push(rcgen::SanType::URI(name.clone().try_into().unwrap()));
        }
        let epoch = rcgen::date_time_ymd(1970, 1, 1);
        csr.params.not_before = epoch + std::time::Duration::from_secs((now() - 60) as u64);
        csr.params.not_after = epoch + std::time::Duration::from_secs((now() + 3600) as u64);
        csr.params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        csr.params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::Other(
            cert_issuer_common::OID_DOCUMENT_SIGNING.to_vec(),
        )];
        csr.signed_by(&ca.issuer).unwrap().pem()
    }

    /// A daemon on a socket whose signer slot its custodian filled with a certificate naming `names`, and a signer
    /// actor asking it.
    async fn signer_with(names: &[&str]) -> (SignerHandle, Ca, tempfile::TempDir) {
        let ca = ca();
        let mut custody = Custody::new(&ca.pem).unwrap();
        let installer = Roles {
            installer: true,
            workload: false,
        };
        let Reply::Csr(csr) = custody.handle(
            installer,
            Request::MakeCsr {
                slot: Slot::Custodian,
                identity: custodian_identity(IDENTITY),
                names: vec![],
            },
            now(),
        ) else {
            panic!("a CSR")
        };
        let custodian = certify(&ca, &csr, &[CustodyPermission::Signing.to_san_string()]);
        for request in [
            Request::Install {
                slot: Slot::Custodian,
                chain_pem: vec![custodian],
            },
            Request::Bootstrap {
                identity: IDENTITY.to_string(),
                client: false,
                server: None,
                escrow: false,
                signing: true,
            },
        ] {
            assert_eq!(custody.handle(installer, request, now()), Reply::Installed);
        }
        let csr = custody.workload_csr(Slot::Signer, vec![]).unwrap();
        let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        custody
            .install_workload(Slot::Signer, vec![certify(&ca, &csr, &names)], now())
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("custody.sock");
        let listener = bind(&socket).unwrap();
        // SAFETY: getuid takes nothing and cannot fail.
        let uid = unsafe { libc::getuid() };
        tokio::spawn(serve(
            listener,
            Arc::new(RwLock::new(custody)),
            Arc::new(Callers {
                installer_uid: uid,
                workload_uids: vec![uid],
            }),
        ));
        let (actor, _) = Actor::spawn(
            None,
            SignerActor,
            SignerArgs {
                client: Arc::new(CustodyClient::new(socket)),
            },
        )
        .await
        .unwrap();
        (SignerHandle::new(actor), ca, dir)
    }

    fn fields(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_record_the_domain_signs_verifies_as_evidence_in_the_pod_s_name() {
        let (signer, ca, _dir) = signer_with(&["c:record-evidence:attestation"]).await;
        let record =
            EvidenceRecord::new("attestation", fields(json!({ "subject": { "pod": "p" } })))
                .unwrap();
        let document = signer.sign(record.clone()).await.unwrap();
        assert_eq!(&document.payload, record.payload());
        assert_eq!(document.payload["type"], "attestation");
        let trust = polar_signing::Trust::from_pem(&[ca.pem]).unwrap();
        let who = polar_signing::verify_in(
            polar_signing::Domain::EVIDENCE_RECORD,
            &document,
            &trust,
            now(),
        )
        .unwrap();
        assert_eq!(who.identity.as_deref(), Some(IDENTITY));
        assert!(
            polar_signing::verify_in(
                polar_signing::Domain::CONFIGURATION,
                &document,
                &trust,
                now()
            )
            .is_err()
        );
        // A type the certificate does not name is the signer's to refuse, before the daemon is asked.
        let other = EvidenceRecord::new("projection-test", Map::new()).unwrap();
        assert!(matches!(
            signer.sign(other).await,
            Err(SignError::Refused(why)) if why.contains("projection-test")
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn with_no_daemon_a_record_is_unavailable_and_the_signer_goes_on() {
        let (actor, _) = Actor::spawn(
            None,
            SignerActor,
            SignerArgs {
                client: Arc::new(CustodyClient::new("/nonexistent/custody.sock")),
            },
        )
        .await
        .unwrap();
        let signer = SignerHandle::new(actor.clone());
        for _ in 0..2 {
            let record = EvidenceRecord::new("attestation", Map::new()).unwrap();
            assert!(matches!(
                signer.sign(record).await,
                Err(SignError::Unavailable(_))
            ));
        }
        assert_eq!(actor.get_status(), ractor::ActorStatus::Running);
    }

    #[test]
    fn a_record_is_a_record_type_and_fields_that_do_not_say_another() {
        let record = EvidenceRecord::new("attestation-report", fields(json!({ "n": 1 }))).unwrap();
        assert_eq!(
            record.payload(),
            &json!({ "type": "attestation-report", "n": 1 })
        );
        for bad in ["", "Attestation", "a_b", "a b", "attestation/x"] {
            assert_eq!(
                EvidenceRecord::new(bad, Map::new()),
                Err(NotARecord::Type(bad.to_string()))
            );
        }
        assert_eq!(
            EvidenceRecord::new("attestation", fields(json!({ "type": "projection-test" }))),
            Err(NotARecord::TypeField)
        );
    }

    /// A client of a daemon whose signer slot's certificate names `names`, and the CA, for a test that signs records
    /// directly.
    async fn client_with(names: &[&str]) -> (Arc<CustodyClient>, Ca, tempfile::TempDir) {
        let (signer, ca, dir) = signer_with(names).await;
        drop(signer);
        (
            Arc::new(CustodyClient::new(dir.path().join("custody.sock"))),
            ca,
            dir,
        )
    }

    proptest! {
        /// For any record type and any set its certificate names (or the bare name), the record is signed exactly when
        /// the set allows its type, and every signature verifies as evidence under the certificate.
        #[test]
        fn a_record_is_signed_exactly_when_its_certificate_names_its_type(
            signed in "[a-z0-9-]{1,10}",
            named in prop::collection::btree_set("[a-z0-9-]{1,10}", 1..4),
            bare in any::<bool>(),
        ) {
            let mut names: Vec<String> = named.iter().map(|t| format!("c:record-evidence:{t}")).collect();
            if bare {
                names.push("c:record-evidence".to_string());
            }
            let allowed = bare || named.contains(&signed);
            let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
            let (outcome, ca) = runtime.block_on(async {
                let names: Vec<&str> = names.iter().map(String::as_str).collect();
                let (client, ca, _dir) = client_with(&names).await;
                let record = EvidenceRecord::new(&signed, Map::new()).unwrap();
                let outcome = tokio::task::spawn_blocking(move || sign_record(&client, &record))
                    .await
                    .unwrap();
                (outcome, ca)
            });
            match outcome {
                Ok(document) => {
                    prop_assert!(allowed, "{} signed, not named", signed);
                    let trust = polar_signing::Trust::from_pem(&[ca.pem]).unwrap();
                    prop_assert!(polar_signing::verify_in(
                        polar_signing::Domain::EVIDENCE_RECORD, &document, &trust, now()).is_ok());
                }
                Err(SignError::Refused(why)) => {
                    prop_assert!(!allowed, "{} named, yet refused: {}", signed, why);
                    prop_assert!(why.contains(&format!("`{signed}`")), "{}", why);
                }
                Err(other) => prop_assert!(false, "{}", other),
            }
        }

        // For every type and fields: a record is made exactly when the type is a record type and the fields do not
        // name one, and then what is signed says that type and every field, and nothing else.
        #[test]
        fn a_record_says_its_type_and_its_fields_and_nothing_else(
            record_type in "[a-zA-Z0-9_ -]{0,10}",
            names in prop::collection::btree_set("[a-z]{1,6}", 0..4),
        ) {
            let fields: Map<String, Value> =
                names.iter().map(|n| (n.clone(), Value::String(n.to_uppercase()))).collect();
            match EvidenceRecord::new(&record_type, fields.clone()) {
                Ok(record) => {
                    prop_assert!(cert_issuer_common::evidence::is_record_type(&record_type));
                    prop_assert!(!fields.contains_key("type"));
                    let mut expected = fields;
                    expected.insert("type".into(), Value::String(record_type));
                    prop_assert_eq!(record.payload(), &Value::Object(expected));
                }
                Err(_) => prop_assert!(
                    !cert_issuer_common::evidence::is_record_type(&record_type)
                        || fields.contains_key("type")
                ),
            }
        }
    }
}
