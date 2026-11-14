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

//! An evidence record, signed with the pod's signing key (docs/architecture/key-custody.md, "Workload signing keys"). The
//! key is the custody daemon's, in its signer slot: made there, never leaving it, never escrowed, gone with the pod. The
//! crypto actor makes the record's signing input, in the evidence domain, and signs only a record of a type the slot's
//! certificate names (`c:record-evidence:<type>`); the daemon signs what it is given. A reader holds every record to its
//! signer's certificate as well, so a record signed outside its types is refused where it is read.
//!
//! Where custody holds no signing key for the agent, it has a [`RecordKey`] instead: a key file of its own, which the
//! crypto actor makes once and holds, certified in the same way and signing in the same way (docs/plans/crypto-actor.md;
//! the credentials agent's, which comes up before anything could fetch it a custody signing key).

use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use polar_custody::client::{ClientError, CustodyClient};
use polar_custody::protocol::Slot;
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

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

/// `record` signed with the signer slot's key, as the evidence document it is: refused unless the slot's certificate
/// names its type; signed in the evidence domain, as `polar-signing` reads it; the signature in its fixed form, with the
/// slot's chain.
pub(crate) fn sign_record(
    client: &CustodyClient,
    record: &EvidenceRecord,
) -> Result<polar_signing::Document, SignError> {
    let not_signed = |e: ClientError| match e {
        ClientError::Refused(refusal) => SignError::Refused(refusal.to_string()),
        other => SignError::Unavailable(other.to_string()),
    };
    let chain = client.certificate(Slot::Signer).map_err(not_signed)?;
    document(record, chain, |input| {
        let der = client.sign(Slot::Signer, input).map_err(not_signed)?;
        p256::ecdsa::Signature::from_der(&der)
            .map_err(|e| SignError::Unavailable(format!("not a signature: {e}")))
    })
}

/// `record` as the evidence document signed by `sign` (over its signing input, in the evidence domain) under `chain`:
/// refused unless the chain's leaf names its type.
fn document(
    record: &EvidenceRecord,
    chain: Vec<String>,
    sign: impl FnOnce(&[u8]) -> Result<p256::ecdsa::Signature, SignError>,
) -> Result<polar_signing::Document, SignError> {
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
    let fixed = sign(&input)?.to_bytes().to_vec();
    Ok(polar_signing::Document {
        payload: record.payload.clone(),
        signature: polar_signing::SignatureBlock {
            algorithm: polar_signing::Algorithm::EcdsaP256Sha256,
            value: fixed,
            certificate_chain: chain,
        },
    })
}

/// The agent's own record key, where custody holds no signing key for it (`environment::RECORD_KEY`): made once at its
/// path and never replaced, as a checkpoint key is ([`crate::checkpoints::load_or_make_key`]); its certificate kept
/// beside it. It signs nothing until it is certified, and then only the record types its certificate names.
pub struct RecordKey {
    path: PathBuf,
    identity: String,
    key: p256::ecdsa::SigningKey,
    key_pem: Zeroizing<String>,
    public_der: Vec<u8>,
    /// The certificate and its CA chain, one PEM each, and when it expires (Unix seconds).
    certificate: Option<(Vec<String>, i64)>,
}

impl RecordKey {
    /// The key at `path` (made there if it is not), as `identity`'s, with the certificate kept beside it when it is this
    /// key's.
    pub fn open(path: &Path, identity: &str) -> Result<Self, String> {
        let key = crate::checkpoints::load_or_make_key(path)?;
        let key_pem = Zeroizing::new(
            key.to_pkcs8_pem(LineEnding::LF)
                .map_err(|e| format!("the record key does not encode: {e}"))?
                .to_string(),
        );
        let public_der = key
            .verifying_key()
            .to_public_key_der()
            .map_err(|e| format!("the record key's public half does not encode: {e}"))?
            .as_bytes()
            .to_vec();
        let mut opened = Self {
            path: path.to_path_buf(),
            identity: identity.to_string(),
            key,
            key_pem,
            public_der,
            certificate: None,
        };
        if let Ok(chain) = std::fs::read_to_string(crate::checkpoints::chain_path(path)) {
            opened.certificate = opened.certifies(&chain);
        }
        Ok(opened)
    }

    /// A CSR for the key, naming the agent's identity; the record types are the certificate's, as the issuer names them.
    pub fn csr(&self) -> Result<String, String> {
        cert_issuer_common::keypair::csr_for_private_key_pem(&self.identity, &[], &self.key_pem)
            .map_err(|e| format!("the record key's CSR: {e}"))
    }

    /// When its certificate expires, in Unix seconds, once it has one.
    pub fn expires_at(&self) -> Option<i64> {
        self.certificate.as_ref().map(|(_, at)| *at)
    }

    /// Takes `chain` (the certificate, then its CA chain) as the key's certificate if it is this key's, for this agent,
    /// naming the record types it may sign, and keeps it beside the key: when it expires. Otherwise refuses it, and
    /// keeps what it had.
    pub fn keep_certificate(&mut self, chain: &str) -> Result<i64, String> {
        let Some(certified) = self.certifies(chain) else {
            return Err(
                "the certificate is not this record key's, for this agent, naming the record types it signs"
                    .to_string(),
            );
        };
        let path = crate::checkpoints::chain_path(&self.path);
        let staged = path.with_extension("pem.new");
        std::fs::write(&staged, chain)
            .and_then(|()| std::fs::rename(&staged, &path))
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let expires = certified.1;
        self.certificate = Some(certified);
        Ok(expires)
    }

    /// `record` signed with the key, as the evidence document it is: refused unless its certificate names the type.
    pub fn sign(&self, record: &EvidenceRecord) -> Result<polar_signing::Document, SignError> {
        let Some((chain, _)) = &self.certificate else {
            return Err(SignError::Unavailable(
                "the record key is not certified yet".to_string(),
            ));
        };
        document(record, chain.clone(), |input| {
            use p256::ecdsa::signature::Signer as _;
            Ok(self.key.sign(input))
        })
    }

    /// The certificates in `chain` and when the first expires, when it is a certificate of this key naming this agent
    /// and record types, and not any record type: a workload signs its own kinds of record.
    fn certifies(&self, chain: &str) -> Option<(Vec<String>, i64)> {
        use cert_issuer_common::evidence::{MayRecord, may_record};
        let certificates: Vec<String> = chain
            .split_inclusive("-----END CERTIFICATE-----")
            .map(str::trim_start)
            .filter(|pem| pem.starts_with("-----BEGIN CERTIFICATE-----"))
            .map(|pem| format!("{pem}\n"))
            .collect();
        let first = certificates.first()?;
        let (_, pem) = x509_parser::pem::parse_x509_pem(first.as_bytes()).ok()?;
        let certificate = pem.parse_x509().ok()?;
        let named = cert_issuer_common::permission::extract_own_identity(first).ok()?;
        let types = matches!(may_record(first).ok()?, MayRecord::Only(_));
        (certificate.public_key().raw == self.public_der.as_slice()
            && named == self.identity
            && types)
            .then(|| {
                let expires = certificate.validity().not_after.timestamp();
                (certificates, expires)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;
    use std::sync::{Arc, RwLock};

    const IDENTITY: &str = "attestation.polar.serviceaccount.cluster.local";

    fn now() -> i64 {
        time::OffsetDateTime::now_utc().unix_timestamp()
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

    /// A client of a daemon on a socket whose signer slot its custodian filled with a certificate naming `names`.
    async fn client_with(names: &[&str]) -> (Arc<CustodyClient>, Ca, tempfile::TempDir) {
        use cert_issuer_common::custody::{CustodyPermission, custodian_identity};
        use polar_custody::custody::{Custody, Roles};
        use polar_custody::protocol::{Reply, Request};
        use polar_custody::server::{Callers, bind, serve};
        use std::os::unix::fs::MetadataExt as _;
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
        let uid = std::fs::metadata(dir.path()).unwrap().uid();
        tokio::spawn(serve(
            listener,
            Arc::new(RwLock::new(custody)),
            Arc::new(Callers {
                installer_uid: uid,
                workload_uids: vec![uid],
            }),
        ));
        (Arc::new(CustodyClient::new(socket)), ca, dir)
    }

    fn fields(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    async fn signed(
        client: &Arc<CustodyClient>,
        record: EvidenceRecord,
    ) -> Result<polar_signing::Document, SignError> {
        let client = client.clone();
        tokio::task::spawn_blocking(move || sign_record(&client, &record))
            .await
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_record_signed_verifies_as_evidence_in_the_pod_s_name_and_as_nothing_else() {
        let (client, ca, _dir) = client_with(&["c:record-evidence:attestation"]).await;
        let record =
            EvidenceRecord::new("attestation", fields(json!({ "subject": { "pod": "p" } })))
                .unwrap();
        let document = signed(&client, record.clone()).await.unwrap();
        assert_eq!(&document.payload, record.payload());
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
        // A type the certificate does not name is refused before the daemon is asked.
        let other = EvidenceRecord::new("projection-test", Map::new()).unwrap();
        assert!(matches!(
            signed(&client, other).await,
            Err(SignError::Refused(why)) if why.contains("projection-test")
        ));
    }

    /// What cert-issuer signs for the credentials agent's record key: its own identity's documentSigning certificate,
    /// naming the record types in `names`.
    fn certify_record_key(ca: &Ca, key: &RecordKey, names: &[&str]) -> String {
        let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        certify(ca, &key.csr().unwrap(), &names)
    }

    /// docs/plans/crypto-actor.md: a key of the agent's own, held by the crypto actor where custody holds none for it,
    /// signs nothing until it is certified, and then only the record types its certificate names, as a pod's does.
    #[test]
    fn a_record_key_signs_only_once_certified_and_only_the_types_it_is_certified_for() {
        let ca = ca();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record-key.pem");
        let mut key = RecordKey::open(&path, IDENTITY).unwrap();
        let revocation = || EvidenceRecord::new("revocation", Map::new()).unwrap();
        assert!(matches!(
            key.sign(&revocation()),
            Err(SignError::Unavailable(why)) if why.contains("not certified")
        ));
        let chain = certify_record_key(&ca, &key, &["c:record-evidence:revocation"]);
        let expires = key.keep_certificate(&chain).unwrap();
        assert_eq!(key.expires_at(), Some(expires));
        let document = key.sign(&revocation()).unwrap();
        let trust = polar_signing::Trust::from_pem(std::slice::from_ref(&ca.pem)).unwrap();
        let who = polar_signing::verify_in(
            polar_signing::Domain::EVIDENCE_RECORD,
            &document,
            &trust,
            now(),
        )
        .unwrap();
        assert_eq!(who.identity.as_deref(), Some(IDENTITY));
        assert!(matches!(
            key.sign(&EvidenceRecord::new("attestation", Map::new()).unwrap()),
            Err(SignError::Refused(why)) if why.contains("attestation")
        ));
        // Opened again, it is the same key, with the certificate kept beside it.
        let again = RecordKey::open(&path, IDENTITY).unwrap();
        assert_eq!(again.expires_at(), Some(expires));
        let document = again.sign(&revocation()).unwrap();
        assert!(
            polar_signing::verify_in(
                polar_signing::Domain::EVIDENCE_RECORD,
                &document,
                &trust,
                now()
            )
            .is_ok()
        );
    }

    /// A certificate is taken only when it is this key's, for this agent, naming record types it may sign and not the
    /// bare name, which would let it sign any; what it had is kept.
    #[test]
    fn a_record_key_takes_only_its_own_certificate_naming_its_types() {
        let ca = ca();
        let dir = tempfile::tempdir().unwrap();
        let mut key = RecordKey::open(&dir.path().join("record-key.pem"), IDENTITY).unwrap();
        let other = RecordKey::open(&dir.path().join("other.pem"), IDENTITY).unwrap();
        let someone_else = RecordKey::open(
            &dir.path().join("else.pem"),
            "x.polar.serviceaccount.cluster.local",
        )
        .unwrap();
        for (refused, why) in [
            (
                certify_record_key(&ca, &other, &["c:record-evidence:revocation"]),
                "another key's",
            ),
            (certify_record_key(&ca, &key, &[]), "no record type"),
            (
                certify_record_key(&ca, &key, &["c:record-evidence"]),
                "any record type",
            ),
            ("not a certificate".to_string(), "not a certificate"),
        ] {
            assert!(key.keep_certificate(&refused).is_err(), "{why}");
            assert_eq!(key.expires_at(), None, "{why}");
        }
        let mut renamed = RecordKey::open(&dir.path().join("else.pem"), IDENTITY).unwrap();
        let theirs = certify_record_key(&ca, &someone_else, &["c:record-evidence:revocation"]);
        assert!(
            renamed.keep_certificate(&theirs).is_err(),
            "another identity's"
        );
    }

    /// The crypto actor holds the record key: the domain gets a CSR for it, hands back the certificate, and has records
    /// signed with it, with no custody daemon at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_crypto_actor_holds_the_record_key_certifies_it_through_the_domain_and_signs_with_it()
     {
        let ca = ca();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state/record-key.pem");
        let probe = RecordKey::open(&dir.path().join("probe.pem"), IDENTITY).unwrap();
        let own = dir.path().join("cert.pem");
        std::fs::write(&own, certify_record_key(&ca, &probe, &[])).unwrap();
        let (router, _) = ractor::Actor::spawn(None, polar_router::RouterActor, ())
            .await
            .unwrap();
        let (tcp_client, _) = ractor::Actor::spawn(None, Subscriptions(Default::default()), ())
            .await
            .unwrap();
        let (actor, _) = ractor::Actor::spawn(
            None,
            crate::CryptoActor,
            crate::CryptoActorArgs::new(tcp_client, router).with_settings(
                crate::environment::CryptoSettings {
                    own_certificate_path: own.to_string_lossy().into_owned(),
                    key_files: crate::environment::KeyFiles {
                        record: Some(path.to_string_lossy().into_owned()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
        )
        .await
        .unwrap();
        let sign = || async {
            ractor::call!(actor, |reply| crate::CryptoMessage::SignRecord {
                record: EvidenceRecord::new("revocation", Map::new()).unwrap(),
                reply
            })
            .unwrap()
        };
        assert!(matches!(sign().await, Err(SignError::Unavailable(_))));
        let csr = ractor::call!(actor, |reply| crate::CryptoMessage::RecordKeyCsr { reply })
            .unwrap()
            .unwrap();
        let names = vec!["c:record-evidence:revocation".to_string()];
        let chain = certify(&ca, &csr, &names);
        ractor::call!(actor, |reply| crate::CryptoMessage::KeepRecordCertificate {
            chain,
            reply
        })
        .unwrap()
        .unwrap();
        let document = sign().await.unwrap();
        let trust = polar_signing::Trust::from_pem(std::slice::from_ref(&ca.pem)).unwrap();
        assert!(
            polar_signing::verify_in(
                polar_signing::Domain::EVIDENCE_RECORD,
                &document,
                &trust,
                now()
            )
            .is_ok()
        );
        assert!(path.exists());
        actor.stop(None);
    }

    /// Stands in for the agent's Cassini client, keeping what it is asked to subscribe to.
    struct Subscriptions(Arc<std::sync::Mutex<Vec<String>>>);

    #[ractor::async_trait]
    impl ractor::Actor for Subscriptions {
        type Msg = cassini_client::TcpClientMessage;
        type State = ();
        type Arguments = ();

        async fn pre_start(
            &self,
            _: ractor::ActorRef<Self::Msg>,
            _: (),
        ) -> Result<(), ractor::ActorProcessingErr> {
            Ok(())
        }

        async fn handle(
            &self,
            _: ractor::ActorRef<Self::Msg>,
            message: Self::Msg,
            _: &mut (),
        ) -> Result<(), ractor::ActorProcessingErr> {
            if let cassini_client::TcpClientMessage::Subscribe { topic, .. } = message {
                self.0.lock().unwrap().push(topic);
            }
            Ok(())
        }
    }

    /// The crypto actor of an agent that signs records (`escrow` false) or also escrows secrets, beside the daemon
    /// `client` reaches, and what it subscribed to once its Cassini client registered.
    async fn actor_signing_with(
        client: &CustodyClient,
        ca: &Ca,
        dir: &tempfile::TempDir,
        escrow: bool,
    ) -> (ractor::ActorRef<crate::CryptoMessage>, Vec<String>) {
        let own = dir.path().join("cert.pem");
        std::fs::write(&own, &client.certificate(Slot::Signer).unwrap()[0]).unwrap();
        let ca_file = dir.path().join("ca.pem");
        std::fs::write(&ca_file, &ca.pem).unwrap();
        let subscribed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (tcp_client, _) = ractor::Actor::spawn(None, Subscriptions(subscribed.clone()), ())
            .await
            .unwrap();
        let (router, _) = ractor::Actor::spawn(None, polar_router::RouterActor, ())
            .await
            .unwrap();
        let (actor, _) = ractor::Actor::spawn(
            None,
            crate::CryptoActor,
            crate::CryptoActorArgs::new(tcp_client, router)
                .with_settings(crate::environment::CryptoSettings {
                    own_certificate_path: own.to_string_lossy().into_owned(),
                    custody_socket: Some(
                        dir.path()
                            .join("custody.sock")
                            .to_string_lossy()
                            .into_owned(),
                    ),
                    ca_cert_path: ca_file.to_string_lossy().into_owned(),
                    ..Default::default()
                })
                .with_escrow(escrow),
        )
        .await
        .unwrap();
        actor.cast(crate::CryptoMessage::ClientRegistered).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let topics = subscribed.lock().unwrap().clone();
        (actor, topics)
    }

    /// The crypto actor signs a record for the domain's signer handle; an agent that only signs asks the credentials
    /// agent nothing, and one that also escrows hears its replies.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_crypto_actor_signs_records_and_an_agent_that_only_signs_hears_no_escrow_replies() {
        let (client, ca, dir) = client_with(&["c:record-evidence:attestation"]).await;
        let (actor, topics) = actor_signing_with(&client, &ca, &dir, false).await;
        assert!(topics.is_empty(), "{topics:?}");
        let record = EvidenceRecord::new("attestation", Map::new()).unwrap();
        let document = ractor::call!(actor, |reply| crate::CryptoMessage::SignRecord {
            record,
            reply
        })
        .unwrap()
        .unwrap();
        let trust = polar_signing::Trust::from_pem(std::slice::from_ref(&ca.pem)).unwrap();
        assert!(
            polar_signing::verify_in(
                polar_signing::Domain::EVIDENCE_RECORD,
                &document,
                &trust,
                now()
            )
            .is_ok()
        );
        actor.stop(None);
        let (actor, topics) = actor_signing_with(&client, &ca, &dir, true).await;
        assert_eq!(topics.len(), crate::REPLY_TOPICS.len(), "{topics:?}");
        actor.stop(None);
    }

    /// The crypto actor starts before the agent's Cassini client: until it is given the client, what needs the credentials
    /// agent is answered NotConnected and nothing is subscribed; once given it, it subscribes when the client registers.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_crypto_actor_started_before_cassini_is_connected_later() {
        let (actor, _) = ractor::Actor::spawn(
            None,
            crate::CryptoActor,
            crate::CryptoActorArgs::unconnected().with_settings(
                crate::environment::CryptoSettings {
                    own_certificate_path: String::new(),
                    custody_socket: None,
                    ca_cert_path: String::new(),
                    ..Default::default()
                },
            ),
        )
        .await
        .unwrap();
        let retrieved = ractor::call!(actor, |reply| crate::CryptoMessage::RetrieveSecret {
            name: "x".to_string(),
            reply
        })
        .unwrap();
        assert!(
            matches!(retrieved, Err(crate::CryptoError::NotConnected)),
            "{retrieved:?}"
        );
        actor.cast(crate::CryptoMessage::ClientRegistered).unwrap();

        let subscribed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (tcp_client, _) = ractor::Actor::spawn(None, Subscriptions(subscribed.clone()), ())
            .await
            .unwrap();
        let (router, _) = ractor::Actor::spawn(None, polar_router::RouterActor, ())
            .await
            .unwrap();
        actor
            .cast(crate::CryptoMessage::Connect { tcp_client, router })
            .unwrap();
        actor.cast(crate::CryptoMessage::ClientRegistered).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(subscribed.lock().unwrap().len(), crate::REPLY_TOPICS.len());
        actor.stop(None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn with_no_daemon_a_record_is_unavailable() {
        let client = Arc::new(CustodyClient::new("/nonexistent/custody.sock"));
        let record = EvidenceRecord::new("attestation", Map::new()).unwrap();
        assert!(matches!(
            signed(&client, record).await,
            Err(SignError::Unavailable(_))
        ));
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
