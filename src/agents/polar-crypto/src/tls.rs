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

//! The agent's TLS, from its own keys (docs/plans/crypto-actor.md, step K3): every TLS configuration an agent uses,
//! client or server, is made here, from the key the custody daemon holds for it or, where a cluster runs without the
//! daemon, the key file it was given. What a key signs in a handshake is decided here: the daemon signs what it is
//! given, and this signer gives it TLS 1.3 handshake inputs alone. rustls asks for that signature synchronously, in
//! the middle of the handshake; this signer answers it so, through the daemon's local socket.

use polar_custody::client::CustodyClient;
use polar_custody::protocol::Slot;
use rustls::SignatureAlgorithm;
use rustls::SignatureScheme;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use std::sync::Arc;

/// Where a TLS key is: in the custody daemon's slot, or, without the daemon, a certificate file and a key file.
#[derive(Debug, Clone)]
pub enum KeySource {
    Custody {
        client: Arc<CustodyClient>,
        slot: Slot,
    },
    Files {
        certificate: String,
        key: String,
    },
}

/// A rustls signing key over a custody slot. It signs ECDSA P-256 SHA-256, and only a TLS 1.3 CertificateVerify
/// input: anything else asked of it is refused before the daemon is.
#[derive(Debug, Clone)]
struct SlotSigner {
    client: Arc<CustodyClient>,
    slot: Slot,
}

impl SigningKey for SlotSigner {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| Box::new(self.clone()) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl Signer for SlotSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        if !polar_custody::tls::is_tls13_certificate_verify(message) {
            return Err(rustls::Error::General(
                "a TLS key signs only a TLS 1.3 CertificateVerify input".to_string(),
            ));
        }
        self.client
            .sign(self.slot, message)
            .map_err(|e| rustls::Error::General(format!("the custody daemon did not sign: {e}")))
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

/// The certificate chain and the key `source` names, for a configuration, and whether it is the daemon's (which
/// signs only TLS 1.3, so the configuration offers that alone).
enum Keyed {
    Custody(Arc<CertifiedKey>),
    Files(
        Vec<CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
}

fn keyed(source: &KeySource) -> Result<Keyed, String> {
    match source {
        KeySource::Custody { client, slot } => {
            let chain = client
                .certificate(*slot)
                .map_err(|e| format!("the custody daemon gave no certificate: {e}"))?
                .iter()
                .map(|pem| {
                    CertificateDer::from_pem_slice(pem.as_bytes())
                        .map_err(|e| format!("the custody daemon's certificate does not read: {e}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Keyed::Custody(Arc::new(CertifiedKey::new(
                chain,
                Arc::new(SlotSigner {
                    client: client.clone(),
                    slot: *slot,
                }),
            ))))
        }
        KeySource::Files { certificate, key } => {
            let chain = CertificateDer::pem_file_iter(certificate)
                .and_then(|certificates| certificates.collect::<Result<Vec<_>, _>>())
                .map_err(|e| format!("reading the certificate from {certificate}: {e}"))?;
            let key = rustls::pki_types::PrivateKeyDer::from_pem_file(key)
                .map_err(|e| format!("reading the key from {key}: {e}"))?;
            Ok(Keyed::Files(chain, key))
        }
    }
}

/// A client configuration presenting the key `source` names, verifying the server with `verifier`.
pub fn client_config(
    verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    source: &KeySource,
) -> Result<rustls::ClientConfig, String> {
    Ok(match keyed(source)? {
        Keyed::Custody(key) => {
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_client_cert_resolver(Arc::new(Presents(key)))
        }
        Keyed::Files(chain, key) => rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(chain, key)
            .map_err(|e| format!("the client configuration: {e}"))?,
    })
}

/// A server configuration presenting the key `source` names, verifying clients with `verifier`, offering `alpn`.
pub fn server_config(
    verifier: Arc<dyn rustls::server::danger::ClientCertVerifier>,
    alpn: Vec<Vec<u8>>,
    source: &KeySource,
) -> Result<rustls::ServerConfig, String> {
    let mut config = match keyed(source)? {
        Keyed::Custody(key) => {
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_client_cert_verifier(verifier)
                .with_cert_resolver(Arc::new(Presents(key)))
        }
        Keyed::Files(chain, key) => rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)
            .map_err(|e| format!("the server configuration: {e}"))?,
    };
    config.alpn_protocols = alpn;
    Ok(config)
}

/// Presents one certificate and key, to every peer that asks.
#[derive(Debug)]
struct Presents(Arc<CertifiedKey>);

impl rustls::client::ResolvesClientCert for Presents {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

impl rustls::server::ResolvesServerCert for Presents {
    fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_custody::custody::{Custody, Roles};
    use polar_custody::protocol::{Reply, Request};
    use polar_custody::server::{Callers, bind, serve};
    use rustls::pki_types::ServerName;
    use std::os::unix::fs::MetadataExt as _;
    use std::sync::RwLock;

    const IDENTITY: &str = "agent.polar.serviceaccount.cluster.local";
    const SERVER_NAME: &str = "agent.polar.svc";

    struct Ca {
        issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
        pem: String,
    }

    fn ca() -> Ca {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test CA");
        let key = rcgen::KeyPair::generate().unwrap();
        let pem = params.self_signed(&key).unwrap().pem();
        Ca {
            issuer: rcgen::Issuer::new(params, key),
            pem,
        }
    }

    fn now() -> i64 {
        time::OffsetDateTime::now_utc().unix_timestamp()
    }

    /// What cert-issuer signs: the identity first, then `names`, for `eku`.
    fn certify(
        ca: &Ca,
        csr_pem: &str,
        names: &[&str],
        eku: rcgen::ExtendedKeyUsagePurpose,
    ) -> String {
        let mut csr = rcgen::CertificateSigningRequestParams::from_pem(csr_pem).unwrap();
        for name in names {
            csr.params
                .subject_alt_names
                .push(rcgen::SanType::DnsName((*name).try_into().unwrap()));
        }
        let at = time::OffsetDateTime::now_utc();
        csr.params.not_before = at - time::Duration::minutes(1);
        csr.params.not_after = at + time::Duration::hours(1);
        csr.params.extended_key_usages = vec![eku];
        csr.signed_by(&ca.issuer).unwrap().pem()
    }

    /// A daemon on a socket holding a client key and a server key, each certified by `ca`.
    async fn daemon(ca: &Ca) -> (Arc<CustodyClient>, tempfile::TempDir) {
        let mut custody = Custody::new(&ca.pem).unwrap();
        let installer = Roles {
            installer: true,
            workload: false,
        };
        for (slot, names, eku) in [
            (
                Slot::Client,
                vec![],
                rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            ),
            (
                Slot::Server,
                vec![SERVER_NAME],
                rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            ),
        ] {
            let Reply::Csr(csr) = custody.handle(
                installer,
                Request::MakeCsr {
                    slot,
                    identity: IDENTITY.to_string(),
                    names: names.iter().map(|n| n.to_string()).collect(),
                },
                now(),
            ) else {
                panic!("a CSR")
            };
            let certificate = certify(ca, &csr, &names, eku);
            assert_eq!(
                custody.handle(
                    installer,
                    Request::Install {
                        slot,
                        chain_pem: vec![certificate]
                    },
                    now()
                ),
                Reply::Installed
            );
        }
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
        (Arc::new(CustodyClient::new(socket)), dir)
    }

    fn roots(ca: &Ca) -> Arc<rustls::RootCertStore> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(ca.pem.as_bytes()).unwrap())
            .unwrap();
        Arc::new(roots)
    }

    /// A handshake between `client` and `server` in memory, and the ALPN protocol they agreed, or why it failed.
    fn handshake(
        client: rustls::ClientConfig,
        server: rustls::ServerConfig,
    ) -> Result<Option<Vec<u8>>, rustls::Error> {
        let mut client = rustls::ClientConnection::new(
            Arc::new(client),
            ServerName::try_from(SERVER_NAME).unwrap(),
        )?;
        let mut server = rustls::ServerConnection::new(Arc::new(server))?;
        for _ in 0..20 {
            let mut buffer = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut buffer).unwrap();
            }
            server.read_tls(&mut buffer.as_slice()).unwrap();
            server.process_new_packets()?;
            let mut buffer = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut buffer).unwrap();
            }
            client.read_tls(&mut buffer.as_slice()).unwrap();
            client.process_new_packets()?;
            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(server.alpn_protocol().map(<[u8]>::to_vec));
            }
        }
        panic!("the handshake did not end")
    }

    fn verifiers(
        ca: &Ca,
    ) -> (
        Arc<rustls::client::WebPkiServerVerifier>,
        Arc<dyn rustls::server::danger::ClientCertVerifier>,
    ) {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        (
            rustls::client::WebPkiServerVerifier::builder_with_provider(
                roots(ca),
                provider.clone(),
            )
            .build()
            .unwrap(),
            rustls::server::WebPkiClientVerifier::builder_with_provider(roots(ca), provider)
                .build()
                .unwrap(),
        )
    }

    /// Both ends keyed by the daemon: a mutual handshake completes over TLS 1.3, the server offering what its caller
    /// asked, and each key signing through the daemon.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_client_and_a_server_keyed_by_the_daemon_shake_hands() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = ca();
        let (custody, _dir) = daemon(&ca).await;
        let (to_server, to_client) = verifiers(&ca);
        let configs = tokio::task::spawn_blocking(move || {
            let client = client_config(
                to_server,
                &KeySource::Custody {
                    client: custody.clone(),
                    slot: Slot::Client,
                },
            )
            .unwrap();
            let mut client_alpn = client;
            client_alpn.alpn_protocols = vec![b"http/1.1".to_vec()];
            let server = server_config(
                to_client,
                vec![b"http/1.1".to_vec()],
                &KeySource::Custody {
                    client: custody,
                    slot: Slot::Server,
                },
            )
            .unwrap();
            handshake(client_alpn, server)
        })
        .await
        .unwrap();
        assert_eq!(configs.unwrap(), Some(b"http/1.1".to_vec()));
    }

    /// Without the daemon, the key files given: the same handshake.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_client_and_a_server_keyed_by_files_shake_hands() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = ca();
        let dir = tempfile::tempdir().unwrap();
        let files = |name: &str, names: &[&str], eku| {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.subject_alt_names = std::iter::once(IDENTITY)
                .chain(names.iter().copied())
                .map(|n| rcgen::SanType::DnsName(n.try_into().unwrap()))
                .collect();
            params.extended_key_usages = vec![eku];
            let certificate = params.signed_by(&key, &ca.issuer).unwrap().pem();
            let (c, k) = (
                dir.path().join(format!("{name}.pem")),
                dir.path().join(format!("{name}.key")),
            );
            std::fs::write(&c, certificate).unwrap();
            std::fs::write(&k, key.serialize_pem()).unwrap();
            KeySource::Files {
                certificate: c.to_string_lossy().into_owned(),
                key: k.to_string_lossy().into_owned(),
            }
        };
        let client = files("client", &[], rcgen::ExtendedKeyUsagePurpose::ClientAuth);
        let server = files(
            "server",
            &[SERVER_NAME],
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        );
        let (to_server, to_client) = verifiers(&ca);
        let agreed = handshake(
            client_config(to_server, &client).unwrap(),
            server_config(to_client, vec![], &server).unwrap(),
        );
        assert_eq!(agreed.unwrap(), None);
    }

    /// The daemon's key signs a TLS 1.3 CertificateVerify input through this signer, and nothing else: anything else is
    /// refused before the daemon is asked.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_signer_signs_only_a_tls13_handshake_input() {
        let ca = ca();
        let (custody, _dir) = daemon(&ca).await;
        let signer = SlotSigner {
            client: custody,
            slot: Slot::Client,
        };
        tokio::task::spawn_blocking(move || {
            let input = polar_custody::tls::certificate_verify_input(
                polar_custody::tls::CLIENT_CONTEXT,
                &[7; 32],
            );
            assert!(Signer::sign(&signer, &input).is_ok());
            for not_one in [b"a document in the agent's name".to_vec(), vec![0x20; 64]] {
                assert!(Signer::sign(&signer, &not_one).is_err());
            }
        })
        .await
        .unwrap();
    }

    async fn crypto_actor(
        settings: crate::environment::CryptoSettings,
    ) -> ractor::ActorRef<crate::CryptoMessage> {
        let (actor, _) = ractor::Actor::spawn(
            None,
            crate::CryptoActor,
            crate::CryptoActorArgs::unconnected()
                .with_settings(settings)
                .with_escrow(false),
        )
        .await
        .unwrap();
        actor
    }

    /// The crypto actor makes the agent's TLS, client and server, from the daemon's keys, the server offering what its
    /// caller asks; with no daemon and no key files it says it has no key.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_crypto_actor_makes_the_agent_s_tls_from_its_own_keys() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = ca();
        let (_custody, dir) = daemon(&ca).await;
        let actor = crypto_actor(crate::environment::CryptoSettings {
            custody_socket: Some(
                dir.path()
                    .join("custody.sock")
                    .to_string_lossy()
                    .into_owned(),
            ),
            ..Default::default()
        })
        .await;
        let (to_server, to_client) = verifiers(&ca);
        let mut client = ractor::call!(actor, |reply| crate::CryptoMessage::ClientTls {
            verifier: to_server,
            reply
        })
        .unwrap()
        .unwrap();
        client.alpn_protocols = vec![b"h2".to_vec()];
        let server = ractor::call!(actor, |reply| crate::CryptoMessage::ServerTls {
            verifier: to_client,
            alpn: vec![b"h2".to_vec()],
            reply
        })
        .unwrap()
        .unwrap();
        let agreed = tokio::task::spawn_blocking(move || handshake(client, server))
            .await
            .unwrap();
        assert_eq!(agreed.unwrap(), Some(b"h2".to_vec()));
        actor.stop(None);

        let keyless = crypto_actor(crate::environment::CryptoSettings::default()).await;
        let (to_server, _) = verifiers(&ca);
        let refused = ractor::call!(keyless, |reply| crate::CryptoMessage::ClientTls {
            verifier: to_server,
            reply
        })
        .unwrap();
        assert!(
            matches!(&refused, Err(why) if why.contains("no Client key")),
            "{:?}",
            refused.err()
        );
        keyless.stop(None);
    }
}
