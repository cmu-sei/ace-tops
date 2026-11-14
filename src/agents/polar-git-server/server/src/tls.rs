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

//! The mTLS listener. A client certificate is required on every connection, verified against the
//! Polar CA; the peer identity is read from the verified certificate and attached to the
//! connection's requests, and from nothing else (never a header or a body, which the caller
//! controls). Follows Cassini's `listener.rs` and cert-issuer's `tls.rs`, except that there is no
//! `allow_unauthenticated`: an anonymous caller does not get through the handshake.

use crate::http::PeerIdentity;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use polar_agent_builder::crypto::TlsHandle;
use rustls::RootCertStore;
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tracing::{debug, warn};

/// Smart HTTP over HTTP/1.1 is all git needs.
pub fn alpn() -> Vec<Vec<u8>> {
    vec![b"http/1.1".to_vec()]
}

/// Builds the server configuration from the agent's crypto actor, which presents the server's certificate with its key
/// (the custody daemon's server slot, or its files: docs/plans/crypto-actor.md), verifying clients against the CA and
/// the deployment CA.
pub async fn server_config(
    tls: &TlsHandle,
    ca: &Path,
    deployment_ca: Option<&Path>,
) -> Result<Arc<rustls::ServerConfig>, String> {
    Ok(Arc::new(
        tls.server_config(client_verifier(ca, deployment_ca)?, alpn())
            .await?,
    ))
}

/// What a client certificate must chain to: the CA, or the deployment CA.
pub fn client_verifier(
    ca: &Path,
    deployment_ca: Option<&Path>,
) -> Result<Arc<dyn ClientCertVerifier>, String> {
    // Another component may have installed it already.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let read = |p: &Path| std::fs::read(p).map_err(|e| format!("cannot read {}: {e}", p.display()));
    let mut roots = RootCertStore::empty();
    for file in std::iter::once(ca).chain(deployment_ca) {
        for ca in rustls_pemfile::certs(&mut read(file)?.as_slice()) {
            roots
                .add(ca.map_err(|e| format!("bad CA certificate: {e}"))?)
                .map_err(|e| format!("cannot trust the CA certificate: {e}"))?;
        }
    }
    WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| format!("cannot build the client verifier: {e}"))
}

/// What marks an identity as the deployment PKI's: the two CAs' names are kept apart, so that one cannot speak for the other.
pub const DEPLOYMENT_PREFIX: &str = "deployment:";

/// Who a verified client certificate is. A caller is named by its certificate's first DNS name. The server also trusts the deployment CA, for Flux
/// (docs/architecture/cluster-bootstrap.md, "Handing off to Polar's git server"), and that CA's word is good only for names of its own: what it signs is named
/// `deployment:<name>`, which is what an access list must say. A certificate that claims such a name from Polar's CA is no one.
#[derive(Default)]
pub struct ClientIdentities {
    deployment_ca: Option<Vec<u8>>,
}

impl ClientIdentities {
    pub fn new(deployment_ca: Option<&Path>) -> Result<Self, String> {
        let deployment_ca = deployment_ca
            .map(|path| {
                let pem = std::fs::read(path)
                    .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
                rustls_pemfile::certs(&mut pem.as_slice())
                    .next()
                    .ok_or_else(|| format!("{} holds no certificate", path.display()))?
                    .map(|der| der.to_vec())
                    .map_err(|e| format!("bad CA certificate: {e}"))
            })
            .transpose()?;
        Ok(Self { deployment_ca })
    }

    /// The identity of a leaf the TLS layer has verified against one of the two CAs.
    pub fn of(&self, leaf: &[u8]) -> Option<String> {
        use x509_parser::prelude::FromDer;
        let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(leaf).ok()?;
        let name = first_dns_name(&parsed)?;
        let from_deployment = self.deployment_ca.as_deref().is_some_and(|ca| {
            x509_parser::certificate::X509Certificate::from_der(ca).is_ok_and(|(_, ca)| {
                parsed.issuer() == ca.subject()
                    && parsed
                        .verify_signature(Some(&ca.tbs_certificate.subject_pki))
                        .is_ok()
            })
        });
        if from_deployment {
            Some(format!("{DEPLOYMENT_PREFIX}{name}"))
        } else if name.starts_with(DEPLOYMENT_PREFIX) {
            None
        } else {
            Some(name)
        }
    }
}

/// The identity of the client on this connection.
pub fn extract_peer_identity(
    stream: &TlsStream<TcpStream>,
    identities: &ClientIdentities,
) -> Option<String> {
    let (_, connection) = stream.get_ref();
    let leaf = connection.peer_certificates()?.first()?;
    identities.of(leaf.as_ref())
}

/// The first DNS name in a certificate's SANs.
fn first_dns_name(parsed: &x509_parser::certificate::X509Certificate<'_>) -> Option<String> {
    for ext in parsed.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            ext.parsed_extension()
        {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                    return Some(dns.to_string());
                }
            }
        }
    }
    None
}

/// Serves `app` over TLS until `stop` is notified. Each connection that completes the handshake
/// with an identity gets it as a [`PeerIdentity`] extension; one whose certificate carries no
/// identity is dropped, since nothing could authorize it.
pub async fn serve_tls(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    app: axum::Router,
    stop: Arc<Notify>,
    active: Arc<AtomicUsize>,
    identities: Arc<ClientIdentities>,
) {
    loop {
        let (tcp, remote) = tokio::select! {
            _ = stop.notified() => return,
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(e) => {
                    warn!(error = %e, "TCP accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        let guard = Connection::open(&active);
        let identities = identities.clone();
        tokio::spawn(async move {
            let _guard = guard;
            let tls = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(%remote, error = %e, "TLS handshake failed");
                    return;
                }
            };
            let Some(identity) = extract_peer_identity(&tls, &identities) else {
                warn!(%remote, "client certificate carries no identity; connection dropped");
                return;
            };
            let leaf = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .map(|leaf| leaf.as_ref().to_vec())
                .unwrap_or_default();
            let app = app
                .layer(axum::Extension(PeerIdentity(identity)))
                .layer(axum::Extension(crate::http::PeerCertificate(leaf)));
            let service = TowerToHyperService::new(app);
            if let Err(e) = Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), service)
                .await
            {
                debug!(%remote, error = %e, "connection closed with error");
            }
        });
    }
}

/// Counts a connection as in flight until it is dropped, so shutdown can wait for them.
struct Connection(Arc<AtomicUsize>);

impl Connection {
    fn open(active: &Arc<AtomicUsize>) -> Self {
        active.fetch_add(1, Ordering::SeqCst);
        Self(active.clone())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    /// A CA and a client under it, as DER.
    fn issued(ca_name: &str, client: &str) -> (Vec<u8>, Vec<u8>) {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, SanType};
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, ca_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let ca = params.self_signed(&key).unwrap().der().to_vec();
        let issuer = Issuer::new(params, key);
        let mut leaf = CertificateParams::new(Vec::<String>::new()).unwrap();
        leaf.subject_alt_names = vec![SanType::DnsName(client.try_into().unwrap())];
        let leaf_key = KeyPair::generate().unwrap();
        let cert = leaf.signed_by(&leaf_key, &issuer).unwrap().der().to_vec();
        (ca, cert)
    }

    fn with_ca(ca: Vec<u8>) -> ClientIdentities {
        ClientIdentities {
            deployment_ca: Some(ca),
        }
    }

    #[test]
    fn the_deployment_cas_clients_are_named_as_its_own() {
        let (ca, flux) = issued("deploy-ca", "flux");
        assert_eq!(with_ca(ca).of(&flux).as_deref(), Some("deployment:flux"));
    }

    /// A CA that has taken the deployment CA's name is not the deployment CA: its key decides, not its name.
    #[test]
    fn another_key_under_the_deployment_cas_name_speaks_only_for_polar() {
        let (ca, _) = issued("deploy-ca", "flux");
        let (_, impostor) = issued("deploy-ca", "alice");
        assert_eq!(with_ca(ca).of(&impostor).as_deref(), Some("alice"));
    }

    #[test]
    fn polar_cannot_claim_a_deployment_name_and_without_a_deployment_ca_nothing_changes() {
        let (_, posing) = issued("polar-ca", "deployment:flux");
        assert_eq!(ClientIdentities::default().of(&posing), None);
        let (_, alice) = issued("polar-ca", "alice");
        assert_eq!(
            ClientIdentities::default().of(&alice).as_deref(),
            Some("alice")
        );
    }

    use super::*;

    // Smart HTTP over HTTP/1.1, presenting the key the crypto actor holds (docs/plans/crypto-actor.md): here its files.
    #[test]
    fn the_server_speaks_http_1_1() {
        let dir = tempfile::tempdir().unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let (cert_path, key_path, ca_path) = (
            dir.path().join("cert.pem"),
            dir.path().join("key.pem"),
            dir.path().join("ca.pem"),
        );
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key.serialize_pem()).unwrap();
        std::fs::write(&ca_path, cert.pem()).unwrap();
        let config = polar_crypto::tls::server_config(
            client_verifier(&ca_path, None).unwrap(),
            alpn(),
            &polar_crypto::tls::KeySource::Files {
                certificate: cert_path.display().to_string(),
                key: key_path.display().to_string(),
            },
        )
        .unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }
}
