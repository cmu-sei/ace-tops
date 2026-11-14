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

//! The daemon's own TLS configuration, its custodian's session's, signed in process with TLS 1.3 alone; and a daemon
//! that does not answer fails a signature in time rather than holding a handshake. A workload's TLS configurations are
//! the crypto actor's, and are tested there (polar-crypto's `tls`; docs/plans/crypto-actor.md).

mod common;

use common::*;
use polar_custody::client::CustodyClient;
use polar_custody::protocol::Slot;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::version::{TLS12, TLS13};
use rustls::{RootCertStore, SupportedProtocolVersion};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

fn roots(ca: &TestCa) -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(ca.pem.as_bytes()).unwrap())
        .unwrap();
    Arc::new(roots)
}

/// A server under `ca` for one connection, demanding a client certificate from it and speaking only `versions`: the
/// name on the client's certificate, or why the handshake failed.
async fn server(
    ca: &TestCa,
    versions: &[&'static SupportedProtocolVersion],
) -> (SocketAddr, JoinHandle<Result<String, String>>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let certificate = params.signed_by(&key, &ca.issuer).unwrap();
    let config = rustls::ServerConfig::builder_with_protocol_versions(versions)
        .with_client_cert_verifier(
            rustls::server::WebPkiClientVerifier::builder(roots(ca))
                .build()
                .unwrap(),
        )
        .with_single_cert(
            vec![certificate.der().clone()],
            PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes()).unwrap(),
        )
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let seen = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.map_err(|e| e.to_string())?;
        let (_, connection) = tls.get_ref();
        let peer = connection
            .peer_certificates()
            .ok_or("no client certificate")?;
        Ok(first_dns_name(peer[0].as_ref()))
    });
    (address, seen)
}

async fn connect(config: rustls::ClientConfig, address: SocketAddr) -> Result<(), String> {
    let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[test]
fn a_daemon_that_does_not_answer_fails_the_signature_in_time() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("silent.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    // Accepts, reads nothing, answers nothing, and keeps the connection open.
    let held = std::thread::spawn(move || listener.accept().map(|(stream, _)| stream));
    let client = CustodyClient::new(&path).with_timeout(Duration::from_millis(200));
    let started = Instant::now();
    assert!(client.sign(Slot::Client, b"anything").is_err());
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "took {:?}",
        started.elapsed()
    );
    drop(held.join());
}

/// A custody in this process, its client slot holding a certificate from `ca`: what the daemon holds once polar-init
/// has installed it.
fn custody_installed(
    ca: &TestCa,
) -> (
    Arc<std::sync::RwLock<polar_custody::custody::Custody>>,
    String,
) {
    use polar_custody::custody::{Custody, Roles};
    use polar_custody::protocol::{Reply, Request};
    let mut custody = Custody::new(&ca.pem).unwrap();
    let installer = Roles {
        installer: true,
        workload: false,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // The daemon's own connection is its custodian's, `custody.<X>`.
    let Reply::Csr(csr) = custody.handle(
        installer,
        Request::MakeCsr {
            slot: Slot::Custodian,
            identity: cert_issuer_common::custody::custodian_identity(IDENTITY),
            names: vec![],
        },
        now,
    ) else {
        panic!("a CSR");
    };
    let certificate = certify(ca, &csr);
    assert_eq!(
        custody.handle(
            installer,
            Request::Install {
                slot: Slot::Custodian,
                chain_pem: vec![certificate.clone()],
            },
            now,
        ),
        Reply::Installed
    );
    (Arc::new(std::sync::RwLock::new(custody)), certificate)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_daemon_s_own_handshake_is_signed_in_process_with_tls13_alone() {
    let ca = test_ca();
    let (custody, _) = custody_installed(&ca);
    let config = polar_custody::own::own_client_config(custody, &ca.pem).unwrap();
    let (address, seen) = server(&ca, &[&TLS13]).await;
    connect(config.clone(), address)
        .await
        .expect("the handshake");
    assert_eq!(
        seen.await.unwrap().unwrap(),
        cert_issuer_common::custody::custodian_identity(IDENTITY)
    );
    let (address, seen) = server(&ca, &[&TLS12]).await;
    assert!(connect(config, address).await.is_err());
    // Refused because it was never offered, not because the custody then declined to sign a TLS 1.2 handshake.
    let refused = seen.await.unwrap().unwrap_err();
    assert!(
        refused.contains("Tls12NotOfferedOrEnabled"),
        "the daemon's own connection offered TLS 1.2: {refused}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn once_revoked_the_daemon_s_own_handshake_fails() {
    let ca = test_ca();
    let (custody, certificate) = custody_installed(&ca);
    let config = polar_custody::own::own_client_config(custody.clone(), &ca.pem).unwrap();
    let serial = cert_issuer_common::serial::serial_from_pem(&certificate).unwrap();
    custody.write().unwrap().revoke(&[serial]);
    let (address, seen) = server(&ca, &[&TLS13]).await;
    assert!(connect(config, address).await.is_err());
    assert!(seen.await.unwrap().is_err(), "no certificate seen signed");
}

#[test]
fn the_daemon_s_own_configuration_needs_a_certificate_installed() {
    let ca = test_ca();
    let custody = Arc::new(std::sync::RwLock::new(
        polar_custody::custody::Custody::new(&ca.pem).unwrap(),
    ));
    assert!(polar_custody::own::own_client_config(custody, &ca.pem).is_err());
}
