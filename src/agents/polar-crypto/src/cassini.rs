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

//! A Cassini client's TLS, from the crypto actor (docs/plans/crypto-actor.md). A Cassini client never reads a key or
//! makes its own TLS: the agent builder asks its agent's crypto actor through here, and a process that is not a builder
//! agent (a command-line tool, the client daemon, cassini-c2) starts a crypto actor of its own with [`standalone`] and
//! asks it the same way.

use crate::{CryptoActor, CryptoActorArgs, CryptoMessage, environment::CryptoSettings};
use cassini_client::{CassiniSettings, TCPClientConfig};
use ractor::{Actor, ActorRef};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;
use std::sync::Arc;

/// The client configuration `crypto` makes for the broker, whose certificate is verified against the CA at `ca_path`.
pub async fn client_tls(
    crypto: &ActorRef<CryptoMessage>,
    ca_path: &str,
) -> Result<rustls::ClientConfig, String> {
    // Another component may have installed it already.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_file_iter(ca_path)
        .map_err(|e| format!("reading the CA from {ca_path}: {e}"))?
    {
        let certificate = certificate.map_err(|e| format!("reading the CA from {ca_path}: {e}"))?;
        roots
            .add(certificate)
            .map_err(|e| format!("the CA at {ca_path}: {e}"))?;
    }
    let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| format!("the broker's verifier: {e}"))?;
    ractor::call!(crypto, |reply| CryptoMessage::ClientTls { verifier, reply })
        .map_err(|e| format!("the crypto actor did not answer: {e}"))?
        .map_err(|e| format!("the Cassini client's TLS: {e}"))
}

/// The client's configuration for `settings`, its TLS made by `crypto`.
pub async fn client_config(
    crypto: &ActorRef<CryptoMessage>,
    settings: &CassiniSettings,
) -> Result<TCPClientConfig, String> {
    let tls = client_tls(crypto, &settings.ca_certificate_path).await?;
    Ok(settings.config(Arc::new(tls)))
}

/// A crypto actor for a process that is not a builder agent, as every process that uses a key has one: unconnected
/// (it asks nothing over Cassini), doing no escrow, its keys the custody daemon's where `env` names its socket and
/// otherwise the key files `env` names. With it, the Cassini client's configuration for what `env` says of the broker.
/// The caller stops the actor when it is done with the client.
pub async fn standalone(
    env: &dyn polar_env::Env,
) -> Result<(ActorRef<CryptoMessage>, TCPClientConfig), String> {
    let settings = CassiniSettings::from_env(env)?;
    let args = CryptoActorArgs::unconnected()
        .with_settings(CryptoSettings::from_env_for(env, false)?)
        .with_escrow(false);
    let (crypto, _) = Actor::spawn(None, CryptoActor, args)
        .await
        .map_err(|e| format!("the crypto actor did not start: {e}"))?;
    match client_config(&crypto, &settings).await {
        Ok(config) => Ok((crypto, config)),
        Err(e) => {
            crypto.stop(None);
            Err(e)
        }
    }
}
