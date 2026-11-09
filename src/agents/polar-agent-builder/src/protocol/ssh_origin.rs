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

//! An ssh server for the git handler's tests: it serves one repository to `git-upload-pack` as a git server over ssh does
//! (the refs, then a pack once the client says it is done), takes one client key for the user `git`, and records every
//! connection and every key it is offered, so a test can say that no key reached a server whose host key was not the one
//! pinned, and that a fetch refused before it went out never connected.

use super::testing::{pack_reply, refs_advertised};
use git2::Repository;
use russh::keys::ssh_key::LineEnding;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{HashAlg, PrivateKey, PublicKey};
use russh::server::{
    Auth, ChannelOpenHandle, Config, Handler, Msg, PublicKeyOffer, Server, Session,
    VerifiedPublicKey,
};
use russh::{Channel, ChannelId};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;

/// An Ed25519 key made from `seed`, so a test's keys are the same every run.
pub(crate) fn key(seed: u8) -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
}

/// A private key as `ssh-keygen` writes it, as a credential holds it.
pub(crate) fn openssh(key: &PrivateKey) -> String {
    key.to_openssh(LineEnding::LF).unwrap().to_string()
}

/// A key's fingerprint as `ssh-keygen -l` writes it, as a binding pins it.
pub(crate) fn fingerprint(key: &PrivateKey) -> String {
    key.public_key().fingerprint(HashAlg::Sha256).to_string()
}

/// What the server saw.
#[derive(Debug, Default, Clone)]
pub(crate) struct Seen {
    pub(crate) connections: usize,
    /// Each key a client offered, by its fingerprint.
    pub(crate) offered: Vec<String>,
    /// Each command a client ran.
    pub(crate) commands: Vec<String>,
}

/// The server, serving the repository at a directory on a port of its own.
pub(crate) struct SshOrigin {
    port: u16,
    seen: Arc<Mutex<Seen>>,
    _serving: tokio::task::JoinHandle<()>,
}

impl SshOrigin {
    /// Serves the repository at `directory`, showing `host` as its host key and letting in only `client`, as `git`.
    pub(crate) async fn serving(directory: &Path, host: PrivateKey, client: PublicKey) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let config = Arc::new(Config {
            keys: vec![host],
            auth_rejection_time: Duration::from_millis(10),
            auth_rejection_time_initial: Some(Duration::ZERO),
            inactivity_timeout: Some(Duration::from_secs(30)),
            ..Default::default()
        });
        let mut origin = Origin {
            directory: directory.to_path_buf(),
            client,
            seen: seen.clone(),
        };
        let serving = tokio::spawn(async move {
            let _ = origin.run_on_socket(config, &listener).await;
        });
        Self {
            port,
            seen,
            _serving: serving,
        }
    }

    /// Its address, with no login in it.
    pub(crate) fn url(&self) -> String {
        format!("ssh://127.0.0.1:{}/r.git", self.port)
    }

    /// The same, by a name that resolves to it.
    pub(crate) fn url_by_name(&self) -> String {
        format!("ssh://localhost:{}/r.git", self.port)
    }

    pub(crate) fn seen(&self) -> Seen {
        self.seen.lock().unwrap().clone()
    }
}

struct Origin {
    directory: PathBuf,
    client: PublicKey,
    seen: Arc<Mutex<Seen>>,
}

impl Server for Origin {
    type Handler = Connection;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Connection {
        self.seen.lock().unwrap().connections += 1;
        Connection {
            directory: self.directory.clone(),
            client: self.client.clone(),
            seen: self.seen.clone(),
            asked: Vec::new(),
        }
    }
}

struct Connection {
    directory: PathBuf,
    client: PublicKey,
    seen: Arc<Mutex<Seen>>,
    /// What the client has said on the channel so far.
    asked: Vec<u8>,
}

impl Handler for Connection {
    type Error = russh::Error;

    async fn auth_publickey_offered(
        &mut self,
        _: &str,
        offer: PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        let offered = offer.public_key.fingerprint(HashAlg::Sha256).to_string();
        self.seen.lock().unwrap().offered.push(offered);
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(if user == "git" && *key.public_key == self.client {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        _: Channel<Msg>,
        reply: ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).to_string();
        self.seen.lock().unwrap().commands.push(command.clone());
        if !command.starts_with("git-upload-pack ") {
            session.channel_failure(channel)?;
            return Ok(());
        }
        session.channel_success(channel)?;
        let repository = Repository::open(&self.directory).expect("the origin's repository");
        session.data(
            channel,
            refs_advertised(&repository).expect("the origin's refs"),
        )?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.asked.extend_from_slice(data);
        // A client that is up to date says only a flush; one that wants something ends what it says with `done`.
        let done = self.asked.ends_with(b"0009done\n");
        if done || self.asked == b"0000" {
            if done {
                let repository =
                    Repository::open(&self.directory).expect("the origin's repository");
                session.data(channel, pack_reply(&repository).expect("the origin's pack"))?;
            }
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
        }
        Ok(())
    }
}
