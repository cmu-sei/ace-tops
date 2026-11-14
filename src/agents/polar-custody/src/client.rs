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

//! The workload's side of the daemon (docs/architecture/key-custody.md, "Step 1 in detail"): a blocking client, since
//! rustls calls its signer synchronously in the handshake, with a few connections kept open so that no signature pays
//! for a connection. Its one user in a workload is the crypto actor (docs/plans/crypto-actor.md), which makes every
//! TLS configuration over it and judges what each key signs; polar-init installs through it, and polar-health asks it.

use crate::protocol::{
    Envelope, FrameError, Refusal, Reply, Request, Slot, decode_reply, read_frame, write_frame,
};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// The most idle connections kept.
const IDLE: usize = 8;

/// How long a request may wait on the daemon. rustls signs in the handshake, on whatever thread runs it, so a daemon
/// that never answered would hold that thread for good; a signature takes tens of microseconds.
pub const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("the reply was for another request")]
    Mismatched,
    #[error("refused: {0}")]
    Refused(Refusal),
    #[error("an answer of another kind: {0:?}")]
    Unexpected(Box<Reply>),
    #[error("the daemon's signature is not an ECDSA P-256 one: {0}")]
    NotASignature(String),
}

#[derive(Debug)]
pub struct CustodyClient {
    path: PathBuf,
    idle: Mutex<Vec<UnixStream>>,
    next: AtomicU64,
    timeout: Duration,
}

impl CustodyClient {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            idle: Mutex::new(Vec::new()),
            next: AtomicU64::new(1),
            timeout: TIMEOUT,
        }
    }

    /// This client, waiting `timeout` on each request instead of [`TIMEOUT`].
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn connect(&self) -> std::io::Result<UnixStream> {
        let stream = UnixStream::connect(&self.path)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        Ok(stream)
    }

    /// One request and its reply, on an idle connection or a new one. A connection that fails is dropped.
    pub fn request(&self, body: Request) -> Result<Reply, ClientError> {
        let idle = self.idle.lock().ok().and_then(|mut idle| idle.pop());
        let mut stream = match idle {
            Some(stream) => stream,
            None => self.connect().map_err(FrameError::Io)?,
        };
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        write_frame(&mut stream, &Envelope { id, body })?;
        let reply = decode_reply(&read_frame(&mut stream)?)?;
        if reply.id != id {
            return Err(ClientError::Mismatched);
        }
        if let Ok(mut idle) = self.idle.lock()
            && idle.len() < IDLE
        {
            idle.push(stream);
        }
        Ok(reply.body)
    }

    pub fn make_csr(
        &self,
        slot: Slot,
        identity: &str,
        names: &[String],
    ) -> Result<String, ClientError> {
        match self.request(Request::MakeCsr {
            slot,
            identity: identity.to_string(),
            names: names.to_vec(),
        })? {
            Reply::Csr(csr) => Ok(csr),
            other => Err(refused_or_unexpected(other)),
        }
    }

    pub fn install(&self, slot: Slot, chain_pem: Vec<String>) -> Result<(), ClientError> {
        match self.request(Request::Install { slot, chain_pem })? {
            Reply::Installed => Ok(()),
            other => Err(refused_or_unexpected(other)),
        }
    }

    pub fn certificate(&self, slot: Slot) -> Result<Vec<String>, ClientError> {
        match self.request(Request::Certificate { slot })? {
            Reply::Certificate(chain) => Ok(chain),
            other => Err(refused_or_unexpected(other)),
        }
    }

    pub fn sign(&self, slot: Slot, message: &[u8]) -> Result<Vec<u8>, ClientError> {
        match self.request(Request::Sign {
            slot,
            message: message.to_vec(),
        })? {
            Reply::Signature(signature) => Ok(signature),
            other => Err(refused_or_unexpected(other)),
        }
    }

    /// What the custodian is to fetch for `identity` (docs/architecture/key-custody.md, "Part A's bootstrap: the
    /// custodian"): `polar-init`'s, once the custodian's certificate is installed.
    pub fn bootstrap(
        &self,
        identity: &str,
        client: bool,
        server: Option<Vec<String>>,
        escrow: bool,
        signing: bool,
    ) -> Result<(), ClientError> {
        match self.request(Request::Bootstrap {
            identity: identity.to_string(),
            client,
            server,
            escrow,
            signing,
        })? {
            Reply::Installed => Ok(()),
            other => Err(refused_or_unexpected(other)),
        }
    }

    /// Whether the custodian has fetched what it was asked to: `Ok(true)` when it has, `Ok(false)` while it is still
    /// fetching, and an error once it cannot.
    pub fn ready(&self) -> Result<bool, ClientError> {
        match self.request(Request::Ready)? {
            Reply::Ready => Ok(true),
            Reply::Refused(crate::protocol::Refusal::NotReady) => Ok(false),
            other => Err(refused_or_unexpected(other)),
        }
    }

    /// The AES key `wrapped` opens to under the pod's escrow key, wiped when dropped: the workload's.
    pub fn unwrap(&self, wrapped: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, ClientError> {
        match self.request(Request::Unwrap {
            wrapped: wrapped.to_vec(),
        })? {
            Reply::Unwrapped(key) => Ok(zeroize::Zeroizing::new(key)),
            other => Err(refused_or_unexpected(other)),
        }
    }
}

fn refused_or_unexpected(reply: Reply) -> ClientError {
    match reply {
        Reply::Refused(refusal) => ClientError::Refused(refusal),
        other => ClientError::Unexpected(Box::new(other)),
    }
}
