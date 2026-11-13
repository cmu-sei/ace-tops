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

//! polar-crypto
//!
//! The process-local, single gateway to the Credentials Agent for
//! every other actor in an agent's own process -- see
//! credentials-agent-architecture.md's own "CryptoActor" section for
//! the full design. Mirrors polar-health's own, already-established
//! pattern: a dedicated, standalone crate any agent depends on and
//! `spawn_linked`s directly within its own supervisor, sharing that
//! agent's existing TcpClientActor rather than opening a second
//! Cassini connection.
//!
//! Scope: general-secret store, encryption to another agent's escrow key (believed only for its
//! certificate, `recipient`), and opening what is sealed to this agent's own escrow key. That key is
//! the pod's custody daemon's, P-256, fetched by its custodian before the workload starts; the daemon
//! unwraps a secret's AES key for this actor and the key never enters this process
//! (docs/architecture/key-custody.md, "Part A's bootstrap: the custodian"). With no daemon there is no
//! escrow key here, and nothing sealed to it opens (`CryptoError::NoEscrowKey`). The actor also holds
//! the secrets that reach the agent, each with the binding that says where it may go (`registry`),
//! escrows them with the credentials agent, and performs named operations on them, so a caller gets
//! the result of an operation and never the secret (`RegisterSecret`, `LoadSecret`, `GitCredential`).
//!
//! Delivery: this actor registers its own reply topics
//! directly with a real, live polar_router::RouterActor -- the same,
//! single, real RouterActor the consuming supervisor already spawned
//! for its own topics, sharing one real Cassini connection rather
//! than requiring a second. This replaced an earlier, real design
//! built entirely around a broadcast-style Arc<OutputPort<ClientEvent>>,
//! back when RouterActor didn't yet exist; that mechanism is
//! structurally incompatible with DeliveryMode::Router (a
//! ClientEvent::MessagePublished event never reaches any real
//! OutputPort in that mode at all -- it's routed by topic instead),
//! which every genuinely router-based consumer (kube-consumer, the
//! first real one) now uses.

// Reading the process environment goes through polar-env (see clippy.toml).
#![deny(clippy::disallowed_methods)]

pub mod environment;
pub mod recipient;
pub mod records;
pub mod registry;
pub mod sending;
pub mod tls;
pub mod workload_certificates;

use cassini_client::TcpClientMessage;
use credentials_agent_common::agent_escrow_key::{AgentEscrowKeyReply, AgentEscrowKeyRequest};
use credentials_agent_common::escrow_key::EscrowKeyRequest;
use credentials_agent_common::escrow_secret::EscrowedSecret;
use credentials_agent_common::secret::{StoreRefusalReason, StoreSecretReply, StoreSecretRequest};
use credentials_agent_common::{
    CREDENTIALS_AGENT_ESCROW_KEY_REPLIES_TOPIC, CREDENTIALS_AGENT_ESCROW_KEY_REQUESTS_TOPIC,
    CREDENTIALS_ESCROW_KEY_REPLIES_TOPIC, CREDENTIALS_ESCROW_KEY_REQUESTS_TOPIC,
    CREDENTIALS_RETRIEVE_SECRET_REPLIES_TOPIC, CREDENTIALS_RETRIEVE_SECRET_REQUESTS_TOPIC,
    CREDENTIALS_STORE_SECRET_REPLIES_TOPIC, CREDENTIALS_STORE_SECRET_REQUESTS_TOPIC,
};
use polar::request_reply::{Envelope, ReplyRouter};
use ractor::{Actor, ActorProcessingErr, ActorRef, RpcReplyPort, async_trait};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};
pub use zeroize::Zeroizing;

/// The credentials agent's request topics the actor publishes to, one for each request it makes. An agent
/// that encrypts uses them because of that need (docs/architecture/topics.md, "Implied topics").
///
/// Not the escrow keypair's retrieval or issuance: those are the custody daemon's custodian's, never the
/// workload's (docs/architecture/key-custody.md, step 9).
pub const REQUEST_TOPICS: [&str; 4] = [
    CREDENTIALS_ESCROW_KEY_REQUESTS_TOPIC,
    CREDENTIALS_STORE_SECRET_REQUESTS_TOPIC,
    CREDENTIALS_AGENT_ESCROW_KEY_REQUESTS_TOPIC,
    CREDENTIALS_RETRIEVE_SECRET_REQUESTS_TOPIC,
];

/// Their replies, which the actor subscribes to. They are shared by every crypto actor: each takes its own
/// by correlation id.
pub const REPLY_TOPICS: [&str; 4] = [
    CREDENTIALS_ESCROW_KEY_REPLIES_TOPIC,
    CREDENTIALS_STORE_SECRET_REPLIES_TOPIC,
    CREDENTIALS_AGENT_ESCROW_KEY_REPLIES_TOPIC,
    CREDENTIALS_RETRIEVE_SECRET_REPLIES_TOPIC,
];

/// How long CryptoActor waits for a single correlated reply from the
/// Credentials Agent before giving up -- generous relative to what a
/// live broker round trip should ever actually take, matching the
/// same conservative-but-bounded spirit as this codebase's other
/// request/reply timeouts elsewhere.
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("failed to reach the broker: {0}")]
    BrokerUnreachable(String),
    #[error("timed out waiting for a reply from the Credentials Agent")]
    Timeout,
    #[error("reply channel closed with no reply")]
    NoReply,
    /// Asked for what needs the credentials agent before the agent's Cassini client was given to the actor.
    #[error("the crypto actor is not connected to Cassini yet")]
    NotConnected,
    /// Asked to escrow or retrieve with no identity of its own: an agent that does not escrow is given none.
    #[error("the crypto actor has no identity of its own: this agent does not escrow secrets")]
    NoIdentity,
    #[error("failed to serialize request: {0}")]
    Serialization(String),
    #[error("encryption failed: {0}")]
    Encryption(#[from] credentials_agent_common::escrow_secret::EscrowError),
    #[error("store refused: {0:?}")]
    Refused(StoreRefusalReason),
    #[error("store request was valid but failed to persist: {0}")]
    StoreFailed(String),
    #[error("retrieve request was valid but failed: {0}")]
    RetrieveFailed(String),
    #[error("{0}")]
    KeyEncoding(String),
    #[error(
        "this pod has no custody daemon, so it holds no escrow key and nothing sealed to it opens here \
         (docs/architecture/key-custody.md)"
    )]
    NoEscrowKey,
    #[error("decrypt failed: {0}")]
    DecryptFailed(String),
    #[error("retrieving the secret was refused: {0:?}")]
    RetrieveSecretRefused(credentials_agent_common::retrieve_secret::RetrieveRefusalReason),
    #[error("policy does not let this agent have that secret: {0}")]
    RetrieveSecretDenied(String),
    #[error(
        "no usable escrow public key exists for identity {0:?} -- that agent may never have completed automated escrow-identity issuance"
    )]
    RecipientKeyNotFound(String),
    #[error("no secret is registered under {0:?}")]
    SecretNotRegistered(String),
    #[error(
        "a credential goes only to this agent's protocol handlers, and this pass is not theirs"
    )]
    NotThePort,
    /// What was asked for is a registered secret's own record, which is used and never read.
    #[error("that secret is a credential: it is used through a protocol handler, and never read")]
    IsACredential,
    #[error(transparent)]
    Use(#[from] registry::UseRefusal),
    #[error(transparent)]
    Record(#[from] registry::RecordError),
}

/// What the actor read on disk at its start.
#[derive(Debug, Clone)]
struct KeyPaths {
    /// The pinned CA, which a recipient's escrow certificate must chain to; none if it could not be read, and then
    /// nothing is encrypted to a recipient.
    pinned_ca: Option<String>,
}

/// A part of a credential sealed in a signed document, as the protocol actor hands it on: the escrowed ciphertext, and
/// the context it was bound to when it was sealed.
#[derive(Debug, Clone)]
pub struct SealedPart {
    pub ciphertext: Vec<u8>,
    pub context: Vec<u8>,
}

/// What lets its holder ask the CryptoActor for a credential: the one the actor was started with, compared by identity,
/// so one made anywhere else is not it. The builder makes it, starts the actor with it and gives it to the protocol
/// handlers, and nothing hands it on, so domain code cannot get a credential by writing a function that asks for one
/// (docs/architecture/protocol-handlers.md, "No way to the credential from domain code").
#[derive(Clone)]
pub struct CredentialPass(Arc<()>);

impl CredentialPass {
    pub fn new() -> Self {
        Self(Arc::new(()))
    }

    fn is(&self, other: &CredentialPass) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Default for CredentialPass {
    fn default() -> Self {
        Self::new()
    }
}

/// What a protocol handler asks for. The named operations: which credential, for which host, in the form its protocol
/// presents (`registry::http_credential`, `registry::git_credential`).
pub enum CredentialAsk {
    /// How the credential `name` is presented to `host` over HTTP, once its binding names the host: a kind, never a value.
    HttpKind {
        name: String,
        host: String,
        reply: RpcReplyPort<Result<sending::HttpKind, CryptoError>>,
    },
    /// Sends `request`, judged and built by the handler with no credential, with the credential `name` on it, by `client`,
    /// the handler's own. The binding is held to the request's host.
    SendHttp {
        name: String,
        request: Box<reqwest::Request>,
        client: reqwest::Client,
        reply: RpcReplyPort<Result<sending::Sent, sending::SendError>>,
    },
    /// Sends `request`, a GET of a registry's auth host that the handler judged, with the login `name` on it, by `client`,
    /// and keeps the token the host answers with.
    Exchange {
        name: String,
        request: Box<reqwest::Request>,
        client: reqwest::Client,
        reply: RpcReplyPort<Result<Exchanged, sending::SendError>>,
    },
    /// Sends `request` with a token an exchange kept, by `client`.
    SendWithToken {
        token: u64,
        request: Box<reqwest::Request>,
        client: reqwest::Client,
        reply: RpcReplyPort<Result<reqwest::Response, sending::SendError>>,
    },
    /// A kept token is no longer needed, and is wiped.
    ReleaseToken { token: u64 },
    /// An ssh key, for git over ssh, until custody signs for it. Anything else is sent, never given
    /// ([`UseRefusal::SentNotGiven`](registry::UseRefusal::SentNotGiven)).
    Git {
        name: String,
        host: String,
        reply: RpcReplyPort<Result<registry::GitCredential, CryptoError>>,
    },
    /// What kind of secret git would be given for `host`, the binding checked. A kind, never a value.
    GitKind {
        name: String,
        host: String,
        reply: RpcReplyPort<Result<registry::SecretKind, CryptoError>>,
    },
    /// A request of git over https sent with the credential `name` on it, as git logs in: Basic, its user name and its
    /// secret, the binding held to where the request goes.
    SendGit {
        name: String,
        request: Box<reqwest::Request>,
        client: reqwest::Client,
        reply: RpcReplyPort<Result<sending::Sent, sending::SendError>>,
    },
    /// Which secret is bound to `host` (`registry::bound_to`). A name, never a value.
    BoundTo {
        host: String,
        reply: RpcReplyPort<Result<Option<String>, CryptoError>>,
    },
}

/// A token a registry's auth host answered a login with, kept by the CryptoActor: the handler presents it by this, and it
/// is wiped when this is dropped.
pub struct TokenHandle {
    id: u64,
    release: Option<Box<dyn FnOnce(u64) + Send + Sync>>,
}

impl TokenHandle {
    /// The token kept under `id`, which `release` lets go of when this is dropped. The actor makes its own; a stand-in for
    /// it in a test makes these.
    pub fn new(id: u64, release: impl FnOnce(u64) + Send + Sync + 'static) -> Self {
        Self {
            id,
            release: Some(Box::new(release)),
        }
    }

    /// What the token is kept under.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The actor's handle for its token `id`: dropped, it tells the actor to wipe the token.
    fn kept_by(id: u64, port: CredentialPort) -> Self {
        Self::new(id, move |token| {
            let _ = port.actor.cast(CryptoMessage::UseCredential {
                pass: port.pass,
                ask: CredentialAsk::ReleaseToken { token },
            });
        })
    }
}

impl Drop for TokenHandle {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            release(self.id);
        }
    }
}

impl std::fmt::Debug for TokenHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TokenHandle({})", self.id)
    }
}

/// What a registry's auth host answered a login with: its status and headers, and the token, kept by the actor, when it
/// gave one; how the login went, and whether its secret looks base64-encoded. Never the token or the login.
pub struct Exchanged {
    pub status: reqwest::StatusCode,
    pub headers: reqwest::header::HeaderMap,
    pub token: Option<TokenHandle>,
    pub kind: sending::HttpKind,
    pub looks_base64: bool,
}

/// A protocol handler's way to the CryptoActor's credentials: the actor and the pass together.
#[derive(Clone)]
pub struct CredentialPort {
    actor: ActorRef<CryptoMessage>,
    pass: CredentialPass,
}

impl CredentialPort {
    pub fn new(actor: ActorRef<CryptoMessage>, pass: CredentialPass) -> Self {
        Self { actor, pass }
    }

    /// How the credential `name` is presented to `host` over HTTP, the binding checked by the actor, where the secret is.
    pub async fn http_kind(
        &self,
        name: String,
        host: String,
    ) -> Result<sending::HttpKind, CryptoError> {
        ractor::call!(self.actor, |reply| CryptoMessage::UseCredential {
            pass: self.pass.clone(),
            ask: CredentialAsk::HttpKind { name, host, reply },
        })
        .map_err(|_| CryptoError::NoReply)?
    }

    /// Sends `request` with the credential `name` on it, by `client`: the credential never leaves the actor.
    pub async fn send_http(
        &self,
        name: String,
        request: reqwest::Request,
        client: reqwest::Client,
    ) -> Result<sending::Sent, sending::SendError> {
        ractor::call!(self.actor, |reply| CryptoMessage::UseCredential {
            pass: self.pass.clone(),
            ask: CredentialAsk::SendHttp {
                name,
                request: Box::new(request),
                client,
                reply,
            },
        })
        .map_err(|_| sending::SendError::Refused(CryptoError::NoReply))?
    }

    /// Exchanges the login `name` at a registry's auth host (`request`, judged by the handler), the token kept by the actor.
    pub async fn exchange(
        &self,
        name: String,
        request: reqwest::Request,
        client: reqwest::Client,
    ) -> Result<Exchanged, sending::SendError> {
        ractor::call!(self.actor, |reply| CryptoMessage::UseCredential {
            pass: self.pass.clone(),
            ask: CredentialAsk::Exchange {
                name,
                request: Box::new(request),
                client,
                reply,
            },
        })
        .map_err(|_| sending::SendError::Refused(CryptoError::NoReply))?
    }

    /// Sends `request` with the token `token` keeps, by `client`.
    pub async fn send_with_token(
        &self,
        token: &TokenHandle,
        request: reqwest::Request,
        client: reqwest::Client,
    ) -> Result<reqwest::Response, sending::SendError> {
        ractor::call!(self.actor, |reply| CryptoMessage::UseCredential {
            pass: self.pass.clone(),
            ask: CredentialAsk::SendWithToken {
                token: token.id,
                request: Box::new(request),
                client,
                reply,
            },
        })
        .map_err(|_| sending::SendError::Refused(CryptoError::NoReply))?
    }

    /// The ssh key git presents to `host`: only an ssh key is given, until custody signs for it.
    pub async fn git(
        &self,
        name: String,
        host: String,
    ) -> Result<registry::GitCredential, CryptoError> {
        ractor::call!(self.actor, |reply| CryptoMessage::UseCredential {
            pass: self.pass.clone(),
            ask: CredentialAsk::Git { name, host, reply },
        })
        .map_err(|_| CryptoError::NoReply)?
    }

    /// What kind of secret git would be given for `host`, the binding checked.
    pub async fn git_kind(
        &self,
        name: String,
        host: String,
    ) -> Result<registry::SecretKind, CryptoError> {
        ractor::call!(self.actor, |reply| CryptoMessage::UseCredential {
            pass: self.pass.clone(),
            ask: CredentialAsk::GitKind { name, host, reply },
        })
        .map_err(|_| CryptoError::NoReply)?
    }

    /// Sends a request of git over https with the credential `name` on it, by `client`.
    pub async fn send_git(
        &self,
        name: String,
        request: reqwest::Request,
        client: reqwest::Client,
    ) -> Result<sending::Sent, sending::SendError> {
        ractor::call!(self.actor, |reply| CryptoMessage::UseCredential {
            pass: self.pass.clone(),
            ask: CredentialAsk::SendGit {
                name,
                request: Box::new(request),
                client,
                reply,
            },
        })
        .map_err(|_| sending::SendError::Refused(CryptoError::NoReply))?
    }

    /// The name of the secret bound to `host`, for a request whose host decides its credential.
    pub async fn bound_to(&self, host: String) -> Result<Option<String>, CryptoError> {
        ractor::call!(self.actor, |reply| CryptoMessage::UseCredential {
            pass: self.pass.clone(),
            ask: CredentialAsk::BoundTo { host, reply },
        })
        .map_err(|_| CryptoError::NoReply)?
    }
}

pub enum CryptoMessage {
    /// The Cassini client has registered (or re-registered after a
    /// reconnect). The client drops any Subscribe sent before
    /// registration completes, so this actor's reply-topic
    /// subscriptions are sent in response to this message, never at
    /// construction. Sent on every registration, so a reconnect
    /// restores them too. Subscribing again is harmless.
    ClientRegistered,
    /// The agent's Cassini client and router, once they exist: the crypto actor starts before them, since Cassini's own
    /// connection is the crypto actor's to sign for (docs/plans/crypto-actor.md).
    Connect {
        tcp_client: ActorRef<TcpClientMessage>,
        router: ActorRef<polar_router::RouterMessage>,
    },
    /// A TLS client configuration presenting the agent's own client key (docs/plans/crypto-actor.md, step K3), verifying
    /// the server with `verifier`.
    ClientTls {
        verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
        reply: RpcReplyPort<Result<rustls::ClientConfig, String>>,
    },
    /// A TLS server configuration presenting the agent's own server key, verifying clients with `verifier`, offering
    /// `alpn`.
    ServerTls {
        verifier: Arc<dyn rustls::server::danger::ClientCertVerifier>,
        alpn: Vec<Vec<u8>>,
        reply: RpcReplyPort<Result<rustls::ServerConfig, String>>,
    },
    /// `record` signed with the pod's signing key, as the evidence document it is ([`records`]): the builder's signer
    /// handle's, for an agent with the `signing` capability.
    SignRecord {
        record: records::EvidenceRecord,
        reply: RpcReplyPort<Result<polar_signing::Document, records::SignError>>,
    },
    /// A general secret to escrow -- e.g. an access token an observer
    /// holds and wants the Credentials Agent to store on its behalf.
    /// Not the agent's own escrow private key, which the custody
    /// daemon holds and this actor never sees.
    StoreSecret {
        name: String,
        plaintext: Vec<u8>,
        reply: RpcReplyPort<Result<(), CryptoError>>,
    },
    /// Encrypts `plaintext` to `recipient_identity`'s own, real
    /// escrow public key -- the one, sole way any other actor in
    /// this process ever encrypts something addressed to a different
    /// identity: this actor looks up (and caches) that identity's
    /// own public key itself, via a real AgentEscrowKeyRequest to the
    /// Credentials Agent on first use, without the caller ever
    /// needing to know or handle any key material directly. The
    /// returned bytes are EscrowedSecret's own, real, serialized wire
    /// format -- the same one credentials-agent-common's own
    /// StoreSecret flow already produces -- ready to publish as-is.
    EncryptForRecipient {
        recipient_identity: String,
        plaintext: Vec<u8>,
        reply: RpcReplyPort<Result<Vec<u8>, CryptoError>>,
    },
    /// Registers a secret that arrived in a signed document. `secret` is an `EscrowedSecret` (its `rkyv` bytes)
    /// encrypted to this identity's own escrow public key, and `context` is what it was bound to when it was made
    /// (`EscrowedSecret::encrypt_bound`): it opens only under that. It is decrypted here, with the key in its
    /// custody, and kept with its `binding`, the hosts it may be used for. Then the secret and its binding are
    /// escrowed together with the credentials agent under `<identity>/<name>`, in the background and retried
    /// until acknowledged, so a restart gets both back (`LoadSecret`). It is stored with one label, `kind`, equal
    /// to the binding's kind, which policy can speak of. The reply does not wait for that: it is
    /// `Ok` once the secret is registered, and refused, with nothing registered or escrowed, if the binding is
    /// not usable, the bytes are not an escrowed secret, or it does not open under `context`. A name registered
    /// again replaces the earlier secret and stops escrowing it. The plaintext never leaves this actor except
    /// through an operation on it, asked for with `UseCredential`.
    RegisterSecret {
        name: String,
        /// The runtime section the secret came from, which `ReplaceSection` speaks of.
        section: String,
        secret: Vec<u8>,
        context: Vec<u8>,
        /// The user name, sealed as the secret is and bound to the same entry under its own field: a credential is its
        /// user name and its secret together, and neither is in the clear in a signed document. The binding names no
        /// user name; the one opened here is put in it.
        username: Option<SealedPart>,
        binding: registry::SecretBinding,
        reply: RpcReplyPort<Result<(), CryptoError>>,
    },
    /// Asks the credentials agent for `<identity>/<name>` and registers what comes back, binding included, for an
    /// agent that has started again. `Ok(false)` is a name nothing is stored under; policy refusing is
    /// `Err(RetrieveSecretDenied)`. A record that is not a credential registers nothing.
    LoadSecret {
        name: String,
        /// The runtime section the secret belongs to, as for `RegisterSecret`.
        section: String,
        reply: RpcReplyPort<Result<bool, CryptoError>>,
    },
    /// A runtime section was replaced whole: drops every secret registered under `section` whose name is not in
    /// `keep`, stops escrowing it, and replies with the names dropped (sorted). Secrets of other sections, and
    /// those registered without this section, are untouched. The copy already escrowed with the credentials
    /// agent stays, since the ledger has no delete; `LoadSecret` is only asked for names a section lists.
    ReplaceSection {
        section: String,
        keep: Vec<String>,
        reply: RpcReplyPort<Vec<String>>,
    },
    /// A protocol handler asks for a credential, with the pass the builder started this actor with: the way
    /// [`CredentialPort`] reaches it. Any other pass is refused, and learns nothing.
    UseCredential {
        pass: CredentialPass,
        ask: CredentialAsk,
    },
    /// Asks the credentials agent for a secret by name. It comes back encrypted to this identity's own
    /// escrow public key and is decrypted here, with the key in custody, so the plaintext is only ever
    /// in this process. `Ok(None)` means nothing is stored under the name. Whether this identity may
    /// have the secret is the credentials agent's policy to decide: a denial is
    /// `Err(RetrieveSecretDenied)`, and says nothing about whether the secret exists. The plaintext is
    /// wiped when dropped. A registered secret's own record is refused, `Err(IsACredential)`, whatever it is
    /// called and whether or not it is registered now: a credential is used, through a protocol handler, and never read
    /// (docs/architecture/protocol-handlers.md, "No way to the credential from domain code").
    RetrieveSecret {
        name: String,
        reply: RpcReplyPort<Result<Option<zeroize::Zeroizing<Vec<u8>>>, CryptoError>>,
    },
    /// Internal: a raw, incoming message on one of this actor's own,
    /// registered reply topics, forwarded by RouterActor. Carries the
    /// topic alongside the payload -- unlike the earlier,
    /// broadcast-style design (a single ClientEvent variant, matched
    /// on internally), RouterActor's own registration is already
    /// per-topic, so each of the five, real Register calls in
    /// pre_start builds its own closure knowing exactly which topic
    /// it's for; this variant exists only because all five, real
    /// closures share the same underlying delivery shape.
    RoutedReply { topic: String, payload: Vec<u8> },
}

#[non_exhaustive]
pub struct CryptoActorArgs {
    /// The consuming agent's own, already-spawned TcpClientActor --
    /// shared, not a second connection. See
    /// credentials-agent-architecture.md's own "CryptoActor" section
    /// for why this must stay fire-and-forget in both directions.
    pub tcp_client: Option<ActorRef<TcpClientMessage>>,
    /// The consuming supervisor's own, already-spawned RouterActor --
    /// the same one its own, real topics are already registered
    /// with, not a second one. CryptoActor registers its own
    /// reply topics with it directly in pre_start, rather than
    /// subscribing to a broadcast-style OutputPort<ClientEvent> (the
    /// earlier, real design, before RouterActor existed) -- see this
    /// crate's own, top-level doc comment for the full reasoning.
    /// With `tcp_client`, or both given later by [`CryptoMessage::Connect`]: the crypto actor starts before the agent's
    /// Cassini client (docs/plans/crypto-actor.md).
    pub router: Option<ActorRef<polar_router::RouterMessage>>,
    /// The certificate, CA and custody-socket paths, already read and judged. The agent builder supplies
    /// them from its snapshot of the environment. `None` is for agents not yet on the
    /// builder: the actor then reads the process.
    pub settings: Option<environment::CryptoSettings>,
    /// How long to wait before trying to escrow a registered secret again, and the most that wait grows to.
    pub escrow_retry: (Duration, Duration),
    /// The pass a protocol handler asks for a credential with. None: nothing can ask that way.
    pub credential_pass: Option<CredentialPass>,
    /// Whether the agent escrows and retrieves secrets (its `encryption` capability), and so hears the credentials
    /// agent's replies. An agent that only signs records does not.
    pub escrow: bool,
}

impl CryptoActorArgs {
    /// Built with this and the `with_` methods, so a field added later touches no caller.
    pub fn new(
        tcp_client: ActorRef<TcpClientMessage>,
        router: ActorRef<polar_router::RouterMessage>,
    ) -> Self {
        Self {
            tcp_client: Some(tcp_client),
            router: Some(router),
            settings: None,
            escrow_retry: (Duration::from_secs(1), Duration::from_secs(30)),
            credential_pass: None,
            escrow: true,
        }
    }

    /// An actor not yet connected to Cassini: it is given the agent's client and router by [`CryptoMessage::Connect`]
    /// once they exist, and until then answers what needs them [`CryptoError::NotConnected`].
    pub fn unconnected() -> Self {
        Self {
            tcp_client: None,
            router: None,
            settings: None,
            escrow_retry: (Duration::from_secs(1), Duration::from_secs(30)),
            credential_pass: None,
            escrow: true,
        }
    }

    /// Whether the agent escrows and retrieves secrets: `false` for one that only signs records.
    pub fn with_escrow(mut self, escrow: bool) -> Self {
        self.escrow = escrow;
        self
    }

    /// The pass the protocol handlers will ask with.
    pub fn with_credential_pass(mut self, pass: CredentialPass) -> Self {
        self.credential_pass = Some(pass);
        self
    }

    /// Escrow a registered secret again after `initial`, doubling up to `most`, until the credentials agent
    /// acknowledges it.
    pub fn with_escrow_retry(mut self, initial: Duration, most: Duration) -> Self {
        self.escrow_retry = (initial, most);
        self
    }

    /// Start on these settings instead of reading the process.
    pub fn with_settings(mut self, settings: environment::CryptoSettings) -> Self {
        self.settings = Some(settings);
        self
    }
}

pub struct CryptoActorState {
    /// The agent's Cassini client, once it is given ([`CryptoMessage::Connect`]).
    tcp_client: Option<ActorRef<TcpClientMessage>>,
    /// Whether it hears the credentials agent's replies ([`CryptoActorArgs::escrow`]).
    escrow: bool,
    /// The agent's key files, for its TLS where no custody daemon holds its keys.
    key_files: environment::KeyFiles,
    escrow_key_reply_router: Arc<ReplyRouter<credentials_agent_common::escrow_key::EscrowKeyReply>>,
    store_secret_reply_router: Arc<ReplyRouter<StoreSecretReply>>,
    agent_escrow_key_reply_router: Arc<ReplyRouter<AgentEscrowKeyReply>>,
    retrieve_secret_reply_router:
        Arc<ReplyRouter<credentials_agent_common::retrieve_secret::RetrieveSecretReply>>,
    /// The Credentials Agent's own current escrow public key, learned
    /// on first use and reused afterward -- avoids re-querying on
    /// every single store, per credentials-agent-architecture.md's
    /// own note on CryptoActor's local caching. Arc<Mutex<_>> rather
    /// than a plain field: the actual store work runs in a spawned
    /// task, not inline in handle() (see handle()'s own StoreSecret
    /// arm for why), so this needs to be mutable from outside the
    /// actor's own sequential mailbox loop.
    cached_credentials_agent_escrow_key: Arc<tokio::sync::Mutex<Option<String>>>,
    /// The pod's custody daemon, which holds this identity's escrow key and unwraps for this actor; `None` when the
    /// pod has no daemon, and then there is no escrow key here at all.
    escrow_key: Option<Arc<polar_custody::client::CustodyClient>>,
    /// Other identities' own, real escrow public keys, keyed by
    /// identity -- learned on first use of EncryptForRecipient for
    /// each specific recipient, and reused afterward, same caching
    /// reasoning as cached_credentials_agent_escrow_key above.
    /// Caches both the real, already-parsed RsaPublicKey (so
    /// EscrowedSecret::encrypt_to_parsed_key can skip a real,
    /// repeated PEM-parse cost on every single call) and the
    /// original PEM string alongside it (still required as real wire
    /// metadata -- see EscrowedSecret::encrypt_to_parsed_key's own
    /// doc comment).
    cached_recipient_public_keys:
        Arc<tokio::sync::Mutex<std::collections::HashMap<String, String>>>,
    own_identity: Option<String>,
    /// What the actor read on disk at its start.
    paths: KeyPaths,
    /// The secrets that reached this agent, by name, each with the binding that says where it may go
    /// (docs/architecture/credentials-agent-architecture.md, "Named operations on registered secrets").
    registry: Registry,
    /// The task escrowing each registered secret, by name. A newer registration of the name replaces it, and
    /// every one is stopped when the actor is.
    escrow_tasks: EscrowTasks,
    escrow_retry: (Duration, Duration),
    /// The pass the protocol handlers ask with.
    credential_pass: Option<CredentialPass>,
    /// The tokens registries' auth hosts answered logins with, by the handle's number, each wiped when it is released.
    tokens: Tokens,
    next_token: Arc<std::sync::atomic::AtomicU64>,
}

type Tokens = Arc<std::sync::Mutex<std::collections::HashMap<u64, zeroize::Zeroizing<Vec<u8>>>>>;

/// A secret and where it may be used. The secret is wiped when it is dropped.
struct RegisteredSecret {
    /// The runtime section it came from.
    section: String,
    binding: registry::SecretBinding,
    secret: zeroize::Zeroizing<Vec<u8>>,
}

type Registry = Arc<tokio::sync::Mutex<std::collections::HashMap<String, RegisteredSecret>>>;
type EscrowTasks =
    Arc<std::sync::Mutex<std::collections::HashMap<String, tokio::task::JoinHandle<()>>>>;

pub struct CryptoActor;

#[async_trait]
impl Actor for CryptoActor {
    type Msg = CryptoMessage;
    type State = CryptoActorState;
    type Arguments = CryptoActorArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: CryptoActorArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        // Derived internally, not threaded in as a real, explicit
        // argument -- deliberately: this identity is already,
        // genuinely readable from this agent's own, already-mounted
        // mTLS client certificate (the same, real TLS_CLIENT_CERT
        // path TCPClientConfig::new() itself already reads), and
        // CryptoActor is meant to be the one, sole, real gateway for
        // every crypto-adjacent concern -- including this one --
        // rather than every, real caller needing its own, separate
        // way to learn or compute the same, real identity string.
        let settings = match args.settings {
            Some(settings) => settings,
            None => environment::CryptoSettings::from_env(&polar_env::ProcessEnv)
                .map_err(ActorProcessingErr::from)?,
        };
        // An agent that does not escrow is given no certificate to take an identity from: it needs none.
        let own_identity = match settings.own_certificate_path.as_str() {
            "" => None,
            path => {
                let certificate_pem = std::fs::read_to_string(path)
                    .map_err(|e| ActorProcessingErr::from(format!("failed to read {path}: {e}")))?;
                Some(
                    cert_issuer_common::permission::extract_own_identity(&certificate_pem)
                        .map_err(|e| ActorProcessingErr::from(e.to_string()))?,
                )
            }
        };

        // Registers each of this actor's own, real reply topics
        // directly with the shared RouterActor -- CryptoActor is a
        // requester here, not a responder, so it registers the reply
        // topics, not the request topics (easy to transpose by
        // accident, worth being explicit about). Each closure does
        // the same, minimal, real thing: forward the raw topic and
        // payload back to this actor as RoutedReply, letting handle()
        // itself do the real, per-topic deserialization/routing --
        // mirroring kube-consumer's own, established
        // register_kube_topics pattern exactly.
        if let Some(router) = &args.router {
            register_replies(&myself, router);
        }

        // Subscriptions are not sent here: the Cassini client drops any
        // Subscribe sent before registration completes, and this actor
        // is spawned while the client is still registering. They are
        // sent on CryptoMessage::ClientRegistered instead.
        Ok(CryptoActorState {
            tcp_client: args.tcp_client,
            escrow: args.escrow,
            key_files: settings.key_files.clone(),
            escrow_key_reply_router: Arc::new(ReplyRouter::new()),
            store_secret_reply_router: Arc::new(ReplyRouter::new()),
            agent_escrow_key_reply_router: Arc::new(ReplyRouter::new()),
            retrieve_secret_reply_router: Arc::new(ReplyRouter::new()),
            cached_credentials_agent_escrow_key: Arc::new(tokio::sync::Mutex::new(None)),
            escrow_key: settings
                .custody_socket
                .as_deref()
                .map(|socket| Arc::new(polar_custody::client::CustodyClient::new(socket))),
            cached_recipient_public_keys: Arc::new(tokio::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            own_identity,
            paths: KeyPaths {
                pinned_ca: match std::fs::read_to_string(&settings.ca_cert_path) {
                    _ if settings.ca_cert_path.is_empty() => None,
                    Ok(pem) => Some(pem),
                    Err(e) => {
                        warn!(
                            path = %settings.ca_cert_path,
                            "the pinned CA cannot be read, so no recipient's key can be believed: {e}"
                        );
                        None
                    }
                },
            },
            registry: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            escrow_tasks: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            escrow_retry: args.escrow_retry,
            credential_pass: args.credential_pass,
            tokens: Arc::default(),
            next_token: Arc::default(),
        })
    }

    /// The actor stops once, when the agent is going away: the Cassini client it talks to is
    /// a stable front that keeps its own connection up, so nothing replaces this actor. The secrets it
    /// holds are wiped, and their escrow stopped. A hard kill gets no cleanup; nothing runs.
    async fn post_stop(
        &self,
        _myself: ActorRef<Self::Msg>,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        for (_, task) in state.escrow_tasks.lock().unwrap().drain() {
            task.abort();
        }
        state.registry.lock().await.clear();
        Ok(())
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            CryptoMessage::SignRecord { record, reply } => match state.escrow_key.clone() {
                None => {
                    let _ = reply.send(Err(records::SignError::Unavailable(
                        "no custody daemon: the signing key is the daemon's".to_string(),
                    )));
                }
                // The client blocks on the socket: off the actor and off the runtime's workers.
                Some(client) => {
                    tokio::spawn(async move {
                        let signed = tokio::task::spawn_blocking(move || {
                            records::sign_record(&client, &record)
                        })
                        .await
                        .map_err(|e| records::SignError::Unavailable(e.to_string()))
                        .and_then(|signed| signed);
                        if let Err(e) = &signed {
                            warn!("a record was not signed: {e}");
                        }
                        let _ = reply.send(signed);
                    });
                }
            },
            CryptoMessage::ClientTls { verifier, reply } => {
                let source = state.key_source(polar_custody::protocol::Slot::Client);
                // The daemon is asked for the certificate over its socket: off the actor and the runtime's workers.
                tokio::task::spawn_blocking(move || {
                    let _ =
                        reply.send(source.and_then(|source| tls::client_config(verifier, &source)));
                });
            }
            CryptoMessage::ServerTls {
                verifier,
                alpn,
                reply,
            } => {
                let source = state.key_source(polar_custody::protocol::Slot::Server);
                tokio::task::spawn_blocking(move || {
                    let _ = reply.send(
                        source.and_then(|source| tls::server_config(verifier, alpn, &source)),
                    );
                });
            }
            CryptoMessage::Connect { tcp_client, router } => {
                register_replies(&myself, &router);
                state.tcp_client = Some(tcp_client);
            }
            CryptoMessage::ClientRegistered => {
                // Subscribes to the *_REPLIES_TOPIC constants specifically --
                // CryptoActor is a requester here, not a responder, so it
                // needs the reply topics, not the request topics (easy to
                // transpose by accident, worth being explicit about). An agent
                // that only signs records asks the credentials agent nothing.
                let Some(tcp_client) = &state.tcp_client else {
                    warn!("CryptoActor: told the client registered before it was given the client");
                    return Ok(());
                };
                for topic in REPLY_TOPICS.iter().filter(|_| state.escrow) {
                    if let Err(e) = tcp_client.send_message(TcpClientMessage::Subscribe {
                        topic: topic.to_string(),
                        trace_ctx: None,
                    }) {
                        error!("CryptoActor failed to subscribe to {topic}: {e}");
                    }
                }
            }
            CryptoMessage::RoutedReply { topic, payload }
                if topic == CREDENTIALS_RETRIEVE_SECRET_REPLIES_TOPIC =>
            {
                match rkyv::from_bytes::<
                    Envelope<credentials_agent_common::retrieve_secret::RetrieveSecretReply>,
                    rkyv::rancor::Error,
                >(&payload)
                {
                    Ok(envelope) => state
                        .retrieve_secret_reply_router
                        .deliver(&envelope.correlation_id, envelope.payload),
                    Err(e) => warn!("CryptoActor failed to deserialize retrieve-secret reply: {e}"),
                }
            }
            CryptoMessage::RoutedReply { topic, payload }
                if topic == CREDENTIALS_ESCROW_KEY_REPLIES_TOPIC =>
            {
                match rkyv::from_bytes::<
                    Envelope<credentials_agent_common::escrow_key::EscrowKeyReply>,
                    rkyv::rancor::Error,
                >(&payload)
                {
                    Ok(envelope) => state
                        .escrow_key_reply_router
                        .deliver(&envelope.correlation_id, envelope.payload),
                    Err(e) => warn!("CryptoActor failed to deserialize escrow-key reply: {e}"),
                }
            }
            CryptoMessage::RoutedReply { topic, payload }
                if topic == CREDENTIALS_STORE_SECRET_REPLIES_TOPIC =>
            {
                match rkyv::from_bytes::<Envelope<StoreSecretReply>, rkyv::rancor::Error>(&payload)
                {
                    Ok(envelope) => state
                        .store_secret_reply_router
                        .deliver(&envelope.correlation_id, envelope.payload),
                    Err(e) => warn!("CryptoActor failed to deserialize store-secret reply: {e}"),
                }
            }
            CryptoMessage::RoutedReply { topic, payload }
                if topic == CREDENTIALS_AGENT_ESCROW_KEY_REPLIES_TOPIC =>
            {
                match rkyv::from_bytes::<Envelope<AgentEscrowKeyReply>, rkyv::rancor::Error>(
                    &payload,
                ) {
                    Ok(envelope) => state
                        .agent_escrow_key_reply_router
                        .deliver(&envelope.correlation_id, envelope.payload),
                    Err(e) => {
                        warn!("CryptoActor failed to deserialize agent escrow-key reply: {e}")
                    }
                }
            }
            CryptoMessage::RoutedReply { .. } => {
                // A topic this actor didn't itself register for --
                // RouterActor's own dispatch already guarantees this
                // never genuinely happens, but kept as an explicit,
                // harmless no-op arm rather than silently falling
                // through a wildcard elsewhere.
            }
            CryptoMessage::StoreSecret {
                name,
                plaintext,
                reply,
            } => {
                // Spawned, not awaited inline -- handle_store_secret
                // itself awaits replies from this same actor's own
                // mailbox (via the reply routers), which handle()
                // can't do without blocking the very mailbox those
                // replies need to be processed by. See this crate's
                // own README/commit history for the deadlock this
                // caused before being caught.
                let Some(tcp_client) = state.tcp_client.clone() else {
                    let _ = reply.send(Err(CryptoError::NotConnected));
                    return Ok(());
                };
                let escrow_key_reply_router = state.escrow_key_reply_router.clone();
                let store_secret_reply_router = state.store_secret_reply_router.clone();
                let cached_key = state.cached_credentials_agent_escrow_key.clone();
                tokio::spawn(async move {
                    let result = handle_store_secret(
                        tcp_client,
                        escrow_key_reply_router,
                        store_secret_reply_router,
                        cached_key,
                        name,
                        &plaintext,
                        Default::default(),
                    )
                    .await;
                    let _ = reply.send(result);
                });
            }
            CryptoMessage::RegisterSecret {
                name,
                section,
                secret,
                context,
                username,
                binding,
                reply,
            } => {
                // Spawned, not awaited inline, for the same reason as the arms around it: the daemon is asked to
                // unwrap, and the secret is escrowed over the broker.
                let shared = match state.shared() {
                    Ok(shared) => shared,
                    Err(e) => {
                        let _ = reply.send(Err(e));
                        return Ok(());
                    }
                };
                tokio::spawn(async move {
                    let result =
                        register_secret(shared, name, section, secret, context, username, binding)
                            .await;
                    let _ = reply.send(result);
                });
            }
            CryptoMessage::LoadSecret {
                name,
                section,
                reply,
            } => {
                let shared = match state.shared() {
                    Ok(shared) => shared,
                    Err(e) => {
                        let _ = reply.send(Err(e));
                        return Ok(());
                    }
                };
                tokio::spawn(async move {
                    let result = load_secret(shared, name, section).await;
                    let _ = reply.send(result);
                });
            }
            CryptoMessage::ReplaceSection {
                section,
                keep,
                reply,
            } => {
                let mut dropped: Vec<String> = {
                    let mut registry = state.registry.lock().await;
                    let dropped: Vec<String> = registry
                        .iter()
                        .filter(|(name, held)| held.section == section && !keep.contains(name))
                        .map(|(name, _)| name.clone())
                        .collect();
                    for name in &dropped {
                        registry.remove(name);
                    }
                    dropped
                };
                dropped.sort();
                for name in &dropped {
                    if let Some(task) = state.escrow_tasks.lock().unwrap().remove(name) {
                        task.abort();
                    }
                    info!(secret = %name, %section, "secret withdrawn by its section");
                }
                let _ = reply.send(dropped);
            }
            CryptoMessage::UseCredential { pass, ask } => {
                let passes = state
                    .credential_pass
                    .as_ref()
                    .is_some_and(|ours| ours.is(&pass));
                if !passes {
                    // Nothing in the agent's own code asks this way: something is trying to.
                    warn!(
                        "a credential was asked for with a pass that is not the protocol handlers'"
                    );
                }
                match ask {
                    CredentialAsk::HttpKind { name, host, reply } => {
                        let result = if passes {
                            http_credential_of(&state.registry, name, &host)
                                .await
                                .map(|credential| sending::kind_of(&credential))
                        } else {
                            Err(CryptoError::NotThePort)
                        };
                        let _ = reply.send(result);
                    }
                    CredentialAsk::SendHttp {
                        name,
                        request,
                        client,
                        reply,
                    } => {
                        if !passes {
                            let _ = reply.send(Err(CryptoError::NotThePort.into()));
                        } else {
                            // Spawned: a request takes as long as the site does, and the actor answers others meanwhile.
                            let registry = state.registry.clone();
                            tokio::spawn(async move {
                                let _ =
                                    reply.send(send_http(registry, name, *request, client).await);
                            });
                        }
                    }
                    CredentialAsk::Exchange {
                        name,
                        request,
                        client,
                        reply,
                    } => match (passes, state.credential_pass.clone()) {
                        (true, Some(pass)) => {
                            let registry = state.registry.clone();
                            let tokens = state.tokens.clone();
                            let next = state.next_token.clone();
                            let port = CredentialPort::new(myself.clone(), pass);
                            tokio::spawn(async move {
                                let result =
                                    exchange(registry, tokens, next, port, name, *request, client)
                                        .await;
                                let _ = reply.send(result);
                            });
                        }
                        _ => {
                            let _ = reply.send(Err(CryptoError::NotThePort.into()));
                        }
                    },
                    CredentialAsk::SendWithToken {
                        token,
                        request,
                        client,
                        reply,
                    } => {
                        let held = if passes {
                            state.tokens.lock().unwrap().get(&token).cloned()
                        } else {
                            None
                        };
                        match held {
                            None => {
                                let refused = if passes {
                                    CryptoError::SecretNotRegistered(format!("token {token}"))
                                } else {
                                    CryptoError::NotThePort
                                };
                                let _ = reply.send(Err(refused.into()));
                            }
                            Some(held) => {
                                tokio::spawn(async move {
                                    let result =
                                        sending::send_bearer(&held, *request, client).await;
                                    let _ = reply.send(result);
                                });
                            }
                        }
                    }
                    CredentialAsk::ReleaseToken { token } => {
                        if passes {
                            state.tokens.lock().unwrap().remove(&token);
                        }
                    }
                    CredentialAsk::Git { name, host, reply } => {
                        let result = if passes {
                            git_credential_of(&state.registry, name, &host)
                                .await
                                .and_then(|credential| match credential.kind {
                                    registry::SecretKind::SshKey => Ok(credential),
                                    _ => Err(CryptoError::Use(registry::UseRefusal::SentNotGiven)),
                                })
                        } else {
                            Err(CryptoError::NotThePort)
                        };
                        let _ = reply.send(result);
                    }
                    CredentialAsk::GitKind { name, host, reply } => {
                        let result = if passes {
                            git_credential_of(&state.registry, name, &host)
                                .await
                                .map(|credential| credential.kind)
                        } else {
                            Err(CryptoError::NotThePort)
                        };
                        let _ = reply.send(result);
                    }
                    CredentialAsk::SendGit {
                        name,
                        request,
                        client,
                        reply,
                    } => {
                        if !passes {
                            let _ = reply.send(Err(CryptoError::NotThePort.into()));
                        } else {
                            let registry = state.registry.clone();
                            tokio::spawn(async move {
                                let _ =
                                    reply.send(send_git(registry, name, *request, client).await);
                            });
                        }
                    }
                    CredentialAsk::BoundTo { host, reply } => {
                        let result = if passes {
                            Ok(bound_to_host(&state.registry, &host).await)
                        } else {
                            Err(CryptoError::NotThePort)
                        };
                        let _ = reply.send(result);
                    }
                }
            }
            CryptoMessage::EncryptForRecipient {
                recipient_identity,
                plaintext,
                reply,
            } => {
                // Same reasoning as StoreSecret's own arm above --
                // spawned, not awaited inline.
                let Some(tcp_client) = state.tcp_client.clone() else {
                    let _ = reply.send(Err(CryptoError::NotConnected));
                    return Ok(());
                };
                let agent_escrow_key_reply_router = state.agent_escrow_key_reply_router.clone();
                let cached_recipient_public_keys = state.cached_recipient_public_keys.clone();
                let pinned_ca = state.paths.pinned_ca.clone();
                tokio::spawn(async move {
                    let result = handle_encrypt_for_recipient(
                        tcp_client,
                        agent_escrow_key_reply_router,
                        cached_recipient_public_keys,
                        pinned_ca,
                        recipient_identity,
                        plaintext,
                    )
                    .await;
                    let _ = reply.send(result);
                });
            }
            CryptoMessage::RetrieveSecret { name, reply } => {
                // Spawned, not awaited inline, for the same reason as StoreSecret above.
                let Some(tcp_client) = state.tcp_client.clone() else {
                    let _ = reply.send(Err(CryptoError::NotConnected));
                    return Ok(());
                };
                let retrieve_secret_reply_router = state.retrieve_secret_reply_router.clone();
                let escrow_key = state.escrow_key.clone();
                tokio::spawn(async move {
                    let result = handle_retrieve_secret(
                        tcp_client,
                        retrieve_secret_reply_router,
                        escrow_key,
                        name.clone(),
                    )
                    .await
                    .and_then(|found| refuse_a_credential(&name, found));
                    let _ = reply.send(result);
                });
            }
        }
        Ok(())
    }
}

async fn handle_store_secret(
    tcp_client: ActorRef<TcpClientMessage>,
    escrow_key_reply_router: Arc<ReplyRouter<credentials_agent_common::escrow_key::EscrowKeyReply>>,
    store_secret_reply_router: Arc<ReplyRouter<StoreSecretReply>>,
    cached_key: Arc<tokio::sync::Mutex<Option<String>>>,
    name: String,
    plaintext: &[u8],
    labels: std::collections::BTreeMap<String, String>,
) -> Result<(), CryptoError> {
    let escrow_key_pem = {
        let mut cached = cached_key.lock().await;
        match &*cached {
            Some(pem) => pem.clone(),
            None => {
                let pem = query_escrow_key(&tcp_client, &escrow_key_reply_router).await?;
                *cached = Some(pem.clone());
                pem
            }
        }
    };

    let secret = EscrowedSecret::encrypt(plaintext, &escrow_key_pem)?;

    let reply = publish_store_secret_request(
        &tcp_client,
        &store_secret_reply_router,
        StoreSecretRequest {
            name,
            secret,
            labels,
        },
    )
    .await?;

    match reply {
        StoreSecretReply::Stored => Ok(()),
        StoreSecretReply::Refused { reason } => Err(CryptoError::Refused(reason)),
        StoreSecretReply::Failed { detail } => Err(CryptoError::StoreFailed(detail)),
    }
}

/// One request to the Credentials Agent and the wait for its reply: the exchange every call
/// above makes, written once. The reply is registered for before the request is published, so
/// one that arrives at once has somewhere to go, and the registration is removed on every way
/// out. `what` names the exchange in the log. Only identifiers and outcomes are logged, never
/// what a request or reply carries.
async fn request_reply<Req, Rep>(
    tcp_client: &ActorRef<TcpClientMessage>,
    reply_router: &Arc<ReplyRouter<Rep>>,
    topic: &str,
    what: &str,
    request: Req,
    timeout: Duration,
) -> Result<Rep, CryptoError>
where
    Req: rkyv::Archive
        + for<'a> rkyv::Serialize<
            rkyv::api::high::HighSerializer<
                rkyv::util::AlignedVec,
                rkyv::ser::allocator::ArenaHandle<'a>,
                rkyv::rancor::Error,
            >,
        >,
{
    let correlation_id = uuid::Uuid::new_v4().to_string();
    let envelope = Envelope {
        correlation_id: correlation_id.clone(),
        payload: request,
    };
    let payload = rkyv::to_bytes::<rkyv::rancor::Error>(&envelope)
        .map(|bytes| bytes.to_vec())
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;

    info!(%correlation_id, %topic, "requesting: {what}");
    let began = std::time::Instant::now();
    let outcome = reply_router
        .register_with_timeout(correlation_id.clone(), timeout, || {
            tcp_client
                .send_message(TcpClientMessage::publish(topic.to_string(), payload, None))
                .map_err(|e| e.to_string())
        })
        .await;

    match outcome {
        Ok(reply) => {
            info!(%correlation_id, elapsed_ms = began.elapsed().as_millis() as u64, "reply received: {what}");
            Ok(reply)
        }
        Err(polar::request_reply::ReplyError::PublishFailed(e)) => {
            warn!(%correlation_id, %topic, "could not publish the request for {what}: {e}");
            Err(CryptoError::BrokerUnreachable(e))
        }
        Err(polar::request_reply::ReplyError::ChannelClosed) => {
            warn!(%correlation_id, "the reply channel for {what} closed with no reply");
            Err(CryptoError::NoReply)
        }
        Err(polar::request_reply::ReplyError::Timeout) => {
            warn!(
                %correlation_id,
                %topic,
                waited_secs = timeout.as_secs(),
                "no reply to {what}: nothing answered on the request topic, or its reply never \
                 reached this client"
            );
            Err(CryptoError::Timeout)
        }
    }
}

async fn query_escrow_key(
    tcp_client: &ActorRef<TcpClientMessage>,
    escrow_key_reply_router: &Arc<
        ReplyRouter<credentials_agent_common::escrow_key::EscrowKeyReply>,
    >,
) -> Result<String, CryptoError> {
    request_reply(
        tcp_client,
        escrow_key_reply_router,
        CREDENTIALS_ESCROW_KEY_REQUESTS_TOPIC,
        "escrow public key",
        EscrowKeyRequest,
        REPLY_TIMEOUT,
    )
    .await
    .map(|reply| reply.public_key_pem)
}

async fn publish_store_secret_request(
    tcp_client: &ActorRef<TcpClientMessage>,
    store_secret_reply_router: &Arc<ReplyRouter<StoreSecretReply>>,
    request: StoreSecretRequest,
) -> Result<StoreSecretReply, CryptoError> {
    request_reply(
        tcp_client,
        store_secret_reply_router,
        CREDENTIALS_STORE_SECRET_REQUESTS_TOPIC,
        "store secret",
        request,
        REPLY_TIMEOUT,
    )
    .await
}

/// Opens `escrowed` under `context` with this identity's escrow key, the custody daemon's: the daemon unwraps the
/// secret's AES key and never sees the payload. With no daemon there is no key to open it with.
async fn open_escrowed(
    escrow_key: &Option<Arc<polar_custody::client::CustodyClient>>,
    escrowed: &EscrowedSecret,
    context: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    use credentials_agent_common::escrow_secret::Suite;
    let daemon = escrow_key.clone().ok_or(CryptoError::NoEscrowKey)?;
    if escrowed.suite() != Suite::HpkeP256 {
        return Err(CryptoError::DecryptFailed(format!(
            "sealed under {:?}, and this agent's escrow key is P-256",
            escrowed.suite()
        )));
    }
    let wrapped = escrowed.wrapped_key().to_vec();
    let key = tokio::task::spawn_blocking(move || daemon.unwrap(&wrapped))
        .await
        .map_err(|e| CryptoError::DecryptFailed(e.to_string()))?
        .map_err(|e| CryptoError::DecryptFailed(format!("the custody daemon: {e}")))?;
    escrowed
        .decrypt_with_bound(Suite::HpkeP256, |_| Ok(key.to_vec()), context)
        .map_err(|e| CryptoError::DecryptFailed(e.to_string()))
}

/// Registers each of this actor's reply topics with the agent's router: it is a requester of the credentials agent, so
/// it registers the reply topics, not the request topics. Each is forwarded to this actor as RoutedReply, which `handle`
/// reads per topic.
fn register_replies(
    myself: &ActorRef<CryptoMessage>,
    router: &ActorRef<polar_router::RouterMessage>,
) {
    for topic in REPLY_TOPICS {
        let myself_for_deliver = myself.clone();
        if let Err(e) = router.send_message(polar_router::RouterMessage::Register {
            topic: topic.to_string(),
            deliver: Box::new(move |incoming: polar_router::IncomingMessage| {
                if let Err(e) = myself_for_deliver.send_message(CryptoMessage::RoutedReply {
                    topic: incoming.topic,
                    payload: incoming.payload,
                }) {
                    warn!("CryptoActor: failed to deliver routed reply to self: {e}");
                }
            }),
        }) {
            error!("CryptoActor failed to register topic {topic} with RouterActor: {e}");
        }
    }
}

/// What the tasks started for the registry need from the actor, cloned out of its state: they run outside the
/// mailbox, since they wait on the credentials agent.
#[derive(Clone)]
struct Shared {
    tcp_client: ActorRef<TcpClientMessage>,
    escrow_key_reply_router: Arc<ReplyRouter<credentials_agent_common::escrow_key::EscrowKeyReply>>,
    store_secret_reply_router: Arc<ReplyRouter<StoreSecretReply>>,
    retrieve_secret_reply_router:
        Arc<ReplyRouter<credentials_agent_common::retrieve_secret::RetrieveSecretReply>>,
    cached_key: Arc<tokio::sync::Mutex<Option<String>>>,
    escrow_key: Option<Arc<polar_custody::client::CustodyClient>>,
    own_identity: String,
    registry: Registry,
    escrow_tasks: EscrowTasks,
    escrow_retry: (Duration, Duration),
}

impl CryptoActorState {
    /// Where the agent's key for `slot` is: the custody daemon, where the pod has one, or the key files it was given.
    fn key_source(&self, slot: polar_custody::protocol::Slot) -> Result<tls::KeySource, String> {
        use polar_custody::protocol::Slot;
        if let Some(client) = &self.escrow_key {
            return Ok(tls::KeySource::Custody {
                client: client.clone(),
                slot,
            });
        }
        let files = match slot {
            Slot::Client => &self.key_files.client,
            Slot::Server => &self.key_files.server,
            _ => &None,
        };
        files
            .clone()
            .map(|(certificate, key)| tls::KeySource::Files { certificate, key })
            .ok_or_else(|| {
                format!("the agent has no {slot:?} key: no custody daemon, and no key files given")
            })
    }

    /// What the registry's tasks need: the Cassini client and the actor's own identity, or why they are not there.
    fn shared(&self) -> Result<Shared, CryptoError> {
        Ok(Shared {
            tcp_client: self.tcp_client.clone().ok_or(CryptoError::NotConnected)?,
            escrow_key_reply_router: self.escrow_key_reply_router.clone(),
            store_secret_reply_router: self.store_secret_reply_router.clone(),
            retrieve_secret_reply_router: self.retrieve_secret_reply_router.clone(),
            cached_key: self.cached_credentials_agent_escrow_key.clone(),
            escrow_key: self.escrow_key.clone(),
            own_identity: self.own_identity.clone().ok_or(CryptoError::NoIdentity)?,
            registry: self.registry.clone(),
            escrow_tasks: self.escrow_tasks.clone(),
            escrow_retry: self.escrow_retry,
        })
    }
}

/// The name a secret is escrowed under: the identity that stores it is the prefix, so only that identity may
/// store under it (docs/architecture/credentials-policy.md, "Storing is governed by policy").
fn escrow_name(own_identity: &str, name: &str) -> String {
    format!("{own_identity}/{name}")
}

/// The real handler behind CryptoMessage::RegisterSecret: refuse an unusable binding first, then open the
/// secret, keep it with its binding, and start escrowing both.
async fn register_secret(
    shared: Shared,
    name: String,
    section: String,
    secret: Vec<u8>,
    context: Vec<u8>,
    username: Option<SealedPart>,
    mut binding: registry::SecretBinding,
) -> Result<(), CryptoError> {
    // A user name comes sealed, never in the binding: one there was put in the clear somewhere.
    if binding.username.is_some() {
        return Err(registry::RecordError::BadBinding(
            "a user name comes sealed, never in the binding".to_string(),
        )
        .into());
    }
    if let Some(sealed) = username {
        let opened =
            handle_decrypt_own_escrowed(&shared.escrow_key, sealed.ciphertext, sealed.context)
                .await?;
        let opened = std::str::from_utf8(&opened)
            .ok()
            .filter(|u| registry::is_username(u))
            .ok_or_else(|| {
                registry::RecordError::BadBinding(format!(
                    "the sealed user name is not 1 to {} characters of text with no control character",
                    registry::MAX_USERNAME
                ))
            })?;
        binding.username = Some(opened.to_string());
    }
    binding.check()?;
    let binding_kind = binding.kind;
    let plaintext = handle_decrypt_own_escrowed(&shared.escrow_key, secret, context).await?;
    // The form that is escrowed also proves the secret is text and the binding is whole.
    let record = registry::escrow_form(&binding, &plaintext)?;
    shared.registry.lock().await.insert(
        name.clone(),
        RegisteredSecret {
            section,
            binding,
            secret: plaintext,
        },
    );
    info!(secret = %name, "secret registered");
    // The one label a secret is stored with: what kind of credential it is, so policy can speak of it.
    let labels = std::collections::BTreeMap::from([(
        "kind".to_string(),
        binding_kind.as_label().to_string(),
    )]);
    start_escrow(&shared, name, record, labels);
    Ok(())
}

/// Escrows `record` under the identity-prefixed name in the background, until the credentials agent acknowledges
/// it, with the `kind` label policy can speak of. A failure is retried after a wait that doubles up to the most;
/// a refusal for the wrong escrow key forgets the cached key and retries; so does one because the agent's
/// certificate is not on record yet; any other refusal (policy, labels, the name) is deterministic, so it is
/// reported and not retried. A newer registration of the name replaces this task.
fn start_escrow(
    shared: &Shared,
    name: String,
    record: zeroize::Zeroizing<Vec<u8>>,
    labels: std::collections::BTreeMap<String, String>,
) {
    let task = shared.clone();
    let task_name = name.clone();
    let handle = tokio::spawn(async move {
        let escrow_name = escrow_name(&task.own_identity, &task_name);
        let (mut wait, most) = task.escrow_retry;
        loop {
            let result = handle_store_secret(
                task.tcp_client.clone(),
                task.escrow_key_reply_router.clone(),
                task.store_secret_reply_router.clone(),
                task.cached_key.clone(),
                escrow_name.clone(),
                &record,
                labels.clone(),
            )
            .await;
            match result {
                Ok(()) => {
                    info!(secret = %task_name, "secret escrowed with the credentials agent");
                    break;
                }
                Err(CryptoError::Refused(StoreRefusalReason::WrongEscrowKey)) => {
                    warn!(secret = %task_name, "the escrow key was not the current one; asking again");
                    *task.cached_key.lock().await = None;
                }
                Err(CryptoError::Refused(StoreRefusalReason::RequesterCertificateNotFound)) => {
                    // Its certificate is not on record yet, as happens just after it was issued: try again.
                    warn!(secret = %task_name, "the credentials agent has no certificate on record for this agent yet; will try again");
                }
                Err(CryptoError::Refused(reason)) => {
                    error!(secret = %task_name, ?reason, "the credentials agent refused to escrow the secret, and trying again cannot change that");
                    break;
                }
                Err(error) => {
                    warn!(secret = %task_name, %error, "escrowing the secret failed; will try again");
                }
            }
            tokio::time::sleep(wait).await;
            wait = (wait * 2).min(most);
        }
    });
    if let Some(earlier) = shared.escrow_tasks.lock().unwrap().insert(name, handle) {
        earlier.abort();
    }
}

/// What was retrieved, unless it is a registered secret's own record. Its value decides, not the name, so a credential
/// not registered yet in this run, or withdrawn, is refused the same.
fn refuse_a_credential(
    name: &str,
    found: Option<zeroize::Zeroizing<Vec<u8>>>,
) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, CryptoError> {
    match found {
        Some(record) if registry::is_escrow_form(&record) => {
            // Nothing in the agent's own code asks this way: something is trying to.
            warn!(secret = %name, "a credential's own record was asked for, and refused");
            Err(CryptoError::IsACredential)
        }
        other => Ok(other),
    }
}

/// The real handler behind CryptoMessage::LoadSecret.
async fn load_secret(shared: Shared, name: String, section: String) -> Result<bool, CryptoError> {
    let found = handle_retrieve_secret(
        shared.tcp_client.clone(),
        shared.retrieve_secret_reply_router.clone(),
        shared.escrow_key.clone(),
        escrow_name(&shared.own_identity, &name),
    )
    .await?;
    let Some(record) = found else {
        return Ok(false);
    };
    let (binding, secret) = registry::from_escrow_form(&record)?;
    shared.registry.lock().await.insert(
        name,
        RegisteredSecret {
            section,
            binding,
            secret,
        },
    );
    Ok(true)
}

/// The credential git is given for `host`, from what is registered under `name`.
async fn git_credential_of(
    registry: &Registry,
    name: String,
    host: &str,
) -> Result<registry::GitCredential, CryptoError> {
    let registry = registry.lock().await;
    match registry.get(&name) {
        None => Err(CryptoError::SecretNotRegistered(name)),
        Some(held) => {
            registry::git_credential(&held.binding, &held.secret, host).map_err(CryptoError::Use)
        }
    }
}

/// Sends a request of git over https with the credential `name` on it, as git logs in: Basic, the user name git is given
/// and the secret. An ssh key goes over ssh only.
async fn send_git(
    registry: Registry,
    name: String,
    request: reqwest::Request,
    client: reqwest::Client,
) -> Result<sending::Sent, sending::SendError> {
    let host = request.url().host_str().unwrap_or_default().to_string();
    let credential = git_credential_of(&registry, name, &host).await?;
    if credential.kind == registry::SecretKind::SshKey {
        return Err(CryptoError::Use(registry::UseRefusal::NotForHttp).into());
    }
    let login = registry::HttpCredential::Basic {
        username: credential.username.clone(),
        password: credential.secret.clone(),
    };
    drop(credential);
    sending::send(&login, request, client).await
}

/// The credential an HTTP request is given for `host`, from what is registered under `name`.
async fn http_credential_of(
    registry: &Registry,
    name: String,
    host: &str,
) -> Result<registry::HttpCredential, CryptoError> {
    let registry = registry.lock().await;
    match registry.get(&name) {
        None => Err(CryptoError::SecretNotRegistered(name)),
        Some(held) => {
            registry::http_credential(&held.binding, &held.secret, host).map_err(CryptoError::Use)
        }
    }
}

/// Sends `request` with the credential `name` on it, the binding held to the request's own host.
async fn send_http(
    registry: Registry,
    name: String,
    request: reqwest::Request,
    client: reqwest::Client,
) -> Result<sending::Sent, sending::SendError> {
    let host = request.url().host_str().unwrap_or_default().to_string();
    let credential = http_credential_of(&registry, name, &host).await?;
    sending::send(&credential, request, client).await
}

/// Sends a login to a registry's auth host and keeps the token it answers with, under a new handle.
async fn exchange(
    registry: Registry,
    tokens: Tokens,
    next: Arc<std::sync::atomic::AtomicU64>,
    port: CredentialPort,
    name: String,
    request: reqwest::Request,
    client: reqwest::Client,
) -> Result<Exchanged, sending::SendError> {
    let host = request.url().host_str().unwrap_or_default().to_string();
    let credential = http_credential_of(&registry, name, &host).await?;
    let answered = sending::log_in(&credential, request, client).await?;
    drop(credential);
    let token = answered.token.map(|token| {
        let id = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tokens.lock().unwrap().insert(id, token);
        TokenHandle::kept_by(id, port)
    });
    Ok(Exchanged {
        status: answered.status,
        headers: answered.headers,
        token,
        kind: answered.kind,
        looks_base64: answered.looks_base64,
    })
}

/// The name of the secret bound to `host`, from what is registered.
async fn bound_to_host(registry: &Registry, host: &str) -> Option<String> {
    let registry = registry.lock().await;
    registry::bound_to(
        registry
            .iter()
            .map(|(name, held)| (name.as_str(), held.binding.host_pattern.as_str())),
        host,
    )
    .map(str::to_string)
}

/// Opens an `EscrowedSecret` addressed to this identity, for `register_secret`: read the bytes as one, and open the
/// secret under `context` with this identity's escrow key, which never leaves the custody daemon. Not a message: no
/// caller has the plaintext of a registered secret.
async fn handle_decrypt_own_escrowed(
    escrow_key: &Option<Arc<polar_custody::client::CustodyClient>>,
    secret: Vec<u8>,
    context: Vec<u8>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    // Read before the key is touched: bytes that are not a secret need no daemon to be refused.
    let escrowed = rkyv::from_bytes::<EscrowedSecret, rkyv::rancor::Error>(&secret)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;
    open_escrowed(escrow_key, &escrowed, &context).await
}

/// The real handler behind CryptoMessage::RetrieveSecret: ask the credentials agent, and decrypt what
/// comes back with this identity's own escrow key, which never leaves the custody daemon. With no daemon nothing is
/// asked: what came back could not be opened.
async fn handle_retrieve_secret(
    tcp_client: ActorRef<TcpClientMessage>,
    retrieve_secret_reply_router: Arc<
        ReplyRouter<credentials_agent_common::retrieve_secret::RetrieveSecretReply>,
    >,
    escrow_key: Option<Arc<polar_custody::client::CustodyClient>>,
    name: String,
) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, CryptoError> {
    use credentials_agent_common::retrieve_secret::{RetrieveSecretReply, RetrieveSecretRequest};

    if escrow_key.is_none() {
        return Err(CryptoError::NoEscrowKey);
    }

    let reply = request_reply(
        &tcp_client,
        &retrieve_secret_reply_router,
        CREDENTIALS_RETRIEVE_SECRET_REQUESTS_TOPIC,
        "retrieve secret",
        RetrieveSecretRequest { name },
        REPLY_TIMEOUT,
    )
    .await?;

    match reply {
        RetrieveSecretReply::NotFound => Ok(None),
        RetrieveSecretReply::Refused { reason } => Err(CryptoError::RetrieveSecretRefused(reason)),
        RetrieveSecretReply::Denied { reason } => Err(CryptoError::RetrieveSecretDenied(reason)),
        RetrieveSecretReply::Failed { detail } => Err(CryptoError::RetrieveFailed(detail)),
        RetrieveSecretReply::Found { secret } => {
            let plaintext = open_escrowed(&escrow_key, &secret, b"").await?;
            Ok(Some(plaintext))
        }
    }
}

/// The real handler behind CryptoMessage::EncryptForRecipient -- see
/// that variant's own doc comment for the complete, intended
/// behavior. Looks up (and caches, per identity) the recipient's own,
/// real escrow public key via a real AgentEscrowKeyRequest on first
/// use for that specific identity, then encrypts via
/// EscrowedSecret::encrypt -- the same, real, standard OAEP-wrapped
/// hybrid cryptosystem StoreSecret already uses, returning its own,
/// real, serialized wire bytes directly.
async fn handle_encrypt_for_recipient(
    tcp_client: ActorRef<TcpClientMessage>,
    agent_escrow_key_reply_router: Arc<ReplyRouter<AgentEscrowKeyReply>>,
    cached_recipient_public_keys: Arc<
        tokio::sync::Mutex<std::collections::HashMap<String, String>>,
    >,
    pinned_ca: Option<String>,
    recipient_identity: String,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    let cached = cached_recipient_public_keys
        .lock()
        .await
        .get(&recipient_identity)
        .cloned();
    let public_key_pem = match cached {
        Some(pem) => pem,
        None => {
            let reply = publish_agent_escrow_key_request(
                &tcp_client,
                &agent_escrow_key_reply_router,
                AgentEscrowKeyRequest {
                    identity: recipient_identity.clone(),
                },
            )
            .await?;
            let (public_key_pem, certificate_pem) = match reply {
                AgentEscrowKeyReply::Found {
                    public_key_pem,
                    certificate_pem,
                } => (public_key_pem, certificate_pem),
                AgentEscrowKeyReply::NotFound => {
                    return Err(CryptoError::RecipientKeyNotFound(recipient_identity));
                }
            };
            // Believed for its certificate, never for the channel it came over (docs/architecture/key-custody.md,
            // "Also in this work"): chained to the pinned CA, naming the recipient, an escrow certificate, valid,
            // holding this key.
            let pinned_ca = pinned_ca.as_deref().ok_or_else(|| {
                CryptoError::KeyEncoding(
                    "no pinned CA to believe a recipient's key under".to_string(),
                )
            })?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let believed = recipient::believed_key(
                &certificate_pem,
                &public_key_pem,
                &recipient_identity,
                pinned_ca,
                now,
            )
            .map_err(|why| {
                warn!(recipient = %recipient_identity, "a recipient's key that cannot be believed: {why}");
                CryptoError::KeyEncoding(format!("the recipient's key cannot be believed: {why}"))
            })?;
            cached_recipient_public_keys
                .lock()
                .await
                .insert(recipient_identity.clone(), believed.clone());
            believed
        }
    };

    // The suite is the key's: HPKE for a P-256 key (every agent's, held by its custody daemon), RSA-OAEP for an RSA one.
    let escrowed = EscrowedSecret::encrypt(&plaintext, &public_key_pem)?;

    rkyv::to_bytes::<rkyv::rancor::Error>(&escrowed)
        .map(|b| b.to_vec())
        .map_err(|e| CryptoError::Serialization(e.to_string()))
}

async fn publish_agent_escrow_key_request(
    tcp_client: &ActorRef<TcpClientMessage>,
    agent_escrow_key_reply_router: &Arc<ReplyRouter<AgentEscrowKeyReply>>,
    request: AgentEscrowKeyRequest,
) -> Result<AgentEscrowKeyReply, CryptoError> {
    request_reply(
        tcp_client,
        agent_escrow_key_reply_router,
        CREDENTIALS_AGENT_ESCROW_KEY_REQUESTS_TOPIC,
        "agent escrow key",
        request,
        REPLY_TIMEOUT,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use credentials_agent_common::escrow_key::EscrowKeyReply;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::{RsaPrivateKey, pkcs8::LineEnding};
    use std::sync::OnceLock;

    /// Cached across every test needing a real keypair to stand in
    /// for the Credentials Agent's own escrow key -- RSA generation
    /// is expensive, matching this codebase's established caching
    /// convention for exactly this reason (see e.g.
    /// credentials-agent's own escrow.rs test_keypair()).
    fn test_credentials_agent_keypair() -> (RsaPrivateKey, String) {
        static KEYPAIR: OnceLock<(RsaPrivateKey, String)> = OnceLock::new();
        KEYPAIR
            .get_or_init(|| {
                let mut rng = rand::rng();
                let private_key = RsaPrivateKey::new(&mut rng, 4096).unwrap();
                let public_key_pem = private_key
                    .to_public_key()
                    .to_public_key_pem(LineEnding::LF)
                    .unwrap();
                (private_key, public_key_pem)
            })
            .clone()
    }

    /// An actor that takes whatever it is sent and says nothing: a client whose request goes
    /// out and is never answered.
    struct Silent;

    #[async_trait]
    impl Actor for Silent {
        type Msg = TcpClientMessage;
        type State = ();
        type Arguments = ();

        async fn pre_start(
            &self,
            _myself: ActorRef<Self::Msg>,
            _args: (),
        ) -> Result<(), ActorProcessingErr> {
            Ok(())
        }

        async fn handle(
            &self,
            _myself: ActorRef<Self::Msg>,
            _message: Self::Msg,
            _state: &mut (),
        ) -> Result<(), ActorProcessingErr> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_request_nobody_answers_times_out_and_leaves_nothing_registered() {
        let (client, _) = Actor::spawn(None, Silent, ()).await.unwrap();
        let router: Arc<ReplyRouter<credentials_agent_common::escrow_key::EscrowKeyReply>> =
            Arc::new(ReplyRouter::new());
        let outcome = request_reply(
            &client,
            &router,
            CREDENTIALS_ESCROW_KEY_REQUESTS_TOPIC,
            "test",
            EscrowKeyRequest,
            Duration::from_millis(100),
        )
        .await;
        assert!(matches!(outcome, Err(CryptoError::Timeout)), "{outcome:?}");
    }

    #[tokio::test]
    async fn a_request_to_a_client_that_is_gone_fails_at_once_as_unreachable() {
        let (client, _) = Actor::spawn(None, Silent, ()).await.unwrap();
        client.stop_and_wait(None, None).await.unwrap();
        let router: Arc<ReplyRouter<credentials_agent_common::escrow_key::EscrowKeyReply>> =
            Arc::new(ReplyRouter::new());
        let outcome = request_reply(
            &client,
            &router,
            CREDENTIALS_ESCROW_KEY_REQUESTS_TOPIC,
            "test",
            EscrowKeyRequest,
            Duration::from_secs(30),
        )
        .await;
        assert!(
            matches!(outcome, Err(CryptoError::BrokerUnreachable(_))),
            "{outcome:?}"
        );
    }

    /// Intercepts CryptoActor's own outgoing publishes and answers
    /// them exactly as the real Credentials Agent would, publishing
    /// its own real replies directly to `router` -- the same, real
    /// RouterActor CryptoActor itself registered its own reply
    /// topics with at pre_start. Mirrors the earlier, real,
    /// broadcast-style FakeCredentialsAgent exactly in every other
    /// respect; only the delivery mechanism changed.
    struct FakeCredentialsAgent {
        router: ActorRef<polar_router::RouterMessage>,
        escrow_private_key: RsaPrivateKey,
        escrow_public_key_pem: String,
        /// Real, shared call count for the escrow-key branch
        /// specifically -- lets a test genuinely prove caching
        /// happened (queried exactly once across N stores), not just
        /// "repeated calls didn't crash."
        escrow_key_queries: Arc<std::sync::atomic::AtomicUsize>,
        /// The escrow key the actor's custody daemon holds (its PKCS#8), which a retrievable secret is encrypted
        /// to, as the real agent does. If None, a retrieval finds nothing.
        stored_escrow_keypair_pem: Option<String>,
        /// Captures the most recently decrypted plaintext from a
        /// genuine StoreSecretRequest -- lets a test assert on its
        /// own, specific expected content directly, now that this
        /// fake agent backs more than one kind of store (see the
        /// removed, hard-coded assertion's own doc comment above).
        /// Arc'd (not a bare Mutex) so the spawning test can hold its
        /// own, shared reference to read from after the actor's own
        /// handle() writes into it.
        last_stored_secret_plaintext: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
        /// If Some, AgentEscrowKeyRequests are answered with a real
        /// Found reply carrying this PEM -- a real, distinct
        /// recipient identity's own public key, standing in for
        /// EncryptForRecipient's own, real target. If None, answered
        /// with NotFound.
        recipient_public_key_pem: Option<String>,
        /// The recipient's key is handed out in a certificate another CA signed, as a forger would.
        forge_recipient_certificate: bool,
        /// Real, shared call count for the agent-escrow-key branch
        /// specifically -- same reasoning as escrow_key_queries,
        /// above, but for EncryptForRecipient's own, separate cache.
        agent_escrow_key_queries: Arc<std::sync::atomic::AtomicUsize>,
        /// Secrets the agent will hand back to RetrieveSecretRequests, by name, each encrypted to the
        /// escrow key the actor under test holds (`stored_escrow_keypair_pem`), as the real one does.
        retrievable_secrets: Vec<(String, Vec<u8>)>,
        /// If true every RetrieveSecretRequest is answered Denied, as policy would.
        deny_retrieval: bool,
        /// Every StoreSecretRequest, as (name, decrypted plaintext), in the order they arrived and whatever
        /// they were answered.
        stored: Option<StoreLog>,
        /// While true every store is answered Failed, as when the ledger cannot be appended to.
        failing_stores: Option<Arc<std::sync::atomic::AtomicBool>>,
        /// How the first stores are answered, in order; after that, Stored.
        store_script: std::sync::Mutex<std::collections::VecDeque<StoreScript>>,
    }

    /// What the fake credentials agent was asked to store, as (name, decrypted plaintext, labels), in arrival order.
    type StoreLog =
        Arc<std::sync::Mutex<Vec<(String, Vec<u8>, std::collections::BTreeMap<String, String>)>>>;

    /// A scripted answer to a store.
    #[derive(Clone, Copy)]
    enum StoreScript {
        Failed,
        Refused(StoreRefusalReason),
    }

    #[async_trait]
    impl Actor for FakeCredentialsAgent {
        type Msg = TcpClientMessage;
        type State = ();
        type Arguments = ();

        async fn pre_start(
            &self,
            _myself: ActorRef<Self::Msg>,
            _args: (),
        ) -> Result<Self::State, ActorProcessingErr> {
            Ok(())
        }

        async fn handle(
            &self,
            _myself: ActorRef<Self::Msg>,
            message: Self::Msg,
            _state: &mut Self::State,
        ) -> Result<(), ActorProcessingErr> {
            let TcpClientMessage::Publish { topic, payload, .. } = message else {
                return Ok(());
            };

            let route = |reply_topic: &str, bytes: Vec<u8>| {
                let _ = self.router.send_message(polar_router::RouterMessage::Route(
                    polar_router::IncomingMessage {
                        topic: reply_topic.to_string(),
                        payload: bytes,
                        published_by: None,
                        published_instance: None,
                        trace_ctx: None,
                    },
                ));
            };

            if topic == CREDENTIALS_ESCROW_KEY_REQUESTS_TOPIC {
                if let Ok(envelope) =
                    rkyv::from_bytes::<Envelope<EscrowKeyRequest>, rkyv::rancor::Error>(&payload)
                {
                    self.escrow_key_queries
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let reply = Envelope {
                        correlation_id: envelope.correlation_id,
                        payload: EscrowKeyReply {
                            public_key_pem: self.escrow_public_key_pem.clone(),
                        },
                    };
                    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&reply)
                        .unwrap()
                        .to_vec();
                    route(CREDENTIALS_ESCROW_KEY_REPLIES_TOPIC, bytes);
                }
            } else if topic == CREDENTIALS_STORE_SECRET_REQUESTS_TOPIC {
                if let Ok(envelope) =
                    rkyv::from_bytes::<Envelope<StoreSecretRequest>, rkyv::rancor::Error>(&payload)
                {
                    // A genuine, real check -- not just "did a
                    // message arrive," but "was the actual submitted
                    // ciphertext genuinely decryptable back to
                    // something," proving CryptoActor really
                    // encrypted to this key, not merely claimed to.
                    // Deliberately not asserting on a specific,
                    // literal plaintext here -- this same fake agent
                    // now backs multiple, different tests (ordinary
                    // secret storage, and the issuance-fallback
                    // flow's own, real private-key escrow step),
                    // each with genuinely different plaintext.
                    // Individual tests assert on their own, specific
                    // expected content directly, via the captured
                    // decrypted value below.
                    let decrypted = envelope
                        .payload
                        .secret
                        .decrypt(&self.escrow_private_key)
                        .expect("submitted secret must genuinely decrypt with the real key");
                    if let Ok(mut guard) = self.last_stored_secret_plaintext.lock() {
                        *guard = Some(decrypted.to_vec());
                    }
                    if let Some(stored) = &self.stored {
                        stored.lock().unwrap().push((
                            envelope.payload.name.clone(),
                            decrypted.to_vec(),
                            envelope.payload.labels.clone(),
                        ));
                    }
                    let failing = self
                        .failing_stores
                        .as_ref()
                        .is_some_and(|f| f.load(std::sync::atomic::Ordering::SeqCst));
                    let scripted = self.store_script.lock().unwrap().pop_front();
                    let answer = match (failing, scripted) {
                        (true, _) | (_, Some(StoreScript::Failed)) => StoreSecretReply::Failed {
                            detail: "scripted".to_string(),
                        },
                        (_, Some(StoreScript::Refused(reason))) => {
                            StoreSecretReply::Refused { reason }
                        }
                        (false, None) => StoreSecretReply::Stored,
                    };

                    let reply = Envelope {
                        correlation_id: envelope.correlation_id,
                        payload: answer,
                    };
                    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&reply)
                        .unwrap()
                        .to_vec();
                    route(CREDENTIALS_STORE_SECRET_REPLIES_TOPIC, bytes);
                }
            } else if topic == CREDENTIALS_RETRIEVE_SECRET_REQUESTS_TOPIC {
                if let Ok(envelope) = rkyv::from_bytes::<
                    Envelope<credentials_agent_common::retrieve_secret::RetrieveSecretRequest>,
                    rkyv::rancor::Error,
                >(&payload)
                {
                    use credentials_agent_common::retrieve_secret::RetrieveSecretReply;
                    let found = self
                        .retrievable_secrets
                        .iter()
                        .find(|(name, _)| *name == envelope.payload.name);
                    let answer = if self.deny_retrieval {
                        RetrieveSecretReply::Denied {
                            reason: "policy says no".to_string(),
                        }
                    } else if let (Some((_, plaintext)), Some(pem)) =
                        (found, &self.stored_escrow_keypair_pem)
                    {
                        // To the actor's own escrow key, as the real agent does: P-256, the custody daemon's.
                        let public = polar_custody::escrow::EscrowKey::from_pkcs8_pem(pem)
                            .unwrap()
                            .public_key_pem()
                            .unwrap();
                        RetrieveSecretReply::Found {
                            secret: EscrowedSecret::encrypt(plaintext, &public).unwrap(),
                        }
                    } else {
                        RetrieveSecretReply::NotFound
                    };
                    let reply = Envelope {
                        correlation_id: envelope.correlation_id,
                        payload: answer,
                    };
                    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&reply)
                        .unwrap()
                        .to_vec();
                    route(CREDENTIALS_RETRIEVE_SECRET_REPLIES_TOPIC, bytes);
                }
            } else if topic == CREDENTIALS_AGENT_ESCROW_KEY_REQUESTS_TOPIC
                && let Ok(envelope) = rkyv::from_bytes::<
                    Envelope<AgentEscrowKeyRequest>,
                    rkyv::rancor::Error,
                >(&payload)
            {
                self.agent_escrow_key_queries
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let reply_payload = match &self.recipient_public_key_pem {
                    // The key, in the escrow certificate cert-issuer would have signed for the recipient.
                    Some(pem) => AgentEscrowKeyReply::Found {
                        public_key_pem: pem.clone(),
                        certificate_pem: escrow_certificate(
                            &envelope.payload.identity,
                            pem,
                            if self.forge_recipient_certificate {
                                forger_ca()
                            } else {
                                test_ca()
                            },
                        ),
                    },
                    None => AgentEscrowKeyReply::NotFound,
                };
                let reply = Envelope {
                    correlation_id: envelope.correlation_id,
                    payload: reply_payload,
                };
                let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&reply)
                    .unwrap()
                    .to_vec();
                route(CREDENTIALS_AGENT_ESCROW_KEY_REPLIES_TOPIC, bytes);
            }

            Ok(())
        }
    }

    async fn spawn_crypto_actor_with_fake_credentials_agent()
    -> (ActorRef<CryptoMessage>, Arc<std::sync::atomic::AtomicUsize>) {
        spawn_crypto_actor_with_fake_credentials_agent_configured(
            FakeCredentialsAgentConfig::default(),
        )
        .await
        .0
    }

    /// Configures the shared FakeCredentialsAgent's own, real behavior
    /// -- see each field's own doc comment (on FakeCredentialsAgent
    /// itself) for exactly what each one controls.
    #[derive(Default)]
    struct FakeCredentialsAgentConfig {
        stored_escrow_keypair_pem: Option<String>,
        recipient_public_key_pem: Option<String>,
        forge_recipient_certificate: bool,
        /// The custody daemon's socket, when the actor's pod has one: without it the actor has no escrow key.
        custody_socket: Option<String>,
        /// The identity in the actor's certificate; unique per actor when not given.
        identity: Option<String>,
        /// Secrets the fake credentials agent will hand back, by name.
        retrievable_secrets: Vec<(String, Vec<u8>)>,
        /// Every retrieval is denied by policy.
        deny_retrieval: bool,
        stored: Option<StoreLog>,
        failing_stores: Option<Arc<std::sync::atomic::AtomicBool>>,
        store_script: Vec<StoreScript>,
        /// The pass the actor is started with, for a test of the port.
        credential_pass: Option<CredentialPass>,
    }

    /// pre_start now derives its own identity by reading a real,
    /// mounted TLS_CLIENT_CERT -- this builds a real, temporary,
    /// self-signed certificate carrying "test-agent" as its own
    /// identity SAN (mirroring extract_own_identity's own, real
    /// test fixtures directly), writes it to a real, temporary file,
    /// and hands the actor its path in its settings, so every test in this module
    /// continues to genuinely exercise "test-agent" as this actor's
    /// own identity, exactly as before this migration.
    /// The CA the test actor pins, and one that is not it.
    fn test_ca() -> &'static (rcgen::Issuer<'static, rcgen::KeyPair>, String) {
        static CA: std::sync::OnceLock<(rcgen::Issuer<'static, rcgen::KeyPair>, String)> =
            std::sync::OnceLock::new();
        CA.get_or_init(new_ca)
    }

    fn forger_ca() -> &'static (rcgen::Issuer<'static, rcgen::KeyPair>, String) {
        static CA: std::sync::OnceLock<(rcgen::Issuer<'static, rcgen::KeyPair>, String)> =
            std::sync::OnceLock::new();
        CA.get_or_init(new_ca)
    }

    fn new_ca() -> (rcgen::Issuer<'static, rcgen::KeyPair>, String) {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Polar Internal CA");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        let pem = params.self_signed(&key).unwrap().pem();
        (rcgen::Issuer::new(params, key), pem)
    }

    /// Where the test CA is written for the actor to pin.
    fn test_ca_file() -> std::path::PathBuf {
        static FILE: std::sync::OnceLock<tempfile::TempPath> = std::sync::OnceLock::new();
        FILE.get_or_init(|| {
            let file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(file.path(), &test_ca().1).unwrap();
            file.into_temp_path()
        })
        .to_path_buf()
    }

    /// An escrow certificate (`CertType::Service`) `ca` signs for `identity`, holding `public_key_pem`.
    fn escrow_certificate(
        identity: &str,
        public_key_pem: &str,
        ca: &(rcgen::Issuer<'static, rcgen::KeyPair>, String),
    ) -> String {
        let mut params = rcgen::CertificateParams::new(vec![identity.to_string()]).unwrap();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::EmailProtection];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(1);
        params.not_after = now + time::Duration::hours(1);
        let subject = rcgen::SubjectPublicKeyInfo::from_pem(public_key_pem).unwrap();
        params.signed_by(&subject, &ca.0).unwrap().pem()
    }

    fn write_test_agent_certificate(identity: &str) -> tempfile::NamedTempFile {
        let mut rng = rand::rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let private_key_pem =
            rsa::pkcs8::EncodePrivateKey::to_pkcs8_pem(&private_key, rsa::pkcs8::LineEnding::LF)
                .unwrap();
        let key_pair = rcgen::KeyPair::from_pem(&private_key_pem).unwrap();
        let params = rcgen::CertificateParams::new(vec![identity.to_string()]).unwrap();
        let certificate_pem = params.self_signed(&key_pair).unwrap().pem();

        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), certificate_pem).unwrap();
        file
    }

    async fn spawn_crypto_actor_with_fake_credentials_agent_configured(
        config: FakeCredentialsAgentConfig,
    ) -> (
        (ActorRef<CryptoMessage>, Arc<std::sync::atomic::AtomicUsize>),
        Arc<std::sync::Mutex<Option<Vec<u8>>>>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let (private_key, public_key_pem) = test_credentials_agent_keypair();
        let escrow_key_queries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let agent_escrow_key_queries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let last_stored_secret_plaintext = Arc::new(std::sync::Mutex::new(None));

        let (router, _) = Actor::spawn(None, polar_router::RouterActor, ())
            .await
            .unwrap();

        let (fake_agent, _) = Actor::spawn(
            None,
            FakeCredentialsAgent {
                router: router.clone(),
                escrow_private_key: private_key,
                escrow_public_key_pem: public_key_pem,
                escrow_key_queries: escrow_key_queries.clone(),
                stored_escrow_keypair_pem: config.stored_escrow_keypair_pem,
                last_stored_secret_plaintext: last_stored_secret_plaintext.clone(),
                recipient_public_key_pem: config.recipient_public_key_pem,
                forge_recipient_certificate: config.forge_recipient_certificate,
                agent_escrow_key_queries: agent_escrow_key_queries.clone(),
                retrievable_secrets: config.retrievable_secrets,
                deny_retrieval: config.deny_retrieval,
                stored: config.stored,
                failing_stores: config.failing_stores,
                store_script: std::sync::Mutex::new(config.store_script.into_iter().collect()),
            },
            (),
        )
        .await
        .unwrap();

        // Each actor gets an identity of its own, so the names its secrets are escrowed under are its own.
        let identity = config
            .identity
            .clone()
            .unwrap_or_else(|| format!("test-agent-{}", uuid::Uuid::new_v4()));
        let own_cert_file = write_test_agent_certificate(&identity);

        let args = CryptoActorArgs::new(fake_agent, router)
            .with_settings(environment::CryptoSettings {
                own_certificate_path: own_cert_file.path().to_string_lossy().into_owned(),
                custody_socket: config.custody_socket.clone(),
                ca_cert_path: test_ca_file().to_string_lossy().into_owned(),
                ..Default::default()
            })
            .with_escrow_retry(
                std::time::Duration::from_millis(5),
                std::time::Duration::from_millis(20),
            );
        let args = match config.credential_pass.clone() {
            Some(pass) => args.with_credential_pass(pass),
            None => args,
        };
        let (crypto_actor, _) = Actor::spawn(None, CryptoActor, args).await.unwrap();

        // own_cert_file must outlive pre_start's own, real read of it
        // above -- explicitly kept alive until here, then dropped
        // (and its own, temp file deleted) only now.
        drop(own_cert_file);

        (
            (crypto_actor, escrow_key_queries),
            last_stored_secret_plaintext,
            agent_escrow_key_queries,
        )
    }

    /// Stops the actor and waits for it, so its `post_stop` has wiped what it held before the test ends.
    async fn stop_and_release_key(actor: &ActorRef<CryptoMessage>) {
        actor
            .stop_and_wait(None, Some(std::time::Duration::from_secs(5)))
            .await
            .unwrap();
    }

    /// A custody daemon on a socket in a directory of its own, as a pod's is, whose custodian has fetched the escrow
    /// key: P-256, as every agent's is (docs/architecture/key-custody.md, "Part A's bootstrap: the custodian"). The
    /// directory is returned to be kept for as long as the socket is used; the key's PKCS#8 is what the fake
    /// credentials agent encrypts a retrievable secret to, as the real one encrypts to the escrow certificate's key.
    fn custody_daemon_holding_an_escrow_key() -> CustodyDaemon {
        use polar_custody::custody::{Custody as Daemon, Roles};
        use polar_custody::protocol::{Reply, Request, Slot};
        use polar_custody::server::{Callers, bind, serve};
        use std::os::unix::fs::MetadataExt as _;
        let (issuer, ca_pem) = new_ca();
        let mut custody = Daemon::new(&ca_pem).unwrap();
        let installer = Roles {
            installer: true,
            workload: false,
        };
        let workload = "test-agent-daemon.polar.serviceaccount.cluster.local";
        let Reply::Csr(csr) = custody.handle(
            installer,
            Request::MakeCsr {
                slot: Slot::Custodian,
                identity: format!("custody.{workload}"),
                names: vec![],
            },
            0,
        ) else {
            panic!("a CSR")
        };
        let mut request = rcgen::CertificateSigningRequestParams::from_pem(&csr).unwrap();
        request
            .params
            .subject_alt_names
            .push(rcgen::SanType::URI("p:custody:escrow".try_into().unwrap()));
        let at = time::OffsetDateTime::now_utc();
        request.params.not_before = at - time::Duration::minutes(1);
        request.params.not_after = at + time::Duration::hours(1);
        let now = at.unix_timestamp();
        let certificate = request.signed_by(&issuer).unwrap().pem();
        assert_eq!(
            custody.handle(
                installer,
                Request::Install {
                    slot: Slot::Custodian,
                    chain_pem: vec![certificate]
                },
                now
            ),
            Reply::Installed
        );
        assert_eq!(
            custody.handle(
                installer,
                Request::Bootstrap {
                    identity: workload.to_string(),
                    client: false,
                    server: None,
                    escrow: true,
                    signing: false,
                },
                now,
            ),
            Reply::Installed
        );
        // A P-256 key, as the custodian would have fetched.
        let pkcs8 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .unwrap()
            .serialize_pem();
        let public_pem = polar_custody::escrow::EscrowKey::from_pkcs8_pem(&pkcs8)
            .unwrap()
            .public_key_pem()
            .unwrap();
        custody.hold_retrieved_escrow(&pkcs8).unwrap();
        custody.set_ready();
        let dir = tempfile::TempDir::new().unwrap();
        let uid = std::fs::metadata(dir.path()).unwrap().uid();
        let socket = dir.path().join("custody.sock");
        tokio::spawn(serve(
            bind(&socket).unwrap(),
            Arc::new(std::sync::RwLock::new(custody)),
            Arc::new(Callers {
                installer_uid: uid,
                workload_uids: vec![uid],
            }),
        ));
        CustodyDaemon {
            _dir: dir,
            socket: socket.display().to_string(),
            pkcs8,
            public_pem,
        }
    }

    /// A custody daemon serving, for as long as this is kept.
    struct CustodyDaemon {
        _dir: tempfile::TempDir,
        socket: String,
        pkcs8: String,
        public_pem: String,
    }

    /// An actor whose escrow key its custody daemon holds, beside a credentials agent holding `secrets` for it.
    async fn crypto_actor_holding_an_escrow_key(
        secrets: &[(&str, &[u8])],
        deny_retrieval: bool,
    ) -> (ActorRef<CryptoMessage>, CustodyDaemon) {
        let daemon = custody_daemon_holding_an_escrow_key();
        let ((crypto_actor, _), _, _) =
            spawn_crypto_actor_with_fake_credentials_agent_configured(FakeCredentialsAgentConfig {
                stored_escrow_keypair_pem: Some(daemon.pkcs8.clone()),
                custody_socket: Some(daemon.socket.clone()),
                retrievable_secrets: secrets
                    .iter()
                    .map(|(n, v)| (n.to_string(), v.to_vec()))
                    .collect(),
                deny_retrieval,
                ..Default::default()
            })
            .await;
        (crypto_actor, daemon)
    }

    /// docs/architecture/key-custody.md, "Part A's bootstrap: the custodian": the escrow key is the custody daemon's,
    /// P-256; a secret retrieved is opened through it, the actor never holding the key, and a secret sealed under
    /// RSA-OAEP, to a key no agent holds now, is refused.
    #[tokio::test(flavor = "multi_thread")]
    async fn with_a_custody_daemon_a_retrieved_secret_is_opened_through_it_and_an_rsa_sealed_one_is_refused()
     {
        let (crypto_actor, _daemon) =
            crypto_actor_holding_an_escrow_key(&[("github-sei", b"a token")], false).await;
        let opened = ractor::call!(crypto_actor, |reply| CryptoMessage::RetrieveSecret {
            name: "github-sei".to_string(),
            reply,
        })
        .unwrap();
        assert_eq!(
            opened.unwrap().as_deref().map(|v| v.as_slice()),
            Some(&b"a token"[..])
        );
        let rsa = RsaPrivateKey::new(&mut rand::rng(), 2048).unwrap();
        let rsa_public = rsa::pkcs8::EncodePublicKey::to_public_key_pem(
            &rsa.to_public_key(),
            rsa::pkcs8::LineEnding::LF,
        )
        .unwrap();
        let sealed = rkyv::to_bytes::<rkyv::rancor::Error>(
            &EscrowedSecret::encrypt_bound(b"a token", &rsa_public, b"ctx").unwrap(),
        )
        .unwrap()
        .to_vec();
        let refused = ractor::call!(crypto_actor, |reply| CryptoMessage::RegisterSecret {
            name: "old".to_string(),
            section: "s".to_string(),
            secret: sealed,
            context: b"ctx".to_vec(),
            username: None,
            binding: token_binding("github.com"),
            reply,
        })
        .unwrap();
        assert!(
            matches!(&refused, Err(CryptoError::DecryptFailed(why)) if why.contains("P-256")),
            "{refused:?}"
        );
        crypto_actor.stop_and_wait(None, None).await.unwrap();
    }

    /// With no custody daemon there is no escrow key (docs/architecture/key-custody.md, step 9): nothing sealed to it
    /// opens, the actor says why at once, and it never asks the credentials agent for the key itself, which only the
    /// custodian may (a request it asked would wait out its reply timeout, unanswered).
    #[tokio::test]
    async fn without_a_custody_daemon_nothing_sealed_to_the_escrow_key_opens_and_the_key_is_never_asked_for()
     {
        let daemon = custody_daemon_holding_an_escrow_key();
        let pass = CredentialPass::new();
        let ((crypto_actor, _), _, _) =
            spawn_crypto_actor_with_fake_credentials_agent_configured(FakeCredentialsAgentConfig {
                stored_escrow_keypair_pem: Some(daemon.pkcs8.clone()),
                // Nothing held: a retrieval asked would come back NotFound, not refused.
                credential_pass: Some(pass.clone()),
                ..Default::default()
            })
            .await;
        let at_once = std::time::Duration::from_secs(5);
        let retrieved = tokio::time::timeout(at_once, async {
            ractor::call!(crypto_actor, |reply| CryptoMessage::RetrieveSecret {
                name: "github-sei".to_string(),
                reply,
            })
        })
        .await
        .expect("refused at once")
        .unwrap();
        assert!(
            matches!(retrieved, Err(CryptoError::NoEscrowKey)),
            "{retrieved:?}"
        );
        let sealed = rkyv::to_bytes::<rkyv::rancor::Error>(
            &EscrowedSecret::encrypt_bound(b"a token", &daemon.public_pem, b"ctx").unwrap(),
        )
        .unwrap()
        .to_vec();
        let registered = tokio::time::timeout(at_once, async {
            ractor::call!(crypto_actor, |reply| CryptoMessage::RegisterSecret {
                name: "github-sei".to_string(),
                section: "s".to_string(),
                secret: sealed,
                context: b"ctx".to_vec(),
                username: None,
                binding: token_binding("github.com"),
                reply,
            })
        })
        .await
        .expect("refused at once")
        .unwrap();
        assert!(
            matches!(registered, Err(CryptoError::NoEscrowKey)),
            "{registered:?}"
        );
        let git = CredentialPort::new(crypto_actor.clone(), pass)
            .git("github-sei".to_string(), "github.com".to_string())
            .await;
        assert!(
            matches!(git, Err(CryptoError::SecretNotRegistered(_))),
            "nothing registered"
        );
        stop_and_release_key(&crypto_actor).await;
    }

    #[tokio::test]
    async fn retrieve_secret_returns_what_the_credentials_agent_encrypted_to_the_escrow_key() {
        let (crypto, _daemon) =
            crypto_actor_holding_an_escrow_key(&[("github-sei", b"a token")], false).await;
        let result = ractor::call!(crypto, |reply| CryptoMessage::RetrieveSecret {
            name: "github-sei".to_string(),
            reply,
        })
        .unwrap();
        assert_eq!(
            result.unwrap().as_deref().map(|v| v.as_slice()),
            Some(&b"a token"[..])
        );
        stop_and_release_key(&crypto).await;
    }

    #[tokio::test]
    async fn retrieve_secret_for_a_name_never_stored_is_none() {
        let (crypto, _daemon) =
            crypto_actor_holding_an_escrow_key(&[("github-sei", b"a token")], false).await;
        let result = ractor::call!(crypto, |reply| CryptoMessage::RetrieveSecret {
            name: "other".to_string(),
            reply,
        })
        .unwrap();
        assert!(matches!(result, Ok(None)), "{result:?}");
        stop_and_release_key(&crypto).await;
    }

    #[tokio::test]
    async fn retrieve_secret_that_policy_denies_is_an_error_that_says_so() {
        let (crypto, _daemon) =
            crypto_actor_holding_an_escrow_key(&[("github-sei", b"a token")], true).await;
        let result = ractor::call!(crypto, |reply| CryptoMessage::RetrieveSecret {
            name: "github-sei".to_string(),
            reply,
        })
        .unwrap();
        assert!(
            matches!(result, Err(CryptoError::RetrieveSecretDenied(_))),
            "{result:?}"
        );
        stop_and_release_key(&crypto).await;
    }

    #[tokio::test]
    async fn store_secret_round_trips_through_a_real_encrypt_and_a_real_fake_broker() {
        let (crypto_actor, _escrow_key_queries) =
            spawn_crypto_actor_with_fake_credentials_agent().await;

        let result = ractor::call!(crypto_actor, |reply| CryptoMessage::StoreSecret {
            name: "gitlab-token".to_string(),
            plaintext: b"a real secret from a real actor".to_vec(),
            reply,
        })
        .unwrap();

        assert!(result.is_ok(), "expected Ok(()), got {result:?}");
        stop_and_release_key(&crypto_actor).await;
    }

    #[tokio::test]
    async fn escrow_key_is_genuinely_cached_after_the_first_store() {
        let (crypto_actor, escrow_key_queries) =
            spawn_crypto_actor_with_fake_credentials_agent().await;

        for _ in 0..3 {
            let result = ractor::call!(crypto_actor, |reply| CryptoMessage::StoreSecret {
                name: "gitlab-token".to_string(),
                plaintext: b"a real secret from a real actor".to_vec(),
                reply,
            })
            .unwrap();
            assert!(result.is_ok(), "expected Ok(()), got {result:?}");
        }

        // The real proof: exactly one query across three stores, not
        // "it didn't crash on repeat calls."
        assert_eq!(
            escrow_key_queries.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "escrow key should be queried exactly once, then served from cache"
        );
        stop_and_release_key(&crypto_actor).await;
    }
    // ---- registered secrets, and what is done with them ---------------------------------------------------------

    use registry::{GitCredential, RecordError, SecretBinding, SecretKind, UseRefusal};

    /// An actor whose custody daemon holds an escrow key a test can encrypt to, beside a credentials agent that records
    /// every store.
    struct Rig {
        actor: ActorRef<CryptoMessage>,
        port: CredentialPort,
        _daemon: CustodyDaemon,
        public_pem: String,
        identity: String,
        stored: StoreLog,
        failing: Arc<std::sync::atomic::AtomicBool>,
        key_queries: Arc<std::sync::atomic::AtomicUsize>,
    }

    /// `held` are secrets the credentials agent holds for this identity, by short name.
    async fn rig(
        script: Vec<StoreScript>,
        held: Vec<(&str, Vec<u8>)>,
        deny_retrieval: bool,
    ) -> Rig {
        rig_configured(script, held, deny_retrieval, None).await
    }

    async fn rig_configured(
        script: Vec<StoreScript>,
        held: Vec<(&str, Vec<u8>)>,
        deny_retrieval: bool,
        credential_pass: Option<CredentialPass>,
    ) -> Rig {
        let daemon = custody_daemon_holding_an_escrow_key();
        let public_pem = daemon.public_pem.clone();
        let credential_pass = credential_pass.unwrap_or_default();
        let identity = format!("test-agent-{}", uuid::Uuid::new_v4());
        let stored = Arc::new(std::sync::Mutex::new(Vec::new()));
        let failing = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let retrievable_secrets = held
            .into_iter()
            .map(|(name, bytes)| (format!("{identity}/{name}"), bytes))
            .collect();
        let ((actor, key_queries), _, _) =
            spawn_crypto_actor_with_fake_credentials_agent_configured(FakeCredentialsAgentConfig {
                stored_escrow_keypair_pem: Some(daemon.pkcs8.clone()),
                custody_socket: Some(daemon.socket.clone()),
                identity: Some(identity.clone()),
                retrievable_secrets,
                deny_retrieval,
                stored: Some(stored.clone()),
                failing_stores: Some(failing.clone()),
                store_script: script,
                credential_pass: Some(credential_pass.clone()),
                ..Default::default()
            })
            .await;
        Rig {
            port: CredentialPort::new(actor.clone(), credential_pass),
            actor,
            _daemon: daemon,
            public_pem,
            identity,
            stored,
            failing,
            key_queries,
        }
    }

    /// A rig whose actor was started with `pass`.
    async fn rig_with_pass(pass: CredentialPass) -> Rig {
        rig_configured(vec![], vec![], false, Some(pass)).await
    }

    fn escrowed_bytes(rig: &Rig, plaintext: &[u8], context: &[u8]) -> Vec<u8> {
        let escrowed = EscrowedSecret::encrypt_bound(plaintext, &rig.public_pem, context).unwrap();
        rkyv::to_bytes::<rkyv::rancor::Error>(&escrowed)
            .unwrap()
            .to_vec()
    }

    /// The `Authorization` a request carries when the port sends it with the credential `name` to `host`: a real request,
    /// to a stand-in server reached under the host's name, so the binding is held to the host as for any request.
    async fn sent_authorization(
        port: &CredentialPort,
        name: &str,
        host: &str,
    ) -> Result<String, sending::SendError> {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::any};
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let address = *server.address();
        let client = reqwest::Client::builder()
            .resolve(host, address)
            .build()
            .unwrap();
        let request = client
            .get(format!("http://{host}:{}/x", address.port()))
            .build()
            .unwrap();
        let sent = port.send_http(name.to_string(), request, client).await?;
        assert_eq!(sent.response.status(), reqwest::StatusCode::OK);
        let received = server.received_requests().await.unwrap();
        Ok(received[0]
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string())
    }

    fn token_binding(host: &str) -> SecretBinding {
        SecretBinding {
            host_pattern: host.to_string(),
            kind: SecretKind::Token,
            username: None,
            host_key: None,
        }
    }

    /// The section the tests register under unless a test says otherwise.
    const SECTION: &str = "credentials";

    /// A binding's user name, as a section hands it on: sealed under its own context, and out of the binding.
    fn sealed_username(
        rig: &Rig,
        context: &[u8],
        mut binding: SecretBinding,
    ) -> (Option<SealedPart>, SecretBinding) {
        let username = binding.username.take().map(|u| {
            let context = [context, b"|username"].concat();
            SealedPart {
                ciphertext: escrowed_bytes(rig, u.as_bytes(), &context),
                context,
            }
        });
        (username, binding)
    }

    async fn register_in(
        rig: &Rig,
        section: &str,
        name: &str,
        plaintext: &[u8],
        context: &[u8],
        binding: SecretBinding,
    ) -> Result<(), CryptoError> {
        let secret = escrowed_bytes(rig, plaintext, context);
        let (username, binding) = sealed_username(rig, context, binding);
        ractor::call!(rig.actor, |reply| CryptoMessage::RegisterSecret {
            name: name.to_string(),
            section: section.to_string(),
            secret,
            context: context.to_vec(),
            username,
            binding,
            reply,
        })
        .unwrap()
    }

    async fn replace_section(rig: &Rig, section: &str, keep: &[&str]) -> Vec<String> {
        ractor::call!(rig.actor, |reply| CryptoMessage::ReplaceSection {
            section: section.to_string(),
            keep: keep.iter().map(|k| k.to_string()).collect(),
            reply,
        })
        .unwrap()
    }

    async fn register(
        rig: &Rig,
        name: &str,
        plaintext: &[u8],
        context: &[u8],
        binding: SecretBinding,
    ) -> Result<(), CryptoError> {
        let secret = escrowed_bytes(rig, plaintext, context);
        let (username, binding) = sealed_username(rig, context, binding);
        ractor::call!(rig.actor, |reply| CryptoMessage::RegisterSecret {
            name: name.to_string(),
            section: SECTION.to_string(),
            secret,
            context: context.to_vec(),
            username,
            binding,
            reply,
        })
        .unwrap()
    }

    async fn git_credential(
        rig: &Rig,
        name: &str,
        host: &str,
    ) -> Result<GitCredential, CryptoError> {
        git_presents(&rig.port, name, host).await
    }

    /// What git presents to `host` with the credential `name`: an ssh key as it is given; anything else as a stand-in
    /// for `host` receives it, from a request the actor sends. The binding is checked for `host` as given first, so a
    /// host no request could name (one with a port) is refused as it would be.
    async fn git_presents(
        port: &CredentialPort,
        name: &str,
        host: &str,
    ) -> Result<GitCredential, CryptoError> {
        use base64::Engine;
        let kind = port.git_kind(name.to_string(), host.to_string()).await?;
        if kind == registry::SecretKind::SshKey {
            return port.git(name.to_string(), host.to_string()).await;
        }
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let client = reqwest::Client::builder()
            .resolve(host, *server.address())
            .build()
            .unwrap();
        let request = client
            .get(format!(
                "http://{host}:{}/r.git/info/refs",
                server.address().port()
            ))
            .build()
            .unwrap();
        port.send_git(name.to_string(), request, client)
            .await
            .map_err(|e| match e {
                sending::SendError::Refused(refused) => refused,
                other => panic!("the stand-in did not answer: {other}"),
            })?;
        let received = server.received_requests().await.unwrap();
        let login = received[0].headers["authorization"].to_str().unwrap();
        let login = base64::engine::general_purpose::STANDARD
            .decode(
                login
                    .strip_prefix("Basic ")
                    .expect("git logs in with Basic"),
            )
            .unwrap();
        let (username, secret) = std::str::from_utf8(&login)
            .unwrap()
            .split_once(':')
            .unwrap();
        Ok(GitCredential {
            kind,
            username: username.to_string(),
            secret: Zeroizing::new(secret.as_bytes().to_vec()),
            host_keys: Vec::new(),
        })
    }

    async fn load(rig: &Rig, name: &str) -> Result<bool, CryptoError> {
        ractor::call!(rig.actor, |reply| CryptoMessage::LoadSecret {
            name: name.to_string(),
            section: SECTION.to_string(),
            reply,
        })
        .unwrap()
    }

    async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
        for _ in 0..600 {
            if condition() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("timed out waiting for {what}");
    }

    async fn settle() {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }

    fn stored_len(rig: &Rig) -> usize {
        rig.stored.lock().unwrap().len()
    }

    fn secret_of(record: &[u8]) -> String {
        String::from_utf8(registry::from_escrow_form(record).unwrap().1.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn a_registered_secret_is_given_to_git_for_a_bound_host_and_never_for_another() {
        let r = rig(vec![], vec![], false).await;
        register(
            &r,
            "github",
            b"ghp-token",
            b"ctx-1",
            token_binding("github.com"),
        )
        .await
        .unwrap();
        let got = git_credential(&r, "github", "github.com").await.unwrap();
        assert_eq!(got.username, "oauth2");
        assert_eq!(got.secret.as_slice(), b"ghp-token");
        for host in ["evil.example.org", "github.com.evil.org", "github.com:443"] {
            let refused = git_credential(&r, "github", host).await;
            assert!(
                matches!(refused, Err(CryptoError::Use(UseRefusal::HostNotBound))),
                "{host}: {refused:?}"
            );
        }
        stop_and_release_key(&r.actor).await;
    }

    /// A credential is used and never read. Its value decides, so one that is not registered in this run, because the agent
    /// has just started or because it was withdrawn, is refused as one that is. What the same route was asked for by any
    /// other secret still comes back.
    #[tokio::test]
    async fn a_credentials_own_record_is_refused_however_it_is_asked_for() {
        let record =
            registry::escrow_form(&token_binding("jira.example.org"), b"the-token").unwrap();
        let (crypto_actor, _daemon) = crypto_actor_holding_an_escrow_key(
            &[("agent/jira", &record[..]), ("plain", b"the-other-value")],
            false,
        )
        .await;
        let ask = |name: &'static str| {
            let actor = crypto_actor.clone();
            async move {
                ractor::call!(actor, |reply| CryptoMessage::RetrieveSecret {
                    name: name.to_string(),
                    reply,
                })
                .unwrap()
            }
        };
        let refused = ask("agent/jira").await;
        assert!(
            matches!(refused, Err(CryptoError::IsACredential)),
            "{refused:?}"
        );
        let plain = ask("plain").await.unwrap();
        assert_eq!(
            plain.as_deref().map(|value| value.as_slice()),
            Some(&b"the-other-value"[..])
        );
        stop_and_release_key(&crypto_actor).await;
    }

    /// The route that is internal does read that record: an agent gets its own secret back that way, and only the port uses it.
    #[tokio::test]
    async fn loading_a_credentials_record_registers_it_for_the_port_and_shows_it_to_nobody() {
        let record =
            registry::escrow_form(&token_binding("jira.example.org"), b"the-token").unwrap();
        let r = rig(vec![], vec![("jira", record.to_vec())], false).await;
        assert!(load(&r, "jira").await.unwrap());
        let git = git_presents(&r.port, "jira", "jira.example.org")
            .await
            .unwrap();
        assert_eq!(git.secret.as_slice(), b"the-token");
        stop_and_release_key(&r.actor).await;
    }

    /// The sibling for an HTTP API: the same registered secret, given as a bearer token for a bound host only.
    #[tokio::test]
    async fn a_registered_secret_is_given_to_an_http_request_for_a_bound_host_and_never_for_another()
     {
        let r = rig(vec![], vec![], false).await;
        register(
            &r,
            "jira",
            b"pat-token",
            b"ctx-1",
            token_binding("jira.example.org"),
        )
        .await
        .unwrap();
        let ask = |host: &str| r.port.http_kind("jira".to_string(), host.to_string());
        assert_eq!(
            ask("jira.example.org").await.unwrap(),
            sending::HttpKind::Bearer
        );
        assert_eq!(
            sent_authorization(&r.port, "jira", "jira.example.org")
                .await
                .unwrap(),
            "Bearer pat-token"
        );
        for host in [
            "evil.example.org",
            "jira.example.org.evil.org",
            "jira.example.org:443",
        ] {
            let refused = ask(host).await;
            assert!(
                matches!(refused, Err(CryptoError::Use(UseRefusal::HostNotBound))),
                "{host}: {refused:?}"
            );
        }
        let unknown = r
            .port
            .http_kind("other".to_string(), "jira.example.org".to_string())
            .await;
        assert!(
            matches!(unknown, Err(CryptoError::SecretNotRegistered(_))),
            "{unknown:?}"
        );
        stop_and_release_key(&r.actor).await;
    }

    /// The port the protocol handlers use (docs/architecture/protocol-handlers.md, "No way to the credential from domain
    /// code"): with the pass this actor was started with it answers as `HttpCredential` and `GitCredential` do, binding and
    /// all, and with any other pass it gives nothing, whoever asks and whatever they name.
    #[tokio::test]
    async fn the_port_with_the_actors_own_pass_is_given_a_credential_for_a_bound_host() {
        let pass = CredentialPass::new();
        let r = rig_with_pass(pass.clone()).await;
        register(
            &r,
            "jira",
            b"pat-token",
            b"ctx-1",
            token_binding("jira.example.org"),
        )
        .await
        .unwrap();
        let port = CredentialPort::new(r.actor.clone(), pass);

        assert_eq!(
            sent_authorization(&port, "jira", "jira.example.org")
                .await
                .unwrap(),
            "Bearer pat-token"
        );
        let git = git_presents(&port, "jira", "jira.example.org")
            .await
            .unwrap();
        assert_eq!(git.secret.as_slice(), b"pat-token");

        for host in ["evil.example.org", "jira.example.org:443"] {
            let refused = port.http_kind("jira".to_string(), host.to_string()).await;
            assert!(
                matches!(refused, Err(CryptoError::Use(UseRefusal::HostNotBound))),
                "{host}: {refused:?}"
            );
            let refused = git_presents(&port, "jira", host).await;
            assert!(
                matches!(refused, Err(CryptoError::Use(UseRefusal::HostNotBound))),
                "{host}: {refused:?}"
            );
        }
        let unknown = port
            .http_kind("other".to_string(), "jira.example.org".to_string())
            .await;
        assert!(
            matches!(unknown, Err(CryptoError::SecretNotRegistered(_))),
            "{unknown:?}"
        );
        stop_and_release_key(&r.actor).await;
    }

    /// A registry's auth host, stood in for: it answers a login with `reply`, and the registry behind it takes only the
    /// token. The client reaches both under the bound host's name.
    async fn auth_host(
        reply: wiremock::ResponseTemplate,
    ) -> (wiremock::MockServer, reqwest::Client, String) {
        use wiremock::{Mock, MockServer, matchers::path};
        let server = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(reply)
            .mount(&server)
            .await;
        Mock::given(path("/v2/x"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let address = *server.address();
        let client = reqwest::Client::builder()
            .resolve("reg.example.org", address)
            .build()
            .unwrap();
        (
            server,
            client,
            format!("http://reg.example.org:{}", address.port()),
        )
    }

    async fn registry_rig() -> Rig {
        let r = rig(vec![], vec![], false).await;
        let binding = SecretBinding {
            username: Some("robot".to_string()),
            ..user_password("reg.example.org")
        };
        register(&r, "reg", b"login-pw", b"ctx", binding)
            .await
            .unwrap();
        r
    }

    /// Only an ssh key is given to git, until custody signs for it; a token or a password is sent with git's request,
    /// as git logs in (Basic, with `oauth2` for a token's user), and an ssh key never goes over https.
    #[tokio::test]
    async fn git_is_given_only_an_ssh_key_and_a_token_goes_with_its_request() {
        let r = rig(vec![], vec![], false).await;
        register(&r, "gh", b"t0ken", b"ctx-gh", token_binding("github.com"))
            .await
            .unwrap();
        let ssh = SecretBinding {
            host_pattern: "git.example.org".to_string(),
            kind: SecretKind::SshKey,
            username: None,
            host_key: Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
        };
        register(&r, "key", b"a-key", b"ctx-key", ssh)
            .await
            .unwrap();

        assert!(matches!(
            r.port.git("gh".into(), "github.com".into()).await,
            Err(CryptoError::Use(UseRefusal::SentNotGiven))
        ));
        assert_eq!(
            r.port
                .git_kind("gh".into(), "github.com".into())
                .await
                .unwrap(),
            SecretKind::Token
        );
        let token = git_presents(&r.port, "gh", "github.com").await.unwrap();
        assert_eq!(
            (token.username.as_str(), token.secret.as_slice()),
            ("oauth2", b"t0ken".as_slice())
        );

        let key = r
            .port
            .git("key".into(), "git.example.org".into())
            .await
            .unwrap();
        assert_eq!(
            (key.kind, key.secret.as_slice()),
            (SecretKind::SshKey, b"a-key".as_slice())
        );
        let request = reqwest::Client::new()
            .get("https://git.example.org/r.git/info/refs")
            .build()
            .unwrap();
        let sent = r
            .port
            .send_git("key".into(), request, reqwest::Client::new())
            .await;
        assert!(matches!(
            sent,
            Err(sending::SendError::Refused(CryptoError::Use(
                UseRefusal::NotForHttp
            )))
        ));
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn a_login_is_exchanged_for_a_token_the_actor_keeps_and_presents_by_its_handle() {
        use base64::Engine;
        let r = registry_rig().await;
        let (server, client, base) = auth_host(
            wiremock::ResponseTemplate::new(200).set_body_string(r#"{"token": "short-lived"}"#),
        )
        .await;
        let exchanged = r
            .port
            .exchange(
                "reg".into(),
                client.get(format!("{base}/token")).build().unwrap(),
                client.clone(),
            )
            .await
            .unwrap();
        assert_eq!(
            (exchanged.status, exchanged.kind),
            (reqwest::StatusCode::OK, sending::HttpKind::Basic)
        );
        let token = exchanged.token.expect("a token kept");
        let response = r
            .port
            .send_with_token(
                &token,
                client.get(format!("{base}/v2/x")).build().unwrap(),
                client.clone(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let received = server.received_requests().await.unwrap();
        let auth = |i: usize| {
            received[i]
                .headers
                .get("authorization")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        };
        assert_eq!(
            auth(0),
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode("robot:login-pw")
            )
        );
        assert_eq!(auth(1), "Bearer short-lived");

        // What a handle shows is its number, never the token.
        assert_eq!(format!("{token:?}"), format!("TokenHandle({})", token.id()));

        // A second login keeps a second token. Dropped, a handle's token is wiped: a handle of its number presents
        // nothing, and the other's still presents its own.
        let second = r
            .port
            .exchange(
                "reg".into(),
                client.get(format!("{base}/token")).build().unwrap(),
                client.clone(),
            )
            .await
            .unwrap()
            .token
            .expect("a second token kept");
        assert_ne!(token.id(), second.id());
        let (gone, kept) = (token.id(), second.id());
        drop(token);
        settle().await;
        let present = |id: u64| {
            let (port, client, base) = (r.port.clone(), client.clone(), base.clone());
            async move {
                let handle = TokenHandle::new(id, |_| {});
                port.send_with_token(
                    &handle,
                    client.get(format!("{base}/v2/x")).build().unwrap(),
                    client.clone(),
                )
                .await
            }
        };
        assert!(matches!(
            present(gone).await,
            Err(sending::SendError::Refused(
                CryptoError::SecretNotRegistered(_)
            ))
        ));
        assert_eq!(
            present(kept).await.unwrap().status(),
            reqwest::StatusCode::OK
        );
        drop(second);
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn an_auth_host_that_refuses_or_answers_with_no_token_keeps_nothing() {
        let r = registry_rig().await;
        let (_s, client, base) = auth_host(wiremock::ResponseTemplate::new(401)).await;
        let exchanged = r
            .port
            .exchange(
                "reg".into(),
                client.get(format!("{base}/token")).build().unwrap(),
                client,
            )
            .await
            .unwrap();
        assert_eq!(exchanged.status, reqwest::StatusCode::UNAUTHORIZED);
        assert!(exchanged.token.is_none());

        let no_token = "the registry's auth host did not answer with a token";
        for (body, said) in [
            (r#"{"nothing": 1}"#.to_string(), no_token),
            ("not json".to_string(), no_token),
            (
                "x".repeat(sending::MAX_TOKEN_REPLY + 1),
                "the registry's auth host answered with more than a token",
            ),
        ] {
            let (_s, client, base) =
                auth_host(wiremock::ResponseTemplate::new(200).set_body_string(body)).await;
            let refused = r
                .port
                .exchange(
                    "reg".into(),
                    client.get(format!("{base}/token")).build().unwrap(),
                    client,
                )
                .await;
            assert!(
                matches!(refused, Err(sending::SendError::Unreadable(why)) if why == said),
                "{said}"
            );
        }

        // A reply of exactly the bound is read.
        let token = r#"{"token": "t"}"#;
        let whole = format!(
            "{token}{}",
            " ".repeat(sending::MAX_TOKEN_REPLY - token.len())
        );
        let (_s, client, base) =
            auth_host(wiremock::ResponseTemplate::new(200).set_body_string(whole)).await;
        let exchanged = r
            .port
            .exchange(
                "reg".into(),
                client.get(format!("{base}/token")).build().unwrap(),
                client,
            )
            .await
            .unwrap();
        assert!(exchanged.token.is_some());
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn any_other_pass_is_refused_and_learns_nothing_of_the_credential() {
        let r = rig_with_pass(CredentialPass::new()).await;
        register(
            &r,
            "jira",
            b"pat-token",
            b"ctx-1",
            token_binding("jira.example.org"),
        )
        .await
        .unwrap();
        let forged = CredentialPort::new(r.actor.clone(), CredentialPass::new());

        // The same answer for a name that exists and one that does not, so a wrong pass cannot find out which.
        for name in ["jira", "other"] {
            let http = forged
                .http_kind(name.to_string(), "jira.example.org".to_string())
                .await;
            assert!(
                matches!(http, Err(CryptoError::NotThePort)),
                "{name}: {http:?}"
            );
            // Nothing is sent for a wrong pass: refused before any connection, the same for every name.
            let client = reqwest::Client::new();
            let request = || client.get("https://jira.example.org/x").build().unwrap();
            let sent = forged
                .send_http(name.to_string(), request(), client.clone())
                .await;
            assert!(
                matches!(
                    sent,
                    Err(sending::SendError::Refused(CryptoError::NotThePort))
                ),
                "{name}"
            );
            let exchanged = forged
                .exchange(name.to_string(), request(), client.clone())
                .await;
            assert!(
                matches!(
                    exchanged,
                    Err(sending::SendError::Refused(CryptoError::NotThePort))
                ),
                "{name}"
            );
            let git = forged
                .git(name.to_string(), "jira.example.org".to_string())
                .await;
            assert!(
                matches!(git, Err(CryptoError::NotThePort)),
                "{name}: {git:?}"
            );
            let kind = forged
                .git_kind(name.to_string(), "jira.example.org".to_string())
                .await;
            assert!(matches!(kind, Err(CryptoError::NotThePort)), "{name}");
            let request = reqwest::Client::new()
                .get("https://jira.example.org/r.git")
                .build()
                .unwrap();
            let sent = forged
                .send_git(name.to_string(), request, reqwest::Client::new())
                .await;
            assert!(
                matches!(
                    sent,
                    Err(sending::SendError::Refused(CryptoError::NotThePort))
                ),
                "{name}"
            );
        }
        let which = forged.bound_to("jira.example.org".to_string()).await;
        assert!(matches!(which, Err(CryptoError::NotThePort)), "{which:?}");
        stop_and_release_key(&r.actor).await;
    }

    /// Which secret a host is bound to is a question for the port, answered with a name: a request whose host decides its
    /// credential, as a registry's does.
    #[tokio::test]
    async fn the_port_says_which_secret_is_bound_to_a_host_by_its_name() {
        let pass = CredentialPass::new();
        let r = rig_with_pass(pass.clone()).await;
        for (name, pattern) in [("broad", "*.example.org"), ("close", "reg.example.org")] {
            register(
                &r,
                name,
                b"a-secret",
                name.as_bytes(),
                token_binding(pattern),
            )
            .await
            .unwrap();
        }
        let port = CredentialPort::new(r.actor.clone(), pass);
        for (host, name) in [
            ("reg.example.org", Some("close")),
            ("other.example.org", Some("broad")),
            ("elsewhere.example.net", None),
        ] {
            assert_eq!(
                port.bound_to(host.to_string()).await.unwrap().as_deref(),
                name,
                "{host}"
            );
        }
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn a_secret_nothing_registered_is_refused_by_name() {
        let r = rig(vec![], vec![], false).await;
        let refused = git_credential(&r, "github", "github.com").await;
        assert!(
            matches!(refused, Err(CryptoError::SecretNotRegistered(_))),
            "{refused:?}"
        );
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn a_secret_made_for_another_context_is_refused_and_nothing_is_registered_or_escrowed() {
        let r = rig(vec![], vec![], false).await;
        let secret = escrowed_bytes(
            &r,
            b"ghp-token",
            b"git-repo-observer|credentials|1|github|secret",
        );
        let refused = ractor::call!(r.actor, |reply| CryptoMessage::RegisterSecret {
            name: "github".to_string(),
            section: SECTION.to_string(),
            secret: secret.clone(),
            context: b"git-repo-observer|credentials|1|other|secret".to_vec(),
            username: None,
            binding: token_binding("github.com"),
            reply,
        })
        .unwrap();
        assert!(
            matches!(refused, Err(CryptoError::DecryptFailed(_))),
            "{refused:?}"
        );
        assert!(matches!(
            git_credential(&r, "github", "github.com").await,
            Err(CryptoError::SecretNotRegistered(_))
        ));
        settle().await;
        assert_eq!(stored_len(&r), 0);
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn bytes_that_are_not_an_escrowed_secret_are_a_serialization_error_and_register_nothing()
    {
        let r = rig(vec![], vec![], false).await;
        let refused = ractor::call!(r.actor, |reply| CryptoMessage::RegisterSecret {
            name: "github".to_string(),
            section: SECTION.to_string(),
            secret: b"not an escrowed secret".to_vec(),
            context: b"ctx".to_vec(),
            username: None,
            binding: token_binding("github.com"),
            reply,
        })
        .unwrap();
        assert!(
            matches!(refused, Err(CryptoError::Serialization(_))),
            "{refused:?}"
        );
        assert!(git_credential(&r, "github", "github.com").await.is_err());
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn a_binding_that_is_not_usable_is_refused_and_registers_and_escrows_nothing() {
        let r = rig(vec![], vec![], false).await;
        let refused = register(&r, "github", b"ghp-token", b"ctx", token_binding("*")).await;
        assert!(
            matches!(
                refused,
                Err(CryptoError::Record(RecordError::BadBinding(_)))
            ),
            "{refused:?}"
        );
        assert!(git_credential(&r, "github", "github.com").await.is_err());
        settle().await;
        assert_eq!(stored_len(&r), 0);
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn a_user_and_password_without_a_username_is_held_but_not_given_to_git() {
        let r = rig(vec![], vec![], false).await;
        let binding = SecretBinding {
            host_pattern: "git.example.org".to_string(),
            kind: SecretKind::UserPassword,
            username: None,
            host_key: None,
        };
        register(&r, "internal", b"hunter2", b"ctx", binding)
            .await
            .unwrap();
        let refused = git_credential(&r, "internal", "git.example.org").await;
        assert!(
            matches!(refused, Err(CryptoError::Use(UseRefusal::NoUsername))),
            "{refused:?}"
        );
        stop_and_release_key(&r.actor).await;
    }

    fn user_password(host: &str) -> SecretBinding {
        SecretBinding {
            host_pattern: host.to_string(),
            kind: SecretKind::UserPassword,
            username: None,
            host_key: None,
        }
    }

    #[tokio::test]
    async fn a_sealed_user_name_is_opened_into_the_binding_and_sent_with_its_password() {
        let r = rig(vec![], vec![], false).await;
        let binding = SecretBinding {
            username: Some("me@example.org".to_string()),
            ..user_password("example.atlassian.net")
        };
        register(&r, "jira", b"api-token", b"ctx", binding)
            .await
            .unwrap();
        use base64::Engine;
        assert_eq!(
            sent_authorization(&r.port, "jira", "example.atlassian.net")
                .await
                .unwrap(),
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode("me@example.org:api-token")
            )
        );
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn a_user_name_in_the_clear_in_the_binding_is_refused() {
        let r = rig(vec![], vec![], false).await;
        let binding = SecretBinding {
            username: Some("me@example.org".to_string()),
            ..user_password("example.atlassian.net")
        };
        let secret = escrowed_bytes(&r, b"api-token", b"ctx");
        let refused = ractor::call!(r.actor, |reply| CryptoMessage::RegisterSecret {
            name: "jira".to_string(),
            section: SECTION.to_string(),
            secret,
            context: b"ctx".to_vec(),
            username: None,
            binding,
            reply,
        })
        .unwrap();
        assert!(
            matches!(&refused, Err(CryptoError::Record(registry::RecordError::BadBinding(why))) if why.contains("sealed")),
            "{refused:?}"
        );
        assert!(
            r.port
                .http_kind("jira".to_string(), "example.atlassian.net".to_string())
                .await
                .is_err()
        );
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn a_user_name_sealed_for_another_field_or_not_one_is_refused() {
        let r = rig(vec![], vec![], false).await;
        let secret = || escrowed_bytes(&r, b"api-token", b"ctx");
        // Sealed under the secret's own context, handed on as the user name's: it does not open.
        let elsewhere = SealedPart {
            ciphertext: escrowed_bytes(&r, b"me@example.org", b"ctx"),
            context: b"ctx|username".to_vec(),
        };
        for (username, opens) in [
            (elsewhere, true),
            (
                SealedPart {
                    ciphertext: escrowed_bytes(&r, b"", b"ctx|username"),
                    context: b"ctx|username".to_vec(),
                },
                false,
            ),
            (
                SealedPart {
                    ciphertext: escrowed_bytes(&r, b"me\nyou", b"ctx|username"),
                    context: b"ctx|username".to_vec(),
                },
                false,
            ),
        ] {
            let refused = ractor::call!(r.actor, |reply| CryptoMessage::RegisterSecret {
                name: "jira".to_string(),
                section: SECTION.to_string(),
                secret: secret(),
                context: b"ctx".to_vec(),
                username: Some(username),
                binding: user_password("example.atlassian.net"),
                reply,
            })
            .unwrap();
            if opens {
                assert!(
                    matches!(refused, Err(CryptoError::DecryptFailed(_))),
                    "{refused:?}"
                );
            } else {
                assert!(
                    matches!(
                        refused,
                        Err(CryptoError::Record(registry::RecordError::BadBinding(_)))
                    ),
                    "{refused:?}"
                );
            }
        }
        assert!(
            r.port
                .http_kind("jira".to_string(), "example.atlassian.net".to_string())
                .await
                .is_err()
        );
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn registering_escrows_the_secret_with_its_binding_under_the_identity_prefixed_name() {
        let r = rig(vec![], vec![], false).await;
        let binding = SecretBinding {
            host_pattern: "github.com".to_string(),
            kind: SecretKind::Token,
            username: Some("daveman1010221".to_string()),
            host_key: None,
        };
        register(&r, "github", b"ghp-token", b"ctx", binding.clone())
            .await
            .unwrap();
        wait_until("the escrow", || stored_len(&r) >= 1).await;
        let (name, record, _labels) = r.stored.lock().unwrap()[0].clone();
        assert_eq!(name, format!("{}/github", r.identity));
        let (escrowed_binding, secret) = registry::from_escrow_form(&record).unwrap();
        assert_eq!(escrowed_binding, binding);
        assert_eq!(secret.as_slice(), b"ghp-token");
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn registering_does_not_wait_for_the_escrow_and_the_secret_is_usable_meanwhile() {
        let r = rig(vec![], vec![], false).await;
        r.failing.store(true, std::sync::atomic::Ordering::SeqCst);
        register(
            &r,
            "github",
            b"ghp-token",
            b"ctx",
            token_binding("github.com"),
        )
        .await
        .unwrap();
        assert!(git_credential(&r, "github", "github.com").await.is_ok());
        wait_until("a retry", || stored_len(&r) >= 2).await;
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn an_escrow_that_fails_is_retried_until_it_is_acknowledged_and_then_stops() {
        let r = rig(
            vec![StoreScript::Failed, StoreScript::Failed],
            vec![],
            false,
        )
        .await;
        register(
            &r,
            "github",
            b"ghp-token",
            b"ctx",
            token_binding("github.com"),
        )
        .await
        .unwrap();
        wait_until("three attempts", || stored_len(&r) >= 3).await;
        settle().await;
        assert_eq!(
            stored_len(&r),
            3,
            "two failures, then the acknowledgement, then nothing more"
        );
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn an_escrow_refused_for_a_reason_retrying_cannot_fix_is_not_retried() {
        for reason in [
            StoreRefusalReason::NameTaken,
            StoreRefusalReason::AnonymousPublisherNotAllowed,
        ] {
            let r = rig(vec![StoreScript::Refused(reason)], vec![], false).await;
            register(
                &r,
                "github",
                b"ghp-token",
                b"ctx",
                token_binding("github.com"),
            )
            .await
            .unwrap();
            wait_until("the attempt", || stored_len(&r) >= 1).await;
            settle().await;
            assert_eq!(stored_len(&r), 1, "{reason:?}");
            // It is still held, and usable, in this agent.
            assert!(git_credential(&r, "github", "github.com").await.is_ok());
            stop_and_release_key(&r.actor).await;
        }
    }

    #[tokio::test]
    async fn an_escrow_refused_for_the_wrong_escrow_key_is_retried_with_the_current_key() {
        let r = rig(
            vec![StoreScript::Refused(StoreRefusalReason::WrongEscrowKey)],
            vec![],
            false,
        )
        .await;
        register(
            &r,
            "github",
            b"ghp-token",
            b"ctx",
            token_binding("github.com"),
        )
        .await
        .unwrap();
        wait_until("a second attempt", || stored_len(&r) >= 2).await;
        settle().await;
        assert_eq!(stored_len(&r), 2);
        assert!(
            r.key_queries.load(std::sync::atomic::Ordering::SeqCst) >= 2,
            "the cached key was kept after the credentials agent said it was wrong"
        );
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn registering_a_name_again_replaces_it_and_stops_escrowing_the_old_value() {
        let r = rig(vec![], vec![], false).await;
        r.failing.store(true, std::sync::atomic::Ordering::SeqCst);
        register(
            &r,
            "github",
            b"old-token",
            b"ctx-1",
            token_binding("github.com"),
        )
        .await
        .unwrap();
        wait_until("an attempt for the old value", || stored_len(&r) >= 1).await;
        register(
            &r,
            "github",
            b"new-token",
            b"ctx-2",
            token_binding("github.com"),
        )
        .await
        .unwrap();
        r.failing.store(false, std::sync::atomic::Ordering::SeqCst);
        wait_until("the new value escrowed", || {
            r.stored
                .lock()
                .unwrap()
                .last()
                .is_some_and(|(_, record, _)| secret_of(record) == "new-token")
        })
        .await;
        settle().await;
        let entries = r.stored.lock().unwrap().clone();
        let first_new = entries
            .iter()
            .position(|(_, record, _)| secret_of(record) == "new-token")
            .unwrap();
        assert!(
            entries[first_new..]
                .iter()
                .all(|(_, record, _)| secret_of(record) == "new-token"),
            "the old value was escrowed after it was replaced"
        );
        let got = git_credential(&r, "github", "github.com").await.unwrap();
        assert_eq!(got.secret.as_slice(), b"new-token");
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn a_stopped_actor_stops_trying_to_escrow() {
        let r = rig(vec![], vec![], false).await;
        r.failing.store(true, std::sync::atomic::Ordering::SeqCst);
        register(
            &r,
            "github",
            b"ghp-token",
            b"ctx",
            token_binding("github.com"),
        )
        .await
        .unwrap();
        wait_until("an attempt", || stored_len(&r) >= 1).await;
        stop_and_release_key(&r.actor).await;
        let at_stop = stored_len(&r);
        settle().await;
        assert_eq!(
            stored_len(&r),
            at_stop,
            "it kept trying after it was stopped"
        );
    }

    #[tokio::test]
    async fn loading_registers_what_the_credentials_agent_holds_under_the_prefixed_name_and_does_not_escrow_it_again()
     {
        let binding = SecretBinding {
            host_pattern: "*.example.org".to_string(),
            kind: SecretKind::Token,
            username: None,
            host_key: None,
        };
        let record = registry::escrow_form(&binding, b"ghp-token").unwrap();
        let r = rig(vec![], vec![("github", record.to_vec())], false).await;
        assert!(load(&r, "github").await.unwrap());
        let got = git_credential(&r, "github", "git.example.org")
            .await
            .unwrap();
        assert_eq!(got.secret.as_slice(), b"ghp-token");
        assert!(git_credential(&r, "github", "github.com").await.is_err());
        settle().await;
        assert_eq!(stored_len(&r), 0);
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn loading_a_name_nothing_holds_is_false_and_registers_nothing() {
        let r = rig(vec![], vec![], false).await;
        assert!(!load(&r, "github").await.unwrap());
        assert!(git_credential(&r, "github", "github.com").await.is_err());
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn loading_a_secret_policy_denies_is_an_error_that_says_so() {
        let binding = token_binding("github.com");
        let record = registry::escrow_form(&binding, b"ghp-token").unwrap();
        let r = rig(vec![], vec![("github", record.to_vec())], true).await;
        let refused = load(&r, "github").await;
        assert!(
            matches!(refused, Err(CryptoError::RetrieveSecretDenied(_))),
            "{refused:?}"
        );
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn loading_something_that_is_not_a_credential_registers_nothing() {
        let r = rig(vec![], vec![("github", b"just some bytes".to_vec())], false).await;
        let refused = load(&r, "github").await;
        assert!(
            matches!(refused, Err(CryptoError::Record(RecordError::Malformed))),
            "{refused:?}"
        );
        assert!(git_credential(&r, "github", "github.com").await.is_err());
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn the_escrow_carries_a_kind_label_equal_to_the_bindings_kind() {
        for (kind, expected) in [
            (SecretKind::Token, "token"),
            (SecretKind::UserPassword, "user-password"),
        ] {
            let r = rig(vec![], vec![], false).await;
            let binding = SecretBinding {
                host_pattern: "github.com".to_string(),
                kind,
                username: Some("alice".to_string()),
                host_key: None,
            };
            register(&r, "github", b"ghp-token", b"ctx", binding)
                .await
                .unwrap();
            wait_until("the escrow", || stored_len(&r) >= 1).await;
            let (_, _, labels) = r.stored.lock().unwrap()[0].clone();
            assert_eq!(labels.len(), 1, "{labels:?}");
            assert_eq!(labels.get("kind").map(String::as_str), Some(expected));
            stop_and_release_key(&r.actor).await;
        }
    }

    #[tokio::test]
    async fn an_escrow_refused_for_a_policy_or_a_label_reason_is_not_retried() {
        for reason in [
            StoreRefusalReason::PolicyDenied,
            StoreRefusalReason::InvalidLabels,
            StoreRefusalReason::LabelsChanged,
            StoreRefusalReason::InvalidSecretName,
        ] {
            let r = rig(vec![StoreScript::Refused(reason)], vec![], false).await;
            register(
                &r,
                "github",
                b"ghp-token",
                b"ctx",
                token_binding("github.com"),
            )
            .await
            .unwrap();
            wait_until("the attempt", || stored_len(&r) >= 1).await;
            settle().await;
            assert_eq!(stored_len(&r), 1, "{reason:?}");
            stop_and_release_key(&r.actor).await;
        }
    }

    #[tokio::test]
    async fn an_escrow_refused_because_the_certificate_is_not_on_record_yet_is_retried() {
        let r = rig(
            vec![StoreScript::Refused(
                StoreRefusalReason::RequesterCertificateNotFound,
            )],
            vec![],
            false,
        )
        .await;
        register(
            &r,
            "github",
            b"ghp-token",
            b"ctx",
            token_binding("github.com"),
        )
        .await
        .unwrap();
        wait_until("a second attempt", || stored_len(&r) >= 2).await;
        settle().await;
        assert_eq!(stored_len(&r), 2);
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn replacing_a_section_drops_what_it_no_longer_lists_and_keeps_what_it_does() {
        let r = rig(vec![], vec![], false).await;
        for name in ["kept", "dropped-b", "dropped-a"] {
            register(&r, name, b"tok", b"ctx", token_binding("github.com"))
                .await
                .unwrap();
        }
        let dropped = replace_section(&r, SECTION, &["kept"]).await;
        assert_eq!(
            dropped,
            vec!["dropped-a".to_string(), "dropped-b".to_string()]
        );
        assert!(git_credential(&r, "kept", "github.com").await.is_ok());
        for name in ["dropped-a", "dropped-b"] {
            assert!(
                matches!(
                    git_credential(&r, name, "github.com").await,
                    Err(CryptoError::SecretNotRegistered(_))
                ),
                "{name}"
            );
        }
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn replacing_a_section_leaves_the_secrets_of_other_sections_alone() {
        let r = rig(vec![], vec![], false).await;
        register_in(
            &r,
            "elsewhere",
            "other",
            b"tok",
            b"ctx",
            token_binding("github.com"),
        )
        .await
        .unwrap();
        register(&r, "mine", b"tok", b"ctx", token_binding("github.com"))
            .await
            .unwrap();
        let dropped = replace_section(&r, SECTION, &[]).await;
        assert_eq!(dropped, vec!["mine".to_string()]);
        assert!(git_credential(&r, "other", "github.com").await.is_ok());
        // a section nothing was registered under drops nothing
        assert!(replace_section(&r, "nothing-here", &[]).await.is_empty());
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn a_name_registered_again_under_another_section_belongs_to_that_one() {
        let r = rig(vec![], vec![], false).await;
        register(&r, "moved", b"tok", b"ctx", token_binding("github.com"))
            .await
            .unwrap();
        register_in(
            &r,
            "elsewhere",
            "moved",
            b"tok",
            b"ctx",
            token_binding("github.com"),
        )
        .await
        .unwrap();
        assert!(replace_section(&r, SECTION, &[]).await.is_empty());
        assert!(git_credential(&r, "moved", "github.com").await.is_ok());
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn a_withdrawn_secret_is_no_longer_escrowed() {
        // Every attempt fails, so the escrow keeps retrying until the secret is withdrawn.
        let r = rig(vec![], vec![], false).await;
        r.failing.store(true, std::sync::atomic::Ordering::SeqCst);
        register(&r, "github", b"tok", b"ctx", token_binding("github.com"))
            .await
            .unwrap();
        wait_until("a first attempt", || stored_len(&r) >= 1).await;
        replace_section(&r, SECTION, &[]).await;
        settle().await;
        let attempts = stored_len(&r);
        settle().await;
        settle().await;
        assert_eq!(
            stored_len(&r),
            attempts,
            "it kept escrowing a withdrawn secret"
        );
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn no_refusal_repeats_the_secret() {
        let r = rig(vec![], vec![], false).await;
        register(
            &r,
            "github",
            b"ghp-super-secret",
            b"ctx",
            token_binding("github.com"),
        )
        .await
        .unwrap();
        let refused = git_credential(&r, "github", "evil.example.org")
            .await
            .unwrap_err();
        assert!(!format!("{refused} {refused:?}").contains("ghp-super-secret"));
        let wrong_context = ractor::call!(r.actor, |reply| CryptoMessage::RegisterSecret {
            name: "other".to_string(),
            section: SECTION.to_string(),
            secret: escrowed_bytes(&r, b"ghp-super-secret", b"ctx-a"),
            context: b"ctx-b".to_vec(),
            username: None,
            binding: token_binding("github.com"),
            reply,
        })
        .unwrap()
        .unwrap_err();
        assert!(!format!("{wrong_context} {wrong_context:?}").contains("ghp-super-secret"));
        stop_and_release_key(&r.actor).await;
    }

    #[tokio::test]
    async fn encrypt_for_recipient_genuinely_round_trips_a_real_message_to_a_real_recipient_public_key()
     {
        let mut rng = rand::rng();
        let recipient_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let recipient_public_key_pem = rsa::pkcs8::EncodePublicKey::to_public_key_pem(
            &recipient_key.to_public_key(),
            rsa::pkcs8::LineEnding::LF,
        )
        .unwrap();

        let ((crypto_actor, _), _, _) =
            spawn_crypto_actor_with_fake_credentials_agent_configured(FakeCredentialsAgentConfig {
                recipient_public_key_pem: Some(recipient_public_key_pem),
                ..Default::default()
            })
            .await;

        let plaintext = b"a real secret, addressed to a specific, real recipient identity";
        let result = ractor::call!(crypto_actor, |reply| {
            CryptoMessage::EncryptForRecipient {
                recipient_identity: "some-other-agent".to_string(),
                plaintext: plaintext.to_vec(),
                reply,
            }
        })
        .unwrap();

        let wire_bytes = match result {
            Ok(bytes) => bytes,
            other => panic!("expected Ok(_), got {other:?}"),
        };

        // The real proof: deserialize the actual, real wire bytes
        // EncryptForRecipient returned, and decrypt them with the
        // recipient's own, real private key -- not CryptoActor's
        // own, since this is addressed to someone else entirely.
        let escrowed: EscrowedSecret =
            rkyv::from_bytes::<EscrowedSecret, rkyv::rancor::Error>(&wire_bytes).unwrap();
        let decrypted = escrowed.decrypt(&recipient_key).unwrap();

        assert_eq!(&*decrypted, plaintext);
        stop_and_release_key(&crypto_actor).await;
    }

    #[tokio::test]
    async fn encrypt_for_recipient_genuinely_caches_the_recipient_key_after_the_first_query() {
        let mut rng = rand::rng();
        let recipient_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let recipient_public_key_pem = rsa::pkcs8::EncodePublicKey::to_public_key_pem(
            &recipient_key.to_public_key(),
            rsa::pkcs8::LineEnding::LF,
        )
        .unwrap();

        let ((crypto_actor, _), _, agent_escrow_key_queries) =
            spawn_crypto_actor_with_fake_credentials_agent_configured(FakeCredentialsAgentConfig {
                recipient_public_key_pem: Some(recipient_public_key_pem),
                ..Default::default()
            })
            .await;

        for _ in 0..3 {
            let result = ractor::call!(crypto_actor, |reply| {
                CryptoMessage::EncryptForRecipient {
                    recipient_identity: "some-other-agent".to_string(),
                    plaintext: b"repeated message".to_vec(),
                    reply,
                }
            })
            .unwrap();
            assert!(result.is_ok());
        }

        assert_eq!(
            agent_escrow_key_queries.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the recipient's own public key must genuinely be queried exactly once across three calls"
        );
        stop_and_release_key(&crypto_actor).await;
    }

    /// Every agent's escrow key is P-256 now, held by its custody daemon: sealed to with HPKE.
    #[tokio::test]
    async fn encrypt_for_recipient_seals_to_a_p256_recipient_with_hpke() {
        use p256::pkcs8::EncodePublicKey as _;
        let recipient = loop {
            if let Ok(key) = p256::SecretKey::from_bytes(&rand::random::<[u8; 32]>().into()) {
                break key;
            }
        };
        let pem = recipient
            .public_key()
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .unwrap();
        let ((crypto_actor, _), _, _) =
            spawn_crypto_actor_with_fake_credentials_agent_configured(FakeCredentialsAgentConfig {
                recipient_public_key_pem: Some(pem),
                ..Default::default()
            })
            .await;
        let wire = ractor::call!(crypto_actor, |reply| CryptoMessage::EncryptForRecipient {
            recipient_identity: "some-other-agent".to_string(),
            plaintext: b"to a P-256 recipient".to_vec(),
            reply,
        })
        .unwrap()
        .unwrap();
        let escrowed = rkyv::from_bytes::<EscrowedSecret, rkyv::rancor::Error>(&wire).unwrap();
        assert_eq!(
            escrowed.suite(),
            credentials_agent_common::escrow_secret::Suite::HpkeP256
        );
        assert_eq!(
            &*escrowed.decrypt_p256(&recipient).unwrap(),
            b"to a P-256 recipient"
        );
        stop_and_release_key(&crypto_actor).await;
    }

    /// docs/architecture/key-custody.md, "Also in this work": a key handed out in a certificate the pinned CA did not
    /// sign is not encrypted to, however it came.
    #[tokio::test]
    async fn encrypt_for_recipient_refuses_a_key_whose_certificate_cannot_be_believed() {
        let recipient_key = RsaPrivateKey::new(&mut rand::rng(), 2048).unwrap();
        let pem = rsa::pkcs8::EncodePublicKey::to_public_key_pem(
            &recipient_key.to_public_key(),
            rsa::pkcs8::LineEnding::LF,
        )
        .unwrap();
        let ((crypto_actor, _), _, _) =
            spawn_crypto_actor_with_fake_credentials_agent_configured(FakeCredentialsAgentConfig {
                recipient_public_key_pem: Some(pem),
                forge_recipient_certificate: true,
                ..Default::default()
            })
            .await;
        let result = ractor::call!(crypto_actor, |reply| CryptoMessage::EncryptForRecipient {
            recipient_identity: "some-other-agent".to_string(),
            plaintext: b"never sealed to a forger".to_vec(),
            reply,
        })
        .unwrap();
        assert!(
            matches!(&result, Err(CryptoError::KeyEncoding(why)) if why.contains("pinned CA")),
            "{result:?}"
        );
        stop_and_release_key(&crypto_actor).await;
    }

    #[tokio::test]
    async fn encrypt_for_recipient_fails_with_recipient_key_not_found_when_the_recipient_has_no_usable_key()
     {
        let ((crypto_actor, _), _, _) =
            spawn_crypto_actor_with_fake_credentials_agent_configured(FakeCredentialsAgentConfig {
                recipient_public_key_pem: None,
                ..Default::default()
            })
            .await;

        let result = ractor::call!(crypto_actor, |reply| {
            CryptoMessage::EncryptForRecipient {
                recipient_identity: "never-issued-agent".to_string(),
                plaintext: b"this should never be encrypted".to_vec(),
                reply,
            }
        })
        .unwrap();

        match result {
            Err(CryptoError::RecipientKeyNotFound(identity)) => {
                assert_eq!(identity, "never-issued-agent");
            }
            other => panic!("expected Err(RecipientKeyNotFound(_)), got {other:?}"),
        }
        stop_and_release_key(&crypto_actor).await;
    }
}
