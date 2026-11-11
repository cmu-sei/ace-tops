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

//! Protocol handlers: the domain's I/O in infrastructure (docs/architecture/protocol-handlers.md).
//!
//! The domain says what it wants, as an [`Operation`] it declared. A handler in the builder's infrastructure judges the
//! request ([`judge`]), records the verdict, gets the credential from the CryptoActor itself, makes the request through
//! its [`Protocol`], and calls the operation's `read` with what came back; the value reaches the domain actor as an
//! ordinary message. Nothing on the domain side is ever given a credential: a [`Protocol`] is sealed to this crate, what
//! `read` is given holds only the response, and the port to the CryptoActor stays here.

pub mod credentials;
pub mod git;
pub mod http;
pub mod judge;
pub mod kubernetes;
#[cfg(test)]
mod ssh_origin;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub use credentials::CredentialsApplied;
pub use judge::{
    Access, Credential, Denial, Location, OperationDecl, ProtocolKind, Target, Verb, Verdict, judge,
};

use crate::configuration::ConfigurationHandle;
use crate::crypto::SectionKeeper;
use crate::health::HealthHandle;
use crate::runtime::RuntimeValue;
use polar_crypto::registry::{GitCredential, HttpCredential, UseRefusal};
use polar_crypto::{CredentialPort, CryptoError};
use polar_health::HoldReason;
use ractor::{Actor, ActorCell, ActorProcessingErr, ActorRef, OutputPort, async_trait};
use std::any::Any;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::JoinSet;
use tokio::time::Instant;

mod sealed {
    /// Only this crate implements [`super::Protocol`]: one written elsewhere would be handed a credential.
    pub trait Sealed {}
}

/// Why a request came to nothing. Reaches the domain, and so never holds a secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Failure {
    #[error("the request was not allowed: {0}")]
    Denied(Denial),
    #[error("the credential `{name}` has not arrived")]
    NoCredential { name: String },
    #[error("the credential `{name}` is not bound to this host")]
    NotBound { name: String },
    #[error("the credential `{name}` cannot be used: {why}")]
    CredentialUnusable { name: String, why: String },
    #[error(
        "the credential `{name}` was refused, and is not presented again until a new version arrives"
    )]
    CredentialHeld { name: String },
    #[error("the credential was refused: {0}")]
    CredentialRefused(String),
    #[error("the host asked for time: nothing goes to it for another {wait:?}")]
    NotYet { wait: Duration },
    #[error("the host answered {status} and asked for time: {wait:?}")]
    Backoff { status: u16, wait: Duration },
    #[error("{0}")]
    Transient(String),
    #[error("{0}")]
    Configuration(String),
    #[error("what came back could not be read: {0}")]
    Read(String),
    #[error("reading what came back took longer than its budget")]
    OverBudget,
    #[error("reading what came back panicked")]
    ReadPanicked,
}

/// What an operation's `read` says when what came back is not what it needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadFailure {
    /// It is not what was expected.
    Malformed(String),
    /// It answered, and the answer means that the credential is not accepted (a Data Center's anonymous 200).
    CredentialRefused(String),
    /// It answered, and the answer means that the agent's configuration cannot work.
    Configuration(String),
}

impl From<ReadFailure> for Failure {
    fn from(failure: ReadFailure) -> Self {
        match failure {
            ReadFailure::Malformed(why) => Failure::Read(why),
            ReadFailure::CredentialRefused(why) => Failure::CredentialRefused(why),
            ReadFailure::Configuration(why) => Failure::Configuration(why),
        }
    }
}

/// Where a protocol gets a credential: the CryptoActor, through the port only this crate holds.
#[async_trait]
pub trait CredentialSource: Send + Sync {
    async fn http(&self, name: String, host: String) -> Result<HttpCredential, CryptoError>;
    async fn git(&self, name: String, host: String) -> Result<GitCredential, CryptoError>;
    /// The name of the credential bound to `host`, for [`Credential::ForHost`].
    async fn bound_to(&self, host: String) -> Result<Option<String>, CryptoError>;
}

#[async_trait]
impl CredentialSource for CredentialPort {
    async fn http(&self, name: String, host: String) -> Result<HttpCredential, CryptoError> {
        CredentialPort::http(self, name, host).await
    }
    async fn git(&self, name: String, host: String) -> Result<GitCredential, CryptoError> {
        CredentialPort::git(self, name, host).await
    }
    async fn bound_to(&self, host: String) -> Result<Option<String>, CryptoError> {
        CredentialPort::bound_to(self, host).await
    }
}

/// Work to run on a task.
type Pending<T = ()> = Pin<Box<dyn Future<Output = T> + Send>>;

/// What a hop comes to: the credential for where it goes, or why it may not go.
type Hopped<P> = Pending<Result<Option<<P as Protocol>::Credential>, Failure>>;

/// What a [`Protocol`] has of the handler while it makes a request.
pub struct Exchange<P: Protocol> {
    /// Reads one reply and sends the value to the domain, saying whether to go on.
    each: Box<dyn FnMut(P::Reply) -> Pending<bool> + Send>,
    /// Judges where the request goes next, and gets the credential for there.
    hop: Box<dyn FnMut(Target) -> Hopped<P> + Send>,
}

impl<P: Protocol> Exchange<P> {
    /// Hands a reply on: it is read by the operation, on a thread of its own and within its budget, and the value goes to
    /// the domain actor. Called once for a request with one reply, and for each change of a stream, which waits here until
    /// the domain has finished with the last one. A stream goes on only while this says so: what it says next would not
    /// follow from what the domain has, or nobody is listening.
    pub async fn reply(&mut self, reply: P::Reply) -> bool {
        (self.each)(reply).await
    }

    /// The request is sent on to `target`, as a redirect asks: judged as the request was, and recorded. The credential
    /// for there, if it goes with one, or why it may not go.
    pub async fn hop(&mut self, target: Target) -> Result<Option<P::Credential>, Failure> {
        (self.hop)(target).await
    }
}

/// What differs between protocols: the request, how a credential attaches, and what a callback reads. Everything else is
/// the handler's, once. Sealed: only this crate implements it, since [`perform`](Self::perform) holds the credential.
#[async_trait]
pub trait Protocol: sealed::Sealed + Send + Sync + Sized + 'static {
    const KIND: ProtocolKind;
    /// How long an operation's `read` has with each reply.
    const BUDGET: Duration;
    /// What the domain says it wants.
    type Request: Send + 'static;
    /// What the protocol presents. Stays in [`perform`](Self::perform).
    type Credential: Send + 'static;
    /// What an operation reads. Holds what came back, never what was sent.
    type Reply: Send + 'static;

    /// Where a request goes that has no variable to say so ([`Location::Cluster`]): what the protocol learned when it started.
    fn own_location(&self) -> Option<String> {
        None
    }
    /// The host of a configured location, the value of the operation's variable.
    fn configured_host(base: &str) -> Result<String, String>;
    /// Where `request` goes; `base` is the value of the operation's variable, if it has one.
    fn target(request: &Self::Request, base: Option<&str>) -> Result<Target, String>;
    /// Asks for the credential in the form this protocol presents it.
    async fn credential(
        source: &dyn CredentialSource,
        name: String,
        host: String,
    ) -> Result<Self::Credential, CryptoError>;
    /// Makes the request, presenting `credential`, and hands what comes back to `exchange`.
    async fn perform(
        &self,
        request: Self::Request,
        base: Option<String>,
        credential: Option<Self::Credential>,
        exchange: &mut Exchange<Self>,
    ) -> Result<(), Failure>;
}

/// A protocol as it was started.
pub(crate) type Started = Arc<dyn Any + Send + Sync>;

/// How a protocol starts, given what the agent is configured with: what it reads of that it reads before it returns.
pub(crate) type Starter = fn(&polar_env::Config) -> Pending<Result<Started, String>>;

/// The protocols the agent started at load, for the operations it declared.
#[derive(Default)]
pub struct Instances(HashMap<&'static str, Started>);

impl Instances {
    /// Starts each protocol `operations` uses, and no other. An agent that cannot is told at load.
    pub(crate) async fn start(
        operations: &[OperationDecl],
        config: &polar_env::Config,
    ) -> Result<Self, String> {
        let mut instances = HashMap::new();
        for operation in operations {
            let kind = operation.protocol;
            if !instances.contains_key(kind.as_str()) {
                instances.insert(kind.as_str(), (kind.start)(config).await?);
            }
        }
        Ok(Self(instances))
    }

    /// `protocol` as a test made it.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn of<P: Protocol>(protocol: P) -> Self {
        Self(HashMap::from([(
            P::KIND.as_str(),
            Arc::new(protocol) as Started,
        )]))
    }

    /// With `protocol` as well, for an agent that speaks more than one.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn and<P: Protocol>(mut self, protocol: P) -> Self {
        self.0
            .insert(P::KIND.as_str(), Arc::new(protocol) as Started);
        self
    }

    /// This protocol as the agent started it, if an operation it declared uses it.
    fn get<P: Protocol>(&self) -> Option<Arc<P>> {
        self.0.get(P::KIND.as_str())?.clone().downcast().ok()
    }
}

/// A request the domain makes, of a kind it declared in `PolarAgent::OPERATIONS`.
pub trait Operation: Send + Sync + 'static {
    type Protocol: Protocol;
    /// What `read` gives the domain.
    type Output: Send + 'static;
    /// The declaration, as it appears in `PolarAgent::OPERATIONS`.
    const DECL: OperationDecl;

    /// The request, in the protocol's terms.
    fn request(&self) -> <Self::Protocol as Protocol>::Request;
    /// The credential this request names, for an operation that declares [`Credential::Chosen`].
    fn credential(&self) -> Option<String> {
        None
    }
    /// Reads what came back. It has the request's own values, and no access to the agent or to the credential.
    fn read(
        &self,
        reply: &<Self::Protocol as Protocol>::Reply,
    ) -> Result<Self::Output, ReadFailure>;
}

/// The record of one request: what it was and what was decided, in one place, and never a path, a query or a value.
/// Logged now, and read by the security dashboard when it exists (docs/architecture/protocol-handlers.md, "The judgment").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestRecord {
    pub operation: &'static str,
    pub protocol: &'static str,
    /// Empty when the request was refused before it had one.
    pub host: String,
    /// The credential's name, when one is presented.
    pub credential: Option<String>,
    /// That it is a request the agent has only the permission to make, not known ahead of time.
    pub arbitrary: bool,
    /// `allowed`, or why it was refused.
    pub verdict: String,
}

/// What the record says a [`Location::Cluster`] request presents: the pod's own token, which the protocol's client reads
/// and no section holds.
pub const SERVICE_ACCOUNT: &str = "service-account";

/// Where the records go.
pub(crate) type Recorder = Arc<dyn Fn(&RequestRecord) + Send + Sync>;

fn log_request(record: &RequestRecord) {
    tracing::info!(
        target: "polar::protocol",
        operation = record.operation,
        protocol = record.protocol,
        host = %record.host,
        credential = record.credential.as_deref().unwrap_or(""),
        arbitrary = record.arbitrary,
        verdict = %record.verdict,
        "request"
    );
}

/// What the handler reads of the configuration in force.
#[async_trait]
pub(crate) trait LiveConfiguration: Send + Sync {
    /// The value a declared variable resolves to: its override, its value, or its default.
    async fn value(&self, name: &str) -> Option<String>;
    /// The latest version of a runtime section.
    async fn section(&self, name: &str) -> Option<RuntimeValue>;
}

#[async_trait]
impl LiveConfiguration for ConfigurationHandle {
    async fn value(&self, name: &str) -> Option<String> {
        // As the setting resolves: its default when nothing sets it, as the agent's own reading of it would have it.
        match self.current().await {
            Ok(config) => config.resolved(name).filter(|value| !value.is_empty()),
            Err(e) => {
                tracing::warn!("the configuration in force could not be read: {e}");
                None
            }
        }
    }
    async fn section(&self, name: &str) -> Option<RuntimeValue> {
        match self.runtime(name).await {
            Ok(value) => value,
            Err(e) => {
                tracing::warn!("the runtime section `{name}` could not be read: {e}");
                None
            }
        }
    }
}

/// How the handler makes a standing problem known.
pub(crate) trait Holds: Send + Sync {
    fn hold_credentials(&self, message: String);
    fn release_credentials(&self);
}

impl Holds for HealthHandle {
    fn hold_credentials(&self, message: String) {
        self.hold(HoldReason::Credentials, message);
    }
    fn release_credentials(&self) {
        self.release(HoldReason::Credentials);
    }
}

/// What every request's task shares.
pub(crate) struct Shared {
    declared: &'static [OperationDecl],
    instances: Instances,
    credentials: Option<Arc<dyn CredentialSource>>,
    configuration: Arc<dyn LiveConfiguration>,
    health: Arc<dyn Holds>,
    record: Recorder,
    /// The cluster's name for each namespace key the deployment names (`POLAR_CLUSTER_NAMESPACES`): where a cluster
    /// operation that names a namespace may act.
    namespaces: BTreeMap<String, String>,
    /// The hosts that asked for time, and until when.
    not_before: Mutex<HashMap<String, Instant>>,
    /// The credentials refused by what they were presented to, until a new version of the section.
    refused: Mutex<HashSet<String>>,
}

impl Shared {
    /// The credential was refused by what it was presented to: it is not presented again, and the agent holds the problem,
    /// until a new version of the section arrives.
    fn refused(&self, operation: &str, name: &str, why: &str) {
        self.refused.lock().unwrap().insert(name.to_string());
        self.health.hold_credentials(format!(
            "{operation}: the credential `{name}` was refused: {why}; sign a new version of the credentials section"
        ));
    }

    /// How long until `host` may be called again, if it asked for time.
    fn wait_for(&self, host: &str) -> Option<Duration> {
        let mut not_before = self.not_before.lock().unwrap();
        let until = *not_before.get(host)?;
        let now = Instant::now();
        if until > now {
            Some(until - now)
        } else {
            not_before.remove(host);
            None
        }
    }
}

/// What a request is, as it is judged at each place it goes.
struct Asked {
    decl: OperationDecl,
    /// What its location names, as it is in force: the host of the operation's variable, for a configured one; the
    /// cluster's name for its namespace, for a cluster one that names one ([`judge`]'s `configured`).
    configured_host: Option<String>,
    /// The credential the request names.
    chosen: Option<String>,
}

/// Whether the request may go to `target`, recorded either way, and the credential to present there: the judgment, a
/// host that asked for time, a credential refused before, and the CryptoActor's binding, in that order. The name of
/// the credential comes back with it.
async fn admit<P: Protocol>(
    shared: &Shared,
    asked: &Asked,
    target: &Target,
) -> Result<(Option<String>, Option<P::Credential>), Failure> {
    let record = |credential: Option<String>, verdict: String| {
        (shared.record)(&RequestRecord {
            operation: asked.decl.name,
            protocol: asked.decl.protocol.as_str(),
            host: target.host.clone(),
            credential,
            arbitrary: asked.decl.location == Location::Arbitrary,
            verdict,
        });
    };
    let refused = |credential: Option<String>, failure: Failure| {
        record(credential, failure.to_string());
        failure
    };

    let name = match judge(
        &asked.decl,
        shared.declared,
        target,
        asked.configured_host.as_deref(),
        asked.chosen.as_deref(),
    ) {
        Verdict::Allow { credential } => credential,
        Verdict::Deny(why) => return Err(refused(None, Failure::Denied(why))),
    };
    if let Some(wait) = shared.wait_for(&target.host) {
        return Err(refused(name, Failure::NotYet { wait }));
    }
    let credential = match &name {
        None => None,
        Some(name) => {
            if shared.refused.lock().unwrap().contains(name) {
                let held = Failure::CredentialHeld { name: name.clone() };
                return Err(refused(Some(name.clone()), held));
            }
            let Some(source) = &shared.credentials else {
                let failure = Failure::CredentialUnusable {
                    name: name.clone(),
                    why: "the agent has no CryptoActor: declare its credentials".to_string(),
                };
                return Err(refused(Some(name.clone()), failure));
            };
            match P::credential(source.as_ref(), name.clone(), target.host.clone()).await {
                Ok(credential) => Some(credential),
                Err(error) => {
                    let failure = credential_failure(name, error);
                    return Err(refused(Some(name.clone()), failure));
                }
            }
        }
    };
    let presented = match asked.decl.location {
        Location::Cluster { .. } => Some(SERVICE_ACCOUNT.to_string()),
        _ => name.clone(),
    };
    record(presented, "allowed".to_string());
    Ok((name, credential))
}

/// How what comes of a request reaches the domain: done when the next may follow, saying whether it should.
type Deliver<T> = Arc<dyn Fn(Result<T, Failure>) -> Pending<bool> + Send + Sync>;

/// Runs one request: the whole of what the handler does for it.
async fn run<O: Operation>(shared: Arc<Shared>, operation: O, send: Deliver<O::Output>) {
    let decl = O::DECL;
    let refuse_early = |failure: Failure| {
        (shared.record)(&RequestRecord {
            operation: decl.name,
            protocol: decl.protocol.as_str(),
            host: String::new(),
            credential: None,
            arbitrary: decl.location == Location::Arbitrary,
            verdict: failure.to_string(),
        });
        let told = send(Err(failure));
        async move {
            told.await;
        }
    };

    let Some(protocol) = shared.instances.get::<O::Protocol>() else {
        return refuse_early(Failure::Configuration(format!(
            "the agent did not start the {} protocol: declare the operation",
            decl.protocol.as_str()
        )))
        .await;
    };
    let request = operation.request();

    let base = match decl.location {
        Location::Configured { variable, .. } => match shared.configuration.value(variable).await {
            Some(base) => Some(base),
            None => return refuse_early(Failure::Denied(Denial::NotConfigured)).await,
        },
        Location::Cluster { .. } => protocol.own_location(),
        Location::Bound { .. } | Location::Arbitrary => None,
    };
    let configured_host = match base.as_deref().map(O::Protocol::configured_host) {
        Some(Ok(host)) => Some(host),
        Some(Err(why)) => return refuse_early(Failure::Configuration(why)).await,
        None => None,
    };
    // A cluster operation that names a namespace is judged against the cluster's name for it, as the deployment says;
    // `None` when it does not, which the judge refuses.
    let configured_host = match decl.location {
        Location::Cluster {
            namespace: Some(key),
            ..
        } => shared.namespaces.get(key).cloned(),
        _ => configured_host,
    };
    let target = match O::Protocol::target(&request, base.as_deref()) {
        Ok(target) => target,
        Err(why) => return refuse_early(Failure::Configuration(why)).await,
    };

    // Which credential the host decides once, where the request first goes: a host it goes on to is checked against that
    // credential's binding, and never finds one of its own.
    let chosen = if decl.location
        == (Location::Bound {
            credential: Credential::ForHost,
        }) {
        let bound = match &shared.credentials {
            Some(source) => source.bound_to(target.host.clone()).await,
            None => Ok(None),
        };
        match bound {
            Ok(bound) => bound,
            Err(error) => {
                return refuse_early(Failure::Transient(format!(
                    "the CryptoActor did not say what is bound to the host: {error}"
                )))
                .await;
            }
        }
    } else {
        operation.credential()
    };
    let asked = Arc::new(Asked {
        decl,
        configured_host,
        chosen,
    });
    let (name, credential) = match admit::<O::Protocol>(&shared, &asked, &target).await {
        Ok(admitted) => admitted,
        Err(failure) => {
            send(Err(failure)).await;
            return;
        }
    };

    // A hop presents what it is given for where it goes, under the credential's own name: what is refused after it is that
    // credential's, as it is for the first.
    let current = Arc::new(Mutex::new(name));
    let operation = Arc::new(operation);
    let mut exchange = Exchange::<O::Protocol> {
        each: {
            let shared = shared.clone();
            let send = send.clone();
            let current = current.clone();
            Box::new(move |reply| {
                let operation = operation.clone();
                let shared = shared.clone();
                let send = send.clone();
                let current = current.clone();
                Box::pin(async move {
                    let result =
                        read_within_budget::<O>(operation, reply, O::Protocol::BUDGET).await;
                    if let Err(Failure::CredentialRefused(why)) = &result {
                        let name = current.lock().unwrap().clone();
                        if let Some(name) = name {
                            shared.refused(decl.name, &name, why);
                        }
                    }
                    let unread = result.is_err();
                    send(result).await && !unread
                })
            })
        },
        hop: {
            let shared = shared.clone();
            let asked = asked.clone();
            let current = current.clone();
            Box::new(move |target| {
                let shared = shared.clone();
                let asked = asked.clone();
                let current = current.clone();
                Box::pin(async move {
                    let (name, credential) = admit::<O::Protocol>(&shared, &asked, &target).await?;
                    *current.lock().unwrap() = name;
                    Ok(credential)
                })
            })
        },
    };
    let outcome = protocol
        .perform(request, base, credential, &mut exchange)
        .await;
    if let Err(failure) = outcome {
        match &failure {
            Failure::CredentialRefused(why) => {
                let name = current.lock().unwrap().clone();
                if let Some(name) = name {
                    shared.refused(decl.name, &name, why);
                }
            }
            Failure::Backoff { wait, .. } => {
                shared
                    .not_before
                    .lock()
                    .unwrap()
                    .insert(target.host.clone(), Instant::now() + *wait);
            }
            _ => {}
        }
        send(Err(failure)).await;
    }
}

/// What the domain is told of what the CryptoActor answered. A refusal says no more than which refusal it was.
fn credential_failure(name: &str, error: CryptoError) -> Failure {
    let name = name.to_string();
    match error {
        CryptoError::SecretNotRegistered(_) => Failure::NoCredential { name },
        CryptoError::Use(UseRefusal::HostNotBound) => Failure::NotBound { name },
        CryptoError::Use(why) => Failure::CredentialUnusable {
            name,
            why: why.to_string(),
        },
        // It did not answer as it should: not the credential's fault, and it may pass.
        other => Failure::Transient(format!(
            "the CryptoActor did not give the credential `{name}`: {other}"
        )),
    }
}

/// Reads one reply on a thread of its own. Past the budget the result is dropped and said to be: a stuck `read` cannot be
/// killed, so it costs that thread until it returns, and shows as what it is.
async fn read_within_budget<O: Operation>(
    operation: Arc<O>,
    reply: <O::Protocol as Protocol>::Reply,
    budget: Duration,
) -> Result<O::Output, Failure> {
    let reading = tokio::task::spawn_blocking(move || operation.read(&reply));
    match tokio::time::timeout(budget, reading).await {
        Ok(Ok(result)) => result.map_err(Failure::from),
        Ok(Err(joined)) => {
            tracing::error!(
                operation = O::DECL.name,
                "an operation's read panicked: {joined}"
            );
            Err(Failure::ReadPanicked)
        }
        Err(_) => {
            tracing::error!(
                operation = O::DECL.name,
                ?budget,
                "an operation's read went past its budget, and its thread is held until it returns"
            );
            Err(Failure::OverBudget)
        }
    }
}

type Job = Box<dyn FnOnce(Arc<Shared>) -> Pending + Send>;

pub(crate) enum ProtocolMessage {
    /// A request of the domain's.
    Run(Job),
    /// A runtime section changed.
    SectionChanged(String),
}

/// The domain's way to its protocols, from `AgentResources::protocols`.
#[derive(Clone)]
pub struct ProtocolHandle {
    actor: ActorRef<ProtocolMessage>,
    applied: Arc<OutputPort<CredentialsApplied>>,
    in_force: Arc<Mutex<Option<CredentialsApplied>>>,
}

/// A change of a stream, as it reaches the domain actor. The next is not read until the actor has let go of this, which it
/// does by finishing with the message: so a stream goes at the pace of what the domain does with it, as a publish that waits
/// for room slows a watch (docs/architecture/cassini-backpressure.md), and a message that is dropped lets it go as well.
#[derive(Debug)]
pub struct Delivery<T> {
    /// A failure is the last the stream says: it has ended.
    pub result: Result<T, Failure>,
    _taken: tokio::sync::oneshot::Sender<()>,
}

/// A stream the domain asked for, which ends when this is dropped.
#[must_use = "a stream ends when this is dropped"]
#[derive(Debug)]
pub struct Streaming {
    _end: tokio::sync::oneshot::Sender<()>,
}

/// The handler has ended, so the agent is ending.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the protocol handler has ended")]
pub struct HandlerEnded;

impl ProtocolHandle {
    /// Makes `operation`'s request and sends each change that comes of it to `to`, wrapped by `wrap`: one message each, in
    /// order, the next once the actor has finished with the last ([`Delivery`]). It goes on until the returned [`Streaming`]
    /// is dropped or it fails, and a failure is its last message: asking again is the domain's to decide, as there are no
    /// retries in a handler.
    pub fn stream<O, M, W>(
        &self,
        operation: O,
        to: ActorRef<M>,
        wrap: W,
    ) -> Result<Streaming, HandlerEnded>
    where
        O: Operation,
        M: ractor::Message,
        W: Fn(Delivery<O::Output>) -> M + Send + Sync + 'static,
    {
        let send: Deliver<O::Output> = Arc::new(move |result| {
            let (taken, finished) = tokio::sync::oneshot::channel();
            let sent = to
                .send_message(wrap(Delivery {
                    result,
                    _taken: taken,
                }))
                .is_ok();
            Box::pin(async move {
                let _ = finished.await;
                sent
            })
        });
        let (end, ended) = tokio::sync::oneshot::channel::<()>();
        self.actor
            .cast(ProtocolMessage::Run(Box::new(move |shared| {
                Box::pin(async move {
                    tokio::select! {
                        () = run(shared, operation, send) => {}
                        _ = ended => {}
                    }
                })
            })))
            .map_err(|_| HandlerEnded)?;
        Ok(Streaming { _end: end })
    }

    /// Makes `operation`'s request and waits for what comes of it, for a domain actor that goes through its work in order,
    /// as a pull of pages does. Waiting holds that actor's mailbox and nothing else. The first reply is the answer, and a
    /// stream goes no further: [`stream`](Self::stream) is for a stream.
    pub async fn ask<O: Operation>(&self, operation: O) -> Result<O::Output, Failure> {
        let (tell, told) = tokio::sync::oneshot::channel();
        let tell = Mutex::new(Some(tell));
        let send: Deliver<O::Output> = Arc::new(move |result| {
            if let Some(tell) = tell.lock().unwrap().take() {
                let _ = tell.send(result);
            }
            Box::pin(std::future::ready(false))
        });
        let ended = || Failure::Transient(HandlerEnded.to_string());
        self.actor
            .cast(ProtocolMessage::Run(Box::new(move |shared| {
                Box::pin(run(shared, operation, send))
            })))
            .map_err(|_| ended())?;
        told.await.map_err(|_| ended())?
    }

    /// Announces what became of each version of the `credentials` section, once the CryptoActor has it: the moment a
    /// request that had no credential is worth making again.
    pub fn credentials_applied(&self) -> Arc<OutputPort<CredentialsApplied>> {
        self.applied.clone()
    }

    /// What became of the version in force, if one has been handed to the CryptoActor: for what starts after it was.
    pub fn credentials_in_force(&self) -> Option<CredentialsApplied> {
        self.in_force.lock().unwrap().clone()
    }
}

pub(crate) struct ProtocolArgs {
    pub(crate) agent: String,
    pub(crate) declared: &'static [OperationDecl],
    pub(crate) instances: Instances,
    pub(crate) credentials: Option<Arc<dyn CredentialSource>>,
    pub(crate) crypto: Option<Arc<dyn SectionKeeper>>,
    pub(crate) configuration: Arc<dyn LiveConfiguration>,
    pub(crate) health: Arc<dyn Holds>,
    pub(crate) record: Recorder,
    pub(crate) namespaces: BTreeMap<String, String>,
    pub(crate) applied: Arc<OutputPort<CredentialsApplied>>,
    pub(crate) in_force: Arc<Mutex<Option<CredentialsApplied>>>,
}

pub(crate) struct ProtocolState {
    agent: String,
    shared: Arc<Shared>,
    crypto: Option<Arc<dyn SectionKeeper>>,
    applied: Arc<OutputPort<CredentialsApplied>>,
    in_force: Arc<Mutex<Option<CredentialsApplied>>>,
    /// The version of the section last handed to the CryptoActor.
    applied_version: Option<u64>,
    /// Each request's task: ended with the actor.
    running: JoinSet<()>,
}

pub(crate) struct ProtocolActor;

#[async_trait]
impl Actor for ProtocolActor {
    type Msg = ProtocolMessage;
    type State = ProtocolState;
    type Arguments = ProtocolArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: ProtocolArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        // A version may be in force already: one that came while the actor was starting.
        myself.cast(ProtocolMessage::SectionChanged(
            credentials::SECTION_NAME.to_string(),
        ))?;
        Ok(ProtocolState {
            agent: args.agent,
            shared: Arc::new(Shared {
                declared: args.declared,
                instances: args.instances,
                credentials: args.credentials,
                configuration: args.configuration,
                health: args.health,
                record: args.record,
                namespaces: args.namespaces,
                not_before: Mutex::new(HashMap::new()),
                refused: Mutex::new(HashSet::new()),
            }),
            crypto: args.crypto,
            applied: args.applied,
            in_force: args.in_force,
            applied_version: None,
            running: JoinSet::new(),
        })
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            ProtocolMessage::Run(job) => {
                state.running.spawn(job(state.shared.clone()));
                while state.running.try_join_next().is_some() {}
            }
            ProtocolMessage::SectionChanged(section) => {
                if section == credentials::SECTION_NAME {
                    apply_section(state).await;
                }
            }
        }
        Ok(())
    }

    async fn post_stop(
        &self,
        _myself: ActorRef<Self::Msg>,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        state.running.abort_all();
        Ok(())
    }
}

/// Hands the version of the `credentials` section in force to the CryptoActor. A version that registers everything clears
/// what was refused, since it may be the new token; one that does not is held, by name and reason.
async fn apply_section(state: &mut ProtocolState) {
    let Some(crypto) = &state.crypto else {
        return;
    };
    let Some(value) = state
        .shared
        .configuration
        .section(credentials::SECTION_NAME)
        .await
    else {
        return;
    };
    // Only a new version is news: the one in force, heard of twice, must not clear what was refused under it.
    if state
        .applied_version
        .is_some_and(|applied| value.version <= applied)
    {
        return;
    }
    state.applied_version = Some(value.version);
    // The section's own `validate` has judged the limit: a body in force is one it took.
    let entries = match credentials::parse(&value.body, usize::MAX) {
        Ok(entries) => entries,
        Err(problems) => {
            state.shared.health.hold_credentials(format!(
                "the credentials section version {} does not read: {}",
                value.version,
                problems.join("; ")
            ));
            return;
        }
    };
    let applied = credentials::apply(crypto.as_ref(), &state.agent, value.version, &entries).await;
    state.shared.refused.lock().unwrap().clear();
    if applied.failed.is_empty() {
        state.shared.health.release_credentials();
    } else {
        let failed: Vec<String> = applied
            .failed
            .iter()
            .map(|(name, why)| format!("`{name}`: {why}"))
            .collect();
        state.shared.health.hold_credentials(format!(
            "the credentials section version {} was not applied whole: {}",
            value.version,
            failed.join("; ")
        ));
    }
    *state.in_force.lock().unwrap() = Some(applied.clone());
    state.applied.send(applied);
}

/// What an agent declared of its protocols.
#[derive(Clone, Copy, Default)]
pub(crate) struct ProtocolSetup {
    pub(crate) operations: &'static [OperationDecl],
    pub(crate) credentials: bool,
}

/// What the handler is started from.
pub(crate) struct Start<'a> {
    pub(crate) service_name: &'a str,
    pub(crate) setup: ProtocolSetup,
    pub(crate) config: &'a polar_env::Config,
    pub(crate) credentials: Option<CredentialPort>,
    pub(crate) crypto: Option<Arc<dyn SectionKeeper>>,
    pub(crate) configuration: ConfigurationHandle,
    pub(crate) health: HealthHandle,
}

/// The cluster's name for each namespace key the deployment names (`POLAR_CLUSTER_NAMESPACES`), as the handler reads it
/// from `env` when it starts. An operation of `operations` that names a key it does not map is refused here, once, so that
/// an agent whose requests of it could never be allowed does not start, rather than have each refused.
pub(crate) fn cluster_namespaces(
    env: &dyn polar_env::Env,
    operations: &[OperationDecl],
) -> Result<BTreeMap<String, String>, String> {
    let variable = crate::environment::CLUSTER_NAMESPACES.name();
    let namespaces = match polar_env::Env::var(env, variable) {
        Some(raw) => crate::environment::parse_cluster_namespaces(&raw)
            .map_err(|why| format!("{variable}: {why}"))?,
        None => BTreeMap::new(),
    };
    let unmapped: Vec<String> = operations
        .iter()
        .filter_map(|operation| match operation.location {
            Location::Cluster {
                namespace: Some(key),
                ..
            } if !namespaces.contains_key(key) => {
                Some(format!("`{key}` (operation `{}`)", operation.name))
            }
            _ => None,
        })
        .collect();
    if !unmapped.is_empty() {
        return Err(format!(
            "{variable} does not name the cluster's namespace for {}: the agent's requests there could never be allowed",
            unmapped.join(", ")
        ));
    }
    Ok(namespaces)
}

/// Starts the handler linked under `supervisor`, for an agent that declares operations or credentials.
pub(crate) async fn start(
    supervisor: ActorCell,
    start: Start<'_>,
) -> Result<Option<ProtocolHandle>, ActorProcessingErr> {
    if start.setup.operations.is_empty() && !start.setup.credentials {
        return Ok(None);
    }
    // The cluster's name for each namespace its operations name by key, as the deployment says; read before the handler
    // starts, as every variable the builder reads is, and refused if it misses one they name.
    let namespaces = cluster_namespaces(start.config, start.setup.operations)
        .map_err(ActorProcessingErr::from)?;
    let instances = Instances::start(start.setup.operations, start.config)
        .await
        .map_err(ActorProcessingErr::from)?;
    let applied = Arc::new(OutputPort::default());
    let in_force = Arc::new(Mutex::new(None));
    let (actor, _) = Actor::spawn_linked(
        Some(format!("{}.protocols", start.service_name)),
        ProtocolActor,
        ProtocolArgs {
            agent: start.service_name.to_string(),
            declared: start.setup.operations,
            instances,
            credentials: start
                .credentials
                .map(|port| Arc::new(port) as Arc<dyn CredentialSource>),
            crypto: start.crypto,
            configuration: Arc::new(start.configuration.clone()),
            health: Arc::new(start.health),
            record: Arc::new(log_request),
            namespaces,
            applied: applied.clone(),
            in_force: in_force.clone(),
        },
        supervisor,
    )
    .await
    .map_err(ActorProcessingErr::from)?;
    start
        .configuration
        .runtime_changes()
        .subscribe(actor.clone(), |changed| {
            Some(ProtocolMessage::SectionChanged(changed.section))
        });
    Ok(Some(ProtocolHandle {
        actor,
        applied,
        in_force,
    }))
}

/// What is wrong with what an agent declares of its operations and credentials, whatever its configuration.
pub(crate) fn problems(
    agent: &str,
    operations: &[OperationDecl],
    credentials: Option<&crate::runtime::RuntimeSection>,
    variables: &[&str],
    cassini_client: bool,
    needs: &[crate::Capability],
) -> Vec<String> {
    let mut problems = Vec::new();
    if let Some(section) = credentials {
        if section.name != credentials::SECTION_NAME {
            problems.push(format!(
                "{agent} declares credentials in a section called `{}`: make it with protocol::credentials::section",
                section.name
            ));
        }
        if !cassini_client {
            problems.push(format!(
                "{agent} declares credentials but is not a Cassini client, so none can reach it"
            ));
        }
    }
    for (i, operation) in operations.iter().enumerate() {
        let name = operation.name;
        let valid = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.');
        if !valid {
            problems.push(format!(
                "operation `{name}` is not a name (lowercase letters, digits, hyphens and dots)"
            ));
        }
        if operations[..i].iter().any(|other| other.name == name) {
            problems.push(format!("operation `{name}` is declared more than once"));
        }
        let credential = match operation.location {
            Location::Configured {
                variable,
                credential,
            } => {
                if !variables.contains(&variable) {
                    problems.push(format!(
                        "operation `{name}` goes to the host of {variable}, which {agent} does not declare"
                    ));
                }
                credential
            }
            Location::Bound { credential } => Some(credential),
            Location::Arbitrary | Location::Cluster { .. } => None,
        };
        let to_the_cluster = matches!(operation.location, Location::Cluster { .. });
        if let Location::Cluster { access: &[], .. } = operation.location {
            problems.push(format!(
                "operation `{name}` goes to the cluster and declares nothing it may do there"
            ));
        }
        if let Location::Cluster {
            namespace: Some(key),
            ..
        } = operation.location
        {
            let a_key = !key.is_empty()
                && key
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
            if !a_key {
                problems.push(format!(
                    "operation `{name}` names the namespace `{key}`, which is not a key of the cluster's namespaces (lowercase letters, digits and hyphens)"
                ));
            }
        }
        if to_the_cluster != operation.protocol.to_the_cluster() {
            problems.push(format!(
                "operation `{name}`: the Kubernetes protocol goes to the cluster and nothing else does"
            ));
        }
        // What it may do there is what one of its capabilities' RBAC grants it, and the token comes with that capability.
        // Exactly one: the role it is computed into and the token it goes with are that capability's, in its namespace.
        if let Location::Cluster { access, namespace } = operation.location {
            let held = namespace
                .map(|key| format!(" in `{key}`"))
                .unwrap_or_default();
            for wanted in access {
                match crate::capability::holders(needs, wanted, namespace).as_slice() {
                    [] => problems.push(format!(
                        "operation `{name}` may {wanted}{held}, and none of {agent}'s capabilities grants it"
                    )),
                    [_] => {}
                    many => problems.push(format!(
                        "operation `{name}` may {wanted}{held}, and more than one of {agent}'s capabilities grants it ({}): one must hold it",
                        many.iter()
                            .map(|c| c.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                }
            }
        }
        if credential.is_some() && credentials.is_none() {
            problems.push(format!(
                "operation `{name}` uses a credential, and {agent} declares no credentials"
            ));
        }
        if matches!(
            operation.location,
            Location::Configured {
                credential: Some(Credential::ForHost),
                ..
            }
        ) {
            problems.push(format!(
                "operation `{name}` goes to a configured host and asks for what is bound to the host it learns: name its credential"
            ));
        }
    }
    problems
}

/// An operation as the scaffold prints it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OperationEntry {
    pub name: String,
    pub doc: String,
    pub protocol: String,
    /// `configured`, `bound`, `arbitrary` or `cluster`.
    pub location: String,
    /// What a cluster operation may do there, as RBAC names it: `watch pods`, `create batch/jobs`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub access: Vec<String>,
    /// The namespace a cluster operation is held to, by its key in the cluster's namespaces: `builds`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// The variable a configured operation goes to the host of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variable: Option<String>,
    /// The credential it uses: its name, `chosen` for one the request names, or `for-host` for the one bound to where it
    /// goes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

impl From<&OperationDecl> for OperationEntry {
    fn from(operation: &OperationDecl) -> Self {
        let (location, variable, credential) = match operation.location {
            Location::Configured {
                variable,
                credential,
            } => ("configured", Some(variable.to_string()), credential),
            Location::Bound { credential } => ("bound", None, Some(credential)),
            Location::Arbitrary => ("arbitrary", None, None),
            Location::Cluster { .. } => ("cluster", None, None),
        };
        let (access, namespace) = match operation.location {
            Location::Cluster { access, namespace } => (
                access.iter().map(ToString::to_string).collect(),
                namespace.map(str::to_string),
            ),
            _ => (Vec::new(), None),
        };
        Self {
            name: operation.name.to_string(),
            doc: operation.doc.to_string(),
            protocol: operation.protocol.as_str().to_string(),
            location: location.to_string(),
            access,
            namespace,
            variable,
            credential: credential.map(|credential| match credential {
                Credential::Named(name) => name.to_string(),
                Credential::Chosen => "chosen".to_string(),
                Credential::ForHost => "for-host".to_string(),
            }),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::credentials::tests_support::{FakeCrypto, ciphertext};
    use super::*;
    use polar_crypto::Zeroizing;
    use proptest::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const WATCH_PODS: &[Access] = &[Access::new(Verb::Watch, "", "pods")];
    const CREATE_JOBS: &[Access] = &[Access::new(Verb::Create, "batch", "jobs")];
    const CREATE_SECRETS: &[Access] = &[Access::new(Verb::Create, "", "secrets")];
    const WATCH_PODS_AND_CREATE_JOBS: &[Access] = &[
        Access::new(Verb::Watch, "", "pods"),
        Access::new(Verb::Create, "batch", "jobs"),
    ];

    // -- a protocol with nothing real in it ---------------------------------------------------------------------------

    /// A request to the test protocol: where it goes, and what the far end does.
    #[derive(Clone)]
    pub(crate) struct TestRequest {
        pub(crate) url: String,
        pub(crate) encrypted: bool,
        pub(crate) answer: Answer,
    }

    #[derive(Clone)]
    pub(crate) enum Answer {
        /// Answers with this body, once.
        Body(String),
        /// Answers with each of these, as a stream does.
        Stream(Vec<String>),
        /// These bodies, in order, and then it never says anything again.
        StreamThenHangs(Vec<String>),
        /// These bodies, in order, and then it fails.
        StreamThenFails(Vec<String>),
        /// Refuses the credential.
        Refuses,
        /// Asks for time.
        Busy(Duration),
        /// Never answers.
        Hangs,
    }

    #[derive(Debug)]
    pub(crate) struct TestReply {
        pub(crate) body: String,
    }

    /// What the far end saw: the credential presented, and where.
    pub(crate) static TEST_WIRE: Mutex<Vec<(String, Option<Vec<u8>>)>> = Mutex::new(Vec::new());

    pub(crate) struct TestProtocol;

    impl sealed::Sealed for TestProtocol {}

    pub(crate) fn start_test_protocol(_: &polar_env::Config) -> Pending<Result<Started, String>> {
        Box::pin(async { Ok(Arc::new(TestProtocol) as Started) })
    }

    #[async_trait]
    impl Protocol for TestProtocol {
        const KIND: ProtocolKind = ProtocolKind::TEST;
        const BUDGET: Duration = Duration::from_millis(200);
        type Request = TestRequest;
        type Credential = Zeroizing<Vec<u8>>;
        type Reply = TestReply;

        fn configured_host(base: &str) -> Result<String, String> {
            Ok(base.to_string())
        }
        fn target(request: &TestRequest, base: Option<&str>) -> Result<Target, String> {
            let host = base.unwrap_or(&request.url).to_string();
            if host == "unreadable" {
                return Err("the location cannot be read".to_string());
            }
            Ok(Target {
                host,
                encrypted: request.encrypted,
                access: None,
                reaches_node: Vec::new(),
                namespace: None,
            })
        }
        async fn credential(
            source: &dyn CredentialSource,
            name: String,
            host: String,
        ) -> Result<Self::Credential, CryptoError> {
            Ok(source.git(name, host).await?.secret)
        }
        async fn perform(
            &self,
            request: TestRequest,
            base: Option<String>,
            credential: Option<Self::Credential>,
            exchange: &mut Exchange<Self>,
        ) -> Result<(), Failure> {
            let host = base.unwrap_or(request.url);
            TEST_WIRE
                .lock()
                .unwrap()
                .push((host, credential.as_ref().map(|c| c.to_vec())));
            match request.answer {
                Answer::Body(body) => {
                    exchange.reply(TestReply { body }).await;
                    Ok(())
                }
                Answer::Stream(bodies) => {
                    for body in bodies {
                        if !exchange.reply(TestReply { body }).await {
                            break;
                        }
                    }
                    Ok(())
                }
                Answer::StreamThenHangs(bodies) => {
                    for body in bodies {
                        if !exchange.reply(TestReply { body }).await {
                            return Ok(());
                        }
                    }
                    std::future::pending().await
                }
                Answer::StreamThenFails(bodies) => {
                    for body in bodies {
                        if !exchange.reply(TestReply { body }).await {
                            return Ok(());
                        }
                    }
                    Err(Failure::Transient("it lost the far end".to_string()))
                }
                Answer::Refuses => Err(Failure::CredentialRefused("the site said no".to_string())),
                Answer::Busy(wait) => Err(Failure::Backoff { status: 503, wait }),
                Answer::Hangs => std::future::pending().await,
            }
        }
    }

    // -- operations ----------------------------------------------------------------------------------------------------

    const fn decl(name: &'static str, location: Location) -> OperationDecl {
        OperationDecl {
            name,
            doc: "",
            protocol: ProtocolKind::TEST,
            location,
        }
    }

    /// An operation, declared by its marker, whose `read` gives the body back.
    macro_rules! operation {
        ($ty:ident, $name:literal, $location:expr) => {
            pub(crate) struct $ty {
                pub(crate) request: TestRequest,
                pub(crate) chosen: Option<String>,
            }
            impl Operation for $ty {
                type Protocol = TestProtocol;
                type Output = String;
                const DECL: OperationDecl = decl($name, $location);
                fn request(&self) -> TestRequest {
                    self.request.clone()
                }
                fn credential(&self) -> Option<String> {
                    self.chosen.clone()
                }
                fn read(&self, reply: &TestReply) -> Result<String, ReadFailure> {
                    read_body(&reply.body)
                }
            }
        };
    }

    /// How many `counted` bodies have been read, by the one test that sends them.
    static COUNTED_READS: AtomicUsize = AtomicUsize::new(0);

    /// What every test operation's `read` does with a body: some bodies say how it should misbehave.
    fn read_body(body: &str) -> Result<String, ReadFailure> {
        match body {
            "panic" => panic!("a read that panics"),
            "block" => {
                BLOCKED.wait_until_released();
                Ok(body.to_string())
            }
            "anonymous" => Err(ReadFailure::CredentialRefused(
                "the site answered as if for nobody".to_string(),
            )),
            "garbled" => Err(ReadFailure::Malformed("not what was expected".to_string())),
            "counted" => {
                COUNTED_READS.fetch_add(1, Ordering::SeqCst);
                Ok(body.to_string())
            }
            _ => Ok(body.to_string()),
        }
    }

    /// Where a blocked `read` waits.
    struct Blocked {
        released: Mutex<bool>,
        changed: std::sync::Condvar,
        entered: AtomicUsize,
    }

    static BLOCKED: Blocked = Blocked {
        released: Mutex::new(false),
        changed: std::sync::Condvar::new(),
        entered: AtomicUsize::new(0),
    };

    impl Blocked {
        fn wait_until_released(&self) {
            self.entered.fetch_add(1, Ordering::SeqCst);
            let mut released = self.released.lock().unwrap();
            while !*released {
                released = self.changed.wait(released).unwrap();
            }
        }
        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.changed.notify_all();
        }
    }

    operation!(
        Site,
        "site.read",
        Location::Configured {
            variable: "SITE_URL",
            credential: Some(Credential::Named("site")),
        }
    );
    operation!(
        Open,
        "open.read",
        Location::Configured {
            variable: "OPEN_URL",
            credential: None,
        }
    );
    operation!(
        Learned,
        "learned.read",
        Location::Bound {
            credential: Credential::Chosen,
        }
    );
    operation!(Anywhere, "anywhere.read", Location::Arbitrary);
    operation!(Undeclared, "undeclared.read", Location::Arbitrary);

    static DECLARED: [OperationDecl; 4] = [Site::DECL, Open::DECL, Learned::DECL, Anywhere::DECL];

    // -- the far side of the handler -----------------------------------------------------------------------------------

    /// The CryptoActor's answers: `name` is bound to `host`, with `secret`.
    struct FakeSource {
        name: String,
        host: String,
        secret: Vec<u8>,
    }

    #[async_trait]
    impl CredentialSource for FakeSource {
        async fn http(&self, _: String, _: String) -> Result<HttpCredential, CryptoError> {
            unreachable!("the test protocol asks as git does")
        }
        async fn git(&self, name: String, host: String) -> Result<GitCredential, CryptoError> {
            if name != self.name {
                return Err(CryptoError::SecretNotRegistered(name));
            }
            if host != self.host {
                return Err(CryptoError::Use(UseRefusal::HostNotBound));
            }
            Ok(GitCredential {
                kind: polar_crypto::registry::SecretKind::Token,
                username: "oauth2".to_string(),
                secret: Zeroizing::new(self.secret.clone()),
                host_keys: Vec::new(),
            })
        }
        async fn bound_to(&self, host: String) -> Result<Option<String>, CryptoError> {
            Ok((host == self.host).then(|| self.name.clone()))
        }
    }

    #[derive(Default)]
    struct FakeConfiguration {
        values: Mutex<HashMap<String, String>>,
        section: Mutex<Option<RuntimeValue>>,
    }

    #[async_trait]
    impl LiveConfiguration for FakeConfiguration {
        async fn value(&self, name: &str) -> Option<String> {
            self.values.lock().unwrap().get(name).cloned()
        }
        async fn section(&self, _: &str) -> Option<RuntimeValue> {
            self.section.lock().unwrap().clone()
        }
    }

    #[derive(Default)]
    struct FakeHealth {
        held: Mutex<Vec<String>>,
        released: AtomicUsize,
    }

    impl Holds for FakeHealth {
        fn hold_credentials(&self, message: String) {
            self.held.lock().unwrap().push(message);
        }
        fn release_credentials(&self) {
            self.released.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// The domain actor: it keeps what it is sent.
    struct Domain;

    type Got = Arc<Mutex<Vec<Result<String, Failure>>>>;

    #[async_trait]
    impl Actor for Domain {
        type Msg = Result<String, Failure>;
        type State = Got;
        type Arguments = Got;
        async fn pre_start(
            &self,
            _: ActorRef<Self::Msg>,
            got: Got,
        ) -> Result<Got, ActorProcessingErr> {
            Ok(got)
        }
        async fn handle(
            &self,
            _: ActorRef<Self::Msg>,
            message: Self::Msg,
            got: &mut Got,
        ) -> Result<(), ActorProcessingErr> {
            got.lock().unwrap().push(message);
            Ok(())
        }
    }

    const SECRET: &str = "the-very-secret-token";

    struct Rig {
        protocols: ProtocolHandle,
        actor: ActorRef<ProtocolMessage>,
        domain: ActorRef<Result<String, Failure>>,
        got: Got,
        configuration: Arc<FakeConfiguration>,
        health: Arc<FakeHealth>,
        crypto: Arc<FakeCrypto>,
        records: Arc<Mutex<Vec<RequestRecord>>>,
        wire_host: String,
        /// The streams of what a test asked for, which last as long as it does.
        streams: Mutex<Vec<Streaming>>,
        /// What a test has taken and wants to look at afterwards.
        kept: Mutex<Vec<Result<String, Failure>>>,
    }

    /// Each test gets a site of its own, so what the wire saw can be told apart from another test's.
    fn fresh_host() -> String {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        format!("site-{}.example.org", NEXT.fetch_add(1, Ordering::SeqCst))
    }

    async fn rig_with(secret: &str) -> Rig {
        rig_refusing(secret, Vec::new()).await
    }

    /// A rig whose CryptoActor refuses to register `refuse`.
    async fn rig_refusing(secret: &str, refuse: Vec<String>) -> Rig {
        let host = fresh_host();
        let got: Got = Arc::default();
        let (domain, _) = Actor::spawn(None, Domain, got.clone()).await.unwrap();
        let configuration = Arc::new(FakeConfiguration::default());
        configuration
            .values
            .lock()
            .unwrap()
            .insert("SITE_URL".to_string(), host.clone());
        let health = Arc::new(FakeHealth::default());
        let crypto = Arc::new(FakeCrypto {
            refuse,
            ..Default::default()
        });
        let records: Arc<Mutex<Vec<RequestRecord>>> = Arc::default();
        let applied = Arc::new(OutputPort::default());
        let in_force = Arc::new(Mutex::new(None));
        let recorded = records.clone();
        let (actor, _) = Actor::spawn(
            None,
            ProtocolActor,
            ProtocolArgs {
                agent: "an-agent".to_string(),
                declared: &DECLARED,
                instances: Instances::of(TestProtocol),
                credentials: Some(Arc::new(FakeSource {
                    name: "site".to_string(),
                    host: host.clone(),
                    secret: secret.as_bytes().to_vec(),
                })),
                crypto: Some(crypto.clone()),
                configuration: configuration.clone(),
                health: health.clone(),
                record: Arc::new(move |record| recorded.lock().unwrap().push(record.clone())),
                namespaces: BTreeMap::new(),
                applied: applied.clone(),
                in_force: in_force.clone(),
            },
        )
        .await
        .unwrap();
        Rig {
            protocols: ProtocolHandle {
                actor: actor.clone(),
                applied,
                in_force,
            },
            actor,
            domain,
            got,
            configuration,
            health,
            crypto,
            records,
            wire_host: host,
            streams: Mutex::default(),
            kept: Mutex::default(),
        }
    }

    async fn rig() -> Rig {
        rig_with(SECRET).await
    }

    fn request(answer: Answer) -> TestRequest {
        TestRequest {
            url: "unused.example.org".to_string(),
            encrypted: true,
            answer,
        }
    }

    fn at(url: &str, answer: Answer) -> TestRequest {
        TestRequest {
            url: url.to_string(),
            encrypted: true,
            answer,
        }
    }

    impl Rig {
        fn ask<O: Operation<Output = String>>(&self, operation: O) {
            let stream = self
                .protocols
                .stream(operation, self.domain.clone(), |delivery| delivery.result)
                .unwrap();
            self.streams.lock().unwrap().push(stream);
        }

        /// Waits for the domain to have been sent `count` messages, and takes them.
        async fn answers(&self, count: usize) -> Vec<Result<String, Failure>> {
            for _ in 0..500 {
                if self.got.lock().unwrap().len() >= count {
                    return self.got.lock().unwrap().drain(..).collect();
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            panic!(
                "expected {count} messages; got {:?}",
                self.got.lock().unwrap()
            );
        }

        async fn answer(&self) -> Result<String, Failure> {
            self.answers(1).await.remove(0)
        }

        /// What the far end saw of this rig's site.
        fn presented(&self) -> Vec<Option<Vec<u8>>> {
            TEST_WIRE
                .lock()
                .unwrap()
                .iter()
                .filter(|(host, _)| *host == self.wire_host)
                .map(|(_, credential)| credential.clone())
                .collect()
        }

        fn site(&self, answer: Answer) -> Site {
            Site {
                request: request(answer),
                chosen: None,
            }
        }

        fn keep(&self, answers: Vec<Result<String, Failure>>) {
            self.kept.lock().unwrap().extend(answers);
        }

        /// Whether the credential has been refused.
        fn is_refused(&self) -> bool {
            !self.health.held.lock().unwrap().is_empty()
        }

        /// A new version of the section arrives, with one entry.
        async fn new_version(&self, version: u64) {
            let body = serde_json::json!({"credentials": [{
                "name": "site", "host_pattern": self.wire_host, "kind": "token",
                "secret": ciphertext(b"new-token", b"context"),
            }]});
            *self.configuration.section.lock().unwrap() = Some(RuntimeValue {
                version,
                id: format!("credentials-{version}"),
                body,
                signer: "someone".to_string(),
            });
            self.actor
                .cast(ProtocolMessage::SectionChanged("credentials".to_string()))
                .unwrap();
            for _ in 0..500 {
                if !self.crypto.kept.lock().unwrap().is_empty() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            panic!("the section was not applied");
        }
    }

    // -- the tests -----------------------------------------------------------------------------------------------------

    #[tokio::test]
    async fn the_handler_gets_the_credential_presents_it_and_the_domain_gets_the_value_as_a_message()
     {
        let r = rig().await;
        r.ask(r.site(Answer::Body("the data".to_string())));
        assert_eq!(r.answer().await, Ok("the data".to_string()));
        assert_eq!(r.presented(), vec![Some(SECRET.as_bytes().to_vec())]);
        let records = r.records.lock().unwrap();
        assert_eq!(
            records[0],
            RequestRecord {
                operation: "site.read",
                protocol: "test",
                host: r.wire_host.clone(),
                credential: Some("site".to_string()),
                arbitrary: false,
                verdict: "allowed".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn the_configured_host_is_read_as_it_is_in_force_for_each_request() {
        let r = rig().await;
        let moved = fresh_host();
        r.configuration
            .values
            .lock()
            .unwrap()
            .insert("OPEN_URL".to_string(), moved.clone());
        let open = || Open {
            request: at("unused", Answer::Body("a".to_string())),
            chosen: None,
        };
        r.ask(open());
        assert_eq!(r.answer().await, Ok("a".to_string()));
        assert_eq!(r.records.lock().unwrap()[0].host, moved);

        let again = fresh_host();
        r.configuration
            .values
            .lock()
            .unwrap()
            .insert("OPEN_URL".to_string(), again.clone());
        r.ask(open());
        assert_eq!(r.answer().await, Ok("a".to_string()));
        assert_eq!(r.records.lock().unwrap()[1].host, again);
    }

    #[tokio::test]
    async fn an_undeclared_operation_is_denied_recorded_and_never_made() {
        let r = rig().await;
        let host = fresh_host();
        r.ask(Undeclared {
            request: at(&host, Answer::Body("no".to_string())),
            chosen: None,
        });
        assert_eq!(r.answer().await, Err(Failure::Denied(Denial::Undeclared)));
        assert!(TEST_WIRE.lock().unwrap().iter().all(|(h, _)| *h != host));
        let records = r.records.lock().unwrap();
        assert_eq!(records[0].operation, "undeclared.read");
        assert!(
            records[0].verdict.contains("does not declare"),
            "{records:?}"
        );
    }

    #[tokio::test]
    async fn an_arbitrary_request_goes_without_a_credential_and_is_marked() {
        let r = rig().await;
        let host = fresh_host();
        r.ask(Anywhere {
            request: at(&host, Answer::Body("public".to_string())),
            // What it names changes nothing.
            chosen: Some("site".to_string()),
        });
        assert_eq!(r.answer().await, Ok("public".to_string()));
        let wire = TEST_WIRE.lock().unwrap();
        let (_, presented) = wire.iter().find(|(h, _)| *h == host).unwrap();
        assert_eq!(*presented, None);
        let records = r.records.lock().unwrap();
        assert!(records[0].arbitrary);
        assert_eq!(records[0].credential, None);
    }

    #[tokio::test]
    async fn a_host_off_the_binding_gets_nothing_and_nothing_is_sent() {
        let r = rig().await;
        let host = fresh_host();
        r.ask(Learned {
            request: at(&host, Answer::Body("no".to_string())),
            chosen: Some("site".to_string()),
        });
        assert_eq!(
            r.answer().await,
            Err(Failure::NotBound {
                name: "site".to_string()
            })
        );
        assert!(TEST_WIRE.lock().unwrap().iter().all(|(h, _)| *h != host));
        assert!(r.records.lock().unwrap()[0].verdict.contains("not bound"));
    }

    #[tokio::test]
    async fn a_host_on_the_binding_gets_the_credential_the_request_names() {
        let r = rig().await;
        r.ask(Learned {
            request: at(&r.wire_host.clone(), Answer::Body("yes".to_string())),
            chosen: Some("site".to_string()),
        });
        assert_eq!(r.answer().await, Ok("yes".to_string()));
        assert_eq!(r.presented(), vec![Some(SECRET.as_bytes().to_vec())]);
    }

    #[tokio::test]
    async fn a_credential_that_has_not_arrived_is_said_to_and_nothing_is_sent() {
        let r = rig().await;
        r.ask(Learned {
            request: at(&r.wire_host.clone(), Answer::Body("no".to_string())),
            chosen: Some("other".to_string()),
        });
        assert_eq!(
            r.answer().await,
            Err(Failure::NoCredential {
                name: "other".to_string()
            })
        );
        assert!(r.presented().is_empty());
    }

    #[tokio::test]
    async fn an_unset_variable_or_a_location_that_cannot_be_read_goes_nowhere() {
        let r = rig().await;
        r.ask(Open {
            request: at("unused", Answer::Body("no".to_string())),
            chosen: None,
        });
        assert_eq!(
            r.answer().await,
            Err(Failure::Denied(Denial::NotConfigured))
        );
        r.ask(Anywhere {
            request: at("unreadable", Answer::Body("no".to_string())),
            chosen: None,
        });
        assert!(matches!(r.answer().await, Err(Failure::Configuration(_))));
    }

    /// A stream's changes arrive one message each, in order, however long each takes to read.
    #[tokio::test]
    async fn each_change_of_a_stream_is_a_message_in_order() {
        let r = rig().await;
        let bodies: Vec<String> = (0..50).map(|i| format!("change {i}")).collect();
        r.ask(r.site(Answer::Stream(bodies.clone())));
        let got: Vec<String> = r
            .answers(50)
            .await
            .into_iter()
            .map(Result::unwrap)
            .collect();
        assert_eq!(got, bodies);
    }

    /// A domain actor that holds on to each delivery until it is told to let go.
    struct Holding;

    type Held = Arc<Mutex<Vec<Delivery<String>>>>;

    #[async_trait]
    impl Actor for Holding {
        type Msg = Delivery<String>;
        type State = Held;
        type Arguments = Held;
        async fn pre_start(
            &self,
            _: ActorRef<Self::Msg>,
            held: Held,
        ) -> Result<Held, ActorProcessingErr> {
            Ok(held)
        }
        async fn handle(
            &self,
            _: ActorRef<Self::Msg>,
            message: Self::Msg,
            held: &mut Held,
        ) -> Result<(), ActorProcessingErr> {
            held.lock().unwrap().push(message);
            Ok(())
        }
    }

    async fn holding() -> (ActorRef<Delivery<String>>, Held) {
        let held = Held::default();
        let (actor, _) = Actor::spawn(None, Holding, held.clone()).await.unwrap();
        (actor, held)
    }

    /// Waits for `held` to hold `count`, and takes the value of the last.
    async fn held_count(held: &Held, count: usize) -> Option<Result<String, Failure>> {
        for _ in 0..500 {
            {
                let held = held.lock().unwrap();
                if held.len() >= count {
                    return held.last().map(|last| last.result.clone());
                }
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!(
            "expected {count} deliveries; got {:?}",
            held.lock().unwrap()
        );
    }

    fn strings(bodies: &[&str]) -> Vec<String> {
        bodies.iter().map(|body| body.to_string()).collect()
    }

    /// docs/architecture/cassini-backpressure.md: a watch slows when what it publishes has to wait, so the next change does
    /// not reach a domain still busy with the last.
    #[tokio::test]
    async fn the_next_change_waits_until_the_domain_has_finished_with_the_last() {
        let r = rig().await;
        let (domain, held) = holding().await;
        let stream = r
            .protocols
            .stream(
                r.site(Answer::Stream(strings(&["one", "two"]))),
                domain,
                |delivery| delivery,
            )
            .unwrap();
        assert_eq!(held_count(&held, 1).await, Some(Ok("one".to_string())));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(held.lock().unwrap().len(), 1, "it waits");
        let first = held.lock().unwrap().remove(0);
        drop(first);
        assert_eq!(held_count(&held, 1).await, Some(Ok("two".to_string())));
        drop(stream);
    }

    #[tokio::test]
    async fn a_domain_busy_with_one_stream_holds_up_no_other() {
        let r = rig().await;
        let (domain, held) = holding().await;
        let _stuck = r
            .protocols
            .stream(
                r.site(Answer::Stream(strings(&["one", "two"]))),
                domain,
                |delivery| delivery,
            )
            .unwrap();
        held_count(&held, 1).await;
        r.ask(r.site(Answer::Stream(strings(&["other", "more"]))));
        let got: Vec<String> = r.answers(2).await.into_iter().map(Result::unwrap).collect();
        assert_eq!(got, strings(&["other", "more"]));
    }

    #[tokio::test]
    async fn dropping_a_stream_ends_it() {
        let r = rig().await;
        let (domain, held) = holding().await;
        let stream = r
            .protocols
            .stream(
                r.site(Answer::StreamThenHangs(strings(&["one", "two"]))),
                domain,
                |delivery| delivery,
            )
            .unwrap();
        held_count(&held, 1).await;
        drop(stream);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let first = held.lock().unwrap().remove(0);
        drop(first);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(held.lock().unwrap().is_empty(), "nothing followed");
    }

    #[tokio::test]
    async fn a_stream_that_fails_says_so_last() {
        let r = rig().await;
        r.ask(r.site(Answer::StreamThenFails(strings(&["one", "two"]))));
        let got = r.answers(3).await;
        assert_eq!(got[0], Ok("one".to_string()));
        assert_eq!(got[1], Ok("two".to_string()));
        assert_eq!(
            got[2],
            Err(Failure::Transient("it lost the far end".to_string()))
        );
    }

    /// A stream says each change once, so one that could not be read leaves the domain with a gap: it ends, and what the
    /// domain asks for next starts afresh.
    #[tokio::test]
    async fn a_change_that_cannot_be_read_ends_the_stream() {
        let r = rig().await;
        r.ask(r.site(Answer::Stream(strings(&["one", "garbled", "three"]))));
        let got = r.answers(2).await;
        assert_eq!(got[0], Ok("one".to_string()));
        assert!(matches!(got[1], Err(Failure::Read(_))), "{got:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(r.got.lock().unwrap().is_empty(), "nothing followed");
    }

    /// Nobody listening means nothing more is read, and an answer needs only its first reply.
    #[tokio::test]
    async fn a_stream_stops_when_the_domain_has_gone_or_has_its_answer() {
        COUNTED_READS.store(0, Ordering::SeqCst);
        let r = rig().await;
        assert_eq!(
            r.protocols
                .ask(r.site(Answer::Stream(strings(&["counted", "counted"]))))
                .await,
            Ok("counted".to_string())
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(COUNTED_READS.load(Ordering::SeqCst), 1);

        let (domain, _held) = holding().await;
        domain
            .stop_and_wait(None, Some(Duration::from_secs(5)))
            .await
            .unwrap();
        let _stream = r
            .protocols
            .stream(
                r.site(Answer::StreamThenHangs(strings(&["counted", "counted"]))),
                domain,
                |delivery| delivery,
            )
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(COUNTED_READS.load(Ordering::SeqCst), 2);
    }

    /// A `read` that does not return stalls nothing else, and one past its budget is reported and its result dropped.
    /// The last thing it does is released, so that the test's thread goes back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_blocked_read_stalls_nothing_else_and_past_its_budget_is_reported() {
        /// Lets the blocked read go however the test ends: a runtime waits for its threads, so a failure here would hang.
        struct ReleaseAtTheEnd;
        impl Drop for ReleaseAtTheEnd {
            fn drop(&mut self) {
                BLOCKED.release();
            }
        }
        let _release = ReleaseAtTheEnd;
        let r = rig().await;
        r.ask(r.site(Answer::Body("block".to_string())));
        for _ in 0..500 {
            if BLOCKED.entered.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert!(BLOCKED.entered.load(Ordering::SeqCst) > 0, "the read began");
        r.ask(r.site(Answer::Body("meanwhile".to_string())));
        let first = r.answer().await;
        assert_eq!(first, Ok("meanwhile".to_string()), "nothing was stalled");
        assert_eq!(r.answer().await, Err(Failure::OverBudget));
        BLOCKED.release();
        // It returned after all, and that does not reach the domain.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(r.got.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_read_that_panics_is_reported_and_the_handler_goes_on() {
        let r = rig().await;
        r.ask(r.site(Answer::Body("panic".to_string())));
        assert_eq!(r.answer().await, Err(Failure::ReadPanicked));
        r.ask(r.site(Answer::Body("still here".to_string())));
        assert_eq!(r.answer().await, Ok("still here".to_string()));
    }

    #[tokio::test]
    async fn a_read_that_cannot_make_sense_of_it_says_so() {
        let r = rig().await;
        r.ask(r.site(Answer::Body("garbled".to_string())));
        assert!(matches!(r.answer().await, Err(Failure::Read(_))));
        assert!(r.health.held.lock().unwrap().is_empty());
    }

    /// Refused, by the far end or by what `read` makes of the answer: the agent holds it, the credential is not presented
    /// again, and a new version clears both with no agent code involved.
    #[tokio::test]
    async fn a_refused_credential_is_held_and_not_presented_again_until_a_new_version() {
        for refusal in [Answer::Refuses, Answer::Body("anonymous".to_string())] {
            let r = rig().await;
            r.ask(r.site(refusal));
            assert!(matches!(
                r.answer().await,
                Err(Failure::CredentialRefused(_))
            ));
            assert_eq!(r.presented().len(), 1);
            {
                let held = r.health.held.lock().unwrap();
                assert_eq!(held.len(), 1, "{held:?}");
                assert!(held[0].contains("`site`"), "{held:?}");
                assert!(!held[0].contains(SECRET), "{held:?}");
            }

            r.ask(r.site(Answer::Body("no".to_string())));
            assert_eq!(
                r.answer().await,
                Err(Failure::CredentialHeld {
                    name: "site".to_string()
                })
            );
            assert_eq!(r.presented().len(), 1, "it was not presented again");

            r.new_version(2).await;
            assert_eq!(r.health.released.load(Ordering::SeqCst), 1);
            r.ask(r.site(Answer::Body("again".to_string())));
            assert_eq!(r.answer().await, Ok("again".to_string()));
            assert_eq!(r.presented().len(), 2);
        }
    }

    #[tokio::test]
    async fn a_version_is_announced_once_the_crypto_actor_has_it() {
        let r = rig().await;
        let announced: Arc<Mutex<Vec<CredentialsApplied>>> = Arc::default();
        struct Listener;
        #[async_trait]
        impl Actor for Listener {
            type Msg = CredentialsApplied;
            type State = Arc<Mutex<Vec<CredentialsApplied>>>;
            type Arguments = Arc<Mutex<Vec<CredentialsApplied>>>;
            async fn pre_start(
                &self,
                _: ActorRef<Self::Msg>,
                state: Self::Arguments,
            ) -> Result<Self::State, ActorProcessingErr> {
                Ok(state)
            }
            async fn handle(
                &self,
                _: ActorRef<Self::Msg>,
                message: Self::Msg,
                state: &mut Self::State,
            ) -> Result<(), ActorProcessingErr> {
                state.lock().unwrap().push(message);
                Ok(())
            }
        }
        let (listener, _) = Actor::spawn(None, Listener, announced.clone())
            .await
            .unwrap();
        r.protocols.credentials_applied().subscribe(listener, Some);

        r.new_version(7).await;
        for _ in 0..500 {
            if !announced.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let applied = announced.lock().unwrap()[0].clone();
        assert_eq!(applied.version, 7);
        assert_eq!(applied.registered, vec!["site".to_string()]);
        assert_eq!(
            r.crypto.registered.lock().unwrap()[0].3.host_pattern,
            r.wire_host
        );
    }

    /// Hearing of the version in force again is not a new version: what was refused under it stays refused.
    #[tokio::test]
    async fn the_same_version_again_changes_nothing() {
        let r = rig().await;
        r.new_version(2).await;
        r.ask(r.site(Answer::Refuses));
        assert!(matches!(
            r.answer().await,
            Err(Failure::CredentialRefused(_))
        ));
        let registered = r.crypto.registered.lock().unwrap().len();
        let released = r.health.released.load(Ordering::SeqCst);

        r.actor
            .cast(ProtocolMessage::SectionChanged("credentials".to_string()))
            .unwrap();
        r.ask(r.site(Answer::Body("no".to_string())));
        assert_eq!(
            r.answer().await,
            Err(Failure::CredentialHeld {
                name: "site".to_string()
            })
        );
        assert_eq!(r.crypto.registered.lock().unwrap().len(), registered);
        assert_eq!(r.health.released.load(Ordering::SeqCst), released);
    }

    /// A version the CryptoActor would not take whole is a standing problem, by name, and no value; and what was refused
    /// before it is not held against what it did bring.
    #[tokio::test]
    async fn a_version_that_is_not_applied_whole_is_held() {
        let r = rig_refusing(SECRET, vec!["site".to_string()]).await;
        r.new_version(2).await;
        for _ in 0..500 {
            if !r.health.held.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let held = r.health.held.lock().unwrap();
        assert_eq!(held.len(), 1, "{held:?}");
        assert!(held[0].contains("version 2"), "{held:?}");
        assert!(held[0].contains("`site`"), "{held:?}");
        assert_eq!(r.health.released.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_host_that_asked_for_time_is_not_called_until_it_has_passed() {
        let r = rig().await;
        r.ask(r.site(Answer::Busy(Duration::from_millis(150))));
        assert!(matches!(r.answer().await, Err(Failure::Backoff { .. })));
        assert_eq!(r.presented().len(), 1);

        r.ask(r.site(Answer::Body("too soon".to_string())));
        assert!(matches!(r.answer().await, Err(Failure::NotYet { .. })));
        assert_eq!(r.presented().len(), 1, "it was not called");

        tokio::time::sleep(Duration::from_millis(200)).await;
        r.ask(r.site(Answer::Body("now".to_string())));
        assert_eq!(r.answer().await, Ok("now".to_string()));
        assert_eq!(r.presented().len(), 2);
    }

    #[tokio::test]
    async fn stopping_the_actor_ends_what_is_running() {
        let r = rig().await;
        r.ask(r.site(Answer::Hangs));
        for _ in 0..500 {
            if !r.presented().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(r.presented().len(), 1);
        r.actor
            .stop_and_wait(None, Some(Duration::from_secs(5)))
            .await
            .unwrap();
        let ended = r.protocols.stream(
            r.site(Answer::Body("no".to_string())),
            r.domain.clone(),
            |delivery| delivery.result,
        );
        assert_eq!(ended.err(), Some(HandlerEnded));
    }

    #[tokio::test]
    async fn a_protocol_is_started_only_for_an_agent_with_an_operation_that_uses_it() {
        let config = polar_env::Config::builder(&polar_env::ProcessEnv).build();
        let used = Instances::start(&DECLARED, &config).await.unwrap();
        assert!(used.get::<TestProtocol>().is_some());
        assert!(used.get::<http::Http>().is_none());
        assert!(used.get::<git::Git>().is_none());
        let none = Instances::start(&[], &config).await.unwrap();
        assert!(none.get::<TestProtocol>().is_none());
    }

    #[tokio::test]
    async fn asking_waits_for_the_one_answer_and_is_told_what_failed() {
        let r = rig().await;
        assert_eq!(
            r.protocols
                .ask(r.site(Answer::Body("the data".to_string())))
                .await,
            Ok("the data".to_string())
        );
        // A stream's first reply is the answer, and the rest go nowhere.
        assert_eq!(
            r.protocols
                .ask(r.site(Answer::Stream(vec![
                    "first".to_string(),
                    "second".to_string()
                ])))
                .await,
            Ok("first".to_string())
        );
        assert!(matches!(
            r.protocols.ask(r.site(Answer::Refuses)).await,
            Err(Failure::CredentialRefused(_))
        ));
        r.actor
            .stop_and_wait(None, Some(Duration::from_secs(5)))
            .await
            .unwrap();
        assert!(matches!(
            r.protocols
                .ask(r.site(Answer::Body("no".to_string())))
                .await,
            Err(Failure::Transient(_))
        ));
    }

    /// What starts after a version was applied can still learn what became of it.
    #[tokio::test]
    async fn what_became_of_the_version_in_force_can_be_read_later() {
        let r = rig().await;
        assert_eq!(r.protocols.credentials_in_force(), None);
        r.new_version(4).await;
        for _ in 0..500 {
            if r.protocols.credentials_in_force().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let in_force = r.protocols.credentials_in_force().unwrap();
        assert_eq!(in_force.version, 4);
        assert_eq!(in_force.registered, vec!["site".to_string()]);
    }

    #[test]
    fn what_an_agent_declares_is_judged() {
        static SECTION: crate::runtime::RuntimeSection = credentials::section::<1>("a credential");
        static WRONG: crate::runtime::RuntimeSection = crate::runtime::RuntimeSection {
            name: "not-credentials",
            ..credentials::section::<1>("a credential")
        };
        assert!(
            problems(
                "a",
                &DECLARED,
                Some(&SECTION),
                &["SITE_URL", "OPEN_URL"],
                true,
                &[],
            )
            .is_empty()
        );
        let all = problems("a", &DECLARED, None, &[], false, &[]).join(" | ");
        for expected in [
            "`site.read` goes to the host of SITE_URL",
            "`open.read` goes to the host of OPEN_URL",
            "`site.read` uses a credential",
            "`learned.read` uses a credential",
        ] {
            assert!(all.contains(expected), "{expected}: {all}");
        }
        let bad = [
            decl("Not A Name", Location::Arbitrary),
            decl("twice", Location::Arbitrary),
            decl("twice", Location::Arbitrary),
        ];
        let all = problems("a", &bad, Some(&WRONG), &[], false, &[]).join(" | ");
        for expected in [
            "`Not A Name` is not a name",
            "`twice` is declared more than once",
            "a section called `not-credentials`",
            "not a Cassini client",
        ] {
            assert!(all.contains(expected), "{expected}: {all}");
        }
        let confused = [decl(
            "confused",
            Location::Configured {
                variable: "SITE_URL",
                credential: Some(Credential::ForHost),
            },
        )];
        let all = problems("a", &confused, Some(&SECTION), &["SITE_URL"], true, &[]).join(" | ");
        assert!(all.contains("name its credential"), "{all}");

        let watches = [OperationDecl {
            name: "watches",
            doc: "",
            protocol: ProtocolKind::KUBERNETES,
            location: Location::Cluster {
                access: WATCH_PODS,
                namespace: None,
            },
        }];
        for enough in [crate::Capability::KubeApiRead, crate::Capability::PodRead] {
            assert!(problems("a", &watches, None, &[], true, &[enough]).is_empty());
        }
        let all = problems("a", &watches, None, &[], true, &[]).join(" | ");
        assert!(
            all.contains("may watch pods, and none of a's capabilities grants it"),
            "{all}"
        );
        // Two capabilities that would both grant it: which role holds it, and which token it goes with, must be one.
        let both = [crate::Capability::KubeApiRead, crate::Capability::PodRead];
        let all = problems("a", &watches, None, &[], true, &both).join(" | ");
        assert!(
            all.contains(
                "may watch pods, and more than one of a's capabilities grants it (kube-api-read, pod-read)"
            ),
            "{all}"
        );

        // A write is granted by job-run alone, in its namespace, and kube-api-read, which reads anything but Secrets,
        // grants none.
        let makes = [OperationDecl {
            name: "makes",
            doc: "",
            protocol: ProtocolKind::KUBERNETES,
            location: Location::Cluster {
                access: CREATE_JOBS,
                namespace: Some("builds"),
            },
        }];
        assert!(problems("a", &makes, None, &[], true, &[crate::Capability::JobRun]).is_empty());
        // The same write held to no namespace, or to another, is not job-run's to grant.
        for elsewhere in [None, Some("core")] {
            let makes_elsewhere = [OperationDecl {
                name: "makes",
                doc: "",
                protocol: ProtocolKind::KUBERNETES,
                location: Location::Cluster {
                    access: CREATE_JOBS,
                    namespace: elsewhere,
                },
            }];
            let all = problems(
                "a",
                &makes_elsewhere,
                None,
                &[],
                true,
                &[crate::Capability::JobRun],
            )
            .join(" | ");
            assert!(
                all.contains("may create batch/jobs")
                    && all.contains("none of a's capabilities grants it"),
                "{elsewhere:?}: {all}"
            );
        }
        let all = problems(
            "a",
            &makes,
            None,
            &[],
            true,
            &[crate::Capability::KubeApiRead],
        )
        .join(" | ");
        assert!(all.contains("may create batch/jobs"), "{all}");
        let secrets = [OperationDecl {
            name: "secrets",
            doc: "",
            protocol: ProtocolKind::KUBERNETES,
            location: Location::Cluster {
                access: CREATE_SECRETS,
                namespace: None,
            },
        }];
        let all =
            problems("a", &secrets, None, &[], true, &[crate::Capability::JobRun]).join(" | ");
        assert!(all.contains("may create secrets"), "{all}");

        let says_nothing = [OperationDecl {
            name: "says-nothing",
            doc: "",
            protocol: ProtocolKind::KUBERNETES,
            location: Location::Cluster {
                access: &[],
                namespace: None,
            },
        }];
        let all = problems(
            "a",
            &says_nothing,
            None,
            &[],
            true,
            &[crate::Capability::PodRead],
        )
        .join(" | ");
        assert!(all.contains("declares nothing it may do"), "{all}");

        let nowhere = [decl(
            "elsewhere",
            Location::Cluster {
                access: WATCH_PODS,
                namespace: None,
            },
        )];
        let all = problems(
            "a",
            &nowhere,
            None,
            &[],
            true,
            &[crate::Capability::PodRead],
        )
        .join(" | ");
        assert!(all.contains("goes to the cluster"), "{all}");
        let off = [OperationDecl {
            name: "off",
            doc: "",
            protocol: ProtocolKind::KUBERNETES,
            location: Location::Arbitrary,
        }];
        let all = problems("a", &off, None, &[], true, &[crate::Capability::PodRead]).join(" | ");
        assert!(all.contains("goes to the cluster"), "{all}");
    }

    #[test]
    fn the_scaffold_says_where_an_operation_goes_and_what_it_uses() {
        let entry = OperationEntry::from(&Site::DECL);
        assert_eq!(entry.location, "configured");
        assert_eq!(entry.variable.as_deref(), Some("SITE_URL"));
        assert_eq!(entry.credential.as_deref(), Some("site"));
        let entry = OperationEntry::from(&Learned::DECL);
        assert_eq!(entry.location, "bound");
        assert_eq!(entry.credential.as_deref(), Some("chosen"));
        let entry = OperationEntry::from(&Anywhere::DECL);
        assert_eq!(entry.location, "arbitrary");
        assert_eq!(entry.credential, None);
        let entry = OperationEntry::from(&decl(
            "watches",
            Location::Cluster {
                access: WATCH_PODS_AND_CREATE_JOBS,
                namespace: None,
            },
        ));
        assert_eq!(entry.location, "cluster");
        assert_eq!(entry.access, ["watch pods", "create batch/jobs"]);
        assert_eq!(entry.credential, None);
        assert_eq!(entry.variable, None);
        assert_eq!(entry.namespace, None);
        assert!(
            serde_json::to_value(&entry)
                .unwrap()
                .get("namespace")
                .is_none()
        );
        let entry = OperationEntry::from(&decl(
            "makes",
            Location::Cluster {
                access: CREATE_JOBS,
                namespace: Some("builds"),
            },
        ));
        assert_eq!(entry.namespace.as_deref(), Some("builds"));
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["namespace"], "builds");
        assert_eq!(
            serde_json::from_value::<OperationEntry>(json).unwrap(),
            entry
        );
    }

    /// A cluster operation names its namespace by a key of the cluster's namespaces, which the catalog maps to the
    /// cluster's name for it; anything else is a declaration problem, named.
    #[test]
    fn an_operation_names_its_namespace_by_a_key() {
        let held_in = |key: &'static str| {
            [OperationDecl {
                name: "held",
                doc: "",
                protocol: ProtocolKind::KUBERNETES,
                location: Location::Cluster {
                    access: WATCH_PODS,
                    namespace: Some(key),
                },
            }]
        };
        for key in ["builds", "workspaces-2"] {
            let all = problems("a", &held_in(key), None, &[], true, &[]).join(" | ");
            assert!(!all.contains("not a key"), "{key}: {all}");
        }
        for key in ["", "Builds", "polar_builds", "polar builds"] {
            let all = problems("a", &held_in(key), None, &[], true, &[]).join(" | ");
            assert!(
                all.contains("is not a key of the cluster's namespaces"),
                "{key:?}: {all}"
            );
        }
    }

    /// The handler reads the cluster's names for its operations' namespaces from the environment it starts in, by key: a
    /// call in `polar-builds` is the operation's `builds`, and is allowed there. An operation whose key the deployment does
    /// not name keeps the agent from starting, rather than have every request of it refused; and a variable that does not
    /// read is refused, naming it.
    #[test]
    fn the_handler_reads_the_cluster_s_namespaces_from_its_environment() {
        let variable = crate::environment::CLUSTER_NAMESPACES.name().to_string();
        let held = [OperationDecl {
            name: "held",
            doc: "",
            protocol: ProtocolKind::KUBERNETES,
            location: Location::Cluster {
                access: WATCH_PODS,
                namespace: Some("builds"),
            },
        }];
        let env = |value: &str| HashMap::from([(variable.clone(), value.to_string())]);
        let none = HashMap::<String, String>::new();
        let deployed = env("builds=polar-builds,core=polar");
        let namespaces = cluster_namespaces(&deployed, &held).unwrap();
        assert_eq!(
            namespaces.get("builds").map(String::as_str),
            Some("polar-builds")
        );
        let in_polar_builds = Target {
            host: "10.96.0.1".to_string(),
            encrypted: true,
            access: Some(WATCH_PODS[0]),
            reaches_node: Vec::new(),
            namespace: Some("polar-builds".to_string()),
        };
        assert_eq!(
            judge(
                &held[0],
                &held,
                &in_polar_builds,
                namespaces.get("builds").map(String::as_str),
                None
            ),
            Verdict::Allow { credential: None }
        );

        let unmapped = cluster_namespaces(&none, &held).unwrap_err();
        assert!(
            unmapped.contains("`builds` (operation `held`)"),
            "{unmapped}"
        );
        assert!(cluster_namespaces(&env("core=polar"), &held).is_err());
        let refused = cluster_namespaces(&env("builds"), &held).unwrap_err();
        assert!(refused.contains(&variable), "{refused}");
        // An agent whose operations name no namespace needs the variable no more than before.
        assert!(cluster_namespaces(&none, &[]).unwrap().is_empty());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// Whatever a stream says, the domain gets each change in order up to the first that cannot be read, that one's
        /// failure, and nothing after it.
        #[test]
        fn a_stream_is_said_in_order_up_to_the_first_it_cannot_read(
            bodies in proptest::collection::vec(prop_oneof![4 => "[a-z]{1,6}", 1 => Just("garbled".to_string())], 0..12),
            fails in any::<bool>(),
        ) {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let readable = bodies.iter().take_while(|body| *body != "garbled").count();
            let unreadable = readable < bodies.len();
            let expected = readable + usize::from(unreadable || fails);
            let got = runtime.block_on(async {
                let r = rig().await;
                let answer = if fails { Answer::StreamThenFails(bodies.clone()) } else { Answer::Stream(bodies.clone()) };
                r.ask(r.site(answer));
                let got = r.answers(expected).await;
                tokio::time::sleep(Duration::from_millis(5)).await;
                assert!(r.got.lock().unwrap().is_empty(), "nothing followed");
                got
            });
            for (at, value) in got.iter().enumerate() {
                if at < readable {
                    prop_assert_eq!(value.as_ref().ok(), Some(&bodies[at]));
                } else {
                    prop_assert!(value.is_err());
                }
            }
        }

        /// For any secret and any sequence of requests, nothing the domain is sent, nothing recorded, and nothing the agent
        /// holds as a problem has the secret in it, and yet it did go out when it should have.
        #[test]
        fn no_sequence_of_requests_shows_the_domain_the_secret(
            secret in "[A-Za-z0-9]{24,40}",
            requests in proptest::collection::vec(0..6u8, 1..12),
        ) {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let (seen, presented) = runtime.block_on(async {
                let r = rig_with(&secret).await;
                for request in &requests {
                    let body = |text: &str| Answer::Body(text.to_string());
                    match request {
                        0 => r.ask(r.site(body("data"))),
                        1 => r.ask(r.site(Answer::Stream(vec!["a".to_string(), "b".to_string()]))),
                        2 => r.ask(r.site(Answer::Refuses)),
                        3 => r.ask(r.site(body("garbled"))),
                        4 => r.ask(Learned { request: at(&fresh_host(), body("no")), chosen: Some("site".to_string()) }),
                        _ => r.ask(Anywhere { request: at(&fresh_host(), body("public")), chosen: Some("site".to_string()) }),
                    }
                    // Each settles before the next, so that a refusal is in force for what follows it.
                    let expect = if *request == 1 && !r.is_refused() { 2 } else { 1 };
                    let answers = r.answers(expect).await;
                    r.keep(answers);
                }
                let mut seen = r.kept.lock().unwrap().iter().map(|a| format!("{a:?}")).collect::<Vec<_>>();
                seen.extend(r.records.lock().unwrap().iter().map(|a| format!("{a:?}")));
                seen.extend(r.health.held.lock().unwrap().iter().cloned());
                (seen, r.presented())
            });
            for line in &seen {
                prop_assert!(!line.contains(&secret), "{line}");
            }
            for credential in presented.into_iter().flatten() {
                prop_assert_eq!(credential, secret.as_bytes().to_vec());
            }
        }
    }

    /// The accesses a cluster declaration draws from, for the property below: each capability's, and some none grants.
    const ACCESSES: [Access; 7] = [
        Access::new(Verb::Watch, "", "pods"),
        Access::new(Verb::Watch, "apps", "deployments"),
        Access::new(Verb::Get, "", "secrets"),
        Access::new(Verb::Create, "batch", "jobs"),
        Access::new(Verb::Get, "", "pods/log"),
        Access::new(Verb::Create, "", "secrets"),
        Access::new(Verb::Delete, "", "pods"),
    ];

    /// The namespaces a cluster declaration may name, for the property below: none, job-run's, and one no capability is
    /// held to.
    const NAMESPACES: [Option<&str>; 3] = [None, Some("builds"), Some("core")];

    fn declared_with(access: Access, namespace: Option<&'static str>) -> &'static [OperationDecl] {
        static ALL: std::sync::OnceLock<Vec<[OperationDecl; 1]>> = std::sync::OnceLock::new();
        let all = ALL.get_or_init(|| {
            NAMESPACES
                .iter()
                .flat_map(|namespace| {
                    ACCESSES.iter().map(move |a| {
                        let access: &'static [Access] = Box::leak(Box::new([*a]));
                        [OperationDecl {
                            name: "cluster",
                            doc: "",
                            protocol: ProtocolKind::KUBERNETES,
                            location: Location::Cluster {
                                access,
                                namespace: *namespace,
                            },
                        }]
                    })
                })
                .collect()
        });
        let n = NAMESPACES.iter().position(|ns| *ns == namespace).unwrap();
        let a = ACCESSES.iter().position(|a| *a == access).unwrap();
        &all[n * ACCESSES.len() + a]
    }

    proptest! {
        /// A cluster operation's access is a problem exactly when not one of the capabilities the agent needs grants it
        /// where the operation is held: none, or more than one. kube-api-read grants any read but of Secrets and pod-read
        /// its Role's rules, both to an operation held to no namespace; job-run its Role's rules, to one held to the
        /// build namespace; nothing else grants anything.
        #[test]
        fn what_a_cluster_operation_may_do_is_what_its_capabilities_grant(
            access in proptest::sample::select(ACCESSES.to_vec()),
            namespace in proptest::sample::select(NAMESPACES.to_vec()),
            needs in proptest::sample::subsequence(crate::Capability::ALL.to_vec(), 0..=crate::Capability::ALL.len()),
        ) {
            let found = problems("a", declared_with(access, namespace), None, &[], true, &needs);
            let none = found.iter().any(|p| p.contains("none of a's capabilities grants it"));
            let many = found.iter().any(|p| p.contains("more than one of a's capabilities grants it"));
            // Said apart from the code: what each grants, and where.
            let holders = needs.iter().filter(|c| match c {
                crate::Capability::KubeApiRead => {
                    namespace.is_none() && !access.verb.writes() && access.resource != "secrets"
                }
                crate::Capability::PodRead => {
                    namespace.is_none() && crate::capability::POD_READ_GRANTS.contains(&access)
                }
                crate::Capability::JobRun => {
                    namespace == Some("builds") && crate::capability::JOB_RUN_GRANTS.contains(&access)
                }
                _ => false,
            }).count();
            prop_assert_eq!(none, holders == 0, "{:?} {:?} {:?}", needs, namespace, found);
            prop_assert_eq!(many, holders > 1, "{:?} {:?} {:?}", needs, namespace, found);
        }
    }
}
