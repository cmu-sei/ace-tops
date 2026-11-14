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

//! InfrastructureSupervisor -- owns HealthCheckActor, RouterActor,
//! TcpClientActor, and (if requested) CryptoActor as real, direct,
//! linked children, in one, real, cohesive subtree. A service that is not a Cassini client (the
//! broker itself) has only the health actor: no router, client or crypto, and nothing to
//! subscribe to. Everything about how it ends is the same. Spawned by
//! AgentBuilder::build() itself as a real, linked child of the
//! domain supervisor; the domain supervisor never spawns any of
//! these four actors directly at all.
//!
//! Exists to solve one, real, genuine problem CryptoActor's own
//! design creates: CryptoActorArgs bakes in a real
//! ActorRef<TcpClientMessage> at spawn time. If TcpClientActor
//! genuinely, unexpectedly terminates and a fresh one spawns, that
//! baked-in reference is now stale. This actor is the one, real
//! place that detects that and respawns both together, atomically,
//! sharing the same, still-live RouterActor.
//!
//! It also owns how the agent ends. Every reason to end goes through one
//! funnel, `begin_shutdown`: a verdict from the health actor, a SIGTERM or SIGINT,
//! or any child ending unexpectedly. The Cassini client is the front
//! (`cassini_client::facade`), which replaces its own transports and does not end
//! for the broker's absence, so its ending is a fault in the front itself. The funnel is idempotent and logs the reason.
//! The domain supervisor's own work (its children, a listener, topics to let go
//! of) may still need the router and the client while it finishes, so the funnel
//! tells it, in its own message, and, for a domain that drains, waits for its
//! InfrastructureSupervisorMessage::ProceedWithShutdown ([`ShutdownNotice`]). Then
//! the graph controller drains and the rest of the infrastructure stops. A watchdog
//! bounds it: if the process is still alive when the shutdown budget runs out, it
//! exits 1 regardless. See shutdown.rs for the decisions themselves.

use crate::configuration::ConfigurationHandle;
use crate::crypto::CryptoHandle;
use crate::health::HealthHandle;
use crate::shutdown::{self, Action, Child, Death, ProcessExit, ShutdownMachine};
use crate::{AgentResources, Subscription, build_lifecycle_handler};
use cassini_client::CassiniSettings;
use cassini_types::ClientEvent;
use polar::cassini::TcpClient;
use polar_health::{HealthCheckActor, HealthCheckArgs, HealthVerdict};
use ractor::{
    Actor, ActorCell, ActorProcessingErr, ActorRef, OutputPort, RpcReplyPort, SupervisionEvent,
    async_trait,
};
use std::sync::Arc;
use std::time::Duration;

/// How long the supervisor waits for its children to stop once told to proceed.
const STOP_CHILDREN_TIMEOUT: Duration = Duration::from_secs(10);

/// How the infrastructure tells the domain supervisor that the agent is to end, for whatever reason (the health
/// actor's verdict, SIGTERM, a child of the infrastructure dying), and whether it then waits for the domain's
/// `ProceedWithShutdown`. The domain registers it with the builder before `build()`: `AgentBuilder::with_drain` (told,
/// and waited for, as long as the shutdown budget allows) or `AgentBuilder::on_shutdown` (told only). A domain that
/// registers neither is not told, and the infrastructure goes on.
#[derive(Clone)]
pub(crate) struct ShutdownNotice {
    /// Sends the domain its own message saying the agent is to end. Once, at most.
    pub(crate) tell: Arc<dyn Fn() + Send + Sync>,
    /// Whether the infrastructure waits for the domain's `ProceedWithShutdown`.
    pub(crate) wait: bool,
}

pub enum InfrastructureSupervisorMessage {
    /// Internal: the real, raw ClientEvent forwarded from
    /// TcpClientActor's own lifecycle callback -- immediately,
    /// directly re-sent via this actor's own, real
    /// Arc<OutputPort<ClientEvent>>, so a domain supervisor's own,
    /// real lifecycle-handling closure still, genuinely works exactly
    /// as it always has, subscribed to that same, real port directly.
    ClientEvent(ClientEvent),
    /// Sent once the domain supervisor's own, direct children
    /// (everything outside this infra subtree) have genuinely, fully
    /// terminated -- tells infra it's now safe to stop its own
    /// remaining children and terminate itself.
    ProceedWithShutdown,
    /// The one, real way AgentBuilder::build() itself retrieves the
    /// initial, real AgentResources this actor's own pre_start
    /// already, genuinely spawned internally. `None` when this supervisor has no Cassini
    /// client, which is what `ServiceBuilder` builds.
    GetResources {
        reply: RpcReplyPort<Option<AgentResources>>,
    },
    /// The `Registered` the client is on, if it is registered now: for a subscriber to the client's events, which may
    /// have come too late to hear it.
    LastRegistered {
        reply: RpcReplyPort<Option<ClientEvent>>,
    },
    /// What a service without a Cassini client is given: the health handle, the shutdown
    /// events and the snapshot.
    GetService {
        reply: RpcReplyPort<crate::ServiceResources>,
    },
    /// Internal: the health actor's verdict, delivered through the port this
    /// supervisor gave it.
    Health(HealthVerdict),
    /// Ask for an orderly shutdown, for this reason. Sent by the signal listener;
    /// it can be sent by anything holding AgentResources::infrastructure. If a
    /// shutdown is already under way this changes nothing.
    BeginShutdown { reason: String },
    /// Internal: time for the self-test to look.
    SelfTestTick,
    /// Internal: the command actor says what it did with a command, published on Cassini if there is a
    /// client.
    CommandOutcome(polar_scheduler_common::CommandOutcome),
    /// Internal: the ConfigurationActor says what it did with a document. Published on Cassini, if there
    /// is a client; a service without one has nowhere to say it.
    Outcome(polar_scheduler_common::ConfigurationOutcome),
    /// A log filter changed, and the logging follows.
    LoggingChanged(polar::logging::LoggingSettings),
    /// The agent wants the current authority from the credentials agent: publish the request on the client as
    /// it is now.
    AuthorityAsk,
    /// What the Cassini client says about the topics the agent was refused.
    Refusals(cassini_client::facade::RefusalNews),
    /// Internal: a question on the agent's own health topic, with the identity the broker stamped on it
    /// (`health_query.rs`). Judged and answered off this actor's thread.
    HealthQuery {
        payload: Vec<u8>,
        published_by: Option<String>,
    },
    /// Internal: a question about the configuration in force, with the identity the broker stamped on it
    /// (`running.rs`). Judged and answered off this actor's thread.
    RunningConfigurationQuestion {
        payload: Vec<u8>,
        published_by: Option<String>,
    },
}

/// The lifecycle callback the Cassini client is given.
pub(crate) type LifecycleHandler =
    Box<dyn Fn(ClientEvent) -> Option<InfrastructureSupervisorMessage> + Send + Sync>;

/// How the supervisor makes its Cassini client. A seam: the real one connects to
/// a broker, a test's does not.
#[async_trait]
pub(crate) trait TcpClientSpawner: Send + Sync {
    async fn spawn(
        &self,
        service_name: &str,
        supervisor: ActorRef<InfrastructureSupervisorMessage>,
        lifecycle: LifecycleHandler,
        router: ActorRef<polar_router::RouterMessage>,
        settings: CassiniSettings,
        tls: crate::crypto::TlsHandle,
    ) -> Result<TcpClient, ActorProcessingErr>;
}

/// Spawns the real client, handing it the agent's topic check (`topic_gate`) when it has one.
#[derive(Default)]
pub(crate) struct CassiniSpawner {
    pub(crate) gate: Option<cassini_client::facade::TopicGate>,
}

#[async_trait]
impl TcpClientSpawner for CassiniSpawner {
    async fn spawn(
        &self,
        service_name: &str,
        supervisor: ActorRef<InfrastructureSupervisorMessage>,
        lifecycle: LifecycleHandler,
        router: ActorRef<polar_router::RouterMessage>,
        settings: CassiniSettings,
        tls: crate::crypto::TlsHandle,
    ) -> Result<TcpClient, ActorProcessingErr> {
        // The connection's TLS is the crypto actor's, from the agent's own key (docs/plans/crypto-actor.md, step K3):
        // the client is given it whole, and reads no key of its own.
        let config = polar_crypto::cassini::client_config(&tls.actor(), &settings)
            .await
            .map_err(ActorProcessingErr::from)?;
        // What the agent was refused comes back here: to ask for the authority, and for its health file.
        let told = supervisor.clone();
        let watch: cassini_client::facade::RefusalWatch = Arc::new(move |news| {
            if let Err(e) = told.send_message(InfrastructureSupervisorMessage::Refusals(news)) {
                tracing::warn!("InfrastructureSupervisor: not told of a refusal: {e}");
            }
        });
        TcpClient::spawn_with_router_config(
            service_name,
            supervisor,
            lifecycle,
            router,
            config,
            self.gate.clone(),
            Some(watch),
        )
        .await
    }
}

/// The checkpoint key's handle, for an agent its deployment gives one (`POLAR_STORE_CHECKPOINT_KEY`, which the
/// `checkpoints` capability requires); none otherwise.
fn checkpoint_handle(
    config: &polar_env::Config,
    crypto: &CryptoHandle,
) -> Option<crate::crypto::CheckpointHandle> {
    matches!(
        config.read(&polar_crypto::environment::STORE_CHECKPOINT_KEY),
        Ok(Some(_))
    )
    .then(|| crate::crypto::CheckpointHandle::new(crypto.actor()))
}

/// The record key's handle, for an agent its deployment gives one (`POLAR_RECORD_KEY`, which the `record-key`
/// capability requires); none otherwise.
fn record_key_handle(
    config: &polar_env::Config,
    crypto: &CryptoHandle,
) -> Option<crate::crypto::RecordKeyHandle> {
    matches!(
        config.read(&polar_crypto::environment::RECORD_KEY),
        Ok(Some(_))
    )
    .then(|| crate::crypto::RecordKeyHandle::new(crypto.actor()))
}

/// The witness key's handle, for an agent its deployment gives one (`POLAR_WITNESS_COSIGNING_KEY`); none otherwise.
fn cosign_handle(
    config: &polar_env::Config,
    crypto: &CryptoHandle,
) -> Option<crate::crypto::CosignHandle> {
    matches!(
        config.read(&polar_crypto::environment::WITNESS_COSIGNING_KEY),
        Ok(Some(_))
    )
    .then(|| crate::crypto::CosignHandle::new(crypto.actor()))
}

pub struct InfrastructureSupervisorArgs {
    pub service_name: String,
    /// The agent's crypto actor, when it was started before the infrastructure (`ConfiguredAgent::tls`): linked, not
    /// spawned again.
    pub(crate) crypto: Option<CryptoParts>,
    pub health_check_args: HealthCheckArgs,
    /// The one snapshot of the environment the builder took. Held for the life of the
    /// agent, and handed out through `AgentResources::config`.
    pub config: Arc<polar_env::Config>,
    pub subscriptions: Vec<Subscription>,
    pub wants_crypto: bool,
    /// For an agent with the `signing` capability: the builder starts a signer for it (`signer.rs`).
    pub wants_signer: bool,
    /// For an agent with the `soft-state` capability, the state agent's identity, which its replies must come from:
    /// the builder starts a state actor for it (`state.rs`).
    pub(crate) state_agent: Option<String>,
    /// For a Cassini client, the identity the floor lets ask about its health: the state agent's writer of its own
    /// namespace and domain (`health_query.rs`). None admits nobody but whom a policy permits.
    pub(crate) health_writer: Option<String>,
    /// Whether this is a Cassini client: a router, a client and its subscriptions. A service
    /// that is the broker, or otherwise not a client, has none of them.
    pub(crate) with_client: bool,
    /// How long the domain supervisor has to drain before the process exits anyway.
    pub(crate) shutdown_budget: Duration,
    /// Listen for SIGTERM and SIGINT. Off in tests, because signals belong to the
    /// whole process.
    pub(crate) listen_for_signals: bool,
    pub(crate) process_exit: ProcessExit,
    pub(crate) tcp_spawner: Arc<dyn TcpClientSpawner>,
    /// The commands the agent declared, each with its handler: what the command actor will run.
    pub(crate) commands: Vec<(
        crate::command::CommandSpec,
        Arc<dyn crate::command_actor::CommandHandler>,
    )>,
    /// The runtime sections the agent declared: what its configuration actor will accept.
    pub(crate) runtime_sections: &'static [&'static crate::runtime::RuntimeSection],
    /// The operations and credentials the agent declared: what its protocol handler serves.
    pub(crate) protocols: crate::protocol::ProtocolSetup,
    /// The workers `run` forked before the runtime: each becomes an actor under this supervisor.
    pub(crate) workers: Vec<crate::worker::Forked>,
    /// The agent's judge of a runtime section before it is replaced, if it has one.
    pub(crate) section_judge: Option<Arc<dyn crate::runtime::SectionJudge>>,
    /// The agent's judge of its settings as a whole, if it has one.
    pub(crate) settings_judge: Option<crate::configuration::SettingsJudge>,
    /// Publish probes to the agent itself and expect them back; see `selftest`.
    pub(crate) self_test: bool,
    /// For an agent that needs the graph, what its graph controller is started with (`graph.rs`).
    pub(crate) graph: Option<crate::graph::GraphSetup>,
    /// How the domain is told the agent is to end, and whether it is waited for; none, not told.
    pub(crate) notice: Option<ShutdownNotice>,
}

/// How often the self-test looks at the clock; a probe is sent every `SELF_TEST_INTERVAL`, and
/// the agent is judged deaf when one has gone `SELF_TEST_TIMEOUT` unanswered.
const SELF_TEST_TICK: Duration = Duration::from_secs(5);
const SELF_TEST_INTERVAL: Duration = Duration::from_secs(30);
const SELF_TEST_TIMEOUT: Duration = Duration::from_secs(20);

/// The topic an agent's probes travel on. Shared by every instance of the service: each tells its
/// own probes from the others by the instance id they carry.
pub(crate) fn self_test_topic(service_name: &str) -> String {
    // The broker names a subscription `{session}:{topic}` and splits it at the first colon, and
    // some services are named with colons.
    format!("selftest.{}", service_name.replace(':', "-"))
}

/// A probe is the instance id followed by its number.
fn probe_payload(instance: &[u8; 16], number: u64) -> Vec<u8> {
    let mut payload = instance.to_vec();
    payload.extend_from_slice(&number.to_be_bytes());
    payload
}

/// The number in a probe sent by `instance`, if that is what this is.
fn probe_number(instance: &[u8; 16], payload: &[u8]) -> Option<u64> {
    let (id, number) = payload.split_at_checked(16)?;
    (id == instance).then_some(())?;
    Some(u64::from_be_bytes(number.try_into().ok()?))
}

struct SelfTestState {
    machine: crate::selftest::SelfTest,
    instance: [u8; 16],
    topic: String,
    /// The highest probe number the router has delivered back.
    heard: Arc<std::sync::atomic::AtomicU64>,
    began: tokio::time::Instant,
    /// Whether the Cassini client is registered, as far as its events say.
    connected: bool,
}

/// The longest a clean shutdown waits for the client to have said goodbye to the broker before it stops it anyway.
const GOODBYE_WAIT: Duration = Duration::from_secs(2);

/// Whether the certificate at `path` names an instance (`cert_issuer_common::instance`): the agent is one pod of a
/// multi-instance workload (docs/architecture/authority-model.md, "Multi-instance workloads"). A certificate that cannot
/// be read names none: the agent is taken for a single instance, whose session is kept for its successor.
pub(crate) fn names_an_instance(path: &str) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|pem| {
            cert_issuer_common::instance::extract_instance(&pem)
                .ok()
                .flatten()
        })
        .is_some()
}

/// What the supervisor needs to make a Cassini client.
struct ClientSetup {
    subscriptions: Vec<Subscription>,
    /// The agent's crypto actor, started before the client, which it is given once it exists.
    crypto: CryptoParts,
    wants_signer: bool,
    state_agent: Option<String>,
    self_test: bool,
    tcp_spawner: Arc<dyn TcpClientSpawner>,
    config: Arc<polar_env::Config>,
    configuration: ConfigurationHandle,
    commands: crate::command_actor::CommandHandle,
    authority: crate::authority::AuthorityHandle,
}

/// The agent's crypto actor: every agent has one, started before anything that uses a key (docs/plans/crypto-actor.md).
#[derive(Clone)]
pub(crate) struct CryptoParts {
    pub(crate) handle: CryptoHandle,
    /// What the protocol handler asks the crypto actor with, for an agent that escrows secrets.
    credential_port: Option<polar_crypto::CredentialPort>,
    /// Whether the agent escrows secrets (`encryption`).
    escrow: bool,
}

/// What a Cassini client brings with it.
struct ClientParts {
    events_output: Arc<OutputPort<ClientEvent>>,
    router: ActorRef<polar_router::RouterMessage>,
    tcp_client: TcpClient,
    /// Whether its certificate names an instance (one pod of a multi-instance workload's): a clean shutdown then ends
    /// its session at once (docs/architecture/authority-model.md, "Multi-instance workloads").
    one_of_many: bool,
    crypto: Option<CryptoHandle>,
    /// Whether the domain is given the crypto actor's handle: an agent that escrows secrets (`encryption`). One that only
    /// signs records reaches it through its signer handle alone.
    escrow: bool,
    /// What the protocol handler asks the crypto actor with: nothing else ever has it.
    credential_port: Option<polar_crypto::CredentialPort>,
    signer: Option<crate::signer::SignerHandle>,
    /// The agent's protocol handler, if it declares operations or credentials.
    protocols: Option<crate::protocol::ProtocolHandle>,
    state: Option<crate::state::StateHandle>,
}

/// Tells `subscriber` of the registration it may have missed, through `map` as its subscription does. Call it after
/// subscribing. Cassini may register while this supervisor is still starting, and that event is sent on as soon as it has,
/// before anything could have been given the port to subscribe to. It may repeat one the subscriber did hear, as a reconnect
/// does.
pub(crate) async fn catch_up<M: ractor::Message>(
    infrastructure: &ActorRef<InfrastructureSupervisorMessage>,
    subscriber: &ActorRef<M>,
    map: &(dyn Fn(ClientEvent) -> Option<M> + Send + Sync),
) -> Result<(), ActorProcessingErr> {
    let registered = ractor::call!(infrastructure, |reply| {
        InfrastructureSupervisorMessage::LastRegistered { reply }
    })
    .map_err(|e| ActorProcessingErr::from(e.to_string()))?;
    if let Some(message) = registered.and_then(map) {
        subscriber
            .send_message(message)
            .map_err(|_| ActorProcessingErr::from("the agent's supervisor has ended"))?;
    }
    Ok(())
}

pub struct InfrastructureSupervisorState {
    /// The agent's workers, each an actor of this supervisor's: one that fails ends the agent.
    workers: crate::worker::Workers,
    config: Arc<polar_env::Config>,
    configuration: ConfigurationHandle,
    commands: crate::command_actor::CommandHandle,
    authority: Option<crate::authority::AuthorityHandle>,
    client: Option<ClientParts>,
    /// The agent's crypto actor, whether or not it is a Cassini client.
    crypto: CryptoHandle,
    healthcheck: HealthHandle,
    service_name: String,
    shutdown: ShutdownMachine,
    shutdown_budget: Duration,
    process_exit: ProcessExit,
    self_test: Option<SelfTestState>,
    /// What answers a health question, for a Cassini client.
    health_answerer: Option<crate::health_query::Answerer>,
    running_answerer: Option<crate::running::Answerer>,
    /// The `Registered` the client is on, until it loses the connection.
    last_registered: Option<ClientEvent>,
    /// The agent's graph controller, until it is drained at the end.
    graph: Option<crate::graph::GraphHandle>,
    /// See `InfrastructureSupervisorArgs::notice`.
    notice: Option<ShutdownNotice>,
    /// This supervisor, to proceed by itself when the domain is not waited for.
    myself: ActorRef<InfrastructureSupervisorMessage>,
}

pub struct InfrastructureSupervisor;

impl InfrastructureSupervisor {
    /// The one entry point to ending the agent. Idempotent: the first reason
    /// starts the shutdown, and any later one is logged and changes nothing.
    fn begin_shutdown(state: &mut InfrastructureSupervisorState, reason: String) {
        if !state.shutdown.begin(&reason) {
            tracing::info!(
                "InfrastructureSupervisor: already shutting down ({}); ignoring a further \
                 reason: {reason}",
                state.shutdown.reason().unwrap_or("no reason recorded")
            );
            return;
        }

        tracing::warn!("InfrastructureSupervisor: beginning an orderly shutdown: {reason}");
        // Asked about its health from now on, the agent says it is draining.
        state.healthcheck.draining();
        Self::start_watchdog(state.shutdown_budget, state.process_exit.clone(), &reason);
        // Nothing new is started while the agent is going down.
        state.commands.drain();
        // The domain is told, if it asked to be; unless it drains, the infrastructure goes on.
        let wait = match &state.notice {
            Some(notice) => {
                (notice.tell)();
                notice.wait
            }
            None => false,
        };
        if !wait
            && let Err(e) = state
                .myself
                .cast(InfrastructureSupervisorMessage::ProceedWithShutdown)
        {
            tracing::error!(
                "InfrastructureSupervisor: could not proceed by itself ({e}); the watchdog ends it"
            );
        }
    }

    /// Asks the scheduler for the signed configuration it holds for this agent. Sent on every
    /// registration: an agent that restarts has forgotten what it was given, and one that reconnects
    /// may have missed what was sent while it was away. What comes back is the stored documents on the
    /// agent's own configuration topic, where they are verified like any other, and one it has already
    /// applied is refused as no newer.
    fn ask_for_configuration(service_name: &str, client: &ClientParts) {
        let request = polar_scheduler_common::ConfigurationReplayRequest {
            agent: service_name.to_string(),
        };
        match rkyv::to_bytes::<rkyv::rancor::Error>(&request) {
            Ok(bytes) => {
                if let Err(e) = client.tcp_client.as_actor_ref().send_message(
                    cassini_client::TcpClientMessage::publish(
                        polar_scheduler_common::CONFIGURATION_REPLAY_TOPIC.to_string(),
                        bytes.to_vec(),
                        None,
                    ),
                ) {
                    tracing::warn!(
                        "InfrastructureSupervisor: cannot ask for the stored configuration: {e}"
                    );
                }
            }
            Err(e) => tracing::error!(
                "InfrastructureSupervisor: cannot encode a configuration request: {e}"
            ),
        }
    }

    /// Looks at what has come back, then at the clock, and does what the self-test says.
    fn self_test_tick(state: &mut InfrastructureSupervisorState) {
        use crate::health::HealthClient;
        use crate::selftest::Action;

        let (Some(test), Some(client)) = (&mut state.self_test, &state.client) else {
            return;
        };
        let heard = test.heard.load(std::sync::atomic::Ordering::SeqCst);
        if heard > 0
            && let Some(Action::Hearing) = test.machine.heard(heard)
        {
            tracing::info!(
                "InfrastructureSupervisor: self-test: a probe came back, the agent hears the \
                 broker again"
            );
            let _ = state.healthcheck.cassini_connected();
        }
        for action in test.machine.tick(test.began.elapsed(), test.connected) {
            match action {
                Action::Probe(number) => {
                    tracing::debug!(number, "InfrastructureSupervisor: self-test: probing");
                    let _ = client.tcp_client.as_actor_ref().send_message(
                        cassini_client::TcpClientMessage::publish(
                            test.topic.clone(),
                            probe_payload(&test.instance, number),
                            None,
                        ),
                    );
                }
                Action::Deaf { unanswered_for } => {
                    tracing::error!(
                        unanswered_secs = unanswered_for.as_secs(),
                        topic = %test.topic,
                        "InfrastructureSupervisor: self-test: no probe has come back, the agent \
                         is registered but cannot hear the broker; reporting the Cassini \
                         connection as lost"
                    );
                    let _ = state.healthcheck.cassini_disconnected();
                }
                Action::Hearing => {}
            }
        }
    }

    /// The last resort: if the process is still alive when the budget runs out, the
    /// domain supervisor never finished, so exit 1 and let the pod's rule restart it.
    ///
    /// A detached task, not a message to this actor, so it does not depend on the
    /// actor still being alive. Without it, a domain supervisor that never answers
    /// leaves only the Kubernetes liveness probe to end the pod.
    fn start_watchdog(budget: Duration, process_exit: ProcessExit, reason: &str) {
        let reason = reason.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(budget).await;
            tracing::error!(
                "InfrastructureSupervisor: the process is still running {}s after the shutdown \
                 began ({reason}); the domain supervisor never finished, exiting 1",
                budget.as_secs()
            );
            process_exit(1);
        });
    }

    /// The agent's crypto actor, before anything that uses a key: one that escrows secrets (`escrow`) reads its identity
    /// and pinned CA and hears the credentials agent; any other needs neither.
    pub(crate) async fn spawn_crypto(
        config: &polar_env::Config,
        escrow: bool,
        supervisor: Option<ractor::ActorCell>,
    ) -> Result<CryptoParts, ActorProcessingErr> {
        let pass = escrow.then(polar_crypto::CredentialPass::new);
        let mut args = polar_crypto::CryptoActorArgs::unconnected()
            .with_settings(
                polar_crypto::environment::CryptoSettings::from_env_for(config, escrow)
                    .map_err(ActorProcessingErr::from)?,
            )
            .with_escrow(escrow);
        if let Some(pass) = &pass {
            args = args.with_credential_pass(pass.clone());
        }
        // Started before the infrastructure (ConfiguredAgent::tls), it has no supervisor yet: the infrastructure links
        // it when it starts.
        let (actor, _) = match supervisor {
            Some(supervisor) => {
                polar_crypto::CryptoActor::spawn_linked(
                    None,
                    polar_crypto::CryptoActor,
                    args,
                    supervisor,
                )
                .await
            }
            None => polar_crypto::CryptoActor::spawn(None, polar_crypto::CryptoActor, args).await,
        }
        .map_err(ActorProcessingErr::from)?;
        Ok(CryptoParts {
            handle: CryptoHandle::new(actor.clone()),
            credential_port: pass.map(|pass| polar_crypto::CredentialPort::new(actor, pass)),
            escrow,
        })
    }

    /// The router, the subscriptions and the Cassini client: what makes this agent a client. Moved out of `pre_start`
    /// so a service without one skips it all.
    async fn spawn_client_parts(
        myself: &ActorRef<InfrastructureSupervisorMessage>,
        service_name: &str,
        setup: ClientSetup,
    ) -> Result<(ClientParts, Option<SelfTestState>), ActorProcessingErr> {
        let myself_cell = myself.get_cell();
        let (router, _) = polar_router::RouterActor::spawn_linked(
            None,
            polar_router::RouterActor,
            (),
            myself_cell.clone(),
        )
        .await
        .map_err(ActorProcessingErr::from)?;

        let mut subscriptions = setup.subscriptions;
        // Every agent hears its own signed configuration and its own signed commands, and the actors
        // verify them.
        subscriptions.push(crate::configuration::subscription(
            service_name,
            setup.configuration.clone(),
        ));
        subscriptions.push(crate::command_actor::subscription(
            service_name,
            setup.commands.clone(),
        ));
        // And the credentials agent's policy and permissions: a live update, and a snapshot (asked for or
        // republished). Whether either is believed, and from whom, is the authority actor's to decide.
        subscriptions.extend(crate::authority::subscriptions(&setup.authority));
        // And questions about its health, answered by the builder from the health actor's report: the domain is never
        // asked (docs/architecture/soft-state.md, "Self-state and introspection").
        subscriptions.push(crate::health_query::subscription(
            service_name,
            myself.clone(),
        ));
        // And questions about its configuration in force, also the builder's to answer.
        subscriptions.push(crate::running::subscription(myself.clone()));
        // An agent that reads its own soft state hears the state agent on its own reply topic.
        let state_replies = setup.state_agent.map(|expected| {
            let router = Arc::new(soft_state_common::ReplyRouter::new());
            subscriptions.push(crate::state::replies_subscription(
                service_name,
                expected,
                router.clone(),
            ));
            router
        });
        let self_test = if setup.self_test {
            let instance: [u8; 16] = rand::random();
            let topic = self_test_topic(service_name);
            let heard = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let heard_by_router = heard.clone();
            subscriptions.push(Subscription::new(topic.clone(), move |incoming| {
                if let Some(number) = probe_number(&instance, &incoming.payload) {
                    heard_by_router.fetch_max(number, std::sync::atomic::Ordering::SeqCst);
                }
            }));
            drop(myself.send_interval(SELF_TEST_TICK, || {
                InfrastructureSupervisorMessage::SelfTestTick
            }));
            Some(SelfTestState {
                machine: crate::selftest::SelfTest::new(SELF_TEST_INTERVAL, SELF_TEST_TIMEOUT),
                instance,
                topic,
                heard,
                began: tokio::time::Instant::now(),
                connected: false,
            })
        } else {
            None
        };

        let subscribed_topics: Vec<String> =
            subscriptions.iter().map(|s| s.topic.clone()).collect();

        tracing::info!(
            "InfrastructureSupervisor: expecting {} subscription(s): {}",
            subscribed_topics.len(),
            subscribed_topics.join(", ")
        );

        for subscription in subscriptions {
            router
                .send_message(polar_router::RouterMessage::Register {
                    topic: subscription.topic,
                    deliver: subscription.deliver,
                })
                .map_err(ActorProcessingErr::from)?;
        }

        let events_output = Arc::new(OutputPort::default());

        // Every real ClientEvent this agent's own TcpClient ever
        // produces is immediately, directly re-sent out via
        // events_output above -- this actor never, itself, tries to
        // interpret them (Registered vs TransportError, etc); a real
        // domain supervisor's own, real lifecycle-handling closure,
        // subscribed to that port, does that.
        let lifecycle_handler: LifecycleHandler = Box::new(build_lifecycle_handler(
            service_name.to_string(),
            subscribed_topics.clone(),
            Box::new(|event: ClientEvent| {
                Some(InfrastructureSupervisorMessage::ClientEvent(event))
            }),
        ));

        let client_settings =
            CassiniSettings::from_env(&*setup.config).map_err(ActorProcessingErr::from)?;
        let one_of_many = names_an_instance(&client_settings.client_certificate_path);
        let tcp_client = setup
            .tcp_spawner
            .spawn(
                service_name,
                myself.clone(),
                lifecycle_handler,
                router.clone(),
                client_settings,
                crate::crypto::TlsHandle::new(setup.crypto.handle.actor()),
            )
            .await?;
        // A change of authority may admit what the agent was refused: the client asks its gate again.
        setup
            .authority
            .changes()
            .subscribe(tcp_client.as_actor_ref(), |_| {
                Some(cassini_client::TcpClientMessage::JudgeAgain)
            });

        // The crypto actor was started before the client: it is given the client and the router now.
        setup
            .crypto
            .handle
            .actor()
            .cast(polar_crypto::CryptoMessage::Connect {
                tcp_client: tcp_client.as_actor_ref(),
                router: router.clone(),
            })
            .map_err(ActorProcessingErr::from)?;
        let crypto = Some(setup.crypto.handle.clone());
        let credential_port = setup.crypto.credential_port.clone();

        // Records are signed by the crypto actor; the domain's handle reaches nothing else of it
        // (docs/architecture/key-custody.md, "Workload signing keys", item 4).
        // The key is the custody daemon's, or, where custody holds none for the agent, its own record key's.
        let signer = if setup.wants_signer {
            let read = |var: &polar_env::Optional<String>| {
                setup
                    .config
                    .read(var)
                    .map_err(|e| ActorProcessingErr::from(e.to_string()))
            };
            if read(&polar_custody::environment::CUSTODY_SOCKET)?.is_none()
                && read(&polar_crypto::environment::RECORD_KEY)?.is_none()
            {
                return Err(ActorProcessingErr::from(format!(
                    "{} or {} is required to sign records: the signing key is the custody daemon's, or the agent's own",
                    polar_custody::environment::CUSTODY_SOCKET.name(),
                    polar_crypto::environment::RECORD_KEY.name()
                )));
            }
            crypto
                .as_ref()
                .map(|crypto| crate::signer::SignerHandle::new(crypto.actor()))
        } else {
            None
        };

        let state = match state_replies {
            Some(replies) => {
                let (state_actor, _) = ractor::Actor::spawn_linked(
                    Some(format!("{service_name}.state")),
                    crate::state::StateActor,
                    crate::state::StateArgs {
                        client: tcp_client.clone(),
                        router: replies,
                        settings: crate::state::StateSettings::from_env(&*setup.config)
                            .map_err(ActorProcessingErr::from)?,
                        configuration: Some(setup.configuration.clone()),
                    },
                    myself.get_cell(),
                )
                .await
                .map_err(ActorProcessingErr::from)?;
                Some(crate::state::StateHandle::new(state_actor))
            }
            None => None,
        };

        Ok((
            ClientParts {
                events_output,
                router,
                tcp_client,
                one_of_many,
                crypto,
                escrow: setup.crypto.escrow,
                credential_port,
                signer,
                protocols: None,
                state,
            },
            self_test,
        ))
    }

    /// Tells the broker this session is done (the client's goodbye, `Disconnect`), and waits for the client to have said
    /// it, at most `GOODBYE_WAIT`: the broker then ends the session at once, where a connection that only closed would
    /// leave it detached for the retention window.
    async fn say_goodbye(service_name: &str, client: &ClientParts) {
        tracing::info!(
            "InfrastructureSupervisor: one instance of a multi-instance workload: telling the broker its session is done"
        );
        if let Err(e) = client
            .tcp_client
            .as_actor_ref()
            .send_message(cassini_client::TcpClientMessage::Disconnect { trace_ctx: None })
        {
            tracing::warn!("InfrastructureSupervisor: could not say goodbye to the broker: {e}");
            return;
        }
        let transport = format!("{service_name}.tcp");
        let deadline = tokio::time::Instant::now() + GOODBYE_WAIT;
        while ractor::registry::where_is(transport.clone()).is_some()
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn classify(state: &InfrastructureSupervisorState, cell: &ActorCell) -> Child {
        let id = cell.get_id();
        if id == state.healthcheck.as_actor_ref().get_id() {
            Child::Health
        } else if state.client.is_some()
            && cell.get_name() == Some(format!("{}.tcp", state.service_name))
        {
            // TcpClientActor is spawned under its own deterministic name; see
            // TcpClient::spawn_with_router.
            Child::TcpClient
        } else if state
            .client
            .as_ref()
            .is_some_and(|client| id == client.router.get_id())
        {
            Child::Other("the router".to_string())
        } else if state.crypto.actor().get_id() == id {
            Child::Other("the crypto actor".to_string())
        } else if state
            .client
            .as_ref()
            .and_then(|client| client.state.as_ref())
            .is_some_and(|handle| handle.as_actor_ref().get_id() == id)
        {
            Child::Other("the state actor".to_string())
        } else if state
            .graph
            .as_ref()
            .is_some_and(|graph| graph.actor().get_id() == id)
        {
            Child::Other("the graph controller".to_string())
        } else {
            Child::Other(match cell.get_name() {
                Some(name) => name,
                None => format!("child {id}"),
            })
        }
    }

    fn child_ended(state: &mut InfrastructureSupervisorState, cell: ActorCell, death: Death) {
        let child = Self::classify(state, &cell);
        match shutdown::on_child_death(state.shutdown.is_running(), &child, &death) {
            Action::Ignore => {
                tracing::debug!(
                    "InfrastructureSupervisor: {child:?} ended during the shutdown ({death:?})"
                );
            }
            Action::Shutdown(reason) => {
                tracing::error!("InfrastructureSupervisor: {reason}");
                Self::begin_shutdown(state, reason);
            }
        }
    }
}

#[async_trait]
impl Actor for InfrastructureSupervisor {
    type Msg = InfrastructureSupervisorMessage;
    type State = InfrastructureSupervisorState;
    type Arguments = InfrastructureSupervisorArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: InfrastructureSupervisorArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        let myself_cell = myself.get_cell();

        // The health actor reports its decision to end the agent here, as a
        // message, and stays alive to keep the health file fresh while the agent
        // drains. Whatever recipient the caller put in the args is replaced: this
        // supervisor is the only place that acts on it.
        let verdicts = Arc::new(OutputPort::default());
        verdicts.subscribe(myself.clone(), |verdict| {
            Some(InfrastructureSupervisorMessage::Health(verdict))
        });
        let health_check_args = args.health_check_args.with_verdict_to(verdicts);

        let (healthcheck, _) = HealthCheckActor::spawn_linked(
            None,
            HealthCheckActor,
            health_check_args,
            myself_cell.clone(),
        )
        .await
        .map_err(ActorProcessingErr::from)?;

        // Owns the configuration the agent runs on from here, and takes updates to it. It needs
        // nothing but the snapshot, so it starts before, and without, the Cassini client.
        // Signed documents are checked against the CA this agent already pins for Cassini. Without a
        // readable one there is nothing to verify against and every document is refused.
        // What the credentials agent says about policy, groups and revoked certificates, kept current for this
        // agent to decide by. Only a Cassini client hears it. It starts first, because signer verification
        // consults its revoked serials.
        let authority = if args.with_client {
            let publisher = args
                .config
                .read(&crate::environment::AUTHORITY_PUBLISHER)
                .map_err(|e| ActorProcessingErr::from(e.to_string()))?;
            // The credentials agent's key is believed only under a certificate from the CA this agent pins. Without a
            // readable one nothing is: the agent believes no authority, as it verifies no signed document.
            let trust = match crate::signed::pinned_trust(&args.config) {
                Ok(trust) => trust,
                Err(why) => {
                    tracing::warn!(
                        "no authority from the credentials agent will be believed: {why}"
                    );
                    polar_signing::Trust::from_pem(&[]).expect("no anchors is a trust")
                }
            };
            let authority = crate::authority::AuthorityHandle::spawn(
                &args.service_name,
                publisher,
                trust,
                myself_cell.clone(),
            )
            .await?;
            authority.asks().subscribe(myself.clone(), |_| {
                Some(InfrastructureSupervisorMessage::AuthorityAsk)
            });
            Some(authority)
        } else {
            None
        };
        let verifier =
            match crate::signed::UpdateVerifier::from_config(&args.config, &args.service_name) {
                Ok(verifier) => {
                    let verifier = match &authority {
                        Some(authority) => verifier.with_revocation(Arc::new(authority.revoked())),
                        None => verifier,
                    };
                    Some(verifier)
                }
                Err(why) => {
                    tracing::warn!(
                        "InfrastructureSupervisor: signed configuration will be refused: {why}"
                    );
                    None
                }
            };
        // The same trust, clock and revocation check commands, with their own authority.
        let command_verifier = verifier
            .as_ref()
            .map(crate::signed::UpdateVerifier::commands);
        let configuration = ConfigurationHandle::spawn_full(
            None,
            args.service_name.clone(),
            (*args.config).clone(),
            verifier,
            args.runtime_sections,
            authority.as_ref().map(|a| a.policy()),
            args.section_judge.clone(),
            args.settings_judge,
            myself_cell.clone(),
        )
        .await?;
        configuration.report_to(HealthHandle::new(healthcheck.clone()));
        let commands = crate::command_actor::CommandHandle::spawn_with_policy(
            None,
            args.service_name.clone(),
            command_verifier,
            args.commands,
            authority.as_ref().map(|a| a.policy()),
            myself_cell.clone(),
        )
        .await?;
        commands.outcomes().subscribe(myself.clone(), |outcome| {
            Some(InfrastructureSupervisorMessage::CommandOutcome(outcome))
        });
        // What became of each signed document is announced for the scheduler to record. It goes through
        // this supervisor so that it uses the Cassini client as it is now, across a respawn.
        configuration
            .outcomes()
            .subscribe(myself.clone(), |outcome| {
                Some(InfrastructureSupervisorMessage::Outcome(outcome))
            });
        let log_filters: [&dyn polar_env::Described; 2] = [
            &polar::logging::CONSOLE_FILTER,
            &polar::logging::TRACE_FILTER,
        ];
        if let Err(why) = configuration
            .follow_group(
                &log_filters,
                |config: &polar_env::Config| {
                    polar::logging::LoggingSettings::read(config).map_err(|e| e.to_string())
                },
                &myself,
                InfrastructureSupervisorMessage::LoggingChanged,
            )
            .await
        {
            tracing::warn!("InfrastructureSupervisor: the log filters: {why}");
        }

        // The crypto actor: every agent's, started before anything that uses a key, Cassini's client among them
        // (docs/plans/crypto-actor.md). It is told the client once there is one.
        let crypto = match args.crypto {
            // Started before the infrastructure, for the domain's TLS before it: linked here, its end ends the agent.
            Some(crypto) => {
                crypto.handle.actor().get_cell().link(myself_cell.clone());
                crypto
            }
            None => {
                Self::spawn_crypto(&args.config, args.wants_crypto, Some(myself_cell.clone()))
                    .await?
            }
        };

        // A witness's crypto actor co-signs only for the store its signed configuration pins: it follows the pin, and
        // holds every co-signature to the value in force.
        if matches!(
            args.config
                .read(&polar_crypto::environment::WITNESS_COSIGNING_KEY),
            Ok(Some(_))
        ) {
            let pinned = configuration
                .follow(
                    &polar_crypto::environment::WITNESSED_STORE,
                    &crypto.handle.actor(),
                    polar_crypto::CryptoMessage::WitnessedStore,
                )
                .await
                .map_err(|e| ActorProcessingErr::from(format!("the witnessed store: {e:?}")))?;
            crypto
                .handle
                .actor()
                .send_message(polar_crypto::CryptoMessage::WitnessedStore(pinned))
                .map_err(ActorProcessingErr::from)?;
        }

        let (mut client, self_test) = if args.with_client {
            let (client, self_test) = Self::spawn_client_parts(
                &myself,
                &args.service_name,
                ClientSetup {
                    subscriptions: args.subscriptions,
                    crypto: crypto.clone(),
                    wants_signer: args.wants_signer,
                    state_agent: args.state_agent.clone(),
                    self_test: args.self_test,
                    tcp_spawner: args.tcp_spawner,
                    config: args.config.clone(),
                    configuration: configuration.clone(),
                    commands: commands.clone(),
                    authority: authority
                        .clone()
                        .expect("a Cassini client has an authority actor"),
                },
            )
            .await?;
            (Some(client), self_test)
        } else {
            // A service that is not a Cassini client has no connection to wait for. The health
            // actor starts its ticks when it is told Cassini is connected, so tell it, once.
            use crate::health::HealthClient;
            let _ = HealthHandle::new(healthcheck.clone()).cassini_connected();
            (None, None)
        };

        if args.listen_for_signals {
            shutdown::spawn_signal_listener(myself.clone());
        }

        let graph = match args.graph {
            Some(setup) => Some(
                crate::graph::start_controller(
                    format!("{}.graph_controller", args.service_name),
                    setup,
                    healthcheck.clone(),
                    myself_cell.clone(),
                    &crate::crypto::TlsHandle::new(crypto.handle.actor()),
                )
                .await?,
            ),
            None => None,
        };

        let healthcheck = HealthHandle::new(healthcheck);
        let mut workers = crate::worker::Workers::default();
        for forked in args.workers {
            let (actor, _) = Actor::spawn_linked(
                Some(format!("{}.worker.{}", args.service_name, forked.decl.name)),
                crate::worker::WorkerActor,
                crate::worker::WorkerArgs {
                    name: forked.decl.name,
                    worker: forked.worker,
                    timeout: forked.decl.timeout,
                },
                myself.get_cell(),
            )
            .await
            .map_err(ActorProcessingErr::from)?;
            workers.insert(forked.decl.name, crate::worker::WorkerHandle::new(actor));
        }
        if let Some(client) = &mut client {
            client.protocols = crate::protocol::start(
                myself.get_cell(),
                crate::protocol::Start {
                    service_name: &args.service_name,
                    setup: args.protocols,
                    config: &args.config,
                    credentials: client.credential_port.take(),
                    crypto: client
                        .crypto
                        .clone()
                        .map(|crypto| Arc::new(crypto) as Arc<dyn crate::crypto::SectionKeeper>),
                    configuration: configuration.clone(),
                    health: healthcheck.clone(),
                },
            )
            .await?;
        }
        let running_answerer = client.as_ref().map(|client| crate::running::Answerer {
            agent: args.service_name.clone(),
            configuration: configuration.clone(),
            client: client.tcp_client.clone(),
        });
        let health_answerer = client.as_ref().map(|client| crate::health_query::Answerer {
            topic: polar_health::report::health_topic(&args.service_name),
            writer: args.health_writer.clone(),
            policy: crate::PolicyLookup::for_service(&args.service_name),
            health: healthcheck.clone(),
            configuration: configuration.clone(),
            client: client.tcp_client.clone(),
        });

        Ok(InfrastructureSupervisorState {
            workers,
            config: args.config,
            configuration,
            commands,
            authority,
            client,
            crypto: crypto.handle,
            healthcheck,
            service_name: args.service_name,
            shutdown: ShutdownMachine::new(),
            shutdown_budget: args.shutdown_budget,
            process_exit: args.process_exit,
            self_test,
            health_answerer,
            running_answerer,
            last_registered: None,
            graph,
            notice: args.notice,
            myself: myself.clone(),
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            InfrastructureSupervisorMessage::ClientEvent(event) => {
                // CryptoActor subscribes to its reply topics only once told
                // the client has registered; the client drops any Subscribe
                // sent earlier. Sent on every Registered, so a reconnect
                // restores them too.
                match &event {
                    ClientEvent::Registered { .. } => {
                        state.last_registered = Some(event.clone());
                        if let Some(test) = &mut state.self_test {
                            test.connected = true;
                            test.machine.registered();
                        }
                    }
                    ClientEvent::TransportError { .. } => {
                        state.last_registered = None;
                        if let Some(test) = &mut state.self_test {
                            test.connected = false;
                        }
                    }
                    // A refusal is said in every agent's log, by the builder, whatever the agent does with it.
                    ClientEvent::SubscribeRefused { topic, reason } => {
                        tracing::warn!(%topic, %reason, "the broker refused a subscription");
                    }
                    ClientEvent::PublishRefused { topic, reason } => {
                        tracing::warn!(%topic, %reason, "the broker refused a publish");
                    }
                    _ => {}
                }
                if let Some(client) = &state.client {
                    if let ClientEvent::Registered { .. } = &event
                        && let Some(crypto) = &client.crypto
                        && let Err(e) = crypto
                            .actor()
                            .send_message(polar_crypto::CryptoMessage::ClientRegistered)
                    {
                        tracing::warn!("failed to tell CryptoActor the client registered: {e}");
                    }
                    if let ClientEvent::Registered { .. } = &event {
                        Self::ask_for_configuration(&state.service_name, client);
                        if let Some(authority) = &state.authority {
                            authority.registered();
                        }
                    }
                    client.events_output.send(event);
                }
            }
            InfrastructureSupervisorMessage::Health(verdict) => {
                match &verdict {
                    HealthVerdict::Rejuvenate => {
                        tracing::info!("InfrastructureSupervisor: the health actor says rejuvenate")
                    }
                    HealthVerdict::Unhealthy(_) => tracing::error!(
                        "InfrastructureSupervisor: the health actor says the agent is unhealthy: {}",
                        verdict.reason()
                    ),
                }
                Self::begin_shutdown(state, verdict.reason());
            }
            InfrastructureSupervisorMessage::BeginShutdown { reason } => {
                Self::begin_shutdown(state, reason);
            }
            InfrastructureSupervisorMessage::SelfTestTick => Self::self_test_tick(state),
            InfrastructureSupervisorMessage::HealthQuery {
                payload,
                published_by,
            } => {
                if let Some(answerer) = state.health_answerer.clone() {
                    tokio::spawn(async move { answerer.answer(payload, published_by).await });
                }
            }
            InfrastructureSupervisorMessage::RunningConfigurationQuestion {
                payload,
                published_by,
            } => {
                if let Some(answerer) = state.running_answerer.clone() {
                    tokio::spawn(async move { answerer.answer(payload, published_by).await });
                }
            }
            InfrastructureSupervisorMessage::CommandOutcome(outcome) => {
                let Some(client) = &state.client else {
                    tracing::debug!(
                        "InfrastructureSupervisor: no Cassini client, command outcome not announced"
                    );
                    return Ok(());
                };
                match rkyv::to_bytes::<rkyv::rancor::Error>(&outcome) {
                    Ok(bytes) => {
                        if let Err(e) = client.tcp_client.as_actor_ref().send_message(
                            cassini_client::TcpClientMessage::publish(
                                polar_scheduler_common::COMMAND_OUTCOME_TOPIC.to_string(),
                                bytes.to_vec(),
                                None,
                            ),
                        ) {
                            tracing::warn!(
                                "InfrastructureSupervisor: cannot announce a command outcome: {e}"
                            );
                        }
                    }
                    Err(e) => tracing::error!(
                        "InfrastructureSupervisor: cannot encode a command outcome: {e}"
                    ),
                }
            }
            InfrastructureSupervisorMessage::Refusals(news) => match news {
                cassini_client::facade::RefusalNews::Unpredicted {
                    topic,
                    use_,
                    reason,
                } => {
                    tracing::info!(
                        %topic,
                        %reason,
                        "the broker refused to {} what this agent's own check let through; asking for the current authority",
                        use_.as_str()
                    );
                    if let Some(authority) = &state.authority {
                        authority.behind();
                    }
                }
                cassini_client::facade::RefusalNews::Standing(standing) => {
                    state.healthcheck.topics_refused(
                        standing
                            .into_iter()
                            .map(|s| polar_health::RefusedTopic {
                                topic: s.topic,
                                access: s.use_.as_str().to_string(),
                                reason: s.reason,
                            })
                            .collect(),
                    );
                }
            },
            InfrastructureSupervisorMessage::AuthorityAsk => {
                if let Some(client) = &state.client {
                    match rkyv::to_bytes::<rkyv::rancor::Error>(
                        &credentials_agent_common::authority_update::AuthoritySnapshotRequest,
                    ) {
                        Ok(bytes) => {
                            if let Err(e) = client.tcp_client.as_actor_ref().send_message(
                                cassini_client::TcpClientMessage::publish(
                                    credentials_agent_common::authority_update::AUTHORITY_SNAPSHOT_REQUESTS_TOPIC
                                        .to_string(),
                                    bytes.to_vec(),
                                    None,
                                ),
                            ) {
                                tracing::warn!(
                                    "InfrastructureSupervisor: cannot ask for the authority: {e}"
                                );
                            }
                        }
                        Err(e) => tracing::error!(
                            "InfrastructureSupervisor: cannot encode a request for the authority: {e}"
                        ),
                    }
                }
            }
            InfrastructureSupervisorMessage::LoggingChanged(settings) => {
                match polar::logging::reload(&settings) {
                    Ok(()) => tracing::info!(
                        "InfrastructureSupervisor: the log filters follow the new configuration"
                    ),
                    Err(why) => tracing::warn!(
                        "InfrastructureSupervisor: the log filters could not be reloaded: {why}"
                    ),
                }
            }
            InfrastructureSupervisorMessage::Outcome(outcome) => {
                let Some(client) = &state.client else {
                    tracing::debug!(
                        "InfrastructureSupervisor: no Cassini client, outcome not announced"
                    );
                    return Ok(());
                };
                match rkyv::to_bytes::<rkyv::rancor::Error>(&outcome) {
                    Ok(bytes) => {
                        if let Err(e) = client.tcp_client.as_actor_ref().send_message(
                            cassini_client::TcpClientMessage::publish(
                                polar_scheduler_common::CONFIGURATION_OUTCOME_TOPIC.to_string(),
                                bytes.to_vec(),
                                None,
                            ),
                        ) {
                            tracing::warn!(
                                "InfrastructureSupervisor: cannot announce an outcome: {e}"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!("InfrastructureSupervisor: cannot encode an outcome: {e}")
                    }
                }
            }
            InfrastructureSupervisorMessage::ProceedWithShutdown => {
                if !state.shutdown.proceed() {
                    tracing::info!(
                        "InfrastructureSupervisor: already stopping, ignoring a further \
                         ProceedWithShutdown"
                    );
                    return Ok(());
                }
                tracing::info!("InfrastructureSupervisor: proceeding with its own shutdown");
                // One pod of a multi-instance workload ends its session at once: no successor of its instance will
                // supersede it, so left to the retention window it would wait there ten minutes as unresponsive. A
                // single-instance workload's session is kept for its successor, as always.
                if let Some(client) = state.client.as_ref().filter(|client| client.one_of_many) {
                    Self::say_goodbye(&state.service_name, client).await;
                }
                // The graph first: what the agent handed it before it proceeded is written, and the
                // rest of the infrastructure is not needed for that.
                if let Some(graph) = state.graph.take() {
                    crate::graph::stop_graph_controller(
                        graph.actor().clone(),
                        crate::graph::GRAPH_DRAIN,
                    )
                    .await;
                }
                myself
                    .stop_children_and_wait(
                        Some("infrastructure shutdown".to_string()),
                        Some(STOP_CHILDREN_TIMEOUT),
                    )
                    .await;
                myself.stop(Some("infrastructure shutdown complete".to_string()));
            }
            InfrastructureSupervisorMessage::GetResources { reply } => {
                let _ = reply.send(state.client.as_ref().map(|client| {
                    AgentResources {
                        router: client.router.clone(),
                        tcp_client: client.tcp_client.clone(),
                        healthcheck: state.healthcheck.clone(),
                        crypto: client.crypto.clone().filter(|_| client.escrow),
                        tls: crate::crypto::TlsHandle::new(state.crypto.actor()),
                        checkpoints: checkpoint_handle(&state.config, &state.crypto),
                        cosigning: cosign_handle(&state.config, &state.crypto),
                        signer: client.signer.clone(),
                        record_key: record_key_handle(&state.config, &state.crypto),
                        protocols: client.protocols.clone(),
                        state: client.state.clone(),
                        workers: state.workers.clone(),
                        graph: state.graph.clone(),
                        events_output: client.events_output.clone(),
                        infrastructure: myself.clone(),
                        config: state.config.clone(),
                        configuration: state.configuration.clone(),
                        authority: state
                            .authority
                            .clone()
                            .expect("a Cassini client has an authority actor"),
                    }
                }));
            }
            InfrastructureSupervisorMessage::LastRegistered { reply } => {
                let _ = reply.send(state.last_registered.clone());
            }
            InfrastructureSupervisorMessage::GetService { reply } => {
                let _ = reply.send(crate::ServiceResources {
                    healthcheck: state.healthcheck.clone(),
                    infrastructure: myself.clone(),
                    config: state.config.clone(),
                    configuration: state.configuration.clone(),
                    tls: crate::crypto::TlsHandle::new(state.crypto.actor()),
                    checkpoints: checkpoint_handle(&state.config, &state.crypto),
                    cosigning: cosign_handle(&state.config, &state.crypto),
                });
            }
        }
        Ok(())
    }

    async fn handle_supervisor_evt(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: SupervisionEvent,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            SupervisionEvent::ActorTerminated(cell, _, reason) => {
                Self::child_ended(state, cell, Death::Terminated(reason));
            }
            SupervisionEvent::ActorFailed(cell, error) => {
                Self::child_ended(state, cell, Death::Failed(error.to_string()));
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cassini_client::TcpClientMessage;
    use ractor::ActorStatus;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    // -- a Cassini client that needs no broker ---------------------------------

    /// What a fake client was asked to publish: the topic and the payload.
    type Published = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    struct FakeTcp {
        fail_on_message: bool,
        /// If set, whatever is published comes straight back through the router, as a broker
        /// would deliver it to a subscriber of the topic.
        echo_to: Option<ActorRef<polar_router::RouterMessage>>,
        /// Every topic and payload published, in order.
        published: Published,
        /// How many times it was told to judge its refusals again.
        judged: Arc<AtomicUsize>,
        /// How many times it said goodbye to the broker (`Disconnect`), after which it stops, as the real client does.
        goodbyes: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Actor for FakeTcp {
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
            myself: ActorRef<Self::Msg>,
            message: Self::Msg,
            _state: &mut Self::State,
        ) -> Result<(), ActorProcessingErr> {
            if let TcpClientMessage::JudgeAgain = message {
                self.judged.fetch_add(1, Ordering::SeqCst);
            }
            if let TcpClientMessage::Disconnect { .. } = message {
                self.goodbyes.fetch_add(1, Ordering::SeqCst);
                myself.stop(Some("goodbye".to_string()));
                return Ok(());
            }
            if let TcpClientMessage::Publish { topic, payload, .. } = message {
                self.published
                    .lock()
                    .unwrap()
                    .push((topic.clone(), payload.clone()));
                if let Some(router) = &self.echo_to {
                    let _ = router.send_message(polar_router::RouterMessage::Route(
                        polar_router::IncomingMessage {
                            topic,
                            payload,
                            published_by: None,
                            published_instance: None,
                            trace_ctx: None,
                        },
                    ));
                }
            }
            if self.fail_on_message {
                Err(ActorProcessingErr::from("the fake client was made to fail"))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Default)]
    struct FakeSpawner {
        spawned: AtomicUsize,
        fail_next_spawn: AtomicBool,
        clients_fail_on_message: AtomicBool,
        /// Clients hand what they publish back to the router.
        clients_echo: AtomicBool,
        /// The configuration each client was started with, in order.
        configs: Mutex<Vec<CassiniSettings>>,
        /// What every client published.
        published: Published,
        /// How many times every client was told to judge its refusals again.
        judged: Arc<AtomicUsize>,
        /// How many times every client said goodbye.
        goodbyes: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl TcpClientSpawner for FakeSpawner {
        async fn spawn(
            &self,
            service_name: &str,
            supervisor: ActorRef<InfrastructureSupervisorMessage>,
            _lifecycle: LifecycleHandler,
            router: ActorRef<polar_router::RouterMessage>,
            settings: CassiniSettings,
            _tls: crate::crypto::TlsHandle,
        ) -> Result<TcpClient, ActorProcessingErr> {
            self.configs.lock().unwrap().push(settings);
            if self.fail_next_spawn.swap(false, Ordering::SeqCst) {
                return Err(ActorProcessingErr::from(
                    "the fake spawner was made to fail",
                ));
            }
            self.spawned.fetch_add(1, Ordering::SeqCst);
            let (actor, _) = Actor::spawn_linked(
                Some(format!("{service_name}.tcp")),
                FakeTcp {
                    fail_on_message: self.clients_fail_on_message.load(Ordering::SeqCst),
                    echo_to: self
                        .clients_echo
                        .load(Ordering::SeqCst)
                        .then(|| router.clone()),
                    published: self.published.clone(),
                    judged: self.judged.clone(),
                    goodbyes: self.goodbyes.clone(),
                },
                (),
                supervisor.get_cell(),
            )
            .await?;
            Ok(TcpClient::from_actor_ref(actor))
        }
    }

    // -- what the domain supervisor is told ------------------------------------------------

    /// How a rig's domain asked to be told that the agent is to end.
    #[derive(Clone, Copy)]
    enum Told {
        /// `with_drain`: told, and waited for.
        AndWaitedFor,
        /// `on_shutdown`: told only.
        Only,
        /// Neither.
        Not,
    }

    /// The notice for `told`, recording "prepare_shutdown" in `events` each time the domain is told.
    fn notice(told: Told, events: &Arc<Mutex<Vec<String>>>) -> Option<ShutdownNotice> {
        let events = events.clone();
        let tell: Arc<dyn Fn() + Send + Sync> =
            Arc::new(move || events.lock().unwrap().push("prepare_shutdown".to_string()));
        match told {
            Told::AndWaitedFor => Some(ShutdownNotice { tell, wait: true }),
            Told::Only => Some(ShutdownNotice { tell, wait: false }),
            Told::Not => None,
        }
    }

    use std::collections::HashMap;

    // -- the rig -----------------------------------------------------------------------
    //
    // The real supervisor with a real router and a real health actor. The health actor is
    // handed its settings from a snapshot of a map, as the builder hands them from the
    // process, so rigs share nothing and run side by side.

    struct Rig {
        infra: ActorRef<InfrastructureSupervisorMessage>,
        done: Option<ractor::concurrency::JoinHandle<()>>,
        resources: AgentResources,
        events: Arc<Mutex<Vec<String>>>,
        exits: Arc<Mutex<Vec<i32>>>,
        spawner: Arc<FakeSpawner>,
        _dir: tempfile::TempDir,
    }

    impl Rig {
        /// `health_env` is applied on top of a health file in a temp directory and a
        /// Cassini deadline too long to matter, so only the tests about the
        /// health actor's own verdicts see one.
        async fn new(
            service: &str,
            budget: Duration,
            health_env: &[(&str, &str)],
            listen_for_signals: bool,
        ) -> Self {
            Self::build(
                service,
                budget,
                health_env,
                listen_for_signals,
                false,
                None,
                vec![],
                &[],
            )
            .await
        }

        /// A rig whose agent declares commands, each with its handler.
        async fn with_commands(
            service: &str,
            health_env: &[(&str, &str)],
            commands: Vec<(
                crate::command::CommandSpec,
                Arc<dyn crate::command_actor::CommandHandler>,
            )>,
        ) -> Self {
            Self::build(
                service,
                Duration::from_secs(20),
                health_env,
                false,
                false,
                None,
                commands,
                &[],
            )
            .await
        }

        /// A rig whose agent tests itself. `echo` is whether its Cassini client hands the
        /// probes back, as a working broker connection would.
        async fn self_testing(service: &str, echo: bool) -> Self {
            Self::build(
                service,
                Duration::from_secs(20),
                &[],
                false,
                false,
                Some(echo),
                vec![],
                &[],
            )
            .await
        }

        /// A rig whose agent declares runtime sections.
        async fn with_runtime(
            service: &str,
            health_env: &[(&str, &str)],
            sections: &'static [&'static crate::runtime::RuntimeSection],
        ) -> Self {
            Self::build(
                service,
                Duration::from_secs(20),
                health_env,
                false,
                false,
                None,
                vec![],
                sections,
            )
            .await
        }

        /// A rig whose agent encrypts: it has a real certificate for the crypto actor to take
        /// its identity from.
        async fn with_crypto(service: &str) -> Self {
            Self::build(
                service,
                Duration::from_secs(20),
                &[],
                false,
                true,
                None,
                vec![],
                &[],
            )
            .await
        }

        /// A rig whose agent signs evidence records: the builder starts a signer for it.
        async fn with_signer(service: &str) -> Self {
            Self::build_with(
                service,
                Duration::from_secs(20),
                &[],
                false,
                false,
                None,
                vec![],
                &[],
                None,
                None,
                Told::AndWaitedFor,
                true,
            )
            .await
        }

        /// A rig whose agent signs evidence records with a record key of its own, custody holding none for it.
        async fn with_record_key(service: &str) -> Self {
            Self::build_with(
                service,
                Duration::from_secs(20),
                &[("POLAR_RECORD_KEY", "")],
                false,
                false,
                None,
                vec![],
                &[],
                None,
                None,
                Told::AndWaitedFor,
                true,
            )
            .await
        }

        /// A rig whose agent reads its own soft state: the builder starts a state actor for it.
        async fn with_state(service: &str) -> Self {
            Self::build_with(
                service,
                Duration::from_secs(20),
                &[],
                false,
                false,
                None,
                vec![],
                &[],
                Some("soft-state-observer.polar.serviceaccount.cluster.local".to_string()),
                None,
                Told::AndWaitedFor,
                false,
            )
            .await
        }

        /// A rig whose agent needs the graph: the builder starts its graph controller with `setup`.
        async fn with_graph(service: &str, setup: crate::graph::GraphSetup) -> Self {
            Self::build_with(
                service,
                Duration::from_secs(20),
                &[],
                false,
                false,
                None,
                vec![],
                &[],
                None,
                Some(setup),
                Told::AndWaitedFor,
                false,
            )
            .await
        }

        #[allow(clippy::too_many_arguments)]
        async fn build(
            service: &str,
            budget: Duration,
            health_env: &[(&str, &str)],
            listen_for_signals: bool,
            crypto: bool,
            self_test: Option<bool>,
            commands: Vec<(
                crate::command::CommandSpec,
                Arc<dyn crate::command_actor::CommandHandler>,
            )>,
            runtime: &'static [&'static crate::runtime::RuntimeSection],
        ) -> Self {
            Self::build_with(
                service,
                budget,
                health_env,
                listen_for_signals,
                crypto,
                self_test,
                commands,
                runtime,
                None,
                None,
                Told::AndWaitedFor,
                false,
            )
            .await
        }

        /// A rig whose domain asked to be told `told`.
        async fn told(service: &str, told: Told) -> Self {
            Self::build_with(
                service,
                Duration::from_secs(20),
                &[],
                false,
                false,
                None,
                vec![],
                &[],
                None,
                None,
                told,
                false,
            )
            .await
        }

        #[allow(clippy::too_many_arguments)]
        async fn build_with(
            service: &str,
            budget: Duration,
            health_env: &[(&str, &str)],
            listen_for_signals: bool,
            crypto: bool,
            self_test: Option<bool>,
            commands: Vec<(
                crate::command::CommandSpec,
                Arc<dyn crate::command_actor::CommandHandler>,
            )>,
            runtime: &'static [&'static crate::runtime::RuntimeSection],
            state_agent: Option<String>,
            graph: Option<crate::graph::GraphSetup>,
            told: Told,
            signing: bool,
        ) -> Self {
            let events = Arc::new(Mutex::new(Vec::new()));
            let health_writer = Some(RIG_WRITER.to_string());
            let dir = tempfile::tempdir().unwrap();
            let certificate = dir.path().join("cert.pem");
            if crypto || signing {
                let params = rcgen::CertificateParams::new(vec![format!("{service}-identity")])
                    .expect("certificate parameters");
                let key = rcgen::KeyPair::generate().expect("key");
                std::fs::write(
                    &certificate,
                    params.self_signed(&key).expect("self-sign").pem(),
                )
                .expect("write the certificate");
            }
            let mut vars: HashMap<String, String> = [
                (
                    "POLAR_HEALTH_FILE",
                    dir.path().join("health.json").to_str().unwrap(),
                ),
                ("POLAR_HEALTH_CASSINI_DEADLINE_SECS", "100000"),
            ]
            .into_iter()
            .chain(crate::environment::fixtures::CASSINI_ENV.iter().copied())
            .chain(health_env.iter().copied())
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
            let mut required = vec![crate::Capability::Cassini];
            // The crypto actor takes its identity from the agent's certificate: one that encrypts or signs has one.
            if crypto || signing {
                vars.insert(
                    "TLS_CLIENT_CERT".to_string(),
                    certificate.to_string_lossy().into_owned(),
                );
            }
            if crypto {
                required.push(crate::Capability::Encryption);
            }
            if state_agent.is_some() {
                required.push(crate::Capability::SoftState);
            }
            // An agent that signs with a key of its own (its record key, which `with_record_key` names): custody holds
            // none for it, and the key is made in the rig's directory.
            if signing && vars.contains_key("POLAR_RECORD_KEY") {
                vars.insert(
                    "POLAR_RECORD_KEY".to_string(),
                    dir.path()
                        .join("record-key.pem")
                        .to_string_lossy()
                        .into_owned(),
                );
                required.push(crate::Capability::RecordKey);
            // An agent that signs: its keys are the custody daemon's, so it names the daemon's socket and no key file.
            } else if signing {
                vars.remove("TLS_CLIENT_KEY");
                vars.insert(
                    "POLAR_CUSTODY_SOCKET".to_string(),
                    dir.path()
                        .join("custody.sock")
                        .to_string_lossy()
                        .into_owned(),
                );
                required.push(crate::Capability::Signing);
            }
            let startup = crate::startup::prepare(&vars, &[], &required, None).unwrap();

            let exits = Arc::new(Mutex::new(Vec::new()));
            let recorded = exits.clone();
            let spawner = Arc::new(FakeSpawner::default());
            if self_test == Some(true) {
                spawner.clients_echo.store(true, Ordering::SeqCst);
            }

            let (infra, done) = Actor::spawn(
                None,
                InfrastructureSupervisor,
                InfrastructureSupervisorArgs {
                    crypto: None,
                    service_name: service.to_string(),
                    health_check_args: HealthCheckArgs::new(false, 300, vec![])
                        .with_config(startup.health),
                    config: startup.config,
                    subscriptions: vec![],
                    wants_crypto: crypto,
                    wants_signer: signing,
                    state_agent,
                    health_writer,
                    with_client: true,
                    shutdown_budget: budget,
                    listen_for_signals,
                    process_exit: Arc::new(move |code| recorded.lock().unwrap().push(code)),
                    tcp_spawner: spawner.clone(),
                    commands,
                    runtime_sections: runtime,
                    protocols: crate::protocol::ProtocolSetup::default(),
                    workers: Vec::new(),
                    section_judge: None,
                    settings_judge: None,
                    self_test: self_test.is_some(),
                    graph,
                    notice: notice(told, &events),
                },
            )
            .await
            .unwrap();

            let resources: AgentResources = ractor::call!(infra, |reply| {
                InfrastructureSupervisorMessage::GetResources { reply }
            })
            .unwrap()
            .expect("a supervisor with a Cassini client");

            Self {
                infra,
                done: Some(done),
                resources,
                events,
                exits,
                spawner,
                _dir: dir,
            }
        }

        async fn standard(service: &str) -> Self {
            Self::new(service, Duration::from_secs(20), &[], false).await
        }

        /// As `standard`, pinning a CA of the test's, which it returns with the directory its file is in.
        async fn pinning(
            service: &str,
        ) -> (Self, polar_signing::testing::Authority, tempfile::TempDir) {
            let ca = polar_signing::testing::root("Polar Internal CA");
            let dir = tempfile::tempdir().unwrap();
            let ca_file = dir.path().join("ca.pem");
            std::fs::write(&ca_file, &ca.pem).unwrap();
            let rig = Self::new(
                service,
                Duration::from_secs(20),
                &[("TLS_CA_CERT", ca_file.to_str().unwrap())],
                false,
            )
            .await;
            (rig, ca, dir)
        }

        fn events(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }

        /// What the health actor last wrote about the agent.
        fn health(&self) -> polar_health::HealthState {
            let text = std::fs::read_to_string(self._dir.path().join("health.json"))
                .expect("a health file");
            serde_json::from_str(&text).expect("a health file that parses")
        }

        /// The agent registers, as its Cassini client reports it.
        async fn registered(&self) {
            use crate::health::HealthClient;
            self.resources.healthcheck.cassini_connected().unwrap();
            self.infra
                .cast(InfrastructureSupervisorMessage::ClientEvent(
                    ClientEvent::Registered {
                        registration_id: "r".to_string(),
                    },
                ))
                .unwrap();
        }

        fn exits(&self) -> Vec<i32> {
            self.exits.lock().unwrap().clone()
        }

        fn begin(&self, reason: &str) {
            self.infra
                .cast(InfrastructureSupervisorMessage::BeginShutdown {
                    reason: reason.to_string(),
                })
                .unwrap();
        }

        /// Lets queued messages and the output ports' forwarding tasks run.
        async fn settle(&self) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    // -- a subscriber that comes after the registration ---------------------------------------------

    /// A stand-in for a domain supervisor: it keeps the events it is sent.
    struct Domain;

    #[async_trait]
    impl Actor for Domain {
        type Msg = ClientEvent;
        type State = Arc<Mutex<Vec<ClientEvent>>>;
        type Arguments = Arc<Mutex<Vec<ClientEvent>>>;
        async fn pre_start(
            &self,
            _: ActorRef<Self::Msg>,
            heard: Self::Arguments,
        ) -> Result<Self::State, ActorProcessingErr> {
            Ok(heard)
        }
        async fn handle(
            &self,
            _: ActorRef<Self::Msg>,
            event: Self::Msg,
            heard: &mut Self::State,
        ) -> Result<(), ActorProcessingErr> {
            heard.lock().unwrap().push(event);
            Ok(())
        }
    }

    /// Cassini can register before the agent's supervisor has subscribed: its agent would then wait for ever for an event
    /// that has gone by, connected and doing nothing. Seen live when building the HTTP client made the infrastructure's start
    /// longer than a registration.
    #[tokio::test(start_paused = true)]
    async fn a_subscriber_that_came_too_late_is_told_of_the_registration() {
        let rig = Rig::standard("late-subscriber").await;
        rig.registered().await;
        rig.settle().await;

        let heard: Arc<Mutex<Vec<ClientEvent>>> = Arc::default();
        let (domain, _) = Actor::spawn(None, Domain, heard.clone()).await.unwrap();
        rig.resources.events_output.subscribe(domain.clone(), Some);
        rig.settle().await;
        assert!(heard.lock().unwrap().is_empty(), "the port does not replay");

        catch_up(&rig.infra, &domain, &Some).await.unwrap();
        rig.settle().await;
        assert!(
            matches!(&heard.lock().unwrap()[..], [ClientEvent::Registered { .. }]),
            "{:?}",
            heard.lock().unwrap()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_is_not_registered_gives_nothing_to_catch_up_on() {
        let rig = Rig::standard("not-registered").await;
        let heard: Arc<Mutex<Vec<ClientEvent>>> = Arc::default();
        let (domain, _) = Actor::spawn(None, Domain, heard.clone()).await.unwrap();

        catch_up(&rig.infra, &domain, &Some).await.unwrap();
        rig.settle().await;
        assert!(heard.lock().unwrap().is_empty());

        // Registered, then gone: what it was registered on is no more.
        rig.registered().await;
        rig.infra
            .cast(InfrastructureSupervisorMessage::ClientEvent(
                ClientEvent::TransportError {
                    reason: "gone".to_string(),
                },
            ))
            .unwrap();
        rig.settle().await;
        catch_up(&rig.infra, &domain, &Some).await.unwrap();
        rig.settle().await;
        assert!(
            heard.lock().unwrap().is_empty(),
            "{:?}",
            heard.lock().unwrap()
        );
    }

    // -- authority from the credentials agent -----------------------------------------------------

    const CREDENTIALS: &str = "credentials-agent.polar.serviceaccount.cluster.local";

    /// A snapshot the credentials agent signed with `key`, under its signing certificate from `ca`.
    fn authority_snapshot(
        ca: &polar_signing::testing::Authority,
        key: &credentials_agent_common::authority_update::AuthorityKey,
        payloads: &[credentials_agent_common::authority_update::AuthorityPayload],
    ) -> credentials_agent_common::authority_update::AuthoritySnapshot {
        let public_key_pem =
            credentials_agent_common::authority_update::public_key_pem(key.verifying_key())
                .unwrap();
        credentials_agent_common::authority_update::AuthoritySnapshot {
            escrow_certificate_chain_pem: Vec::new(),
            certificate_chain_pem: vec![polar_signing::testing::escrow_certificate_for(
                ca,
                polar_signing::testing::authority_spec(CREDENTIALS),
                &public_key_pem,
            )],
            public_key_pem,
            updates: payloads
                .iter()
                .map(|p| credentials_agent_common::authority_update::sign(p, key).unwrap())
                .collect(),
        }
    }

    fn deliver_snapshot(
        rig: &Rig,
        snapshot: &credentials_agent_common::authority_update::AuthoritySnapshot,
        published_by: Option<&str>,
    ) {
        rig.resources
            .router
            .send_message(polar_router::RouterMessage::Route(
                polar_router::IncomingMessage {
                    topic:
                        credentials_agent_common::authority_update::AUTHORITY_SNAPSHOT_REPLIES_TOPIC
                            .to_string(),
                    payload: rkyv::to_bytes::<rkyv::rancor::Error>(snapshot)
                        .unwrap()
                        .to_vec(),
                    published_by: published_by.map(str::to_string),
                    published_instance: None,
                    trace_ctx: None,
                },
            ))
            .unwrap();
    }

    fn requests_for_authority(rig: &Rig) -> usize {
        rig.spawner
            .published
            .lock()
            .unwrap()
            .iter()
            .filter(|(topic, _)| {
                topic
                    == credentials_agent_common::authority_update::AUTHORITY_SNAPSHOT_REQUESTS_TOPIC
            })
            .count()
    }

    #[tokio::test(start_paused = true)]
    async fn an_agent_asks_the_credentials_agent_for_the_current_authority_when_it_registers() {
        let rig = Rig::standard("infra-authority-ask").await;
        assert_eq!(
            requests_for_authority(&rig),
            0,
            "nothing before it registers"
        );
        rig.registered().await;
        rig.settle().await;
        assert_eq!(requests_for_authority(&rig), 1);
    }

    // -- what the agent was refused (docs/architecture/policy-enforcement.md, stage 5b) ------------------------

    #[tokio::test(start_paused = true)]
    async fn a_refusal_the_gate_did_not_predict_asks_for_the_current_authority() {
        let rig = Rig::standard("infra-refusal-ask").await;
        rig.registered().await;
        rig.settle().await;
        assert_eq!(requests_for_authority(&rig), 1);
        tokio::time::sleep(Duration::from_secs(6)).await;
        rig.infra
            .cast(InfrastructureSupervisorMessage::Refusals(
                cassini_client::facade::RefusalNews::Unpredicted {
                    topic: "news".to_string(),
                    use_: cassini_client::facade::TopicUse::Subscribe,
                    reason: "the broker refused: no".to_string(),
                },
            ))
            .unwrap();
        rig.settle().await;
        assert_eq!(requests_for_authority(&rig), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn the_topics_an_agent_is_refused_are_in_its_health_file_and_it_stays_healthy() {
        let rig = Rig::standard("infra-refusal-health").await;
        rig.registered().await;
        rig.infra
            .cast(InfrastructureSupervisorMessage::Refusals(
                cassini_client::facade::RefusalNews::Standing(vec![
                    cassini_client::refused::StandingRefusal {
                        topic: "news".to_string(),
                        use_: cassini_client::facade::TopicUse::Subscribe,
                        reason: "policy forbids this agent to subscribe on `news`".to_string(),
                        by_broker: false,
                    },
                ]),
            ))
            .unwrap();
        rig.settle().await;
        // The next write carries it.
        tokio::time::sleep(Duration::from_secs(31)).await;
        rig.settle().await;
        let health = rig.health();
        assert_eq!(health.status, polar_health::HealthStatus::Healthy);
        assert_eq!(
            health.refused_topics,
            [polar_health::RefusedTopic {
                topic: "news".to_string(),
                access: "subscribe".to_string(),
                reason: "policy forbids this agent to subscribe on `news`".to_string(),
            }]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_change_of_authority_has_the_client_judge_what_it_was_refused_again() {
        use credentials_agent_common::authority_update::{AuthorityBody, AuthorityPayload};
        let (rig, ca, _dir) = Rig::pinning("infra-refusal-judge").await;
        assert_eq!(rig.spawner.judged.load(Ordering::SeqCst), 0);
        let key = credentials_agent_common::authority_update::generate_key().unwrap();
        let snapshot = authority_snapshot(
            &ca,
            &key,
            &[AuthorityPayload {
                sequence: 1,
                version: 1,
                body: AuthorityBody::Policy {
                    source: r#"permit(principal == Identity::"alice", action, resource);"#.into(),
                },
                authored_by: None,
            }],
        );
        deliver_snapshot(&rig, &snapshot, Some(CREDENTIALS));
        rig.settle().await;
        assert_eq!(rig.spawner.judged.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_snapshot_from_the_credentials_agent_reaches_the_agents_policy_and_permissions() {
        use credentials_agent_common::authority_update::{
            AuthorityBody, AuthorityKind, AuthorityPayload,
        };
        let (rig, ca, _dir) = Rig::pinning("infra-authority-snapshot").await;
        let key = credentials_agent_common::authority_update::generate_key().unwrap();
        let snapshot = authority_snapshot(
            &ca,
            &key,
            &[AuthorityPayload {
                sequence: 1,
                version: 4,
                body: AuthorityBody::Policy {
                    source: r#"permit(principal == Identity::"alice", action, resource);"#.into(),
                },
                authored_by: None,
            }],
        );

        // From anyone else it is ignored.
        deliver_snapshot(&rig, &snapshot, Some("some-other-agent"));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(rig.resources.authority.versions().await.unwrap().is_empty());

        // From the credentials agent it is believed and applied.
        deliver_snapshot(&rig, &snapshot, Some(CREDENTIALS));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            rig.resources.authority.versions().await.unwrap()[&AuthorityKind::Policy],
            4
        );
        let decision = ractor::call!(rig.resources.authority.policy(), |reply| {
            polar_policy::PolicyMessage::CheckAuthorization {
                facts: Default::default(),
                requester_identity: "alice".to_string(),
                requester_certificate_pem: None,
                action: r#"Action::"run-command""#.to_string(),
                resource: r#"Command::"a/b""#.to_string(),
                reply,
            }
        })
        .unwrap()
        .unwrap();
        assert_eq!(decision, polar_policy::Decision::Allow);
    }

    #[tokio::test(start_paused = true)]
    async fn a_signer_the_credentials_agent_revoked_is_refused_by_the_next_document() {
        use crate::configuration::{ApplyOutcome, Refusal};
        use crate::signed::Rejection;
        use credentials_agent_common::authority_update::{AuthorityBody, AuthorityPayload};
        use polar_signing::testing::{Spec, root, signer};

        let ca = root("Polar Internal CA");
        let dir = tempfile::tempdir().unwrap();
        let ca_file = dir.path().join("ca.pem");
        std::fs::write(&ca_file, &ca.pem).unwrap();
        let rig = Rig::with_runtime(
            "infra-revoked",
            &[("TLS_CA_CERT", ca_file.to_str().unwrap())],
            &INFRA_RUNTIME,
        )
        .await;
        let s = signer(
            &ca,
            Spec {
                capabilities: vec!["c:update-runtime"],
                not_after_year: 2090,
                ..Spec::default()
            },
        );
        let document = |version: u64| {
            polar_signing::sign(
                serde_json::json!({
                    "type": "runtime", "id": format!("r-{version}"), "target": {"agent": "infra-revoked"},
                    "section": "repositories", "version": version, "body": {}
                }),
                std::slice::from_ref(&s.cert_pem),
                &s.key_pem,
            )
            .unwrap()
            .to_value()
        };

        // The first is accepted, and the history says whose certificate signed it.
        let outcome = rig
            .resources
            .configuration
            .submit(document(1))
            .await
            .unwrap();
        assert!(
            matches!(outcome, ApplyOutcome::Applied { .. }),
            "{outcome:?}"
        );
        let history = rig.resources.configuration.history().await.unwrap();
        let signer_text = history.last().unwrap().signer.clone().unwrap();
        let serial = signer_text
            .split("serial ")
            .nth(1)
            .unwrap()
            .trim_end_matches(')')
            .to_string();

        // The credentials agent says that certificate is revoked.
        let key = credentials_agent_common::authority_update::generate_key().unwrap();
        deliver_snapshot(
            &rig,
            &authority_snapshot(
                &ca,
                &key,
                &[AuthorityPayload {
                    sequence: 1,
                    version: 1,
                    body: AuthorityBody::Revoked {
                        serials: vec![serial],
                        compromised: Vec::new(),
                    },
                    authored_by: None,
                }],
            ),
            Some(CREDENTIALS),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;

        let outcome = rig
            .resources
            .configuration
            .submit(document(2))
            .await
            .unwrap();
        assert!(
            matches!(
                outcome,
                ApplyOutcome::Refused(Refusal::Unverified(Rejection::Revoked(_)))
            ),
            "{outcome:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_policy_from_the_credentials_agent_decides_who_may_change_a_section_before_the_certificate_does()
     {
        use crate::configuration::{ApplyOutcome, Refusal};
        use crate::signed::Rejection;
        use credentials_agent_common::authority_update::{AuthorityBody, AuthorityPayload};
        use polar_signing::testing::{ALICE_ACCOUNT_ID, Spec, root, signer};

        let ca = root("Polar Internal CA");
        let dir = tempfile::tempdir().unwrap();
        let ca_file = dir.path().join("ca.pem");
        std::fs::write(&ca_file, &ca.pem).unwrap();
        let rig = Rig::with_runtime(
            "infra-policy-first",
            &[("TLS_CA_CERT", ca_file.to_str().unwrap())],
            &INFRA_RUNTIME,
        )
        .await;
        // alice holds update-configuration only: the certificate does not admit her to a runtime section.
        let s = signer(
            &ca,
            Spec {
                not_after_year: 2090,
                ..Spec::default()
            },
        );
        let document = |version: u64| {
            polar_signing::sign(
                serde_json::json!({
                    "type": "runtime", "id": format!("r-{version}"), "target": {"agent": "infra-policy-first"},
                    "section": "repositories", "version": version, "body": {}
                }),
                std::slice::from_ref(&s.cert_pem),
                &s.key_pem,
            )
            .unwrap()
            .to_value()
        };
        let outcome = rig
            .resources
            .configuration
            .submit(document(1))
            .await
            .unwrap();
        assert!(
            matches!(
                outcome,
                ApplyOutcome::Refused(Refusal::Unverified(Rejection::Unauthorized(_)))
            ),
            "before any policy: {outcome:?}"
        );

        // The credentials agent sends a policy that lets alice change that section.
        let key = credentials_agent_common::authority_update::generate_key().unwrap();
        deliver_snapshot(
            &rig,
            &authority_snapshot(
                &ca,
                &key,
                &[AuthorityPayload {
                    sequence: 1,
                    version: 1,
                    body: AuthorityBody::Policy {
                        source: format!(
                            r#"permit(principal == Identity::"{ALICE_ACCOUNT_ID}", action == Action::"update-runtime", resource == Section::"infra-policy-first/repositories");"#
                        ),
                    },
                    authored_by: None,
                }],
            ),
            Some(CREDENTIALS),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        let outcome = rig
            .resources
            .configuration
            .submit(document(1))
            .await
            .unwrap();
        assert!(
            matches!(outcome, ApplyOutcome::Applied { .. }),
            "once policy says so: {outcome:?}"
        );
    }

    // -- asking for the configuration the scheduler holds -------------------------------

    #[tokio::test]
    async fn an_agent_asks_for_its_configuration_each_time_it_registers() {
        let rig = Rig::standard("infra-replay").await;
        let asked = |rig: &Rig| -> Vec<String> {
            rig.spawner
                .published
                .lock()
                .unwrap()
                .iter()
                .filter(|(topic, _)| topic == polar_scheduler_common::CONFIGURATION_REPLAY_TOPIC)
                .map(|(_, payload)| {
                    rkyv::from_bytes::<
                        polar_scheduler_common::ConfigurationReplayRequest,
                        rkyv::rancor::Error,
                    >(payload)
                    .unwrap()
                    .agent
                })
                .collect()
        };
        assert!(
            asked(&rig).is_empty(),
            "nothing is asked before it registers"
        );

        rig.registered().await;
        rig.settle().await;
        assert_eq!(asked(&rig), ["infra-replay"]);

        // A reconnect registers again and asks again: what the scheduler sent while it was away is
        // not otherwise replayed.
        rig.registered().await;
        rig.settle().await;
        assert_eq!(asked(&rig), ["infra-replay", "infra-replay"]);
    }

    // -- the funnel ----------------------------------------------------------------------

    /// The infrastructure follows the log filters, so an update to one says nothing of it going unfollowed, and an
    /// update to anything else does not reach the logging: where traces are sent is fixed when the exporter is built, so
    /// it is Static and not followed.
    #[tokio::test]
    async fn the_log_filters_are_followed_and_nothing_else_reaches_the_logging() {
        let rig = Rig::standard("infra-log-filters").await;
        assert_eq!(
            rig.resources
                .configuration
                .dynamic_settings_problems(&[&polar::logging::SECTION])
                .await
                .unwrap(),
            Vec::<String>::new()
        );
        let outcome = rig
            .resources
            .configuration
            .apply_unchecked(1, vec![("RUST_LOG".to_string(), "debug".to_string())])
            .await
            .unwrap();
        assert_eq!(
            outcome,
            crate::configuration::ApplyOutcome::Applied {
                changed: vec!["RUST_LOG".to_string()],
                notes: Vec::new(),
            }
        );
    }

    /// A witness's crypto actor co-signs only for the store its signed configuration pins: the infrastructure has it
    /// follow the pin, so a signed change reaches it, and the domain's handle co-signs through it.
    #[tokio::test]
    async fn a_witness_co_signs_for_the_store_its_signed_configuration_pins() {
        let dir = tempfile::tempdir().unwrap();
        let certificate = dir.path().join("cert.pem");
        let key = rcgen::KeyPair::generate().unwrap();
        std::fs::write(
            &certificate,
            rcgen::CertificateParams::new(vec!["attestation-agent.polar".to_string()])
                .unwrap()
                .self_signed(&key)
                .unwrap()
                .pem(),
        )
        .unwrap();
        let witness_key = dir.path().join("witness/witness-key.pem");
        let rig = Rig::new(
            "infra-witness",
            Duration::from_secs(20),
            &[
                ("TLS_CLIENT_CERT", certificate.to_str().unwrap()),
                ("POLAR_WITNESS_COSIGNING_KEY", witness_key.to_str().unwrap()),
            ],
            false,
        )
        .await;
        let witness = rig
            .resources
            .cosigning
            .clone()
            .expect("a witness is given its handle");
        assert!(rig.resources.checkpoints.is_none(), "and nothing else");
        let store = polar_crypto::checkpoints::CheckpointKey::open(
            &dir.path().join("store.pem"),
            "polar-git-server.polar",
        )
        .unwrap();
        let text = polar_log::checkpoint::Checkpoint {
            origin: "polar-git-server.polar/evidence".to_string(),
            size: 1,
            root: [2; 32],
        }
        .text();
        let refused = witness.cosign(text.clone()).await.unwrap_err();
        assert!(refused.contains("no store is pinned"), "{refused}");

        rig.resources
            .configuration
            .apply_unchecked(
                1,
                vec![(
                    "POLAR_ATTESTATION_WITNESSED_STORE".to_string(),
                    store.verifier_key(),
                )],
            )
            .await
            .unwrap();
        rig.settle().await;
        let (line, at) = witness.cosign(text.clone()).await.unwrap();
        polar_log::checkpoint::open_witnessed(
            &format!("{text}\n{}{line}", store.sign(&text).unwrap()),
            &polar_log::checkpoint::NoteVerifier::parse(&store.verifier_key()).unwrap(),
            &polar_log::checkpoint::NoteVerifier::parse(&witness.key().await.unwrap()).unwrap(),
            at,
        )
        .expect("a reader holding both pins takes it");
    }

    #[tokio::test(start_paused = true)]
    async fn the_resources_carry_the_snapshot_the_supervisor_holds() {
        let rig = Rig::standard("infra-config").await;
        // Declared by the health section, set in the rig's map: in the snapshot.
        assert_eq!(
            rig.resources
                .config
                .read(&polar_health::vars::CASSINI_DEADLINE_SECS)
                .unwrap(),
            100000
        );
        // Not declared by anything: refused, not read from wherever it might be.
        assert!(matches!(
            rig.resources
                .config
                .read(&polar_env::Optional::<String>::text(
                    "NOT_DECLARED",
                    "nothing declares this"
                )),
            Err(polar_env::ConfigError::Undeclared(_))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn the_resources_carry_a_live_configuration_that_refuses_to_change_the_health_invariants()
    {
        let rig = Rig::standard("infra-live-config").await;
        let configuration = &rig.resources.configuration;
        let name = polar_health::vars::CASSINI_DEADLINE_SECS.name();

        // It starts as the snapshot.
        assert_eq!(
            configuration
                .current()
                .await
                .unwrap()
                .read(&polar_health::vars::CASSINI_DEADLINE_SECS)
                .unwrap(),
            100000
        );
        // A health safety invariant is static: an update to it is refused by name and the value
        // in force is unchanged.
        let outcome = configuration
            .apply_unchecked(1, vec![(name.to_string(), "1".to_string())])
            .await
            .unwrap();
        let crate::configuration::ApplyOutcome::Refused(crate::configuration::Refusal::Invalid(
            problems,
        )) = outcome
        else {
            panic!("the health deadline must not be changeable at runtime");
        };
        assert!(problems.iter().any(|p| p.contains(name)), "{problems:?}");
        assert_eq!(
            configuration
                .current()
                .await
                .unwrap()
                .read(&polar_health::vars::CASSINI_DEADLINE_SECS)
                .unwrap(),
            100000
        );
    }

    /// An agent held at start (`held::stay_up`) is asked to try again on each configuration change, with the
    /// configuration in force: while its answer is no, the hold stays with the new message; once yes, the hold is
    /// released, the notice that the agent is ending goes to its work, which answers the shutdown itself, and it is not
    /// asked again.
    #[tokio::test(start_paused = true)]
    async fn a_held_agent_starts_its_work_when_an_update_mends_it_and_keeps_its_hold_until_then() {
        use polar_health::{HealthReason, HoldReason};

        /// Stands in for the work: counts the notices it is sent.
        struct Work;
        #[async_trait]
        impl Actor for Work {
            type Msg = ();
            type State = Arc<AtomicUsize>;
            type Arguments = Arc<AtomicUsize>;
            async fn pre_start(
                &self,
                _: ActorRef<()>,
                told: Arc<AtomicUsize>,
            ) -> Result<Arc<AtomicUsize>, ActorProcessingErr> {
                Ok(told)
            }
            async fn handle(
                &self,
                _: ActorRef<()>,
                _: (),
                told: &mut Arc<AtomicUsize>,
            ) -> Result<(), ActorProcessingErr> {
                told.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let rig = Rig::new("held-retry", Duration::from_secs(20), &[], false).await;
        let told = Arc::new(AtomicUsize::new(0));
        let (work, _) = Actor::spawn(None, Work, told.clone()).await.unwrap();
        let asked: Arc<Mutex<Vec<String>>> = Arc::default();
        let seen = asked.clone();
        let try_again: crate::held::TryAgain = Box::new(move |retry| {
            let work = work.clone();
            let filter = retry
                .config
                .read(&polar::logging::CONSOLE_FILTER)
                .unwrap_or_default();
            seen.lock().unwrap().push(filter.clone());
            Box::pin(async move {
                if filter == "debug" {
                    Ok(crate::held::WorkStarted::told(work, || ()))
                } else {
                    Err(format!("still wrong with {filter}"))
                }
            })
        });
        rig.resources
            .healthcheck
            .hold(HoldReason::Configuration, "wrong at start");
        let mut held = crate::held::HeldState::new(
            "held-retry".to_string(),
            HoldReason::Configuration,
            rig.resources.clone(),
            try_again,
        );
        let cell = rig.infra.get_cell();

        // An update that does not mend it: still held, with what the agent says now.
        rig.resources
            .configuration
            .apply_unchecked(1, vec![("RUST_LOG".to_string(), "info".to_string())])
            .await
            .unwrap();
        held.configuration_changed(cell.clone()).await;
        let report = rig.resources.healthcheck.report().await.unwrap();
        assert_eq!(report.status, crate::ReportStatus::Unhealthy);
        assert_eq!(report.reason, Some(HealthReason::Configuration));
        assert_eq!(report.message.as_deref(), Some("still wrong with info"));

        // One that mends it: the work starts, and the hold is released.
        rig.resources
            .configuration
            .apply_unchecked(2, vec![("RUST_LOG".to_string(), "debug".to_string())])
            .await
            .unwrap();
        held.configuration_changed(cell.clone()).await;
        let report = rig.resources.healthcheck.report().await.unwrap();
        assert_ne!(
            report.reason,
            Some(HealthReason::Configuration),
            "{report:?}"
        );
        assert!(!held.prepare_shutdown(), "the work answers the shutdown");
        rig.settle().await;
        assert_eq!(told.load(Ordering::SeqCst), 1, "the work is told");

        // Not asked again once the work runs.
        held.configuration_changed(cell).await;
        assert_eq!(*asked.lock().unwrap(), ["info", "debug"]);
    }

    static INFRA_REPOS: crate::runtime::RuntimeSection = crate::runtime::RuntimeSection {
        authority: crate::runtime::SectionAuthority::Runtime,
        name: "repositories",
        doc: "The repositories to observe.",
        body: "{}",
        validate: |_| Ok(()),
    };
    static INFRA_RUNTIME: [&crate::runtime::RuntimeSection; 1] = [&INFRA_REPOS];

    #[tokio::test(start_paused = true)]
    async fn a_runtime_document_for_a_section_the_agent_declared_reaches_it_through_the_router() {
        use polar_signing::testing::{Spec, root, signer};

        let ca = root("Polar Internal CA");
        let dir = tempfile::tempdir().unwrap();
        let ca_file = dir.path().join("ca.pem");
        std::fs::write(&ca_file, &ca.pem).unwrap();
        let rig = Rig::with_runtime(
            "infra-runtime",
            &[("TLS_CA_CERT", ca_file.to_str().unwrap())],
            &INFRA_RUNTIME,
        )
        .await;
        let s = signer(
            &ca,
            Spec {
                capabilities: vec!["c:update-runtime"],
                not_after_year: 2090,
                ..Spec::default()
            },
        );
        let document = polar_signing::sign(
            serde_json::json!({
                "type": "runtime", "id": "repos-1", "target": {"agent": "infra-runtime"},
                "section": "repositories", "version": 1,
                "body": {"repositories": [{"url": "https://example.org/r.git"}]}
            }),
            std::slice::from_ref(&s.cert_pem),
            &s.key_pem,
        )
        .unwrap()
        .to_value();
        let notification = polar_scheduler_common::ConfigurationNotification {
            agent: "infra-runtime".to_string(),
            document_json: document.to_string(),
        };
        rig.resources
            .router
            .send_message(polar_router::RouterMessage::Route(
                polar_router::IncomingMessage {
                    topic: polar_scheduler_common::configuration_topic("infra-runtime"),
                    payload: rkyv::to_bytes::<rkyv::rancor::Error>(&notification)
                        .unwrap()
                        .to_vec(),
                    published_by: None,
                    published_instance: None,
                    trace_ctx: None,
                },
            ))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let held = rig
            .resources
            .configuration
            .runtime("repositories")
            .await
            .unwrap()
            .expect("the section was replaced");
        assert_eq!(held.version, 1);
        assert_eq!(
            held.body["repositories"][0]["url"],
            "https://example.org/r.git"
        );

        // And an agent that declared nothing holds nothing, whoever signs.
        let bare = Rig::with_runtime(
            "infra-runtime-bare",
            &[("TLS_CA_CERT", ca_file.to_str().unwrap())],
            &[],
        )
        .await;
        let mut for_bare = document.clone();
        for_bare["payload"]["target"]["agent"] = serde_json::json!("infra-runtime-bare");
        // (Altering the payload breaks the signature, so it is refused earlier still; either way nothing
        // is held. The point is the declared agent above did hold it.)
        let outcome = bare.resources.configuration.submit(for_bare).await.unwrap();
        assert!(matches!(
            outcome,
            crate::configuration::ApplyOutcome::Refused(_)
        ));
        assert!(
            bare.resources
                .configuration
                .runtime("repositories")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn signed_configuration_is_checked_against_the_ca_the_agent_pins_and_refused_without_one()
    {
        use crate::configuration::{ApplyOutcome, Refusal};
        use crate::signed::Rejection;
        use polar_signing::testing::{Spec, root, signer};

        // An agent that pins a real CA accepts what that CA's signers sign, and the document goes on
        // to the configuration checks: HOST-style variables of the health section are static.
        let ca = root("Polar Internal CA");
        let dir = tempfile::tempdir().unwrap();
        let ca_file = dir.path().join("ca.pem");
        std::fs::write(&ca_file, &ca.pem).unwrap();
        let rig = Rig::new(
            "infra-signed",
            Duration::from_secs(20),
            &[("TLS_CA_CERT", ca_file.to_str().unwrap())],
            false,
        )
        .await;
        let s = signer(
            &ca,
            Spec {
                not_after_year: 2090,
                ..Spec::default()
            },
        );
        let name = polar_health::vars::CASSINI_DEADLINE_SECS.name();
        let document = polar_signing::sign(
            serde_json::json!({
                "type": "configuration",
                "id": "u",
                "target": {"agent": "infra-signed"},
                "version": 1,
                "changes": [{"name": name, "value": "1"}]
            }),
            std::slice::from_ref(&s.cert_pem),
            &s.key_pem,
        )
        .unwrap()
        .to_value();
        // The agent hears its own configuration topic through the real router, and the document goes to
        // the same checks.
        let notification = polar_scheduler_common::ConfigurationNotification {
            agent: "infra-signed".to_string(),
            document_json: document.to_string(),
        };
        rig.resources
            .router
            .send_message(polar_router::RouterMessage::Route(
                polar_router::IncomingMessage {
                    topic: polar_scheduler_common::configuration_topic("infra-signed"),
                    payload: rkyv::to_bytes::<rkyv::rancor::Error>(&notification)
                        .unwrap()
                        .to_vec(),
                    published_by: None,
                    published_instance: None,
                    trace_ctx: None,
                },
            ))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let history = rig.resources.configuration.history().await.unwrap();
        assert_eq!(history.len(), 1, "{history:?}");
        assert!(
            history[0].signer.is_some(),
            "it was verified, then refused for what it asks"
        );

        let outcome = rig
            .resources
            .configuration
            .submit(document.clone())
            .await
            .unwrap();
        // Verified (signature, signer, target), then refused for what it asks: a static variable.
        assert!(
            matches!(outcome, ApplyOutcome::Refused(Refusal::Invalid(_))),
            "{outcome:?}"
        );

        // And it says so on Cassini, for the scheduler to record: two documents have been handled (the
        // one that came over the router, and the one submitted), each refused for what it asks.
        let published = rig.spawner.published.lock().unwrap().clone();
        let outcomes: Vec<polar_scheduler_common::ConfigurationOutcome> = published
            .iter()
            .filter(|(topic, _)| topic == polar_scheduler_common::CONFIGURATION_OUTCOME_TOPIC)
            .map(|(_, payload)| {
                rkyv::from_bytes::<
                        polar_scheduler_common::ConfigurationOutcome,
                        rkyv::rancor::Error,
                    >(payload)
                    .unwrap()
            })
            .collect();
        assert_eq!(outcomes.len(), 2, "{outcomes:?}");
        assert!(
            outcomes
                .iter()
                .all(|o| o.agent == "infra-signed" && o.status == "invalid")
        );
        assert_eq!(outcomes[0].sequence + 1, outcomes[1].sequence);

        // An agent whose CA file is not there refuses the very same document, and says why.
        let rig = Rig::new(
            "infra-unpinned",
            Duration::from_secs(20),
            &[("TLS_CA_CERT", "/nonexistent/ca.pem")],
            false,
        )
        .await;
        assert_eq!(
            rig.resources.configuration.submit(document).await.unwrap(),
            ApplyOutcome::Refused(Refusal::Unverified(Rejection::NotConfigured))
        );
    }

    /// Notes the ids of the commands it was asked to run.
    struct Ran(Arc<Mutex<Vec<String>>>);

    #[async_trait]
    impl crate::command_actor::CommandHandler for Ran {
        async fn run(
            &self,
            request: crate::command_actor::CommandRequest,
        ) -> Result<String, String> {
            self.0.lock().unwrap().push(request.id);
            Ok("done".to_string())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_signed_command_reaches_its_handler_through_the_router_and_is_announced_and_refused_once_shutting_down()
     {
        use crate::command::{ArgSpec, CommandSpec, Delivery};
        use polar_scheduler_common::{CommandOutcome, command_topic};
        use polar_signing::testing::{Spec, root, signer};

        const PING: CommandSpec = CommandSpec {
            name: "ping",
            doc: "answers",
            args: &[] as &[ArgSpec],
            delivery: Delivery::Idempotent,
            exclusive: false,
            timeout: Duration::from_secs(5),
        };

        let ca = root("Polar Internal CA");
        let dir = tempfile::tempdir().unwrap();
        let ca_file = dir.path().join("ca.pem");
        std::fs::write(&ca_file, &ca.pem).unwrap();
        let ran = Arc::new(Mutex::new(Vec::new()));
        let rig = Rig::with_commands(
            "infra-commands",
            &[("TLS_CA_CERT", ca_file.to_str().unwrap())],
            vec![(PING, Arc::new(Ran(ran.clone())))],
        )
        .await;
        let s = signer(
            &ca,
            Spec {
                capabilities: vec!["c:run-command"],
                not_after_year: 2090,
                ..Spec::default()
            },
        );
        // The verifier reads the real clock, so the command is issued now.
        let issued = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let command = |id: &str| {
            polar_signing::sign(
                serde_json::json!({
                    "type": "command",
                    "id": id,
                    "target": {"agent": "infra-commands"},
                    "command": "ping",
                    "args": {},
                    "issued_at": issued,
                    "not_after": issued + 900
                }),
                std::slice::from_ref(&s.cert_pem),
                &s.key_pem,
            )
            .unwrap()
            .to_value()
        };
        let route = |rig: &Rig, document: serde_json::Value| {
            let payload = rkyv::to_bytes::<rkyv::rancor::Error>(
                &polar_scheduler_common::CommandNotification {
                    agent: "infra-commands".to_string(),
                    document_json: document.to_string(),
                },
            )
            .unwrap()
            .to_vec();
            rig.resources
                .router
                .send_message(polar_router::RouterMessage::Route(
                    polar_router::IncomingMessage {
                        topic: command_topic("infra-commands"),
                        payload,
                        published_by: None,
                        published_instance: None,
                        trace_ctx: None,
                    },
                ))
                .unwrap();
        };
        let announced = |rig: &Rig| -> Vec<CommandOutcome> {
            rig.spawner
                .published
                .lock()
                .unwrap()
                .iter()
                .filter(|(topic, _)| topic == polar_scheduler_common::COMMAND_OUTCOME_TOPIC)
                .map(|(_, payload)| {
                    rkyv::from_bytes::<CommandOutcome, rkyv::rancor::Error>(payload).unwrap()
                })
                .collect()
        };

        // Through the router to the actor, verified, run, and announced on Cassini.
        route(&rig, command("one"));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(*ran.lock().unwrap(), ["one"]);
        let statuses: Vec<String> = announced(&rig).into_iter().map(|o| o.status).collect();
        assert_eq!(statuses, ["accepted", "started", "succeeded"]);

        // Once the agent is told to shut down, nothing new is started, and that is announced too.
        rig.infra
            .cast(InfrastructureSupervisorMessage::BeginShutdown {
                reason: "a test".to_string(),
            })
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        route(&rig, command("two"));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(*ran.lock().unwrap(), ["one"], "the second never ran");
        let last = announced(&rig).pop().unwrap();
        assert_eq!(last.status, "refused");
        assert_eq!(last.id.as_deref(), Some("two"));
        assert!(
            last.detail[0].contains("shutting down"),
            "{:?}",
            last.detail
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_policy_from_the_credentials_agent_decides_who_may_run_a_command_before_the_certificate_does()
     {
        use crate::command::{ArgSpec, CommandSpec, Delivery};
        use credentials_agent_common::authority_update::{AuthorityBody, AuthorityPayload};
        use polar_scheduler_common::command_topic;
        use polar_signing::testing::{ALICE_ACCOUNT_ID, Spec, root, signer};

        const PING: CommandSpec = CommandSpec {
            name: "ping",
            doc: "answers",
            args: &[] as &[ArgSpec],
            delivery: Delivery::Idempotent,
            exclusive: false,
            timeout: Duration::from_secs(5),
        };
        let ca = root("Polar Internal CA");
        let dir = tempfile::tempdir().unwrap();
        let ca_file = dir.path().join("ca.pem");
        std::fs::write(&ca_file, &ca.pem).unwrap();
        let ran = Arc::new(Mutex::new(Vec::new()));
        let rig = Rig::with_commands(
            "infra-command-policy",
            &[("TLS_CA_CERT", ca_file.to_str().unwrap())],
            vec![(PING, Arc::new(Ran(ran.clone())))],
        )
        .await;
        // alice holds update-configuration, not run-command.
        let s = signer(
            &ca,
            Spec {
                not_after_year: 2090,
                ..Spec::default()
            },
        );
        let issued = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let run = |rig: &Rig, id: &str| {
            let document = polar_signing::sign(
                serde_json::json!({
                    "type": "command", "id": id, "target": {"agent": "infra-command-policy"},
                    "command": "ping", "args": {}, "issued_at": issued, "not_after": issued + 900
                }),
                std::slice::from_ref(&s.cert_pem),
                &s.key_pem,
            )
            .unwrap()
            .to_value();
            let payload = rkyv::to_bytes::<rkyv::rancor::Error>(
                &polar_scheduler_common::CommandNotification {
                    agent: "infra-command-policy".to_string(),
                    document_json: document.to_string(),
                },
            )
            .unwrap()
            .to_vec();
            rig.resources
                .router
                .send_message(polar_router::RouterMessage::Route(
                    polar_router::IncomingMessage {
                        topic: command_topic("infra-command-policy"),
                        payload,
                        published_by: None,
                        published_instance: None,
                        trace_ctx: None,
                    },
                ))
                .unwrap();
        };

        run(&rig, "before");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            ran.lock().unwrap().is_empty(),
            "the certificate alone does not admit her"
        );

        let key = credentials_agent_common::authority_update::generate_key().unwrap();
        deliver_snapshot(
            &rig,
            &authority_snapshot(
                &ca,
                &key,
                &[AuthorityPayload {
                    sequence: 1,
                    version: 1,
                    body: AuthorityBody::Policy {
                        source: format!(
                            r#"permit(principal == Identity::"{ALICE_ACCOUNT_ID}", action == Action::"run-command", resource == Command::"infra-command-policy/ping");"#
                        ),
                    },
                    authored_by: None,
                }],
            ),
            Some(CREDENTIALS),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        run(&rig, "after");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(*ran.lock().unwrap(), ["after"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_to_shut_down_tells_the_domain_supervisor_once() {
        let rig = Rig::standard("infra-begin").await;
        rig.begin("a test asked");
        rig.settle().await;
        assert_eq!(rig.events(), ["prepare_shutdown"]);
    }

    #[tokio::test(start_paused = true)]
    async fn every_further_trigger_is_ignored() {
        let rig = Rig::standard("infra-idempotent").await;
        rig.begin("first");
        rig.begin("second");
        rig.infra
            .cast(InfrastructureSupervisorMessage::Health(
                HealthVerdict::Rejuvenate,
            ))
            .unwrap();
        rig.infra
            .cast(InfrastructureSupervisorMessage::Health(
                HealthVerdict::Unhealthy("late".into()),
            ))
            .unwrap();
        rig.settle().await;
        assert_eq!(rig.events(), ["prepare_shutdown"], "exactly one");
    }

    #[tokio::test(start_paused = true)]
    async fn a_rejuvenation_verdict_starts_the_shutdown() {
        let rig = Rig::standard("infra-rejuvenate").await;
        rig.infra
            .cast(InfrastructureSupervisorMessage::Health(
                HealthVerdict::Rejuvenate,
            ))
            .unwrap();
        rig.settle().await;
        assert_eq!(rig.events(), ["prepare_shutdown"]);
    }

    #[tokio::test(start_paused = true)]
    async fn an_unhealthy_verdict_starts_the_shutdown() {
        let rig = Rig::standard("infra-unhealthy").await;
        rig.infra
            .cast(InfrastructureSupervisorMessage::Health(
                HealthVerdict::Unhealthy("the graph went dark".into()),
            ))
            .unwrap();
        rig.settle().await;
        assert_eq!(rig.events(), ["prepare_shutdown"]);
    }

    #[tokio::test(start_paused = true)]
    async fn the_real_health_actor_reaches_the_funnel_through_its_verdict_port() {
        // Cassini never connects, so the actor's own deadline (60 s) gives a
        // verdict at its third tick. Nothing here sends one by hand.
        let rig = Rig::new(
            "infra-end-to-end",
            Duration::from_secs(20),
            &[("POLAR_HEALTH_CASSINI_DEADLINE_SECS", "60")],
            false,
        )
        .await;

        tokio::time::sleep(Duration::from_secs(100)).await;
        assert_eq!(rig.events(), ["prepare_shutdown"]);

        // And the health actor stayed alive to keep the file fresh while draining.
        assert_eq!(
            rig.resources.healthcheck.as_actor_ref().get_status(),
            ActorStatus::Running
        );
        let file = rig._dir.path().join("health.json");
        let state: polar_health::HealthState =
            serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
        assert_eq!(state.phase, polar_health::HealthPhase::ShuttingDown);
    }

    // -- the handshake and the watchdog ---------------------------------------------------

    /// A client certificate, written to a file of `dir`, naming the pod `uid` as its instance or none.
    fn client_certificate(dir: &std::path::Path, uid: Option<&str>) -> String {
        let mut params = rcgen::CertificateParams::new(vec!["w.polar".to_string()]).unwrap();
        if let Some(uid) = uid {
            for name in [format!("i:uid:{uid}"), format!("i:pod:{uid}-pod")] {
                params
                    .subject_alt_names
                    .push(rcgen::SanType::URI(name.try_into().unwrap()));
            }
        }
        let pem = params
            .self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap()
            .pem();
        let path = dir.join(format!("client-{}.pem", uid.unwrap_or("one")));
        std::fs::write(&path, pem).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// docs/architecture/authority-model.md, "Multi-instance workloads": one pod of a multi-instance workload that
    /// shuts down cleanly tells the broker its session is done (the client's goodbye) before its client stops; a
    /// single-instance workload's drain leaves its session for its successor, as before.
    #[tokio::test]
    async fn a_clean_shutdown_ends_a_multi_instance_pod_s_session_and_only_its() {
        let dir = tempfile::tempdir().unwrap();
        for (uid, goodbyes) in [(Some("pod-a"), 1), (None, 0)] {
            let certificate = client_certificate(dir.path(), uid);
            assert_eq!(names_an_instance(&certificate), uid.is_some());
            let mut rig = Rig::new(
                &format!("infra-goodbye-{}", uid.unwrap_or("one")),
                Duration::from_secs(20),
                &[("TLS_CLIENT_CERT", certificate.as_str())],
                false,
            )
            .await;
            rig.begin("test");
            rig.settle().await;
            rig.infra
                .cast(InfrastructureSupervisorMessage::ProceedWithShutdown)
                .unwrap();
            let ended =
                tokio::time::timeout(Duration::from_secs(30), rig.done.take().unwrap()).await;
            assert!(ended.is_ok(), "the supervisor never ended");
            assert_eq!(
                rig.spawner.goodbyes.load(Ordering::SeqCst),
                goodbyes,
                "{uid:?}"
            );
            assert!(
                rig.exits().is_empty(),
                "a clean handshake needs no watchdog"
            );
        }
        assert!(!names_an_instance("/no/such/certificate.pem"));
    }

    #[tokio::test(start_paused = true)]
    async fn proceeding_stops_the_children_and_ends_the_supervisor() {
        let mut rig = Rig::standard("infra-proceed").await;
        rig.begin("test");
        rig.settle().await;
        rig.infra
            .cast(InfrastructureSupervisorMessage::ProceedWithShutdown)
            .unwrap();

        let ended = tokio::time::timeout(Duration::from_secs(30), rig.done.take().unwrap()).await;
        assert!(ended.is_ok(), "the supervisor never ended");

        assert_eq!(rig.resources.router.get_status(), ActorStatus::Stopped);
        assert_eq!(
            rig.resources.healthcheck.as_actor_ref().get_status(),
            ActorStatus::Stopped
        );
        assert_eq!(
            rig.resources.tcp_client.as_actor_ref().get_status(),
            ActorStatus::Stopped
        );
        // Stopping the health actor is expected now and must not start another
        // shutdown, as it used to.
        assert_eq!(rig.events(), ["prepare_shutdown"]);
        assert!(
            rig.exits().is_empty(),
            "a clean handshake needs no watchdog"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_proceed_is_harmless() {
        let mut rig = Rig::standard("infra-proceed-twice").await;
        rig.begin("test");
        rig.infra
            .cast(InfrastructureSupervisorMessage::ProceedWithShutdown)
            .unwrap();
        let _ = rig
            .infra
            .cast(InfrastructureSupervisorMessage::ProceedWithShutdown);
        let ended = tokio::time::timeout(Duration::from_secs(30), rig.done.take().unwrap()).await;
        assert!(ended.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn the_watchdog_exits_1_when_the_domain_supervisor_never_answers() {
        let rig = Rig::new("infra-watchdog", Duration::from_secs(20), &[], false).await;
        rig.begin("test");
        rig.settle().await;

        tokio::time::sleep(Duration::from_secs(19)).await;
        assert!(rig.exits().is_empty(), "not before the budget runs out");

        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(rig.exits(), [1], "exit 1, never 0");
    }

    #[tokio::test(start_paused = true)]
    async fn the_budget_is_the_one_the_agent_was_given() {
        let rig = Rig::new("infra-budget", Duration::from_secs(50), &[], false).await;
        rig.begin("test");
        tokio::time::sleep(Duration::from_secs(49)).await;
        assert!(rig.exits().is_empty());
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(rig.exits(), [1]);
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_running_on_a_timer_until_a_shutdown_begins() {
        let rig = Rig::standard("infra-no-watchdog").await;
        tokio::time::sleep(Duration::from_secs(600)).await;
        assert!(rig.exits().is_empty());
        assert!(rig.events().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn the_health_verdict_runs_the_whole_pipeline_to_the_watchdog() {
        let rig = Rig::new(
            "infra-whole-pipeline",
            Duration::from_secs(20),
            &[("POLAR_HEALTH_CASSINI_DEADLINE_SECS", "60")],
            false,
        )
        .await;
        // The verdict comes at the third tick (90 s); 100 s is 10 s into the budget.
        tokio::time::sleep(Duration::from_secs(100)).await;
        assert!(rig.exits().is_empty());
        // The domain supervisor never answers, so 20 s after the verdict: exit 1.
        tokio::time::sleep(Duration::from_secs(15)).await;
        assert_eq!(rig.exits(), [1]);
    }

    // -- an agent with no drain of its own ----------------------------------------------------

    /// A domain that asked only to be told is told, and the infrastructure proceeds by itself: nobody
    /// sends `ProceedWithShutdown`, and it ends well inside its budget, with no watchdog.
    #[tokio::test(start_paused = true)]
    async fn an_agent_told_only_is_told_and_not_waited_for() {
        let mut rig = Rig::told("infra-told-only", Told::Only).await;
        rig.begin("test");
        let ended = tokio::time::timeout(Duration::from_secs(15), rig.done.take().unwrap()).await;
        assert!(
            ended.is_ok(),
            "the infrastructure waited for a proceed nobody sends"
        );
        assert_eq!(rig.events(), ["prepare_shutdown"], "the agent is told");
        assert!(
            rig.exits().is_empty(),
            "no watchdog: it ended inside its 20 s budget"
        );
    }

    /// A domain that asked for nothing is not told, and the infrastructure ends without it.
    #[tokio::test(start_paused = true)]
    async fn an_agent_that_asked_for_nothing_is_not_told_and_not_waited_for() {
        let mut rig = Rig::told("infra-untold", Told::Not).await;
        rig.begin("test");
        let ended = tokio::time::timeout(Duration::from_secs(15), rig.done.take().unwrap()).await;
        assert!(
            ended.is_ok(),
            "the infrastructure waited for a proceed nobody sends"
        );
        assert!(rig.events().is_empty(), "{:?}", rig.events());
        assert!(rig.exits().is_empty(), "no watchdog");
    }

    /// A domain that drains is told and waited for: without its proceed the infrastructure does not end,
    /// and only the watchdog ends the process, at the budget.
    #[tokio::test(start_paused = true)]
    async fn an_agent_that_drains_is_told_and_waited_for() {
        let mut rig = Rig::told("infra-drains", Told::AndWaitedFor).await;
        rig.begin("test");
        let ended = tokio::time::timeout(Duration::from_secs(15), rig.done.take().unwrap()).await;
        assert!(ended.is_err(), "it ended without the domain's proceed");
        assert_eq!(rig.events(), ["prepare_shutdown"]);
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(rig.exits(), [1], "the watchdog, at its 20 s budget");
    }

    // -- children dying -----------------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn the_router_dying_starts_an_orderly_shutdown() {
        let rig = Rig::standard("infra-router-dies").await;
        rig.resources.router.kill();
        rig.settle().await;
        assert_eq!(rig.events(), ["prepare_shutdown"]);
    }

    #[tokio::test(start_paused = true)]
    async fn the_health_actor_dying_starts_an_orderly_shutdown() {
        let rig = Rig::standard("infra-health-dies").await;
        rig.resources.healthcheck.as_actor_ref().kill();
        rig.settle().await;
        assert_eq!(rig.events(), ["prepare_shutdown"]);
    }

    #[tokio::test(start_paused = true)]
    async fn the_cassini_client_ending_starts_an_orderly_shutdown_and_is_not_replaced() {
        // The client front keeps the connection up itself, so what ends here is the front,
        // which only happens when it cannot go on. The supervisor does not make another.
        let rig = Rig::standard("infra-tcp-ends").await;
        assert_eq!(rig.spawner.spawned.load(Ordering::SeqCst), 1);

        rig.resources.tcp_client.as_actor_ref().kill();
        rig.settle().await;

        assert_eq!(rig.events(), ["prepare_shutdown"]);
        assert_eq!(
            rig.spawner.spawned.load(Ordering::SeqCst),
            1,
            "no replacement"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_agent_that_reads_its_soft_state_is_given_a_state_actor_and_one_that_does_not_is_not()
     {
        let rig = Rig::with_state("infra-state").await;
        assert!(rig.resources.state.is_some());
        assert!(
            Rig::standard("infra-no-state")
                .await
                .resources
                .state
                .is_none()
        );
    }

    // -- a question about the configuration in force -----------------------------------------

    /// Answers on the topic where every agent answers, off the wire.
    fn running_answers(rig: &Rig) -> Vec<polar_scheduler_common::running::RunningConfiguration> {
        rig.spawner
            .published
            .lock()
            .unwrap()
            .iter()
            .filter(|(topic, _)| topic == polar_scheduler_common::running::ANSWERS_TOPIC)
            .map(|(_, payload)| polar_scheduler_common::running::decode_answer(payload).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn a_question_reaches_the_answer_through_the_one_topic_and_only_its_agent_answers() {
        use polar_scheduler_common::running::{QUESTIONS_TOPIC, question_payload};
        use polar_signing::testing::{ALICE_ACCOUNT_ID, Spec, root, signer};
        let ca = root("Polar Internal CA");
        let dir = tempfile::tempdir().unwrap();
        let ca_file = dir.path().join("ca.pem");
        std::fs::write(&ca_file, &ca.pem).unwrap();
        let rig = Rig::with_commands(
            "infra-asked",
            &[("TLS_CA_CERT", ca_file.to_str().unwrap())],
            vec![],
        )
        .await;
        rig.registered().await;
        rig.settle().await;
        let s = signer(&ca, Spec::default());
        let issued = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ask = |agent: &str, id: &str, stamp: Option<&str>| {
            let document = polar_signing::sign_in(
                polar_signing::Domain::RUNNING_CONFIGURATION_QUESTION,
                question_payload(agent, id, issued, issued + 60),
                std::slice::from_ref(&s.cert_pem),
                &s.key_pem,
            )
            .unwrap()
            .to_value();
            rig.resources
                .router
                .send_message(polar_router::RouterMessage::Route(
                    polar_router::IncomingMessage {
                        topic: QUESTIONS_TOPIC.to_string(),
                        payload: document.to_string().into_bytes(),
                        published_by: stamp.map(str::to_string),
                        published_instance: None,
                        trace_ctx: None,
                    },
                ))
                .unwrap();
        };
        ask("infra-asked", "mine", Some(ALICE_ACCOUNT_ID));
        ask("another-agent", "theirs", Some(ALICE_ACCOUNT_ID));
        ask("infra-asked", "unstamped", None);
        rig.settle().await;
        let answers = running_answers(&rig);
        assert_eq!(answers.len(), 1, "{answers:?}");
        assert_eq!(answers[0].id, "mine");
        assert_eq!(answers[0].agent, "infra-asked");
        assert!(!answers[0].settings.is_empty());
    }

    // -- pulled health -------------------------------------------------------------------

    /// The identity a rig's floor lets ask about its health.
    const RIG_WRITER: &str = "soft-state-processor.polar.serviceaccount.cluster.local";

    /// Asks the rig's agent about its health as `asker`, as the broker would deliver the question.
    fn ask_health(rig: &Rig, service: &str, asker: Option<&str>, round: &str) {
        rig.resources
            .router
            .send_message(polar_router::RouterMessage::Route(
                polar_router::IncomingMessage {
                    topic: polar_health::report::health_topic(service),
                    payload: polar_health::report::encode_query(&polar_health::HealthQuery {
                        correlation_id: round.to_string(),
                    }),
                    published_by: asker.map(str::to_string),
                    published_instance: None,
                    trace_ctx: None,
                },
            ))
            .unwrap();
    }

    /// The health answers the rig's agent published.
    fn answers(rig: &Rig) -> Vec<polar_health::HealthAnswer> {
        rig.spawner
            .published
            .lock()
            .unwrap()
            .iter()
            .filter(|(topic, _)| topic == polar_health::report::HEALTH_REPLIES_TOPIC)
            .map(|(_, payload)| polar_health::report::decode_answer(payload).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn the_writer_s_question_is_answered_with_the_health_actor_s_report_and_anyone_else_s_is_not()
     {
        let rig = Rig::standard("infra-health").await;
        rig.registered().await;
        rig.settle().await;
        ask_health(&rig, "infra-health", Some(RIG_WRITER), "round-1");
        ask_health(
            &rig,
            "infra-health",
            Some("kube-observer.polar.serviceaccount.cluster.local"),
            "round-2",
        );
        ask_health(&rig, "infra-health", None, "round-3");
        rig.settle().await;
        let answers = answers(&rig);
        assert_eq!(answers.len(), 1, "{answers:?}");
        assert_eq!(answers[0].correlation_id, "round-1");
        assert_eq!(
            answers[0].report.status,
            polar_health::ReportStatus::Healthy
        );
        assert!(answers[0].report.cassini_connected);
    }

    #[tokio::test]
    async fn a_held_configuration_problem_is_answered_and_never_ends_the_agent() {
        let rig = Rig::standard("infra-held").await;
        rig.registered().await;
        rig.resources.healthcheck.hold(
            polar_health::HoldReason::Configuration,
            "JIRA_URL is still the example placeholder",
        );
        rig.settle().await;
        ask_health(&rig, "infra-held", Some(RIG_WRITER), "round-1");
        rig.settle().await;
        let answers = answers(&rig);
        assert_eq!(answers.len(), 1);
        let report = &answers[0].report;
        assert_eq!(report.status, polar_health::ReportStatus::Unhealthy);
        assert_eq!(
            report.reason,
            Some(polar_health::HealthReason::Configuration)
        );
        assert_eq!(
            report.message.as_deref(),
            Some("JIRA_URL is still the example placeholder")
        );
        assert!(rig.events().is_empty(), "the agent was told to end");
        assert!(rig.exits().is_empty());

        // An agent that begins to end says it is draining.
        rig.begin("told to");
        rig.settle().await;
        ask_health(&rig, "infra-held", Some(RIG_WRITER), "round-2");
        rig.settle().await;
        let answers = self::answers(&rig);
        assert_eq!(
            answers.last().unwrap().report.status,
            polar_health::ReportStatus::Draining
        );
    }

    /// docs/plans/crypto-actor.md: every agent has a crypto actor, encrypting or not, linked to the infrastructure (its end
    /// ends the agent); one that does not encrypt is not handed it.
    #[tokio::test]
    async fn every_agent_has_a_crypto_actor_and_one_that_does_not_encrypt_is_not_handed_it() {
        let rig = Rig::new("infra-plain-crypto", Duration::from_secs(20), &[], false).await;
        assert!(rig.resources.crypto.is_none());
        let crypto: Vec<_> = rig
            .infra
            .get_children()
            .into_iter()
            .filter(|child| child.is_message_type_of::<polar_crypto::CryptoMessage>() == Some(true))
            .collect();
        assert_eq!(crypto.len(), 1, "one crypto actor");
        assert!(
            crypto[0].get_name().is_none(),
            "unnamed: nothing finds it by name"
        );
        crypto[0].kill();
        rig.settle().await;
        assert_eq!(rig.events(), ["prepare_shutdown"]);
    }

    #[tokio::test]
    async fn the_crypto_actor_dying_starts_an_orderly_shutdown() {
        let rig = Rig::with_crypto("infra-crypto-dies").await;
        let crypto = rig
            .resources
            .crypto
            .clone()
            .expect("an encrypting agent has one");
        crypto.actor().kill();
        rig.settle().await;
        assert_eq!(rig.events(), ["prepare_shutdown"]);
    }

    // docs/architecture/key-custody.md, "Workload signing keys", item 4, and docs/plans/crypto-actor.md: an agent with the
    // `signing` capability is given a signer handle, one without none; it reaches the crypto actor, which a signing agent
    // has whether it encrypts or not, and whose end ends the agent. One that only signs is not handed the crypto actor.
    #[tokio::test]
    async fn an_agent_that_signs_is_given_a_signer_and_its_end_ends_the_agent() {
        let plain = Rig::with_crypto("infra-no-signer").await;
        assert!(plain.resources.signer.is_none());
        let rig = Rig::with_signer("infra-signer-dies").await;
        let signer = rig
            .resources
            .signer
            .clone()
            .expect("a signing agent has one");
        assert!(
            rig.resources.crypto.is_none(),
            "an agent that only signs is not handed the crypto actor"
        );
        assert!(
            signer.actor().get_name().is_none(),
            "unnamed: nothing finds it by name"
        );
        signer.actor().kill();
        rig.settle().await;
        assert_eq!(rig.events(), ["prepare_shutdown"]);
    }

    // docs/plans/crypto-actor.md: an agent with the `record-key` capability, which custody holds no signing key for, is
    // given a signer and a record-key handle that reach its crypto actor; it signs nothing until the key is certified
    // through the handle, and then the record types its certificate names. One that signs with custody has no handle.
    #[tokio::test]
    async fn an_agent_with_a_record_key_has_it_certified_and_signs_with_it_through_its_crypto_actor()
     {
        use crate::signer::{EvidenceRecord, RecordSigner, SignError};
        let custody = Rig::with_signer("infra-signer-custody").await;
        assert!(custody.resources.record_key.is_none());
        let rig = Rig::with_record_key("infra-record-key").await;
        let signer = rig
            .resources
            .signer
            .clone()
            .expect("a signing agent has one");
        let key = rig
            .resources
            .record_key
            .clone()
            .expect("an agent with a record key has its handle");
        let revocation = || EvidenceRecord::new("revocation", serde_json::Map::new()).unwrap();
        assert!(matches!(
            signer.sign(revocation()).await,
            Err(SignError::Unavailable(_))
        ));
        let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let issuer = rcgen::Issuer::new(ca, ca_key);
        let mut csr =
            rcgen::CertificateSigningRequestParams::from_pem(&key.csr().await.unwrap()).unwrap();
        csr.params.subject_alt_names.push(rcgen::SanType::URI(
            "c:record-evidence:revocation".try_into().unwrap(),
        ));
        csr.params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::Other(
            cert_issuer_common::OID_DOCUMENT_SIGNING.to_vec(),
        )];
        let chain = csr.signed_by(&issuer).unwrap().pem();
        key.keep(chain).await.unwrap();
        let document = signer.sign(revocation()).await.unwrap();
        assert_eq!(document.payload["type"], "revocation");
        assert!(matches!(
            signer
                .sign(EvidenceRecord::new("attestation", serde_json::Map::new()).unwrap())
                .await,
            Err(SignError::Refused(_))
        ));
    }

    // -- the graph controller -----------------------------------------------------------------

    /// What a writer's controller is started with, reaching `settings`.
    fn writer(settings: polar::graph::environment::GraphSettings) -> crate::graph::GraphSetup {
        crate::graph::GraphSetup {
            uses: crate::graph::GraphUse::Writes,
            settings,
            key_indexes: Vec::new(),
            repairs: Vec::new(),
        }
    }

    /// A graph nobody answers at, for a test that writes nothing.
    fn nowhere() -> polar::graph::environment::GraphSettings {
        polar::graph::environment::GraphSettings {
            database: "neo4j".to_string(),
            user: "neo4j".to_string(),
            password: "unused".to_string(),
            endpoint: "bolt://127.0.0.1:1".to_string(),
            tls: polar::graph::environment::GraphTls::None,
        }
    }

    #[tokio::test]
    async fn an_agent_that_needs_the_graph_is_given_a_controller_and_one_that_does_not_is_not() {
        let graph = Rig::with_graph("infra-graph-given", writer(nowhere())).await;
        assert!(graph.resources.graph.is_some());
        let plain = Rig::standard("infra-graph-none").await;
        assert!(plain.resources.graph.is_none());
    }

    #[tokio::test]
    async fn the_graph_controller_dying_starts_an_orderly_shutdown() {
        let rig = Rig::with_graph("infra-graph-dies", writer(nowhere())).await;
        let graph = rig.resources.graph.clone().expect("a graph agent has one");
        graph.actor().kill();
        rig.settle().await;
        assert_eq!(rig.events(), ["prepare_shutdown"]);
    }

    /// What the domain handed the graph before it proceeded is written before the infrastructure ends, and nothing is
    /// taken after: the controller drains first (`graph::GRAPH_DRAIN`), against a real Neo4j.
    #[tokio::test]
    async fn proceeding_writes_what_the_agent_handed_the_graph_and_takes_no_more() {
        use polar::graph::controller::{DynamicNodeKey, GraphOp};
        const LABEL: &str = "ProceedProbe";
        const HANDED: usize = 200;
        let probe = |i: usize| GraphOp::UpsertNode {
            key: Box::new(DynamicNodeKey::new(LABEL, "id", i.to_string()).unwrap()),
            props: Vec::new(),
        };

        let store = polar_test_graph::neo4j();
        let _runtime = polar_test_graph::enter();
        polar_test_graph::clear_graph(store).await;
        let c = polar_test_graph::connection();
        let mut rig = Rig::with_graph(
            "infra-graph-drains",
            writer(polar::graph::environment::GraphSettings {
                database: "neo4j".to_string(),
                user: c.user,
                password: c.password,
                endpoint: c.bolt,
                tls: polar::graph::environment::GraphTls::None,
            }),
        )
        .await;
        let graph = rig.resources.graph.clone().expect("a graph agent has one");

        graph.write_all((0..HANDED).map(probe)).unwrap();
        rig.begin("test");
        rig.infra
            .cast(InfrastructureSupervisorMessage::ProceedWithShutdown)
            .unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(60), rig.done.take().unwrap()).await;
        assert!(ended.is_ok(), "the supervisor never ended");

        let written = polar_test_graph::dump(store)
            .await
            .into_iter()
            .filter(|line| line.contains(LABEL))
            .count();
        assert_eq!(written, HANDED, "everything handed over is in the graph");
        assert!(
            graph.write(probe(HANDED)).is_err(),
            "a write after the end is refused"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_client_is_started_with_the_snapshots_coordinates() {
        // The rig's process has no BROKER_ADDR; the snapshot is built from a map that does.
        let rig = Rig::standard("infra-tcp-config").await;
        let configs = rig.spawner.configs.lock().unwrap().clone();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].broker_endpoint, "cassini:8080");
        assert_eq!(configs[0].server_name, "cassini.local");
        assert_eq!(configs[0].client_certificate_path, "/c/cert.pem");
    }

    #[tokio::test(start_paused = true)]
    async fn children_ending_during_the_drain_change_nothing() {
        let rig = Rig::standard("infra-drain-deaths").await;
        rig.begin("test");
        rig.settle().await;

        rig.resources.router.kill();
        rig.resources.tcp_client.as_actor_ref().kill();
        rig.settle().await;

        assert_eq!(rig.events(), ["prepare_shutdown"], "no second event");
        assert_eq!(
            rig.spawner.spawned.load(Ordering::SeqCst),
            1,
            "no replacement"
        );
        assert_eq!(
            rig.infra.get_status(),
            ActorStatus::Running,
            "still up for the drain"
        );
    }

    // -- signals ---------------------------------------------------------------------------------

    /// Real signals belong to the whole process, so only one test installs a
    /// listener, and it cannot overlap another rig.
    #[tokio::test]
    async fn sigterm_starts_an_orderly_shutdown() {
        let rig = Rig::new("infra-sigterm", Duration::from_secs(20), &[], true).await;
        // Give the listener task time to register its handler.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(rig.events().is_empty());

        // SAFETY: raising a signal that the listener above has a handler for.
        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
        for _ in 0..50 {
            if !rig.events().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(rig.events(), ["prepare_shutdown"]);

        // A second one, as Kubernetes sends when it grows impatient, is ignored.
        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(rig.events(), ["prepare_shutdown"]);
    }

    // -- the self-test -----------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn the_policy_actor_is_found_by_the_name_of_the_service() {
        let rig = Rig::standard("infra-registered-policy").await;
        let found = crate::authority::PolicyLookup::for_service("infra-registered-policy")
            .actor()
            .expect("the infrastructure registers the policy actor under the service name");
        assert_eq!(found.get_id(), rig.resources.authority.policy().get_id());
    }

    #[tokio::test(start_paused = true)]
    async fn an_agent_that_hears_its_probes_stays_connected() {
        let rig = Rig::self_testing("selftest-hearing", true).await;
        rig.registered().await;
        tokio::time::sleep(Duration::from_secs(600)).await;
        assert!(rig.health().cassini_connected, "{:?}", rig.health());
    }

    #[tokio::test(start_paused = true)]
    async fn an_agent_registered_but_deaf_reports_its_connection_lost() {
        let rig = Rig::self_testing("selftest-deaf", false).await;
        rig.registered().await;
        // Past the timeout, with room for the health actor's own tick to write the file.
        tokio::time::sleep(Duration::from_secs(120)).await;
        let health = rig.health();
        assert!(!health.cassini_connected, "{health:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn an_agent_without_the_self_test_is_not_judged_by_silence() {
        let rig = Rig::standard("selftest-off").await;
        rig.registered().await;
        tokio::time::sleep(Duration::from_secs(600)).await;
        assert!(rig.health().cassini_connected, "{:?}", rig.health());
    }

    #[test]
    fn the_probe_topic_has_no_colon_in_it() {
        // The broker names a subscription `{session}:{topic}` and splits it at the first colon;
        // a service named `jira:observer:web_client`, as the Jira observer once was, still gets one.
        assert_eq!(
            self_test_topic("jira:observer:web_client"),
            "selftest.jira-observer-web_client"
        );
        assert_eq!(
            self_test_topic("credentials-agent"),
            "selftest.credentials-agent"
        );
    }

    #[test]
    fn a_probe_is_recognised_only_by_the_instance_that_sent_it() {
        let ours = [1u8; 16];
        let theirs = [2u8; 16];
        assert_eq!(probe_number(&ours, &probe_payload(&ours, 7)), Some(7));
        assert_eq!(probe_number(&ours, &probe_payload(&theirs, 7)), None);
        assert_eq!(probe_number(&ours, b"short"), None);
    }
}

/// A service that is not a Cassini client: the same funnel, the health actor and the watchdog,
/// with no router, client or crypto.
#[cfg(test)]
mod service_tests {
    use super::*;
    use ractor::ActorStatus;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct ServiceRig {
        infra: ActorRef<InfrastructureSupervisorMessage>,
        done: Option<ractor::concurrency::JoinHandle<()>>,
        service: crate::ServiceResources,
        events: Arc<Mutex<Vec<String>>>,
        exits: Arc<Mutex<Vec<i32>>>,
        dir: tempfile::TempDir,
    }

    impl ServiceRig {
        async fn new(budget: Duration, health_env: &[(&str, &str)]) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let vars: HashMap<String, String> = [(
                "POLAR_HEALTH_FILE",
                dir.path().join("health.json").to_str().unwrap(),
            )]
            .into_iter()
            .chain(health_env.iter().copied())
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
            // No Cassini capability: a service is not a client.
            let startup = crate::startup::prepare(&vars, &[], &[], None).unwrap();
            let exits = Arc::new(Mutex::new(Vec::new()));
            let recorded = exits.clone();
            let events = Arc::new(Mutex::new(Vec::new()));
            let (infra, done) = Actor::spawn(
                None,
                InfrastructureSupervisor,
                InfrastructureSupervisorArgs {
                    crypto: None,
                    service_name: "a-service".to_string(),
                    health_check_args: HealthCheckArgs::new(false, 300, vec![])
                        .with_config(startup.health),
                    config: startup.config,
                    subscriptions: vec![],
                    wants_crypto: false,
                    wants_signer: false,
                    state_agent: None,
                    health_writer: None,
                    with_client: false,
                    shutdown_budget: budget,
                    listen_for_signals: false,
                    process_exit: Arc::new(move |code| recorded.lock().unwrap().push(code)),
                    tcp_spawner: Arc::new(CassiniSpawner::default()),
                    commands: vec![],
                    runtime_sections: &[],
                    protocols: crate::protocol::ProtocolSetup::default(),
                    workers: Vec::new(),
                    section_judge: None,
                    settings_judge: None,
                    self_test: false,
                    graph: None,
                    notice: Some(ShutdownNotice {
                        tell: {
                            let events = events.clone();
                            Arc::new(move || {
                                events.lock().unwrap().push("prepare_shutdown".to_string())
                            })
                        },
                        wait: true,
                    }),
                },
            )
            .await
            .unwrap();
            let service = ractor::call!(infra, |reply| {
                InfrastructureSupervisorMessage::GetService { reply }
            })
            .unwrap();
            Self {
                infra,
                done: Some(done),
                service,
                events,
                exits,
                dir,
            }
        }

        async fn settle(&self) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_service_has_no_cassini_client_and_says_so() {
        let rig = ServiceRig::new(Duration::from_secs(20), &[]).await;
        let resources = ractor::call!(rig.infra, |reply| {
            InfrastructureSupervisorMessage::GetResources { reply }
        })
        .unwrap();
        assert!(resources.is_none(), "no router, client or crypto to give");
    }

    #[tokio::test(start_paused = true)]
    async fn a_service_is_not_failed_for_a_connection_it_never_makes() {
        // An agent that never connects is ended at its Cassini deadline. A service has nothing
        // to connect to, so the health actor is told it is connected and never gives that verdict.
        let rig = ServiceRig::new(
            Duration::from_secs(20),
            &[("POLAR_HEALTH_CASSINI_DEADLINE_SECS", "60")],
        )
        .await;
        tokio::time::sleep(Duration::from_secs(200)).await;
        assert!(
            rig.events.lock().unwrap().is_empty(),
            "no verdict, no shutdown"
        );
        assert_eq!(
            rig.service.healthcheck.as_actor_ref().get_status(),
            ActorStatus::Running
        );
        // And it is keeping its health file, which is what the probe reads.
        assert!(rig.dir.path().join("health.json").exists());
    }

    #[tokio::test(start_paused = true)]
    async fn a_health_verdict_tells_the_service_once() {
        let rig = ServiceRig::new(Duration::from_secs(20), &[]).await;
        for verdict in [
            HealthVerdict::Rejuvenate,
            HealthVerdict::Unhealthy("late".into()),
        ] {
            rig.infra
                .cast(InfrastructureSupervisorMessage::Health(verdict))
                .unwrap();
        }
        rig.settle().await;
        assert_eq!(*rig.events.lock().unwrap(), ["prepare_shutdown"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_service_asking_to_end_goes_through_the_same_funnel() {
        // A shutdown requested over the wire, as the broker's control manager does.
        let rig = ServiceRig::new(Duration::from_secs(20), &[]).await;
        rig.infra
            .cast(InfrastructureSupervisorMessage::BeginShutdown {
                reason: "asked over the wire".into(),
            })
            .unwrap();
        rig.settle().await;
        assert_eq!(*rig.events.lock().unwrap(), ["prepare_shutdown"]);
    }

    #[tokio::test(start_paused = true)]
    async fn the_watchdog_ends_a_service_that_never_finishes_draining() {
        let rig = ServiceRig::new(Duration::from_secs(20), &[]).await;
        rig.infra
            .cast(InfrastructureSupervisorMessage::BeginShutdown {
                reason: "test".into(),
            })
            .unwrap();
        rig.settle().await;
        tokio::time::sleep(Duration::from_secs(19)).await;
        assert!(rig.exits.lock().unwrap().is_empty());
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(*rig.exits.lock().unwrap(), [1]);
    }

    #[tokio::test(start_paused = true)]
    async fn proceeding_ends_the_service_infrastructure() {
        let mut rig = ServiceRig::new(Duration::from_secs(20), &[]).await;
        rig.infra
            .cast(InfrastructureSupervisorMessage::BeginShutdown {
                reason: "test".into(),
            })
            .unwrap();
        rig.settle().await;
        rig.infra
            .cast(InfrastructureSupervisorMessage::ProceedWithShutdown)
            .unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(30), rig.done.take().unwrap()).await;
        assert!(ended.is_ok(), "the supervisor never ended");
        assert_eq!(
            rig.service.healthcheck.as_actor_ref().get_status(),
            ActorStatus::Stopped
        );
        assert!(rig.exits.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn the_health_actor_dying_ends_a_service_in_order() {
        let rig = ServiceRig::new(Duration::from_secs(20), &[]).await;
        rig.service.healthcheck.as_actor_ref().kill();
        rig.settle().await;
        assert_eq!(*rig.events.lock().unwrap(), ["prepare_shutdown"]);
    }
}
