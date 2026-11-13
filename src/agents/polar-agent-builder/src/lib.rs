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

//! polar-agent-builder
//!
//! The real, shared, foundational sequencing every agent's own
//! pre_start has, so far, hand-rolled separately: spawn
//! HealthCheckActor, spawn RouterActor, register this agent's own
//! topics with it, spawn TcpClient via spawn_with_router sharing
//! that same router, and (optionally) spawn CryptoActor sharing both.
//! kube-consumer's own, real supervisor.rs and credentials-agent's
//! own supervisor.rs both, independently, contain a near-identical,
//! real version of this exact sequence today.
//!
//! Zero-trust by construction, not by convention: a Subscription
//! binds "register this topic with the router" and "genuinely
//! subscribe to it on the wire once connected" into one, real,
//! atomic unit -- there is no code path through this crate that
//! registers a topic without also, automatically, subscribing to it,
//! or vice versa. build() itself is the one, sole, real orchestrator;
//! nothing it produces can exist in a half-wired state.
// Reading the process environment goes through polar-env (see clippy.toml).
#![deny(clippy::disallowed_methods)]

pub mod agent;
pub mod authority;
pub use agent::{Configured, PolarAgent, StartError, run};
pub use authority::{LookupError, PolicyLookup};
pub mod capability;
pub use capability::Capability;
pub mod configuration;
pub use configuration::{ConfigChanged, ConfigurationHandle};
pub mod command;
pub use command::{ArgKind, ArgSpec, CommandSpec, CommandVerifier, Delivery, VerifiedCommand};
pub mod command_actor;
pub use command_actor::{CommandHandle, CommandHandler, CommandRequest};
pub mod crypto;
pub mod environment;
pub mod floor;
pub use crypto::{CryptoClient, CryptoError, CryptoHandle, Zeroizing};
pub use floor::Floor;
pub mod graph;
pub mod graph_schema;
pub use graph::{Drain, GRAPH_DRAIN, GraphClosed, GraphHandle, GraphUse};
pub use graph_schema::{EdgeDecl, GraphAccess, GraphDecl};
pub mod health;
pub use health::{HealthClient, HealthHandle};
pub mod health_query;
pub mod held;
/// What a domain reports a standing problem with ([`HealthHandle::hold`]), and what an agent says when it is asked
/// about its health.
pub use polar_health::{HealthReason, HealthReport, HoldReason, ReportStatus};
pub mod infrastructure;
pub mod landlock;
pub mod lock;
pub use infrastructure::{InfrastructureSupervisor, InfrastructureSupervisorMessage};
pub mod message;
pub use message::{Encrypted, Outbound, Plaintext};
pub mod policy_authority;
pub mod protocol;
pub mod role;
pub use role::Role;
pub mod running;
pub mod runtime;
pub use runtime::{RuntimeChanged, RuntimeSection, RuntimeValue};
pub mod selftest;
pub mod shutdown;
pub mod signer;
pub use signer::{EvidenceRecord, RecordSigner, SignError, SignerHandle};
pub mod state;
pub use state::{SoftValue, StateClient, StateError, StateHandle, StateQuery};
pub mod signed;
mod start_marker;
pub use signed::{Rejection, UpdateVerifier};
pub(crate) mod own_name;
pub(crate) mod startup;
pub mod topic_gate;
pub mod topics;
pub mod worker;
pub use shutdown::{DEFAULT_SHUTDOWN_BUDGET, SHUTDOWN_BUDGET_ENV};
pub use topics::{Access, Cause, TopicDecl, TopicSet};

use cassini_client::TcpClientMessage;
use cassini_types::ClientEvent;
use polar::cassini::TcpClient;
use polar_health::HealthCheckArgs;
use ractor::{Actor, ActorProcessingErr, ActorRef};
use std::sync::Arc;

/// Binds a topic to the real, per-message deliver closure RouterActor
/// itself already expects -- exactly the same shape every existing,
/// hand-rolled `register_kube_topics`-style function already builds.
/// A real, atomic unit of intent: "I want this topic's messages,"
/// covering both the in-process router-registration half and the
/// real, wire-level Subscribe half together.
pub struct Subscription {
    pub topic: String,
    pub deliver: Box<dyn Fn(polar_router::IncomingMessage) + Send + Sync>,
}

impl Subscription {
    pub fn new(
        topic: impl Into<String>,
        deliver: impl Fn(polar_router::IncomingMessage) + Send + Sync + 'static,
    ) -> Self {
        Self {
            topic: topic.into(),
            deliver: Box::new(deliver),
        }
    }
}

/// The real, complete set of resources a successful build() produces
/// -- everything an agent's own pre_start needs to finish its own,
/// remaining, genuinely agent-specific wiring (spawning its own
/// domain actors, e.g. a graph controller). Every real handle here
/// is trait-based (HealthHandle, CryptoHandle), not a raw ActorRef --
/// the whole, real point of this crate is that an agent's own code
/// should never need to touch ractor primitives directly at all.
/// router and tcp_client remain genuinely, deliberately raw: they're
/// this crate's own, real, foundational building blocks, not
/// something a higher-level, trait-based wrapper genuinely adds value
/// over for every, real caller's own use.
///
/// healthcheck is never Option -- InfrastructureSupervisor's own
/// shutdown-coordination mechanism structurally depends on a real
/// HealthCheckActor existing, so build() always spawns one. Its
/// configuration is derived from the capabilities this agent
/// requires and from the deployment's own environment
/// (POLAR_HEALTH_DEP_ENDPOINTS and the other POLAR_HEALTH_* variables
/// HealthCheckActor already reads), not passed in by the agent.
#[derive(Clone)]
pub struct AgentResources {
    pub router: ActorRef<polar_router::RouterMessage>,
    pub tcp_client: TcpClient,
    pub healthcheck: crate::health::HealthHandle,
    pub crypto: Option<crate::crypto::CryptoHandle>,
    /// The agent's TLS, from its own keys: every TLS configuration it uses comes from here (docs/plans/crypto-actor.md).
    pub tls: crate::crypto::TlsHandle,
    /// What the agent signs its evidence records with, for one with the `signing` capability ([`signer`]).
    pub signer: Option<crate::signer::SignerHandle>,
    /// The agent's way to the outside, for one that declares operations or credentials ([`protocol::ProtocolHandle`]).
    pub protocols: Option<protocol::ProtocolHandle>,
    /// The agent's way to its own soft state, for an agent with the `soft-state` capability (it declares a graph
    /// read): see [`state::StateClient`].
    pub state: Option<crate::state::StateHandle>,
    /// The agent's workers, by name, each locked as seccomp's strict mode locks a process (`PolarAgent::WORKERS`; [`worker`]).
    pub workers: crate::worker::Workers,
    /// The agent's way to its graph controller, for one that needs `graph-write` or `graph-read` ([`graph`]). The
    /// infrastructure starts it, reports its signals to the health actor and drains it at the end.
    pub graph: Option<crate::graph::GraphHandle>,
    /// Every real ClientEvent this agent's own TcpClient produces --
    /// subscribe with your own, real mapping closure, exactly the
    /// same, established pattern as prepare_shutdown_port/
    /// graph_signal_port.
    pub events_output: Arc<ractor::OutputPort<ClientEvent>>,
    /// The real, direct way to send
    /// infrastructure::InfrastructureSupervisorMessage::ProceedWithShutdown
    /// once your own, domain-specific children have genuinely, fully
    /// shut down.
    pub infrastructure: ActorRef<crate::infrastructure::InfrastructureSupervisorMessage>,
    /// The one snapshot of the environment the builder took: the variables the builder, its
    /// components and this agent declared, and nothing else. Read a declared variable with
    /// `config.read(&VAR)`; one nobody declared is refused.
    pub config: Arc<polar_env::Config>,
    /// The same configuration, live: it takes versioned updates to the variables the code
    /// declared `Dynamic`, and tells subscribers when one changes. `config` above stays the
    /// startup snapshot; read `configuration.current()` for what is in force now.
    pub configuration: crate::configuration::ConfigurationHandle,
    /// What the credentials agent says about policy, groups and revoked certificates, kept current: the
    /// policy and permissions actors to decide with, and a port that announces when it changes.
    pub authority: crate::authority::AuthorityHandle,
}

pub struct AgentBuilder<M: ractor::Message> {
    myself: ActorRef<M>,
    service_name: String,
    subscriptions: Vec<Subscription>,
    requires: Vec<Capability>,
    map_lifecycle_event: Option<Box<dyn Fn(ClientEvent) -> Option<M> + Send + Sync>>,
    wants_crypto: bool,
    /// Start a state actor (the `soft-state` capability).
    wants_state: bool,
    self_test: bool,
    shutdown_budget: Option<std::time::Duration>,
    environment: Vec<&'static polar_env::Section>,
    /// The handlers the agent registered, by the command each runs.
    commands: Vec<(&'static str, Arc<dyn CommandHandler>)>,
    /// What the agent declared it accepts (`PolarAgent::COMMANDS`).
    declared_commands: &'static [CommandSpec],
    /// The runtime sections the agent declared (`PolarAgent::RUNTIME`).
    declared_runtime: &'static [&'static RuntimeSection],
    /// The operations and credentials the agent declared (`PolarAgent::OPERATIONS`, `PolarAgent::CREDENTIALS`).
    declared_protocols: protocol::ProtocolSetup,
    /// The workers `run` forked, for the infrastructure to supervise.
    declared_workers: Vec<worker::Forked>,
    /// The agent's judge of a runtime section before it is replaced ([`with_section_judge`](Self::with_section_judge)).
    section_judge: Option<Arc<dyn runtime::SectionJudge>>,
    /// The agent's judge of its settings as a whole (`PolarAgent::SETTINGS_JUDGE`).
    settings_judge: Option<configuration::SettingsJudge>,
    /// The agent's topics, from `PolarAgent`; with them the client checks each publish and subscribe.
    topics: Option<Arc<topics::TopicSet>>,
    /// How the graph controller the infrastructure starts serves the agent, if it starts one, with the constraints
    /// and repairs it makes at the first contact with the graph (from `PolarAgent`).
    graph: Option<graph::GraphUse>,
    graph_key_indexes: Vec<polar::graph::schema::KeyIndex>,
    graph_repairs: &'static [polar::graph::repair::Repair],
    /// How the domain is told the agent is to end, and whether it is waited for ([`with_drain`](Self::with_drain),
    /// [`on_shutdown`](Self::on_shutdown)).
    shutdown: Option<Shutdown<M>>,
}

/// What a domain asked for at the end: its own message, made each time it is told, and whether the infrastructure
/// waits for its `ProceedWithShutdown`.
struct Shutdown<M> {
    message: Arc<dyn Fn() -> M + Send + Sync>,
    wait: bool,
}

impl<M: ractor::Message> Shutdown<M> {
    /// The infrastructure's notice: `message` sent to `domain`.
    fn notice(self, domain: ActorRef<M>) -> infrastructure::ShutdownNotice {
        let message = self.message;
        infrastructure::ShutdownNotice {
            tell: Arc::new(move || {
                if let Err(e) = domain.cast(message()) {
                    tracing::warn!(
                        "the domain supervisor could not be told the agent is ending: {e}"
                    );
                }
            }),
            wait: self.wait,
        }
    }
}

/// Each declared command with its handler.
type CommandPairs = Vec<(CommandSpec, Arc<dyn CommandHandler>)>;

/// Pairs each command an agent declared with its handler, and says what does not pair: a declared command
/// with no handler can be sent and never run, and a handler for an undeclared command can never be reached,
/// so either is a startup failure rather than a surprise later.
fn resolve_commands(
    declared: &'static [CommandSpec],
    registered: Vec<(&'static str, Arc<dyn CommandHandler>)>,
) -> Result<CommandPairs, String> {
    let mut problems = Vec::new();
    let mut handlers: std::collections::HashMap<&'static str, Arc<dyn CommandHandler>> =
        std::collections::HashMap::new();
    for (name, handler) in registered {
        if handlers.insert(name, handler).is_some() {
            problems.push(format!("a handler for `{name}` is registered twice"));
        }
    }
    let mut resolved = Vec::new();
    for spec in declared {
        match handlers.remove(spec.name) {
            Some(handler) => resolved.push((*spec, handler)),
            None => problems.push(format!(
                "`{}` is declared in COMMANDS but has no handler: register one with with_command",
                spec.name
            )),
        }
    }
    let mut undeclared: Vec<&str> = handlers.keys().copied().collect();
    undeclared.sort_unstable();
    for name in undeclared {
        problems.push(format!(
            "a handler is registered for `{name}`, which is not declared in COMMANDS"
        ));
    }
    if problems.is_empty() {
        Ok(resolved)
    } else {
        Err(problems.join("; "))
    }
}

impl<M: ractor::Message> AgentBuilder<M> {
    pub fn new(myself: ActorRef<M>, service_name: impl Into<String>) -> Self {
        Self {
            myself,
            service_name: service_name.into(),
            subscriptions: Vec::new(),
            requires: Vec::new(),
            map_lifecycle_event: None,
            wants_crypto: false,
            wants_state: false,
            self_test: false,
            shutdown_budget: None,
            environment: Vec::new(),
            commands: Vec::new(),
            declared_commands: &[],
            declared_runtime: &[],
            declared_protocols: protocol::ProtocolSetup::default(),
            declared_workers: Vec::new(),
            section_judge: None,
            settings_judge: None,
            topics: None,
            graph: None,
            graph_key_indexes: Vec::new(),
            graph_repairs: &[],
            shutdown: None,
        }
    }

    /// The agent has work of its own to finish when it ends (children to stop, a listener or a queue to drain, topics
    /// to let go of): when it is to end, for whatever reason, the infrastructure sends the domain supervisor `message`
    /// and waits for its `ProceedWithShutdown`, as long as the shutdown budget allows. The graph controller is drained
    /// after it. Registered before `build`, so a notice that comes while the domain is still starting waits in its
    /// mailbox.
    pub fn with_drain(mut self, message: impl Fn() -> M + Send + Sync + 'static) -> Self {
        self.shutdown = Some(Shutdown {
            message: Arc::new(message),
            wait: true,
        });
        self
    }

    /// The agent only needs to know it is ending (to stop starting new work): the infrastructure sends the domain
    /// supervisor `message` and goes on without waiting. An agent that registers neither this nor
    /// [`with_drain`](Self::with_drain) is not told.
    pub fn on_shutdown(mut self, message: impl Fn() -> M + Send + Sync + 'static) -> Self {
        self.shutdown = Some(Shutdown {
            message: Arc::new(message),
            wait: false,
        });
        self
    }

    /// Registers the handler that runs the command `name`, which the agent must have declared in
    /// `PolarAgent::COMMANDS`. The infrastructure verifies each signed command, checks its arguments against
    /// the declaration, and runs the handler under the declared timeout, announcing every step; the handler
    /// is only the doing. The agent does not start if what is declared and what is registered disagree.
    pub fn with_command(mut self, name: &'static str, handler: Arc<dyn CommandHandler>) -> Self {
        self.commands.push((name, handler));
        self
    }

    /// Declares the variables this agent's own code reads. They join the builder's and its
    /// components' in the one snapshot, are checked with them before anything spawns (so a
    /// missing or malformed one is named at startup, together with every other problem),
    /// and are read afterwards from `AgentResources::config`. A variable that is not
    /// declared is not in the snapshot, so the agent cannot read it by accident.
    pub fn with_environment(mut self, section: &'static polar_env::Section) -> Self {
        self.environment.push(section);
        self
    }

    /// How long this agent's domain supervisor needs to drain, from being told to
    /// shut down to releasing the infrastructure. If it has not finished by then the
    /// process exits 1 regardless, so an agent whose drain can take longer than the
    /// default (20 s) must say so.
    ///
    /// This is a requirement, checked against what the deployment provides
    /// (`POLAR_SHUTDOWN_BUDGET_SECS`, which also sizes the pod's termination grace
    /// period): the deployment may give more, never less, and `build()` refuses to
    /// start when it gives less.
    pub fn with_shutdown_budget(mut self, budget: std::time::Duration) -> Self {
        self.shutdown_budget = Some(budget);
        self
    }

    /// Declares a capability this agent's own code needs from its
    /// deployment, beyond the ones a with_* method below already
    /// declares (for example Capability::KubeApiRead, which the builder
    /// itself does nothing for). build() checks everything declared
    /// against what the deployment says it provides
    /// (POLAR_CAPABILITIES) and refuses to start on a mismatch.
    pub fn requires(mut self, capability: Capability) -> Self {
        if !self.requires.contains(&capability) {
            self.requires.push(capability);
        }
        self
    }

    /// This agent writes to the graph over mTLS: its own health check
    /// then also watches the graph connection.
    pub fn with_graph_write(self) -> Self {
        self.requires(Capability::GraphWrite)
    }

    /// Spawns a real, live CryptoActor alongside this agent's own,
    /// real router and TcpClient once build() succeeds -- see
    /// crypto::CryptoHandle's own doc comment for what it exposes.
    /// Deliberately opt-in: an agent that never encrypts a payload
    /// (the observers) does not declare it, and credentials-agent's
    /// own, real, existing supervisor holds its own, direct escrow
    /// key, so build() genuinely can't assume every real caller
    /// wants it.
    pub fn with_encryption(mut self) -> Self {
        self.wants_crypto = true;
        self.requires(Capability::Encryption)
    }

    /// The agent publishes probes to itself and expects to hear them: if it is registered but
    /// no probe comes back, it reports its Cassini connection as lost, and the health check
    /// ends it. For agents that wait on requests, whose silence would otherwise look like
    /// having nothing to do. See `selftest`.
    pub fn with_self_test(mut self) -> Self {
        self.self_test = true;
        self
    }

    pub fn with_subscription(mut self, subscription: Subscription) -> Self {
        self.subscriptions.push(subscription);
        self
    }

    /// Has `judge` decide whether a runtime section may be replaced, given the sections in force, once its own check
    /// has accepted the body: a refusal is an `invalid` outcome with the judge's reasons, and the section in force
    /// stays; an acceptance carries the judge's notes into the `applied` outcome.
    pub fn with_section_judge(mut self, judge: Arc<dyn runtime::SectionJudge>) -> Self {
        self.section_judge = Some(judge);
        self
    }

    /// The real, required handler for every other, real
    /// ClientEvent variant this agent's own supervisor still wants
    /// to observe directly (Registered beyond subscribing,
    /// TransportError, etc.) -- exactly the same, real map_event
    /// shape lib::cassini::TcpClient::spawn_with_router itself
    /// already takes. Required: every real agent built so far
    /// genuinely needs at least CassiniConnected/CassiniDisconnected
    /// forwarded to its own healthcheck.
    pub fn with_lifecycle_handler(
        mut self,
        map_event: impl Fn(ClientEvent) -> Option<M> + Send + Sync + 'static,
    ) -> Self {
        self.map_lifecycle_event = Some(Box::new(map_event));
        self
    }

    /// Reads and judges the environment, and spawns nothing.
    ///
    /// This is the first half of [`build`](Self::build). Take it first when the domain
    /// supervisor needs its own settings (from [`ConfiguredAgent::config`]) before it starts
    /// the actors that use them, and spawn the infrastructure afterwards with
    /// [`ConfiguredAgent::build`]. An unsound environment fails here, with every problem, before
    /// anything has been started.
    pub fn configure(self) -> Result<ConfiguredAgent<M>, ActorProcessingErr> {
        self.configure_from(&polar_env::ProcessEnv)
    }

    /// As [`configure`](Self::configure), reading `env`.
    pub(crate) fn configure_from(
        self,
        env: &dyn polar_env::Env,
    ) -> Result<ConfiguredAgent<M>, ActorProcessingErr> {
        // Every agent built here is a Cassini client; the rest are what its own code
        // declared.
        let mut required = self.requires.clone();
        if !required.contains(&Capability::Cassini) {
            required.insert(0, Capability::Cassini);
        }

        // One snapshot of the environment, judged as a whole before anything else happens.
        // Everything after this reads the snapshot.
        let startup = startup::prepare(env, &self.environment, &required, self.shutdown_budget)
            .map_err(ActorProcessingErr::from)?;

        Ok(ConfiguredAgent {
            builder: self,
            startup,
        })
    }

    /// For an agent that implements [`PolarAgent`]: takes what `run` already judged instead of
    /// reading the environment again, and declares from it what the agent declared (its
    /// capabilities, encryption, the self-test), so the builder cannot be told anything that
    /// contradicts the trait. The subscriptions and the lifecycle handler are still the
    /// agent's to add before this.
    pub fn into_configured(mut self, configured: Configured) -> ConfiguredAgent<M> {
        self.requires = configured.required.clone();
        self.wants_crypto = configured.required.contains(&Capability::Encryption);
        self.wants_state = configured.required.contains(&Capability::SoftState);
        self.self_test = configured.self_test;
        self.declared_commands = configured.commands;
        self.declared_runtime = configured.runtime;
        self.settings_judge = configured.settings_judge;
        self.declared_protocols = configured.protocols;
        self.declared_workers = configured.workers;
        self.topics = Some(configured.topics.clone());
        self.graph = configured.graph;
        self.graph_key_indexes = configured.graph_key_indexes.clone();
        self.graph_repairs = configured.graph_repairs;
        ConfiguredAgent {
            builder: self,
            startup: configured.startup,
        }
    }

    /// Reads the environment and spawns the infrastructure: [`configure`](Self::configure)
    /// then [`ConfiguredAgent::build`].
    pub async fn build(self) -> Result<AgentResources, ActorProcessingErr> {
        self.configure()?.build().await
    }
}

/// An agent whose environment has been read and judged, and whose infrastructure is not yet
/// spawned. From [`AgentBuilder::configure`].
pub struct ConfiguredAgent<M: ractor::Message> {
    builder: AgentBuilder<M>,
    startup: startup::Startup,
}

impl<M: ractor::Message> ConfiguredAgent<M> {
    /// As [`AgentBuilder::with_section_judge`], for a judge made from what the agent builds from its settings
    /// before the infrastructure starts (the credentials agent's, from its model and its ledger).
    pub fn with_section_judge(mut self, judge: Arc<dyn runtime::SectionJudge>) -> Self {
        self.builder.section_judge = Some(judge);
        self
    }

    /// The snapshot the infrastructure will run on. Read the agent's own settings from it
    /// with `config.read(&VAR)`, or parse a component's settings with its own
    /// `from_env(&*config)`.
    pub fn config(&self) -> &Arc<polar_env::Config> {
        &self.startup.config
    }

    /// Spawns the infrastructure: the health check, the router, the subscriptions and the
    /// Cassini client, on the snapshot taken when this was configured.
    pub async fn build(self) -> Result<AgentResources, ActorProcessingErr> {
        let ConfiguredAgent {
            builder: this,
            startup,
        } = self;
        let health_check_args = HealthCheckArgs::new(
            startup.health.expects_graph,
            startup.health.rejuvenation_threshold_secs,
            startup.health.dep_cert_endpoints.clone(),
        )
        .with_config(startup.health);

        let commands = resolve_commands(this.declared_commands, this.commands)
            .map_err(|problems| ActorProcessingErr::from(format!("the commands: {problems}")))?;

        // The graph controller's connection, read and judged from the snapshot like the rest.
        let graph = match this.graph {
            Some(uses) => Some(graph::GraphSetup {
                uses,
                settings: polar::graph::environment::GraphSettings::from_env(&*startup.config)
                    .map_err(ActorProcessingErr::from)?,
                key_indexes: this.graph_key_indexes,
                repairs: this.graph_repairs.to_vec(),
            }),
            None => None,
        };

        // The agent is the workload its certificate names, or it does not start.
        let certificate = startup
            .config
            .read(&cassini_client::environment::TLS_CLIENT_CERT)
            .map_err(|e| ActorProcessingErr::from(e.to_string()))?;
        let own = own_name::check_certificate(&this.service_name, &certificate)
            .map_err(ActorProcessingErr::from)?;
        // Its soft state's answers come from the state agent of its own namespace and domain.
        let state_agent = if this.wants_state {
            Some(state::state_agent_identity(&own.identity).ok_or_else(|| {
                ActorProcessingErr::from(format!(
                    "{} names no workload, so the state agent cannot be found",
                    own.identity
                ))
            })?)
        } else {
            None
        };
        // Who the floor lets ask about its health: the state agent's writer of its own namespace and domain.
        let health_writer = health_query::writer_identity(&own.identity);
        // Each publish and subscribe is checked before it leaves: the agent's policy, then its topics.
        let gate = this
            .topics
            .clone()
            .map(|set| topic_gate::gate(&this.service_name, own.identity, Some(own.pem), set));

        let process_exit = shutdown::real_process_exit();

        // The infrastructure: the health check, the router, the subscriptions, the client and the
        // actors the agent's capabilities bring, under one supervisor of the builder's own. It is
        // not the domain supervisor's child: the builder watches it (`end_with_infrastructure`),
        // and the domain hears nothing of it but `PrepareShutdown`.
        let (infrastructure, ended) = InfrastructureSupervisor::spawn(
            None,
            InfrastructureSupervisor,
            infrastructure::InfrastructureSupervisorArgs {
                service_name: this.service_name.clone(),
                health_check_args,
                config: startup.config,
                subscriptions: this.subscriptions,
                wants_crypto: this.wants_crypto,
                wants_signer: this.requires.contains(&Capability::Signing),
                state_agent,
                health_writer,
                with_client: true,
                self_test: this.self_test,
                graph,
                notice: this
                    .shutdown
                    .map(|shutdown| shutdown.notice(this.myself.clone())),
                shutdown_budget: startup.shutdown_budget,
                listen_for_signals: true,
                process_exit: process_exit.clone(),
                tcp_spawner: Arc::new(infrastructure::CassiniSpawner { gate }),
                commands,
                runtime_sections: this.declared_runtime,
                protocols: this.declared_protocols,
                workers: this.declared_workers,
                section_judge: this.section_judge,
                settings_judge: this.settings_judge,
            },
        )
        .await
        .map_err(ActorProcessingErr::from)?;
        shutdown::end_with_infrastructure(ended, this.myself.get_cell(), process_exit);

        let resources: AgentResources = ractor::call!(infrastructure, |reply| {
            InfrastructureSupervisorMessage::GetResources { reply }
        })
        .map_err(|e| ActorProcessingErr::from(e.to_string()))?
        .ok_or_else(|| ActorProcessingErr::from("the infrastructure has no Cassini client"))?;

        // The caller's own, real lifecycle-handling closure --
        // subscribed directly to InfrastructureSupervisor's own,
        // real events_output, the same, established pattern every
        // other real port in this codebase already uses (matching
        // TcpClient::spawn_with_router's own, previous, direct
        // parameter exactly, just one real layer removed now).
        let map_lifecycle_event: Arc<dyn Fn(ClientEvent) -> Option<M> + Send + Sync> =
            match this.map_lifecycle_event {
                Some(map) => Arc::from(map),
                None => Arc::new(|_event| None),
            };
        resources.events_output.subscribe(this.myself.clone(), {
            let map = map_lifecycle_event.clone();
            move |event| map(event)
        });
        // Cassini may have registered the agent already.
        infrastructure::catch_up(
            &resources.infrastructure,
            &this.myself,
            map_lifecycle_event.as_ref(),
        )
        .await?;

        Ok(resources)
    }
}

/// What a service that is not a Cassini client is given: the health handle, the shutdown
/// events, the shutdown handshake and the snapshot. The broker is one.
#[derive(Clone)]
pub struct ServiceResources {
    pub healthcheck: crate::health::HealthHandle,
    /// Where to send `ProceedWithShutdown` once the service has drained, and `BeginShutdown` to
    /// ask for the service to end (a shutdown requested over the wire, for example).
    pub infrastructure: ActorRef<crate::infrastructure::InfrastructureSupervisorMessage>,
    pub config: Arc<polar_env::Config>,
    /// The configuration, live. See [`AgentResources::configuration`].
    pub configuration: crate::configuration::ConfigurationHandle,
    /// The service's TLS, from its own keys. See [`AgentResources::tls`].
    pub tls: crate::crypto::TlsHandle,
}

/// The infrastructure of a service that is not a Cassini client: the broker itself, or any
/// future service that serves instead of consuming. It has the health check, the signals, the
/// shutdown handshake with its budget and watchdog, and the one configuration snapshot, and none
/// of the router, the client or the subscriptions that `AgentBuilder` adds.
pub struct ServiceBuilder<M: ractor::Message> {
    myself: ActorRef<M>,
    service_name: String,
    requires: Vec<Capability>,
    shutdown_budget: Option<std::time::Duration>,
    environment: Vec<&'static polar_env::Section>,
    /// As `AgentBuilder`'s.
    shutdown: Option<Shutdown<M>>,
}

impl<M: ractor::Message> ServiceBuilder<M> {
    pub fn new(myself: ActorRef<M>, service_name: impl Into<String>) -> Self {
        Self {
            myself,
            service_name: service_name.into(),
            requires: Vec::new(),
            shutdown_budget: None,
            environment: Vec::new(),
            shutdown: None,
        }
    }

    /// As [`AgentBuilder::with_drain`].
    pub fn with_drain(mut self, message: impl Fn() -> M + Send + Sync + 'static) -> Self {
        self.shutdown = Some(Shutdown {
            message: Arc::new(message),
            wait: true,
        });
        self
    }

    /// As [`AgentBuilder::on_shutdown`].
    pub fn on_shutdown(mut self, message: impl Fn() -> M + Send + Sync + 'static) -> Self {
        self.shutdown = Some(Shutdown {
            message: Arc::new(message),
            wait: false,
        });
        self
    }

    /// Declares the variables the service's own code reads, as `AgentBuilder::with_environment`.
    pub fn with_environment(mut self, section: &'static polar_env::Section) -> Self {
        self.environment.push(section);
        self
    }

    /// The least the service needs to drain, as `AgentBuilder::with_shutdown_budget`.
    pub fn with_shutdown_budget(mut self, budget: std::time::Duration) -> Self {
        self.shutdown_budget = Some(budget);
        self
    }

    /// For a service that implements [`PolarAgent`] with `CASSINI_CLIENT = false`, or one whose
    /// Cassini is optional and the deployment does not provide it
    /// (`Configured::cassini_enabled` is false): takes what `run` already judged.
    pub fn into_configured(mut self, configured: Configured) -> ConfiguredService<M> {
        self.requires = configured.required.clone();
        ConfiguredService {
            builder: self,
            startup: configured.startup,
            hooks: configured.hooks,
        }
    }
}

/// A service whose configuration has been judged and whose infrastructure is not yet spawned.
pub struct ConfiguredService<M: ractor::Message> {
    builder: ServiceBuilder<M>,
    startup: startup::Startup,
    hooks: agent::Hooks,
}

impl<M: ractor::Message> ConfiguredService<M> {
    pub fn config(&self) -> &Arc<polar_env::Config> {
        &self.startup.config
    }

    /// Spawns the infrastructure: the health actor, the signal listener and the shutdown
    /// handshake, on the snapshot taken when this was configured.
    pub async fn build(self) -> Result<ServiceResources, ActorProcessingErr> {
        let ConfiguredService {
            builder: this,
            startup,
            hooks,
        } = self;
        if this.requires.contains(&Capability::Encryption) {
            return Err(ActorProcessingErr::from(
                "a service without a Cassini client cannot encrypt: the crypto actor works \
                 through the client",
            ));
        }
        let health_check_args = HealthCheckArgs::new(
            startup.health.expects_graph,
            startup.health.rejuvenation_threshold_secs,
            startup.health.dep_cert_endpoints.clone(),
        )
        .with_config(startup.health);

        // Not the domain supervisor's child, as for an agent: the builder watches it.
        let (infrastructure, ended) = InfrastructureSupervisor::spawn(
            None,
            InfrastructureSupervisor,
            infrastructure::InfrastructureSupervisorArgs {
                service_name: this.service_name.clone(),
                health_check_args,
                config: startup.config,
                subscriptions: Vec::new(),
                wants_crypto: false,
                wants_signer: false,
                state_agent: None,
                health_writer: None,
                with_client: false,
                self_test: false,
                graph: None,
                notice: this
                    .shutdown
                    .map(|shutdown| shutdown.notice(this.myself.clone())),
                shutdown_budget: startup.shutdown_budget,
                listen_for_signals: hooks.listen_for_signals,
                process_exit: hooks.process_exit.clone(),
                tcp_spawner: Arc::new(infrastructure::CassiniSpawner::default()),
                commands: Vec::new(),
                runtime_sections: &[],
                protocols: protocol::ProtocolSetup::default(),
                workers: Vec::new(),
                section_judge: None,
                settings_judge: None,
            },
        )
        .await
        .map_err(ActorProcessingErr::from)?;
        shutdown::end_with_infrastructure(
            ended,
            this.myself.get_cell(),
            hooks.process_exit.clone(),
        );

        let resources: ServiceResources = ractor::call!(infrastructure, |reply| {
            InfrastructureSupervisorMessage::GetService { reply }
        })
        .map_err(|e| ActorProcessingErr::from(e.to_string()))?;
        if let Some(out) = &hooks.resources_out {
            *out.lock().unwrap() = Some(resources.clone());
        }
        Ok(resources)
    }
}

/// The real, testable core of AgentBuilder::build()'s own lifecycle
/// wiring -- extracted specifically because build() itself, like
/// every other, real agent's own pre_start, can't genuinely be
/// tested without a live broker and valid TLS certs (TcpClientConfig::new()
/// reads real environment variables). This function's own, real
/// logic can: on ClientEvent::Registered, fire every real,
/// remembered Subscribe call, then always still forward the event to
/// the caller's own map_lifecycle_event -- proving both halves of
/// Subscription's own, atomic guarantee actually hold, and that a
/// caller's own, separate lifecycle-handling logic is never silently
/// dropped.
pub(crate) fn build_lifecycle_handler<M: ractor::Message>(
    service_name: String,
    subscribed_topics: Vec<String>,
    map_lifecycle_event: Box<dyn Fn(ClientEvent) -> Option<M> + Send + Sync>,
) -> impl Fn(ClientEvent) -> Option<M> {
    move |event: ClientEvent| -> Option<M> {
        if let ClientEvent::Registered { registration_id } = &event {
            tracing::info!(
                %registration_id,
                topics = subscribed_topics.len(),
                "AgentBuilder: registered with Cassini, subscribing to every request topic"
            );
            // The real, live TcpClientActor genuinely, necessarily
            // already exists by the time Registered fires -- it's
            // the very actor that produced this event -- so a
            // registry lookup by its own, real, deterministic name
            // (the same one spawn_with_router itself uses) is safe
            // here, even though no direct handle to it was available
            // yet when this closure was built.
            if let Some(tcp_client_cell) = ractor::registry::where_is(format!("{service_name}.tcp"))
            {
                // Genuinely, deliberately trusted, not verified --
                // confirmed directly against ractor's own source
                // before relying on it: From<ActorCell> for
                // ActorRef<TMessage> does zero real runtime type
                // checking of its own, it's a pure PhantomData
                // wrapper. Safe here specifically because
                // TcpClient::spawn_with_router is the one, sole, real
                // thing that ever registers an actor under this
                // exact, deterministic name -- the same,
                // already-established convention this codebase's own
                // where_is call sites already rely on elsewhere (e.g.
                // credentials-agent's own dispatch_store_secret_request).
                let tcp_client_ref: ActorRef<TcpClientMessage> = tcp_client_cell.into();
                for topic in &subscribed_topics {
                    match tcp_client_ref.send_message(TcpClientMessage::Subscribe {
                        topic: topic.clone(),
                        trace_ctx: None,
                    }) {
                        Ok(()) => tracing::info!("AgentBuilder: subscribing to {topic}"),
                        Err(e) => {
                            tracing::error!("AgentBuilder: failed to subscribe to {topic}: {e}")
                        }
                    }
                }
            } else {
                tracing::error!(
                    "AgentBuilder: TcpClientActor not found under its own, expected name while \
                     attempting to fire real, remembered subscriptions"
                );
            }
        }
        map_lifecycle_event(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_env::Env;
    use ractor::{Actor, async_trait};
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone, PartialEq)]
    enum FakeMessage {
        Forwarded(String),
    }

    /// A minimal, real stand-in for TcpClientActor -- spawned under
    /// the exact, same, real, deterministic name
    /// build_lifecycle_handler itself expects
    /// (`{service_name}.tcp`), so where_is genuinely finds it.
    /// Records every real TcpClientMessage it receives.
    struct FakeTcpClient {
        received: Arc<Mutex<Vec<TcpClientMessage>>>,
    }

    #[async_trait]
    impl Actor for FakeTcpClient {
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
            self.received.lock().unwrap().push(message);
            Ok(())
        }
    }

    #[tokio::test]
    async fn registered_fires_every_real_remembered_subscribe_and_still_forwards_to_the_caller() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let (_tcp_client, _) = Actor::spawn(
            Some("test-service.tcp".to_string()),
            FakeTcpClient {
                received: received.clone(),
            },
            (),
        )
        .await
        .unwrap();

        let handler = build_lifecycle_handler(
            "test-service".to_string(),
            vec!["topic-a".to_string(), "topic-b".to_string()],
            Box::new(|event| match event {
                ClientEvent::Registered { registration_id } => {
                    Some(FakeMessage::Forwarded(registration_id))
                }
                _ => None,
            }),
        );

        let result = handler(ClientEvent::Registered {
            registration_id: "a-real-registration-id".to_string(),
        });

        // Real proof 1: the caller's own map_lifecycle_event still,
        // genuinely fired -- Subscription's own machinery never
        // silently swallows the caller's own, separate lifecycle
        // logic.
        assert_eq!(
            result,
            Some(FakeMessage::Forwarded("a-real-registration-id".to_string()))
        );

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Real proof 2: both, real, remembered topics were genuinely
        // subscribed to -- not just registered with the router
        // earlier, but actually, really subscribed on the wire.
        let messages = received.lock().unwrap();
        let subscribed_topics: Vec<String> = messages
            .iter()
            .filter_map(|m| match m {
                TcpClientMessage::Subscribe { topic, .. } => Some(topic.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(subscribed_topics.len(), 2);
        assert!(subscribed_topics.contains(&"topic-a".to_string()));
        assert!(subscribed_topics.contains(&"topic-b".to_string()));
    }

    #[tokio::test]
    async fn a_non_registered_event_never_fires_any_subscribe_but_still_forwards_to_the_caller() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let (_tcp_client, _) = Actor::spawn(
            Some("test-service-2.tcp".to_string()),
            FakeTcpClient {
                received: received.clone(),
            },
            (),
        )
        .await
        .unwrap();

        let handler = build_lifecycle_handler(
            "test-service-2".to_string(),
            vec!["topic-a".to_string()],
            Box::new(|event| match event {
                ClientEvent::TransportError { reason } => Some(FakeMessage::Forwarded(reason)),
                _ => None,
            }),
        );

        let result = handler(ClientEvent::TransportError {
            reason: "a real, genuine disconnect".to_string(),
        });

        assert_eq!(
            result,
            Some(FakeMessage::Forwarded(
                "a real, genuine disconnect".to_string()
            ))
        );

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert!(
            received.lock().unwrap().is_empty(),
            "a non-Registered event must never trigger a real subscribe call"
        );
    }

    #[tokio::test]
    async fn a_missing_tcp_client_actor_never_panics_and_still_forwards_to_the_caller() {
        // Genuinely, deliberately, no real FakeTcpClient spawned under
        // this service name at all -- proving the missing-registry-entry
        // path is a real, harmless, logged no-op, not a panic.
        let handler = build_lifecycle_handler(
            "genuinely-nonexistent-service".to_string(),
            vec!["topic-a".to_string()],
            Box::new(|event| match event {
                ClientEvent::Registered { registration_id } => {
                    Some(FakeMessage::Forwarded(registration_id))
                }
                _ => None,
            }),
        );

        let result = handler(ClientEvent::Registered {
            registration_id: "still-works".to_string(),
        });

        assert_eq!(
            result,
            Some(FakeMessage::Forwarded("still-works".to_string()))
        );
    }

    // -- configuring is reading the environment, and spawns nothing --------------------

    struct Idle;

    #[async_trait]
    impl Actor for Idle {
        type Msg = FakeMessage;
        type State = ();
        type Arguments = ();

        async fn pre_start(
            &self,
            _myself: ActorRef<Self::Msg>,
            _args: (),
        ) -> Result<Self::State, ActorProcessingErr> {
            Ok(())
        }
    }

    fn map(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[tokio::test]
    async fn configuring_takes_the_snapshot_before_anything_is_spawned() {
        let (idle, _) = Actor::spawn(None, Idle, ()).await.unwrap();
        let env = map(environment::fixtures::CASSINI_ENV);
        let configured = AgentBuilder::new(idle, "configure-test")
            .configure_from(&env)
            .unwrap();

        // The snapshot is there to read, so a domain supervisor can take its own settings
        // from it before it starts the actors that need them.
        assert_eq!(
            configured.config().var("BROKER_ADDR").as_deref(),
            Some("cassini:8080")
        );
        // Nothing was spawned: the client's name is not registered.
        assert!(ractor::registry::where_is("configure-test.tcp".to_string()).is_none());
    }

    // -- commands: what is declared and what is registered ----------------------------------

    struct NoHandler;
    #[ractor::async_trait]
    impl CommandHandler for NoHandler {
        async fn run(&self, _: CommandRequest) -> Result<String, String> {
            Ok(String::new())
        }
    }

    const ONE: CommandSpec = CommandSpec {
        name: "one",
        doc: "",
        args: &[],
        delivery: Delivery::Idempotent,
        exclusive: false,
        timeout: std::time::Duration::from_secs(1),
    };
    const TWO: CommandSpec = CommandSpec {
        name: "two",
        doc: "",
        args: &[],
        delivery: Delivery::Once,
        exclusive: true,
        timeout: std::time::Duration::from_secs(1),
    };
    static BOTH: [CommandSpec; 2] = [ONE, TWO];

    fn handler() -> Arc<dyn CommandHandler> {
        Arc::new(NoHandler)
    }

    #[test]
    fn declared_commands_are_paired_with_their_handlers_in_the_order_declared() {
        let resolved =
            resolve_commands(&BOTH, vec![("two", handler()), ("one", handler())]).unwrap();
        let names: Vec<&str> = resolved.iter().map(|(spec, _)| spec.name).collect();
        assert_eq!(names, ["one", "two"]);
        assert!(resolve_commands(&[], vec![]).unwrap().is_empty());
    }

    #[test]
    fn a_declared_command_with_no_handler_and_a_handler_for_nothing_declared_are_both_refused() {
        let missing = resolve_commands(&BOTH, vec![("one", handler())])
            .err()
            .unwrap();
        assert!(
            missing.contains("`two` is declared") && missing.contains("no handler"),
            "{missing}"
        );

        let stray = resolve_commands(
            &BOTH,
            vec![("one", handler()), ("two", handler()), ("three", handler())],
        )
        .err()
        .unwrap();
        assert!(
            stray.contains("`three`") && stray.contains("not declared"),
            "{stray}"
        );

        // Several problems are all said, and a handler registered twice is one of them.
        let all = resolve_commands(
            &BOTH,
            vec![("one", handler()), ("one", handler()), ("ghost", handler())],
        )
        .err()
        .unwrap();
        assert!(
            all.contains("twice") && all.contains("`two`") && all.contains("`ghost`"),
            "{all}"
        );

        // Handlers and no declaration at all.
        assert!(resolve_commands(&[], vec![("one", handler())]).is_err());
    }

    #[tokio::test]
    async fn an_agent_whose_declared_commands_have_no_handlers_does_not_build_and_starts_nothing() {
        let (idle, _) = Actor::spawn(None, Idle, ()).await.unwrap();
        let env = map(environment::fixtures::CASSINI_ENV);
        let required = vec![Capability::Cassini];
        let startup = startup::prepare(&env, &[], &required, None).unwrap();
        let configured = Configured {
            startup,
            required,
            optional_off: Vec::new(),
            self_test: false,
            commands: &BOTH,
            runtime: &[],
            settings_judge: None,
            protocols: protocol::ProtocolSetup::default(),
            workers: Vec::new(),
            graph_key_indexes: Vec::new(),
            graph: None,
            graph_repairs: &[],
            topics: Default::default(),
            hooks: crate::agent::Hooks::real(),
        };
        let error = AgentBuilder::new(idle, "no-handlers")
            .into_configured(configured)
            .build()
            .await
            .err()
            .expect("it must not build");
        let said = error.to_string();
        assert!(
            said.contains("the commands") && said.contains("no handler"),
            "{said}"
        );
        // It stopped before it spawned anything.
        assert!(ractor::registry::where_is("no-handlers.tcp".to_string()).is_none());
    }

    #[tokio::test]
    async fn an_agent_with_another_workloads_certificate_does_not_build_and_starts_nothing() {
        let (idle, _) = Actor::spawn(None, Idle, ()).await.unwrap();
        let other =
            own_name::tests::certificate_for("kube-consumer.polar.serviceaccount.cluster.local");
        let path = other.path().to_str().unwrap().to_string();
        let mut pairs: Vec<(&str, &str)> = environment::fixtures::CASSINI_ENV
            .iter()
            .filter(|(name, _)| *name != "TLS_CLIENT_CERT")
            .copied()
            .collect();
        pairs.push(("TLS_CLIENT_CERT", &path));
        let env = map(&pairs);
        let required = vec![Capability::Cassini];
        let startup = startup::prepare(&env, &[], &required, None).unwrap();
        let configured = Configured {
            startup,
            required,
            optional_off: Vec::new(),
            self_test: false,
            commands: &[],
            runtime: &[],
            settings_judge: None,
            protocols: protocol::ProtocolSetup::default(),
            workers: Vec::new(),
            graph_key_indexes: Vec::new(),
            graph: None,
            graph_repairs: &[],
            topics: Default::default(),
            hooks: crate::agent::Hooks::real(),
        };
        let error = AgentBuilder::new(idle, "kube-observer")
            .into_configured(configured)
            .build()
            .await
            .err()
            .expect("it must not build");
        let said = error.to_string();
        assert!(
            said.contains("`kube-observer`") && said.contains("`kube-consumer`"),
            "{said}"
        );
        assert!(ractor::registry::where_is("kube-observer.tcp".to_string()).is_none());
    }

    #[tokio::test]
    async fn an_agent_built_from_the_trait_declares_to_the_builder_what_the_trait_declared() {
        let (idle, _) = Actor::spawn(None, Idle, ()).await.unwrap();
        let env = map(environment::fixtures::CASSINI_ENV);
        let required = vec![Capability::Cassini, Capability::Encryption];
        let startup = startup::prepare(&env, &[], &required, None).unwrap();
        let configured = Configured {
            startup,
            required: required.clone(),
            optional_off: Vec::new(),
            self_test: false,
            commands: &[],
            runtime: &[],
            settings_judge: None,
            protocols: protocol::ProtocolSetup::default(),
            workers: Vec::new(),
            graph_key_indexes: Vec::new(),
            graph: None,
            graph_repairs: &[],
            topics: Default::default(),
            hooks: crate::agent::Hooks::real(),
        };

        let built = AgentBuilder::new(idle, "from-the-trait")
            // What a hand-written chain might also have said: it is overruled.
            .with_graph_write()
            .with_self_test()
            .into_configured(configured);

        assert_eq!(built.builder.requires, required);
        assert!(built.builder.wants_crypto, "encryption was needed");
        assert!(!built.builder.self_test, "the trait said no self-test");
    }

    #[tokio::test]
    async fn configuring_refuses_an_unsound_environment_with_every_problem() {
        let (idle, _) = Actor::spawn(None, Idle, ()).await.unwrap();
        let error = AgentBuilder::new(idle, "configure-bad")
            .configure_from(&map(&[("POLAR_HEALTH_TICK_SECS", "soon")]))
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("POLAR_HEALTH_TICK_SECS"), "{error}");
        assert!(error.contains("BROKER_ADDR"), "the client's too: {error}");
    }

    #[tokio::test]
    async fn what_the_agent_declares_is_judged_when_configuring() {
        let (idle, _) = Actor::spawn(None, Idle, ()).await.unwrap();
        let error = AgentBuilder::new(idle, "configure-graph")
            .with_graph_write()
            .configure_from(&map(environment::fixtures::CASSINI_ENV))
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("GRAPH_ENDPOINT"), "{error}");
    }

    #[tokio::test]
    async fn an_agent_can_take_the_graph_settings_without_making_its_health_depend_on_the_graph() {
        // The credentials consumer's case: it projects to the graph but must not have its
        // health watch Neo4j, so it declares the graph section itself instead of requiring
        // the graph-write capability.
        let (idle, _) = Actor::spawn(None, Idle, ()).await.unwrap();
        let mut vars = environment::fixtures::CASSINI_ENV.to_vec();
        vars.extend_from_slice(environment::fixtures::GRAPH_ENV);
        let configured = AgentBuilder::new(idle, "configure-projection")
            .with_environment(&polar::graph::environment::SECTION)
            .configure_from(&map(&vars))
            .unwrap();

        let settings =
            polar::graph::environment::GraphSettings::from_env(&**configured.config()).unwrap();
        assert_eq!(settings.endpoint, "bolt+s://db:7687");
        assert!(
            !configured.startup.health.expects_graph,
            "health does not watch the graph"
        );
    }
}

#[cfg(test)]
mod the_infrastructure_ending {
    use super::*;
    use crate::infrastructure::InfrastructureSupervisorMessage;
    use ractor::{Actor, SupervisionEvent};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Duration;

    /// A service's domain supervisor that does nothing when its infrastructure ends: whatever ends it then is the
    /// builder's doing. It keeps every supervision event it hears. Told to `Hang`, it is busy for good, as a domain
    /// stuck in a handler is.
    struct Indifferent;

    type Heard = Arc<Mutex<Vec<String>>>;

    enum Domain {
        Hang,
    }

    #[ractor::async_trait]
    impl Actor for Indifferent {
        type Msg = Domain;
        type State = Heard;
        type Arguments = (crate::Configured, Heard);

        async fn pre_start(
            &self,
            myself: ActorRef<Domain>,
            (configured, heard): (crate::Configured, Heard),
        ) -> Result<Heard, ActorProcessingErr> {
            ServiceBuilder::new(myself, "indifferent")
                .into_configured(configured)
                .build()
                .await?;
            Ok(heard)
        }

        async fn handle(
            &self,
            _myself: ActorRef<Domain>,
            message: Domain,
            _state: &mut Heard,
        ) -> Result<(), ActorProcessingErr> {
            match message {
                Domain::Hang => std::future::pending::<()>().await,
            }
            Ok(())
        }

        async fn handle_supervisor_evt(
            &self,
            _myself: ActorRef<Domain>,
            event: SupervisionEvent,
            heard: &mut Heard,
        ) -> Result<(), ActorProcessingErr> {
            heard.lock().unwrap().push(format!("{event:?}"));
            Ok(())
        }
    }

    type Exits = Arc<Mutex<Vec<i32>>>;

    struct Service {
        domain: ActorRef<Domain>,
        domain_ended: ractor::concurrency::JoinHandle<()>,
        resources: ServiceResources,
        exits: Exits,
        heard: Heard,
        _dir: tempfile::TempDir,
    }

    async fn service() -> Service {
        let dir = tempfile::tempdir().unwrap();
        let env: HashMap<String, String> = [(
            "POLAR_HEALTH_FILE".to_string(),
            dir.path()
                .join("health.json")
                .to_string_lossy()
                .into_owned(),
        )]
        .into();
        let exits = Arc::new(Mutex::new(Vec::new()));
        let (configured, out) =
            crate::Configured::for_service_test(&env, Duration::from_secs(20), exits.clone());
        let heard = Arc::new(Mutex::new(Vec::new()));
        let (domain, domain_ended) = Actor::spawn(None, Indifferent, (configured, heard.clone()))
            .await
            .unwrap();
        let resources = out.lock().unwrap().clone().expect("the service was built");
        Service {
            domain,
            domain_ended,
            resources,
            exits,
            heard,
            _dir: dir,
        }
    }

    /// The end of the shutdown handshake ends the domain supervisor, with no help from it, so `run` returns non-zero
    /// as it does for any agent that ends; the process is not exited from under it.
    #[tokio::test]
    async fn the_end_of_the_handshake_ends_the_domain_supervisor() {
        let service = service().await;
        service
            .resources
            .infrastructure
            .cast(InfrastructureSupervisorMessage::BeginShutdown {
                reason: "test".to_string(),
            })
            .unwrap();
        service
            .resources
            .infrastructure
            .cast(InfrastructureSupervisorMessage::ProceedWithShutdown)
            .unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(15), service.domain_ended).await;
        assert!(
            ended.is_ok(),
            "the domain supervisor outlived its infrastructure"
        );
        assert!(service.exits.lock().unwrap().is_empty());
    }

    /// An infrastructure that ends without a handshake, killed outright (no `post_stop` runs), ends the domain
    /// supervisor too.
    #[tokio::test]
    async fn an_infrastructure_killed_outright_ends_the_domain_supervisor() {
        let service = service().await;
        service.resources.infrastructure.kill();
        let ended = tokio::time::timeout(Duration::from_secs(15), service.domain_ended).await;
        assert!(
            ended.is_ok(),
            "the domain supervisor outlived its infrastructure"
        );
        assert!(service.exits.lock().unwrap().is_empty());
    }

    /// The infrastructure is the builder's: the domain supervisor is not its supervisor and hears nothing of it,
    /// failure or end, so its own handling of what it supervises covers its own children alone.
    #[tokio::test]
    async fn the_domain_supervisor_hears_nothing_of_its_infrastructure() {
        let service = service().await;
        service.resources.infrastructure.kill();
        let ended = tokio::time::timeout(Duration::from_secs(15), service.domain_ended).await;
        assert!(
            ended.is_ok(),
            "the domain supervisor outlived its infrastructure"
        );
        assert!(
            service.heard.lock().unwrap().is_empty(),
            "{:?}",
            service.heard.lock().unwrap()
        );
    }

    /// A service that drains registers its own message for the notice; it is sent it, its proceed ends the
    /// infrastructure, and the builder then ends the service. No port, no subscription after `build`.
    #[tokio::test]
    async fn a_domain_that_registers_a_drain_is_told_in_its_own_message_and_its_proceed_ends_it() {
        struct Draining;
        enum Polite {
            Told,
        }
        struct Held {
            told: Arc<std::sync::atomic::AtomicUsize>,
            infrastructure: Option<ActorRef<InfrastructureSupervisorMessage>>,
        }
        #[ractor::async_trait]
        impl Actor for Draining {
            type Msg = Polite;
            type State = Held;
            type Arguments = (crate::Configured, Arc<std::sync::atomic::AtomicUsize>);
            async fn pre_start(
                &self,
                myself: ActorRef<Polite>,
                (configured, told): (crate::Configured, Arc<std::sync::atomic::AtomicUsize>),
            ) -> Result<Held, ActorProcessingErr> {
                let resources = ServiceBuilder::new(myself, "draining")
                    .with_drain(|| Polite::Told)
                    .into_configured(configured)
                    .build()
                    .await?;
                Ok(Held {
                    told,
                    infrastructure: Some(resources.infrastructure),
                })
            }
            async fn handle(
                &self,
                _myself: ActorRef<Polite>,
                message: Polite,
                held: &mut Held,
            ) -> Result<(), ActorProcessingErr> {
                match message {
                    Polite::Told => {
                        held.told.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if let Some(infrastructure) = &held.infrastructure {
                            infrastructure
                                .cast(InfrastructureSupervisorMessage::ProceedWithShutdown)?;
                        }
                    }
                }
                Ok(())
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let env: HashMap<String, String> = [(
            "POLAR_HEALTH_FILE".to_string(),
            dir.path()
                .join("health.json")
                .to_string_lossy()
                .into_owned(),
        )]
        .into();
        let exits = Arc::new(Mutex::new(Vec::new()));
        let (configured, out) =
            crate::Configured::for_service_test(&env, Duration::from_secs(20), exits.clone());
        let told = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (_domain, domain_ended) = Actor::spawn(None, Draining, (configured, told.clone()))
            .await
            .unwrap();
        let resources = out.lock().unwrap().clone().expect("the service was built");
        resources
            .infrastructure
            .cast(InfrastructureSupervisorMessage::BeginShutdown {
                reason: "test".to_string(),
            })
            .unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(15), domain_ended).await;
        assert!(ended.is_ok(), "the service never ended");
        assert_eq!(told.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(
            exits.lock().unwrap().is_empty(),
            "no watchdog, no grace exit"
        );
    }

    /// A domain supervisor that cannot end, stuck in a handler, does not keep the process alive without its
    /// infrastructure: after the grace the process exits 1.
    #[tokio::test(start_paused = true)]
    async fn a_domain_supervisor_that_cannot_end_is_ended_by_the_exit() {
        let service = service().await;
        service.domain.cast(Domain::Hang).unwrap();
        service.resources.infrastructure.kill();
        tokio::time::sleep(crate::shutdown::DOMAIN_END_GRACE + Duration::from_secs(1)).await;
        assert_eq!(*service.exits.lock().unwrap(), [1]);
    }
}
