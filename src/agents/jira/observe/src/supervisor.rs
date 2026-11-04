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
use crate::agent::Prepared;
use crate::groups::JiraGroupObserver;
use crate::issues::JiraIssueObserver;
use crate::projects::JiraProjectObserver;
use crate::users::JiraUserObserver;
use crate::{
    BROKER_CLIENT_NAME, CREDENTIAL, JIRA_GROUP_OBSERVER, JIRA_ISSUE_OBSERVER,
    JIRA_PROJECT_OBSERVER, JIRA_USER_OBSERVER, JiraAuth, JiraObserverArgs, JiraObserverMessage,
    RETRY,
};
use cassini_types::ClientEvent;
use polar::cassini::TcpClient;
use polar_agent_builder::protocol::{CredentialsApplied, ProtocolHandle};
use polar_agent_builder::{
    AgentBuilder, AgentResources, ConfigurationHandle, Configured, HealthClient, HealthHandle,
    HoldReason, InfrastructureEvent, InfrastructureSupervisorMessage, StateClient,
};
use ractor::concurrency::Duration;
use ractor::{Actor, ActorId, ActorProcessingErr, ActorRef, SupervisionEvent, async_trait};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// How long a child observer gets to stop before the supervisor moves on.
/// An observer in the middle of a Jira pull only sees the stop between
/// messages, so this has to be bounded.
const OBSERVER_STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the infrastructure supervisor gives this agent to drain: each observer
/// is stopped in turn, bounded at `OBSERVER_STOP_TIMEOUT`, so this allows for
/// several, plus a margin. If it is not done by then the process exits 1
/// regardless.
pub const SHUTDOWN_BUDGET: Duration = Duration::from_secs(OBSERVER_STOP_TIMEOUT.as_secs() * 3 + 10);

/// This supervisor's own message type. polar::SupervisorMessage cannot carry
/// the infrastructure signals without polar-agent-builder depending back on
/// lib, so the builder is generic over the message (see kube-observer).
pub enum ObserverSupervisorMessage {
    ClientEvent {
        event: ClientEvent,
    },
    /// The HealthCheckActor, a child of InfrastructureSupervisor, has
    /// terminated for rejuvenation. Stop the observers, then send
    /// InfrastructureSupervisorMessage::ProceedWithShutdown.
    PrepareShutdown,
    /// A version of the `credentials` section reached the CryptoActor: it brings a new credential, or withdraws it.
    CredentialsApplied(CredentialsApplied),
    /// A signed update changed what the observers are started with: they start again with it.
    SettingsChanged(Prepared),
}

pub struct ObserverSupervisor;

pub struct ObserverSupervisorState {
    /// The settings the observers are started with.
    prepared: Prepared,
    /// The agent's way to the site.
    protocols: ProtocolHandle,
    tcp_client: TcpClient,
    /// The agent's soft state, which the issue observer's cursor is read from (its state actor).
    state: Option<Arc<dyn StateClient>>,
    healthcheck: HealthHandle,
    /// The CryptoActor has the credential: from the latest `credentials` section, until one withdraws it.
    credential: bool,
    /// Why the latest `credentials` section gave no credential, when it was refused.
    credential_problem: Option<String>,
    /// Cassini has registered this agent: nothing calls Jira before.
    registered: bool,
    /// The standing problem the supervisor itself holds (no credential), apart from the observers' own.
    held: Option<HoldReason>,
    /// Sent ProceedWithShutdown once the observers have stopped.
    infrastructure: ActorRef<InfrastructureSupervisorMessage>,
    projects: Option<ActorRef<JiraObserverMessage>>,
    groups: Option<ActorRef<JiraObserverMessage>>,
    users: Option<ActorRef<JiraObserverMessage>>,
    issues: Option<ActorRef<JiraObserverMessage>>,
}

/// Where the supervisor's infrastructure comes from.
pub enum Infrastructure {
    /// The configuration `run` judged: the supervisor builds the agent from it.
    Build(Configured),
    /// Built already, by the held supervisor of an agent that refused its configuration at start and was mended by a
    /// signed update (`polar_agent_builder::held`); `registered` is whether Cassini has registered it already.
    Built {
        resources: AgentResources,
        registered: bool,
    },
}

pub struct ObserverSupervisorArgs {
    /// The agent's infrastructure, to build or already built.
    pub infrastructure: Infrastructure,
}

/// What the supervisor holds when it has no credential to start the observers with.
const NO_CREDENTIAL: &str = "jira-observer: no credential: sign a `credentials` runtime section for jira-observer \
     (polar-sign), or set JIRA_ANONYMOUS to true";

impl ObserverSupervisorState {
    /// How the observers authenticate: anonymously, or with the credential. None while a credential is needed and none
    /// is registered.
    fn auth(&self) -> Option<JiraAuth> {
        if self.prepared.anonymous {
            return Some(JiraAuth::Anonymous);
        }
        self.credential.then_some(JiraAuth::Credential)
    }

    /// What became of a version of the `credentials` section: whether the observers have their credential, and why not.
    fn credentials_applied(&mut self, applied: &CredentialsApplied) {
        self.credential = applied.registered.iter().any(|name| name == CREDENTIAL);
        self.credential_problem = if self.credential {
            None
        } else if let Some((name, why)) = applied.failed.first() {
            Some(format!(
                "the credentials section version {}: `{name}`: {why}",
                applied.version
            ))
        } else if !applied.registered.is_empty() {
            Some(format!(
                "the credentials section version {} has no entry named `{CREDENTIAL}`, which is the one jira-observer presents",
                applied.version
            ))
        } else {
            None
        };
        if let Some(why) = &self.credential_problem {
            error!(version = applied.version, "{why}");
        }
    }

    fn observer_args(&self, auth: JiraAuth) -> JiraObserverArgs {
        JiraObserverArgs {
            jira_url: self.prepared.jira_url.clone(),
            auth,
            deployment: self.prepared.deployment,
            tcp_client: self.tcp_client.clone(),
            protocols: self.protocols.clone(),
            base_interval: self.prepared.poll_secs,
            page_size: self.prepared.page_size,
            query_date: self.prepared.query_date.clone(),
            retry: RETRY,
            clock: std::time::Instant::now,
            cursor: self.state.clone(),
            wall_clock: crate::issues::wall_clock_ms,
            health: self.healthcheck.clone(),
        }
    }

    /// True if this is one of the observers the supervisor currently expects
    /// to be running. Observers it stopped on purpose have already been
    /// taken out of their slot, so their termination is not an error.
    fn tracks(&self, id: ActorId) -> bool {
        [&self.projects, &self.groups, &self.users, &self.issues]
            .into_iter()
            .any(|slot| slot.as_ref().is_some_and(|o| o.get_id() == id))
    }

    fn take_observers(&mut self) -> Vec<ActorRef<JiraObserverMessage>> {
        [
            self.projects.take(),
            self.groups.take(),
            self.users.take(),
            self.issues.take(),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    /// Stops every running observer and waits for each, bounded. A timeout
    /// is logged rather than fatal: the process is about to exit or the
    /// observers are about to be rebuilt either way.
    async fn stop_observers(&mut self, reason: &str) {
        for observer in self.take_observers() {
            if let Err(e) = observer
                .stop_and_wait(Some(reason.to_string()), Some(OBSERVER_STOP_TIMEOUT))
                .await
            {
                warn!("OBSERVER_SUPERVISOR: observer did not stop cleanly: {e:?}");
            }
        }
    }

    /// Holds `reason` with `message` for the supervisor itself.
    fn hold(&mut self, reason: HoldReason, message: String) {
        error!("{message}");
        self.healthcheck.hold(reason, message);
        self.held = Some(reason);
    }
}

impl ObserverSupervisor {
    /// Starts the observers once Cassini has registered the agent, with the credential if one is needed: without
    /// one, nothing is pulled and the supervisor holds `Credentials` until a `credentials` section brings one.
    async fn start_observers(
        myself: &ActorRef<ObserverSupervisorMessage>,
        state: &mut ObserverSupervisorState,
    ) -> Result<(), ActorProcessingErr> {
        if !state.registered {
            return Ok(());
        }
        match state.auth() {
            None => {
                let message = match &state.credential_problem {
                    Some(why) => format!("jira-observer: {why}"),
                    None => NO_CREDENTIAL.to_string(),
                };
                state.hold(HoldReason::Credentials, message);
                Ok(())
            }
            Some(auth) => {
                if let Some(reason) = state.held.take() {
                    state.healthcheck.release(reason);
                }
                ObserverSupervisor::spawn_observers(myself, state, auth).await
            }
        }
    }

    /// Stops the observers and starts them again with what is in force now. A standing problem an observer held goes
    /// with it, so every hold is released first; an observer that meets it again holds it again.
    async fn restart_observers(
        myself: &ActorRef<ObserverSupervisorMessage>,
        state: &mut ObserverSupervisorState,
        why: &str,
    ) -> Result<(), ActorProcessingErr> {
        info!("OBSERVER_SUPERVISOR: starting the observers again: {why}");
        state.stop_observers(why).await;
        state.healthcheck.release(HoldReason::Credentials);
        state.healthcheck.release(HoldReason::Configuration);
        state.held = None;
        ObserverSupervisor::start_observers(myself, state).await
    }

    /// The supervisor follows the observers' settings as one value, so that an update to several is one start. The
    /// answer is the value in force. An update that could not work never gets here: the agent's judge refused it
    /// (`crate::agent::settings_work`).
    async fn follow_settings(
        configuration: &ConfigurationHandle,
        myself: &ActorRef<ObserverSupervisorMessage>,
    ) -> Result<Prepared, polar_agent_builder::configuration::FollowError> {
        configuration
            .follow_group(
                crate::settings::VARIABLES,
                crate::agent::prepare,
                myself,
                ObserverSupervisorMessage::SettingsChanged,
            )
            .await
    }

    /// Starts whichever observers are not running. Safe to call on every
    /// Registered: a reconnect finds the slots full and starts nothing.
    async fn spawn_observers(
        myself: &ActorRef<ObserverSupervisorMessage>,
        state: &mut ObserverSupervisorState,
        auth: JiraAuth,
    ) -> Result<(), ActorProcessingErr> {
        let args = state.observer_args(auth);

        if state.projects.is_none() {
            let (observer, _) = Actor::spawn_linked(
                Some(JIRA_PROJECT_OBSERVER.to_string()),
                JiraProjectObserver,
                args.clone(),
                myself.clone().into(),
            )
            .await?;
            state.projects = Some(observer);
        }
        if state.groups.is_none() {
            let (observer, _) = Actor::spawn_linked(
                Some(JIRA_GROUP_OBSERVER.to_string()),
                JiraGroupObserver,
                args.clone(),
                myself.clone().into(),
            )
            .await?;
            state.groups = Some(observer);
        }
        // Reading anonymously the users observer is not started (DECIDED, to review): a Data Center lists users only
        // to a login (Apache answers 401 to the user search and 404 to the picker), so it could only hold Credentials.
        if state.users.is_none() && !state.prepared.anonymous {
            let (observer, _) = Actor::spawn_linked(
                Some(JIRA_USER_OBSERVER.to_string()),
                JiraUserObserver,
                args.clone(),
                myself.clone().into(),
            )
            .await?;
            state.users = Some(observer);
        }
        if state.issues.is_none() {
            let (observer, _) = Actor::spawn_linked(
                Some(JIRA_ISSUE_OBSERVER.to_string()),
                JiraIssueObserver,
                args,
                myself.clone().into(),
            )
            .await?;
            state.issues = Some(observer);
        }
        Ok(())
    }
}

#[async_trait]
impl Actor for ObserverSupervisor {
    type Msg = ObserverSupervisorMessage;
    type State = ObserverSupervisorState;
    type Arguments = ObserverSupervisorArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: ObserverSupervisorArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        debug!("{myself:?} starting");

        // Health check, router, broker client and CryptoActor in one call. Observers only
        // depend on Cassini, which is the default capability; the issue
        // observer's soft state comes with the state actor the builder starts.
        let (resources, registered) = match args.infrastructure {
            Infrastructure::Build(configured) => (
                AgentBuilder::new(myself.clone(), BROKER_CLIENT_NAME)
                    .with_lifecycle_handler(|event| {
                        Some(ObserverSupervisorMessage::ClientEvent { event })
                    })
                    .into_configured(configured)
                    .build()
                    .await?,
                false,
            ),
            // Its lifecycle events go to the held supervisor that built it, and to whoever subscribes.
            Infrastructure::Built {
                resources,
                registered,
            } => {
                resources.events_output.subscribe(myself.clone(), |event| {
                    Some(ObserverSupervisorMessage::ClientEvent { event })
                });
                (resources, registered)
            }
        };

        resources
            .infrastructure_events
            .subscribe(myself.clone(), |event| match event {
                InfrastructureEvent::PrepareShutdown => {
                    Some(ObserverSupervisorMessage::PrepareShutdown)
                }
            });
        let prepared =
            ObserverSupervisor::follow_settings(&resources.configuration, &myself).await?;
        let protocols = resources.protocols.clone().ok_or(
            "the builder gave no protocol handler, which this agent declares operations for",
        )?;
        protocols
            .credentials_applied()
            .subscribe(myself.clone(), |applied| {
                Some(ObserverSupervisorMessage::CredentialsApplied(applied))
            });

        Ok(ObserverSupervisorState {
            prepared,
            protocols,
            tcp_client: resources.tcp_client,
            state: resources
                .state
                .map(|handle| Arc::new(handle) as Arc<dyn StateClient>),
            healthcheck: resources.healthcheck,
            credential: false,
            credential_problem: None,
            registered,
            held: None,
            infrastructure: resources.infrastructure,
            projects: None,
            groups: None,
            users: None,
            issues: None,
        })
    }

    async fn post_start(
        &self,
        myself: ActorRef<Self::Msg>,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        // A section that reached the CryptoActor before the subscription.
        if let Some(applied) = state.protocols.credentials_in_force() {
            state.credentials_applied(&applied);
        }
        // Built by a held supervisor after Cassini registered the agent: no `Registered` comes again.
        ObserverSupervisor::start_observers(&myself, state).await
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            ObserverSupervisorMessage::PrepareShutdown => {
                info!(
                    "OBSERVER_SUPERVISOR: PrepareShutdown received, stopping observers \
                     before infrastructure"
                );
                state.stop_observers("rejuvenation").await;

                let _ = state
                    .infrastructure
                    .cast(InfrastructureSupervisorMessage::ProceedWithShutdown);
            }
            ObserverSupervisorMessage::SettingsChanged(prepared) => {
                crate::agent::log_anonymous(&prepared);
                state.prepared = prepared;
                ObserverSupervisor::restart_observers(
                    &myself,
                    state,
                    "a signed update changed the settings",
                )
                .await?;
            }
            ObserverSupervisorMessage::CredentialsApplied(applied) => {
                state.credentials_applied(&applied);
                ObserverSupervisor::restart_observers(
                    &myself,
                    state,
                    "a new version of the credentials section",
                )
                .await?;
            }
            ObserverSupervisorMessage::ClientEvent { event } => match event {
                ClientEvent::Registered { .. } => {
                    let _ = state.healthcheck.cassini_connected();
                    state.registered = true;
                    ObserverSupervisor::start_observers(&myself, state).await?;
                }
                ClientEvent::MessagePublished { .. } => {
                    warn!("OBSERVER_SUPERVISOR: unexpected MessagePublished event, ignoring");
                }
                // The broker ended its session while it was away: the issue observer pulls from the graph's cursor
                // next (what it was owed is lost).
                ClientEvent::SessionEnded {
                    registration_id,
                    reason,
                } => {
                    warn!(%registration_id, "the broker ended this agent's session: {reason}");
                    if let Some(issues) = &state.issues {
                        let _ = issues.cast(JiraObserverMessage::Resync);
                    }
                }
                ClientEvent::TransportError { reason } => {
                    warn!("Transport error occurred (non-fatal, awaiting reconnect): {reason}");
                    let _ = state.healthcheck.cassini_disconnected();
                }
                _ => (),
            },
        }
        Ok(())
    }

    async fn handle_supervisor_evt(
        &self,
        _myself: ActorRef<Self::Msg>,
        msg: SupervisionEvent,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match msg {
            SupervisionEvent::ActorStarted(_) => (),
            SupervisionEvent::ActorTerminated(actor_cell, _, reason) => {
                let actor_name = actor_cell.get_name().unwrap_or_default();

                // InfrastructureSupervisor finishing is the end of the
                // shutdown handshake. Exit non-zero so the Job controller
                // starts a new pod with fresh certs.
                if actor_cell.get_id() == state.infrastructure.get_id() {
                    info!(
                        "OBSERVER_SUPERVISOR: infrastructure shutdown complete, exiting for rejuvenation"
                    );
                    std::process::exit(1);
                }

                // An observer we still expect to be running stopped on its
                // own. A failure in talking to Jira, a rejected token among
                // them, never stops one (it is retried, or held through the
                // agent's health), so this is something else gone wrong, and
                // a visible pod restart is the signal.
                if state.tracks(actor_cell.get_id()) {
                    error!(
                        "OBSERVER_SUPERVISOR: observer {actor_name:?} stopped unexpectedly: {reason:?}"
                    );
                    std::process::exit(1);
                }

                debug!("OBSERVER_SUPERVISOR: {actor_name:?} stopped as requested: {reason:?}");
            }
            SupervisionEvent::ActorFailed(actor_cell, e) => {
                error!(
                    "OBSERVER_SUPERVISOR: {0:?}:{1:?} failed! {e:?}",
                    actor_cell.get_name(),
                    actor_cell.get_id()
                );
                std::process::exit(1);
            }
            SupervisionEvent::ProcessGroupChanged(..) => (),
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_crypto::{FakeCrypto, Gives};
    use crate::test_health::{Told, health_recorder, told};
    use polar_agent_builder::HoldReason;
    use polar_agent_builder::protocol::testing::Site;
    use serde_json::json;

    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Takes any message and drops it: the supervisor's own reference, its infrastructure and its broker client, in a
    /// test of what it starts.
    struct Sink<M>(std::marker::PhantomData<fn() -> M>);

    #[async_trait]
    impl<M: ractor::Message> Actor for Sink<M> {
        type Msg = M;
        type State = ();
        type Arguments = ();

        async fn pre_start(
            &self,
            _myself: ActorRef<M>,
            _args: (),
        ) -> Result<(), ActorProcessingErr> {
            Ok(())
        }
    }

    async fn sink<M: ractor::Message>() -> ActorRef<M> {
        Actor::spawn(None, Sink::<M>(std::marker::PhantomData), ())
            .await
            .unwrap()
            .0
    }

    /// The supervisor's state as `pre_start` makes it, for a site at `url` (a stand-in is reached through TLS), read
    /// anonymously or with a credential if `credential`, as `crypto` gives it, its health `health`, Cassini registered.
    async fn supervisor_state(
        url: String,
        anonymous: bool,
        credential: bool,
        crypto: FakeCrypto,
        health: ActorRef<polar_health::HealthCheckMessage>,
    ) -> (ObserverSupervisorState, Site) {
        let url = crate::test_crypto::behind_tls(&url).await;
        let site = crate::test_crypto::handler(&url, crypto).await;
        let state = ObserverSupervisorState {
            prepared: Prepared {
                jira_url: url,
                anonymous,
                deployment: crate::JiraDeployment::ServerOrDataCenter,
                query_date: None,
                poll_secs: 3600,
                page_size: 50,
            },
            protocols: site.handle.clone(),
            tcp_client: TcpClient::from_actor_ref(sink().await),
            state: None,
            healthcheck: HealthHandle::new(health),
            credential,
            credential_problem: None,
            registered: true,
            held: None,
            infrastructure: sink().await,
            projects: None,
            groups: None,
            users: None,
            issues: None,
        };
        (state, site)
    }

    /// The observers are registered by name, so the tests that start them take turns.
    static NAMED: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn running(state: &ObserverSupervisorState) -> usize {
        [&state.projects, &state.groups, &state.users, &state.issues]
            .iter()
            .filter(|slot| slot.is_some())
            .count()
    }

    /// Without a credential, and not reading anonymously, nothing is asked of Jira: the supervisor starts no observer
    /// and holds `Credentials`, saying to sign a credentials section. One arriving releases it, and the observers
    /// start with it, asking the CryptoActor for the site's host.
    #[tokio::test]
    async fn without_a_credential_it_holds_and_a_credential_arriving_starts_the_observers() {
        let _turn = NAMED.lock().await;
        let server = site_without_data().await;
        let (health, recorded) = health_recorder().await;
        let crypto = FakeCrypto::giving(Gives::Bearer("t0ken"));
        let (mut state, _site) =
            supervisor_state(server.uri(), false, false, crypto.clone(), health.clone()).await;
        let myself = sink::<ObserverSupervisorMessage>().await;

        ObserverSupervisor::start_observers(&myself, &mut state)
            .await
            .unwrap();
        assert_eq!(running(&state), 0);
        assert_eq!(
            told(&health, &recorded).await,
            [Told::Hold(
                HoldReason::Credentials,
                NO_CREDENTIAL.to_string()
            )]
        );
        assert!(server.received_requests().await.unwrap().is_empty());

        state.credential = true;
        ObserverSupervisor::restart_observers(&myself, &mut state, "a new credential")
            .await
            .unwrap();
        assert_eq!(running(&state), 4);
        let after = told_at_least(&health, &recorded, 3).await;
        assert_eq!(after[1], Told::Release(HoldReason::Credentials));
        assert!(
            crypto
                .asked
                .lock()
                .unwrap()
                .iter()
                .all(|(name, host)| name == "jira" && host == "localhost")
        );
        assert!(!crypto.asked.lock().unwrap().is_empty());
        state.stop_observers("the test is over").await;
    }

    /// Reading anonymously, the users observer is not started: a Data Center lists users only to a login. The other
    /// three are, groups among them (anonymously a Data Center answers no groups, not a refusal).
    #[tokio::test]
    async fn reading_anonymously_the_users_observer_is_not_started() {
        let _turn = NAMED.lock().await;
        let server = site_without_data().await;
        let (health, _) = health_recorder().await;
        let (mut state, _site) = supervisor_state(
            server.uri(),
            true,
            false,
            FakeCrypto::giving(Gives::NotRegistered),
            health,
        )
        .await;
        let myself = sink::<ObserverSupervisorMessage>().await;
        ObserverSupervisor::start_observers(&myself, &mut state)
            .await
            .unwrap();
        assert!(state.users.is_none());
        assert!(state.projects.is_some() && state.groups.is_some() && state.issues.is_some());
        state.stop_observers("the test is over").await;
    }

    /// Starting again (a new credential, new settings) stops every observer first, releases every hold, since the
    /// observers that held are gone, and starts new ones, which hold again what they meet again.
    #[tokio::test]
    async fn starting_again_releases_every_hold_and_starts_new_observers() {
        let _turn = NAMED.lock().await;
        let server = site_without_data().await;
        let (health, recorded) = health_recorder().await;
        let (mut state, _site) = supervisor_state(
            server.uri(),
            false,
            true,
            FakeCrypto::giving(Gives::Bearer("t0ken")),
            health.clone(),
        )
        .await;
        let myself = sink::<ObserverSupervisorMessage>().await;
        ObserverSupervisor::start_observers(&myself, &mut state)
            .await
            .unwrap();
        let before: Vec<ActorId> = [&state.projects, &state.issues]
            .iter()
            .map(|o| o.as_ref().unwrap().get_id())
            .collect();
        // Each of the four is told 404 on what it pulls, and holds it.
        told_at_least(&health, &recorded, 4).await;

        ObserverSupervisor::restart_observers(&myself, &mut state, "new settings")
            .await
            .unwrap();
        let after: Vec<ActorId> = [&state.projects, &state.issues]
            .iter()
            .map(|o| o.as_ref().unwrap().get_id())
            .collect();
        assert!(before.iter().all(|id| !after.contains(id)), "new observers");
        let told = told_at_least(&health, &recorded, 10).await;
        assert_eq!(
            told[4..6],
            [
                Told::Release(HoldReason::Credentials),
                Told::Release(HoldReason::Configuration)
            ]
        );
        assert!(
            told[6..]
                .iter()
                .all(|t| matches!(t, Told::Hold(HoldReason::Configuration, _))),
            "{told:?}"
        );
        state.stop_observers("the test is over").await;
    }

    /// The live configuration, as the builder gives it, holding `pairs`: what `current()` answers.
    async fn configuration_of(pairs: &[(&str, &str)]) -> ConfigurationHandle {
        let env: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let config = polar_env::Config::builder(&env)
            .register(&crate::settings::SECTION)
            .register(&polar::egress::SECTION)
            .build();
        let parent = sink::<()>().await;
        ConfigurationHandle::spawn(None, BROKER_CLIENT_NAME, config, None, parent.get_cell())
            .await
            .unwrap()
    }

    /// Each of the settings reaches the supervisor: it follows them all, and what it is told depends on each.
    #[tokio::test]
    async fn every_setting_is_followed_and_what_the_observers_get_depends_on_each() {
        let configuration = configuration_of(&[("JIRA_URL", "https://jira.invalid")]).await;
        let myself = sink::<ObserverSupervisorMessage>().await;
        let prepared = ObserverSupervisor::follow_settings(&configuration, &myself)
            .await
            .unwrap();
        assert_eq!(prepared.jira_url, "https://jira.invalid");
        assert_eq!(
            configuration
                .dynamic_settings_problems(&[&crate::settings::SECTION])
                .await
                .unwrap(),
            Vec::<String>::new()
        );
    }

    /// The observers start with what the settings say of the poll and the page.
    #[tokio::test]
    async fn the_observers_are_given_the_poll_and_the_page_in_force() {
        let (health, _) = health_recorder().await;
        let (mut state, _site) = supervisor_state(
            "http://jira.invalid".into(),
            true,
            false,
            FakeCrypto::giving(Gives::NotRegistered),
            health,
        )
        .await;
        state.prepared.poll_secs = 90;
        state.prepared.page_size = 7;
        let args = state.observer_args(JiraAuth::Anonymous);
        assert_eq!(args.base_interval, 90);
        assert_eq!(args.page_size, 7);
    }

    /// New settings start the observers again, whatever they held released, and they ask the site now in force.
    #[tokio::test]
    async fn new_settings_start_the_observers_again_at_the_site_now_in_force() {
        let _turn = NAMED.lock().await;
        let server = site_without_data().await;
        let (health, recorded) = health_recorder().await;
        let (mut state, site) = supervisor_state(
            "http://jira.invalid".into(),
            true,
            false,
            FakeCrypto::giving(Gives::NotRegistered),
            health.clone(),
        )
        .await;
        let myself = sink::<ObserverSupervisorMessage>().await;
        ObserverSupervisor::start_observers(&myself, &mut state)
            .await
            .unwrap();
        // Read anonymously: three, the users observer not among them.
        assert_eq!(running(&state), 3);
        let before = told(&health, &recorded).await;

        let mended = crate::test_crypto::behind_tls(&server.uri()).await;
        site.set("JIRA_URL", mended.clone());
        let prepared = Prepared {
            jira_url: mended.clone(),
            ..state.prepared.clone()
        };
        ObserverSupervisor
            .handle(
                myself.clone(),
                ObserverSupervisorMessage::SettingsChanged(prepared),
                &mut state,
            )
            .await
            .unwrap();
        assert_eq!(running(&state), 3);
        assert_eq!(state.prepared.jira_url, mended);
        let after = told(&health, &recorded).await;
        assert!(
            after[before.len()..].contains(&Told::Release(HoldReason::Configuration)),
            "{after:?}"
        );
        // And they ask the new site.
        for _ in 0..100 {
            if !server.received_requests().await.unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!server.received_requests().await.unwrap().is_empty());
        state.stop_observers("the test is over").await;
    }

    /// What the handler says became of a version decides whether the observers have their credential: an entry called
    /// `jira`. Any other leaves none, and the supervisor says why when it holds.
    #[tokio::test]
    async fn the_credentials_section_gives_the_credential_or_says_why_not() {
        let (health, recorded) = health_recorder().await;
        let crypto = FakeCrypto::giving(Gives::Bearer("t0ken"));
        let (mut state, _site) = supervisor_state(
            "http://jira.invalid".into(),
            false,
            false,
            crypto.clone(),
            health.clone(),
        )
        .await;
        let version = |version, registered: &[&str], failed: &[(&str, &str)]| CredentialsApplied {
            version,
            registered: registered.iter().map(|name| name.to_string()).collect(),
            failed: failed
                .iter()
                .map(|(name, why)| (name.to_string(), why.to_string()))
                .collect(),
            withdrawn: Vec::new(),
        };
        let myself = sink::<ObserverSupervisorMessage>().await;

        state.credentials_applied(&version(3, &["jira"], &[]));
        assert!(state.credential);
        assert_eq!(state.credential_problem, None);

        // Registered under a name the observer does not present: what to do about it.
        state.credentials_applied(&version(4, &["jira-dc"], &[]));
        assert!(!state.credential);
        ObserverSupervisor::start_observers(&myself, &mut state)
            .await
            .unwrap();
        let said = told(&health, &recorded).await;
        let Some(Told::Hold(HoldReason::Credentials, message)) = said.last() else {
            panic!("a hold: {said:?}");
        };
        assert!(message.contains("no entry named `jira`"), "{message}");

        // The CryptoActor would not take it.
        state.credentials_applied(&version(5, &[], &[("jira", "it does not open")]));
        assert!(!state.credential);
        ObserverSupervisor::start_observers(&myself, &mut state)
            .await
            .unwrap();
        let said = told(&health, &recorded).await;
        let Some(Told::Hold(HoldReason::Credentials, message)) = said.last() else {
            panic!("a hold: {said:?}");
        };
        assert!(message.contains("version 5"), "{message}");
        assert!(message.contains("it does not open"), "{message}");

        // A version with no entry withdraws it, and it is then as if none had come.
        state.credentials_applied(&version(6, &[], &[]));
        assert!(!state.credential);
        assert_eq!(state.credential_problem, None);
        assert_eq!(running(&state), 0);
    }

    /// A site that answers who the token is and what it is, and 404 to everything else.
    async fn site_without_data() -> MockServer {
        let server = MockServer::start().await;
        for (endpoint, body) in [
            (
                "/rest/api/2/myself",
                json!({ "name": "svc-polar", "key": "JIRAUSER10100" }),
            ),
            (
                "/rest/api/2/serverInfo",
                json!({ "deploymentType": "Server" }),
            ),
        ] {
            Mock::given(method("GET"))
                .and(wiremock::matchers::path(endpoint))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        server
    }

    /// Waits up to five seconds for the health actor to have been told `count` things.
    async fn told_at_least(
        health: &ActorRef<polar_health::HealthCheckMessage>,
        recorded: &std::sync::Arc<std::sync::Mutex<Vec<Told>>>,
        count: usize,
    ) -> Vec<Told> {
        for _ in 0..250 {
            let now = told(health, recorded).await;
            if now.len() >= count {
                return now;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        told(health, recorded).await
    }

    /// The observers it starts hold what a retry cannot fix through the agent's own health: the supervisor's
    /// `resources.healthcheck`.
    #[tokio::test]
    async fn the_observers_hold_through_the_agent_s_health() {
        let _turn = NAMED.lock().await;
        let server = site_without_data().await;
        let (health, recorded) = health_recorder().await;
        let (mut state, _site) = supervisor_state(
            server.uri(),
            false,
            true,
            FakeCrypto::giving(Gives::Bearer("t0ken")),
            health.clone(),
        )
        .await;
        let myself = sink::<ObserverSupervisorMessage>().await;
        ObserverSupervisor::start_observers(&myself, &mut state)
            .await
            .unwrap();

        // Each of the four is told 404 on what it pulls.
        let told = told_at_least(&health, &recorded, 4).await;
        let mut held: Vec<&str> = told
            .iter()
            .map(|t| match t {
                Told::Hold(HoldReason::Configuration, message) => {
                    message.split(':').next().unwrap_or_default()
                }
                other => panic!("{other:?}"),
            })
            .collect();
        held.sort();
        assert_eq!(
            held,
            [
                JIRA_GROUP_OBSERVER,
                JIRA_ISSUE_OBSERVER,
                JIRA_PROJECT_OBSERVER,
                JIRA_USER_OBSERVER
            ]
        );
        state.stop_observers("the test is over").await;
    }
}
