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

//! An agent that refuses its own configuration at start, and stays up (docs/architecture/soft-state.md, "As built:
//! pulled health"). A problem a restart does not help (an address that is a placeholder) used to end the agent, and
//! the pod's rule restarted every container, in a loop. Instead the agent starts its infrastructure and nothing of its
//! domain, holds the problem ([`crate::HealthHandle::hold`]), answers health queries with it, rejuvenates as any
//! agent does, and ends only by its health actor's verdict or a signal.
//!
//! It does not only wait. A signed update can change what the agent refused (its Dynamic settings), and the scheduler
//! replays the signed documents to an agent that has just registered, so after every restart the render's
//! environment applies first and the update arrives just after. On each change the ConfigurationActor announces, the
//! agent's [`TryAgain`] is called with the configuration in force and the resources already built: it judges the
//! configuration again and, if it can work, starts the agent's work, linked under this supervisor, and the hold is
//! released. An update that leaves the problem in place keeps the hold, with the new message. Once the work runs it
//! takes the agent's client events itself ([`crate::AgentResources::events_output`]); the notice that the agent is
//! ending comes to this supervisor, which registered for it, and goes on to the work ([`WorkStarted`]), which answers
//! it. This supervisor only ends with the infrastructure or the work.
//!
//! In `PolarAgent::start`: `return polar_agent_builder::held::stay_up(configured, NAME, HoldReason::Configuration,
//! why, try_again).await;`

use crate::{AgentBuilder, AgentResources, Configured, InfrastructureSupervisorMessage};
use cassini_types::ClientEvent;
use polar_health::HoldReason;
use ractor::{Actor, ActorCell, ActorProcessingErr, ActorRef, SupervisionEvent, async_trait};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// What a held agent is given when it is asked to try again.
pub struct Retry {
    /// The configuration in force now, every signed update applied.
    pub config: Arc<polar_env::Config>,
    /// The agent's infrastructure, already built: the work it starts takes its events from here.
    pub resources: AgentResources,
    /// The supervisor to link the work under, so that its ending ends the agent.
    pub supervisor: ActorCell,
    /// Whether Cassini has registered the agent already: the work will not see that `Registered` again.
    pub cassini_registered: bool,
}

/// The work a held agent started, and how to tell it the agent is ending: it drains, then sends the infrastructure
/// `ProceedWithShutdown` itself, as an agent that registered `AgentBuilder::with_drain` does.
pub struct WorkStarted {
    tell: Arc<dyn Fn() + Send + Sync>,
}

impl WorkStarted {
    /// The work is `work`, told with its own `message`.
    pub fn told<M: ractor::Message>(
        work: ActorRef<M>,
        message: impl Fn() -> M + Send + Sync + 'static,
    ) -> Self {
        Self {
            tell: Arc::new(move || {
                if let Err(e) = work.cast(message()) {
                    tracing::warn!(
                        "the held agent's work could not be told the agent is ending: {e}"
                    );
                }
            }),
        }
    }
}

/// The agent's way out of a hold: judge `Retry::config` again and, if it can work, start the work and say how to tell
/// it the agent is ending; if it still cannot, say why, which becomes the hold's message.
pub type TryAgain = Box<
    dyn Fn(Retry) -> Pin<Box<dyn Future<Output = Result<WorkStarted, String>> + Send>>
        + Send
        + Sync,
>;

/// A [`TryAgain`] that never gets out: for an agent whose refusal no update can mend.
pub fn never() -> TryAgain {
    Box::new(|_| Box::pin(async { Err("no update can mend this".to_string()) }))
}

/// Runs the agent `service_name` with its infrastructure only, holding `reason` with `message`, until it is told to end,
/// and on each configuration change asks `try_again` whether the agent can start its work now.
/// Returns an error then, as every agent's `start` does: an agent that ends has failed.
pub async fn stay_up(
    configured: Configured,
    service_name: &str,
    reason: HoldReason,
    message: impl Into<String>,
    try_again: TryAgain,
) -> Result<(), crate::StartError> {
    let message = message.into();
    tracing::error!(
        "{service_name} cannot start its work, and stays up to say so (a restart would not help): {message}"
    );
    let (_supervisor, handle) = Actor::spawn(
        Some(format!("{service_name}.held")),
        HeldSupervisor,
        HeldArgs {
            configured,
            service_name: service_name.to_string(),
            reason,
            message,
            try_again,
        },
    )
    .await
    .map_err(|e| format!("the held supervisor did not start: {e}"))?;
    handle
        .await
        .map_err(|e| format!("the held supervisor's task failed: {e}"))?;
    Err(format!("{service_name} held a standing problem and has ended").into())
}

pub(crate) struct HeldArgs {
    configured: Configured,
    service_name: String,
    reason: HoldReason,
    message: String,
    try_again: TryAgain,
}

pub(crate) enum HeldMessage {
    Client(ClientEvent),
    PrepareShutdown,
    /// A signed update changed the configuration.
    ConfigChanged,
}

pub(crate) struct HeldState {
    service_name: String,
    reason: HoldReason,
    resources: AgentResources,
    try_again: TryAgain,
    /// Cassini has registered the agent, and has not dropped it since.
    registered: bool,
    /// The work, once it has started: it takes the agent's events, and answers the shutdown it is told of.
    work: Option<WorkStarted>,
}

impl HeldState {
    pub(crate) fn new(
        service_name: String,
        reason: HoldReason,
        resources: AgentResources,
        try_again: TryAgain,
    ) -> Self {
        Self {
            service_name,
            reason,
            resources,
            try_again,
            registered: false,
            work: None,
        }
    }

    /// The configuration changed: while held, the agent is asked whether it can start its work now. It does, and the
    /// hold is released; or it cannot, and the hold stays, with its new message.
    pub(crate) async fn configuration_changed(&mut self, supervisor: ActorCell) {
        if self.work.is_some() {
            return;
        }
        let config = match self.resources.configuration.current().await {
            Ok(config) => config,
            Err(e) => {
                tracing::warn!(
                    "{}: the configuration in force could not be read: {e}",
                    self.service_name
                );
                return;
            }
        };
        let retry = Retry {
            config,
            resources: self.resources.clone(),
            supervisor,
            cassini_registered: self.registered,
        };
        match (self.try_again)(retry).await {
            Ok(work) => {
                tracing::info!(
                    "{}: a signed update mended what held it; its work has started",
                    self.service_name
                );
                self.work = Some(work);
                self.resources.healthcheck.release(self.reason);
            }
            Err(why) => {
                tracing::error!(
                    "{}: still held after a signed update: {why}",
                    self.service_name
                );
                self.resources.healthcheck.hold(self.reason, why);
            }
        }
    }

    /// The infrastructure asks the agent to finish: a held agent has nothing to finish and lets it go at once, unless
    /// its work runs, which is told and answers for itself. True if this supervisor let it go.
    pub(crate) fn prepare_shutdown(&self) -> bool {
        if let Some(work) = &self.work {
            (work.tell)();
            return false;
        }
        let _ = self
            .resources
            .infrastructure
            .cast(InfrastructureSupervisorMessage::ProceedWithShutdown);
        true
    }
}

/// The domain supervisor of an agent that holds a standing problem: until its work starts it has no domain, so it only
/// tells the health actor about Cassini, lets the infrastructure go at once when told to end, and asks the agent to
/// try again on each configuration change.
pub(crate) struct HeldSupervisor;

#[async_trait]
impl Actor for HeldSupervisor {
    type Msg = HeldMessage;
    type State = HeldState;
    type Arguments = HeldArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: HeldArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        let resources = AgentBuilder::new(myself.clone(), args.service_name.clone())
            .with_lifecycle_handler(|event| Some(HeldMessage::Client(event)))
            .with_drain(|| HeldMessage::PrepareShutdown)
            .into_configured(args.configured)
            .build()
            .await?;
        resources.healthcheck.hold(args.reason, args.message);
        resources
            .configuration
            .changes()
            .subscribe(myself.clone(), |_| Some(HeldMessage::ConfigChanged));
        // Any change asks the agent to try again, so while it is held nothing goes unfollowed.
        let dynamic = resources
            .configuration
            .current()
            .await?
            .describe()
            .into_iter()
            .flat_map(|(_, variables)| variables)
            .filter(|variable| variable.mutability == polar_env::Mutability::Dynamic)
            .map(|variable| variable.name)
            .collect();
        resources
            .configuration
            .followed_by(dynamic, myself.get_cell())
            .await?;
        Ok(HeldState::new(
            args.service_name,
            args.reason,
            resources,
            args.try_again,
        ))
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        use crate::HealthClient;
        match message {
            HeldMessage::Client(ClientEvent::Registered { .. }) => {
                state.registered = true;
                if state.work.is_none() {
                    let _ = state.resources.healthcheck.cassini_connected();
                }
            }
            HeldMessage::Client(ClientEvent::TransportError { .. }) => {
                state.registered = false;
                if state.work.is_none() {
                    let _ = state.resources.healthcheck.cassini_disconnected();
                }
            }
            HeldMessage::Client(_) => {}
            HeldMessage::PrepareShutdown => {
                state.prepare_shutdown();
            }
            HeldMessage::ConfigChanged => {
                state.configuration_changed(myself.get_cell()).await;
            }
        }
        Ok(())
    }

    async fn handle_supervisor_evt(
        &self,
        myself: ActorRef<Self::Msg>,
        event: SupervisionEvent,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        // The infrastructure's ending is the end of the shutdown handshake, or a failure; the work's ending, once it
        // runs, is the agent's end too.
        if let SupervisionEvent::ActorTerminated(actor, ..)
        | SupervisionEvent::ActorFailed(actor, _) = event
        {
            if actor.get_id() == state.resources.infrastructure.get_id() {
                myself.stop(Some("the infrastructure has ended".to_string()));
            } else if state.work.is_some() {
                myself.stop(Some("the agent's work has ended".to_string()));
            }
        }
        Ok(())
    }
}
