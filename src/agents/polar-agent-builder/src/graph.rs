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

//! An agent's graph controller. The builder starts it under the infrastructure supervisor for an
//! agent that needs `graph-write` or `graph-read`, as it starts the crypto actor: from the
//! snapshot, with the constraints and repairs the agent declared, its signals going to the health
//! actor by how the agent uses the graph, and drained at the end, before the rest of the
//! infrastructure stops. The agent writes through its [`GraphHandle`].
//!
//! Also here, for a supervisor with a drain of its own (the build orchestrator's): the [`Drain`]
//! that precedes its exit or its handover to the infrastructure supervisor.

use crate::infrastructure::InfrastructureSupervisorMessage;
use polar::graph::controller::{
    GraphControllerActor, GraphControllerArgs, GraphControllerMsg, GraphOp, GraphSignal,
};
use polar::graph::environment::GraphSettings;
use polar::graph::repair::Repair;
use polar::graph::schema::KeyIndex;
use polar_health::HealthCheckMessage;
use ractor::concurrency::Duration;
use ractor::{Actor, ActorProcessingErr, ActorRef, Message, OutputPort};
use std::sync::Arc;
use tracing::{error, info, warn};

/// How long the graph controller has, at the end, to write what is queued before the rest of the
/// infrastructure stops. Part of the least shutdown budget of an agent whose controller the
/// builder starts.
pub const GRAPH_DRAIN: Duration = Duration::from_secs(30);

/// How an agent uses the graph, which decides what its health makes of the graph's signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphUse {
    /// It writes (`graph-write`): it is no use without the graph, so a graph that fails its
    /// writes long enough ends it (`POLAR_HEALTH_GRAPH_DEADLINE_SECS`).
    Writes,
    /// It reads (`graph-read`): it stays up while the graph is down, answers that it cannot
    /// read, and its health says the graph is not connected.
    Reads,
}

/// What the health actor is told of a signal from the graph controller.
pub(crate) fn health_message(uses: GraphUse, signal: GraphSignal) -> HealthCheckMessage {
    match (uses, signal) {
        (_, GraphSignal::Available) => HealthCheckMessage::GraphAvailable,
        (GraphUse::Writes, GraphSignal::OpFailed(reason)) => {
            HealthCheckMessage::GraphOpFailed(reason)
        }
        (GraphUse::Reads, GraphSignal::OpFailed(_)) => HealthCheckMessage::GraphDisconnected,
    }
}

/// What the infrastructure supervisor starts the controller with.
pub(crate) struct GraphSetup {
    pub(crate) uses: GraphUse,
    pub(crate) settings: GraphSettings,
    pub(crate) key_indexes: Vec<KeyIndex>,
    pub(crate) repairs: Vec<Repair>,
}

/// Starts the agent's graph controller under `supervisor`, its signals reported to `health` as
/// the agent uses the graph. The controller only builds its pool here; `Available` is what proves
/// the graph answers.
pub(crate) async fn start_controller(
    name: String,
    setup: GraphSetup,
    health: ActorRef<HealthCheckMessage>,
    supervisor: ractor::ActorCell,
) -> Result<GraphHandle, ActorProcessingErr> {
    let port = Arc::new(OutputPort::<GraphSignal>::default());
    let uses = setup.uses;
    port.subscribe(health.clone(), move |signal| {
        Some(health_message(uses, signal))
    });
    let (controller, _) = Actor::spawn_linked(
        Some(name),
        GraphControllerActor,
        GraphControllerArgs::new(port)
            .with_settings(setup.settings)
            .with_key_indexes(setup.key_indexes)
            .with_repairs(setup.repairs),
        supervisor,
    )
    .await
    .map_err(ActorProcessingErr::from)?;
    if let Err(e) = health.cast(HealthCheckMessage::GraphConnected) {
        warn!("could not tell the health actor the graph controller started: {e}");
    }
    Ok(GraphHandle::new(controller))
}

/// The agent's way to its graph controller.
#[derive(Clone)]
pub struct GraphHandle {
    controller: ActorRef<GraphControllerMsg>,
}

/// A write the controller no longer takes: it is draining what was queued before the agent ends.
#[derive(Debug, thiserror::Error)]
#[error("the graph controller takes no more writes: the agent is ending")]
pub struct GraphClosed;

impl GraphHandle {
    /// A handle on `controller`: the builder's, or a stand-in in a test.
    pub fn new(controller: ActorRef<GraphControllerMsg>) -> Self {
        Self { controller }
    }

    /// Queues `op`. Refused once the controller is draining at the end.
    pub fn write(&self, op: GraphOp) -> Result<(), GraphClosed> {
        self.controller
            .cast(GraphControllerMsg::Op(op))
            .map_err(|_| GraphClosed)
    }

    /// Queues each of `ops` in order, stopping at the first refused.
    pub fn write_all(&self, ops: impl IntoIterator<Item = GraphOp>) -> Result<(), GraphClosed> {
        ops.into_iter().try_for_each(|op| self.write(op))
    }

    /// The controller itself, for code that talks to it directly.
    pub fn actor(&self) -> &ActorRef<GraphControllerMsg> {
        &self.controller
    }
}

/// Stops the controller once it has handled every write already queued, waiting up to `wait`. A
/// stop would come ahead of the queue and lose those writes; a drain is behind them. A controller
/// that does not finish in time is logged, not waited on: the process is about to end.
pub(crate) async fn stop_graph_controller(
    controller: ActorRef<GraphControllerMsg>,
    wait: Duration,
) {
    match controller.drain_and_wait(Some(wait)).await {
        Ok(()) => info!("graph controller stopped cleanly"),
        Err(e) => error!(
            "graph controller did not stop cleanly within {}s, exiting anyway: {e:?}",
            wait.as_secs()
        ),
    }
}

/// Where a supervisor is in coming down. Messages that arrive while `draining` are logged and not
/// processed, since whatever failed (likely the graph controller) cannot be trusted.
#[derive(Debug, Default)]
pub struct Drain {
    draining: bool,
    rejuvenating: bool,
}

impl Drain {
    pub fn is_draining(&self) -> bool {
        self.draining
    }

    /// True when the drain was begun by `PrepareShutdown`, so its end completes the handshake
    /// instead of exiting directly.
    pub fn is_rejuvenating(&self) -> bool {
        self.rejuvenating
    }

    /// Begins the drain: after `window`, `elapsed` is delivered to `supervisor`. A drain already
    /// under way is left alone, since its exit is pending.
    pub fn begin<M: Message>(
        &mut self,
        supervisor: &ActorRef<M>,
        window: Duration,
        rejuvenating: bool,
        elapsed: fn() -> M,
    ) -> bool {
        if self.draining {
            return false;
        }
        self.draining = true;
        self.rejuvenating = rejuvenating;
        drop(supervisor.send_after(window, elapsed));
        true
    }

    /// The end of the drain, once the supervisor has stopped its own children: after
    /// `PrepareShutdown` the infrastructure supervisor is told to proceed, otherwise the process
    /// exits 1 so the Job starts a fresh pod.
    pub fn complete(&self, infrastructure: &ActorRef<InfrastructureSupervisorMessage>) {
        if self.rejuvenating {
            info!("domain shutdown complete, releasing infrastructure");
            if let Err(e) =
                infrastructure.cast(InfrastructureSupervisorMessage::ProceedWithShutdown)
            {
                error!("could not tell infrastructure to proceed ({e}); exiting now");
                std::process::exit(1);
            }
        } else {
            warn!("exiting now");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer is made unhealthy by a graph that fails its writes long enough; a reader is only told the graph is not
    /// connected, and stays up; both are told when the graph answers.
    #[test]
    fn the_health_actor_hears_the_graph_as_the_agent_uses_it() {
        for uses in [GraphUse::Writes, GraphUse::Reads] {
            assert!(matches!(
                health_message(uses, GraphSignal::Available),
                HealthCheckMessage::GraphAvailable
            ));
        }
        assert!(matches!(
            health_message(GraphUse::Writes, GraphSignal::OpFailed("refused".into())),
            HealthCheckMessage::GraphOpFailed(reason) if reason == "refused"
        ));
        assert!(matches!(
            health_message(GraphUse::Reads, GraphSignal::OpFailed("refused".into())),
            HealthCheckMessage::GraphDisconnected
        ));
    }
    use std::sync::{Arc, Mutex};

    struct Probe;
    enum Msg {
        Elapsed,
    }

    #[ractor::async_trait]
    impl Actor for Probe {
        type Msg = Msg;
        type State = Arc<Mutex<u32>>;
        type Arguments = Arc<Mutex<u32>>;
        async fn pre_start(
            &self,
            _: ActorRef<Msg>,
            seen: Self::Arguments,
        ) -> Result<Self::State, ActorProcessingErr> {
            Ok(seen)
        }
        async fn handle(
            &self,
            _: ActorRef<Msg>,
            _: Msg,
            seen: &mut Self::State,
        ) -> Result<(), ActorProcessingErr> {
            *seen.lock().unwrap() += 1;
            Ok(())
        }
    }

    /// Stands in for the graph controller: it takes a while over each op, and counts the ops it wrote.
    struct SlowGraph {
        written: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[ractor::async_trait]
    impl Actor for SlowGraph {
        type Msg = polar::graph::controller::GraphControllerMsg;
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
            message: Self::Msg,
            _state: &mut (),
        ) -> Result<(), ActorProcessingErr> {
            if let polar::graph::controller::GraphControllerMsg::Op(_) = message {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                self.written
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(())
        }
    }

    /// The writes still queued for the graph are written before the controller stops: none is dropped. A fast check
    /// with a stand-in for the controller (from jira-processor, whose own copy of the stop this was); against a real
    /// Neo4j in `tests/graph_controller.rs`.
    #[tokio::test]
    async fn the_graph_controller_writes_what_is_queued_before_it_stops() {
        let written = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (graph, _) = Actor::spawn(
            None,
            SlowGraph {
                written: written.clone(),
            },
            (),
        )
        .await
        .unwrap();
        for _ in 0..40 {
            graph
                .cast(polar::graph::controller::GraphControllerMsg::Op(
                    polar::graph::controller::GraphOp::Transaction { ops: vec![] },
                ))
                .unwrap();
        }

        stop_graph_controller(graph, Duration::from_secs(10)).await;
        assert_eq!(written.load(std::sync::atomic::Ordering::SeqCst), 40);
    }

    #[tokio::test]
    async fn a_drain_begins_once_and_delivers_one_elapsed() {
        let seen = Arc::new(Mutex::new(0));
        let (probe, _) = Actor::spawn(None, Probe, seen.clone()).await.unwrap();
        let mut drain = Drain::default();
        assert!(!drain.is_draining());
        assert!(drain.begin(&probe, Duration::from_millis(20), true, || Msg::Elapsed));
        assert!(drain.is_draining() && drain.is_rejuvenating());
        // A second begin, as a failure after PrepareShutdown would make, changes nothing.
        assert!(!drain.begin(&probe, Duration::from_millis(20), false, || Msg::Elapsed));
        assert!(drain.is_rejuvenating());
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(*seen.lock().unwrap(), 1);
    }
}
