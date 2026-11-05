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

//! A processor for what an observer publishes, as a library (docs/architecture/http-observers.md): a signed mapping says which
//! data goes where, inside the schema the kind was built with. A kind is a small crate that gives its name, whose documents it
//! takes, and that schema.

#![deny(clippy::disallowed_methods)]

use cert_issuer_common::identity::workload_of;
use polar::graph::controller::{
    GraphControllerActor, GraphControllerArgs, GraphControllerMsg, GraphOp, GraphSignal, NodeShape,
};
use polar_agent_builder::{
    AgentBuilder, ConfigurationHandle, Configured, Drain, HealthClient, HealthHandle, HoldReason,
    InfrastructureEvent, InfrastructureSupervisorMessage, StartError, Subscription,
    stop_graph_controller,
};
use polar_http_observer::Observation;
use polar_projection::{Bounds, Projection, Stamp, graph};
use ractor::concurrency::Duration;
use ractor::{Actor, ActorProcessingErr, ActorRef, OutputPort, SupervisionEvent, async_trait};
use serde_json::Value;
use std::marker::PhantomData;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// What the section is called in a document.
pub const SECTION_NAME: &str = "projection";
/// What describes the section's body, for `--scaffold` and its template.
pub const SECTION_BODY: &str = r#"{"rules": {"type": "a projection: polar-projection/projection.dhall, signed with polar-sign runtime --projection", "required": true, "doc": "how a document becomes nodes and edges, inside this workload's schema"}}"#;

const DRAIN_WINDOW_SECS: u64 = 5;
const GRAPH_STOP_SECS: u64 = 30;
/// The drain window and the graph controller's stop, plus a margin.
pub const SHUTDOWN_BUDGET: std::time::Duration =
    std::time::Duration::from_secs(DRAIN_WINDOW_SECS + GRAPH_STOP_SECS + 10);

/// What is particular to one kind of processor. Fixed when it is built: a signed mapping chooses data inside `BOUNDS`.
pub trait Kind: Send + Sync + 'static {
    /// The workload it runs as.
    const NAME: &'static str;
    /// The workload it takes documents from.
    const OBSERVER: &'static str;
    /// Where they arrive.
    const TOPIC: &'static str;
    /// What it may write.
    const BOUNDS: Bounds;
}

/// Judges a section's body, for a kind's `RuntimeSection`: a projection, inside what it was built to write, whose names Cypher takes.
pub fn judge(body: &Value, bounds: Bounds) -> Result<(), Vec<String>> {
    let projection = Projection::judged(body, bounds)?;
    let problems = graph::identifier_problems(&projection);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// The shapes the graph's constraints are made from, for a kind's `GRAPH_KEYS`.
pub fn node_shapes(bounds: Bounds) -> Vec<NodeShape> {
    bounds
        .shapes
        .iter()
        .map(|shape| NodeShape {
            labels: vec![shape.label.to_string()],
            keys: shape.keys.iter().map(|k| k.to_string()).collect(),
        })
        .collect()
}

/// Whether a message is from the observer it should be, by the broker's word. A policy could permit another publisher on the
/// topic, and that would not make it this kind's observer.
pub fn from_its_observer(published_by: Option<&str>, observer: &str) -> bool {
    published_by.and_then(workload_of) == Some(observer)
}

/// What became of a document.
#[derive(Debug)]
pub enum Outcome {
    /// What to write, and how many entries could not be identified and were skipped.
    Write { op: Option<GraphOp>, skipped: usize },
    /// Nothing is written, and why.
    Refused(String),
}

/// A document, through a mapping, into what the graph controller takes.
pub fn process(
    projection: &Projection,
    version: u64,
    workload: &str,
    observation: &Observation,
) -> Outcome {
    let body: Value = match serde_json::from_slice(&observation.body) {
        Ok(body) => body,
        Err(e) => return Outcome::Refused(format!("it is not JSON: {e}")),
    };
    let stamp = Stamp {
        workload,
        version,
        observed_at_unix_secs: observation.observed_at_unix_secs,
    };
    match projection.project(&observation.source, &body, &stamp) {
        Ok(projected) => Outcome::Write {
            op: graph::operation(projected.writes),
            skipped: projected.skipped,
        },
        Err(refused) => Outcome::Refused(refused.to_string()),
    }
}

pub enum ProcessorMessage {
    ClientEvent { event: cassini_types::ClientEvent },
    Observed(Observation),
    GraphSignal(GraphSignal),
    ProjectionChanged,
    ProjectionRead(Result<Option<(u64, Projection)>, Vec<String>>),
    PrepareShutdown,
    DrainElapsed,
}

pub struct Processor<K>(PhantomData<fn() -> K>);

pub struct ProcessorState {
    healthcheck: HealthHandle,
    infrastructure: ActorRef<InfrastructureSupervisorMessage>,
    configuration: ConfigurationHandle,
    graph_controller: Option<ActorRef<GraphControllerMsg>>,
    projection: Option<(u64, Projection)>,
    drain: Drain,
}

const NO_MAPPING: &str = "no projection is signed yet, so what the observer publishes is not written. Sign one: \
                          polar-sign runtime --section projection --projection <file>";

#[async_trait]
impl<K: Kind> Actor for Processor<K> {
    type Msg = ProcessorMessage;
    type State = ProcessorState;
    type Arguments = Configured;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        configured: Configured,
    ) -> Result<Self::State, ActorProcessingErr> {
        debug!("{myself:?} starting");
        let key_indexes = configured.graph_key_indexes();
        let to = myself.clone();
        let observed = Subscription::new(K::TOPIC, move |incoming| {
            if !from_its_observer(incoming.published_by.as_deref(), K::OBSERVER) {
                warn!(
                    "a document on {} from {:?} was dropped: only {} is believed",
                    K::TOPIC,
                    incoming.published_by,
                    K::OBSERVER
                );
                return;
            }
            match Observation::decode(&incoming.payload) {
                Ok(observation) => {
                    if let Err(e) = to.cast(ProcessorMessage::Observed(observation)) {
                        error!("failed to hand a document to the supervisor: {e}");
                    }
                }
                Err(e) => warn!("what came on {} is not an observation: {e}", K::TOPIC),
            }
        });
        let resources = AgentBuilder::new(myself.clone(), K::NAME)
            .with_subscription(observed)
            .with_lifecycle_handler(|event| Some(ProcessorMessage::ClientEvent { event }))
            .into_configured(configured)
            .build()
            .await?;
        resources
            .infrastructure_events
            .subscribe(myself.clone(), |event| match event {
                InfrastructureEvent::PrepareShutdown => Some(ProcessorMessage::PrepareShutdown),
            });
        resources
            .configuration
            .runtime_changes()
            .subscribe(myself.clone(), |changed| {
                (changed.section == SECTION_NAME).then_some(ProcessorMessage::ProjectionChanged)
            });
        let signals = Arc::new(OutputPort::<GraphSignal>::default());
        signals.subscribe(myself.clone(), |signal| {
            Some(ProcessorMessage::GraphSignal(signal))
        });
        let (graph_controller, _) = GraphControllerActor::spawn_linked(
            Some(format!("{}.graph_controller", K::NAME)),
            GraphControllerActor,
            GraphControllerArgs::new(signals)
                .with_settings(
                    polar::graph::environment::GraphSettings::from_env(&*resources.config)
                        .map_err(ActorProcessingErr::from)?,
                )
                .with_key_indexes(key_indexes),
            myself.get_cell(),
        )
        .await
        .map_err(ActorProcessingErr::from)?;

        resources
            .healthcheck
            .hold(HoldReason::Configuration, NO_MAPPING);
        myself.cast(ProcessorMessage::ProjectionChanged)?;
        Ok(ProcessorState {
            healthcheck: resources.healthcheck,
            infrastructure: resources.infrastructure,
            configuration: resources.configuration,
            graph_controller: Some(graph_controller),
            projection: None,
            drain: Drain::default(),
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            ProcessorMessage::GraphSignal(signal) => match signal {
                GraphSignal::Available => {
                    let _ = state.healthcheck.graph_available();
                }
                GraphSignal::OpFailed(reason) => {
                    let _ = state.healthcheck.graph_op_failed(reason);
                }
            },
            ProcessorMessage::ClientEvent { event } => match event {
                cassini_types::ClientEvent::Registered { .. } => {
                    let _ = state.healthcheck.cassini_connected();
                    let _ = state.healthcheck.graph_connected();
                }
                cassini_types::ClientEvent::TransportError { reason } => {
                    warn!("Transport error (non-fatal, awaiting reconnect): {reason}");
                    let _ = state.healthcheck.cassini_disconnected();
                }
                _ => {}
            },
            ProcessorMessage::ProjectionChanged => {
                let configuration = state.configuration.clone();
                let to = myself.clone();
                ractor::concurrency::spawn(async move {
                    let read = match configuration.runtime(SECTION_NAME).await {
                        Ok(None) => Ok(None),
                        Ok(Some(value)) => Projection::judged(&value.body, K::BOUNDS)
                            .map(|projection| Some((value.version, projection))),
                        Err(e) => Err(vec![e.to_string()]),
                    };
                    let _ = to.cast(ProcessorMessage::ProjectionRead(read));
                });
            }
            ProcessorMessage::ProjectionRead(read) => match read {
                Ok(Some((version, projection))) => {
                    info!("projection version {version} in force");
                    state.projection = Some((version, projection));
                    state.healthcheck.release(HoldReason::Configuration);
                }
                Ok(None) => info!("{NO_MAPPING}"),
                // Judged when it arrived, so this is not expected. What is in force stays.
                Err(problems) => error!("the projection in force: {problems:?}"),
            },
            ProcessorMessage::Observed(observation) => {
                let source = observation.source.clone();
                if state.drain.is_draining() {
                    warn!("draining -- what `{source}` said is not written; its next read is");
                    return Ok(());
                }
                let Some((version, projection)) = &state.projection else {
                    warn!("what `{source}` said is not written: {NO_MAPPING}");
                    return Ok(());
                };
                match process(projection, *version, K::NAME, &observation) {
                    Outcome::Write { op, skipped } => {
                        info!(
                            "`{source}`: written under projection {version}, {skipped} entries skipped"
                        );
                        if let (Some(op), Some(controller)) = (op, &state.graph_controller) {
                            controller.cast(GraphControllerMsg::Op(op))?;
                        }
                    }
                    Outcome::Refused(why) => warn!("what `{source}` said is not written: {why}"),
                }
            }
            ProcessorMessage::PrepareShutdown => {
                if state.drain.begin(
                    &myself,
                    Duration::from_secs(DRAIN_WINDOW_SECS),
                    true,
                    || ProcessorMessage::DrainElapsed,
                ) {
                    info!("PrepareShutdown received; entering the drain window");
                }
            }
            ProcessorMessage::DrainElapsed => {
                if let Some(controller) = state.graph_controller.take() {
                    stop_graph_controller(controller, Duration::from_secs(GRAPH_STOP_SECS)).await;
                }
                state.drain.complete(&state.infrastructure);
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
        match event {
            SupervisionEvent::ActorStarted(actor) => debug!("{actor:?} started"),
            SupervisionEvent::ActorTerminated(actor, _, reason) => {
                info!("{actor:?} terminated: {reason:?}");
                if actor.get_id() == state.infrastructure.get_id() {
                    std::process::exit(1);
                }
                if state
                    .graph_controller
                    .as_ref()
                    .is_some_and(|c| c.get_id() == actor.get_id())
                    && state.drain.begin(
                        &myself,
                        Duration::from_secs(DRAIN_WINDOW_SECS),
                        false,
                        || ProcessorMessage::DrainElapsed,
                    )
                {
                    state.graph_controller = None;
                    warn!("the graph controller ended; draining before exit");
                }
            }
            SupervisionEvent::ActorFailed(actor, reason) => {
                error!("{actor:?} failed: {reason:?}");
                if !state.drain.begin(
                    &myself,
                    Duration::from_secs(DRAIN_WINDOW_SECS),
                    false,
                    || ProcessorMessage::DrainElapsed,
                ) {
                    warn!("already draining");
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// The agent's `start`.
pub async fn start<K: Kind>(configured: Configured) -> Result<(), StartError> {
    configured.init_logging(K::NAME);
    let name = format!("{}.supervisor", K::NAME);
    let (_supervisor, handle) =
        Actor::spawn(Some(name.clone()), Processor::<K>(PhantomData), configured)
            .await
            .map_err(|e| format!("failed to start {name}: {e}"))?;
    handle
        .await
        .map_err(|e| format!("{name} task failed: {e}"))?;
    // A processor that is no longer processing must be restarted.
    Err(format!("{name} stopped").into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_projection::Shape;
    use proptest::prelude::*;
    use serde_json::json;

    const BOUNDS: Bounds = Bounds {
        shapes: &[Shape {
            label: "TestDoc",
            keys: &["source"],
        }],
        edges: &[],
    };

    fn body() -> Value {
        json!({ "rules": [{
            "name": "doc", "parent": "", "each": [], "label": "TestDoc",
            "keys": [{ "name": "source", "from": "source" }],
            "set": [{ "name": "title", "from": "body.title" }],
            "edge": ""
        }]})
    }

    fn observation(document: &[u8]) -> Observation {
        Observation {
            source: "s".to_string(),
            observed_at_unix_secs: 1,
            body: document.to_vec(),
        }
    }

    #[test]
    fn a_mapping_is_judged_against_the_schema_and_cypher_s_own_rule() {
        judge(&body(), BOUNDS).unwrap();
        let mut outside = body();
        outside["rules"][0]["label"] = json!("Pod");
        assert!(judge(&outside, BOUNDS).is_err());
        let mut keyword = body();
        keyword["rules"][0]["set"][0]["name"] = json!("delete");
        assert!(judge(&keyword, BOUNDS).is_err());
    }

    #[test]
    fn only_its_own_observer_is_believed_by_the_broker_s_word() {
        let stamp = "openapi-observer.polar.serviceaccount.cluster.local";
        assert!(from_its_observer(Some(stamp), "openapi-observer"));
        assert!(!from_its_observer(Some(stamp), "jira-observer"));
        assert!(
            !from_its_observer(Some("openapi-observer"), "openapi-observer"),
            "a person's name is not a workload"
        );
        assert!(!from_its_observer(None, "openapi-observer"));
    }

    #[test]
    fn a_document_becomes_one_operation_and_what_is_not_json_is_refused() {
        let projection = Projection::judged(&body(), BOUNDS).unwrap();
        match process(&projection, 3, "w", &observation(br#"{"title":"t"}"#)) {
            Outcome::Write {
                op: Some(GraphOp::Transaction { ops }),
                skipped: 0,
            } => assert_eq!(ops.len(), 1),
            other => panic!("{other:?}"),
        }
        for not_json in [&b"openapi: 3.0.0\n"[..], b"", b"{"] {
            assert!(matches!(
                process(&projection, 3, "w", &observation(not_json)),
                Outcome::Refused(_)
            ));
        }
    }

    #[test]
    fn the_constraints_come_from_the_schema() {
        let shapes = node_shapes(BOUNDS);
        assert_eq!(shapes[0].labels, ["TestDoc"]);
        assert_eq!(shapes[0].keys, ["source"]);
    }

    proptest! {
        #[test]
        fn any_bytes_are_written_or_refused_and_never_panic(document in prop::collection::vec(any::<u8>(), 0..128)) {
            let projection = Projection::judged(&body(), BOUNDS).unwrap();
            let _ = process(&projection, 1, "w", &observation(&document));
        }
    }
}
