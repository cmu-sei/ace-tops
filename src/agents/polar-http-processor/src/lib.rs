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

pub mod processing;

use cert_issuer_common::identity::workload_of;
use polar::graph::controller::{
    GraphControllerActor, GraphControllerArgs, GraphControllerMsg, GraphSignal, NodeShape,
};
use polar_agent_builder::{
    AgentBuilder, ConfigurationHandle, Configured, Drain, HealthClient, HealthHandle,
    InfrastructureEvent, InfrastructureSupervisorMessage, StartError, Subscription,
    stop_graph_controller,
};
use polar_http_observer::Observation;
use polar_projection::{Bounds, Projection, graph};
use processing::{Event, Processing, Step};
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
    /// What it may write: the `SCHEMA` its [`schema!`] made.
    const BOUNDS: Bounds<'static>;
}

/// A kind's schema, declared once: each label it writes with what identifies it, and each edge with the labels at its ends,
/// each with its purpose. Makes, in the calling module, `SCHEMA` (the [`Bounds`] a signed mapping is judged by), and `LABELS`
/// and `EDGES` for the kind's `GRAPH` and `GRAPH_EDGES`, so what the scaffold prints and what a mapping is held to are one
/// declaration and cannot drift.
///
/// ```
/// polar_http_processor::schema! {
///     labels {
///         OpenApiApplication [source] "each source's application",
///         OpenApiEndpoint [source, method, path] "each operation of each application",
///     }
///     edges {
///         OpenApiApplication HAS_ENDPOINT OpenApiEndpoint "each operation of an application",
///     }
/// }
/// assert_eq!(SCHEMA.shapes[1].keys, ["source", "method", "path"]);
/// assert_eq!(LABELS[0].label, "OpenApiApplication");
/// assert_eq!(EDGES[0].to, "OpenApiEndpoint");
/// ```
#[macro_export]
macro_rules! schema {
    (
        labels { $( $label:ident [ $( $key:ident ),+ ] $purpose:literal ),+ $(,)? }
        edges { $( $from:ident $kind:ident $to:ident $edge_purpose:literal ),* $(,)? }
    ) => {
        /// What this workload was built to write. A signed mapping chooses data inside it, and cannot widen it.
        pub const SCHEMA: $crate::__private::Bounds<'static> = $crate::__private::Bounds {
            shapes: &[ $( $crate::__private::Shape {
                label: stringify!($label),
                keys: &[ $( stringify!($key) ),+ ],
            } ),+ ],
            edges: &[ $( $crate::__private::Edge {
                from: stringify!($from),
                kind: stringify!($kind),
                to: stringify!($to),
            } ),* ],
        };
        /// The labels of [`SCHEMA`], for the kind's `GRAPH`.
        pub const LABELS: &[$crate::__private::GraphDecl] =
            &[ $( $crate::__private::GraphDecl::owns(stringify!($label), $purpose) ),+ ];
        /// The edges of [`SCHEMA`], for the kind's `GRAPH_EDGES`.
        pub const EDGES: &[$crate::__private::EdgeDecl] = &[ $( $crate::__private::EdgeDecl::new(
            stringify!($from),
            stringify!($kind),
            stringify!($to),
            $edge_purpose,
        ) ),* ];
    };
}

#[doc(hidden)]
pub mod __private {
    pub use polar_agent_builder::{EdgeDecl, GraphDecl};
    pub use polar_projection::{Bounds, Edge, Shape};
}

/// Judges a section's body, for a kind's `RuntimeSection`: a projection, inside what it was built to write. Names are held to
/// Cypher's own rule in judging, so the tool that signs a mapping, judging it by the kind's scaffold, refuses what this does.
pub fn judge(body: &Value, bounds: Bounds<'_>) -> Result<(), Vec<String>> {
    Projection::judged(body, bounds).map(|_| ())
}

/// The shapes the graph's constraints are made from, for a kind's `GRAPH_KEYS`.
pub fn node_shapes(bounds: Bounds<'_>) -> Vec<NodeShape> {
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
    processing: Processing,
    drain: Drain,
}

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

        let mut processing = Processing::new(K::NAME);
        let steps = processing.on(Event::Started);
        let state = ProcessorState {
            healthcheck: resources.healthcheck,
            infrastructure: resources.infrastructure,
            configuration: resources.configuration,
            graph_controller: Some(graph_controller),
            processing,
            drain: Drain::default(),
        };
        carry_out(&state, steps)?;
        myself.cast(ProcessorMessage::ProjectionChanged)?;
        Ok(state)
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
            ProcessorMessage::ProjectionRead(read) => {
                let steps = state.processing.on(Event::Mapping(read));
                carry_out(state, steps)?;
            }
            ProcessorMessage::Observed(observation) => {
                if state.drain.is_draining() {
                    warn!(
                        "draining -- what `{}` said is not written; its next read is",
                        observation.source
                    );
                    return Ok(());
                }
                let steps = state.processing.on(Event::Observed(observation));
                carry_out(state, steps)?;
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

/// Does what was decided.
fn carry_out(state: &ProcessorState, steps: Vec<Step>) -> Result<(), ActorProcessingErr> {
    for step in steps {
        match step {
            Step::Write { source, writes } => {
                if let (Some(op), Some(controller)) =
                    (graph::operation(writes), &state.graph_controller)
                {
                    controller.cast(GraphControllerMsg::Op(op)).map_err(|e| {
                        format!("could not hand what `{source}` said to the graph: {e}")
                    })?;
                }
            }
            Step::Health(change) => change.apply(&state.healthcheck),
        }
    }
    Ok(())
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
    use serde_json::json;

    const BOUNDS: Bounds<'static> = Bounds {
        shapes: &[Shape {
            label: "TestDoc",
            keys: &["source"],
        }],
        edges: &[],
    };

    mod declared {
        crate::schema! {
            labels {
                TestDoc [source] "each source's document",
                TestPart [source, n] "each part of a document",
            }
            edges {
                TestDoc HAS_PART TestPart "each part of a document",
            }
        }
    }

    /// One declaration is the bound a mapping is judged by and what the scaffold prints, in the same order.
    #[test]
    fn a_schema_is_declared_once_for_the_bound_and_the_scaffold() {
        use declared::{EDGES, LABELS, SCHEMA};
        let shapes: Vec<(&str, &[&str])> =
            SCHEMA.shapes.iter().map(|s| (s.label, s.keys)).collect();
        assert_eq!(
            shapes,
            [
                ("TestDoc", &["source"][..]),
                ("TestPart", &["source", "n"][..])
            ]
        );
        let labels: Vec<(&str, &str)> = LABELS.iter().map(|l| (l.label, l.purpose)).collect();
        assert_eq!(
            labels,
            [
                ("TestDoc", "each source's document"),
                ("TestPart", "each part of a document")
            ]
        );
        assert!(
            LABELS
                .iter()
                .all(|l| l.access == polar_agent_builder::GraphAccess::Owns)
        );
        assert_eq!(
            SCHEMA.edges,
            [polar_projection::Edge {
                from: "TestDoc",
                kind: "HAS_PART",
                to: "TestPart"
            }]
        );
        assert_eq!(
            EDGES,
            [polar_agent_builder::EdgeDecl::new(
                "TestDoc",
                "HAS_PART",
                "TestPart",
                "each part of a document"
            )]
        );
        assert!(polar_agent_builder::graph_schema::edge_problems(EDGES, LABELS).is_empty());
    }

    fn body() -> Value {
        json!({ "guard": [{ "any_of": [{ "path": "body.title", "prefixes": [] }] }], "rules": [{
            "name": "doc", "parent": "", "each": [], "label": "TestDoc",
            "keys": [{ "name": "source", "from": "source" }],
            "set": [{ "name": "title", "from": "body.title" }],
            "edge": ""
        }]})
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
    fn the_constraints_come_from_the_schema() {
        let shapes = node_shapes(BOUNDS);
        assert_eq!(shapes[0].labels, ["TestDoc"]);
        assert_eq!(shapes[0].keys, ["source"]);
    }
}
