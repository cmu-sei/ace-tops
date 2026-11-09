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

use crate::BROKER_CLIENT_NAME;
use crate::{GraphOperable, Scope};
use cassini_types::ClientEvent;
use k8s_openapi::api::apps::v1::{Deployment, ReplicaSet};
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::{Namespace, Node, Pod};
use kube_common::{
    KIND_KUSTOMIZATION, KIND_OCI_REPOSITORY, RESOURCE_APPLIED_ACTION, RESOURCE_DELETED_ACTION,
    flux::{kustomization::Kustomization, oci_repositories::OciRepository},
};
use kube_common::{KUBERNETES_CONSUMER, RawKubeEvent};
use polar::DiscoverySourceRef;
use polar::ProvenanceEvent;
use polar::RkyvError;
use polar::cassini::CassiniClient;
use polar::cassini::TcpClient;
use polar::graph::controller::{GraphController, GraphControllerMsg, GraphOp, IntoGraphKey};
use polar::graph::nodes::builds::ArtifactNodeKey;
use polar::graph::nodes::kube::KubeNodeKey;
use polar::topics::KUBERNETES_RESOLUTION_EVENTS;
use polar_agent_builder::{
    AgentBuilder, Configured, GraphHandle, HealthClient, HealthHandle, InfrastructureEvent,
    InfrastructureSupervisorMessage, Subscription,
};
use ractor::Actor;
use ractor::ActorProcessingErr;
use ractor::ActorRef;
use ractor::SupervisionEvent;
use ractor::async_trait;
use ractor::concurrency::Duration;
use serde::de::DeserializeOwned;
use serde_json::from_value;
use std::collections::{BTreeSet, HashMap};
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

/// What this agent needs to drain beyond the graph controller, whose drain the
/// builder counts: letting go of its topics, the infrastructure's own children
/// stopping, and a margin. If it is not done by then the process exits 1
/// regardless.
pub const SHUTDOWN_BUDGET: Duration = Duration::from_secs(15);

/// This supervisor's own message type. The shared `polar::SupervisorMessage`
/// cannot carry the two infrastructure signals (respawn, prepare-shutdown)
/// without `polar-agent-builder` depending back on `polar`, so, like
/// kube-observer and jira-processor, the consumer defines exactly the
/// messages it handles.
pub enum ConsumerSupervisorMessage {
    ClientEvent {
        event: ClientEvent,
    },
    /// The agent is ending. The infrastructure waits for this supervisor to
    /// let go of its topics and answer with
    /// `InfrastructureSupervisorMessage::ProceedWithShutdown`; it then drains
    /// the graph controller.
    PrepareShutdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateFingerprint {
    pub signature: String,
    pub valid_from: String,
    pub last_state_node_id: Option<String>,
}

#[derive(Default)]
pub struct ProjectionCache {
    entries: HashMap<(String, String), StateFingerprint>,
    /// Each node seen, by name: the uid it was seen with.
    nodes: HashMap<String, String>,
    /// The pods each node not yet seen runs, by its name, to be joined to it when it is.
    waiting: HashMap<String, BTreeSet<String>>,
}

pub enum EmitDecision {
    Suppress,
    Emit {
        previous_state_node_id: Option<String>,
    },
}

impl ProjectionCache {
    pub fn should_emit(
        &mut self,
        kind: String,
        uid: String,
        new_signature: String,
        valid_from: String,
    ) -> EmitDecision {
        let key = (kind.clone(), uid.clone());

        match self.entries.get(&key) {
            Some(existing) if existing.signature == new_signature => EmitDecision::Suppress,
            Some(existing) => {
                let prev = existing.last_state_node_id.clone();
                self.entries.insert(
                    key,
                    StateFingerprint {
                        signature: new_signature,
                        valid_from,
                        last_state_node_id: None,
                    },
                );
                EmitDecision::Emit {
                    previous_state_node_id: prev,
                }
            }
            None => {
                self.entries.insert(
                    key,
                    StateFingerprint {
                        signature: new_signature,
                        valid_from,
                        last_state_node_id: None,
                    },
                );
                EmitDecision::Emit {
                    previous_state_node_id: None,
                }
            }
        }
    }

    pub fn set_last_state_node_id(&mut self, kind: &str, uid: &str, node_id: String) {
        if let Some(entry) = self.entries.get_mut(&(kind.to_string(), uid.to_string())) {
            entry.last_state_node_id = Some(node_id);
        }
    }

    pub fn evict(&mut self, kind: String, uid: &str) {
        self.entries.remove(&(kind, uid.to_string()));
    }

    /// When the state last written for this resource began.
    pub fn valid_from_of(&self, kind: &str, uid: &str) -> Option<String> {
        self.entries
            .get(&(kind.to_string(), uid.to_string()))
            .map(|entry| entry.valid_from.clone())
    }

    /// The uid of the node seen under `name`.
    pub fn node_uid(&self, name: &str) -> Option<&str> {
        self.nodes.get(name).map(String::as_str)
    }

    /// A node seen under `name`, with `uid`. The answer is the pods that were waiting for it.
    pub fn record_node(&mut self, name: &str, uid: &str) -> Vec<String> {
        self.nodes.insert(name.to_string(), uid.to_string());
        self.waiting
            .remove(name)
            .map(|pods| pods.into_iter().collect())
            .unwrap_or_default()
    }

    /// The node `uid` has gone, so its name joins no pod to it; a node seen under the name since keeps it.
    pub fn forget_node(&mut self, name: &str, uid: &str) {
        if self.nodes.get(name).is_some_and(|seen| seen == uid) {
            self.nodes.remove(name);
        }
    }

    /// A pod runs on the node `name`, which has not been seen.
    pub fn wait_for_node(&mut self, name: &str, pod_uid: &str) {
        self.waiting
            .entry(name.to_string())
            .or_default()
            .insert(pod_uid.to_string());
    }

    /// The pod has gone, so it waits for no node.
    pub fn forget_pod(&mut self, pod_uid: &str) {
        self.waiting.retain(|_, pods| {
            pods.remove(pod_uid);
            !pods.is_empty()
        });
    }
}

pub struct ClusterConsumerSupervisor;

pub struct ClusterConsumerSupervisorState {
    broker_client: TcpClient,
    /// The builder's: it reports the graph's health and drains it at the end.
    graph: GraphHandle,
    projection_cache: ProjectionCache,
    healthcheck: HealthHandle,
    /// The real, first, genuine CryptoActor user -- shares this
    /// supervisor's own, already-established Cassini connection and
    /// RouterActor rather than opening a second connection. Not yet
    /// consumed by anything in this file's own, real projection
    /// logic; the real, upcoming, plaintext-Kubernetes-secret
    /// encryption work (see this crate's own, real design
    /// discussion) is the actual, first real caller.
    /// The InfrastructureSupervisor (HealthCheckActor, RouterActor,
    /// TcpClientActor, CryptoActor) this supervisor's builder spawned. Its
    /// termination means the shutdown handshake is complete (or that
    /// infrastructure died), and either way this process must exit.
    infrastructure: ActorRef<InfrastructureSupervisorMessage>,
    /// Set true at `PrepareShutdown`. While true, incoming messages are logged
    /// instead of processed: the agent is ending.
    draining: bool,
}

impl ClusterConsumerSupervisor {
    pub fn handle_event<T>(
        ev: RawKubeEvent,
        cluster_uid: &str,
        cache: &mut ProjectionCache,
        graph_controller: &GraphController,
        tcp_client: &dyn CassiniClient,
    ) -> Result<(), ActorProcessingErr>
    where
        T: DeserializeOwned + GraphOperable,
    {
        debug!("Handling event for resource {}", ev.kind);
        let obj = from_value::<T>(ev.object)?;
        let mut scope = Scope { cluster_uid, cache };

        match ev.action.as_str() {
            RESOURCE_APPLIED_ACTION => {
                debug!("handling RESOURCE_APPLIED_ACTION.");
                obj.project_into_graph(graph_controller, tcp_client, &mut scope)?
            }
            RESOURCE_DELETED_ACTION => {
                debug!("handling RESOURCE_DELETED_ACTION.");
                obj.project_delete(graph_controller, &mut scope)?;
            }
            _ => warn!("Unexpected action received!! {}", ev.action),
        }
        Ok(())
    }

    /// One of the observer's events, projected by its kind. An event that does not say which cluster it is of (from an
    /// observer older than that) is not projected: its namespace could not be named.
    pub fn handle_kube_event(
        ev: RawKubeEvent,
        cache: &mut ProjectionCache,
        graph_controller: &GraphController,
        tcp_client: &dyn CassiniClient,
    ) -> Result<(), ActorProcessingErr> {
        let Some(cluster_uid) = ev.cluster_uid.clone() else {
            warn!(
                kind = ev.kind,
                "an event that does not say which cluster it is of, not projected"
            );
            return Ok(());
        };
        let cluster_uid = cluster_uid.as_str();
        // TODO: Define constants for these and match on them instead, these literals are also used in the marco calls to define their watchers
        match ev.kind.as_str() {
            "Namespace" => Self::handle_event::<Namespace>(
                ev,
                cluster_uid,
                cache,
                graph_controller,
                tcp_client,
            )?,
            "Node" => {
                Self::handle_event::<Node>(ev, cluster_uid, cache, graph_controller, tcp_client)?
            }
            "Pod" => {
                Self::handle_event::<Pod>(ev, cluster_uid, cache, graph_controller, tcp_client)?
            }
            "Deployment" => Self::handle_event::<Deployment>(
                ev,
                cluster_uid,
                cache,
                graph_controller,
                tcp_client,
            )?,
            "ReplicaSet" => Self::handle_event::<ReplicaSet>(
                ev,
                cluster_uid,
                cache,
                graph_controller,
                tcp_client,
            )?,
            "Job" => {
                Self::handle_event::<Job>(ev, cluster_uid, cache, graph_controller, tcp_client)?
            }
            KIND_OCI_REPOSITORY => Self::handle_event::<OciRepository>(
                ev,
                cluster_uid,
                cache,
                graph_controller,
                tcp_client,
            )?,
            KIND_KUSTOMIZATION => Self::handle_event::<Kustomization>(
                ev,
                cluster_uid,
                cache,
                graph_controller,
                tcp_client,
            )?,
            _ => warn!("Unexpected resource type {}", ev.kind),
        }
        Ok(())
    }

    fn deserialize_and_dispatch(
        topic: String,
        payload: Vec<u8>,
        cache: &mut ProjectionCache,
        graph_controller: &GraphController,
        tcp_client: &TcpClient,
    ) -> Result<(), ActorProcessingErr> {
        // determine the topic the mesasge came from, we could've gotten notified of a new resource, or been notified that
        // some resource we saw was resolved from an external source (like a container image)
        match topic.as_str() {
            KUBERNETES_CONSUMER => {
                // 1) Parse the raw message into your RawKubeEvent
                let ev: RawKubeEvent = serde_json::from_slice(&payload)?;

                Self::handle_kube_event(ev, cache, graph_controller, tcp_client)?;
            }
            KUBERNETES_RESOLUTION_EVENTS => {
                let ev = rkyv::from_bytes::<ProvenanceEvent, RkyvError>(&payload)?;
                // Only a pod container's resolution is projected; every other event is ignored.
                if let ProvenanceEvent::OCIArtifactResolved {
                    digest,
                    source_ref:
                        DiscoverySourceRef::KubernetesPodContainer {
                            pod_uid,
                            container_name,
                            ..
                        },
                    ..
                } = ev
                {
                    debug!(
                        "pod {pod_uid} container {container_name} was resolved with digest {digest}, updating graph"
                    );
                    let container_k = KubeNodeKey::PodContainer {
                        pod_uid,
                        name: container_name,
                    };
                    let artifact_k = ArtifactNodeKey::OCIArtifact { digest };
                    let op = GraphOp::EnsureEdge {
                        from: container_k.into_key(),
                        to: artifact_k.into_key(),
                        rel_type: "USES_IMAGE".to_string(),
                        props: vec![],
                    };
                    graph_controller.send_message(GraphControllerMsg::Op(op))?;
                }
            }
            _ => (), //ignore unhandled topics for now, we shouldn't see anything else
        }
        Ok(())
    }

    /// Builds this agent's own two, real, genuinely-owned
    /// Subscriptions (KUBERNETES_CONSUMER, KUBERNETES_RESOLUTION_EVENTS)
    /// -- each one's own, real deliver closure reconstructs the exact
    /// same ClientEvent::MessagePublished this agent's own, existing,
    /// unchanged handle()/deserialize_and_dispatch logic already
    /// expects, and forwards it to `supervisor` as the same, existing
    /// ConsumerSupervisorMessage::ClientEvent it already handles.
    ///
    /// Extracted into its own, real, standalone function -- not left
    /// inlined inside pre_start -- specifically so a real test can
    /// exercise these two, real, exact closures directly, without
    /// needing the real network connection pre_start itself,
    /// separately, attempts. Mirrors this file's own, previous,
    /// established register_kube_topics's own, real testability
    /// design exactly; only how the results get registered with
    /// RouterActor changed (AgentBuilder's own, real
    /// .with_subscription(...) now owns that part).
    fn kube_subscriptions(supervisor: &ActorRef<ConsumerSupervisorMessage>) -> Vec<Subscription> {
        let supervisor_for_consumer = supervisor.clone();
        let supervisor_for_resolution = supervisor.clone();
        vec![
            Subscription::new(KUBERNETES_CONSUMER, move |incoming| {
                let event = ClientEvent::MessagePublished {
                    topic: incoming.topic,
                    payload: incoming.payload,
                    trace_ctx: incoming.trace_ctx,
                    published_by: incoming.published_by,
                    published_instance: incoming.published_instance,
                };
                if let Err(e) = supervisor_for_consumer
                    .send_message(ConsumerSupervisorMessage::ClientEvent { event })
                {
                    warn!("AgentBuilder: failed to deliver routed message to supervisor: {e}");
                }
            }),
            Subscription::new(KUBERNETES_RESOLUTION_EVENTS, move |incoming| {
                let event = ClientEvent::MessagePublished {
                    topic: incoming.topic,
                    payload: incoming.payload,
                    trace_ctx: incoming.trace_ctx,
                    published_by: incoming.published_by,
                    published_instance: incoming.published_instance,
                };
                if let Err(e) = supervisor_for_resolution
                    .send_message(ConsumerSupervisorMessage::ClientEvent { event })
                {
                    warn!("AgentBuilder: failed to deliver routed message to supervisor: {e}");
                }
            }),
        ]
    }

    /// Tells the broker this agent is going dark, so it stops routing
    /// messages here. Failures are logged and do not stop the shutdown.
    fn unsubscribe_from_topics(client: &TcpClient) {
        for topic in [KUBERNETES_CONSUMER, KUBERNETES_RESOLUTION_EVENTS] {
            if let Err(e) = client.unsubscribe(polar::cassini::UnsubscribeRequest {
                topic: topic.to_string(),
                trace_ctx: None,
            }) {
                warn!("CONSUMER_SUPERVISOR: unsubscribe from '{topic}' failed (continuing): {e}");
            }
        }
    }
}

#[async_trait]
impl Actor for ClusterConsumerSupervisor {
    type Msg = ConsumerSupervisorMessage;
    type State = ClusterConsumerSupervisorState;
    /// The configuration `run` judged: the builder is made from it, so what the agent declared
    /// (its capabilities, its budget, the self-test) is what the infrastructure is built to.
    type Arguments = Configured;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        configured: Configured,
    ) -> Result<Self::State, ActorProcessingErr> {
        debug!("{myself:?} starting");
        info!("Read neo configuration successfully.");

        // The real, entire, formerly hand-rolled sequence --
        // HealthCheckActor, RouterActor, this agent's own two,
        // genuinely-owned topics (each bound to the real, wire-level
        // Subscribe AgentBuilder itself now, automatically fires on
        // ClientEvent::Registered -- see polar-agent-builder's own
        // Subscription for the complete, real reasoning), TcpClient,
        // and CryptoActor -- collapsed into one, real, composed call.
        let mut builder = AgentBuilder::new(myself.clone(), BROKER_CLIENT_NAME);

        for subscription in Self::kube_subscriptions(&myself) {
            builder = builder.with_subscription(subscription);
        }
        let resources = builder
            .with_lifecycle_handler(|event| Some(ConsumerSupervisorMessage::ClientEvent { event }))
            .into_configured(configured)
            .build()
            .await?;

        // The "infrastructure -> domain" half of the respawn/shutdown
        // protocol. Without this subscription the InfrastructureSupervisor
        // would wait forever for a ProceedWithShutdown after rejuvenation.
        resources
            .infrastructure_events
            .subscribe(myself.clone(), |event| match event {
                InfrastructureEvent::PrepareShutdown => {
                    Some(ConsumerSupervisorMessage::PrepareShutdown)
                }
            });

        // The encryption capability must have produced the crypto actor; nothing here uses it.
        resources.crypto.as_ref().ok_or_else(|| {
            ActorProcessingErr::from(
                "with_encryption() was called but the builder returned no CryptoHandle",
            )
        })?;

        Ok(ClusterConsumerSupervisorState {
            broker_client: resources.tcp_client,
            graph: resources
                .graph
                .ok_or("the builder started no graph controller for a graph-write agent")?,
            projection_cache: ProjectionCache::default(),
            healthcheck: resources.healthcheck,
            infrastructure: resources.infrastructure,
            draining: false,
        })
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            ConsumerSupervisorMessage::PrepareShutdown => {
                if state.draining {
                    warn!("CONSUMER_SUPERVISOR: PrepareShutdown received again; already ending");
                } else {
                    state.draining = true;
                    info!(
                        "CONSUMER_SUPERVISOR: PrepareShutdown received, unsubscribing from \
                         Cassini and proceeding; the infrastructure drains the graph"
                    );
                    Self::unsubscribe_from_topics(&state.broker_client);
                    if let Err(e) = state
                        .infrastructure
                        .cast(InfrastructureSupervisorMessage::ProceedWithShutdown)
                    {
                        error!(
                            "CONSUMER_SUPERVISOR: could not tell infrastructure to proceed ({e}); \
                             exiting now"
                        );
                        std::process::exit(1);
                    }
                }
            }

            ConsumerSupervisorMessage::ClientEvent { event } => {
                match event {
                    ClientEvent::Registered { .. } => {
                        // AgentBuilder already fired the wire-level Subscribe
                        // for both of this agent's topics when this event
                        // fired (see Subscription), and the builder's graph
                        // controller reports the graph's own health, so only
                        // the broker's is told here.
                        let _ = state.healthcheck.cassini_connected();
                    }

                    ClientEvent::MessagePublished { topic, payload, .. } => {
                        if state.draining {
                            warn!(
                                "CONSUMER_SUPERVISOR: draining -- logging message on topic \
                                 '{topic}' ({} bytes) instead of processing; will be lost on exit",
                                payload.len()
                            );
                            // TODO: publish to dead-letter queue once Cassini
                            // supports one, instead of only logging.
                        } else {
                            Self::deserialize_and_dispatch(
                                topic,
                                payload,
                                &mut state.projection_cache,
                                state.graph.actor(),
                                &state.broker_client,
                            )?;
                        }
                    }

                    ClientEvent::TransportError { reason } => {
                        error!("Transport error occurred! {reason}");
                        let _ = state.healthcheck.cassini_disconnected();
                    }

                    _ => (),
                }
            }
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
            SupervisionEvent::ActorStarted(actor_cell) => {
                info!(
                    "CONSUMER_SUPERVISOR: {0:?}:{1:?} started",
                    actor_cell.get_name(),
                    actor_cell.get_id()
                );
            }
            SupervisionEvent::ActorTerminated(actor_cell, _, reason) => {
                let actor_name = actor_cell.get_name().unwrap_or_default();
                info!(
                    "CONSUMER_SUPERVISOR: {0:?}:{1:?} terminated. {reason:?}",
                    actor_name,
                    actor_cell.get_id()
                );
                // The InfrastructureSupervisor is this supervisor's direct
                // child (the builder spawned it linked); the health check
                // is its child, not ours, so rejuvenation reaches us as
                // PrepareShutdown, not as a termination event. Infrastructure
                // terminating is the end of the handshake -- or infrastructure
                // dying on its own -- and in both cases the process exits so
                // the Job starts a new pod with fresh certs. Matched by id,
                // since the actor is spawned unnamed.
                if actor_cell.get_id() == state.infrastructure.get_id() {
                    info!(
                        "CONSUMER_SUPERVISOR: infrastructure terminated, exiting so the Job restarts the pod"
                    );
                    std::process::exit(1);
                }
            }
            SupervisionEvent::ActorFailed(actor_cell, e) => {
                let actor_name = actor_cell.get_name().unwrap_or_default();
                error!(
                    "CONSUMER_SUPERVISOR: {0:?}:{1:?} failed! {e:?}",
                    actor_name,
                    actor_cell.get_id()
                );
                // Its one child is the infrastructure, whose failure leaves the
                // agent nothing to run on: exit, so the Job starts a new pod.
                if actor_cell.get_id() == state.infrastructure.get_id() {
                    std::process::exit(1);
                }
            }
            SupervisionEvent::ProcessGroupChanged(..) => {}
        }

        Ok(())
    }
}

#[cfg(test)]
mod subscription_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A minimal, real stand-in for ClusterConsumerSupervisor itself
    /// -- genuinely receives ConsumerSupervisorMessage, just records what it
    /// got, since this test's own, real purpose is proving
    /// kube_subscriptions's own, two, real deliver closures
    /// correctly reconstruct and forward ClientEvent::MessagePublished,
    /// not re-testing this crate's own, separate, unchanged
    /// handle()/deserialize_and_dispatch logic.
    struct FakeSupervisor {
        received: Arc<Mutex<Vec<ClientEvent>>>,
    }

    #[async_trait]
    impl Actor for FakeSupervisor {
        type Msg = ConsumerSupervisorMessage;
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
            if let ConsumerSupervisorMessage::ClientEvent { event } = message {
                self.received.lock().unwrap().push(event);
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn kube_subscriptions_returns_exactly_this_agents_own_two_real_topics() {
        let (fake_supervisor, _) = Actor::spawn(
            None,
            FakeSupervisor {
                received: Arc::new(Mutex::new(Vec::new())),
            },
            (),
        )
        .await
        .unwrap();

        let subscriptions = ClusterConsumerSupervisor::kube_subscriptions(&fake_supervisor);

        assert_eq!(subscriptions.len(), 2);
        let topics: Vec<&str> = subscriptions.iter().map(|s| s.topic.as_str()).collect();
        assert!(topics.contains(&KUBERNETES_CONSUMER));
        assert!(topics.contains(&KUBERNETES_RESOLUTION_EVENTS));
    }

    #[tokio::test]
    async fn every_topic_it_subscribes_to_is_in_its_declared_set() {
        let (fake_supervisor, _) = Actor::spawn(
            None,
            FakeSupervisor {
                received: Arc::new(Mutex::new(Vec::new())),
            },
            (),
        )
        .await
        .unwrap();
        let set = polar_agent_builder::agent::topic_set::<crate::agent::KubeConsumer>();
        for subscription in ClusterConsumerSupervisor::kube_subscriptions(&fake_supervisor) {
            assert!(
                set.allows(&subscription.topic, polar_agent_builder::Access::Subscribe),
                "{} is not declared",
                subscription.topic
            );
        }
    }

    #[tokio::test]
    async fn each_real_deliver_closure_genuinely_forwards_a_correctly_reconstructed_client_event() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let (fake_supervisor, _) = Actor::spawn(
            None,
            FakeSupervisor {
                received: received.clone(),
            },
            (),
        )
        .await
        .unwrap();

        let subscriptions = ClusterConsumerSupervisor::kube_subscriptions(&fake_supervisor);

        // The real, direct proof: invoke each of the two, real
        // deliver closures directly -- no RouterActor involved at
        // all, since this function no longer registers with one
        // itself (AgentBuilder's own, real .with_subscription(...)
        // does that now, separately, and is already, separately
        // tested in polar-agent-builder's own test suite).
        for subscription in &subscriptions {
            (subscription.deliver)(polar_router::IncomingMessage {
                topic: subscription.topic.clone(),
                payload: format!("payload for {}", subscription.topic).into_bytes(),
                published_by: Some("kube-observer".to_string()),
                published_instance: None,
                trace_ctx: None,
            });
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let events = received.lock().unwrap();
        assert_eq!(events.len(), 2);
        for event in events.iter() {
            match event {
                ClientEvent::MessagePublished {
                    topic,
                    payload,
                    published_by,
                    ..
                } => {
                    assert_eq!(payload, format!("payload for {topic}").as_bytes());
                    assert_eq!(published_by, &Some("kube-observer".to_string()));
                }
                other => panic!("expected MessagePublished, got {other:?}"),
            }
        }
    }
}
