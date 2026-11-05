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

use cassini_types::ClientEvent;
use k8s_openapi::api::apps::v1::{Deployment, ReplicaSet};
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Pod, Secret};
use kube::Config;
use kube::ResourceExt;
use kube::runtime::{watcher, watcher::Event};
use kube::{Api, Client, api::ListParams};
use kube_common::{KIND_KUSTOMIZATION, KIND_OCI_REPOSITORY};
use polar::cassini::TcpClient;
use polar_agent_builder::{
    AgentBuilder, Configured, HealthClient, HealthHandle, InfrastructureEvent,
    InfrastructureSupervisorMessage,
};
use ractor::concurrency::Duration;
use ractor::{Actor, ActorProcessingErr, ActorRef, SupervisionEvent, async_trait};
use serde_json::to_value;
use std::collections::HashMap;
use tracing::{debug, error, info, warn};
use tracing::{instrument, trace};

use crate::{
    GlobalWatcherState, KustomizationWatcher, NamespacedWatcherState, OciRepositoryWatcher,
    TCP_CLIENT_NAME, WatcherMsg, emit_event, impl_namespaced_watcher,
};
use futures::{StreamExt, TryStreamExt};
use kube_common::{RESOURCE_APPLIED_ACTION, RESOURCE_DELETED_ACTION, RawKubeEvent};

// TODO: establish what kind of messages these receive
pub type NamespaceWatcherMap = HashMap<String, ActorRef<()>>;
pub type Watcher = ActorRef<WatcherMsg>;

/// How long the infrastructure supervisor gives this agent to drain: its three
/// watchers are stopped one after another, each bounded at 10 s, plus a margin. If
/// it is not done by then the process exits 1 regardless.
pub const SHUTDOWN_BUDGET: Duration = Duration::from_secs(3 * 10 + 10);

/// This supervisor's own, real, local message type -- the shared,
/// core polar::SupervisorMessage can't structurally carry either of
/// the two, new, real signals this migration needs
/// (InfrastructureRespawned, PrepareShutdown) without
/// polar-agent-builder depending back on lib, a genuine circular
/// dependency. AgentBuilder<M> only requires M: ractor::Message
/// (automatically satisfied by any Send + 'static type), so a
/// smaller, local type matching exactly what this supervisor
/// genuinely needs is the correct, clean fix, not a workaround.
pub enum ObserverSupervisorMessage {
    ClientEvent {
        event: ClientEvent,
    },
    /// InfrastructureSupervisor's own InfrastructureEvent::PrepareShutdown,
    /// forwarded here -- HealthCheckActor (now InfrastructureSupervisor's
    /// own, direct child, not this supervisor's) has genuinely,
    /// cleanly terminated for rejuvenation. Coordinate this
    /// supervisor's own, direct children (the watcher trees) shutting
    /// down first, then send
    /// InfrastructureSupervisorMessage::ProceedWithShutdown -- see
    /// this crate's own, real handle() arm for the complete sequence.
    PrepareShutdown,
    /// A watcher lost its watch. It comes here directly: the NamespaceSupervisor between the two
    /// is inside its own watch loop for as long as it runs, so it never hears of a child.
    WatchLost {
        watcher: String,
        reason: String,
    },
}

pub struct ClusterObserverSupervisor;

pub struct ClusterObserverSupervisorState {
    kube_client: kube::Client,
    tcp_client: TcpClient,
    healthcheck: HealthHandle,
    /// Sent InfrastructureSupervisorMessage::ProceedWithShutdown once
    /// this supervisor's own, direct children have genuinely, fully
    /// shut down -- see PrepareShutdown's own doc comment above.
    infrastructure: ActorRef<InfrastructureSupervisorMessage>,
    #[allow(dead_code)]
    node_watcher: Option<Watcher>,
    namespace_watcher: Option<Watcher>,
    /// Watches Flux OCIRepository resources cluster-wide.
    oci_repository_watcher: Option<Watcher>,
    /// Watches Flux Kustomization resources cluster-wide.
    kustomization_watcher: Option<Watcher>,
}

impl ClusterObserverSupervisor {
    pub fn init(
        kube_config: Config,
        tcp_client: TcpClient,
        healthcheck: HealthHandle,
        infrastructure: ActorRef<InfrastructureSupervisorMessage>,
    ) -> Result<ClusterObserverSupervisorState, ActorProcessingErr> {
        // try to create a client and auth with the kube api
        match Client::try_from(kube_config) {
            Ok(kube_client) => {
                debug!("Kubernetes client initialized");

                Ok(ClusterObserverSupervisorState {
                    kube_client,
                    tcp_client,
                    healthcheck,
                    infrastructure,
                    namespace_watcher: None,
                    node_watcher: None,
                    oci_repository_watcher: None,
                    kustomization_watcher: None,
                })
            }
            Err(e) => Err(ActorProcessingErr::from(e)),
        }
    }
}

#[async_trait]
impl Actor for ClusterObserverSupervisor {
    type Msg = ObserverSupervisorMessage;
    type State = ClusterObserverSupervisorState;
    /// The configuration `run` judged; the builder is made from it.
    type Arguments = Configured;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        configured: Configured,
    ) -> Result<Self::State, ActorProcessingErr> {
        // Read Kubernetes credentials and other data from the environment
        info!("{myself:?} starting");

        // The real, entire, formerly hand-rolled sequence --
        // HealthCheckActor, RouterActor, TcpClient -- collapsed into
        // one, real, composed call. No with_encryption(): this agent
        // only publishes observations, it never encrypts a payload.
        // It does need the Kubernetes API, which the deployment
        // provisions (ClusterRole, binding, token); the builder checks
        // that against POLAR_CAPABILITIES before anything starts.
        let resources = AgentBuilder::new(myself.clone(), TCP_CLIENT_NAME)
            .with_lifecycle_handler(|event| Some(ObserverSupervisorMessage::ClientEvent { event }))
            .into_configured(configured)
            .build()
            .await?;

        // The real "infra → domain" half of InfrastructureSupervisor's
        // own, real respawn/shutdown protocol -- subscribed directly,
        // the same, established pattern every other real port in this
        // codebase already uses.
        resources
            .infrastructure_events
            .subscribe(myself.clone(), |event| match event {
                InfrastructureEvent::PrepareShutdown => {
                    Some(ObserverSupervisorMessage::PrepareShutdown)
                }
            });

        // detect deployed environment, otherwise, try to infer configuration from the environment
        if let Ok(kube_config) = kube::Config::incluster() {
            info!("Attempting to infer kube configuration from pod environment...");
            ClusterObserverSupervisor::init(
                kube_config,
                resources.tcp_client,
                resources.healthcheck,
                resources.infrastructure,
            )
        } else if let Ok(kube_config) = kube::Config::infer().await {
            info!("Attempting to infer kube configuration from local environment...");
            ClusterObserverSupervisor::init(
                kube_config,
                resources.tcp_client,
                resources.healthcheck,
                resources.infrastructure,
            )
        } else {
            Err(ActorProcessingErr::from(
                "Failed to configure kubernetes client!",
            ))
        }
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
                info!(
                    "CLUSTER_SUPERVISOR: {0:?}:{1:?} terminated. {reason:?}",
                    actor_name,
                    actor_cell.get_id()
                );

                // InfrastructureSupervisor itself -- this supervisor's
                // one, real, direct, linked child from AgentBuilder's
                // own build() call. Its own termination is the real,
                // genuine signal this supervisor's own graceful
                // shutdown sequence (see PrepareShutdown's own handler
                // in handle(), below) is now fully, completely done --
                // exit so the Job controller creates a new pod with
                // fresh certs. Matched by real, genuine actor id, not
                // name (InfrastructureSupervisor is spawned unnamed).
                if actor_cell.get_id() == state.infrastructure.get_id() {
                    info!(
                        "CLUSTER_SUPERVISOR: infrastructure shutdown complete, exiting for rejuvenation"
                    );
                    std::process::exit(1);
                }
            }
            SupervisionEvent::ActorFailed(actor_cell, e) => {
                warn!(
                    "CLUSTER_SUPERVISOR: {0:?}:{1:?} failed! {e:?}",
                    actor_cell.get_name(),
                    actor_cell.get_id()
                );
                // Any child actor failure is fatal -- exit so the Job
                // controller creates a new pod. This is a deliberately blunt
                // fail-fast policy for now: we want a visible Job restart
                // event as the signal something needs investigating, rather
                // than silently degrading. Finer-grained resilience (e.g.
                // per-watcher restart without a full pod cycle) can be added
                // later if warranted, and should route through the logging
                // agent / OTel trace once that's wired up.
                std::process::exit(1);
            }
            SupervisionEvent::ProcessGroupChanged(..) => {}
        }

        Ok(())
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            ObserverSupervisorMessage::WatchLost { watcher, reason } => {
                // The same fail-fast policy as a child's failure, in handle_supervisor_evt: a new
                // pod lists everything again, where this one would stay blind to what was lost.
                error!("CLUSTER_SUPERVISOR: {watcher} lost its watch, exiting: {reason}");
                std::process::exit(1);
            }
            ObserverSupervisorMessage::PrepareShutdown => {
                info!(
                    "CLUSTER_SUPERVISOR: PrepareShutdown received -- stopping this \
                     supervisor's own, direct children before infrastructure"
                );

                if let Some(w) = state.namespace_watcher.take() {
                    w.stop_and_wait(None, Some(Duration::from_secs(10))).await?;
                }
                if let Some(w) = state.oci_repository_watcher.take() {
                    w.stop_and_wait(None, Some(Duration::from_secs(10))).await?;
                }
                if let Some(w) = state.kustomization_watcher.take() {
                    w.stop_and_wait(None, Some(Duration::from_secs(10))).await?;
                }

                let _ = state
                    .infrastructure
                    .cast(InfrastructureSupervisorMessage::ProceedWithShutdown);
            }
            ObserverSupervisorMessage::ClientEvent { event } => match event {
                ClientEvent::Registered { .. } => {
                    let _ = state.healthcheck.cassini_connected();

                    if state.namespace_watcher.is_none() {
                        let ns_watcher_state = NamespaceSupervisorState {
                            observer: myself.clone(),
                            tcp_client: state.tcp_client.clone(),
                            kube_client: state.kube_client.clone(),
                            supervisors: HashMap::new(),
                        };

                        let (ns_watcher, _) = Actor::spawn_linked(
                            Some("cluster.nodes".into()),
                            NamespaceSupervisor,
                            ns_watcher_state,
                            myself.clone().into(),
                        )
                        .await?;

                        state.namespace_watcher = Some(ns_watcher);
                    } else {
                        debug!("Namespace watcher already running; skipping respawn on reconnect");
                    }

                    if state.oci_repository_watcher.is_none() {
                        let oci_watcher_state = GlobalWatcherState {
                            tcp_client: state.tcp_client.clone(),
                            kube_client: state.kube_client.clone(),
                            kind: KIND_OCI_REPOSITORY,
                        };

                        let (oci_watcher, _) = Actor::spawn_linked(
                            Some("cluster.flux.ocirepositories".into()),
                            OciRepositoryWatcher,
                            oci_watcher_state,
                            myself.clone().into(),
                        )
                        .await?;

                        state.oci_repository_watcher = Some(oci_watcher);
                    } else {
                        debug!(
                            "OCIRepository watcher already running; skipping respawn on reconnect"
                        );
                    }

                    if state.kustomization_watcher.is_none() {
                        let ks_watcher_state = GlobalWatcherState {
                            tcp_client: state.tcp_client.clone(),
                            kube_client: state.kube_client.clone(),
                            kind: KIND_KUSTOMIZATION,
                        };

                        let (ks_watcher, _) = Actor::spawn_linked(
                            Some("cluster.flux.kustomizations".into()),
                            KustomizationWatcher,
                            ks_watcher_state,
                            myself.clone().into(),
                        )
                        .await?;

                        state.kustomization_watcher = Some(ks_watcher);
                    } else {
                        debug!(
                            "Kustomization watcher already running; skipping respawn on reconnect"
                        );
                    }
                }
                ClientEvent::MessagePublished { .. } => {
                    todo!("Handle incoming messages")
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
}

impl_namespaced_watcher!(
    DeploymentWatcher,
    resource = Deployment,
    kind = "Deployment"
);
impl_namespaced_watcher!(
    ReplicasetWatcher,
    resource = ReplicaSet,
    kind = "ReplicaSet"
);
impl_namespaced_watcher!(PodWatcher, resource = Pod, kind = "Pod");
impl_namespaced_watcher!(SecretWatcher, resource = Secret, kind = "Secret");
impl_namespaced_watcher!(ConfigMapWatcher, resource = ConfigMap, kind = "ConfigMap");
impl_namespaced_watcher!(JobWatcher, resource = Job, kind = "Job");
// impl_namespaced_watcher!(ContainerWatcher, resource = Container, kind = "Container");

pub struct NamespaceWatcherSupervisor;
pub struct NamespaceWatcherSupervisorArgs {
    pub observer: ActorRef<ObserverSupervisorMessage>,
    pub kube_client: Client,
    pub tcp_client: TcpClient,
    pub namespace: String,
}
pub struct NamespaceWatcherSupervisorState {
    pub observer: ActorRef<ObserverSupervisorMessage>,
    pub kube_client: Client,
    pub tcp_client: TcpClient,
    pub namespace: String,
    pub deployment_watcher: Watcher,
    pub replicaset_watcher: Watcher,
    pub pod_watcher: Watcher,
}

#[async_trait]
impl Actor for NamespaceWatcherSupervisor {
    type Msg = ();
    type State = NamespaceWatcherSupervisorState;
    type Arguments = NamespaceWatcherSupervisorArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        debug!("{myself:?} starting");

        // TODO: This is getting ugly fast, various calls to the impl_watcher! macro, not very DRY init flow, it works, but I do hate it.
        // We could benefit from a function that instantiates the namesapce watcher, and that doesn't eat so much memory doing all the cloning.
        let d_watcher = NamespacedWatcherState {
            tcp_client: args.tcp_client.clone(),
            kube_client: args.kube_client.clone(),
            kind: "Deployment",
            namespace: args.namespace.clone(),
        };

        let deployment_watcher = Actor::spawn_linked(
            Some(format!("cluster.{ns}.deployments", ns = args.namespace)),
            DeploymentWatcher,
            d_watcher,
            myself.clone().into(),
        )
        .await?
        .0;

        let rs_watcher = NamespacedWatcherState {
            tcp_client: args.tcp_client.clone(),
            kube_client: args.kube_client.clone(),
            kind: "ReplicaSet",
            namespace: args.namespace.clone(),
        };

        let replicaset_watcher = Actor::spawn_linked(
            Some(format!("cluster.{ns}.replicasets", ns = args.namespace)),
            ReplicasetWatcher,
            rs_watcher,
            myself.clone().into(),
        )
        .await?
        .0;

        let p_watcher = NamespacedWatcherState {
            tcp_client: args.tcp_client.clone(),
            kube_client: args.kube_client.clone(),
            kind: "Pod",
            namespace: args.namespace.clone(),
        };

        let pod_watcher = Actor::spawn_linked(
            Some(format!("cluster.{ns}.pods", ns = args.namespace)),
            PodWatcher,
            p_watcher,
            myself.clone().into(),
        )
        .await?
        .0;

        let j_watcher = NamespacedWatcherState {
            tcp_client: args.tcp_client.clone(),
            kube_client: args.kube_client.clone(),
            kind: "Job",
            namespace: args.namespace.clone(),
        };

        let _job_watcher = Actor::spawn_linked(
            Some(format!("cluster.{ns}.jobs", ns = args.namespace)),
            JobWatcher,
            j_watcher,
            myself.clone().into(),
        )
        .await?
        .0;

        let state = NamespaceWatcherSupervisorState {
            observer: args.observer,
            namespace: args.namespace,
            tcp_client: args.tcp_client,
            kube_client: args.kube_client,
            deployment_watcher,
            replicaset_watcher,
            pod_watcher,
        };

        Ok(state)
    }

    async fn post_start(
        &self,
        myself: ActorRef<Self::Msg>,
        _state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        debug!("{myself:?} started");
        Ok(())
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        _state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        //TODO: handle messages that might come in
        debug!("Received message {message:?}");
        Ok(())
    }

    async fn handle_supervisor_evt(
        &self,
        _: ActorRef<Self::Msg>,
        msg: SupervisionEvent,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match msg {
            // A watcher fails when it has lost its watch; one that only stops was stopped on
            // purpose, as when its namespace goes. Nothing else would ever watch that kind here
            // again, so the agent has to start over.
            SupervisionEvent::ActorFailed(watcher, e) => {
                let _ = state.observer.cast(ObserverSupervisorMessage::WatchLost {
                    watcher: watcher.get_name().unwrap_or_default(),
                    reason: e.to_string(),
                });
            }
            other => debug!("Saw supervision event {other:?}"),
        }
        Ok(())
    }
}

struct NamespaceSupervisor;

pub struct NamespaceSupervisorState {
    pub observer: ActorRef<ObserverSupervisorMessage>,
    pub kube_client: Client,
    pub tcp_client: TcpClient,
    pub supervisors: NamespaceWatcherMap,
}
impl NamespaceSupervisor {
    /// A typed specific override of list_and_watch implementations.
    /// When we see namespaces, we want to spawn supervisors that will handle watchers for us.
    #[instrument(skip(observer, tcp_client, kube_client))]
    pub async fn list_and_watch_namespaces(
        myself: &Watcher,
        observer: &ActorRef<ObserverSupervisorMessage>,
        tcp_client: &TcpClient,
        kube_client: Client,
        supervisors: &mut NamespaceWatcherMap,
    ) -> Result<(), ActorProcessingErr> {
        // get all deployed pods in our given namespace
        let api: Api<Namespace> = Api::all(kube_client.clone());
        let kind = "Namespace";

        debug!("Observing {} resources.", kind);
        // ---- LIST ----
        let list = api.list(&ListParams::default()).await?;

        let resource_version = list.metadata.resource_version.clone();

        for ns in list.items {
            debug!("Discovered k8s object of kind: {kind}. {ns:?} ");
            let ev = RawKubeEvent {
                kind: kind.to_string(),
                action: RESOURCE_APPLIED_ACTION.into(),
                object: to_value(&ns)?,
                resource_version: resource_version.clone(),
            };

            emit_event(tcp_client, ev).await?;
            let ns_name = ns.name_any();

            let supervisor_state = NamespaceWatcherSupervisorArgs {
                observer: observer.clone(),
                tcp_client: tcp_client.to_owned(),
                kube_client: kube_client.clone(),
                namespace: ns_name.clone(),
            };
            //spawn watcher supervisor
            match Actor::spawn_linked(
                Some(format!("cluster.{ns_name}.supervisor")),
                NamespaceWatcherSupervisor,
                supervisor_state,
                myself.clone().into(),
            )
            .await
            {
                Ok((supervisior, _)) => {
                    let _ = supervisors.insert(ns_name, supervisior);
                }
                Err(e) => return Err(e.into()),
            }
        }
        // ---------------------------------------------------------------------
        // WATCHER CONFIGURATION
        // ---------------------------------------------------------------------
        //
        // We rely on kube_runtime's watcher to:
        //  - Perform initial LIST
        //  - Handle relisting on 410 Gone
        //  - Maintain resourceVersion continuity
        //
        // We enable bookmarks for better stream continuity and observability.
        //
        let watcher_config = watcher::Config {
            label_selector: None,
            field_selector: None,
            timeout: None,
            list_semantic: watcher::ListSemantic::MostRecent,
            initial_list_strategy: watcher::InitialListStrategy::ListWatch,
            page_size: None,
            bookmarks: true,
        };

        // ---------------------------------------------------------------------
        // STREAM INITIALIZATION
        // ---------------------------------------------------------------------

        let mut stream = watcher(api, watcher_config).boxed();

        // ---------------------------------------------------------------------
        // EVENT LOOP
        // ---------------------------------------------------------------------
        //
        // This loop is intentionally infinite. If it exits, something abnormal
        // occurred and we fail hard so supervision can restart us.
        //
        while let Some(event) = stream.try_next().await? {
            trace!("Observed kube event for kind {kind}: {event:?}");

            match event {
                Event::Apply(obj) => {
                    let ns_name = obj.name_any();

                    debug!("Discovered new namespace {ns_name}");
                    let ev = RawKubeEvent {
                        kind: kind.into(),
                        action: RESOURCE_APPLIED_ACTION.into(),
                        object: serde_json::to_value(obj)?,
                        resource_version: None, // runtime watcher manages this internally
                    };

                    emit_event(tcp_client, ev).await?;

                    match supervisors.get(&ns_name) {
                        Some(_s) => (),
                        None => {
                            //spawn watcher supervisor
                            let supervisor_state = NamespaceWatcherSupervisorArgs {
                                observer: observer.clone(),
                                kube_client: kube_client.clone(),
                                tcp_client: tcp_client.to_owned(),
                                namespace: ns_name.clone(),
                            };

                            match Actor::spawn_linked(
                                Some(format!("cluster.{ns_name}.supervisor")),
                                NamespaceWatcherSupervisor,
                                supervisor_state,
                                myself.clone().into(),
                            )
                            .await
                            {
                                Ok((supervisior, _)) => {
                                    let _ = supervisors.insert(ns_name, supervisior);
                                }
                                Err(e) => return Err(e.into()),
                            }
                        }
                    }
                }

                Event::Delete(obj) => {
                    let ns_name = obj.name_any();

                    debug!("Namespace {ns_name} was deleted.");
                    let ev = RawKubeEvent {
                        kind: kind.into(),
                        action: RESOURCE_DELETED_ACTION.into(),
                        object: serde_json::to_value(obj)?,
                        resource_version: None,
                    };

                    emit_event(tcp_client, ev).await?;

                    if let Some(_supervisor) = supervisors.get(&ns_name) {
                        debug!("removing namespace supervisor for {ns_name} ");
                        if let Some((_ns, supervisor)) = supervisors.remove_entry(&ns_name) {
                            supervisor
                                .stop_children_and_wait(None, Some(Duration::from_millis(500)))
                                .await;
                            supervisor.stop(None);
                        }
                    }
                }
                _ => (),
            }
        }

        error!("Watcher stream for {kind} terminated unexpectedly");

        Err(ActorProcessingErr::from(format!(
            "watch stream for {kind} ended unexpectedly"
        )))
    }
}
#[async_trait]
impl Actor for NamespaceSupervisor {
    type Msg = WatcherMsg;
    type State = NamespaceSupervisorState;
    type Arguments = NamespaceSupervisorState;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        state: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        debug!("{myself:?} starting");
        Ok(state)
    }

    async fn post_start(
        &self,
        myself: ActorRef<Self::Msg>,
        _state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        debug!("{myself:?} stgarted");
        myself.cast(WatcherMsg::Start)?;
        Ok(())
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            WatcherMsg::Start => {
                if let Err(e) = Self::list_and_watch_namespaces(
                    &myself,
                    &state.observer,
                    &state.tcp_client,
                    state.kube_client.clone(),
                    &mut state.supervisors,
                )
                .await
                {
                    error!("Failed to watch namespaces {e}");
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cassini_client::TcpClientMessage;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

    /// What the stand-in for the Kubernetes API does with every request.
    #[derive(Clone, Copy)]
    enum StandIn {
        /// Lists nothing, and a watch is told at once that its version has gone (410), as the
        /// API server says to a watch that has fallen behind. The watch was going, then lost.
        ListsThenTheWatchIsGone,
        /// This cluster has no such kind (404), as for Flux's kinds where Flux is not installed.
        NoSuchKind,
        /// Takes the request and never answers, a watch quietly going.
        Silent,
    }

    fn answer(api: StandIn, head: &str) -> Option<(&'static str, String)> {
        match api {
            StandIn::Silent => None,
            StandIn::NoSuchKind => Some((
                "404 Not Found",
                r#"{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"the server could not find the requested resource","reason":"NotFound","code":404}"#
                    .to_string(),
            )),
            StandIn::ListsThenTheWatchIsGone if head.contains("watch=true") => Some((
                "200 OK",
                concat!(
                    r#"{"type":"ERROR","object":{"kind":"Status","apiVersion":"v1","metadata":{},"#,
                    r#""status":"Failure","message":"too old resource version","reason":"Expired","code":410}}"#,
                    "\n"
                )
                .to_string(),
            )),
            StandIn::ListsThenTheWatchIsGone => Some((
                "200 OK",
                r#"{"kind":"List","apiVersion":"v1","metadata":{"resourceVersion":"1"},"items":[]}"#
                    .to_string(),
            )),
        }
    }

    /// A client of a stand-in for the Kubernetes API, over plain HTTP on a local port.
    async fn kube_client(api: StandIn) -> Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut request = vec![0; 8192];
                    let read = stream.read(&mut request).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(&request[..read]).to_string();
                    match answer(api, &head) {
                        Some((status, body)) => {
                            let response = format!(
                                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\n\
                                 content-length: {}\r\nconnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            let _ = stream.write_all(response.as_bytes()).await;
                        }
                        None => std::future::pending::<()>().await,
                    }
                });
            }
        });
        let config = Config::new(format!("http://127.0.0.1:{port}").parse().unwrap());
        Client::try_from(config).unwrap()
    }

    /// A client nothing here publishes through: the stand-in lists nothing, so there is no event.
    struct NoBroker;

    #[async_trait]
    impl Actor for NoBroker {
        type Msg = TcpClientMessage;
        type State = ();
        type Arguments = ();

        async fn pre_start(
            &self,
            _: ActorRef<Self::Msg>,
            _: (),
        ) -> Result<Self::State, ActorProcessingErr> {
            Ok(())
        }
    }

    async fn tcp_client() -> TcpClient {
        let (broker, _) = Actor::spawn(None, NoBroker, ()).await.unwrap();
        TcpClient::from_actor_ref(broker)
    }

    /// Stands in for ClusterObserverSupervisor: says which watcher was reported lost.
    struct Top;

    #[async_trait]
    impl Actor for Top {
        type Msg = ObserverSupervisorMessage;
        type State = UnboundedSender<String>;
        type Arguments = UnboundedSender<String>;

        async fn pre_start(
            &self,
            _: ActorRef<Self::Msg>,
            told: Self::Arguments,
        ) -> Result<Self::State, ActorProcessingErr> {
            Ok(told)
        }

        async fn handle(
            &self,
            _: ActorRef<Self::Msg>,
            message: Self::Msg,
            told: &mut Self::State,
        ) -> Result<(), ActorProcessingErr> {
            if let ObserverSupervisorMessage::WatchLost { watcher, .. } = message {
                let _ = told.send(watcher);
            }
            Ok(())
        }
    }

    /// Stands in for ClusterObserverSupervisor as a parent: says how a child ended.
    struct Parent;

    #[async_trait]
    impl Actor for Parent {
        type Msg = ();
        type State = UnboundedSender<&'static str>;
        type Arguments = UnboundedSender<&'static str>;

        async fn pre_start(
            &self,
            _: ActorRef<Self::Msg>,
            told: Self::Arguments,
        ) -> Result<Self::State, ActorProcessingErr> {
            Ok(told)
        }

        async fn handle_supervisor_evt(
            &self,
            _: ActorRef<Self::Msg>,
            event: SupervisionEvent,
            told: &mut Self::State,
        ) -> Result<(), ActorProcessingErr> {
            match event {
                SupervisionEvent::ActorFailed(..) => {
                    let _ = told.send("failed");
                }
                SupervisionEvent::ActorTerminated(..) => {
                    let _ = told.send("stopped");
                }
                _ => (),
            }
            Ok(())
        }
    }

    const LONG_ENOUGH: Duration = Duration::from_secs(10);
    const QUIET_FOR: Duration = Duration::from_secs(2);

    async fn namespace_under_top(
        namespace: &str,
        api: StandIn,
    ) -> (ActorRef<()>, UnboundedReceiver<String>) {
        let (told, heard) = unbounded_channel();
        let (top, _) = Actor::spawn(None, Top, told).await.unwrap();
        let (supervisor, _) = Actor::spawn(
            None,
            NamespaceWatcherSupervisor,
            NamespaceWatcherSupervisorArgs {
                observer: top,
                kube_client: kube_client(api).await,
                tcp_client: tcp_client().await,
                namespace: namespace.to_string(),
            },
        )
        .await
        .unwrap();
        (supervisor, heard)
    }

    #[tokio::test]
    async fn a_namespaced_watch_that_is_lost_reaches_the_top_supervisor() {
        let (_supervisor, mut heard) =
            namespace_under_top("lost", StandIn::ListsThenTheWatchIsGone).await;

        let watcher = tokio::time::timeout(LONG_ENOUGH, heard.recv())
            .await
            .expect("nobody told the top supervisor that a watch was lost")
            .unwrap();

        assert!(watcher.starts_with("cluster.lost."), "{watcher}");
    }

    #[tokio::test]
    async fn a_watcher_that_ends_without_failing_is_not_a_lost_watch() {
        // How a watcher goes when its namespace goes: on purpose, by whoever owns it.
        let (supervisor, mut heard) = namespace_under_top("going", StandIn::Silent).await;

        supervisor.get_children()[0].kill();

        let told = tokio::time::timeout(QUIET_FOR, heard.recv()).await;
        assert!(told.is_err(), "told of a lost watch: {told:?}");
    }

    async fn flux_watcher_under_parent(api: StandIn) -> UnboundedReceiver<&'static str> {
        let (told, heard) = unbounded_channel();
        let (parent, _) = Actor::spawn(None, Parent, told).await.unwrap();
        Actor::spawn_linked(
            None,
            OciRepositoryWatcher,
            GlobalWatcherState {
                kube_client: kube_client(api).await,
                tcp_client: tcp_client().await,
                kind: KIND_OCI_REPOSITORY,
            },
            parent.get_cell(),
        )
        .await
        .unwrap();
        heard
    }

    #[tokio::test]
    async fn a_cluster_wide_watch_that_is_lost_fails_its_watcher() {
        // ClusterObserverSupervisor ends the agent on a child's failure, and not on its stopping.
        let mut heard = flux_watcher_under_parent(StandIn::ListsThenTheWatchIsGone).await;

        let ended = tokio::time::timeout(LONG_ENOUGH, heard.recv())
            .await
            .expect("the watcher did not end")
            .unwrap();

        assert_eq!(ended, "failed");
    }

    #[tokio::test]
    async fn a_kind_this_cluster_does_not_have_is_no_failure() {
        // A cluster without Flux: this must not become a restart loop.
        let mut heard = flux_watcher_under_parent(StandIn::NoSuchKind).await;

        let ended = tokio::time::timeout(QUIET_FOR, heard.recv()).await;

        assert!(ended.is_err(), "the watcher ended: {ended:?}");
    }
}
