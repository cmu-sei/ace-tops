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

//! What the observer watches, and what it does with what it sees. The stream is the protocol handler's: this says which watches there
//! should be, as namespaces come and go, and publishes each change at the pace it can (docs/architecture/cassini-backpressure.md).
//!
//! A watch that ends is asked for again. It starts from a list, which says again everything there is, so the consumer loses only what was
//! deleted meanwhile, as it does when the observer itself restarts.

use cassini_client::{OfflineBehavior, PublishRequest};
use k8s_openapi::api::apps::v1::{Deployment, ReplicaSet};
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::{Namespace, Pod};
use kube_common::{
    KIND_KUSTOMIZATION, KIND_OCI_REPOSITORY, KUBERNETES_CONSUMER, RESOURCE_APPLIED_ACTION,
    RESOURCE_DELETED_ACTION, RawKubeEvent,
};
use polar::cassini::TcpClient;
use polar_agent_builder::ConfigurationHandle;
use polar_agent_builder::protocol::kubernetes::{self, Kubernetes, Resource};
use polar_agent_builder::protocol::{
    Access, Delivery, Failure, Location, Operation, OperationDecl, ProtocolHandle, ProtocolKind,
    ReadFailure, Streaming, Verb,
};
use ractor::{Actor, ActorProcessingErr, ActorRef, async_trait};
use serde_json::{Value, to_vec};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// What the agent asks of the Kubernetes API.
pub const WATCH: OperationDecl = OperationDecl {
    name: "kube.watch",
    doc: "every change to the cluster's namespaces, their workloads and pods, and Flux's sources and kustomizations",
    protocol: ProtocolKind::KUBERNETES,
    location: Location::Cluster { access: &WATCHED },
};

/// What it may do: watch each kind it watches, and nothing else.
const WATCHED: [Access; 7] = [
    Kind::Namespace.resource().access(Verb::Watch),
    Kind::OciRepository.resource().access(Verb::Watch),
    Kind::Kustomization.resource().access(Verb::Watch),
    Kind::Deployment.resource().access(Verb::Watch),
    Kind::ReplicaSet.resource().access(Verb::Watch),
    Kind::Pod.resource().access(Verb::Watch),
    Kind::Job.resource().access(Verb::Watch),
];

/// A kind it watches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Namespace,
    OciRepository,
    Kustomization,
    Deployment,
    ReplicaSet,
    Pod,
    Job,
}

/// Watched across the cluster.
const CLUSTER_WIDE: [Kind; 3] = [Kind::Namespace, Kind::OciRepository, Kind::Kustomization];

/// Watched in each namespace.
const IN_EACH_NAMESPACE: [Kind; 4] = [Kind::Deployment, Kind::ReplicaSet, Kind::Pod, Kind::Job];

const OCI_REPOSITORY: Resource = Resource {
    group: "source.toolkit.fluxcd.io",
    version: "v1",
    kind: KIND_OCI_REPOSITORY,
    plural: "ocirepositories",
};

const KUSTOMIZATION: Resource = Resource {
    group: "kustomize.toolkit.fluxcd.io",
    version: "v1",
    kind: KIND_KUSTOMIZATION,
    plural: "kustomizations",
};

impl Kind {
    const fn resource(self) -> Resource {
        match self {
            Kind::Namespace => Resource::of::<Namespace>(),
            Kind::OciRepository => OCI_REPOSITORY,
            Kind::Kustomization => KUSTOMIZATION,
            Kind::Deployment => Resource::of::<Deployment>(),
            Kind::ReplicaSet => Resource::of::<ReplicaSet>(),
            Kind::Pod => Resource::of::<Pod>(),
            Kind::Job => Resource::of::<Job>(),
        }
    }
}

/// One watch: a kind, and the namespace it is in, if it is not across the cluster.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Watched {
    pub kind: Kind,
    pub namespace: Option<String>,
}

/// What it reads from what a watch says.
#[derive(Debug, Clone)]
pub enum Seen {
    Listing,
    Listed,
    Applied(RawKubeEvent),
    Deleted(RawKubeEvent),
}

/// A watch, as a request of the handler's.
pub struct Watching(pub Watched);

fn event(kind: Kind, action: &str, object: &Value) -> RawKubeEvent {
    RawKubeEvent {
        kind: kind.resource().kind.to_string(),
        action: action.to_string(),
        object: object.clone(),
        // The watcher keeps it, and the consumer does not read it.
        resource_version: None,
    }
}

impl Operation for Watching {
    type Protocol = Kubernetes;
    type Output = Seen;
    const DECL: OperationDecl = WATCH;

    fn request(&self) -> kubernetes::Call {
        let resource = self.0.kind.resource();
        match &self.0.namespace {
            Some(namespace) => kubernetes::Watch::in_namespace(resource, namespace.clone()),
            None => kubernetes::Watch::cluster_wide(resource),
        }
        .into()
    }

    fn read(&self, said: &kubernetes::Answer) -> Result<Seen, ReadFailure> {
        let kind = self.0.kind;
        Ok(match said.change()? {
            kubernetes::Change::Listing => Seen::Listing,
            kubernetes::Change::Listed => Seen::Listed,
            kubernetes::Change::Applied(object) => {
                Seen::Applied(event(kind, RESOURCE_APPLIED_ACTION, object))
            }
            kubernetes::Change::Deleted(object) => {
                Seen::Deleted(event(kind, RESOURCE_DELETED_ACTION, object))
            }
        })
    }
}

/// Which namespaces are watched, from what the watch of namespaces says. A namespace that went while that watch was lost is
/// told by its not being in the next list.
#[derive(Debug, Default)]
pub struct Namespaces {
    watched: BTreeSet<String>,
    /// What the list in progress has said so far.
    listing: Option<BTreeSet<String>>,
}

impl Namespaces {
    pub fn listing(&mut self) {
        self.listing = Some(BTreeSet::new());
    }

    /// The namespace was seen. True if it is new, and so its watches are to start.
    pub fn applied(&mut self, name: &str) -> bool {
        if let Some(listing) = &mut self.listing {
            listing.insert(name.to_string());
        }
        self.watched.insert(name.to_string())
    }

    /// The namespace has gone. True if it was watched, and so its watches are to stop.
    pub fn deleted(&mut self, name: &str) -> bool {
        if let Some(listing) = &mut self.listing {
            listing.remove(name);
        }
        self.watched.remove(name)
    }

    /// The list has finished: the namespaces that were not in it, whose watches are to stop.
    pub fn listed(&mut self) -> Vec<String> {
        let Some(listing) = self.listing.take() else {
            return Vec::new();
        };
        let gone: Vec<String> = self.watched.difference(&listing).cloned().collect();
        self.watched = listing;
        gone
    }

    pub fn is_watched(&self, name: &str) -> bool {
        self.watched.contains(name)
    }
}

/// Where what it sees goes.
#[async_trait]
pub trait Publisher: Send + Sync {
    /// Waits while there is no room, so that a broker that falls behind slows the watch instead of failing it.
    async fn publish(&self, event: &RawKubeEvent) -> Result<(), String>;
}

#[async_trait]
impl Publisher for TcpClient {
    async fn publish(&self, event: &RawKubeEvent) -> Result<(), String> {
        let payload = to_vec(event).map_err(|e| e.to_string())?;
        self.publish_when_ready(PublishRequest {
            topic: KUBERNETES_CONSUMER.to_string(),
            trace_ctx: None,
            payload,
            offline_behavior: OfflineBehavior::default(),
            share_identity: true,
        })
        .await
        .map_err(|e| e.to_string())
    }
}

/// How long a watch that ended waits before it is asked for again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Waits {
    /// When it lost the API.
    pub lost: Duration,
    /// When the API refused it, or does not serve the kind: Flux's kinds are not in every cluster.
    pub refused: Duration,
}

pub enum WatcherMsg {
    /// What a watch said, or that it has ended.
    Seen {
        watched: Watched,
        delivery: Delivery<Seen>,
    },
    /// A signed update changed how long a watch waits.
    WaitsChanged(Waits),
    /// Time to ask for a watch again.
    Again(Watched),
}

pub struct ClusterWatcherArgs {
    pub protocols: ProtocolHandle,
    pub publisher: Arc<dyn Publisher>,
    pub waits: WaitsFrom,
}

/// Where the watcher has its waits.
pub enum WaitsFrom {
    /// The configuration, which it follows.
    Followed(ConfigurationHandle),
    /// As given: a test whose waits are shorter than a setting can say.
    Fixed(Waits),
}

pub struct ClusterWatcherState {
    protocols: ProtocolHandle,
    publisher: Arc<dyn Publisher>,
    waits: Waits,
    namespaces: Namespaces,
    /// Each watch in progress, which ends when it is dropped from here.
    streams: BTreeMap<Watched, Streaming>,
}

/// The watcher holds the waits, so it follows them. The answer is the waits in force.
pub async fn follow_waits(
    configuration: &ConfigurationHandle,
    myself: &ActorRef<WatcherMsg>,
) -> Result<Waits, polar_agent_builder::configuration::FollowError> {
    configuration
        .follow_group(
            crate::settings::VARIABLES,
            crate::settings::waits,
            myself,
            WatcherMsg::WaitsChanged,
        )
        .await
}

/// Every watch, and what publishes what they see. Waiting to publish holds this actor, and through its one mailbox every watch: the
/// agent's life is its supervisor's, which is not held.
pub struct ClusterWatcher;

impl ClusterWatcherState {
    fn start(
        &mut self,
        myself: &ActorRef<WatcherMsg>,
        watched: Watched,
    ) -> Result<(), ActorProcessingErr> {
        let of = watched.clone();
        let stream = self
            .protocols
            .stream(Watching(watched.clone()), myself.clone(), move |delivery| {
                WatcherMsg::Seen {
                    watched: of.clone(),
                    delivery,
                }
            })
            .map_err(|e| ActorProcessingErr::from(e.to_string()))?;
        self.streams.insert(watched, stream);
        Ok(())
    }

    fn start_namespace(
        &mut self,
        myself: &ActorRef<WatcherMsg>,
        namespace: &str,
    ) -> Result<(), ActorProcessingErr> {
        debug!("watching namespace {namespace}");
        for kind in IN_EACH_NAMESPACE {
            self.start(
                myself,
                Watched {
                    kind,
                    namespace: Some(namespace.to_string()),
                },
            )?;
        }
        Ok(())
    }

    fn stop_namespace(&mut self, namespace: &str) {
        debug!("no longer watching namespace {namespace}");
        self.streams
            .retain(|watched, _| watched.namespace.as_deref() != Some(namespace));
    }

    /// Publishes, and a publish that is refused goes no further. There are two ways to be refused, a client that has gone, whose agent is
    /// ending, and an object over what a frame carries, which will not fit next time either.
    async fn publish(&self, event: &RawKubeEvent) {
        if let Err(why) = self.publisher.publish(event).await {
            error!(kind = event.kind, "a change was not published: {why}");
        }
    }

    async fn seen(
        &mut self,
        myself: &ActorRef<WatcherMsg>,
        watched: &Watched,
        seen: Seen,
    ) -> Result<(), ActorProcessingErr> {
        let of_namespaces = watched.kind == Kind::Namespace;
        match seen {
            Seen::Listing if of_namespaces => self.namespaces.listing(),
            Seen::Listed if of_namespaces => {
                for gone in self.namespaces.listed() {
                    self.stop_namespace(&gone);
                }
            }
            Seen::Listing | Seen::Listed => {}
            Seen::Applied(event) => {
                self.publish(&event).await;
                if of_namespaces
                    && let Some(name) = name_of(&event.object)
                    && self.namespaces.applied(name)
                {
                    self.start_namespace(myself, name)?;
                }
            }
            Seen::Deleted(event) => {
                self.publish(&event).await;
                if of_namespaces
                    && let Some(name) = name_of(&event.object)
                    && self.namespaces.deleted(name)
                {
                    self.stop_namespace(name);
                }
            }
        }
        Ok(())
    }

    /// A watch ended. It is asked for again, after a while.
    fn ended(&mut self, myself: &ActorRef<WatcherMsg>, watched: Watched, why: &Failure) {
        warn!(
            ?watched,
            "a watch ended, and will be asked for again: {why}"
        );
        self.streams.remove(&watched);
        let wait = match why {
            Failure::Configuration(_) => self.waits.refused,
            _ => self.waits.lost,
        };
        myself.send_after(wait, move || WatcherMsg::Again(watched));
    }

    /// Whether a watch that ended is still wanted: its namespace may have gone meanwhile.
    fn wants(&self, watched: &Watched) -> bool {
        match &watched.namespace {
            Some(namespace) => self.namespaces.is_watched(namespace),
            None => true,
        }
    }
}

fn name_of(object: &Value) -> Option<&str> {
    object.get("metadata")?.get("name")?.as_str()
}

#[async_trait]
impl Actor for ClusterWatcher {
    type Msg = WatcherMsg;
    type State = ClusterWatcherState;
    type Arguments = ClusterWatcherArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        let waits = match &args.waits {
            WaitsFrom::Followed(configuration) => follow_waits(configuration, &myself).await?,
            WaitsFrom::Fixed(waits) => *waits,
        };
        let mut state = ClusterWatcherState {
            protocols: args.protocols,
            publisher: args.publisher,
            waits,
            namespaces: Namespaces::default(),
            streams: BTreeMap::new(),
        };
        for kind in CLUSTER_WIDE {
            state.start(
                &myself,
                Watched {
                    kind,
                    namespace: None,
                },
            )?;
        }
        info!("watching the cluster");
        Ok(state)
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            WatcherMsg::Seen { watched, delivery } => match delivery.result {
                Ok(seen) => state.seen(&myself, &watched, seen).await?,
                Err(why) => state.ended(&myself, watched, &why),
            },
            // A watch already waiting keeps what it was told.
            WatcherMsg::WaitsChanged(waits) => state.waits = waits,
            WatcherMsg::Again(watched) => {
                if state.wants(&watched) {
                    state.start(&myself, watched)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::Resource as _;

    /// Every kind it watches is one its operation declares, so no watch it starts is refused for want of it.
    #[test]
    fn every_kind_it_watches_is_declared() {
        for kind in CLUSTER_WIDE.iter().chain(&IN_EACH_NAMESPACE) {
            assert!(
                WATCHED.contains(&kind.resource().access(Verb::Watch)),
                "{kind:?}"
            );
        }
        assert_eq!(WATCHED.len(), CLUSTER_WIDE.len() + IN_EACH_NAMESPACE.len());
    }
    use kube_common::flux::kustomization::Kustomization;
    use kube_common::flux::oci_repositories::OciRepository;
    use polar_agent_builder::protocol::testing::{KubeApi, Site, kubernetes_handle};
    use proptest::prelude::*;
    use serde_json::json;
    use std::sync::Mutex;

    #[test]
    fn fluxs_kinds_are_named_as_their_types_say() {
        for (resource, group, version, kind, plural) in [
            (
                OCI_REPOSITORY,
                OciRepository::group(&()),
                OciRepository::version(&()),
                OciRepository::kind(&()),
                OciRepository::plural(&()),
            ),
            (
                KUSTOMIZATION,
                Kustomization::group(&()),
                Kustomization::version(&()),
                Kustomization::kind(&()),
                Kustomization::plural(&()),
            ),
        ] {
            assert_eq!(resource.group, group);
            assert_eq!(resource.version, version);
            assert_eq!(resource.kind, kind);
            assert_eq!(resource.plural, plural);
        }
    }

    #[test]
    fn what_a_watch_says_is_published_with_the_kind_the_consumer_goes_by() {
        let object = json!({"metadata": {"name": "a"}});
        let watching = Watching(Watched {
            kind: Kind::Pod,
            namespace: Some("polar".to_string()),
        });
        let Ok(Seen::Applied(applied)) = watching.read(&kubernetes::Answer::Change(
            kubernetes::Change::Applied(object.clone()),
        )) else {
            panic!("applied");
        };
        assert_eq!(applied.kind, "Pod");
        assert_eq!(applied.action, RESOURCE_APPLIED_ACTION);
        assert_eq!(applied.object, object);
        let Ok(Seen::Deleted(deleted)) = watching.read(&kubernetes::Answer::Change(
            kubernetes::Change::Deleted(object.clone()),
        )) else {
            panic!("deleted");
        };
        assert_eq!(deleted.action, RESOURCE_DELETED_ACTION);
        for (kind, name) in [
            (Kind::Namespace, "Namespace"),
            (Kind::Deployment, "Deployment"),
            (Kind::ReplicaSet, "ReplicaSet"),
            (Kind::Job, "Job"),
            (Kind::OciRepository, KIND_OCI_REPOSITORY),
            (Kind::Kustomization, KIND_KUSTOMIZATION),
        ] {
            assert_eq!(event(kind, "x", &object).kind, name);
        }
    }

    #[derive(Debug, Clone)]
    enum NamespaceEvent {
        Listing,
        Listed,
        Applied(u8),
        Deleted(u8),
    }

    fn a_namespace_event() -> impl Strategy<Value = NamespaceEvent> {
        prop_oneof![
            Just(NamespaceEvent::Listing),
            Just(NamespaceEvent::Listed),
            (0..6u8).prop_map(NamespaceEvent::Applied),
            (0..6u8).prop_map(NamespaceEvent::Deleted),
        ]
    }

    proptest! {
        /// What it says to start and stop always leaves the watches running as the set it keeps; a namespace is never started
        /// twice or stopped when it was not running; and at the end of a list, what is watched is what the list said.
        #[test]
        fn the_watches_running_follow_what_was_said_of_namespaces(
            events in proptest::collection::vec(a_namespace_event(), 0..40),
        ) {
            let mut namespaces = Namespaces::default();
            let mut running = BTreeSet::new();
            let mut list: Option<BTreeSet<String>> = None;
            for event in events {
                match event {
                    NamespaceEvent::Listing => {
                        namespaces.listing();
                        list = Some(BTreeSet::new());
                    }
                    NamespaceEvent::Listed => {
                        for gone in namespaces.listed() {
                            prop_assert!(running.remove(&gone));
                        }
                        if let Some(list) = list.take() {
                            prop_assert_eq!(&running, &list);
                        }
                    }
                    NamespaceEvent::Applied(name) => {
                        let name = name.to_string();
                        if let Some(list) = &mut list {
                            list.insert(name.clone());
                        }
                        if namespaces.applied(&name) {
                            prop_assert!(running.insert(name));
                        }
                    }
                    NamespaceEvent::Deleted(name) => {
                        let name = name.to_string();
                        if let Some(list) = &mut list {
                            list.remove(&name);
                        }
                        if namespaces.deleted(&name) {
                            prop_assert!(running.remove(&name));
                        }
                    }
                }
                for name in 0..6u8 {
                    let name = name.to_string();
                    prop_assert_eq!(namespaces.is_watched(&name), running.contains(&name));
                }
            }
        }
    }

    /// Keeps what is published, after waiting for the gate if it is shut.
    #[derive(Default)]
    struct Kept {
        events: Mutex<Vec<RawKubeEvent>>,
        gate: tokio::sync::RwLock<()>,
    }

    #[async_trait]
    impl Publisher for Kept {
        async fn publish(&self, event: &RawKubeEvent) -> Result<(), String> {
            self.events.lock().unwrap().push(event.clone());
            let _open = self.gate.read().await;
            Ok(())
        }
    }

    impl Kept {
        fn names(&self, kind: &str) -> Vec<String> {
            self.events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| event.kind == kind)
                .filter_map(|event| name_of(&event.object).map(str::to_string))
                .collect()
        }

        async fn until(&self, what: &str, done: impl Fn(&Self) -> bool) {
            for _ in 0..1000 {
                if done(self) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            panic!(
                "{what}: {:?}",
                self.events
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|e| (&e.kind, &e.action, name_of(&e.object)))
                    .collect::<Vec<_>>()
            );
        }
    }

    fn named(name: &str) -> Value {
        json!({"metadata": {"name": name, "resourceVersion": "1"}})
    }

    const FAST: Waits = Waits {
        lost: Duration::from_millis(10),
        refused: Duration::from_millis(10),
    };

    const NAMESPACES: &str = "/api/v1/namespaces";
    const POLAR_PODS: &str = "/api/v1/namespaces/polar/pods";

    /// The namespaced paths of `namespace`, each holding nothing.
    fn empty_namespace(api: &KubeApi, namespace: &str) {
        for path in [
            format!("/apis/apps/v1/namespaces/{namespace}/deployments"),
            format!("/apis/apps/v1/namespaces/{namespace}/replicasets"),
            format!("/api/v1/namespaces/{namespace}/pods"),
            format!("/apis/batch/v1/namespaces/{namespace}/jobs"),
        ] {
            api.holds(&path, vec![]);
        }
    }

    async fn watching(api: &KubeApi) -> (Site, Arc<Kept>, ActorRef<WatcherMsg>) {
        watching_with(api, FAST).await
    }

    async fn watching_with(api: &KubeApi, waits: Waits) -> (Site, Arc<Kept>, ActorRef<WatcherMsg>) {
        static OPERATIONS: [OperationDecl; 1] = [WATCH];
        let site = kubernetes_handle(&OPERATIONS, api).await;
        let kept = Arc::new(Kept::default());
        let (actor, _) = Actor::spawn(
            None,
            ClusterWatcher,
            ClusterWatcherArgs {
                protocols: site.handle.clone(),
                publisher: kept.clone(),
                waits: WaitsFrom::Fixed(waits),
            },
        )
        .await
        .unwrap();
        (site, kept, actor)
    }

    /// What the API refuses will not change in a moment, so it is asked about rarely; what was lost may be back at once.
    #[tokio::test]
    async fn a_refused_watch_waits_longer_than_a_lost_one() {
        const KUSTOMIZATIONS: &str = "/apis/kustomize.toolkit.fluxcd.io/v1/kustomizations";
        let api = KubeApi::start().await;
        api.holds(NAMESPACES, vec![named("first")]);
        api.then_fails(NAMESPACES, 500);
        empty_namespace(&api, "first");
        empty_namespace(&api, "back");
        let waits = Waits {
            lost: Duration::from_millis(10),
            refused: Duration::from_secs(3600),
        };
        let (_site, kept, _actor) = watching_with(&api, waits).await;
        kept.until("the first list", |kept| {
            kept.names("Namespace") == ["first"]
        })
        .await;
        api.holds(NAMESPACES, vec![named("back")]);
        kept.until("the list after it was lost", |kept| {
            kept.names("Namespace") == ["first", "back"]
        })
        .await;
        api.holds(KUSTOMIZATIONS, vec![named("served-now")]);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(api.asked_of(KUSTOMIZATIONS).await, 1, "once, and not again");
        assert!(kept.names(KIND_KUSTOMIZATION).is_empty());
    }

    /// One run through the handler, over a stand-in for the API: the namespaces, and in each the kinds of it, and Flux's across the
    /// cluster, with each object as it was listed.
    #[tokio::test]
    async fn it_publishes_what_the_cluster_has() {
        let api = KubeApi::start().await;
        api.holds(NAMESPACES, vec![named("polar")]);
        api.holds(
            "/apis/source.toolkit.fluxcd.io/v1/ocirepositories",
            vec![named("a-source")],
        );
        api.holds(
            "/apis/kustomize.toolkit.fluxcd.io/v1/kustomizations",
            vec![named("a-kustomization")],
        );
        api.holds(
            "/apis/apps/v1/namespaces/polar/deployments",
            vec![named("a-deployment")],
        );
        api.holds(
            "/apis/apps/v1/namespaces/polar/replicasets",
            vec![named("a-replicaset")],
        );
        api.holds(POLAR_PODS, vec![named("a-pod")]);
        api.holds("/apis/batch/v1/namespaces/polar/jobs", vec![named("a-job")]);
        let (site, kept, _actor) = watching(&api).await;
        kept.until("every kind", |kept| kept.events.lock().unwrap().len() >= 7)
            .await;
        for (kind, name) in [
            ("Namespace", "polar"),
            (KIND_OCI_REPOSITORY, "a-source"),
            (KIND_KUSTOMIZATION, "a-kustomization"),
            ("Deployment", "a-deployment"),
            ("ReplicaSet", "a-replicaset"),
            ("Pod", "a-pod"),
            ("Job", "a-job"),
        ] {
            assert_eq!(kept.names(kind), [name], "{kind}");
        }
        assert!(
            kept.events
                .lock()
                .unwrap()
                .iter()
                .all(|event| event.action == RESOURCE_APPLIED_ACTION)
        );
        let records = site.records.lock().unwrap().clone();
        assert_eq!(records.len(), 7, "one line for each watch: {records:?}");
        assert!(records.iter().all(|record| record.verdict == "allowed"));
    }

    /// A kind the cluster does not serve (Flux's, say) costs its own watch and nothing else, and it is asked for again in case it comes.
    #[tokio::test]
    async fn a_kind_the_api_does_not_serve_leaves_the_rest_watching() {
        let api = KubeApi::start().await;
        api.holds(NAMESPACES, vec![named("polar")]);
        empty_namespace(&api, "polar");
        api.holds(POLAR_PODS, vec![named("a-pod")]);
        let (site, kept, _actor) = watching(&api).await;
        kept.until("the pod", |kept| !kept.names("Pod").is_empty())
            .await;
        // Asked again, it has come.
        api.holds(
            "/apis/kustomize.toolkit.fluxcd.io/v1/kustomizations",
            vec![named("now-served")],
        );
        kept.until("the kind that came", |kept| {
            !kept.names(KIND_KUSTOMIZATION).is_empty()
        })
        .await;
        assert!(site.records.lock().unwrap().len() > 7);
    }

    #[tokio::test]
    async fn a_namespace_that_appears_is_watched() {
        let api = KubeApi::start().await;
        api.holds(NAMESPACES, vec![named("polar")]);
        api.then_says(NAMESPACES, vec![("ADDED", "later", "2")]);
        empty_namespace(&api, "polar");
        empty_namespace(&api, "later");
        api.holds("/api/v1/namespaces/later/pods", vec![named("later-pod")]);
        let (_site, kept, _actor) = watching(&api).await;
        kept.until("the pod of the new namespace", |kept| {
            kept.names("Pod") == ["later-pod"]
        })
        .await;
        assert_eq!(kept.names("Namespace"), ["polar", "later"]);
    }

    /// A namespace that has gone has its watches stopped, so nothing more is asked of it: a watch of it that had ended is not asked for again.
    #[tokio::test]
    async fn a_namespace_that_goes_is_no_longer_watched() {
        let api = KubeApi::start().await;
        api.holds(NAMESPACES, vec![named("polar"), named("going")]);
        api.then_says(NAMESPACES, vec![("DELETED", "going", "2")]);
        empty_namespace(&api, "polar");
        // Its pods' watch ends at once, so it would ask again and again if it were still wanted.
        for _ in 0..200 {
            api.then_fails("/api/v1/namespaces/going/pods", 500);
        }
        empty_namespace(&api, "going");
        let (_site, kept, _actor) = watching(&api).await;
        kept.until("the deletion", |kept| {
            kept.events
                .lock()
                .unwrap()
                .iter()
                .any(|event| event.action == RESOURCE_DELETED_ACTION)
        })
        .await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        let asked = api.asked_of("/api/v1/namespaces/going/pods").await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(api.asked_of("/api/v1/namespaces/going/pods").await, asked);
    }

    /// A watch of namespaces lost, and listed again: what was said by the new list stands, so one that went while it was lost is no
    /// longer watched and everything there is goes out again.
    #[tokio::test]
    async fn a_watch_that_is_lost_is_asked_for_again_and_lists_everything_again() {
        let api = KubeApi::start().await;
        api.holds(NAMESPACES, vec![named("polar"), named("going")]);
        api.then_fails(NAMESPACES, 500);
        empty_namespace(&api, "polar");
        empty_namespace(&api, "going");
        let (_site, kept, _actor) = watching(&api).await;
        kept.until("the first list", |kept| kept.names("Namespace").len() == 2)
            .await;
        api.holds(NAMESPACES, vec![named("polar")]);
        kept.until("the list after it was lost", |kept| {
            kept.names("Namespace").len() == 3
        })
        .await;
        assert_eq!(kept.names("Namespace"), ["polar", "going", "polar"]);
    }

    /// A namespace that went while the watch of namespaces was lost is not in the next list, and that is the only word of it.
    #[tokio::test]
    async fn a_namespace_not_in_the_next_list_is_no_longer_watched() {
        const GOING_PODS: &str = "/api/v1/namespaces/going/pods";
        let api = KubeApi::start().await;
        api.holds(NAMESPACES, vec![named("polar"), named("going")]);
        api.then_fails(NAMESPACES, 500);
        empty_namespace(&api, "polar");
        empty_namespace(&api, "going");
        // Each watch of its pods ends at once, so it would ask again and again if it were still wanted.
        for _ in 0..500 {
            api.then_fails(GOING_PODS, 500);
        }
        let (_site, kept, _actor) = watching(&api).await;
        kept.until("the first list", |kept| kept.names("Namespace").len() == 2)
            .await;
        api.holds(NAMESPACES, vec![named("polar")]);
        kept.until("the next list", |kept| kept.names("Namespace").len() == 3)
            .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let asked = api.asked_of(GOING_PODS).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(api.asked_of(GOING_PODS).await, asked);
    }

    /// An actor that does nothing with what it is sent, for a test that works the state directly: what is decided is then seen
    /// without a race against what the streams say.
    struct Deaf;

    #[async_trait]
    impl Actor for Deaf {
        type Msg = WatcherMsg;
        type State = ();
        type Arguments = ();
        async fn pre_start(&self, _: ActorRef<Self::Msg>, _: ()) -> Result<(), ActorProcessingErr> {
            Ok(())
        }
    }

    async fn state_over(api: &KubeApi) -> (Site, ClusterWatcherState, ActorRef<WatcherMsg>) {
        static OPERATIONS: [OperationDecl; 1] = [WATCH];
        let site = kubernetes_handle(&OPERATIONS, api).await;
        let state = ClusterWatcherState {
            protocols: site.handle.clone(),
            publisher: Arc::new(Kept::default()),
            waits: FAST,
            namespaces: Namespaces::default(),
            streams: BTreeMap::new(),
        };
        let (deaf, _) = Actor::spawn(None, Deaf, ()).await.unwrap();
        (site, state, deaf)
    }

    const NAMESPACE_WATCH: Watched = Watched {
        kind: Kind::Namespace,
        namespace: None,
    };

    fn namespace_event(action: &str, name: &str) -> RawKubeEvent {
        event(Kind::Namespace, action, &named(name))
    }

    fn watches_in(state: &ClusterWatcherState, namespace: &str) -> Vec<Kind> {
        state
            .streams
            .keys()
            .filter(|watched| watched.namespace.as_deref() == Some(namespace))
            .map(|watched| watched.kind)
            .collect()
    }

    fn applied(name: &str) -> Seen {
        Seen::Applied(namespace_event(RESOURCE_APPLIED_ACTION, name))
    }

    #[tokio::test]
    async fn a_namespace_has_a_watch_of_each_kind_until_it_goes() {
        let api = KubeApi::start().await;
        let (_site, mut state, deaf) = state_over(&api).await;
        state
            .seen(&deaf, &NAMESPACE_WATCH, applied("polar"))
            .await
            .unwrap();
        state
            .seen(&deaf, &NAMESPACE_WATCH, applied("other"))
            .await
            .unwrap();
        assert_eq!(watches_in(&state, "polar"), IN_EACH_NAMESPACE);
        assert_eq!(watches_in(&state, "other"), IN_EACH_NAMESPACE);

        // Seeing it again starts nothing more, and an object of any other kind starts nothing at all.
        let before = state.streams.len();
        state
            .seen(&deaf, &NAMESPACE_WATCH, applied("polar"))
            .await
            .unwrap();
        let pods = Watched {
            kind: Kind::Pod,
            namespace: Some("polar".to_string()),
        };
        state
            .seen(&deaf, &pods, applied("not-a-namespace"))
            .await
            .unwrap();
        assert_eq!(state.streams.len(), before);
        assert!(watches_in(&state, "not-a-namespace").is_empty());

        let going = Seen::Deleted(namespace_event(RESOURCE_DELETED_ACTION, "polar"));
        state.seen(&deaf, &NAMESPACE_WATCH, going).await.unwrap();
        assert!(watches_in(&state, "polar").is_empty());
        assert_eq!(watches_in(&state, "other"), IN_EACH_NAMESPACE);
    }

    #[tokio::test]
    async fn a_namespace_not_in_the_next_list_has_its_watches_stopped() {
        let api = KubeApi::start().await;
        let (_site, mut state, deaf) = state_over(&api).await;
        state
            .seen(&deaf, &NAMESPACE_WATCH, applied("stays"))
            .await
            .unwrap();
        state
            .seen(&deaf, &NAMESPACE_WATCH, applied("went"))
            .await
            .unwrap();
        state
            .seen(&deaf, &NAMESPACE_WATCH, Seen::Listing)
            .await
            .unwrap();
        state
            .seen(&deaf, &NAMESPACE_WATCH, applied("stays"))
            .await
            .unwrap();
        // A list of something else says nothing of namespaces.
        let pods = Watched {
            kind: Kind::Pod,
            namespace: Some("stays".to_string()),
        };
        state.seen(&deaf, &pods, Seen::Listing).await.unwrap();
        state.seen(&deaf, &pods, Seen::Listed).await.unwrap();
        assert_eq!(watches_in(&state, "went"), IN_EACH_NAMESPACE);
        state
            .seen(&deaf, &NAMESPACE_WATCH, Seen::Listed)
            .await
            .unwrap();
        assert!(watches_in(&state, "went").is_empty());
        assert_eq!(watches_in(&state, "stays"), IN_EACH_NAMESPACE);
    }

    /// A watch that ended while its namespace went: it is asked for again only if the namespace is still there.
    #[tokio::test]
    async fn a_watch_is_wanted_while_its_namespace_is_there() {
        let api = KubeApi::start().await;
        let (_site, mut state, deaf) = state_over(&api).await;
        state
            .seen(&deaf, &NAMESPACE_WATCH, applied("polar"))
            .await
            .unwrap();
        let pods = Watched {
            kind: Kind::Pod,
            namespace: Some("polar".to_string()),
        };
        assert!(state.wants(&pods));
        assert!(state.wants(&NAMESPACE_WATCH));
        state.ended(&deaf, pods.clone(), &Failure::Transient("lost".to_string()));
        assert!(!state.streams.contains_key(&pods), "it has ended");
        let going = Seen::Deleted(namespace_event(RESOURCE_DELETED_ACTION, "polar"));
        state.seen(&deaf, &NAMESPACE_WATCH, going).await.unwrap();
        assert!(!state.wants(&pods));
        assert!(
            state.wants(&NAMESPACE_WATCH),
            "across the cluster is always wanted"
        );
    }

    /// docs/architecture/cassini-backpressure.md: a broker that falls behind slows the watch. Nothing more is taken while one publish
    /// waits, and it all goes once there is room.
    #[tokio::test]
    async fn waiting_to_publish_slows_the_watches_and_loses_nothing() {
        let api = KubeApi::start().await;
        let names: Vec<Value> = (0..20).map(|i| named(&format!("pod-{i}"))).collect();
        api.holds(NAMESPACES, vec![named("polar")]);
        empty_namespace(&api, "polar");
        api.holds(POLAR_PODS, names);
        let (_site, kept, _actor) = watching(&api).await;
        let shut = kept.gate.write().await;
        kept.until("the first", |kept| !kept.events.lock().unwrap().is_empty())
            .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(kept.events.lock().unwrap().len(), 1, "one at a time");
        drop(shut);
        kept.until("all of it", |kept| kept.names("Pod").len() == 20)
            .await;
    }

    #[tokio::test]
    async fn stopping_it_ends_every_watch() {
        let api = KubeApi::start().await;
        api.holds(NAMESPACES, vec![]);
        for _ in 0..200 {
            api.then_fails(NAMESPACES, 500);
        }
        let (_site, _kept, actor) = watching(&api).await;
        actor
            .stop_and_wait(None, Some(Duration::from_secs(5)))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let asked = api.asked_of(NAMESPACES).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(api.asked_of(NAMESPACES).await, asked);
    }

    /// The watcher follows its waits, and a new one is what the next ended watch goes by.
    #[tokio::test]
    async fn the_waits_are_followed_and_the_next_ended_watch_goes_by_them() {
        let api = KubeApi::start().await;
        let (_site, mut state, deaf) = state_over(&api).await;
        let env: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let configuration = ConfigurationHandle::spawn(
            None,
            crate::TCP_CLIENT_NAME,
            polar_env::Config::builder(&env)
                .register(&crate::settings::SECTION)
                .build(),
            None,
            deaf.get_cell(),
        )
        .await
        .unwrap();
        assert_eq!(
            follow_waits(&configuration, &deaf).await.unwrap(),
            Waits {
                lost: Duration::from_secs(5),
                refused: Duration::from_secs(300)
            }
        );
        assert_eq!(
            configuration
                .dynamic_settings_problems(&[&crate::settings::SECTION])
                .await
                .unwrap(),
            Vec::<String>::new()
        );

        let new = Waits {
            lost: Duration::from_secs(7),
            refused: Duration::from_secs(70),
        };
        ClusterWatcher
            .handle(deaf, WatcherMsg::WaitsChanged(new), &mut state)
            .await
            .unwrap();
        assert_eq!(state.waits, new);
    }
}
