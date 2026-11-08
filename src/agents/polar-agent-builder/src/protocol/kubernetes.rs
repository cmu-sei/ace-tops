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

//! The Kubernetes API, as a stream: a watch of one kind of object, and one change at a time (docs/architecture/protocol-handlers.md,
//! "The protocols"). `kube`'s own watcher stays. There is one protocol for every kind, so what it hands on is the object as
//! JSON, and the type it is read as is the operation's. It goes with the pod's service account token, which `kube` reads and
//! renews from its file: no section holds it, the capability declares it, and the file stays readable in the pod, which no
//! handler changes, since Kubernetes is the trust base.
//!
//! A watch that fails is over, and the domain says when to ask again: what the stream said may be stale, so a resumed one
//! is not assumed to have missed nothing. What `kube` starts again by itself it starts again from where it was told to,
//! as an API server closes a watch every few minutes as a matter of course.

use super::{
    Access, CredentialSource, Exchange, Failure, Pending, Protocol, ProtocolKind, Started, Target,
    Verb, http,
};
use async_trait::async_trait;
use futures::StreamExt;
use kube::api::{Api, ApiResource, DynamicObject, GroupVersionKind};
use kube::runtime::watcher::{self, Event, watcher};
use kube::{Client, Config};
use polar_crypto::CryptoError;
use reqwest::Url;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

/// How long an operation's `read` has with one object.
const READ_BUDGET: Duration = Duration::from_secs(30);

/// What kind of object a watch is of, as the API names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resource {
    /// Empty for the core group.
    pub group: &'static str,
    pub version: &'static str,
    pub kind: &'static str,
    /// The kind's name in a path.
    pub plural: &'static str,
}

impl Resource {
    /// The resource of a type the API itself defines.
    pub const fn of<K: k8s_openapi::Resource>() -> Self {
        Self {
            group: K::GROUP,
            version: K::VERSION,
            kind: K::KIND,
            plural: K::URL_PATH_SEGMENT,
        }
    }

    fn api_resource(&self) -> ApiResource {
        ApiResource::from_gvk_with_plural(
            &GroupVersionKind::gvk(self.group, self.version, self.kind),
            self.plural,
        )
    }
}

/// A watch of one kind, in one namespace or across the cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Watch {
    resource: Resource,
    namespace: Option<String>,
}

impl Resource {
    /// What `verb` on it is, as an operation declares it and RBAC names it.
    pub const fn access(&self, verb: Verb) -> Access {
        Access::new(verb, self.group, self.plural)
    }
}

impl Watch {
    /// What it does: watch its kind.
    pub fn access(&self) -> Access {
        self.resource.access(Verb::Watch)
    }

    pub fn cluster_wide(resource: Resource) -> Self {
        Self {
            resource,
            namespace: None,
        }
    }

    pub fn in_namespace(resource: Resource, namespace: impl Into<String>) -> Self {
        Self {
            resource,
            namespace: Some(namespace.into()),
        }
    }
}

/// One thing a watch says. An object is as the API has it, with its `apiVersion` and `kind`.
#[derive(Debug, Clone, PartialEq)]
pub enum Change {
    /// It is listing: what it said before does not stand until it has finished.
    Listing,
    /// It has finished listing. An object it said before and has not said since has gone.
    Listed,
    Applied(Value),
    Deleted(Value),
}

/// The Kubernetes protocol, with its client: one, shared, for the agent.
pub struct Kubernetes {
    client: Client,
    /// The API's address, which is recorded and judged.
    address: String,
}

impl Kubernetes {
    pub(crate) fn of(config: Config) -> Result<Self, String> {
        let address = config.cluster_url.to_string();
        let client = Client::try_from(config).map_err(|e| format!("no Kubernetes client: {e}"))?;
        Ok(Self { client, address })
    }
}

/// The client for the API of the pod's cluster, or, run by hand outside one, of what the environment says: one that cannot
/// be made stops the agent before it does anything.
pub(crate) fn start(_: &polar_env::Config) -> Pending<Result<Started, String>> {
    Box::pin(async {
        // `kube`'s TLS takes the process's provider, and more than one is linked in. Whoever is first installs it.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = match Config::incluster() {
            Ok(config) => config,
            Err(_) => Config::infer()
                .await
                .map_err(|e| format!("no Kubernetes API in this pod or environment: {e}"))?,
        };
        Ok(Arc::new(Kubernetes::of(config)?) as Started)
    })
}

/// An object as the API has it. An item of a list comes without its `apiVersion` and `kind`, which the list had.
fn object_of(object: DynamicObject, resource: &ApiResource) -> Result<Value, Failure> {
    let mut object = serde_json::to_value(object)
        .map_err(|e| Failure::Read(format!("an object did not read as JSON: {e}")))?;
    if let Value::Object(fields) = &mut object {
        fields
            .entry("apiVersion")
            .or_insert_with(|| Value::String(resource.api_version.clone()));
        fields
            .entry("kind")
            .or_insert_with(|| Value::String(resource.kind.clone()));
    }
    Ok(object)
}

/// What a watch's error means. The API refusing, or not serving the kind at all, is no passing thing; anything else may be.
fn failure_of(error: &watcher::Error, resource: &Resource) -> Failure {
    let code = match error {
        watcher::Error::InitialListFailed(kube::Error::Api(status))
        | watcher::Error::WatchStartFailed(kube::Error::Api(status))
        | watcher::Error::WatchFailed(kube::Error::Api(status))
        | watcher::Error::WatchError(status) => Some(status.code),
        _ => None,
    };
    let plural = resource.plural;
    match code {
        Some(403) => Failure::Configuration(format!(
            "the service account may not watch {plural}: {error}"
        )),
        Some(404) => Failure::Configuration(format!("the API does not serve {plural}: {error}")),
        _ => Failure::Transient(format!("the watch of {plural} lost the API: {error}")),
    }
}

impl super::sealed::Sealed for Kubernetes {}

#[async_trait]
impl Protocol for Kubernetes {
    const KIND: ProtocolKind = ProtocolKind::KUBERNETES;
    const BUDGET: Duration = READ_BUDGET;
    type Request = Watch;
    /// No credential of the CryptoActor's goes this way.
    type Credential = std::convert::Infallible;
    type Reply = Change;

    fn own_location(&self) -> Option<String> {
        Some(self.address.clone())
    }

    fn configured_host(base: &str) -> Result<String, String> {
        Self::target(&Watch::cluster_wide(NOTHING), Some(base)).map(|target| target.host)
    }

    fn target(request: &Watch, base: Option<&str>) -> Result<Target, String> {
        let base = base.ok_or("the Kubernetes protocol was not given the API's address")?;
        let url = Url::parse(base).map_err(|_| "the API's address cannot be read".to_string())?;
        Ok(Target {
            access: Some(request.access()),
            ..http::target_of(&url)?
        })
    }

    async fn credential(
        _: &dyn CredentialSource,
        name: String,
        _: String,
    ) -> Result<Self::Credential, CryptoError> {
        Err(CryptoError::SecretNotRegistered(name))
    }

    async fn perform(
        &self,
        request: Watch,
        _: Option<String>,
        _: Option<Self::Credential>,
        exchange: &mut Exchange<Self>,
    ) -> Result<(), Failure> {
        let resource = request.resource.api_resource();
        let api: Api<DynamicObject> = match &request.namespace {
            Some(namespace) => Api::namespaced_with(self.client.clone(), namespace, &resource),
            None => Api::all_with(self.client.clone(), &resource),
        };
        // Its default list says what exists now and not what a cache last heard, so what is not in it may be taken to be gone.
        let mut events = watcher(api, watcher::Config::default()).boxed();
        while let Some(event) = events.next().await {
            let change = match event {
                Ok(Event::Init) => Change::Listing,
                Ok(Event::InitDone) => Change::Listed,
                Ok(Event::InitApply(object) | Event::Apply(object)) => {
                    Change::Applied(object_of(object, &resource)?)
                }
                Ok(Event::Delete(object)) => Change::Deleted(object_of(object, &resource)?),
                Err(error) => return Err(failure_of(&error, &request.resource)),
            };
            if !exchange.reply(change).await {
                return Ok(());
            }
        }
        Err(Failure::Transient(format!(
            "the watch of {} ended",
            request.resource.plural
        )))
    }
}

/// What a host is read with, which has no resource.
const NOTHING: Resource = Resource {
    group: "",
    version: "",
    kind: "",
    plural: "",
};

#[cfg(test)]
mod tests {
    use super::super::testing::{KubeApi, Site, kubernetes_handle, kubernetes_handle_unencrypted};
    use super::super::{
        Delivery, Denial, Location, Operation, OperationDecl, ReadFailure, SERVICE_ACCOUNT,
    };
    use super::*;
    use k8s_openapi::api::core::v1::{Namespace, Pod};
    use ractor::{Actor, ActorProcessingErr, ActorRef};
    use serde_json::json;
    use std::sync::Mutex;

    const POD: Resource = Resource::of::<Pod>();
    const NAMESPACE: Resource = Resource::of::<Namespace>();
    const CUSTOM: Resource = Resource {
        group: "source.toolkit.fluxcd.io",
        version: "v1",
        kind: "OCIRepository",
        plural: "ocirepositories",
    };

    struct Watching(Watch);

    const WATCHING: OperationDecl = OperationDecl {
        name: "a.watch",
        doc: "",
        protocol: ProtocolKind::KUBERNETES,
        location: Location::Cluster {
            access: &[
                POD.access(Verb::Watch),
                NAMESPACE.access(Verb::Watch),
                CUSTOM.access(Verb::Watch),
            ],
        },
    };
    const DECLARED: [OperationDecl; 1] = [WATCHING];

    impl Operation for Watching {
        type Protocol = Kubernetes;
        type Output = Change;
        const DECL: OperationDecl = WATCHING;
        fn request(&self) -> Watch {
            self.0.clone()
        }
        fn read(&self, reply: &Change) -> Result<Change, ReadFailure> {
            Ok(reply.clone())
        }
    }

    struct Domain;

    type Said = Arc<Mutex<Vec<Result<Change, Failure>>>>;

    #[ractor::async_trait]
    impl Actor for Domain {
        type Msg = Delivery<Change>;
        type State = Said;
        type Arguments = Said;
        async fn pre_start(
            &self,
            _: ActorRef<Self::Msg>,
            said: Said,
        ) -> Result<Said, ActorProcessingErr> {
            Ok(said)
        }
        async fn handle(
            &self,
            _: ActorRef<Self::Msg>,
            message: Self::Msg,
            said: &mut Said,
        ) -> Result<(), ActorProcessingErr> {
            said.lock().unwrap().push(message.result.clone());
            Ok(())
        }
    }

    /// Watches, and returns once `count` things have been said.
    async fn said(site: &Site, watch: Watch, count: usize) -> Vec<Result<Change, Failure>> {
        let said = Said::default();
        let (domain, _) = Actor::spawn(None, Domain, said.clone()).await.unwrap();
        let _stream = site
            .handle
            .stream(Watching(watch), domain, |delivery| delivery)
            .unwrap();
        for _ in 0..1000 {
            if said.lock().unwrap().len() >= count {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let said = said.lock().unwrap().clone();
        assert!(said.len() >= count, "expected {count}: {said:?}");
        said
    }

    fn named(name: &str, version: &str) -> Value {
        json!({"metadata": {"name": name, "namespace": "polar", "resourceVersion": version}})
    }

    fn name_of(change: &Result<Change, Failure>) -> &str {
        match change {
            Ok(Change::Applied(object) | Change::Deleted(object)) => {
                object["metadata"]["name"].as_str().unwrap()
            }
            other => panic!("not an object: {other:?}"),
        }
    }

    /// The whole of a watch against a real TLS connection, as the Kubernetes API speaks: the list, in its pages' terms, and
    /// each change after it in order.
    #[tokio::test]
    async fn it_says_the_list_and_then_each_change_in_order() {
        let api = KubeApi::start().await;
        let pods = "/api/v1/namespaces/polar/pods";
        api.holds(pods, vec![named("one", "1"), named("two", "2")]);
        api.then_says(
            pods,
            vec![
                ("ADDED", "three", "3"),
                ("MODIFIED", "one", "4"),
                ("DELETED", "two", "5"),
            ],
        );
        let site = kubernetes_handle(&DECLARED, &api).await;
        let said = said(&site, Watch::in_namespace(POD, "polar"), 7).await;

        assert_eq!(said[0], Ok(Change::Listing));
        assert_eq!(name_of(&said[1]), "one");
        assert_eq!(name_of(&said[2]), "two");
        assert_eq!(said[3], Ok(Change::Listed));
        assert_eq!(name_of(&said[4]), "three");
        assert_eq!(name_of(&said[5]), "one");
        assert!(matches!(said[6], Ok(Change::Deleted(_))), "{said:?}");
        assert_eq!(name_of(&said[6]), "two");
    }

    /// An item of a list comes without the `apiVersion` and `kind` its list had, and what reads it may want them.
    #[tokio::test]
    async fn an_object_says_what_it_is_whether_it_came_by_a_list_or_not() {
        let api = KubeApi::start().await;
        let path = "/apis/source.toolkit.fluxcd.io/v1/ocirepositories";
        api.holds(path, vec![named("listed", "1")]);
        api.then_says(path, vec![("ADDED", "watched", "2")]);
        let site = kubernetes_handle(&DECLARED, &api).await;
        let said = said(&site, Watch::cluster_wide(CUSTOM), 4).await;
        let Ok(Change::Applied(listed)) = &said[1] else {
            panic!("{said:?}");
        };
        assert_eq!(listed["apiVersion"], "source.toolkit.fluxcd.io/v1");
        assert_eq!(listed["kind"], "OCIRepository");
        // What the API says of an object itself stands.
        let Ok(Change::Applied(watched)) = &said[3] else {
            panic!("{said:?}");
        };
        assert_eq!(watched["kind"], "Whatever");
    }

    #[tokio::test]
    async fn the_pods_token_goes_with_each_request_and_the_record_says_so_with_no_value() {
        let api = KubeApi::start().await;
        api.holds("/api/v1/namespaces", vec![named("polar", "1")]);
        let site = kubernetes_handle(&DECLARED, &api).await;
        said(&site, Watch::cluster_wide(NAMESPACE), 3).await;

        let presented = api.presented().await;
        assert!(!presented.is_empty());
        for each in presented {
            assert_eq!(each.as_deref(), Some(KubeApi::BEARER));
        }
        let records = site.records.lock().unwrap().clone();
        assert_eq!(records.len(), 1, "one line for the watch: {records:?}");
        let record = &records[0];
        assert_eq!(record.operation, "a.watch");
        assert_eq!(record.protocol, "kubernetes");
        assert_eq!(record.host, "localhost");
        assert_eq!(record.credential.as_deref(), Some(SERVICE_ACCOUNT));
        assert_eq!(record.verdict, "allowed");
        assert!(!record.arbitrary);
        assert!(!format!("{records:?}").contains(KubeApi::TOKEN));
    }

    /// "What is not in it may be taken to be gone" needs the API's answer and not its cache's, which a resource version of
    /// 0 would ask for.
    #[tokio::test]
    async fn a_list_asks_for_what_exists_now() {
        let api = KubeApi::start().await;
        api.holds("/api/v1/namespaces", vec![]);
        let site = kubernetes_handle(&DECLARED, &api).await;
        said(&site, Watch::cluster_wide(NAMESPACE), 2).await;
        let queries = api.queries().await;
        let list = queries
            .iter()
            .find(|query| !query.contains("watch=true"))
            .expect("a list");
        assert!(!list.contains("resourceVersion=0"), "{list}");
    }

    /// The token goes over nothing else, so nothing goes.
    #[tokio::test]
    async fn over_no_encryption_nothing_is_sent() {
        let api = KubeApi::start().await;
        let site = kubernetes_handle_unencrypted(&DECLARED, &api).await;
        let said = said(&site, Watch::cluster_wide(NAMESPACE), 1).await;
        assert_eq!(said[0], Err(Failure::Denied(Denial::NotEncrypted)));
        assert!(api.presented().await.is_empty());
    }

    /// A watch of a kind its operation does not declare is refused before anything is sent: a declaration binds what
    /// the operation may do.
    #[tokio::test]
    async fn a_watch_of_a_kind_not_declared_is_refused_and_nothing_is_sent() {
        const SECRET: Resource = Resource::of::<k8s_openapi::api::core::v1::Secret>();
        let api = KubeApi::start().await;
        let site = kubernetes_handle(&DECLARED, &api).await;
        let said = said(&site, Watch::cluster_wide(SECRET), 1).await;
        assert_eq!(said[0], Err(Failure::Denied(Denial::AccessUndeclared)));
        assert!(api.presented().await.is_empty());
    }

    #[test]
    fn a_watchs_target_says_what_it_does() {
        let target = Kubernetes::target(
            &Watch::in_namespace(CUSTOM, "flux"),
            Some("https://10.96.0.1/"),
        )
        .unwrap();
        assert_eq!(
            target.access,
            Some(Access::new(
                Verb::Watch,
                "source.toolkit.fluxcd.io",
                "ocirepositories"
            ))
        );
    }

    #[tokio::test]
    async fn the_api_refusing_or_not_serving_a_kind_is_configuration_and_ends_the_watch() {
        for status in [403, 404] {
            let api = KubeApi::start().await;
            api.refuses_the_list("/api/v1/namespaces", status);
            let site = kubernetes_handle(&DECLARED, &api).await;
            let said = said(&site, Watch::cluster_wide(NAMESPACE), 2).await;
            assert_eq!(said[0], Ok(Change::Listing));
            assert!(
                matches!(&said[1], Err(Failure::Configuration(_))),
                "{status}: {said:?}"
            );
            assert_eq!(said.len(), 2);
        }
    }

    /// One failure, as the last thing it says, and no asking again by itself: that is the domain's to decide.
    #[tokio::test]
    async fn a_lost_watch_says_so_once_and_asks_for_nothing_more() {
        let api = KubeApi::start().await;
        api.holds("/api/v1/namespaces", vec![]);
        api.then_fails("/api/v1/namespaces", 500);
        let site = kubernetes_handle(&DECLARED, &api).await;
        let said = said(&site, Watch::cluster_wide(NAMESPACE), 3).await;
        assert_eq!(said[1], Ok(Change::Listed));
        assert!(matches!(&said[2], Err(Failure::Transient(_))), "{said:?}");
        let requests = api.presented().await.len();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(api.presented().await.len(), requests);
    }

    /// A watch that cannot read a change goes no further, as what it held would have a gap, and asks for nothing more.
    #[tokio::test]
    async fn a_change_the_operation_cannot_read_ends_the_watch() {
        struct Fussy(Watch);
        const FUSSY: OperationDecl = OperationDecl {
            name: "a.fussy.watch",
            doc: "",
            protocol: ProtocolKind::KUBERNETES,
            location: Location::Cluster {
                access: &[NAMESPACE.access(Verb::Watch)],
            },
        };
        static FUSSY_DECLARED: [OperationDecl; 1] = [FUSSY];
        impl Operation for Fussy {
            type Protocol = Kubernetes;
            type Output = Change;
            const DECL: OperationDecl = FUSSY;
            fn request(&self) -> Watch {
                self.0.clone()
            }
            fn read(&self, reply: &Change) -> Result<Change, ReadFailure> {
                match reply {
                    Change::Applied(object) if object["metadata"]["name"] == "unreadable" => {
                        Err(ReadFailure::Malformed("no".to_string()))
                    }
                    other => Ok(other.clone()),
                }
            }
        }
        let api = KubeApi::start().await;
        api.holds(
            "/api/v1/namespaces",
            vec![named("unreadable", "1"), named("after", "2")],
        );
        let site = kubernetes_handle(&FUSSY_DECLARED, &api).await;
        let told = Said::default();
        let (domain, _) = Actor::spawn(None, Domain, told.clone()).await.unwrap();
        let _stream = site
            .handle
            .stream(Fussy(Watch::cluster_wide(NAMESPACE)), domain, |delivery| {
                delivery
            })
            .unwrap();
        for _ in 0..1000 {
            if told.lock().unwrap().len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let told = told.lock().unwrap();
        assert_eq!(told.len(), 2, "{told:?}");
        assert_eq!(told[0], Ok(Change::Listing));
        assert!(matches!(told[1], Err(Failure::Read(_))), "{told:?}");
    }

    /// What the server says inside the stream, as a resource version too old is, or a right that has been taken away.
    #[tokio::test]
    async fn an_error_in_the_stream_ends_it_and_means_what_it_would_have() {
        let api = KubeApi::start().await;
        api.holds("/api/v1/namespaces", vec![]);
        api.then_errs("/api/v1/namespaces", 410);
        let site = kubernetes_handle(&DECLARED, &api).await;
        let told = said(&site, Watch::cluster_wide(NAMESPACE), 3).await;
        assert!(matches!(&told[2], Err(Failure::Transient(_))), "{told:?}");

        api.then_errs("/api/v1/namespaces", 403);
        let told = said(&site, Watch::cluster_wide(NAMESPACE), 3).await;
        assert!(
            matches!(&told[2], Err(Failure::Configuration(_))),
            "{told:?}"
        );
    }

    #[test]
    fn a_kind_the_api_defines_is_named_as_the_api_names_it() {
        assert_eq!(POD.group, "");
        assert_eq!(POD.version, "v1");
        assert_eq!(POD.kind, "Pod");
        assert_eq!(POD.plural, "pods");
        assert_eq!(POD.api_resource().api_version, "v1");
        assert_eq!(
            CUSTOM.api_resource().api_version,
            "source.toolkit.fluxcd.io/v1"
        );
    }

    #[test]
    fn the_address_is_read_as_any_other_host() {
        let host = |base| Kubernetes::configured_host(base);
        assert_eq!(host("https://10.96.0.1:443/").unwrap(), "10.96.0.1");
        assert_eq!(
            host("https://KUBERNETES.default.svc/").unwrap(),
            "kubernetes.default.svc"
        );
        let target = Kubernetes::target(&Watch::cluster_wide(POD), Some("http://site")).unwrap();
        assert!(!target.encrypted);
        assert!(Kubernetes::target(&Watch::cluster_wide(POD), None).is_err());
    }
}
