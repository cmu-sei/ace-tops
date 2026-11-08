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

//! The Kubernetes API: a watch of one kind of object, one change at a time, and the calls an agent that runs work makes
//! (create, get, delete and list an object, read a pod's log), each a request of this protocol, declared with what it may do,
//! judged and recorded (docs/architecture/protocol-handlers.md, "The protocols"; build-orchestrator.md, 5a). `kube`'s own watcher stays. There is one protocol for every kind, so what it hands on is the object as
//! JSON, and the type it is read as is the operation's. It goes with the pod's service account token, which `kube` reads and
//! renews from its file: no section holds it, the capability declares it, and the file stays readable in the pod, which no
//! handler changes, since Kubernetes is the trust base.
//!
//! A watch that fails is over, and the domain says when to ask again: what the stream said may be stale, so a resumed one
//! is not assumed to have missed nothing. What `kube` starts again by itself it starts again from where it was told to,
//! as an API server closes a watch every few minutes as a matter of course.

use super::{
    Access, CredentialSource, Exchange, Failure, Pending, Protocol, ProtocolKind, ReadFailure,
    Started, Target, Verb, http,
};
use async_trait::async_trait;
use futures::{AsyncReadExt, StreamExt};
use k8s_openapi::api::core::v1::Pod;
use kube::api::{
    Api, ApiResource, DeleteParams, DynamicObject, GroupVersionKind, ListParams, LogParams,
    PostParams, Preconditions, PropagationPolicy,
};
use kube::runtime::watcher::{self, Event, watcher};
use kube::{Client, Config};
use polar_crypto::CryptoError;
use reqwest::Url;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

/// How long an operation's `read` has with one object.
const READ_BUDGET: Duration = Duration::from_secs(30);
/// How long a call (not a watch or a log) has for the API to answer.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
/// The most of a log handed on at once.
const MAX_LOG_PIECE: usize = 64 * 1024;
/// The most of one log read: past it the read ends as a failure, since a log nothing bounds could fill what holds it. As
/// `http`'s body, to review.
const MAX_LOG: usize = 256 * 1024 * 1024;

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

/// How a delete reaches what the object owns, as the API names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Propagation {
    Foreground,
    Background,
    Orphan,
}

/// A request of the Kubernetes API: a watch, or one call. Its object, when it has one, is JSON, as a watch's are.
#[derive(Debug, Clone, PartialEq)]
pub enum Call {
    Watch(Watch),
    /// Make `object`, of `resource`, in `namespace`.
    Create {
        resource: Resource,
        namespace: String,
        object: Value,
    },
    Get {
        resource: Resource,
        namespace: String,
        name: String,
    },
    /// Delete `name`, if its uid is still `uid` when one is given, so that what was made again under the name is not the
    /// one removed.
    Delete {
        resource: Resource,
        namespace: String,
        name: String,
        propagation: Propagation,
        uid: Option<String>,
    },
    /// What `namespace` holds of `resource`, by label and field selector.
    List {
        resource: Resource,
        namespace: String,
        labels: Option<String>,
        fields: Option<String>,
    },
    /// A pod's log, a piece at a time, to its end or, with `follow`, to the container's.
    Log {
        namespace: String,
        pod: String,
        container: Option<String>,
        follow: bool,
    },
}

impl From<Watch> for Call {
    fn from(watch: Watch) -> Self {
        Call::Watch(watch)
    }
}

/// What reading a pod's log is, as RBAC names it.
pub const POD_LOG: Access = Access::new(Verb::Get, "", "pods/log");

impl Call {
    /// Make `object`, a type the API defines, in `namespace`.
    pub fn create<K: k8s_openapi::Resource + serde::Serialize>(
        namespace: impl Into<String>,
        object: &K,
    ) -> Result<Self, String> {
        Ok(Call::Create {
            resource: Resource::of::<K>(),
            namespace: namespace.into(),
            object: serde_json::to_value(object)
                .map_err(|e| format!("the object does not write as JSON: {e}"))?,
        })
    }

    /// What it does, as an operation declares it and RBAC names it.
    pub fn access(&self) -> Access {
        match self {
            Call::Watch(watch) => watch.access(),
            Call::Create { resource, .. } => resource.access(Verb::Create),
            Call::Get { resource, .. } => resource.access(Verb::Get),
            Call::Delete { resource, .. } => resource.access(Verb::Delete),
            Call::List { resource, .. } => resource.access(Verb::List),
            Call::Log { .. } => POD_LOG,
        }
    }
}

/// The API's own answer to a call it did not do, for the operation's `read` to judge, as `http` hands it a status: what
/// was asked for is not there (404), is there already or was changed (409), or is not a valid object (422).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiAnswer {
    pub code: u16,
    pub reason: String,
    pub message: String,
}

/// What the API said.
#[derive(Debug, Clone, PartialEq)]
pub enum Answer {
    /// A watch's.
    Change(Change),
    /// What was got or made (with its uid), or a deleted object still being finalised.
    Object(Value),
    /// A list's, each with its `apiVersion` and `kind`.
    Objects(Vec<Value>),
    /// A delete the API says is done.
    Gone,
    Said(ApiAnswer),
    /// A piece of a log, at most `MAX_LOG_PIECE` bytes.
    Log(Vec<u8>),
    /// The log's end.
    LogEnded,
}

impl Answer {
    /// A watch's change, which is all a watch is answered.
    pub fn change(&self) -> Result<&Change, ReadFailure> {
        match self {
            Answer::Change(change) => Ok(change),
            other => Err(ReadFailure::Malformed(format!(
                "a watch was answered {other:?}"
            ))),
        }
    }
}

/// What a call's error means: the API's own answer to it, for the domain; a refusal, which is the configuration's; or a
/// failure that may pass.
fn answer_of(error: kube::Error, what: &str) -> Result<Answer, Failure> {
    match error {
        kube::Error::Api(status) if matches!(status.code, 404 | 409 | 422) => {
            Ok(Answer::Said(ApiAnswer {
                code: status.code,
                reason: status.reason.clone(),
                message: status.message.clone(),
            }))
        }
        kube::Error::Api(status) if status.code == 403 => Err(Failure::Configuration(format!(
            "the service account may not {what}: {}",
            status.message
        ))),
        other => Err(Failure::Transient(format!("{what} lost the API: {other}"))),
    }
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
    type Request = Call;
    /// No credential of the CryptoActor's goes this way.
    type Credential = std::convert::Infallible;
    type Reply = Answer;

    fn own_location(&self) -> Option<String> {
        Some(self.address.clone())
    }

    fn configured_host(base: &str) -> Result<String, String> {
        Self::target(&Call::Watch(Watch::cluster_wide(NOTHING)), Some(base))
            .map(|target| target.host)
    }

    fn target(request: &Call, base: Option<&str>) -> Result<Target, String> {
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
        request: Call,
        _: Option<String>,
        _: Option<Self::Credential>,
        exchange: &mut Exchange<Self>,
    ) -> Result<(), Failure> {
        match request {
            Call::Watch(watch) => self.watch(watch, exchange).await,
            Call::Log {
                namespace,
                pod,
                container,
                follow,
            } => {
                self.log(&namespace, &pod, container, follow, exchange)
                    .await
            }
            call => {
                let answer = tokio::time::timeout(REQUEST_TIMEOUT, self.call(call))
                    .await
                    .map_err(|_| Failure::Transient("the API did not answer in time".into()))??;
                exchange.reply(answer).await;
                Ok(())
            }
        }
    }
}

impl Kubernetes {
    async fn watch(&self, request: Watch, exchange: &mut Exchange<Self>) -> Result<(), Failure> {
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
            if !exchange.reply(Answer::Change(change)).await {
                return Ok(());
            }
        }
        Err(Failure::Transient(format!(
            "the watch of {} ended",
            request.resource.plural
        )))
    }

    /// One call that is not a watch or a log: its answer, or the API's own answer to it.
    async fn call(&self, call: Call) -> Result<Answer, Failure> {
        let api = |resource: &Resource, namespace: &str| -> (Api<DynamicObject>, ApiResource) {
            let resource = resource.api_resource();
            (
                Api::namespaced_with(self.client.clone(), namespace, &resource),
                resource,
            )
        };
        match call {
            Call::Create {
                resource,
                namespace,
                object,
            } => {
                let (api, of) = api(&resource, &namespace);
                let object: DynamicObject = serde_json::from_value(object)
                    .map_err(|e| Failure::Read(format!("the object to make is not one: {e}")))?;
                match api.create(&PostParams::default(), &object).await {
                    Ok(made) => Ok(Answer::Object(object_of(made, &of)?)),
                    Err(e) => answer_of(e, &format!("create {}", resource.plural)),
                }
            }
            Call::Get {
                resource,
                namespace,
                name,
            } => {
                let (api, of) = api(&resource, &namespace);
                match api.get(&name).await {
                    Ok(got) => Ok(Answer::Object(object_of(got, &of)?)),
                    Err(e) => answer_of(e, &format!("get {}", resource.plural)),
                }
            }
            Call::Delete {
                resource,
                namespace,
                name,
                propagation,
                uid,
            } => {
                let (api, of) = api(&resource, &namespace);
                let params = DeleteParams {
                    propagation_policy: Some(match propagation {
                        Propagation::Foreground => PropagationPolicy::Foreground,
                        Propagation::Background => PropagationPolicy::Background,
                        Propagation::Orphan => PropagationPolicy::Orphan,
                    }),
                    preconditions: uid.map(|uid| Preconditions {
                        uid: Some(uid),
                        resource_version: None,
                    }),
                    ..DeleteParams::default()
                };
                match api.delete(&name, &params).await {
                    // The object, still being finalised; or the API's status, that it is gone.
                    Ok(deleted) => match deleted.left() {
                        Some(finalising) => Ok(Answer::Object(object_of(finalising, &of)?)),
                        None => Ok(Answer::Gone),
                    },
                    Err(e) => answer_of(e, &format!("delete {}", resource.plural)),
                }
            }
            Call::List {
                resource,
                namespace,
                labels,
                fields,
            } => {
                let (api, of) = api(&resource, &namespace);
                let mut params = ListParams::default();
                if let Some(labels) = &labels {
                    params = params.labels(labels);
                }
                if let Some(fields) = &fields {
                    params = params.fields(fields);
                }
                match api.list(&params).await {
                    Ok(list) => Ok(Answer::Objects(
                        list.items
                            .into_iter()
                            .map(|item| object_of(item, &of))
                            .collect::<Result<_, _>>()?,
                    )),
                    Err(e) => answer_of(e, &format!("list {}", resource.plural)),
                }
            }
            Call::Watch(_) | Call::Log { .. } => unreachable!("a watch and a log are streams"),
        }
    }

    /// A pod's log, a piece at a time, paced by the domain as a watch is, to its end or past its bound.
    async fn log(
        &self,
        namespace: &str,
        pod: &str,
        container: Option<String>,
        follow: bool,
        exchange: &mut Exchange<Self>,
    ) -> Result<(), Failure> {
        let api: Api<Pod> = Api::namespaced(self.client.clone(), namespace);
        let params = LogParams {
            follow,
            container,
            ..LogParams::default()
        };
        let mut reader = match api.log_stream(pod, &params).await {
            Ok(reader) => reader,
            Err(e) => {
                let said = answer_of(e, "read a pod's log")?;
                exchange.reply(said).await;
                return Ok(());
            }
        };
        let mut piece = vec![0u8; MAX_LOG_PIECE];
        let mut read = 0usize;
        loop {
            let n = reader
                .read(&mut piece)
                .await
                .map_err(|e| Failure::Transient(format!("the log was lost: {e}")))?;
            if n == 0 {
                exchange.reply(Answer::LogEnded).await;
                return Ok(());
            }
            read += n;
            if read > MAX_LOG {
                return Err(Failure::Transient(format!(
                    "the log passed its bound of {MAX_LOG} bytes"
                )));
            }
            if !exchange.reply(Answer::Log(piece[..n].to_vec())).await {
                return Ok(());
            }
        }
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
        fn request(&self) -> Call {
            self.0.clone().into()
        }
        fn read(&self, reply: &Answer) -> Result<Change, ReadFailure> {
            reply.change().cloned()
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
            &Watch::in_namespace(CUSTOM, "flux").into(),
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
            fn request(&self) -> Call {
                self.0.clone().into()
            }
            fn read(&self, reply: &Answer) -> Result<Change, ReadFailure> {
                match reply.change()? {
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
        let target =
            Kubernetes::target(&Watch::cluster_wide(POD).into(), Some("http://site")).unwrap();
        assert!(!target.encrypted);
        assert!(Kubernetes::target(&Watch::cluster_wide(POD).into(), None).is_err());
    }

    // -- the calls ----------------------------------------------------------------------------------------------------

    const JOB: Resource = Resource::of::<k8s_openapi::api::batch::v1::Job>();
    const EVENT: Resource = Resource::of::<k8s_openapi::api::core::v1::Event>();

    /// One call, answered as the API answered it.
    struct Calling(Call);

    const CALLING: OperationDecl = OperationDecl {
        name: "a.call",
        doc: "",
        protocol: ProtocolKind::KUBERNETES,
        location: Location::Cluster {
            access: &[
                JOB.access(Verb::Create),
                JOB.access(Verb::Get),
                JOB.access(Verb::Delete),
                JOB.access(Verb::List),
                EVENT.access(Verb::List),
                POD.access(Verb::List),
                POD_LOG,
            ],
        },
    };
    const CALLS: [OperationDecl; 1] = [CALLING];

    impl Operation for Calling {
        type Protocol = Kubernetes;
        type Output = Answer;
        const DECL: OperationDecl = CALLING;
        fn request(&self) -> Call {
            self.0.clone()
        }
        fn read(&self, reply: &Answer) -> Result<Answer, ReadFailure> {
            Ok(reply.clone())
        }
    }

    const JOBS: &str = "/apis/batch/v1/namespaces/builds/jobs";

    fn job(name: &str, uid: &str) -> Value {
        json!({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name, "namespace": "builds", "uid": uid}})
    }

    fn status(code: u16, reason: &str) -> Value {
        json!({"kind": "Status", "apiVersion": "v1", "metadata": {}, "status": "Failure",
               "message": format!("the stand-in says {reason}"), "reason": reason, "code": code})
    }

    fn body_of(received: &[(String, String, String, Vec<u8>)], method: &str) -> Value {
        let (_, _, _, body) = received
            .iter()
            .find(|(m, ..)| m == method)
            .unwrap_or_else(|| panic!("no {method}: {received:?}"));
        serde_json::from_slice(body).unwrap()
    }

    #[tokio::test]
    async fn a_job_is_made_in_its_namespace_and_what_was_made_comes_back() {
        let api = KubeApi::start().await;
        api.answers("POST", JOBS, 201, job("build-1", "u-1"));
        let site = kubernetes_handle(&CALLS, &api).await;
        let made = site
            .handle
            .ask(Calling(Call::Create {
                resource: JOB,
                namespace: "builds".into(),
                object: job("build-1", ""),
            }))
            .await
            .unwrap();
        let Answer::Object(made) = made else {
            panic!("{made:?}")
        };
        assert_eq!(made["metadata"]["uid"], "u-1");
        assert_eq!(made["kind"], "Job");
        let received = api.received().await;
        assert_eq!(body_of(&received, "POST")["metadata"]["name"], "build-1");
        assert!(
            received.iter().all(|(_, path, ..)| path == JOBS),
            "{received:?}"
        );
    }

    /// What the API refuses to do, it says why, and that is the operation's to judge, as a status is to an HTTP one's:
    /// a Job that is there already, one that is not, one that is not valid.
    #[tokio::test]
    async fn the_apis_own_answer_to_a_call_it_did_not_do_is_for_read_to_judge() {
        for (method, code, reason) in [("POST", 409, "AlreadyExists"), ("POST", 422, "Invalid")] {
            let api = KubeApi::start().await;
            api.answers(method, JOBS, code, status(code, reason));
            let site = kubernetes_handle(&CALLS, &api).await;
            let said = site
                .handle
                .ask(Calling(Call::Create {
                    resource: JOB,
                    namespace: "builds".into(),
                    object: job("build-1", ""),
                }))
                .await
                .unwrap();
            assert!(
                matches!(&said, Answer::Said(ApiAnswer { code: c, reason: r, .. }) if *c == code && r == reason),
                "{said:?}"
            );
        }
        let api = KubeApi::start().await;
        api.answers(
            "GET",
            &format!("{JOBS}/build-9"),
            404,
            status(404, "NotFound"),
        );
        let site = kubernetes_handle(&CALLS, &api).await;
        let said = site
            .handle
            .ask(Calling(Call::Get {
                resource: JOB,
                namespace: "builds".into(),
                name: "build-9".into(),
            }))
            .await
            .unwrap();
        assert!(
            matches!(said, Answer::Said(ApiAnswer { code: 404, .. })),
            "{said:?}"
        );
    }

    /// A delete says how what the Job owns goes, and that it is of this Job and not one made again under its name.
    #[tokio::test]
    async fn a_delete_sends_its_propagation_and_its_uid_and_says_when_it_is_done() {
        let api = KubeApi::start().await;
        let path = format!("{JOBS}/build-1");
        api.answers(
            "DELETE",
            &path,
            200,
            json!({"kind": "Status", "apiVersion": "v1", "metadata": {}, "status": "Success"}),
        );
        api.answers("DELETE", &path, 200, job("build-1", "u-1"));
        let site = kubernetes_handle(&CALLS, &api).await;
        let delete = || {
            Calling(Call::Delete {
                resource: JOB,
                namespace: "builds".into(),
                name: "build-1".into(),
                propagation: Propagation::Background,
                uid: Some("u-1".into()),
            })
        };
        assert_eq!(site.handle.ask(delete()).await.unwrap(), Answer::Gone);
        let finalising = site.handle.ask(delete()).await.unwrap();
        assert!(
            matches!(&finalising, Answer::Object(o) if o["metadata"]["uid"] == "u-1"),
            "{finalising:?}"
        );
        let sent = body_of(&api.received().await, "DELETE");
        assert_eq!(sent["propagationPolicy"], "Background");
        assert_eq!(sent["preconditions"]["uid"], "u-1");
    }

    #[tokio::test]
    async fn a_list_is_by_its_selectors_and_each_item_says_its_kind() {
        let api = KubeApi::start().await;
        api.answers(
            "GET",
            JOBS,
            200,
            json!({"apiVersion": "batch/v1", "kind": "JobList", "metadata": {"resourceVersion": "1"},
                   "items": [{"metadata": {"name": "build-1", "uid": "u-1"}}]}),
        );
        api.answers(
            "GET",
            "/api/v1/namespaces/builds/events",
            200,
            json!({"apiVersion": "v1", "kind": "EventList", "metadata": {}, "items": []}),
        );
        let site = kubernetes_handle(&CALLS, &api).await;
        let listed = site
            .handle
            .ask(Calling(Call::List {
                resource: JOB,
                namespace: "builds".into(),
                labels: Some("app.kubernetes.io/managed-by=build-orchestrator".into()),
                fields: None,
            }))
            .await
            .unwrap();
        let Answer::Objects(items) = listed else {
            panic!("{listed:?}")
        };
        assert_eq!(items.len(), 1);
        assert_eq!(
            (items[0]["apiVersion"].as_str(), items[0]["kind"].as_str()),
            (Some("batch/v1"), Some("Job"))
        );
        let events = site
            .handle
            .ask(Calling(Call::List {
                resource: EVENT,
                namespace: "builds".into(),
                labels: None,
                fields: Some("involvedObject.name=build-1".into()),
            }))
            .await
            .unwrap();
        assert_eq!(events, Answer::Objects(vec![]));
        let queries: Vec<String> = api
            .received()
            .await
            .into_iter()
            .map(|(_, _, q, _)| q)
            .collect();
        assert!(
            queries[0]
                .contains("labelSelector=app.kubernetes.io%2Fmanaged-by%3Dbuild-orchestrator"),
            "{queries:?}"
        );
        assert!(
            queries[1].contains("fieldSelector=involvedObject.name%3Dbuild-1"),
            "{queries:?}"
        );
    }

    /// A log comes a piece at a time, as the domain takes each, and says once that it has ended.
    #[tokio::test]
    async fn a_log_comes_piece_by_piece_and_ends_once() {
        struct Reading;
        #[async_trait]
        impl Actor for Reading {
            type Msg = Delivery<Answer>;
            type State = Arc<Mutex<Vec<Result<Answer, Failure>>>>;
            type Arguments = Self::State;
            async fn pre_start(
                &self,
                _: ActorRef<Self::Msg>,
                said: Self::State,
            ) -> Result<Self::State, ActorProcessingErr> {
                Ok(said)
            }
            async fn handle(
                &self,
                _: ActorRef<Self::Msg>,
                delivery: Self::Msg,
                said: &mut Self::State,
            ) -> Result<(), ActorProcessingErr> {
                said.lock().unwrap().push(delivery.result.clone());
                Ok(())
            }
        }
        let api = KubeApi::start().await;
        let log: Vec<u8> = (0..200_000u32).map(|i| b'a' + (i % 26) as u8).collect();
        api.logs(
            "/api/v1/namespaces/builds/pods/build-1-abc/log",
            log.clone(),
        );
        let site = kubernetes_handle(&CALLS, &api).await;
        let said = Arc::new(Mutex::new(Vec::new()));
        let (domain, _) = Actor::spawn(None, Reading, said.clone()).await.unwrap();
        let _stream = site
            .handle
            .stream(
                Calling(Call::Log {
                    namespace: "builds".into(),
                    pod: "build-1-abc".into(),
                    container: Some("pipeline".into()),
                    follow: true,
                }),
                domain,
                |delivery| delivery,
            )
            .unwrap();
        for _ in 0..1000 {
            if said
                .lock()
                .unwrap()
                .iter()
                .any(|a| matches!(a, Ok(Answer::LogEnded)))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let said = said.lock().unwrap().clone();
        let mut read = Vec::new();
        let mut ends = 0;
        for answer in &said {
            match answer {
                Ok(Answer::Log(piece)) => {
                    assert!(piece.len() <= MAX_LOG_PIECE);
                    read.extend_from_slice(piece);
                }
                Ok(Answer::LogEnded) => ends += 1,
                other => panic!("{other:?}"),
            }
        }
        assert_eq!((read.len(), ends), (log.len(), 1));
        assert_eq!(read, log);
        let query = &api.received().await[0].2;
        assert!(
            query.contains("follow=true") && query.contains("container=pipeline"),
            "{query}"
        );
    }

    #[tokio::test]
    async fn a_call_the_api_refuses_the_account_is_configuration() {
        let api = KubeApi::start().await;
        api.answers("POST", JOBS, 403, status(403, "Forbidden"));
        let site = kubernetes_handle(&CALLS, &api).await;
        let refused = site
            .handle
            .ask(Calling(Call::Create {
                resource: JOB,
                namespace: "builds".into(),
                object: job("build-1", ""),
            }))
            .await;
        assert!(
            matches!(refused, Err(Failure::Configuration(_))),
            "{refused:?}"
        );
    }

    /// A call its operation does not declare is refused before anything is sent: a list of Jobs cannot delete one.
    #[tokio::test]
    async fn a_call_its_operation_does_not_declare_is_refused_and_nothing_is_sent() {
        struct Listing(Call);
        const LISTING: OperationDecl = OperationDecl {
            name: "a.list",
            doc: "",
            protocol: ProtocolKind::KUBERNETES,
            location: Location::Cluster {
                access: &[JOB.access(Verb::List)],
            },
        };
        static LISTS: [OperationDecl; 1] = [LISTING];
        impl Operation for Listing {
            type Protocol = Kubernetes;
            type Output = Answer;
            const DECL: OperationDecl = LISTING;
            fn request(&self) -> Call {
                self.0.clone()
            }
            fn read(&self, reply: &Answer) -> Result<Answer, ReadFailure> {
                Ok(reply.clone())
            }
        }
        let api = KubeApi::start().await;
        let site = kubernetes_handle(&LISTS, &api).await;
        let refused = site
            .handle
            .ask(Listing(Call::Delete {
                resource: JOB,
                namespace: "builds".into(),
                name: "build-1".into(),
                propagation: Propagation::Background,
                uid: None,
            }))
            .await;
        assert_eq!(refused, Err(Failure::Denied(Denial::AccessUndeclared)));
        assert!(api.received().await.is_empty());
    }

    /// The record of a call says which operation it was and where it went, as every other request's, and nothing of the
    /// namespace, the object or its spec.
    #[tokio::test]
    async fn a_calls_record_holds_no_namespace_name_or_spec() {
        let api = KubeApi::start().await;
        api.answers("POST", JOBS, 201, job("build-secretive", "u-1"));
        let site = kubernetes_handle(&CALLS, &api).await;
        site.handle
            .ask(Calling(Call::Create {
                resource: JOB,
                namespace: "builds".into(),
                object: job("build-secretive", ""),
            }))
            .await
            .unwrap();
        let records = format!("{:?}", site.records.lock().unwrap());
        assert!(
            records.contains("a.call") && records.contains(SERVICE_ACCOUNT),
            "{records}"
        );
        for word in ["builds", "build-secretive", "batch", "jobs"] {
            assert!(!records.contains(word), "{word} in {records}");
        }
    }
}
