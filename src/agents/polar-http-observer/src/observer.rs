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

//! The observer's supervisor: the builder's infrastructure, and what [`Observing`] decides, carried out. One source's
//! failure is said and tried again at its next time, and touches no other.

use crate::graphql;
use crate::observing::{Event, Observing, Step};
use crate::paging::{self, Page, Style};
use crate::sources::{self, SECTION_NAME, Source};
use crate::{MAX_DOCUMENT_BYTES, Observation};
use cassini_client::{OfflineBehavior, PublishRequest};
use cassini_types::{ClientEvent, WireTraceCtx};
use polar::cassini::{CassiniClient, TcpClient};
use polar_agent_builder::protocol::http::{Http, Reply, Request};
use polar_agent_builder::protocol::{
    Failure, Operation, OperationDecl, ProtocolHandle, ReadFailure,
};
use polar_agent_builder::{
    AgentBuilder, ConfigurationHandle, Configured, HealthClient, HealthHandle, InfrastructureEvent,
    InfrastructureSupervisorMessage, StartError,
};
use ractor::{Actor, ActorProcessingErr, ActorRef, SupervisionEvent, async_trait};
use std::marker::PhantomData;
use tracing::{debug, error, info, warn};

/// What it needs to drain: nothing of its own, since a read in flight is simply not published, and a margin.
pub const SHUTDOWN_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

/// What is particular to one kind of observer. Fixed when it is built: a signed section says what to read and nothing else.
pub trait Kind: Send + Sync + 'static {
    /// The workload it runs as.
    const NAME: &'static str;
    /// Where what it reads goes. The kind's processor subscribes to it, which is what pairs them.
    const TOPIC: &'static str;
    /// Its operation for a source that names no credential, declared `Location::Arbitrary`: a URL from a signed section,
    /// never with a credential.
    const OPERATION: OperationDecl;
    /// Its operation for a source that names one, declared `Location::Bound` with `Credential::Chosen`: the credential's
    /// signed binding must name the source's host. A kind without one refuses such a source.
    const CREDENTIALED: Option<OperationDecl> = None;
}

/// What a page is asked with: where, with which credential, how the source is paged, and, for a GraphQL source, its
/// query and the cursor this page comes after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageRequest {
    pub url: String,
    pub credential: Option<String>,
    pub paging: Option<Style>,
    pub query: Option<String>,
    pub after: Option<String>,
}

impl PageRequest {
    /// A page read by GET.
    pub fn new(url: String, credential: Option<String>, paging: Option<Style>) -> Self {
        Self {
            url,
            credential,
            paging,
            query: None,
            after: None,
        }
    }

    /// The page is `query`, POSTed, after the cursor `after`, none on the first page.
    pub fn graphql(mut self, query: impl Into<String>, after: Option<String>) -> Self {
        self.query = Some(query.into());
        self.after = after;
        self
    }

    fn request(&self) -> Request {
        match &self.query {
            None => Request::get_at(self.url.clone()),
            Some(query) => Request::post_at(
                self.url.clone(),
                graphql::request_body(query, self.after.as_deref()),
            )
            .header("content-type", "application/json"),
        }
    }

    fn read(&self, reply: &Reply) -> Result<Page, ReadFailure> {
        read_page(self, reply)
    }
}

/// A page of a source, with no credential.
struct Fetch<K> {
    asked: PageRequest,
    kind: PhantomData<fn() -> K>,
}

impl<K: Kind> Operation for Fetch<K> {
    type Protocol = Http;
    type Output = Page;
    const DECL: OperationDecl = K::OPERATION;

    fn request(&self) -> Request {
        self.asked.request()
    }

    fn read(&self, reply: &Reply) -> Result<Page, ReadFailure> {
        self.asked.read(reply)
    }
}

/// A page of a source, with the credential the source names.
struct FetchWith<K> {
    asked: PageRequest,
    credential: String,
    kind: PhantomData<fn() -> K>,
}

impl<K: Kind> Operation for FetchWith<K> {
    type Protocol = Http;
    type Output = Page;
    // Never asked for a kind without one ([`read`] refuses first); and were it, the arbitrary operation carries none.
    const DECL: OperationDecl = match K::CREDENTIALED {
        Some(declared) => declared,
        None => K::OPERATION,
    };

    fn request(&self) -> Request {
        self.asked.request()
    }

    fn credential(&self) -> Option<String> {
        Some(self.credential.clone())
    }

    fn read(&self, reply: &Reply) -> Result<Page, ReadFailure> {
        self.asked.read(reply)
    }
}

/// A page of a source, read through the protocol handler as one of this kind's operations, with the credential the
/// source names or none, and where its next page is when it is paged: what the observer publishes, and what a kind's
/// tests read through the same handler (`polar-http-testkit`).
pub async fn read<K: Kind>(
    protocols: &ProtocolHandle,
    asked: PageRequest,
) -> Result<Page, Failure> {
    match (asked.credential.clone(), K::CREDENTIALED) {
        (None, _) => {
            protocols
                .ask(Fetch::<K> {
                    asked,
                    kind: PhantomData,
                })
                .await
        }
        (Some(credential), Some(_)) => {
            protocols
                .ask(FetchWith::<K> {
                    asked,
                    credential,
                    kind: PhantomData,
                })
                .await
        }
        (Some(credential), None) => Err(Failure::Configuration(format!(
            "the source names the credential `{credential}`, and {} reads every source with none",
            K::NAME
        ))),
    }
}

/// A page, and where the next is when the source is paged: a next page that cannot be found, or is on another host, is a
/// failure of the read, so a paging that cannot work is said rather than taken for the last page.
fn read_page(asked: &PageRequest, reply: &Reply) -> Result<Page, ReadFailure> {
    let body = read_document(reply.status.as_u16(), &reply.body)?;
    if asked.query.is_some() && graphql::failed(&body) {
        return Err(ReadFailure::Malformed(
            "the GraphQL answer holds errors and no data".to_string(),
        ));
    }
    let next = match &asked.paging {
        None => None,
        Some(style) => {
            let link: Vec<String> = reply
                .headers
                .get_all("link")
                .iter()
                .filter_map(|value| value.to_str().ok())
                .map(str::to_string)
                .collect();
            paging::following(style, &asked.url, asked.after.as_deref(), &link, &body)
                .map_err(ReadFailure::Malformed)?
        }
    };
    Ok(Page { body, next })
}

/// Whether what came back is a document this observer can publish. What it says is the processor's to judge.
fn read_document(status: u16, body: &[u8]) -> Result<Vec<u8>, ReadFailure> {
    if !(200..300).contains(&status) {
        return Err(ReadFailure::Malformed(format!("it answered {status}")));
    }
    if body.len() > MAX_DOCUMENT_BYTES {
        return Err(ReadFailure::Malformed(format!(
            "its document is {} bytes, and at most {MAX_DOCUMENT_BYTES} can be published",
            body.len()
        )));
    }
    Ok(body.to_vec())
}

pub enum ObserverMessage {
    ClientEvent {
        event: ClientEvent,
    },
    /// A signed section changed.
    SourcesChanged,
    SourcesRead(Vec<Source>),
    /// It is time to read this source.
    Due {
        name: String,
        generation: u64,
    },
    /// A page of a read came back.
    Read {
        name: String,
        generation: u64,
        page: u32,
        outcome: Result<Page, Failure>,
    },
    PrepareShutdown,
}

pub struct Observer<K>(PhantomData<fn() -> K>);

pub struct ObserverState {
    tcp_client: TcpClient,
    healthcheck: HealthHandle,
    infrastructure: ActorRef<InfrastructureSupervisorMessage>,
    configuration: ConfigurationHandle,
    protocols: ProtocolHandle,
    observing: Observing,
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

#[async_trait]
impl<K: Kind> Actor for Observer<K> {
    type Msg = ObserverMessage;
    type State = ObserverState;
    type Arguments = Configured;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        configured: Configured,
    ) -> Result<Self::State, ActorProcessingErr> {
        debug!("{myself:?} starting");
        let resources = AgentBuilder::new(myself.clone(), K::NAME)
            .with_lifecycle_handler(|event| Some(ObserverMessage::ClientEvent { event }))
            .into_configured(configured)
            .build()
            .await?;
        resources
            .infrastructure_events
            .subscribe(myself.clone(), |event| match event {
                InfrastructureEvent::PrepareShutdown => Some(ObserverMessage::PrepareShutdown),
            });
        resources
            .configuration
            .runtime_changes()
            .subscribe(myself.clone(), |changed| {
                (changed.section == SECTION_NAME).then_some(ObserverMessage::SourcesChanged)
            });
        let protocols = resources
            .protocols
            .clone()
            .ok_or("an observer declares its operation, and has no protocol handler")?;
        // One already held, if the replay was quick.
        myself.cast(ObserverMessage::SourcesChanged)?;
        Ok(ObserverState {
            tcp_client: resources.tcp_client,
            healthcheck: resources.healthcheck,
            infrastructure: resources.infrastructure,
            configuration: resources.configuration,
            protocols,
            observing: Observing::default(),
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            ObserverMessage::ClientEvent { event } => match event {
                ClientEvent::Registered { .. } => {
                    let _ = state.healthcheck.cassini_connected();
                }
                ClientEvent::TransportError { reason } => {
                    warn!("Transport error (non-fatal, awaiting reconnect): {reason}");
                    let _ = state.healthcheck.cassini_disconnected();
                }
                _ => {}
            },
            ObserverMessage::SourcesChanged => {
                let configuration = state.configuration.clone();
                let to = myself.clone();
                tokio::spawn(async move {
                    match configuration.runtime(SECTION_NAME).await {
                        Ok(Some(value)) => match sources::parse(&value.body) {
                            Ok(list) => {
                                let _ = to.cast(ObserverMessage::SourcesRead(list));
                            }
                            // Judged when it arrived, so this is not expected.
                            Err(problems) => error!("the sources in force: {problems:?}"),
                        },
                        Ok(None) => info!("no sources are signed yet, so nothing is read"),
                        Err(e) => error!("cannot read the sources in force: {e}"),
                    }
                });
            }
            ObserverMessage::SourcesRead(list) => {
                let steps = state.observing.on(Event::Sources(list));
                carry_out::<K>(&myself, state, steps);
            }
            ObserverMessage::Due { name, generation } => {
                let steps = state.observing.on(Event::Due { name, generation });
                carry_out::<K>(&myself, state, steps);
            }
            ObserverMessage::Read {
                name,
                generation,
                page,
                outcome,
            } => {
                let steps = state.observing.on(Event::Read {
                    name,
                    generation,
                    page,
                    outcome,
                });
                carry_out::<K>(&myself, state, steps);
            }
            ObserverMessage::PrepareShutdown => {
                let steps = state.observing.on(Event::PrepareShutdown);
                carry_out::<K>(&myself, state, steps);
            }
        }
        Ok(())
    }

    async fn handle_supervisor_evt(
        &self,
        _myself: ActorRef<Self::Msg>,
        event: SupervisionEvent,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match event {
            SupervisionEvent::ActorStarted(actor) => debug!("{actor:?} started"),
            // The infrastructure is the one child: its ending means the shutdown handshake is done, or that it failed.
            // Either way exit non-zero, so the pod comes back with fresh certificates.
            SupervisionEvent::ActorTerminated(actor, _, reason) => {
                info!("{actor:?} terminated: {reason:?}");
                if actor.get_id() == state.infrastructure.get_id() {
                    std::process::exit(1);
                }
            }
            SupervisionEvent::ActorFailed(actor, reason) => {
                error!("{actor:?} failed: {reason:?}");
                std::process::exit(1);
            }
            _ => {}
        }
        Ok(())
    }
}

/// Does what was decided.
fn carry_out<K: Kind>(myself: &ActorRef<ObserverMessage>, state: &ObserverState, steps: Vec<Step>) {
    for step in steps {
        match step {
            Step::Fetch {
                name,
                generation,
                url,
                credential,
                paging,
                page,
                query,
                after,
            } => {
                let protocols = state.protocols.clone();
                let to = myself.clone();
                let asked = PageRequest {
                    url,
                    credential,
                    paging,
                    query,
                    after,
                };
                // Off the actor, so a slow host holds up no other source.
                tokio::spawn(async move {
                    let outcome = read::<K>(&protocols, asked).await;
                    let _ = to.cast(ObserverMessage::Read {
                        name,
                        generation,
                        page,
                        outcome,
                    });
                });
            }
            Step::Publish {
                source,
                origin,
                body,
            } => publish::<K>(&state.tcp_client, &source, origin, body),
            Step::Again {
                name,
                generation,
                after,
            } => drop(myself.send_after(after, move || ObserverMessage::Due { name, generation })),
            Step::Health(change) => change.apply(&state.healthcheck),
            Step::ProceedWithShutdown => {
                let _ = state
                    .infrastructure
                    .cast(InfrastructureSupervisorMessage::ProceedWithShutdown);
            }
        }
    }
}

fn publish<K: Kind>(client: &TcpClient, source: &str, origin: String, body: Vec<u8>) {
    let observation = Observation {
        source: source.to_string(),
        origin,
        observed_at_unix_secs: now_unix_secs(),
        body,
    };
    let payload = match observation.encode() {
        Ok(payload) => payload,
        Err(e) => {
            error!("could not encode what `{source}` said: {e}");
            return;
        }
    };
    let size = payload.len();
    match client.publish(PublishRequest {
        topic: K::TOPIC.to_string(),
        payload,
        trace_ctx: WireTraceCtx::from_current_span(),
        offline_behavior: OfflineBehavior::default(),
        share_identity: true,
    }) {
        Ok(()) => info!("read `{source}`: {size} bytes published"),
        Err(e) => warn!("could not publish what `{source}` said: {e:?}"),
    }
}

/// The agent's `start`.
pub async fn start<K: Kind>(configured: Configured) -> Result<(), StartError> {
    configured.init_logging(K::NAME);
    let name = format!("{}.supervisor", K::NAME);
    let (_supervisor, handle) =
        Actor::spawn(Some(name.clone()), Observer::<K>(PhantomData), configured)
            .await
            .map_err(|e| format!("failed to start {name}: {e}"))?;
    handle
        .await
        .map_err(|e| format!("{name} task failed: {e}"))?;
    // The supervisor stopping is never a success: an observer that no longer observes must be restarted.
    Err(format!("{name} stopped").into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observing::next_read;
    use crate::paging::{Next, Page, Style};
    use polar_agent_builder::protocol::testing::{http_handle, http_handle_for};
    use polar_agent_builder::protocol::{Credential, Location, ProtocolKind};
    use polar_crypto::registry::{SecretBinding, SecretKind};
    use ractor::concurrency::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    struct TestKind;

    const READ: OperationDecl = OperationDecl {
        name: "test.document.read",
        doc: "reads a test's document",
        protocol: ProtocolKind::HTTP,
        location: Location::Arbitrary,
    };

    impl Kind for TestKind {
        const NAME: &'static str = "test-observer";
        const TOPIC: &'static str = "test.observations";
        const OPERATION: OperationDecl = READ;
    }

    async fn handler() -> ProtocolHandle {
        static OPERATIONS: &[OperationDecl] = &[READ];
        let ca = polar::egress::testing::TestCa::new("a test's CA");
        http_handle(&ca.pem, OPERATIONS, vec![], None).await.handle
    }

    fn fetch(url: String) -> Fetch<TestKind> {
        Fetch {
            asked: PageRequest::new(url, None, None),
            kind: PhantomData,
        }
    }

    #[tokio::test]
    async fn a_document_comes_back_through_the_handler_exactly_as_it_was() {
        let site = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/openapi.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(b"{\"not\": \"read here\"".to_vec()),
            )
            .mount(&site)
            .await;
        let got = handler()
            .await
            .ask(fetch(format!("{}/openapi.json", site.uri())))
            .await;
        assert_eq!(got.unwrap().body, b"{\"not\": \"read here\"".to_vec());
    }

    #[tokio::test]
    async fn an_answer_that_is_not_a_success_is_a_failure_and_a_host_s_wait_is_honoured() {
        let site = MockServer::start().await;
        Mock::given(path("/gone"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&site)
            .await;
        Mock::given(path("/busy"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "900"))
            .mount(&site)
            .await;
        let protocols = handler().await;
        assert!(
            protocols
                .ask(fetch(format!("{}/gone", site.uri())))
                .await
                .is_err()
        );
        let busy = protocols.ask(fetch(format!("{}/busy", site.uri()))).await;
        assert!(matches!(busy, Err(Failure::Backoff { .. })), "{busy:?}");
        assert_eq!(
            next_read(Duration::from_secs(60), &busy),
            Duration::from_secs(900)
        );
    }

    struct CredentialedKind;

    const READ_WITH: OperationDecl = OperationDecl {
        name: "test.document.read-with-credential",
        doc: "reads a test's document with the credential its source names",
        protocol: ProtocolKind::HTTP,
        location: Location::Bound {
            credential: Credential::Chosen,
        },
    };

    impl Kind for CredentialedKind {
        const NAME: &'static str = "test-credentialed-observer";
        const TOPIC: &'static str = "test.credentialed.observations";
        const OPERATION: OperationDecl = READ;
        const CREDENTIALED: Option<OperationDecl> = Some(READ_WITH);
    }

    const TOKEN: &str = "a-token-found-nowhere-else";

    /// A stand-in behind TLS on `localhost`, every request it saw, and a handler holding one token bound to `localhost`.
    async fn credentialed_site() -> (MockServer, String, ProtocolHandle) {
        static OPERATIONS: &[OperationDecl] = &[READ, READ_WITH];
        let ca = polar::egress::testing::TestCa::new("a credentialed test's CA");
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/projects"))
            .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
            .mount(&server)
            .await;
        let port = polar::egress::testing::https_front(&ca, &server.uri()).await;
        let binding = SecretBinding {
            host_pattern: "localhost".to_string(),
            kind: SecretKind::Token,
            username: None,
        };
        let site =
            http_handle_for(&ca.pem, OPERATIONS, vec![], Some(("jira", TOKEN, binding))).await;
        (
            server,
            format!("https://localhost:{port}/projects"),
            site.handle,
        )
    }

    async fn authorizations(server: &MockServer) -> Vec<Option<String>> {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| {
                r.headers
                    .get("authorization")
                    .map(|v| v.to_str().unwrap().to_string())
            })
            .collect()
    }

    #[tokio::test]
    async fn a_source_that_names_a_credential_is_read_with_it_and_one_that_names_none_with_nothing()
    {
        let (server, url, protocols) = credentialed_site().await;
        let with = read::<CredentialedKind>(
            &protocols,
            PageRequest::new(url.clone(), Some("jira".to_string()), None),
        )
        .await;
        assert_eq!(with.unwrap().body, b"[]".to_vec());
        let without = read::<CredentialedKind>(&protocols, PageRequest::new(url, None, None)).await;
        assert_eq!(without.unwrap().body, b"[]".to_vec());
        assert_eq!(
            authorizations(&server).await,
            vec![Some(format!("Bearer {TOKEN}")), None]
        );
    }

    #[tokio::test]
    async fn a_credential_the_agent_does_not_hold_is_a_failure_and_nothing_is_sent() {
        let (server, url, protocols) = credentialed_site().await;
        let got = read::<CredentialedKind>(
            &protocols,
            PageRequest::new(url, Some("gitlab".to_string()), None),
        )
        .await;
        assert!(
            matches!(got, Err(Failure::NoCredential { ref name }) if name == "gitlab"),
            "{got:?}"
        );
        assert!(authorizations(&server).await.is_empty());
    }

    #[tokio::test]
    async fn a_kind_that_reads_with_no_credential_refuses_a_source_that_names_one_and_sends_nothing()
     {
        let (server, url, protocols) = credentialed_site().await;
        let got = read::<TestKind>(
            &protocols,
            PageRequest::new(url, Some("jira".to_string()), None),
        )
        .await;
        assert!(matches!(got, Err(Failure::Configuration(_))), "{got:?}");
        assert!(authorizations(&server).await.is_empty());
    }

    /// Pages read through the handler as the observer reads them: each says where the next is, the last names none, and
    /// one that sends the observer to another host is a failure of the read, not a page published.
    #[tokio::test]
    async fn a_paged_source_s_pages_say_where_the_next_is_and_only_on_its_own_host() {
        let site = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/projects"))
            .and(wiremock::matchers::query_param_is_missing("page"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("[1]")
                    .insert_header("Link", "</projects?page=2>; rel=\"next\""),
            )
            .mount(&site)
            .await;
        Mock::given(method("GET"))
            .and(path("/projects"))
            .and(wiremock::matchers::query_param("page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_string("[2]"))
            .mount(&site)
            .await;
        Mock::given(method("GET"))
            .and(path("/elsewhere"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("[3]")
                    .insert_header("Link", "<https://other.example/x>; rel=\"next\""),
            )
            .mount(&site)
            .await;
        let protocols = handler().await;
        let link = Some(Style::Link);
        let first = read::<TestKind>(
            &protocols,
            PageRequest::new(format!("{}/projects", site.uri()), None, link.clone()),
        )
        .await
        .unwrap();
        assert_eq!(first.body, b"[1]".to_vec());
        let next = first.next.expect("the first page names the next");
        let Next::At(next) = next else {
            panic!("a link names an address: {next:?}")
        };
        assert_eq!(next, format!("{}/projects?page=2", site.uri()));
        let second = read::<TestKind>(&protocols, PageRequest::new(next, None, link.clone()))
            .await
            .unwrap();
        assert_eq!(
            second,
            Page {
                body: b"[2]".to_vec(),
                next: None
            }
        );
        // Unpaged, a Link header is not followed: the source is one page.
        let unpaged = read::<TestKind>(
            &protocols,
            PageRequest::new(format!("{}/projects", site.uri()), None, None),
        )
        .await
        .unwrap();
        assert_eq!(unpaged.next, None);
        let elsewhere = read::<TestKind>(
            &protocols,
            PageRequest::new(format!("{}/elsewhere", site.uri()), None, link),
        )
        .await;
        assert!(
            matches!(&elsewhere, Err(Failure::Read(why)) if why.contains("another host")),
            "{elsewhere:?}"
        );
    }

    /// A GraphQL source through the handler as the observer reads it: its query POSTed as JSON, each page asked after the
    /// cursor the last named, and an answer of errors with no data a failure of the read, not a page published.
    #[tokio::test]
    async fn a_graphql_source_is_posted_and_paged_by_its_cursor() {
        const QUERY: &str = "query($after: String) { projects(after: $after) { nodes { id } pageInfo { endCursor hasNextPage } } }";
        let site = MockServer::start().await;
        let page = |ids: &[&str], next: Option<&str>| {
            serde_json::json!({ "data": { "projects": {
                "nodes": ids.iter().map(|id| serde_json::json!({ "id": id })).collect::<Vec<_>>(),
                "pageInfo": { "endCursor": next, "hasNextPage": next.is_some() }
            } } })
            .to_string()
        };
        for (after, answer) in [
            (serde_json::Value::Null, page(&["1", "2"], Some("c1"))),
            (serde_json::json!("c1"), page(&["3"], None)),
        ] {
            Mock::given(method("POST"))
                .and(path("/api/graphql"))
                .and(wiremock::matchers::header(
                    "content-type",
                    "application/json",
                ))
                .and(wiremock::matchers::body_json(
                    serde_json::json!({ "query": QUERY, "variables": { "after": after } }),
                ))
                .respond_with(ResponseTemplate::new(200).set_body_string(answer))
                .mount(&site)
                .await;
        }
        Mock::given(method("POST"))
            .and(path("/broken/graphql"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"errors": [{"message": "secret detail"}], "data": null}"#),
            )
            .mount(&site)
            .await;
        let protocols = handler().await;
        let paging = Some(Style::GraphQl {
            connection: "/data/projects".to_string(),
        });
        let url = format!("{}/api/graphql", site.uri());
        let asked = |after: Option<&str>| {
            PageRequest::new(url.clone(), None, paging.clone())
                .graphql(QUERY, after.map(str::to_string))
        };
        let first = read::<TestKind>(&protocols, asked(None)).await.unwrap();
        assert_eq!(first.next, Some(Next::After("c1".to_string())));
        let second = read::<TestKind>(&protocols, asked(Some("c1")))
            .await
            .unwrap();
        assert_eq!(second.next, None, "hasNextPage false: the last page");
        assert!(String::from_utf8_lossy(&second.body).contains("\"3\""));
        let broken = read::<TestKind>(
            &protocols,
            PageRequest::new(format!("{}/broken/graphql", site.uri()), None, None)
                .graphql("{ a }", None),
        )
        .await;
        assert!(
            matches!(&broken, Err(Failure::Read(why)) if !why.contains("secret detail")),
            "{broken:?}"
        );
    }

    #[test]
    fn a_document_too_large_to_publish_is_a_failure_for_its_source() {
        assert!(read_document(200, &vec![0; MAX_DOCUMENT_BYTES + 1]).is_err());
        assert!(read_document(200, &[0; 8]).is_ok());
        for status in [199, 300, 404, 500] {
            assert!(read_document(status, b"{}").is_err(), "{status}");
        }
    }
}
