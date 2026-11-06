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

use crate::observing::{Event, Observing, Step};
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
    /// Its one operation, declared `Location::Arbitrary`: a URL from a signed section, never with a credential.
    const OPERATION: OperationDecl;
}

/// A GET of a source's address.
struct Fetch<K> {
    url: String,
    kind: PhantomData<fn() -> K>,
}

impl<K: Kind> Operation for Fetch<K> {
    type Protocol = Http;
    type Output = Vec<u8>;
    const DECL: OperationDecl = K::OPERATION;

    fn request(&self) -> Request {
        Request::get_at(self.url.clone())
    }

    fn read(&self, reply: &Reply) -> Result<Vec<u8>, ReadFailure> {
        read_document(reply.status.as_u16(), &reply.body)
    }
}

/// A source's document, read through the protocol handler as this kind's one operation: what the observer publishes, and
/// what a kind's tests read through the same handler (`polar-http-testkit`).
pub async fn read<K: Kind>(protocols: &ProtocolHandle, url: String) -> Result<Vec<u8>, Failure> {
    protocols
        .ask(Fetch::<K> {
            url,
            kind: PhantomData,
        })
        .await
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
    /// A read came back.
    Read {
        name: String,
        generation: u64,
        outcome: Result<Vec<u8>, Failure>,
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
                outcome,
            } => {
                let steps = state.observing.on(Event::Read {
                    name,
                    generation,
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
            } => {
                let protocols = state.protocols.clone();
                let to = myself.clone();
                // Off the actor, so a slow host holds up no other source.
                tokio::spawn(async move {
                    let outcome = read::<K>(&protocols, url).await;
                    let _ = to.cast(ObserverMessage::Read {
                        name,
                        generation,
                        outcome,
                    });
                });
            }
            Step::Publish { source, body } => publish::<K>(&state.tcp_client, &source, body),
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

fn publish<K: Kind>(client: &TcpClient, source: &str, body: Vec<u8>) {
    let observation = Observation {
        source: source.to_string(),
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
    use polar_agent_builder::protocol::testing::http_handle;
    use polar_agent_builder::protocol::{Location, ProtocolKind};
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
            url,
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
        assert_eq!(got.unwrap(), b"{\"not\": \"read here\"".to_vec());
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

    #[test]
    fn a_document_too_large_to_publish_is_a_failure_for_its_source() {
        assert!(read_document(200, &vec![0; MAX_DOCUMENT_BYTES + 1]).is_err());
        assert!(read_document(200, &[0; 8]).is_ok());
        for status in [199, 300, 404, 500] {
            assert!(read_document(status, b"{}").is_err(), "{status}");
        }
    }
}
