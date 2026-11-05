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

//! The observer's supervisor: the builder's infrastructure, and a schedule of the sources in force. One source's failure is
//! said and tried again at its next time, and touches no other.

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
use ractor::concurrency::Duration;
use ractor::{Actor, ActorProcessingErr, ActorRef, SupervisionEvent, async_trait};
use std::collections::BTreeMap;
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

/// When a source is read next, given how the last read went: its interval, or longer if the host asked for time.
fn next_read(interval: Duration, outcome: &Result<Vec<u8>, Failure>) -> Duration {
    match outcome {
        Err(Failure::Backoff { wait, .. }) | Err(Failure::NotYet { wait }) => interval.max(*wait),
        _ => interval,
    }
}

/// The sources in force, each with a generation, so what was scheduled or read under an older version of a source says so
/// when it comes back and is dropped.
#[derive(Debug, Default)]
struct Schedule {
    sources: BTreeMap<String, (Source, u64)>,
    next_generation: u64,
}

impl Schedule {
    /// Takes a new list whole. What is unchanged keeps its time, what is gone is forgotten, and what is new or changed is
    /// returned, to be read now.
    fn replace(&mut self, sources: Vec<Source>) -> Vec<(String, u64)> {
        let mut kept = BTreeMap::new();
        let mut start = Vec::new();
        for source in sources {
            let name = source.name.clone();
            match self.sources.remove(&name) {
                Some((held, generation)) if held == source => {
                    kept.insert(name, (held, generation));
                }
                _ => {
                    self.next_generation += 1;
                    start.push((name.clone(), self.next_generation));
                    kept.insert(name, (source, self.next_generation));
                }
            }
        }
        self.sources = kept;
        start
    }

    /// The source, if `generation` is still the one in force.
    fn current(&self, name: &str, generation: u64) -> Option<&Source> {
        self.sources
            .get(name)
            .filter(|(_, held)| *held == generation)
            .map(|(source, _)| source)
    }
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
    schedule: Schedule,
    shutting_down: bool,
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
            schedule: Schedule::default(),
            shutting_down: false,
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
                info!("{} source(s) in force", list.len());
                for (name, generation) in state.schedule.replace(list) {
                    myself.cast(ObserverMessage::Due { name, generation })?;
                }
            }
            ObserverMessage::Due { name, generation } => {
                let Some(source) = state.schedule.current(&name, generation) else {
                    return Ok(());
                };
                if state.shutting_down {
                    return Ok(());
                }
                let fetch = Fetch::<K> {
                    url: source.url.clone(),
                    kind: PhantomData,
                };
                let protocols = state.protocols.clone();
                let to = myself.clone();
                // Off the actor, so a slow host holds up no other source.
                tokio::spawn(async move {
                    let outcome = protocols.ask(fetch).await;
                    let _ = to.cast(ObserverMessage::Read {
                        name,
                        generation,
                        outcome,
                    });
                });
            }
            ObserverMessage::Read {
                name,
                generation,
                outcome,
            } => {
                let Some(source) = state.schedule.current(&name, generation) else {
                    debug!("a read of `{name}` came back after its source changed");
                    return Ok(());
                };
                let wait = next_read(Duration::from_secs(source.interval_secs), &outcome);
                if !state.shutting_down {
                    match outcome {
                        Ok(body) => publish::<K>(&state.tcp_client, &name, body),
                        Err(failure) => {
                            warn!(
                                "could not read `{name}`, and will try again in {wait:?}: {failure}"
                            );
                        }
                    }
                    drop(
                        myself.send_after(wait, move || ObserverMessage::Due { name, generation }),
                    );
                }
            }
            ObserverMessage::PrepareShutdown => {
                info!("PrepareShutdown received; a read in flight is not published");
                state.shutting_down = true;
                let _ = state
                    .infrastructure
                    .cast(InfrastructureSupervisorMessage::ProceedWithShutdown);
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
    use polar_agent_builder::protocol::testing::http_handle;
    use polar_agent_builder::protocol::{Location, ProtocolKind};
    use proptest::prelude::*;
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

    fn source(name: &str, url: &str, secs: u64) -> Source {
        Source {
            name: name.to_string(),
            url: url.to_string(),
            interval_secs: secs,
        }
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

    #[test]
    fn a_failure_or_success_waits_its_interval_and_a_shorter_wait_from_a_host_does_not_shorten_it()
    {
        let interval = Duration::from_secs(600);
        assert_eq!(next_read(interval, &Ok(vec![])), interval);
        assert_eq!(
            next_read(interval, &Err(Failure::Transient("x".into()))),
            interval
        );
        let short = Err(Failure::NotYet {
            wait: Duration::from_secs(1),
        });
        assert_eq!(next_read(interval, &short), interval);
    }

    #[test]
    fn a_new_list_reads_only_what_is_new_or_changed_and_forgets_what_is_gone() {
        let mut schedule = Schedule::default();
        let started = schedule.replace(vec![
            source("a", "http://h/a", 60),
            source("b", "http://h/b", 60),
        ]);
        assert_eq!(started.len(), 2);
        let a = started.iter().find(|(n, _)| n == "a").unwrap().1;
        let b = started.iter().find(|(n, _)| n == "b").unwrap().1;

        let again = schedule.replace(vec![
            source("a", "http://h/a", 60),
            source("b", "http://h/moved", 60),
            source("c", "http://h/c", 60),
        ]);
        let names: Vec<&str> = again.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["b", "c"]);
        assert!(
            schedule.current("a", a).is_some(),
            "unchanged keeps its time"
        );
        assert!(
            schedule.current("b", b).is_none(),
            "what was scheduled under the old address is dropped"
        );

        assert!(schedule.replace(vec![]).is_empty());
        assert!(schedule.current("a", a).is_none(), "gone");
    }

    proptest! {
        /// After any sequence of lists: exactly the last list is in force, each at one generation.
        #[test]
        fn the_schedule_holds_exactly_the_last_list(
            lists in prop::collection::vec(prop::collection::btree_map("[a-c]", (0u8..3, 60u64..63), 0..4), 1..6)
        ) {
            let mut schedule = Schedule::default();
            let mut last = Vec::new();
            for list in lists {
                last = list.into_iter().map(|(n, (u, s))| source(&n, &format!("http://h/{u}"), s)).collect::<Vec<_>>();
                schedule.replace(last.clone());
            }
            let held: Vec<Source> = schedule.sources.values().map(|(s, _)| s.clone()).collect();
            prop_assert_eq!(held, last);
        }
    }
}
