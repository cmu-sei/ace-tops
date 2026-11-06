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

//! A test kit for every kind of HTTP observer and processor (docs/architecture/http-observers.md, "Evidence", bite 3).
//! A kind's crate calls [`polar_http_tests!`] with its observer, its processor, its mapping and the samples beside it, and
//! gets the same tests every kind has:
//!
//! - the mapping, judged by the processor's scaffold, signed by `polar-sign`, committed as Dhall, evaluated as the
//!   scheduler's observer does and submitted to a configuration actor holding the processor's own sections, is the
//!   section in force, and the projection the processor takes from it is the mapping's;
//! - each sample, served by a stand-in service and read through the real protocol handler as the observer's operation,
//!   decided on by the observer's and the processor's own cores, and carried between them as an encoded observation,
//!   becomes what is written beside it, which a person reads and reviews;
//! - written to real Neo4j, one sample to a source and then all to one source in turn, the graph is what the model graph
//!   says ([`polar_projection::testing::MemoryGraph`]), which is what the processor's property is held to;
//! - `polar-sign projection test`, which a deployment holds its own mapping to, passes for the kind's by the processor's
//!   own scaffold.
//!
//! A sample is `<name>.json`, the document as a service returns it, beside `<name>.expected.json`, what it becomes:
//! the nodes and edges it writes, without the stamps, and how many entries were skipped, or why it was refused. Run with
//! `POLAR_BLESS=1` to write what each sample becomes now; read it before committing it, since it is then what is
//! expected.

use polar_agent_builder::protocol::ProtocolHandle;
use polar_agent_builder::{ConfigurationHandle, PolarAgent, UpdateVerifier};
use polar_http_observer::Observation;
use polar_http_observer::observing::{self, Observing};
use polar_http_observer::sources::Source;
use polar_http_processor::processing::{self, Outcome, Processing};
use polar_http_processor::{Kind as ProcessorKind, SECTION_NAME};
use polar_projection::samples::{self, Sample};
use polar_projection::testing::MemoryGraph;
use polar_projection::{Projection, Write};
use ractor::{Actor, ActorProcessingErr, ActorRef};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub use polar_agent_builder::configuration::ApplyOutcome;

/// The tests every kind has. `mapping` and `samples` are paths from the kind's crate.
///
/// ```ignore
/// polar_http_testkit::polar_http_tests! {
///     observer: openapi_observer::agent::OpenApiObserver,
///     processor: OpenApiProcessor,
///     mapping: "../../polar-projection/examples/openapi.dhall",
///     samples: "../../polar-projection/examples/openapi",
/// }
/// ```
#[macro_export]
macro_rules! polar_http_tests {
    (observer: $observer:ty, processor: $processor:ty, mapping: $mapping:literal, samples: $samples:literal $(,)?) => {
        fn kit() -> $crate::Kit {
            $crate::Kit::new(
                concat!(env!("CARGO_MANIFEST_DIR"), "/", $mapping),
                concat!(env!("CARGO_MANIFEST_DIR"), "/", $samples),
            )
        }

        #[test]
        fn the_mapping_is_signed_and_the_processor_takes_it_as_written() {
            $crate::block_on($crate::the_mapping_is_signed_and_taken::<$processor>(&kit()));
        }

        #[test]
        fn each_sample_read_through_the_pair_becomes_what_is_written_beside_it() {
            $crate::block_on($crate::each_sample_becomes_what_is_beside_it::<
                $observer,
                $processor,
            >(&kit()));
        }

        #[test]
        fn a_deployment_s_test_of_the_mapping_passes_by_the_processor_s_own_scaffold() {
            $crate::a_deployment_s_test_passes::<$processor>(&kit());
        }

        #[test]
        fn the_samples_written_to_neo4j_make_the_graph_the_model_says() {
            $crate::block_on($crate::neo4j_is_what_the_model_says::<$observer, $processor>(&kit()));
        }
    };
}

/// Runs a test's body on a runtime of its own, with the threads an actor wants.
pub fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(future)
}

/// A kind's mapping and the samples beside it.
pub struct Kit {
    pub mapping: PathBuf,
    pub samples: PathBuf,
}

impl Kit {
    pub fn new(mapping: impl Into<PathBuf>, samples: impl Into<PathBuf>) -> Self {
        Self {
            mapping: mapping.into(),
            samples: samples.into(),
        }
    }

    fn mapping_source(&self) -> String {
        std::fs::read_to_string(&self.mapping)
            .unwrap_or_else(|e| panic!("cannot read the mapping {}: {e}", self.mapping.display()))
    }

    /// Every sample, by name. A kind with none has not said what its mapping does, so that is a failure.
    pub fn samples(&self) -> Vec<Sample> {
        samples::read(&self.samples).unwrap_or_else(|problem| panic!("{problem}"))
    }
}

/// A parent for the configuration actor to be linked to, as the agent's supervisor is.
struct Parent;

#[ractor::async_trait]
impl Actor for Parent {
    type Msg = ();
    type State = ();
    type Arguments = ();
    async fn pre_start(&self, _: ActorRef<()>, _: ()) -> Result<(), ActorProcessingErr> {
        Ok(())
    }
}

/// The mapping as a deployment's takes it: judged by the processor's scaffold and signed by `polar-sign`, written as the
/// Dhall file that is committed, evaluated as the scheduler's observer does, submitted to a configuration actor holding
/// the processor's own sections, and read back as the section in force, judged as the processor judges it.
pub async fn signed_in_force<P: ProcessorKind + PolarAgent>(kit: &Kit) -> (u64, Projection) {
    let agent = <P as ProcessorKind>::NAME;
    let scaffold = polar_agent_builder::agent::scaffold_json::<P>(None, |_: &str| None)
        .expect("the processor's scaffold");
    let scaffold = polar_sign::scaffold::Scaffold::parse(&scaffold).expect("a scaffold");
    let body = polar_sign::projection_for(&scaffold, SECTION_NAME, &kit.mapping_source())
        .unwrap_or_else(|problems| panic!("the mapping is not signed: {problems:#?}"));

    let ca = polar_signing::testing::root("Polar Internal CA");
    let signer = polar_signing::testing::signer(
        &ca,
        polar_signing::testing::Spec {
            capabilities: vec!["c:update-runtime"],
            ..Default::default()
        },
    );
    let identity = polar_sign::Identity {
        chain: vec![signer.cert_pem],
        key_pem: signer.key_pem,
    };
    let payload = polar_sign::runtime_payload(agent, SECTION_NAME, 1, "the-kit-1", body);
    let file = polar_sign::sign_to_dhall(payload, &identity).expect("signed");
    let document = polar_sign::evaluate(&file).expect("the committed file evaluates");

    let (parent, _) = Actor::spawn(None, Parent, ()).await.expect("a parent");
    let env: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let verifier = UpdateVerifier::new(
        polar_signing::Trust::from_pem(std::slice::from_ref(&ca.pem)).expect("the CA"),
        agent,
    )
    .with_clock(polar_signing::testing::now);
    let configuration = ConfigurationHandle::spawn_with_runtime(
        None,
        agent,
        polar_env::Config::builder(&env).build(),
        Some(verifier),
        <P as PolarAgent>::RUNTIME,
        parent.get_cell(),
    )
    .await
    .expect("a configuration actor");
    match configuration.submit(document).await.expect("an answer") {
        ApplyOutcome::Applied { .. } => {}
        refused => panic!("the processor refused its signed mapping: {refused:?}"),
    }
    let in_force = configuration
        .runtime(SECTION_NAME)
        .await
        .expect("an answer")
        .expect("the section is in force");
    let projection = Projection::judged(&in_force.body, P::BOUNDS).unwrap_or_else(|problems| {
        panic!("the processor judges the section in force: {problems:#?}")
    });
    parent.stop(None);
    (in_force.version, projection)
}

/// The test of [`signed_in_force`]: what the processor takes is what the author wrote.
pub async fn the_mapping_is_signed_and_taken<P: ProcessorKind + PolarAgent>(kit: &Kit) {
    let (version, projection) = signed_in_force::<P>(kit).await;
    assert_eq!(version, 1);
    let written = polar_sign::projection_body(&kit.mapping_source()).expect("the mapping");
    assert_eq!(
        projection,
        Projection::judged(&written, P::BOUNDS).expect("judged")
    );
}

/// What `polar-sign projection test` finds of the kind's mapping and samples by the processor's own scaffold, which is
/// what a deployment's own mapping is held to: the same checks, so a deployment's test passing means what the kind's does.
pub fn a_deployment_s_test_passes<P: ProcessorKind + PolarAgent>(kit: &Kit) {
    let agent = <P as ProcessorKind>::NAME;
    let scaffold = polar_agent_builder::agent::scaffold_json::<P>(None, |_: &str| None)
        .expect("the processor's scaffold");
    let ca = polar_signing::testing::root("Polar Internal CA");
    let someone = polar_signing::testing::signer(&ca, polar_signing::testing::Spec::default());
    let identity = polar_sign::Identity {
        chain: vec![someone.cert_pem],
        key_pem: someone.key_pem,
    };
    let tested = polar_sign::evidence::projection_test(
        &polar_sign::evidence::ProjectionTest {
            scaffold: &scaffold,
            section: SECTION_NAME,
            mapping: &kit.mapping_source(),
            mapping_name: "the kit's mapping",
            samples: &kit.samples,
        },
        &identity,
        std::slice::from_ref(&ca.pem),
        polar_signing::testing::now(),
    )
    .expect("a test");
    assert!(tested.passed(), "{}", tested.details.join("\n\n"));
    assert_eq!(tested.record["subject"]["agent"], agent);
    assert_eq!(tested.record["scaffold"]["agent_version"]["name"], agent);
    assert_eq!(
        tested.record["samples"].as_array().map(Vec::len),
        Some(kit.samples().len())
    );
}

/// An observer and its processor as their actors run them, without the actors or a broker: the observer's core says what
/// to read and the real protocol handler reads it from a stand-in service as the observer's one operation; what it
/// publishes is encoded and decoded as the broker carries it; the processor's core says what to write.
pub struct Pair<O> {
    server: wiremock::MockServer,
    protocols: ProtocolHandle,
    observing: Observing,
    processing: Processing,
    sources: Vec<Source>,
    /// The generation each source's next read is at, from the observer's last `Again`.
    due: BTreeMap<String, u64>,
    clock: i64,
    observer: std::marker::PhantomData<fn() -> O>,
}

/// What a read through the pair came to: the observation the processor was given, and what it said to write.
pub struct Observed {
    pub observation: Observation,
    pub writes: Vec<Write>,
}

impl<O: polar_http_observer::Kind + PolarAgent> Pair<O> {
    pub async fn start(workload: &'static str, mapping: (u64, Projection)) -> Self {
        let ca = polar::egress::testing::TestCa::new("the kit's CA");
        let site = polar_agent_builder::protocol::testing::http_handle(
            &ca.pem,
            O::OPERATIONS,
            vec![],
            None,
        )
        .await;
        let mut processing = Processing::new(workload);
        processing.on(processing::Event::Started);
        processing.on(processing::Event::Mapping(Ok(Some(mapping))));
        Self {
            server: wiremock::MockServer::start().await,
            protocols: site.handle,
            observing: Observing::default(),
            processing,
            sources: Vec::new(),
            due: BTreeMap::new(),
            clock: 0,
            observer: std::marker::PhantomData,
        }
    }

    /// The service answers `document` for `source` now, and the source is read: listed the first time, then when it is
    /// next due.
    pub async fn read(&mut self, source: &str, document: &[u8]) -> Observed {
        let at = format!("/{source}");
        self.server.reset().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(at.as_str()))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(document.to_vec()))
            .mount(&self.server)
            .await;
        let event = match self.due.get(source) {
            Some(generation) => observing::Event::Due {
                name: source.to_string(),
                generation: *generation,
            },
            None => {
                self.sources.push(Source {
                    name: source.to_string(),
                    url: format!("{}{at}", self.server.uri()),
                    interval_secs: 60,
                    credential: None,
                });
                observing::Event::Sources(self.sources.clone())
            }
        };
        let fetches: Vec<observing::Step> = self.observing.on(event);
        let [
            observing::Step::Fetch {
                name,
                generation,
                url,
                credential,
            },
        ] = &fetches[..]
        else {
            panic!("the observer reads `{source}` and only it: {fetches:?}");
        };
        let outcome = polar_http_observer::observer::read::<O>(
            &self.protocols,
            url.clone(),
            credential.clone(),
        )
        .await;
        let steps = self.observing.on(observing::Event::Read {
            name: name.clone(),
            generation: *generation,
            outcome,
        });
        let mut published = None;
        for step in steps {
            match step {
                observing::Step::Publish { source, body } => published = Some((source, body)),
                observing::Step::Again {
                    name, generation, ..
                } => {
                    self.due.insert(name, generation);
                }
                observing::Step::Health(_) => {}
                other => panic!("not a step a read comes to: {other:?}"),
            }
        }
        let (source, body) =
            published.unwrap_or_else(|| panic!("`{source}` was read and not published"));
        self.clock += 1;
        let sent = Observation {
            source,
            observed_at_unix_secs: self.clock,
            body,
        };
        let observation = Observation::decode(&sent.encode().expect("encoded")).expect("decoded");
        assert_eq!(observation, sent, "the broker carries it as it was");
        let mut writes = Vec::new();
        for step in self
            .processing
            .on(processing::Event::Observed(observation.clone()))
        {
            if let processing::Step::Write { writes: these, .. } = step {
                writes.extend(these);
            }
        }
        Observed {
            observation,
            writes,
        }
    }
}

pub use samples::plainly;

fn blessing() -> bool {
    std::env::var_os("POLAR_BLESS").is_some_and(|v| !v.is_empty())
}

/// Each sample, read through the pair, becomes what is written beside it; and what the pair wrote is what the mapping makes
/// of the same observation.
pub async fn each_sample_becomes_what_is_beside_it<O, P>(kit: &Kit)
where
    O: polar_http_observer::Kind + PolarAgent,
    P: ProcessorKind + PolarAgent,
{
    let (version, projection) = signed_in_force::<P>(kit).await;
    let workload = <P as ProcessorKind>::NAME;
    let mut pair = Pair::<O>::start(workload, (version, projection.clone())).await;
    let mut wrong = Vec::new();
    for sample in kit.samples() {
        let observed = pair.read(&sample.name, &sample.document).await;
        let outcome = processing::process(&projection, version, workload, &observed.observation);
        let made = match &outcome {
            Outcome::Write { writes, .. } => writes.clone(),
            Outcome::Refused(_) => Vec::new(),
        };
        assert_eq!(
            observed.writes, made,
            "`{}`: the pair wrote other than the mapping makes of what it read",
            sample.name
        );
        let got = plainly(&outcome);
        if blessing() {
            sample.bless(&got).expect("written");
            continue;
        }
        if let Err(differs) = sample.check(&got) {
            wrong.push(differs.fully(&sample));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n\n"));
}

/// One test at a time in a test binary uses the graph, which they share.
static GRAPH: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The samples written to real Neo4j through the operation the processor hands its graph controller, run by the
/// controller's own write: each to a source of its own, then all to one source in turn and in reverse, which is what a
/// service changing its document is. After each, the graph is what the model graph says.
pub async fn neo4j_is_what_the_model_says<O, P>(kit: &Kit)
where
    O: polar_http_observer::Kind + PolarAgent,
    P: ProcessorKind + PolarAgent,
{
    let graph = polar_test_graph::neo4j();
    let _runtime = polar_test_graph::enter();
    let _one = GRAPH.lock().await;
    polar_test_graph::clear_graph(graph).await;

    let mapping = signed_in_force::<P>(kit).await;
    let mut pair = Pair::<O>::start(<P as ProcessorKind>::NAME, mapping).await;
    let mut model = MemoryGraph::default();
    let samples = kit.samples();
    let one_source = samples.iter().map(|s| (s.name.clone(), s));
    let in_turn = samples
        .iter()
        .chain(samples.iter().rev())
        .map(|s| ("one-source".to_string(), s));
    for (step, (source, sample)) in one_source.chain(in_turn).enumerate() {
        let observed = pair.read(&source, &sample.document).await;
        if let Some(op) = polar_projection::graph::operation(observed.writes.clone()) {
            polar::graph::controller::handle_op(graph, &op)
                .await
                .unwrap_or_else(|e| panic!("`{}` as `{source}` was not written: {e}", sample.name));
        }
        model.apply(&observed.writes);
        assert_eq!(
            polar_test_graph::dump(graph).await,
            model.dump(),
            "after step {step}, `{}` as `{source}`: Neo4j is not what the model graph says",
            sample.name
        );
    }
}
