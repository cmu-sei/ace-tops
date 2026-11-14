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

//! The attestation agent's supervisor, on the agent builder: health, the Cassini client and the shutdown handshake come from
//! `AgentBuilder`. It keeps the holdings current from its watches and answers each question on its asker's own reply topic. The judgement
//! is `attestation_common::judge`; what it reads about a pod is [`crate::holdings`].
//!
//! A question with no verified asker, or from an identity that names no workload, has no reply topic, and is dropped with a warning, as
//! the state agent's are.

use crate::evidence::{StandingLog, report_record, standing, standing_record};
use crate::holdings::{Change, Holdings, Kind, Watch};
use crate::record::{Arrival, arrival, read_record};
use crate::settings;
use crate::watch::Watching;
use crate::witness::{Kept, Misbehaviour, Witness, WitnessArgs, WitnessMessage};
use attestation_common::witness::{STORE_WITNESS_REPLIES_TOPIC, WITNESS_REQUESTS_TOPIC};
use attestation_common::{
    AGENT_NAME, DeploymentRecord, Doubt, DriftWatch, Envelope, InstanceQuestion, Proved,
    REPORTS_TOPIC, REQUESTS_TOPIC, Report, Reporting, Verdict, WorkloadFacts, decode_question,
    drift, encode_report, encode_verdict, findings, judge, prove, replies_topic,
};
use cassini_client::{OfflineBehavior, PublishRequest};
use cassini_types::{ClientEvent, WireTraceCtx};
use polar::cassini::{CassiniClient, TcpClient};
use polar_agent_builder::protocol::{Delivery, Failure, ProtocolHandle, Streaming};
use polar_agent_builder::recorder::{Recorder, RecorderArgs, RecorderMessage};
use polar_agent_builder::{AgentBuilder, Configured, HealthClient, HealthHandle, Subscription};
use polar_scheduler_common::DEPLOYMENT_RECORD_TOPIC;
use polar_signing::Trust;
use ractor::concurrency::Duration;
use ractor::{Actor, ActorProcessingErr, ActorRef, async_trait};
use std::collections::BTreeMap;
use tracing::{debug, error, info, warn};

/// How long a watch that lost the API waits before listing again.
const RETRY: Duration = Duration::from_secs(5);

/// How often what is deployed is held to the record.
const COMPARE_EVERY: Duration = Duration::from_secs(60);

/// How long a difference has to last before it is reported. A record and what Flux applies from the same commit do not arrive together,
/// and a later layer waits for the health of the ones before it.
const DRIFT_GRACE_SECS: u64 = 600;

/// What it holds is nothing it must save, so this is the handshake's margin.
pub const SHUTDOWN_BUDGET: Duration = Duration::from_secs(10);

/// The answer to a question, from what it holds and what the signed record says of the identity. Until it has proved itself it cannot say, which
/// covers every watch having listed: a pod it does not hold may exist until then, so nothing can be called absent.
pub fn answer(
    held: &Holdings,
    proved: &Result<Proved, Doubt>,
    record: impl Fn(&str) -> Option<WorkloadFacts>,
    question: &InstanceQuestion,
) -> Verdict {
    if proved.is_err() || !held.ready() {
        return Verdict::CannotSay;
    }
    judge(
        record(&question.identity).as_ref(),
        held.facts_of(&question.pod_uid).as_ref(),
    )
}

/// Where the answer to a question from `published_by` goes: the reply topic of the workload its identity names.
pub fn reply_topic_for(published_by: Option<&str>) -> Option<String> {
    published_by
        .and_then(cert_issuer_common::identity::workload_of)
        .map(replies_topic)
}

/// Whether its verdicts are to be believed now, saying so when that changes. A doubt says what it is, and an answer of `CannotSay` follows from it:
/// the askers issue and record that they did (docs/architecture/attestation-when-it-cannot-answer.md, "The agent proves itself").
fn reconsider(state: &mut AttestationState) {
    let now = prove(
        judge,
        state.held.ready(),
        state.record.as_ref(),
        &state.held.pods(),
    );
    match (&state.proved, &now) {
        (Ok(before), Ok(proved)) if before.with_record == proved.with_record => {}
        (Err(before), Err(doubt)) if before == doubt => {}
        // Waiting for what it needs is not doubting itself: a watch relists.
        (_, Err(doubt @ (Doubt::NotYet | Doubt::NotListed))) => {
            info!("it cannot say yet: {doubt:?}");
        }
        (_, Err(doubt)) => error!(
            "it doubts itself, and answers that it cannot say until this has gone: {doubt:?}"
        ),
        (_, Ok(proved)) if proved.with_record => info!(
            judged = proved.judged,
            condemned = proved.condemned,
            "it has proved itself: its verdicts stand"
        ),
        // A record comes through the configuration agent and the git server, so a rollout can leave it with none for over a minute.
        (_, Ok(proved)) => info!(
            judged = proved.judged,
            condemned = proved.condemned,
            "it has proved itself as far as it can with no record: it holds pods to their owners, and cannot say of one that holds up"
        ),
    }
    state.proved = now;
}

/// What is lasting of what is deployed against the record, each said with whether it is under test; none when it cannot compare
/// (no record held, or not everything listed).
pub fn lasting_of(
    record: Option<&DeploymentRecord>,
    ready: bool,
    drift: &DriftWatch,
) -> Option<Vec<(attestation_common::Drift, bool)>> {
    let record = record.filter(|_| ready)?;
    Some(
        drift
            .lasting()
            .map(|d| (d.clone(), record.under_test(d)))
            .collect(),
    )
}

/// The records of `new` findings at `now`, with those that waited for a target: a record names the cluster by the deployment
/// record's target, so until one is held they wait (at most `bound`; past it, what is new is given back, dropped).
pub fn report_records(
    target: Option<&str>,
    waiting: &mut Vec<(Report, i64)>,
    new: &[Report],
    now: i64,
    bound: usize,
) -> (Vec<polar_agent_builder::EvidenceRecord>, Vec<Report>) {
    let mut dropped = Vec::new();
    for found in new {
        if waiting.len() < bound {
            waiting.push((found.clone(), now));
        } else {
            dropped.push(found.clone());
        }
    }
    let Some(target) = target else {
        return (Vec::new(), dropped);
    };
    let records = waiting
        .drain(..)
        .map(|(found, at)| report_record(target, &found, at))
        .collect();
    (records, dropped)
}

/// Each new finding, and those that waited, to the recorder.
fn record_reports(state: &mut AttestationState, new: &[Report]) {
    let target = state.record.as_ref().map(|r| r.target.clone());
    let (records, dropped) = report_records(
        target.as_deref(),
        &mut state.waiting,
        new,
        now_secs(),
        polar_agent_builder::recorder::BOUND,
    );
    for found in dropped {
        error!(
            pod = found.pod,
            "a finding was not recorded: {} wait for a deployment record already: {:?}",
            polar_agent_builder::recorder::BOUND,
            found.finding
        );
    }
    for record in records {
        if let Err(e) = state.recorder.cast(RecorderMessage::Keep(record)) {
            error!("a finding's record could not be handed to the recorder: {e}");
        }
    }
}

/// The cluster's standing, to the recorder when it is due: on a change of what a verdict says, or a day after the last.
fn record_standing(state: &mut AttestationState) {
    let Some(target) = state.record.as_ref().map(|r| r.target.clone()) else {
        return;
    };
    let lasting = lasting_of(state.record.as_ref(), state.held.ready(), &state.drift);
    let verdicts = standing(
        &state.proved,
        state.reporting.standing(),
        lasting.as_deref(),
    );
    let now = now_secs();
    if !state.standing_log.due(&verdicts, now) {
        return;
    }
    match state.recorder.cast(RecorderMessage::Keep(standing_record(
        &target, &verdicts, now,
    ))) {
        Ok(()) => state.standing_log.recorded(&verdicts, now),
        Err(e) => error!("the standing's record could not be handed to the recorder: {e}"),
    }
}

/// Says what is new, once, and publishes what is to go out. A change says only what is new; each minute everything that stands goes again, since the credentials
/// agent, which records it, restarts too. It keeps one of each. What it holds is not whole until it has listed everything, so nothing is said before.
fn report(state: &mut AttestationState, regular_check: bool) {
    if !state.held.ready() {
        return;
    }
    let now = findings(
        &state.held.observed(),
        state.proved.is_ok(),
        state.record.as_ref(),
    );
    let new = if regular_check {
        state.reporting.check(&now)
    } else {
        state.reporting.changed(&now)
    };
    for found in &new {
        // Under test: what a configuration under test made is said apart (docs/architecture/configurations-under-test.md, CT2).
        if found.under_test {
            warn!(
                namespace = found.namespace,
                pod = found.pod,
                pod_uid = found.pod_uid,
                under_test = true,
                "found of a pod under test, to be looked at: {:?}",
                found.finding
            );
        } else {
            error!(
                namespace = found.namespace,
                pod = found.pod,
                pod_uid = found.pod_uid,
                "found of a pod, to be looked at: {:?}",
                found.finding
            );
        }
    }
    record_reports(state, &new);
    let going: &[Report] = if regular_check {
        state.reporting.standing()
    } else {
        &new
    };
    for found in going {
        if let Err(e) = state.tcp_client.publish(PublishRequest {
            topic: REPORTS_TOPIC.to_string(),
            payload: encode_report(found),
            trace_ctx: WireTraceCtx::from_current_span(),
            offline_behavior: OfflineBehavior::default(),
            share_identity: true,
        }) {
            warn!("could not report on {REPORTS_TOPIC}: {e:?}");
        }
    }
}

pub enum AttestationMessage {
    ClientEvent {
        event: ClientEvent,
    },
    Question {
        payload: Vec<u8>,
        published_by: Option<String>,
    },
    /// What a watch said, or that it has ended.
    Seen {
        watch: Watch,
        delivery: Delivery<Change>,
    },
    /// Time to ask for a watch again.
    Again(Watch),
    /// The deployment's signed record, as the configuration agent delivered it.
    Record {
        payload: Vec<u8>,
    },
    /// Time to hold what is deployed to the record.
    Compare,
    /// Something arrived on its evidence reply topic: for the recorder.
    Evidence {
        payload: Vec<u8>,
        published_by: Option<String>,
    },
    /// A checkpoint brought to be witnessed: for the witness.
    Witness {
        payload: Vec<u8>,
        published_by: Option<String>,
    },
    /// The store's key signed a checkpoint that cannot follow what the witness co-signed.
    LogMisbehaved(Misbehaviour),
}

pub struct AttestationSupervisor;

pub struct AttestationState {
    tcp_client: TcpClient,
    healthcheck: HealthHandle,
    protocols: ProtocolHandle,
    /// Each watch in progress: one that ended is not here until it is asked for again.
    watches: BTreeMap<Watch, Streaming>,
    held: Holdings,
    /// The deployment CA, for the record alone.
    deployment_ca: Trust,
    record: Option<DeploymentRecord>,
    namespaces: Vec<String>,
    drift: DriftWatch,
    reporting: Reporting,
    /// Whether its verdicts are to be believed.
    proved: Result<Proved, Doubt>,
    /// Gets its evidence records into `polar-evidence`.
    recorder: ActorRef<RecorderMessage>,
    /// When the standing was last recorded.
    standing_log: StandingLog,
    /// Findings that wait for a deployment record to name the cluster by.
    waiting: Vec<(Report, i64)>,
    /// The witness of the store's logs; none when what it keeps is damaged, so it answers nothing.
    witness: Option<ActorRef<WitnessMessage>>,
    /// The store's identity, whose pod a log's misbehaviour is said of.
    store: String,
    /// Whether a request with no witness to take it has been said.
    said_no_witness: bool,
}

/// The reports of `found`, said of each pod of the store's workload it holds (normally one): the key that signed is the
/// store's, and its pod is the instance that brought it.
pub fn misbehaviour_reports(
    observed: &[attestation_common::ObservedPod],
    store: &str,
    found: &Misbehaviour,
) -> Vec<Report> {
    use base64::Engine as _;
    let base64 = |root: &[u8; 32]| base64::engine::general_purpose::STANDARD.encode(root);
    let Some(subject) = cert_issuer_common::identity::kubernetes_subject_of(store) else {
        return Vec::new();
    };
    let Some((namespace, account)) = subject
        .strip_prefix("system:serviceaccount:")
        .and_then(|rest| rest.split_once(':'))
    else {
        return Vec::new();
    };
    observed
        .iter()
        .filter(|pod| pod.namespace == namespace && pod.facts.service_account == account)
        .map(|pod| Report {
            namespace: pod.namespace.clone(),
            pod: pod.name.clone(),
            pod_uid: pod.uid.clone(),
            finding: attestation_common::Finding::LogInconsistent {
                origin: found.origin.clone(),
                held_size: found.held.as_ref().map(|h| h.size),
                held_root: found.held.as_ref().map(|h| base64(&h.root)),
                offered_size: found.offered_size,
                offered_root: base64(&found.offered_root),
            },
            under_test: false,
        })
        .collect()
}

/// The witness, from what it keeps under its root and its crypto actor's co-signing key: none, said as an error, when
/// what it keeps is damaged or another key's, since a witness that started again from nothing would co-sign whatever came
/// next; none, said, when its deployment gives it no co-signing key.
async fn start_witness(
    myself: &ActorRef<AttestationMessage>,
    root: &str,
    cosigning: Option<polar_agent_builder::crypto::CosignHandle>,
    store: &str,
    client: TcpClient,
    configuration: polar_agent_builder::ConfigurationHandle,
) -> Result<Option<ActorRef<WitnessMessage>>, ActorProcessingErr> {
    let Some(cosigning) = cosigning else {
        error!(
            "the witness of the store's logs does not start, and co-signs nothing: its deployment gives it no co-signing key (POLAR_WITNESS_COSIGNING_KEY)"
        );
        return Ok(None);
    };
    let key = match cosigning.key().await {
        Ok(key) => key,
        Err(e) => {
            error!("the witness of the store's logs does not start, and co-signs nothing: {e}");
            return Ok(None);
        }
    };
    let (kept, holding) = match Kept::open(std::path::Path::new(root), &key) {
        Ok(opened) => opened,
        Err(damage) => {
            error!(
                "the witness of the store's logs does not start, and co-signs nothing: {damage}"
            );
            return Ok(None);
        }
    };
    let report_to = myself.clone();
    let (witness, _) = Actor::spawn_linked(
        Some(format!("{AGENT_NAME}.witness")),
        Witness,
        WitnessArgs {
            kept,
            cosigner: std::sync::Arc::new(cosigning),
            holding,
            store: store.to_string(),
            configuration,
            publish: std::sync::Arc::new(move |payload| {
                client
                    .publish(PublishRequest {
                        topic: STORE_WITNESS_REPLIES_TOPIC.to_string(),
                        payload,
                        trace_ctx: WireTraceCtx::from_current_span(),
                        offline_behavior: OfflineBehavior::default(),
                        share_identity: true,
                    })
                    .map_err(|e| format!("{e:?}"))
            }),
            misbehaved: std::sync::Arc::new(move |found| {
                if let Err(e) = report_to.cast(AttestationMessage::LogMisbehaved(found)) {
                    error!("a log's misbehaviour could not be handed to the supervisor: {e}");
                }
            }),
            clock: || now_secs().max(0) as u64,
        },
        myself.get_cell(),
    )
    .await?;
    Ok(Some(witness))
}

/// Asks for `watch`, whose changes come to `myself`.
fn start_watch(
    protocols: &ProtocolHandle,
    myself: &ActorRef<AttestationMessage>,
    watch: Watch,
) -> Result<Streaming, ActorProcessingErr> {
    let of = watch.clone();
    protocols
        .stream(Watching(watch), myself.clone(), move |delivery| {
            AttestationMessage::Seen {
                watch: of.clone(),
                delivery,
            }
        })
        .map_err(|e| ActorProcessingErr::from(e.to_string()))
}

/// What it holds from what a watch said, and whether the watch has ended: a failure is its last word, and leaves what it said in doubt.
fn change_of(watch: Watch, said: Result<Change, Failure>) -> (Change, bool) {
    match said {
        Ok(change) => (change, false),
        Err(why) => {
            warn!(?watch, "a watch lost the API: {why}");
            (Change::Lost { watch }, true)
        }
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or_default()
}

#[async_trait]
impl Actor for AttestationSupervisor {
    type Msg = AttestationMessage;
    type State = AttestationState;
    type Arguments = Configured;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        configured: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        let namespaces =
            settings::namespaces(&**configured.config()).map_err(ActorProcessingErr::from)?;

        let deliver_to = myself.clone();
        let questions = Subscription::new(REQUESTS_TOPIC, move |incoming| {
            if let Err(e) = deliver_to.cast(AttestationMessage::Question {
                payload: incoming.payload,
                published_by: incoming.published_by,
            }) {
                warn!("failed to hand a question to the supervisor: {e}");
            }
        });
        let ca_path =
            settings::deployment_ca(&**configured.config()).map_err(ActorProcessingErr::from)?;
        let ca_pem = std::fs::read_to_string(&ca_path).map_err(|e| {
            ActorProcessingErr::from(format!("cannot read the deployment CA at {ca_path}: {e}"))
        })?;
        let deployment_ca = Trust::from_pem(&[ca_pem]).map_err(|e| {
            ActorProcessingErr::from(format!(
                "the deployment CA at {ca_path} cannot be used: {e}"
            ))
        })?;

        let deliver_record = myself.clone();
        let records = Subscription::new(DEPLOYMENT_RECORD_TOPIC, move |incoming| {
            if let Err(e) = deliver_record.cast(AttestationMessage::Record {
                payload: incoming.payload,
            }) {
                warn!("failed to hand a deployment record to the supervisor: {e}");
            }
        });
        let deliver_answer = myself.clone();
        let answers = Subscription::new(
            polar_git_server_common::ATTESTATION_AGENT_EVIDENCE_REPLIES_TOPIC,
            move |incoming| {
                if let Err(e) = deliver_answer.cast(AttestationMessage::Evidence {
                    payload: incoming.payload,
                    published_by: incoming.published_by,
                }) {
                    warn!("failed to hand an answer about evidence to the supervisor: {e}");
                }
            },
        );
        let deliver_witness = myself.clone();
        let checkpoints = Subscription::new(WITNESS_REQUESTS_TOPIC, move |incoming| {
            if let Err(e) = deliver_witness.cast(AttestationMessage::Witness {
                payload: incoming.payload,
                published_by: incoming.published_by,
            }) {
                warn!("failed to hand a checkpoint to the supervisor: {e}");
            }
        });
        let witness_root =
            settings::witness_root(&**configured.config()).map_err(ActorProcessingErr::from)?;
        // The git server is in its own namespace and domain: its identity is read off this agent's certificate.
        let own_identity = configured
            .config()
            .read(&cassini_client::environment::TLS_CLIENT_CERT)
            .map_err(|e| ActorProcessingErr::from(e.to_string()))
            .and_then(|path| {
                std::fs::read_to_string(&path).map_err(|e| {
                    ActorProcessingErr::from(format!(
                        "cannot read this agent's certificate at {path}: {e}"
                    ))
                })
            })
            .and_then(|pem| {
                cert_issuer_common::permission::extract_own_identity(&pem).map_err(|e| {
                    ActorProcessingErr::from(format!(
                        "this agent's certificate names no identity: {e}"
                    ))
                })
            })?;
        let server =
            polar_agent_builder::recorder::server_identity(&own_identity).ok_or_else(|| {
                ActorProcessingErr::from(format!(
                    "this agent's identity `{own_identity}` names no workload"
                ))
            })?;
        let resources = AgentBuilder::new(myself.clone(), AGENT_NAME)
            .with_subscription(questions)
            .with_subscription(records)
            .with_subscription(answers)
            .with_subscription(checkpoints)
            .with_lifecycle_handler(|event| Some(AttestationMessage::ClientEvent { event }))
            .into_configured(configured)
            .build()
            .await?;

        let protocols = resources.protocols.clone().ok_or(
            "the builder started no protocol handler, though the agent declares an operation",
        )?;
        let mut watches = BTreeMap::new();
        for namespace in &namespaces {
            for kind in Kind::ALL {
                let watch = Watch {
                    kind,
                    namespace: namespace.clone(),
                };
                let stream = start_watch(&protocols, &myself, watch.clone())?;
                watches.insert(watch, stream);
            }
        }

        let signer = resources
            .signer
            .clone()
            .ok_or("the builder started no signer, though the agent declares `signing`")?;
        let client = resources.tcp_client.clone();
        let (recorder, _) = Actor::spawn_linked(
            Some(format!("{AGENT_NAME}.recorder")),
            Recorder,
            RecorderArgs {
                signer: std::sync::Arc::new(signer),
                publish: std::sync::Arc::new(move |payload| {
                    client
                        .publish(PublishRequest {
                            topic: polar_git_server_common::EVIDENCE_REQUESTS_TOPIC.to_string(),
                            payload,
                            trace_ctx: WireTraceCtx::from_current_span(),
                            offline_behavior: OfflineBehavior::default(),
                            share_identity: true,
                        })
                        .map_err(|e| format!("{e:?}"))
                }),
                server: server.clone(),
                prefix: format!("{AGENT_NAME}-{}", now_secs()),
                clock: now_secs,
                taken: None,
            },
            myself.get_cell(),
        )
        .await?;

        let witness = start_witness(
            &myself,
            &witness_root,
            resources.cosigning.clone(),
            &server,
            resources.tcp_client.clone(),
            resources.configuration.clone(),
        )
        .await?;

        myself.send_interval(COMPARE_EVERY, || AttestationMessage::Compare);

        Ok(AttestationState {
            tcp_client: resources.tcp_client,
            healthcheck: resources.healthcheck,
            protocols,
            watches,
            held: Holdings::new(&namespaces),
            deployment_ca,
            record: None,
            namespaces,
            drift: DriftWatch::new(DRIFT_GRACE_SECS),
            reporting: Reporting::default(),
            proved: Err(Doubt::NotYet),
            recorder,
            standing_log: StandingLog::default(),
            waiting: Vec::new(),
            witness,
            store: server,
            said_no_witness: false,
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            AttestationMessage::ClientEvent { event } => match event {
                ClientEvent::Registered { .. } => {
                    let _ = state.healthcheck.cassini_connected();
                }
                ClientEvent::TransportError { reason } => {
                    warn!("Transport error occurred (non-fatal, awaiting reconnect): {reason}");
                    let _ = state.healthcheck.cassini_disconnected();
                }
                _ => (),
            },
            AttestationMessage::Again(watch) => {
                let stream = start_watch(&state.protocols, &myself, watch.clone())?;
                state.watches.insert(watch, stream);
            }
            AttestationMessage::Seen { watch, delivery } => {
                let (change, ended) = change_of(watch.clone(), delivery.result);
                if ended {
                    state.watches.remove(&watch);
                    myself.send_after(RETRY, move || AttestationMessage::Again(watch));
                }
                let was_ready = state.held.ready();
                state.held.apply(change);
                if state.held.ready() != was_ready {
                    info!(ready = !was_ready, "what it holds of the cluster changed");
                    reconsider(state);
                }
                report(state, false);
            }
            AttestationMessage::Record { payload } => {
                let record = match read_record(&payload, &state.deployment_ca, now_secs()) {
                    Ok(record) => record,
                    Err(why) => {
                        error!("refused a deployment record: {why}");
                        return Ok(());
                    }
                };
                match arrival(state.record.as_ref().map(|r| r.version), record.version) {
                    Arrival::Same => {}
                    Arrival::Older => error!(
                        version = record.version,
                        held = state.record.as_ref().map(|r| r.version),
                        "refused an older deployment record than it holds"
                    ),
                    Arrival::Newer => {
                        info!(
                            version = record.version,
                            workloads = record.workloads.len(),
                            "holds a new deployment record"
                        );
                        state.record = Some(record);
                        reconsider(state);
                        // What was found before the cluster could be named is recorded now.
                        record_reports(state, &[]);
                    }
                }
            }
            AttestationMessage::Compare => {
                // Each time, since the cluster can change under it: a Kubernetes upgrade, a Role lost.
                reconsider(state);
                report(state, true);
                // What it does not hold yet is not missing, so nothing is compared until it has listed everything.
                if let Some(record) = state.record.as_ref().filter(|_| state.held.ready()) {
                    let current = drift(record, &state.held.deployed(), &state.namespaces);
                    let changes = state.drift.observe(now_secs() as u64, &current);
                    for difference in &changes.lasting {
                        if record.under_test(difference) {
                            warn!(
                                version = record.version,
                                under_test = true,
                                "what is deployed under test is not what the signed record says: {difference:?}"
                            );
                        } else {
                            error!(
                                version = record.version,
                                "what is deployed is not what the signed record says: {difference:?}"
                            );
                        }
                    }
                    for difference in &changes.gone {
                        info!(
                            under_test = record.under_test(difference),
                            "what is deployed is again what the signed record says: {difference:?}"
                        );
                    }
                }
                // Each minute, whatever it could compare: a standing it cannot say is a standing too.
                record_standing(state);
            }
            AttestationMessage::Evidence {
                payload,
                published_by,
            } => {
                if let Err(e) = state.recorder.cast(RecorderMessage::Answer {
                    payload,
                    published_by,
                }) {
                    error!("an answer about evidence could not be handed to the recorder: {e}");
                }
            }
            AttestationMessage::Witness {
                payload,
                published_by,
            } => match &state.witness {
                Some(witness) => {
                    if let Err(e) = witness.cast(WitnessMessage::Request {
                        payload,
                        published_by,
                    }) {
                        error!("a checkpoint could not be handed to the witness: {e}");
                    }
                }
                None if !state.said_no_witness => {
                    error!(
                        "a checkpoint arrived, and the witness is not running: nothing is co-signed"
                    );
                    state.said_no_witness = true;
                }
                None => {}
            },
            AttestationMessage::LogMisbehaved(found) => {
                let reports = misbehaviour_reports(&state.held.observed(), &state.store, &found);
                if reports.is_empty() {
                    error!(
                        origin = found.origin,
                        store = state.store,
                        "a log's misbehaviour is said of no pod: none of the store's is held"
                    );
                }
                for report in &reports {
                    if let Err(e) = state.tcp_client.publish(PublishRequest {
                        topic: REPORTS_TOPIC.to_string(),
                        payload: encode_report(report),
                        trace_ctx: WireTraceCtx::from_current_span(),
                        offline_behavior: OfflineBehavior::default(),
                        share_identity: true,
                    }) {
                        warn!("could not report on {REPORTS_TOPIC}: {e:?}");
                    }
                }
                record_reports(state, &reports);
            }
            AttestationMessage::Question {
                payload,
                published_by,
            } => {
                let Some(topic) = reply_topic_for(published_by.as_deref()) else {
                    warn!(
                        requester = published_by.as_deref().unwrap_or("unverified"),
                        "dropped a question with no asker to answer"
                    );
                    return Ok(());
                };
                let envelope = match decode_question(&payload) {
                    Ok(envelope) => envelope,
                    Err(why) => {
                        warn!(
                            requester = published_by.as_deref(),
                            "dropped a question: {why}"
                        );
                        return Ok(());
                    }
                };
                // The signed record is the next step of slice A: until it is held, no identity is named.
                let record = state.record.as_ref();
                let verdict = answer(
                    &state.held,
                    &state.proved,
                    |identity| record.and_then(|r| r.facts_of(identity)),
                    &envelope.payload,
                );
                match &verdict {
                    Verdict::NotGenuine(why) => warn!(
                        requester = published_by.as_deref(),
                        identity = envelope.payload.identity,
                        pod_uid = envelope.payload.pod_uid,
                        "not genuine: {why:?}"
                    ),
                    other => debug!(
                        identity = envelope.payload.identity,
                        pod_uid = envelope.payload.pod_uid,
                        "answered {other:?}"
                    ),
                }
                let reply = Envelope {
                    correlation_id: envelope.correlation_id,
                    payload: verdict,
                };
                if let Err(e) = state.tcp_client.publish(PublishRequest {
                    topic: topic.clone(),
                    payload: encode_verdict(&reply),
                    trace_ctx: WireTraceCtx::from_current_span(),
                    offline_behavior: OfflineBehavior::default(),
                    share_identity: true,
                }) {
                    warn!("could not answer on {topic}: {e:?}");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::holdings::{Change, Watch};
    use attestation_common::{NotGenuine, OwnerKind};

    const PROVED: Result<Proved, Doubt> = Ok(Proved {
        judged: 1,
        condemned: 0,
        with_record: true,
    });

    fn question() -> InstanceQuestion {
        InstanceQuestion {
            identity: "the-app.polar.serviceaccount.cluster.local".into(),
            pod_uid: "p1".into(),
        }
    }

    fn listed_holdings() -> Holdings {
        let mut held = Holdings::new(&["polar".to_string()]);
        for kind in Kind::ALL {
            held.apply(Change::Listed {
                watch: Watch {
                    kind,
                    namespace: "polar".into(),
                },
            });
        }
        held
    }

    /// However a watch ends, what it holds is no longer whole, and a pod it does not hold can no longer be called absent.
    #[test]
    fn a_watch_that_ended_leaves_it_unable_to_say() {
        let watch = Watch {
            kind: Kind::Pod,
            namespace: "polar".into(),
        };
        let mut held = listed_holdings();
        let (change, ended) = change_of(
            watch.clone(),
            Ok(Change::Listed {
                watch: watch.clone(),
            }),
        );
        assert!(!ended);
        held.apply(change);
        assert!(held.ready());
        for why in [
            Failure::Transient("lost".into()),
            Failure::Configuration("refused".into()),
            Failure::Read("unreadable".into()),
        ] {
            let mut held = listed_holdings();
            let (change, ended) = change_of(watch.clone(), Err(why));
            assert!(ended);
            held.apply(change);
            assert!(!held.ready());
            assert_eq!(
                answer(&held, &PROVED, |_| None, &question()),
                Verdict::CannotSay
            );
        }
    }

    #[test]
    fn before_every_watch_has_listed_it_cannot_say_even_for_a_pod_it_does_not_hold() {
        let held = Holdings::new(&["polar".to_string()]);
        assert_eq!(
            answer(&held, &PROVED, |_| None, &question()),
            Verdict::CannotSay
        );
    }

    #[test]
    fn once_it_has_listed_a_pod_it_does_not_hold_does_not_exist() {
        assert_eq!(
            answer(&listed_holdings(), &PROVED, |_| None, &question()),
            Verdict::NotGenuine(NotGenuine::NoSuchPod)
        );
    }

    // docs/architecture/attestation-when-it-cannot-answer.md, "The agent proves itself": an agent that doubts itself refuses no one.
    #[test]
    fn until_it_has_proved_itself_it_cannot_say_whatever_it_would_have_said() {
        for doubt in [
            Doubt::NotYet,
            Doubt::CondemnsMost {
                condemned: 3,
                judged: 4,
            },
        ] {
            assert_eq!(
                answer(&listed_holdings(), &Err(doubt), |_| None, &question()),
                Verdict::CannotSay
            );
        }
    }

    #[test]
    fn the_record_is_asked_about_the_identity_the_question_names() {
        let asked = std::cell::RefCell::new(String::new());
        let record = |identity: &str| {
            *asked.borrow_mut() = identity.to_string();
            Some(WorkloadFacts {
                owner_kind: OwnerKind::Deployment,
                owner_name: "the-app".into(),
                service_account: "the-app".into(),
                hardening: Default::default(),
            })
        };
        answer(&listed_holdings(), &PROVED, record, &question());
        assert_eq!(*asked.borrow(), question().identity);
    }

    fn crash(pod: &str) -> Report {
        Report {
            namespace: "polar".into(),
            pod: pod.into(),
            pod_uid: format!("uid-{pod}"),
            finding: attestation_common::Finding::Panicked {
                container: "agent".into(),
                exit_code: 101,
                finished_at: "2026-11-10T12:00:00Z".into(),
                image_id: "registry/agent@sha256:0".into(),
            },
            under_test: false,
        }
    }

    // docs/architecture/polar-eden.md, "Attestation verdicts as records": a record names the cluster by the deployment record's target, so
    // what is found before one is held waits, in order and within the bound, and is recorded with the time it was found once one is.
    #[test]
    fn a_finding_waits_for_the_cluster_s_name_and_is_recorded_when_it_comes() {
        let mut waiting = Vec::new();
        let (records, dropped) =
            report_records(None, &mut waiting, &[crash("a"), crash("b")], 10, 3);
        assert!(records.is_empty() && dropped.is_empty());
        let (records, dropped) =
            report_records(None, &mut waiting, &[crash("c"), crash("d")], 20, 3);
        assert!(records.is_empty());
        assert_eq!(dropped, [crash("d")], "past the bound, what is new");
        let (records, dropped) = report_records(Some("u7c"), &mut waiting, &[], 30, 3);
        assert!(dropped.is_empty() && waiting.is_empty());
        let said: Vec<(String, i64)> = records
            .iter()
            .map(|r| {
                (
                    r.payload()["subject"]["pod"].as_str().unwrap().to_string(),
                    r.payload()["found_at_unix_secs"].as_i64().unwrap(),
                )
            })
            .collect();
        assert_eq!(said, [("a".into(), 10), ("b".into(), 10), ("c".into(), 20)]);
        assert!(
            records
                .iter()
                .all(|r| r.payload()["subject"]["target"] == "u7c")
        );
        let (records, _) = report_records(Some("u7c"), &mut waiting, &[crash("e")], 40, 3);
        assert_eq!(records.len(), 1, "with a name, at once");
    }

    #[test]
    fn what_is_lasting_is_said_only_once_it_can_compare_and_with_whether_it_is_under_test() {
        let record = DeploymentRecord::from_payload(&serde_json::json!({
            "schema": 1, "target": "u7c", "version": 1,
            "workloads": [{
                "identity": "the-app.polar.serviceaccount.cluster.local",
                "owner_kind": "Deployment", "owner_name": "the-app", "namespace": "polar",
                "service_account": "the-app",
                "containers": [{ "name": "the-app", "image": "r/app@sha256:aa" }]
            }]
        }))
        .unwrap();
        let mut watch = DriftWatch::new(0);
        let gone = attestation_common::Drift::NotDeployed {
            workload: "the-app".into(),
        };
        watch.observe(0, &[gone.clone()].into());
        assert_eq!(lasting_of(None, true, &watch), None, "no record");
        assert_eq!(lasting_of(Some(&record), false, &watch), None, "not listed");
        assert_eq!(
            lasting_of(Some(&record), true, &watch),
            Some(vec![(gone, false)])
        );
    }

    #[test]
    fn an_answer_goes_to_the_workload_the_broker_vouches_for() {
        assert_eq!(
            reply_topic_for(Some("credentials-agent.polar.serviceaccount.cluster.local"))
                .as_deref(),
            Some("attestation-instance-replies.credentials-agent")
        );
        assert_eq!(reply_topic_for(None), None);
        assert_eq!(reply_topic_for(Some("not an identity")), None);
    }

    #[test]
    fn a_logs_misbehaviour_is_said_of_the_stores_pod_alone() {
        use crate::witness::{Held, Misbehaviour};
        let pod = |namespace: &str, name: &str, account: &str| attestation_common::ObservedPod {
            namespace: namespace.into(),
            name: name.into(),
            uid: format!("uid-{name}"),
            facts: attestation_common::PodFacts {
                service_account: account.into(),
                owner: None,
                containers: Vec::new(),
                ephemeral: Vec::new(),
            },
            terminations: Vec::new(),
        };
        let observed = [
            pod("polar", "polar-git-server-abc", "polar-git-server"),
            pod("polar", "jira-observer-1", "jira-observer"),
            pod("elsewhere", "polar-git-server-x", "polar-git-server"),
        ];
        let found = Misbehaviour {
            origin: "polar-git-server.polar.serviceaccount.cluster.local/evidence".into(),
            held: Some(Held {
                size: 4,
                root: [1; 32],
                time: 9,
                line: String::new(),
            }),
            offered_size: 3,
            offered_root: [2; 32],
        };
        let reports = misbehaviour_reports(
            &observed,
            "polar-git-server.polar.serviceaccount.cluster.local",
            &found,
        );
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].pod, "polar-git-server-abc");
        assert!(matches!(
            &reports[0].finding,
            attestation_common::Finding::LogInconsistent {
                held_size: Some(4),
                offered_size: 3,
                ..
            }
        ));
        assert!(misbehaviour_reports(&observed, "not an identity", &found).is_empty());
    }
}
