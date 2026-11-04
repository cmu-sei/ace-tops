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

use crate::holdings::{Change, Holdings, Kind, Watch};
use crate::record::{Arrival, arrival, read_record};
use crate::settings;
use crate::watch::Watching;
use attestation_common::{
    AGENT_NAME, DeploymentRecord, Doubt, DriftWatch, Envelope, InstanceQuestion, Proved,
    REPORTS_TOPIC, REQUESTS_TOPIC, Report, Reporting, Verdict, WorkloadFacts, decode_question,
    drift, encode_report, encode_verdict, findings, judge, prove, replies_topic,
};
use cassini_client::{OfflineBehavior, PublishRequest};
use cassini_types::{ClientEvent, WireTraceCtx};
use polar::cassini::{CassiniClient, TcpClient};
use polar_agent_builder::protocol::{Delivery, Failure, ProtocolHandle, Streaming};
use polar_agent_builder::{
    AgentBuilder, Configured, HealthClient, HealthHandle, InfrastructureEvent,
    InfrastructureSupervisorMessage, Subscription,
};
use polar_scheduler_common::DEPLOYMENT_RECORD_TOPIC;
use polar_signing::Trust;
use ractor::concurrency::Duration;
use ractor::{Actor, ActorProcessingErr, ActorRef, SupervisionEvent, async_trait};
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

/// Says what is new, once, and publishes what is to go out. A change says only what is new; each minute everything that stands goes again, since the credentials
/// agent, which records it, restarts too. It keeps one of each. What it holds is not whole until it has listed everything, so nothing is said before.
fn report(state: &mut AttestationState, regular_check: bool) {
    if !state.held.ready() {
        return;
    }
    let now = findings(&state.held.observed(), state.proved.is_ok());
    let new = if regular_check {
        state.reporting.check(&now)
    } else {
        state.reporting.changed(&now)
    };
    for found in &new {
        error!(
            namespace = found.namespace,
            pod = found.pod,
            pod_uid = found.pod_uid,
            "found of a pod, to be looked at: {:?}",
            found.finding
        );
    }
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
    PrepareShutdown,
}

pub struct AttestationSupervisor;

pub struct AttestationState {
    tcp_client: TcpClient,
    healthcheck: HealthHandle,
    infrastructure: ActorRef<InfrastructureSupervisorMessage>,
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
    shutting_down: bool,
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
        let resources = AgentBuilder::new(myself.clone(), AGENT_NAME)
            .with_subscription(questions)
            .with_subscription(records)
            .with_lifecycle_handler(|event| Some(AttestationMessage::ClientEvent { event }))
            .into_configured(configured)
            .build()
            .await?;
        resources
            .infrastructure_events
            .subscribe(myself.clone(), |event| match event {
                InfrastructureEvent::PrepareShutdown => Some(AttestationMessage::PrepareShutdown),
            });

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

        myself.send_interval(COMPARE_EVERY, || AttestationMessage::Compare);

        Ok(AttestationState {
            tcp_client: resources.tcp_client,
            healthcheck: resources.healthcheck,
            infrastructure: resources.infrastructure,
            protocols,
            watches,
            held: Holdings::new(&namespaces),
            deployment_ca,
            record: None,
            namespaces,
            drift: DriftWatch::new(DRIFT_GRACE_SECS),
            reporting: Reporting::default(),
            proved: Err(Doubt::NotYet),
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
                    }
                }
            }
            AttestationMessage::Compare => {
                // Each time, since the cluster can change under it: a Kubernetes upgrade, a Role lost.
                reconsider(state);
                report(state, true);
                // What it does not hold yet is not missing, so nothing is compared until it has listed everything.
                let Some(record) = state.record.as_ref().filter(|_| state.held.ready()) else {
                    return Ok(());
                };
                let current = drift(record, &state.held.deployed(), &state.namespaces);
                let changes = state.drift.observe(now_secs() as u64, &current);
                for difference in &changes.lasting {
                    error!(
                        version = record.version,
                        "what is deployed is not what the signed record says: {difference:?}"
                    );
                }
                for difference in &changes.gone {
                    info!("what is deployed is again what the signed record says: {difference:?}");
                }
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
            AttestationMessage::PrepareShutdown => {
                info!("PrepareShutdown received");
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
            SupervisionEvent::ActorTerminated(actor, _, reason) => {
                // The infrastructure is this supervisor's linked child from build(); its ending is the end of the shutdown handshake, or a
                // failure. Either way exit non-zero, so the pod starts afresh.
                if actor.get_id() == state.infrastructure.get_id() {
                    info!("infrastructure is down, exiting");
                    std::process::exit(1);
                }
                if !state.shutting_down {
                    error!("{actor:?} stopped unexpectedly: {reason:?}");
                    std::process::exit(1);
                }
            }
            SupervisionEvent::ActorFailed(actor, reason) => {
                error!("{actor:?} failed: {reason:?}");
                if !state.shutting_down {
                    std::process::exit(1);
                }
            }
            _ => (),
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
            })
        };
        answer(&listed_holdings(), &PROVED, record, &question());
        assert_eq!(*asked.borrow(), question().identity);
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
}
