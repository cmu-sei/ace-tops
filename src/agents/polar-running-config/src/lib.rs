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

//! Asking a running agent for its configuration, the asking side (docs/architecture/dynamic-settings.md, "Asking an
//! agent what is in force"), for anything that asks: the tool, and later a service.
//!
//! Three layers, and a caller takes the ones it needs. [`question`] makes the signed question. [`Asking`] says what to do
//! on each thing the broker says, with nothing running, for a caller that already has a Cassini client. [`ask`] connects,
//! asks and waits. Writing a file from the answer is `polar_sign::template`, which needs no connection. The tool is
//! `polar-sign`'s binary `polar-running-config`.

use cassini_client::{
    ClientEventForwarder, ClientEventForwarderArgs, DeliveryMode, TCPClientConfig, TcpClientActor,
    TcpClientArgs, TcpClientMessage,
};
use cassini_types::ClientEvent;
use polar_scheduler_common::running::{
    ANSWERS_TOPIC, MAX_QUESTION_VALIDITY_SECS, QUESTIONS_TOPIC, RunningConfiguration,
    decode_answer, question_payload,
};
use polar_signing::identity::Identity;
use ractor::{Actor, ActorProcessingErr, ActorRef};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

/// Why no answer came.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AskError {
    #[error("cannot sign the question: {0}")]
    Sign(String),
    #[error("cannot use the certificate to reach the broker: {0}")]
    Client(String),
    #[error("cannot start: {0}")]
    Start(String),
    /// The broker said no, or could not take it.
    #[error("{0}")]
    Refused(String),
    #[error("the connection to the broker ended before an answer")]
    ConnectionEnded,
    #[error(
        "no answer from {agent} in {secs} s. It answers nothing it refuses, so look for the refusal in its log; or it is \
         not running, or the broker cannot be reached (from your own machine: `just port-forwards-up broker`)"
    )]
    NoAnswer { agent: String, secs: u64 },
}

/// A question, signed and ready to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub id: String,
    pub agent: String,
    pub document: Vec<u8>,
}

/// How long a question stays good, in seconds: long enough to outlast the wait, and never past the most an agent takes.
pub fn validity_secs(wait_secs: u64) -> u64 {
    MAX_QUESTION_VALIDITY_SECS.min(wait_secs.max(60))
}

/// The question for `agent`, signed by `identity`. `now` is seconds since the epoch.
pub fn question(
    agent: &str,
    identity: &Identity,
    now: u64,
    wait_secs: u64,
) -> Result<Question, AskError> {
    let id = uuid::Uuid::new_v4().to_string();
    let document = polar_signing::sign_in(
        polar_signing::Domain::RUNNING_CONFIGURATION_QUESTION,
        question_payload(agent, &id, now, now + validity_secs(wait_secs)),
        &identity.chain,
        &identity.key_pem,
    )
    .map_err(|e| AskError::Sign(e.to_string()))?
    .to_value()
    .to_string()
    .into_bytes();
    Ok(Question {
        id,
        agent: agent.to_string(),
        document,
    })
}

/// A Cassini client's settings from a person's files: `<dir>/<user>.crt`, `.key` and `ca.pem`.
pub fn client_config(
    dir: &Path,
    user: &str,
    broker: &str,
    server_name: &str,
) -> Result<TCPClientConfig, AskError> {
    let path = |name: String| dir.join(name).to_string_lossy().to_string();
    let env: HashMap<String, String> = HashMap::from([
        ("TLS_CLIENT_CERT".to_string(), path(format!("{user}.crt"))),
        ("TLS_CLIENT_KEY".to_string(), path(format!("{user}.key"))),
        ("TLS_CA_CERT".to_string(), path("ca.pem".to_string())),
        ("BROKER_ADDR".to_string(), broker.to_string()),
        ("CASSINI_SERVER_NAME".to_string(), server_name.to_string()),
    ]);
    TCPClientConfig::from_env(&env).map_err(AskError::Client)
}

struct Asker;

struct AskerArgs {
    asking: Asking,
    document: Vec<u8>,
    config: TCPClientConfig,
    done: oneshot::Sender<Result<RunningConfiguration, String>>,
}

struct AskerState {
    asking: Asking,
    document: Vec<u8>,
    client: ActorRef<TcpClientMessage>,
    done: Option<oneshot::Sender<Result<RunningConfiguration, String>>>,
}

#[ractor::async_trait]
impl Actor for Asker {
    type Msg = ClientEvent;
    type State = AskerState;
    type Arguments = AskerArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: AskerArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        let (forwarder, _) = Actor::spawn_linked(
            None,
            ClientEventForwarder::new(),
            ClientEventForwarderArgs {
                target: myself.clone(),
                mapper: Box::new(Some),
            },
            myself.clone().into(),
        )
        .await?;
        let events: Arc<ractor::OutputPort<ClientEvent>> = Arc::new(ractor::OutputPort::default());
        events.subscribe(forwarder, Some);
        let (client, _) = Actor::spawn_linked(
            None,
            TcpClientActor,
            TcpClientArgs {
                config: args.config,
                registration_id: None,
                delivery: DeliveryMode::Broadcast(events),
                answers: None,
            },
            myself.clone().into(),
        )
        .await?;
        Ok(AskerState {
            asking: args.asking,
            document: args.document,
            client,
            done: Some(args.done),
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        event: ClientEvent,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match state.asking.on(event) {
            Step::Nothing => {}
            Step::Subscribe => state.client.send_message(TcpClientMessage::Subscribe {
                topic: ANSWERS_TOPIC.to_string(),
                trace_ctx: None,
            })?,
            Step::Ask => state.client.send_message(TcpClientMessage::publish(
                QUESTIONS_TOPIC.to_string(),
                state.document.clone(),
                None,
            ))?,
            Step::Answered(answer) => {
                if let Some(done) = state.done.take() {
                    let _ = done.send(Ok(*answer));
                }
                myself.stop(None);
            }
            Step::Failed(why) => {
                if let Some(done) = state.done.take() {
                    let _ = done.send(Err(why));
                }
                myself.stop(None);
            }
        }
        Ok(())
    }
}

/// Connects with `config`, puts `question`, and waits up to `wait` for its answer.
pub async fn ask(
    question: Question,
    config: TCPClientConfig,
    wait: Duration,
) -> Result<RunningConfiguration, AskError> {
    let (done, answered) = oneshot::channel();
    let agent = question.agent.clone();
    let (asker, _handle) = Actor::spawn(
        None,
        Asker,
        AskerArgs {
            asking: Asking {
                agent: question.agent,
                id: question.id,
            },
            document: question.document,
            config,
            done,
        },
    )
    .await
    .map_err(|e| AskError::Start(e.to_string()))?;

    let outcome = tokio::time::timeout(wait, answered).await;
    // A caller that goes on running is not left with a connection.
    asker.stop(None);
    match outcome {
        Ok(Ok(Ok(answer))) => Ok(answer),
        Ok(Ok(Err(why))) => Err(AskError::Refused(why)),
        Ok(Err(_)) => Err(AskError::ConnectionEnded),
        Err(_) => Err(AskError::NoAnswer {
            agent,
            secs: wait.as_secs(),
        }),
    }
}

/// What to do next.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    Nothing,
    /// Listen for answers. First, so the answer cannot go by before anyone hears it.
    Subscribe,
    /// Put the question.
    Ask,
    Answered(Box<RunningConfiguration>),
    Failed(String),
}

/// What it means to be refused on one of the two topics: a person's certificate names no topics, so only policy lets
/// one use them.
fn refused(what: &str, topic: &str, reason: &str) -> Step {
    Step::Failed(format!(
        "the broker refused to let you {what} on {topic}: {reason}. Asking needs you in the group config-readers, by the \
         signed groups document, and the rules in infra/seeds/signed/policy.cedar in the policy in force"
    ))
}

/// Whether an answer is the one asked for: to this question, about this agent, and from it by the broker's word.
pub fn is_the_answer(
    answer: &RunningConfiguration,
    id: &str,
    agent: &str,
    published_by: Option<&str>,
) -> bool {
    answer.id == id
        && answer.agent == agent
        && published_by.and_then(cert_issuer_common::identity::workload_of) == Some(agent)
}

/// The tool's one question.
pub struct Asking {
    pub agent: String,
    pub id: String,
}

impl Asking {
    pub fn on(&self, event: ClientEvent) -> Step {
        match event {
            // Again after a reconnection: a new session holds no subscription.
            ClientEvent::Registered { .. } => Step::Subscribe,
            ClientEvent::ClientSubscribed { topic } if topic == ANSWERS_TOPIC => Step::Ask,
            ClientEvent::SubscribeRefused { topic, reason } if topic == ANSWERS_TOPIC => {
                refused("listen", &topic, &reason)
            }
            ClientEvent::PublishRefused { topic, reason } if topic == QUESTIONS_TOPIC => {
                refused("ask", &topic, &reason)
            }
            ClientEvent::PublishDropped { topic, reason }
            | ClientEvent::PublishDeferred { topic, reason }
                if topic == QUESTIONS_TOPIC =>
            {
                Step::Failed(format!(
                    "the broker could not take the question now: {reason}. Try again"
                ))
            }
            ClientEvent::RegistrationRefused { reason, .. } => {
                Step::Failed(format!("the broker refused the connection: {reason}"))
            }
            ClientEvent::MessagePublished {
                topic,
                payload,
                published_by,
                ..
            } if topic == ANSWERS_TOPIC => match decode_answer(&payload) {
                Ok(answer)
                    if is_the_answer(&answer, &self.id, &self.agent, published_by.as_deref()) =>
                {
                    Step::Answered(Box::new(answer))
                }
                // Anyone asking hears every answer. Not ours.
                _ => Step::Nothing,
            },
            _ => Step::Nothing,
        }
    }
}

/// An answer a survey heard: from which agent, and which of its pods by the broker's stamp, when it runs several.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heard {
    pub agent: String,
    /// The pod's `Instance.uid`, as the broker stamped it, and its name if the broker had it.
    pub instance: Option<String>,
    pub pod: Option<String>,
    pub answer: RunningConfiguration,
}

/// What to do next, asking several agents at once.
#[derive(Debug, PartialEq, Eq)]
pub enum SurveyStep {
    Nothing,
    /// Listen for answers, first.
    Subscribe,
    /// Put every question.
    AskAll,
    Heard(Box<Heard>),
    Failed(String),
}

/// Many questions on one connection: every agent of a deployment asked, and every answer each of its pods gives heard,
/// until the wait ends, since each pod holds its own configuration (`polar-sign check --ask`).
pub struct Surveying {
    /// Each question's agent, by its id.
    pub asked: HashMap<String, String>,
}

impl Surveying {
    pub fn on(&self, event: ClientEvent) -> SurveyStep {
        match event {
            ClientEvent::Registered { .. } => SurveyStep::Subscribe,
            ClientEvent::ClientSubscribed { topic } if topic == ANSWERS_TOPIC => SurveyStep::AskAll,
            ClientEvent::SubscribeRefused { topic, reason } if topic == ANSWERS_TOPIC => {
                match refused("listen", &topic, &reason) {
                    Step::Failed(why) => SurveyStep::Failed(why),
                    _ => SurveyStep::Nothing,
                }
            }
            ClientEvent::PublishRefused { topic, reason } if topic == QUESTIONS_TOPIC => {
                match refused("ask", &topic, &reason) {
                    Step::Failed(why) => SurveyStep::Failed(why),
                    _ => SurveyStep::Nothing,
                }
            }
            ClientEvent::RegistrationRefused { reason, .. } => {
                SurveyStep::Failed(format!("the broker refused the connection: {reason}"))
            }
            ClientEvent::MessagePublished {
                topic,
                payload,
                published_by,
                published_instance,
                ..
            } if topic == ANSWERS_TOPIC => match decode_answer(&payload) {
                Ok(answer) => match self.asked.get(&answer.id) {
                    Some(agent)
                        if is_the_answer(&answer, &answer.id, agent, published_by.as_deref()) =>
                    {
                        SurveyStep::Heard(Box::new(Heard {
                            agent: agent.clone(),
                            instance: published_instance.as_ref().map(|i| i.uid.clone()),
                            pod: published_instance.and_then(|i| i.pod),
                            answer,
                        }))
                    }
                    _ => SurveyStep::Nothing,
                },
                _ => SurveyStep::Nothing,
            },
            _ => SurveyStep::Nothing,
        }
    }
}

struct Surveyor;

struct SurveyorArgs {
    surveying: Surveying,
    documents: Vec<Vec<u8>>,
    config: TCPClientConfig,
    heard: tokio::sync::mpsc::UnboundedSender<Result<Heard, String>>,
}

struct SurveyorState {
    surveying: Surveying,
    documents: Vec<Vec<u8>>,
    client: ActorRef<TcpClientMessage>,
    heard: tokio::sync::mpsc::UnboundedSender<Result<Heard, String>>,
}

#[ractor::async_trait]
impl Actor for Surveyor {
    type Msg = ClientEvent;
    type State = SurveyorState;
    type Arguments = SurveyorArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: SurveyorArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        let (forwarder, _) = Actor::spawn_linked(
            None,
            ClientEventForwarder::new(),
            ClientEventForwarderArgs {
                target: myself.clone(),
                mapper: Box::new(Some),
            },
            myself.clone().into(),
        )
        .await?;
        let events: Arc<ractor::OutputPort<ClientEvent>> = Arc::new(ractor::OutputPort::default());
        events.subscribe(forwarder, Some);
        let (client, _) = Actor::spawn_linked(
            None,
            TcpClientActor,
            TcpClientArgs {
                config: args.config,
                registration_id: None,
                delivery: DeliveryMode::Broadcast(events),
                answers: None,
            },
            myself.clone().into(),
        )
        .await?;
        Ok(SurveyorState {
            surveying: args.surveying,
            documents: args.documents,
            client,
            heard: args.heard,
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        event: ClientEvent,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match state.surveying.on(event) {
            SurveyStep::Nothing => {}
            SurveyStep::Subscribe => state.client.send_message(TcpClientMessage::Subscribe {
                topic: ANSWERS_TOPIC.to_string(),
                trace_ctx: None,
            })?,
            SurveyStep::AskAll => {
                for document in &state.documents {
                    state.client.send_message(TcpClientMessage::publish(
                        QUESTIONS_TOPIC.to_string(),
                        document.clone(),
                        None,
                    ))?;
                }
            }
            SurveyStep::Heard(heard) => {
                let _ = state.heard.send(Ok(*heard));
            }
            SurveyStep::Failed(why) => {
                let _ = state.heard.send(Err(why));
                myself.stop(None);
            }
        }
        Ok(())
    }
}

/// Connects with `config`, puts every question, and hears answers for all of `wait`: every pod of every agent asked
/// answers once. What it heard, or why it could not ask.
pub async fn survey(
    questions: Vec<Question>,
    config: TCPClientConfig,
    wait: Duration,
) -> Result<Vec<Heard>, AskError> {
    let (heard, mut hearing) = tokio::sync::mpsc::unbounded_channel();
    let surveying = Surveying {
        asked: questions
            .iter()
            .map(|q| (q.id.clone(), q.agent.clone()))
            .collect(),
    };
    let (surveyor, _handle) = Actor::spawn(
        None,
        Surveyor,
        SurveyorArgs {
            surveying,
            documents: questions.into_iter().map(|q| q.document).collect(),
            config,
            heard,
        },
    )
    .await
    .map_err(|e| AskError::Start(e.to_string()))?;
    let mut answers = Vec::new();
    let until = tokio::time::Instant::now() + wait;
    let outcome = loop {
        match tokio::time::timeout_at(until, hearing.recv()).await {
            Ok(Some(Ok(one))) => answers.push(one),
            Ok(Some(Err(why))) => break Err(AskError::Refused(why)),
            Ok(None) => break Err(AskError::ConnectionEnded),
            Err(_) => break Ok(()),
        }
    };
    surveyor.stop(None);
    outcome.map(|()| answers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_scheduler_common::running::{QUESTION_TYPE, encode_answer};
    use polar_signing::testing;
    use proptest::prelude::*;

    fn signer_identity() -> (testing::Authority, Identity) {
        let ca = testing::root("Polar Internal CA");
        let signer = testing::signer(&ca, testing::Spec::default());
        let identity = Identity {
            chain: vec![signer.cert_pem.clone()],
            key_pem: signer.key_pem.clone(),
        };
        (ca, identity)
    }

    #[test]
    fn a_question_is_signed_for_questions_alone_names_its_agent_and_is_good_now() {
        let (ca, identity) = signer_identity();
        let now = testing::now() as u64;
        let asked = question(AGENT, &identity, now, 15).unwrap();
        let document =
            polar_signing::Document::from_value(&serde_json::from_slice(&asked.document).unwrap())
                .unwrap();
        let trust = polar_signing::Trust::from_pem(std::slice::from_ref(&ca.pem)).unwrap();
        polar_signing::verify_in(
            polar_signing::Domain::RUNNING_CONFIGURATION_QUESTION,
            &document,
            &trust,
            now as i64,
        )
        .unwrap();
        let payload = &document.payload;
        assert_eq!(payload["type"], QUESTION_TYPE);
        assert_eq!(payload["target"]["agent"], AGENT);
        assert_eq!(payload["id"], asked.id.as_str());
        assert_eq!(payload["issued_at"], now);
        assert_eq!(payload["not_after"], now + 60);
        assert!(
            polar_signing::verify(&document, &trust, now as i64).is_err(),
            "not a configuration document"
        );
    }

    #[test]
    fn each_question_has_its_own_id() {
        let (_, identity) = signer_identity();
        let first = question(AGENT, &identity, 1, 15).unwrap();
        let second = question(AGENT, &identity, 1, 15).unwrap();
        assert_ne!(first.id, second.id);
    }

    #[test]
    fn a_key_that_is_not_a_key_says_it_cannot_sign() {
        let (_, mut identity) = signer_identity();
        identity.key_pem = "not a key".to_string();
        assert!(matches!(
            question(AGENT, &identity, 1, 15),
            Err(AskError::Sign(_))
        ));
    }

    #[tokio::test]
    async fn with_no_broker_there_the_wait_ends_and_says_where_to_look() {
        let dir = tempfile::tempdir().unwrap();
        let ca = testing::root("Polar Internal CA");
        let signer = testing::signer(&ca, testing::Spec::default());
        std::fs::write(dir.path().join("alice.crt"), &signer.cert_pem).unwrap();
        std::fs::write(dir.path().join("alice.key"), &signer.key_pem).unwrap();
        std::fs::write(dir.path().join("ca.pem"), &ca.pem).unwrap();
        // A port nothing listens on: bound, read, and let go.
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let broker = free.local_addr().unwrap().to_string();
        drop(free);
        let config = client_config(dir.path(), "alice", &broker, "cassini.example").unwrap();
        let identity = Identity {
            chain: vec![signer.cert_pem.clone()],
            key_pem: signer.key_pem.clone(),
        };
        let asked = question(AGENT, &identity, testing::now() as u64, 1).unwrap();
        let got = ask(asked, config, Duration::from_secs(1))
            .await
            .unwrap_err();
        // However the client gives up, it is said, and never hangs.
        assert!(
            matches!(
                got,
                AskError::NoAnswer { .. } | AskError::ConnectionEnded | AskError::Refused(_)
            ),
            "{got:?}"
        );
    }

    proptest! {
        #[test]
        fn a_question_outlasts_the_wait_within_reason_and_never_passes_what_an_agent_takes(wait in 0u64..100_000) {
            let secs = validity_secs(wait);
            prop_assert!(secs <= MAX_QUESTION_VALIDITY_SECS);
            prop_assert!(secs >= 60);
            prop_assert!(secs >= wait.min(MAX_QUESTION_VALIDITY_SECS));
        }
    }

    const AGENT: &str = "jira-observer";
    const STAMP: &str = "jira-observer.polar.serviceaccount.cluster.local";

    fn asking() -> Asking {
        Asking {
            agent: AGENT.to_string(),
            id: "q1".to_string(),
        }
    }

    fn answer(id: &str, agent: &str) -> RunningConfiguration {
        RunningConfiguration {
            id: id.to_string(),
            agent: agent.to_string(),
            version: 3,
            settings: vec![],
            sections: vec![],
            build: polar_scheduler_common::running::RunningBuild {
                name: "a".to_string(),
                version: "1.0.0".to_string(),
                release: true,
                target: "t".to_string(),
            },
            at_unix_secs: 1,
        }
    }

    #[test]
    fn a_survey_listens_first_asks_everyone_and_hears_each_pod_of_each_agent_asked() {
        let s = Surveying {
            asked: HashMap::from([
                ("q1".to_string(), AGENT.to_string()),
                ("q2".to_string(), "kube-observer".to_string()),
            ]),
        };
        assert_eq!(
            s.on(ClientEvent::Registered {
                registration_id: "r".to_string()
            }),
            SurveyStep::Subscribe
        );
        assert_eq!(
            s.on(ClientEvent::ClientSubscribed {
                topic: ANSWERS_TOPIC.to_string()
            }),
            SurveyStep::AskAll
        );
        let stamp = |w: &str| format!("{w}.polar.serviceaccount.cluster.local");
        let mut from_a_pod = delivered(
            ANSWERS_TOPIC,
            encode_answer(&answer("q2", "kube-observer")).unwrap(),
            Some(&stamp("kube-observer")),
        );
        if let ClientEvent::MessagePublished {
            published_instance, ..
        } = &mut from_a_pod
        {
            *published_instance = Some(cassini_types::Instance {
                uid: "u1".to_string(),
                pod: Some("pod-1".to_string()),
            });
        }
        match s.on(from_a_pod) {
            SurveyStep::Heard(heard) => {
                assert_eq!(heard.agent, "kube-observer");
                assert_eq!(heard.instance.as_deref(), Some("u1"));
                assert_eq!(heard.pod.as_deref(), Some("pod-1"));
            }
            other => panic!("{other:?}"),
        }
        // An answer to a question not asked, one about another agent, or one another workload sent is not heard.
        for (id, agent, by) in [
            ("q9", AGENT, stamp(AGENT)),
            ("q1", "kube-observer", stamp("kube-observer")),
            ("q1", AGENT, stamp("kube-observer")),
        ] {
            let event = delivered(
                ANSWERS_TOPIC,
                encode_answer(&answer(id, agent)).unwrap(),
                Some(&by),
            );
            assert_eq!(s.on(event), SurveyStep::Nothing, "{id} {agent} {by}");
        }
        assert!(matches!(
            s.on(ClientEvent::SubscribeRefused {
                topic: ANSWERS_TOPIC.to_string(),
                reason: "no".to_string()
            }),
            SurveyStep::Failed(why) if why.contains("config-readers")
        ));
    }

    fn delivered(topic: &str, payload: Vec<u8>, stamp: Option<&str>) -> ClientEvent {
        ClientEvent::MessagePublished {
            topic: topic.to_string(),
            payload,
            trace_ctx: None,
            published_by: stamp.map(str::to_string),
            published_instance: None,
        }
    }

    #[test]
    fn it_listens_first_then_asks_then_takes_its_answer() {
        let a = asking();
        assert_eq!(
            a.on(ClientEvent::Registered {
                registration_id: "r".to_string()
            }),
            Step::Subscribe
        );
        assert_eq!(
            a.on(ClientEvent::ClientSubscribed {
                topic: ANSWERS_TOPIC.to_string()
            }),
            Step::Ask
        );
        let good = answer("q1", AGENT);
        assert_eq!(
            a.on(delivered(
                ANSWERS_TOPIC,
                encode_answer(&good).unwrap(),
                Some(STAMP)
            )),
            Step::Answered(Box::new(good))
        );
    }

    #[test]
    fn a_refusal_says_what_was_refused_and_what_would_admit_it() {
        for event in [
            ClientEvent::SubscribeRefused {
                topic: ANSWERS_TOPIC.to_string(),
                reason: "no".to_string(),
            },
            ClientEvent::PublishRefused {
                topic: QUESTIONS_TOPIC.to_string(),
                reason: "no".to_string(),
            },
        ] {
            let Step::Failed(why) = asking().on(event) else {
                panic!("a refusal is the end of it");
            };
            assert!(why.contains("policy.cedar"), "{why}");
            assert!(why.contains("config-readers"), "{why}");
        }
    }

    #[test]
    fn what_goes_by_on_other_topics_or_is_not_an_answer_is_ignored() {
        let a = asking();
        assert_eq!(
            a.on(ClientEvent::SubscribeRefused {
                topic: "other".to_string(),
                reason: "no".to_string()
            }),
            Step::Nothing
        );
        assert_eq!(
            a.on(delivered(ANSWERS_TOPIC, vec![1, 2, 3], Some(STAMP))),
            Step::Nothing
        );
        let good = encode_answer(&answer("q1", AGENT)).unwrap();
        assert_eq!(a.on(delivered("other", good, Some(STAMP))), Step::Nothing);
    }

    proptest! {
        /// An answer counts only if it answers this question, is about this agent, and the broker says that agent sent it:
        /// another agent, or anyone who may publish there, cannot speak for it.
        #[test]
        fn only_the_agent_asked_can_answer(
            right_id in any::<bool>(),
            right_agent in any::<bool>(),
            stamp in prop_oneof![
                Just(Some(STAMP)),
                Just(Some("kube-observer.polar.serviceaccount.cluster.local")),
                Just(Some("jira-observer")),
                Just(Some("d983a3d2-9b61-41c5-88a0-d123fb50ba33")),
                Just(None),
            ],
        ) {
            let a = answer(if right_id { "q1" } else { "q2" }, if right_agent { AGENT } else { "kube-observer" });
            let taken = is_the_answer(&a, "q1", AGENT, stamp);
            prop_assert_eq!(taken, right_id && right_agent && stamp == Some(STAMP));
        }
    }
}
