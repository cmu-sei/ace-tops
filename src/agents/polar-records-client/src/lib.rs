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

//! A person's tools asking the store over Cassini (docs/architecture/record-store.md, "People's tools over Cassini"):
//! adding a signed evidence record, putting a signed section of polar-schedules at its place, and reading a log's
//! leaves. Each connects with the person's own certificate, as `polar-running-config` does, listens on the answer topic
//! addressed to them (which Cedar lets nobody else hear), sends the request, and takes only the store's answer to it, by
//! its correlation id and the identity the broker stamped on it.

use cassini_client::{
    ClientEventForwarder, ClientEventForwarderArgs, DeliveryMode, TCPClientConfig, TcpClientActor,
    TcpClientArgs, TcpClientMessage,
};
use cassini_types::ClientEvent;
use polar_git_server_common::{
    AddRecord, AddSection, EVIDENCE_REQUESTS_TOPIC, Envelope, LOG_READ_REQUESTS_TOPIC, LogRead,
    ReadLog, RecordAdded, SCHEDULES_REQUESTS_TOPIC, SectionAdded, decode_added, decode_log_read,
    decode_section_added, encode_add, encode_add_section, encode_read_log, evidence_replies_topic,
    log_read_replies_topic, schedules_replies_topic,
};
use ractor::{Actor, ActorProcessingErr, ActorRef};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

pub use polar_running_config::client_config;

/// The workload whose answers are taken.
const STORE: &str = "polar-git-server";

/// The broker's name in the cluster, on its certificate, as the tools reach it through a forward.
pub const BROKER_NAME: &str = "cassini-ip-svc.polar.svc.cluster.local";

/// The identity in a person's certificate (`<dir>/<user>.crt`): what the broker stamps, and what their answers are
/// addressed to.
pub fn identity_of(dir: &Path, user: &str) -> Result<String, String> {
    let file = dir.join(format!("{user}.crt"));
    let pem = std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
    cert_issuer_common::permission::extract_own_identity(&pem).map_err(|e| e.to_string())
}

/// Whether an answer's bytes answer a request.
pub type Answers = Box<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// One request and where its answer comes: the topic it is sent on, the one addressed to the asker it is answered on,
/// its bytes, and how to tell its answer.
pub struct Exchange {
    pub request_topic: String,
    pub reply_topic: String,
    pub payload: Vec<u8>,
    /// The answer's bytes, when they answer this request.
    pub answers: Answers,
}

/// What to do next.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    Nothing,
    /// Listen first, so the answer cannot go by before anyone hears it.
    Subscribe,
    Send,
    Answered(Vec<u8>),
    Failed(String),
}

impl Exchange {
    /// What `event` from the broker means for this exchange.
    pub fn on(&self, event: ClientEvent) -> Step {
        match event {
            // Again after a reconnection: a new session holds no subscription.
            ClientEvent::Registered { .. } => Step::Subscribe,
            ClientEvent::ClientSubscribed { topic } if topic == self.reply_topic => Step::Send,
            ClientEvent::SubscribeRefused { topic, reason } if topic == self.reply_topic => {
                Step::Failed(format!(
                    "the broker refused to let you hear {topic}: {reason}. A person hears what is addressed to them by the \
                 first policy's rule (infra/seeds/signed/policy.cedar)"
                ))
            }
            ClientEvent::PublishRefused { topic, reason } if topic == self.request_topic => {
                Step::Failed(format!(
                    "the broker refused to let you send on {topic}: {reason}"
                ))
            }
            ClientEvent::PublishDropped { topic, reason }
            | ClientEvent::PublishDeferred { topic, reason }
                if topic == self.request_topic =>
            {
                Step::Failed(format!(
                    "the broker could not take the request now: {reason}. Try again"
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
            } if topic == self.reply_topic => {
                let from_the_store = published_by
                    .as_deref()
                    .and_then(cert_issuer_common::identity::workload_of)
                    == Some(STORE);
                if from_the_store && (self.answers)(&payload) {
                    Step::Answered(payload)
                } else {
                    Step::Nothing
                }
            }
            _ => Step::Nothing,
        }
    }
}

struct Asker;

struct AskerArgs {
    exchange: Exchange,
    config: TCPClientConfig,
    done: oneshot::Sender<Result<Vec<u8>, String>>,
}

struct AskerState {
    exchange: Exchange,
    client: ActorRef<TcpClientMessage>,
    done: Option<oneshot::Sender<Result<Vec<u8>, String>>>,
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
            exchange: args.exchange,
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
        match state.exchange.on(event) {
            Step::Nothing => {}
            Step::Subscribe => state.client.send_message(TcpClientMessage::Subscribe {
                topic: state.exchange.reply_topic.clone(),
                trace_ctx: None,
            })?,
            Step::Send => state.client.send_message(TcpClientMessage::publish(
                state.exchange.request_topic.clone(),
                state.exchange.payload.clone(),
                None,
            ))?,
            Step::Answered(answer) => {
                if let Some(done) = state.done.take() {
                    let _ = done.send(Ok(answer));
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

/// Connects with `config`, makes `exchange`, and waits up to `wait` for its answer: the answer's bytes.
pub async fn exchange(
    exchange: Exchange,
    config: TCPClientConfig,
    wait: Duration,
) -> Result<Vec<u8>, String> {
    let (done, answered) = oneshot::channel();
    let topic = exchange.request_topic.clone();
    let (asker, _handle) = Actor::spawn(
        None,
        Asker,
        AskerArgs {
            exchange,
            config,
            done,
        },
    )
    .await
    .map_err(|e| format!("cannot start: {e}"))?;
    let outcome = tokio::time::timeout(wait, answered).await;
    asker.stop(None);
    match outcome {
        Ok(Ok(answer)) => answer,
        Ok(Err(_)) => Err("the connection to the broker ended before an answer".to_string()),
        Err(_) => Err(format!(
            "no answer to {topic} from the store in {} s: is the broker reachable (`just port-forwards-up broker`)?",
            wait.as_secs()
        )),
    }
}

fn correlation() -> String {
    format!("person-{}", uuid::Uuid::new_v4())
}

/// The exchange that adds the signed evidence `record`, for the person `identity`.
pub fn add_record_exchange(identity: &str, record: &str) -> (Exchange, String) {
    let id = correlation();
    let payload = encode_add(&Envelope {
        correlation_id: id.clone(),
        payload: AddRecord {
            record: record.to_string(),
        },
    });
    let wanted = id.clone();
    (
        Exchange {
            request_topic: EVIDENCE_REQUESTS_TOPIC.to_string(),
            reply_topic: evidence_replies_topic(identity),
            payload,
            answers: Box::new(move |bytes| {
                decode_added(bytes).is_ok_and(|a| a.correlation_id == wanted)
            }),
        },
        id,
    )
}

/// The exchange that puts the signed section `content` at `path` in polar-schedules, for the person `identity`.
pub fn add_section_exchange(identity: &str, path: &str, content: &[u8]) -> (Exchange, String) {
    let id = correlation();
    let payload = encode_add_section(&Envelope {
        correlation_id: id.clone(),
        payload: AddSection {
            path: path.to_string(),
            content: content.to_vec(),
        },
    });
    let wanted = id.clone();
    (
        Exchange {
            request_topic: SCHEDULES_REQUESTS_TOPIC.to_string(),
            reply_topic: schedules_replies_topic(identity),
            payload,
            answers: Box::new(move |bytes| {
                decode_section_added(bytes).is_ok_and(|a| a.correlation_id == wanted)
            }),
        },
        id,
    )
}

/// The exchange that reads `log`'s leaves from `from`, for the person `identity`.
pub fn read_log_exchange(identity: &str, log: &str, from: u64) -> (Exchange, String) {
    let id = correlation();
    let payload = encode_read_log(&Envelope {
        correlation_id: id.clone(),
        payload: ReadLog {
            log: log.to_string(),
            from,
        },
    });
    let wanted = id.clone();
    (
        Exchange {
            request_topic: LOG_READ_REQUESTS_TOPIC.to_string(),
            reply_topic: log_read_replies_topic(identity),
            payload,
            answers: Box::new(move |bytes| {
                decode_log_read(bytes).is_ok_and(|a| a.correlation_id == wanted)
            }),
        },
        id,
    )
}

/// Adds a signed evidence record over Cassini.
pub async fn add_record(
    config: TCPClientConfig,
    identity: &str,
    record: &str,
    wait: Duration,
) -> Result<RecordAdded, String> {
    let (asked, _) = add_record_exchange(identity, record);
    decode_added(&exchange(asked, config, wait).await?).map(|a| a.payload)
}

/// Puts a signed section of polar-schedules at its place over Cassini.
pub async fn add_section(
    config: TCPClientConfig,
    identity: &str,
    path: &str,
    content: &[u8],
    wait: Duration,
) -> Result<SectionAdded, String> {
    let (asked, _) = add_section_exchange(identity, path, content);
    decode_section_added(&exchange(asked, config, wait).await?).map(|a| a.payload)
}

/// Reads a log's leaves from `from` over Cassini.
pub async fn read_log(
    config: TCPClientConfig,
    identity: &str,
    log: &str,
    from: u64,
    wait: Duration,
) -> Result<LogRead, String> {
    let (asked, _) = read_log_exchange(identity, log, from);
    decode_log_read(&exchange(asked, config, wait).await?).map(|a| a.payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_git_server_common::{encode_added, encode_section_added};

    const ALICE: &str = "0a11ce00-0000-4000-8000-000000000001";
    const STORE_IDENTITY: &str = "polar-git-server.polar.serviceaccount.cluster.local";

    fn published(topic: &str, payload: Vec<u8>, by: Option<&str>) -> ClientEvent {
        ClientEvent::MessagePublished {
            topic: topic.to_string(),
            payload,
            published_by: by.map(str::to_string),
            trace_ctx: None,
            published_instance: None,
        }
    }

    /// It listens on the topic addressed to the asker before it sends, and sends once that is heard; a refusal to
    /// listen or to send ends it with why.
    #[test]
    fn it_listens_on_its_own_topic_then_sends_and_a_refusal_ends_it() {
        let (asked, _) = add_section_exchange(ALICE, "permanent/a/configuration.dhall", b"x");
        assert_eq!(
            asked.reply_topic,
            format!("polar-schedules-replies.{ALICE}")
        );
        assert_eq!(asked.request_topic, SCHEDULES_REQUESTS_TOPIC);
        assert_eq!(
            asked.on(ClientEvent::Registered {
                registration_id: "r".into()
            }),
            Step::Subscribe
        );
        assert_eq!(
            asked.on(ClientEvent::ClientSubscribed {
                topic: asked.reply_topic.clone()
            }),
            Step::Send
        );
        assert_eq!(
            asked.on(ClientEvent::ClientSubscribed {
                topic: "another".into()
            }),
            Step::Nothing
        );
        assert!(matches!(
            asked.on(ClientEvent::SubscribeRefused { topic: asked.reply_topic.clone(), reason: "no".into() }),
            Step::Failed(why) if why.contains("addressed to them")
        ));
        assert!(matches!(
            asked.on(ClientEvent::PublishRefused {
                topic: SCHEDULES_REQUESTS_TOPIC.into(),
                reason: "no".into()
            }),
            Step::Failed(_)
        ));
    }

    /// Only the store's answer to this request is taken: another's correlation id, another sender, or none, is not.
    #[test]
    fn only_the_store_s_answer_to_this_request_is_taken() {
        let (asked, id) = add_record_exchange(ALICE, "{}");
        let answer = |correlation_id: &str| {
            encode_added(&Envelope {
                correlation_id: correlation_id.to_string(),
                payload: RecordAdded::AlreadyThere { path: "p".into() },
            })
        };
        let topic = asked.reply_topic.clone();
        assert_eq!(
            asked.on(published(&topic, answer(&id), Some(STORE_IDENTITY))),
            Step::Answered(answer(&id))
        );
        assert_eq!(
            asked.on(published(&topic, answer("another"), Some(STORE_IDENTITY))),
            Step::Nothing
        );
        assert_eq!(
            asked.on(published(
                &topic,
                answer(&id),
                Some("attestation-agent.polar.serviceaccount.cluster.local")
            )),
            Step::Nothing
        );
        assert_eq!(
            asked.on(published(&topic, answer(&id), None)),
            Step::Nothing
        );
        assert_eq!(
            asked.on(published("elsewhere", answer(&id), Some(STORE_IDENTITY))),
            Step::Nothing
        );
        // A section's answer is not a record's.
        let section = encode_section_added(&Envelope {
            correlation_id: id.clone(),
            payload: SectionAdded::AlreadyThere,
        });
        assert_eq!(
            asked.on(published(&topic, section, Some(STORE_IDENTITY))),
            Step::Nothing
        );
    }

    #[test]
    fn each_request_is_on_the_store_s_topic_and_answered_on_one_addressed_to_the_asker() {
        let (record, _) = add_record_exchange(ALICE, "{}");
        let (read, _) = read_log_exchange(ALICE, "schedules", 0);
        assert_eq!(
            (record.request_topic.as_str(), record.reply_topic.as_str()),
            (
                EVIDENCE_REQUESTS_TOPIC,
                format!("polar-git-evidence-replies.{ALICE}").as_str()
            )
        );
        assert_eq!(
            (read.request_topic.as_str(), read.reply_topic.as_str()),
            (
                LOG_READ_REQUESTS_TOPIC,
                format!("polar-log-read-replies.{ALICE}").as_str()
            )
        );
        let (_, a) = read_log_exchange(ALICE, "schedules", 0);
        let (_, b) = read_log_exchange(ALICE, "schedules", 0);
        assert_ne!(a, b, "each request its own correlation id");
    }
}
