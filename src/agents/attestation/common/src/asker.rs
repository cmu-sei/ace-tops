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

//! How a vouching agent asks the attestation agent about an instance (docs/architecture/runtime-attestation.md, "Slice A, the askers"):
//! one actor in each asker, which the paths that issue ask and wait on. It answers [`Asked`], and it always answers: at once when
//! there is no Cassini session to ask over, or after [`ANSWER_WAIT`] when nothing comes back. A reply counts only from the attestation
//! agent's identity, as the broker stamped it, with the correlation id of a question still waiting.

use crate::protocol::{AGENT_NAME, Envelope, InstanceQuestion, decode_verdict, encode_question};
use crate::verdict::{NotGenuine, Verdict};
use cert_issuer_common::custody::custodian_of;
use cert_issuer_common::identity::workload_of;
use ractor::{Actor, ActorProcessingErr, ActorRef, RpcReplyPort};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// How long a question waits for its answer. A guess until a release build has been measured against it.
pub const ANSWER_WAIT: Duration = Duration::from_secs(2);

/// What asking came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asked {
    Genuine,
    NotGenuine(NotGenuine),
    /// Nothing was learned about the instance, and why.
    CouldNotAsk(NotAsked),
}

/// Why asking learned nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAsked {
    /// This agent has no Cassini session to ask over.
    NoSession,
    /// The question could not be handed to its Cassini client.
    NotPublished,
    /// Nothing came back in time.
    NoAnswer,
    /// The attestation agent answered that it cannot say yet.
    CannotSay,
    /// The asker itself is not running.
    NoAsker,
}

impl From<Verdict> for Asked {
    fn from(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Genuine => Asked::Genuine,
            Verdict::NotGenuine(why) => Asked::NotGenuine(why),
            Verdict::CannotSay => Asked::CouldNotAsk(NotAsked::CannotSay),
        }
    }
}

/// The attestation agent's identity in the asker's own namespace and domain, from the asker's own `<workload>.<namespace>.serviceaccount.
/// <domain>`. None for an identity that names no workload.
pub fn agent_identity(own_identity: &str) -> Option<String> {
    let workload = workload_of(own_identity)?;
    Some(format!("{AGENT_NAME}{}", &own_identity[workload.len()..]))
}

/// What is asked about for a certificate requested under `identity`, on the pod `pod_uid`. A custodian is asked about as the service it
/// keeps keys for, since it is that service's pod it runs in and that service the record names.
pub fn question_about(identity: &str, pod_uid: &str) -> InstanceQuestion {
    InstanceQuestion {
        identity: custodian_of(identity).unwrap_or(identity).to_string(),
        pod_uid: pod_uid.to_string(),
    }
}

/// The verdict in `payload`, if it is the attestation agent's: published, the broker says, by `agent`, and readable.
pub fn accepted(
    payload: &[u8],
    published_by: Option<&str>,
    agent: &str,
) -> Result<Envelope<Verdict>, String> {
    match published_by {
        Some(who) if who == agent => decode_verdict(payload),
        Some(who) => Err(format!("{who} answered for the attestation agent")),
        None => Err("an answer with no verified publisher".to_string()),
    }
}

/// Hands a question's bytes to this agent's Cassini client.
pub type Publish = Arc<dyn Fn(Vec<u8>) -> Result<(), String> + Send + Sync>;

pub enum InstanceAskerMessage {
    Ask {
        question: InstanceQuestion,
        reply: RpcReplyPort<Asked>,
    },
    /// Something arrived on this agent's reply topic, published (the broker says) by `published_by`.
    Answered {
        payload: Vec<u8>,
        published_by: Option<String>,
    },
    /// The Cassini session is up: questions go by `publish`, and answers count from `agent`.
    SessionUp { publish: Publish, agent: String },
    /// The Cassini session is gone: what waits is told so, and so is what is asked until it is back.
    SessionDown,
    /// The question `correlation_id` has waited long enough.
    Expired { correlation_id: String },
}

pub struct InstanceAskerArgs {
    pub wait: Duration,
}

struct Session {
    publish: Publish,
    agent: String,
}

pub struct InstanceAskerState {
    wait: Duration,
    session: Option<Session>,
    waiting: HashMap<String, RpcReplyPort<Asked>>,
}

impl InstanceAskerState {
    fn answer(&mut self, correlation_id: &str, asked: Asked) {
        if let Some(reply) = self.waiting.remove(correlation_id) {
            // The one who asked may have gone, and then nobody is waiting.
            let _ = reply.send(asked);
        }
    }
}

pub struct InstanceAsker;

#[ractor::async_trait]
impl Actor for InstanceAsker {
    type Msg = InstanceAskerMessage;
    type State = InstanceAskerState;
    type Arguments = InstanceAskerArgs;

    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        args: InstanceAskerArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(InstanceAskerState {
            wait: args.wait,
            session: None,
            waiting: HashMap::new(),
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            InstanceAskerMessage::Ask { question, reply } => {
                let Some(session) = &state.session else {
                    let _ = reply.send(Asked::CouldNotAsk(NotAsked::NoSession));
                    return Ok(());
                };
                let correlation_id = format!("{:032x}", rand::random::<u128>());
                let bytes = encode_question(&Envelope {
                    correlation_id: correlation_id.clone(),
                    payload: question,
                });
                if let Err(why) = (session.publish)(bytes) {
                    warn!("a question about an instance was not published: {why}");
                    let _ = reply.send(Asked::CouldNotAsk(NotAsked::NotPublished));
                    return Ok(());
                }
                state.waiting.insert(correlation_id.clone(), reply);
                // Dropping the handle detaches the timer; it still fires.
                drop(
                    myself.send_after(state.wait, move || InstanceAskerMessage::Expired {
                        correlation_id,
                    }),
                );
            }
            InstanceAskerMessage::Answered {
                payload,
                published_by,
            } => {
                let Some(session) = &state.session else {
                    return Ok(());
                };
                match accepted(&payload, published_by.as_deref(), &session.agent) {
                    Ok(envelope) => {
                        state.answer(&envelope.correlation_id, envelope.payload.into());
                    }
                    Err(why) => warn!("not taken as a verdict: {why}"),
                }
            }
            InstanceAskerMessage::SessionUp { publish, agent } => {
                state.session = Some(Session { publish, agent });
            }
            InstanceAskerMessage::SessionDown => {
                state.session = None;
                for (_, reply) in state.waiting.drain() {
                    let _ = reply.send(Asked::CouldNotAsk(NotAsked::NoSession));
                }
            }
            InstanceAskerMessage::Expired { correlation_id } => {
                state.answer(&correlation_id, Asked::CouldNotAsk(NotAsked::NoAnswer));
            }
        }
        Ok(())
    }
}

/// Asks `asker` about `question`. It answers every question it takes, so this does not time out of its own.
pub async fn ask(asker: &ActorRef<InstanceAskerMessage>, question: InstanceQuestion) -> Asked {
    ractor::call!(asker, |reply| InstanceAskerMessage::Ask { question, reply })
        .unwrap_or(Asked::CouldNotAsk(NotAsked::NoAsker))
}

/// The instance check: it asks, says what it was told, and gives it back for the asker to act on (docs/architecture/runtime-attestation.md,
/// "Slice A, the askers"). `path` says which way into issuance asked.
pub async fn check(
    asker: Option<&ActorRef<InstanceAskerMessage>>,
    path: &'static str,
    identity: &str,
    pod_uid: &str,
) -> Asked {
    let question = question_about(identity, pod_uid);
    let started = Instant::now();
    let asked = match asker {
        Some(asker) => ask(asker, question).await,
        None => Asked::CouldNotAsk(NotAsked::NoAsker),
    };
    let elapsed_ms = started.elapsed().as_millis() as u64;
    match &asked {
        Asked::Genuine => {
            debug!(
                path,
                identity, pod_uid, elapsed_ms, "instance check: genuine"
            );
        }
        Asked::NotGenuine(why) => {
            warn!(
                path,
                identity, pod_uid, elapsed_ms, "instance check: NOT GENUINE, refused: {why:?}"
            );
        }
        Asked::CouldNotAsk(why) => {
            info!(
                path,
                identity,
                pod_uid,
                elapsed_ms,
                "instance check: could not ask, so it goes ahead unattested: {why:?}"
            );
        }
    }
    asked
}

/// A running asker for tests of those who ask, answering every question with `verdict` as the attestation agent, and what it was asked.
#[cfg(feature = "testing")]
pub mod testing {
    use super::*;
    use crate::protocol::{decode_question, encode_verdict};
    use std::sync::Mutex;

    const AGENT: &str = "attestation-agent.polar.serviceaccount.cluster.local";

    pub async fn answering(
        verdict: Verdict,
    ) -> (
        ActorRef<InstanceAskerMessage>,
        Arc<Mutex<Vec<InstanceQuestion>>>,
    ) {
        let (asker, _) = Actor::spawn(
            None,
            InstanceAsker,
            InstanceAskerArgs {
                wait: Duration::from_secs(30),
            },
        )
        .await
        .expect("the asker starts");
        let asked = Arc::new(Mutex::new(Vec::new()));
        let publish: Publish = {
            let (asked, asker) = (asked.clone(), asker.clone());
            Arc::new(move |bytes| {
                let question = decode_question(&bytes)?;
                asked.lock().unwrap().push(question.payload);
                let reply = Envelope {
                    correlation_id: question.correlation_id,
                    payload: verdict.clone(),
                };
                asker
                    .send_message(InstanceAskerMessage::Answered {
                        payload: encode_verdict(&reply),
                        published_by: Some(AGENT.to_string()),
                    })
                    .map_err(|e| e.to_string())
            })
        };
        asker
            .send_message(InstanceAskerMessage::SessionUp {
                publish,
                agent: AGENT.to_string(),
            })
            .expect("the asker is running");
        (asker, asked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{decode_question, encode_verdict};
    use proptest::prelude::*;
    use std::sync::Mutex;

    const AGENT: &str = "attestation-agent.polar.serviceaccount.cluster.local";
    const LONG: Duration = Duration::from_secs(600);

    fn question() -> InstanceQuestion {
        question_about("the-app.polar.serviceaccount.cluster.local", "uid-1")
    }

    async fn asker(wait: Duration) -> ActorRef<InstanceAskerMessage> {
        Actor::spawn(None, InstanceAsker, InstanceAskerArgs { wait })
            .await
            .unwrap()
            .0
    }

    /// An asker in session, and the envelopes it publishes.
    async fn in_session(
        wait: Duration,
    ) -> (
        ActorRef<InstanceAskerMessage>,
        Arc<Mutex<Vec<Envelope<InstanceQuestion>>>>,
    ) {
        let asker = asker(wait).await;
        let published = Arc::new(Mutex::new(Vec::new()));
        let publish: Publish = {
            let published = published.clone();
            Arc::new(move |bytes| {
                published.lock().unwrap().push(decode_question(&bytes)?);
                Ok(())
            })
        };
        asker
            .send_message(InstanceAskerMessage::SessionUp {
                publish,
                agent: AGENT.to_string(),
            })
            .unwrap();
        (asker, published)
    }

    /// Asks, in the background, and waits for the question to be published: its correlation id.
    async fn asked(
        asker: &ActorRef<InstanceAskerMessage>,
        published: &Arc<Mutex<Vec<Envelope<InstanceQuestion>>>>,
    ) -> (tokio::task::JoinHandle<Asked>, String) {
        let before = published.lock().unwrap().len();
        let waiting = tokio::spawn({
            let asker = asker.clone();
            async move { ask(&asker, question()).await }
        });
        loop {
            if let Some(envelope) = published.lock().unwrap().get(before) {
                return (waiting, envelope.correlation_id.clone());
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    fn verdict(correlation_id: &str, verdict: Verdict) -> Vec<u8> {
        encode_verdict(&Envelope {
            correlation_id: correlation_id.to_string(),
            payload: verdict,
        })
    }

    fn answered(payload: Vec<u8>, by: Option<&str>) -> InstanceAskerMessage {
        InstanceAskerMessage::Answered {
            payload,
            published_by: by.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn the_attestation_agents_verdict_is_what_asking_comes_to() {
        for (said, comes_to) in [
            (Verdict::Genuine, Asked::Genuine),
            (
                Verdict::NotGenuine(NotGenuine::NoOwner),
                Asked::NotGenuine(NotGenuine::NoOwner),
            ),
            (Verdict::CannotSay, Asked::CouldNotAsk(NotAsked::CannotSay)),
        ] {
            let (asker, published) = in_session(LONG).await;
            let (waiting, id) = asked(&asker, &published).await;
            asker
                .send_message(answered(verdict(&id, said), Some(AGENT)))
                .unwrap();
            assert_eq!(waiting.await.unwrap(), comes_to);
        }
    }

    // The bring-up's case: with no session there is nothing to wait for.
    #[tokio::test]
    async fn with_no_session_it_answers_at_once() {
        let asker = asker(LONG).await;
        let asking = ask(&asker, question());
        let told = tokio::time::timeout(Duration::from_secs(5), asking).await;
        assert_eq!(told.unwrap(), Asked::CouldNotAsk(NotAsked::NoSession));
    }

    #[tokio::test]
    async fn a_session_lost_answers_what_waits_at_once_and_what_is_asked_after() {
        let (asker, published) = in_session(LONG).await;
        let (waiting, _) = asked(&asker, &published).await;
        asker
            .send_message(InstanceAskerMessage::SessionDown)
            .unwrap();
        let told = tokio::time::timeout(Duration::from_secs(5), waiting).await;
        assert_eq!(
            told.unwrap().unwrap(),
            Asked::CouldNotAsk(NotAsked::NoSession)
        );
        assert_eq!(
            ask(&asker, question()).await,
            Asked::CouldNotAsk(NotAsked::NoSession)
        );
    }

    #[tokio::test]
    async fn nothing_coming_back_ends_at_the_wait() {
        let (asker, _published) = in_session(Duration::from_millis(50)).await;
        let started = Instant::now();
        assert_eq!(
            ask(&asker, question()).await,
            Asked::CouldNotAsk(NotAsked::NoAnswer)
        );
        assert!(started.elapsed() >= Duration::from_millis(50));
    }

    #[tokio::test]
    async fn a_question_that_could_not_be_published_waits_for_nothing() {
        let asker = asker(LONG).await;
        asker
            .send_message(InstanceAskerMessage::SessionUp {
                publish: Arc::new(|_| Err("no client".to_string())),
                agent: AGENT.to_string(),
            })
            .unwrap();
        let told = tokio::time::timeout(Duration::from_secs(5), ask(&asker, question())).await;
        assert_eq!(told.unwrap(), Asked::CouldNotAsk(NotAsked::NotPublished));
    }

    // A verdict is taken only from the attestation agent, and only for the question it answers: anyone else's, on the same topic, is not
    // an answer, and the question goes on waiting for the real one.
    #[tokio::test]
    async fn only_the_agents_answer_to_this_question_is_taken() {
        let (asker, published) = in_session(LONG).await;
        let (waiting, id) = asked(&asker, &published).await;
        for wrong in [
            answered(
                verdict(&id, Verdict::Genuine),
                Some("cassini.polar.serviceaccount.cluster.local"),
            ),
            answered(verdict(&id, Verdict::Genuine), None),
            answered(verdict("another-question", Verdict::Genuine), Some(AGENT)),
            answered(b"not a verdict".to_vec(), Some(AGENT)),
        ] {
            asker.send_message(wrong).unwrap();
        }
        // A question answered after them: the actor has handled them all by the time it comes back.
        let (after, after_id) = asked(&asker, &published).await;
        asker
            .send_message(answered(verdict(&after_id, Verdict::Genuine), Some(AGENT)))
            .unwrap();
        after.await.unwrap();
        assert!(!waiting.is_finished(), "something else answered it");
        asker
            .send_message(answered(
                verdict(&id, Verdict::NotGenuine(NotGenuine::NoOwner)),
                Some(AGENT),
            ))
            .unwrap();
        assert_eq!(
            waiting.await.unwrap(),
            Asked::NotGenuine(NotGenuine::NoOwner)
        );
    }

    #[tokio::test]
    async fn an_asker_that_is_gone_is_a_question_not_asked() {
        let asker = asker(LONG).await;
        asker.stop(None);
        while asker.get_status() != ractor::ActorStatus::Stopped {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(
            ask(&asker, question()).await,
            Asked::CouldNotAsk(NotAsked::NoAsker)
        );
    }

    #[tokio::test]
    async fn each_question_has_its_own_correlation_id() {
        let (asker, published) = in_session(LONG).await;
        let (_first, one) = asked(&asker, &published).await;
        let (_second, two) = asked(&asker, &published).await;
        assert_ne!(one, two);
    }

    #[test]
    fn a_custodian_is_asked_about_as_its_service() {
        let service = "the-app.polar.serviceaccount.cluster.local";
        let custodian = cert_issuer_common::custody::custodian_identity(service);
        assert_eq!(question_about(&custodian, "p").identity, service);
        assert_eq!(question_about(service, "p").identity, service);
        assert_eq!(question_about(service, "p").pod_uid, "p");
    }

    #[test]
    fn the_agent_is_found_in_the_askers_own_namespace_and_domain() {
        assert_eq!(
            agent_identity("cert-issuer.polar.serviceaccount.cluster.local").as_deref(),
            Some(AGENT)
        );
        assert_eq!(
            agent_identity("credentials-agent.other.serviceaccount.example.org").as_deref(),
            Some("attestation-agent.other.serviceaccount.example.org")
        );
        assert_eq!(agent_identity("2f0c6a1e-alice"), None);
    }

    fn any_verdict() -> impl Strategy<Value = Verdict> {
        prop_oneof![
            Just(Verdict::Genuine),
            Just(Verdict::CannotSay),
            Just(Verdict::NotGenuine(NotGenuine::NoSuchPod)),
            "\\PC{0,12}".prop_map(|container| Verdict::NotGenuine(
                NotGenuine::EphemeralContainer { container }
            )),
        ]
    }

    proptest! {
        // Whatever the bytes say, nobody but the agent is taken, and an unverified publisher never is.
        #[test]
        fn nobody_but_the_agent_is_taken(
            id in "\\PC{0,24}",
            said in any_verdict(),
            who in proptest::option::of("\\PC{0,40}"),
        ) {
            prop_assume!(who.as_deref() != Some(AGENT));
            prop_assert!(accepted(&verdict(&id, said), who.as_deref(), AGENT).is_err());
        }

        // What the agent says is taken as it said it.
        #[test]
        fn the_agents_verdict_is_taken_as_it_said_it(id in "\\PC{0,24}", said in any_verdict()) {
            let taken = accepted(&verdict(&id, said.clone()), Some(AGENT), AGENT).unwrap();
            prop_assert_eq!(taken.correlation_id, id);
            prop_assert_eq!(taken.payload, said);
        }

        // Bytes that are not a verdict are refused, whoever sent them, and never read as one.
        #[test]
        fn bytes_from_the_agent_that_are_no_verdict_do_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let _ = accepted(&bytes, Some(AGENT), AGENT);
        }

        // Asking comes to CouldNotAsk only for what says nothing about the pod: a verdict of either kind is never lost to it.
        #[test]
        fn a_verdict_is_never_turned_into_could_not_ask(said in any_verdict()) {
            let asked: Asked = said.clone().into();
            prop_assert_eq!(
                matches!(asked, Asked::CouldNotAsk(_)),
                said == Verdict::CannotSay
            );
        }
    }
}
