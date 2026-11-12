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

//! Reading Polar's git server over Cassini (docs/architecture/git-server.md, "Reads over Cassini"; runtime-attestation.md,
//! slice C, C2, O2): the observer asks what a repository's `main` holds on `polar-git-read-requests` and is answered on its
//! own topic, so it runs no `git` and holds no key to reach the server. Only an answer the git server published is taken;
//! what is read is believed for nothing, since what reads it checks what it is (the agents verify every document).

use cassini_client::TcpClientMessage;
use polar::request_reply::{Envelope, ReplyRouter};
use polar_agent_builder::Subscription;
use polar_git_server_common::{
    MainRead, READ_REQUESTS_TOPIC, ReadMain, SCHEDULER_OBSERVER_READ_REPLIES_TOPIC,
    decode_main_read, encode_read,
};
use ractor::ActorRef;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::warn;

/// How long an answer is waited for: the server reads in process, so one that has not answered by then is not up.
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The workload whose answers are taken.
const GIT_SERVER: &str = "polar-git-server";

/// What a repository's `main` holds, asked of whoever answers.
#[ractor::async_trait]
pub trait ReadsMain: Send + Sync {
    /// The files of `repo`'s `main` under `paths` (none: every file), unless it is still the commit `have`; or why the
    /// asking failed (nothing answered in time, or the request could not be sent).
    async fn read_main(
        &self,
        repo: &str,
        paths: &[String],
        have: Option<&str>,
    ) -> Result<MainRead, String>;
}

/// The git server, asked over Cassini.
pub struct ServerReads {
    client: ActorRef<TcpClientMessage>,
    router: Arc<ReplyRouter<MainRead>>,
    timeout: Duration,
}

impl ServerReads {
    pub fn new(
        client: ActorRef<TcpClientMessage>,
        router: Arc<ReplyRouter<MainRead>>,
        timeout: Duration,
    ) -> Self {
        Self {
            client,
            router,
            timeout,
        }
    }
}

/// Tells one request from another within this process.
static ASKED: AtomicU64 = AtomicU64::new(0);

#[ractor::async_trait]
impl ReadsMain for ServerReads {
    async fn read_main(
        &self,
        repo: &str,
        paths: &[String],
        have: Option<&str>,
    ) -> Result<MainRead, String> {
        let correlation_id = format!(
            "read-{}-{}",
            std::process::id(),
            ASKED.fetch_add(1, Ordering::Relaxed)
        );
        let request = encode_read(&Envelope {
            correlation_id: correlation_id.clone(),
            payload: ReadMain {
                repo: repo.to_string(),
                paths: paths.to_vec(),
                have: have.map(str::to_string),
            },
        });
        let client = self.client.clone();
        self.router
            .register_with_timeout(correlation_id, self.timeout, move || {
                client
                    .send_message(TcpClientMessage::publish(
                        READ_REQUESTS_TOPIC.to_string(),
                        request,
                        None,
                    ))
                    .map_err(|e| e.to_string())
            })
            .await
            .map_err(|e| format!("reading {repo} from the git server: {e}"))
    }
}

/// The subscription to the observer's own answers, each handed to whichever read is waiting for it.
pub fn replies_subscription(router: Arc<ReplyRouter<MainRead>>) -> Subscription {
    Subscription::new(SCHEDULER_OBSERVER_READ_REPLIES_TOPIC, move |incoming| {
        on_reply(&router, incoming.published_by.as_deref(), &incoming.payload)
    })
}

/// Hands an answer to the read waiting for it: only one the git server published, as the broker stamped it, and only one
/// that is an answer. Anything else is dropped with a warning.
pub fn on_reply(router: &ReplyRouter<MainRead>, published_by: Option<&str>, payload: &[u8]) {
    if published_by.and_then(workload_of) != Some(GIT_SERVER) {
        warn!(
            published_by,
            "dropped an answer to a read that the git server did not publish"
        );
        return;
    }
    match decode_main_read(payload) {
        Ok(answer) => router.deliver(&answer.correlation_id, answer.payload),
        Err(why) => warn!("dropped an answer to a read: {why}"),
    }
}

/// The workload a workload identity names: `<workload>.<namespace>.serviceaccount.<domain>`.
fn workload_of(identity: &str) -> Option<&str> {
    let (workload, rest) = identity.split_once('.')?;
    let (namespace, rest) = rest.split_once('.')?;
    let domain = rest.strip_prefix("serviceaccount.")?;
    (!workload.is_empty() && !namespace.is_empty() && !domain.is_empty()).then_some(workload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_git_server_common::{decode_read, encode_main_read};
    use ractor::{Actor, ActorProcessingErr};
    use std::sync::Mutex;

    const SERVER: &str = "polar-git-server.polar.serviceaccount.cluster.local";

    /// What was published, by topic.
    type Sent = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    /// A Cassini client that keeps what it is asked to publish, and answers as the server would, through the router.
    struct Client;

    struct ClientState {
        sent: Sent,
        answer: Option<(Arc<ReplyRouter<MainRead>>, MainRead)>,
    }

    #[ractor::async_trait]
    impl Actor for Client {
        type Msg = TcpClientMessage;
        type State = ClientState;
        type Arguments = ClientState;
        async fn pre_start(
            &self,
            _: ActorRef<Self::Msg>,
            state: ClientState,
        ) -> Result<ClientState, ActorProcessingErr> {
            Ok(state)
        }
        async fn handle(
            &self,
            _: ActorRef<Self::Msg>,
            message: Self::Msg,
            state: &mut ClientState,
        ) -> Result<(), ActorProcessingErr> {
            if let TcpClientMessage::Publish { topic, payload, .. } = message {
                state.sent.lock().unwrap().push((topic, payload.clone()));
                if let Some((router, answer)) = &state.answer {
                    let asked = decode_read(&payload).unwrap();
                    let reply = encode_main_read(&Envelope {
                        correlation_id: asked.correlation_id,
                        payload: answer.clone(),
                    });
                    on_reply(router, Some(SERVER), &reply);
                }
            }
            Ok(())
        }
    }

    async fn reads(answer: Option<MainRead>, timeout: Duration) -> (ServerReads, Sent) {
        let router = Arc::new(ReplyRouter::new());
        let sent = Arc::new(Mutex::new(Vec::new()));
        let (client, _) = Actor::spawn(
            None,
            Client,
            ClientState {
                sent: sent.clone(),
                answer: answer.map(|a| (router.clone(), a)),
            },
        )
        .await
        .unwrap();
        (ServerReads::new(client, router, timeout), sent)
    }

    /// A read is published on the request topic as asked, and what the server answers to its correlation id is the answer.
    #[tokio::test]
    async fn a_read_is_asked_on_the_request_topic_and_answered_by_its_reply() {
        let answer = MainRead::Unchanged {
            commit: "c".repeat(40),
        };
        let (reads, sent) = reads(Some(answer.clone()), READ_TIMEOUT).await;
        let got = reads
            .read_main("polar-schedules", &["permanent".to_string()], Some("abc"))
            .await
            .unwrap();
        assert_eq!(got, answer);
        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, READ_REQUESTS_TOPIC);
        let asked = decode_read(&sent[0].1).unwrap().payload;
        assert_eq!(
            asked,
            ReadMain {
                repo: "polar-schedules".into(),
                paths: vec!["permanent".into()],
                have: Some("abc".into()),
            }
        );
    }

    #[tokio::test]
    async fn a_read_nobody_answers_fails_in_its_time() {
        let (reads, _) = reads(None, Duration::from_millis(50)).await;
        let failed = reads
            .read_main("polar-schedules", &[], None)
            .await
            .unwrap_err();
        assert!(failed.contains("timed out"), "{failed}");
    }

    /// Only the git server's answer is taken: one stamped with another identity, or with none, or that is not an answer,
    /// reaches no read.
    #[tokio::test]
    async fn only_the_git_servers_answer_is_taken() {
        let router = ReplyRouter::<MainRead>::new();
        let answer = |id: &str| {
            encode_main_read(&Envelope {
                correlation_id: id.into(),
                payload: MainRead::NoMain,
            })
        };
        for (id, by) in [
            (
                "a",
                Some("attestation-agent.polar.serviceaccount.cluster.local"),
            ),
            ("b", None),
            ("c", Some("polar-git-server")),
        ] {
            let waiting = router.register(id.into());
            on_reply(&router, by, &answer(id));
            router.cancel(id);
            assert!(waiting.await.is_err(), "{by:?}");
        }
        let waiting = router.register("d".into());
        on_reply(&router, Some(SERVER), b"not an answer");
        router.cancel("d");
        assert!(waiting.await.is_err());
        let waiting = router.register("e".into());
        on_reply(&router, Some(SERVER), &answer("e"));
        assert_eq!(waiting.await.unwrap(), MainRead::NoMain);
    }
}
