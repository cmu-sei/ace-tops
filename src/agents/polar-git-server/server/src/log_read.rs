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

//! Reads of a log over Cassini (docs/architecture/record-store.md, "Bite 6"): an agent inside Polar's boundary asks for a
//! log's leaves from a sequence on `polar-log-read-requests`, and is answered on its own topic with the log's latest
//! co-signed checkpoint and its leaves up to that checkpoint, never past it. Who may read a log is the readers of its
//! governing repository, judged on the identity the broker stamped, as a read of `main` is; a refusal is said before
//! whether the log exists.

use crate::access::{Access, Authorizer, Identity};
use crate::logs::{LogsMessage, governing_repo};
use polar_git_server_common::{
    Envelope, LogRead, ReadLog, decode_read_log, encode_log_read, log_read_replies_topic,
};
use std::sync::Arc;
use tracing::warn;

/// What the store needs to answer log reads: its logs, and who may read them.
pub struct LogReader {
    pub logs: ractor::ActorRef<LogsMessage>,
    pub authorizer: Arc<dyn Authorizer>,
    /// The most an answer may be, in bytes.
    pub limit: usize,
}

impl LogReader {
    /// The answer to a request `published_by` sent, and the topic it goes to; none when there is nobody to answer (no
    /// identity the broker stamped, or one that names no workload) or no request to answer, each said in a warning.
    pub async fn take(
        &self,
        published_by: Option<&str>,
        payload: &[u8],
    ) -> Option<(String, Envelope<LogRead>)> {
        let Some(sender) = published_by else {
            warn!("dropped a log read with no sender the broker stamped");
            return None;
        };
        let Some(workload) = crate::reply::answered_as(sender) else {
            warn!(
                sender,
                "dropped a log read from an identity that is neither a workload nor a person"
            );
            return None;
        };
        let request = match decode_read_log(payload) {
            Ok(request) => request,
            Err(why) => {
                warn!(sender, "dropped a log read: {why}");
                return None;
            }
        };
        let log = request.payload.log.clone();
        let answer = Envelope {
            correlation_id: request.correlation_id,
            payload: self.read(sender, request.payload).await,
        };
        if let LogRead::Refused { why } | LogRead::NotNow { why } = &answer.payload {
            warn!(sender, log, "a log read was not answered: {why}");
        }
        Some((log_read_replies_topic(workload), answer))
    }

    async fn read(&self, sender: &str, request: ReadLog) -> LogRead {
        let ReadLog { log, from } = request;
        let may = governing_repo(&log).is_some_and(|repo| {
            self.authorizer
                .allows(&Identity(sender.to_string()), repo, Access::Read)
        });
        if !may {
            return LogRead::Refused {
                why: format!("{sender} may not read the log {log}"),
            };
        }
        // What wraps the leaves (the envelope, the correlation id) is kept out of the leaves' allowance.
        let limit = self.limit.saturating_sub(1024);
        ractor::call!(self.logs, |reply| LogsMessage::ReadFrom {
            log,
            from,
            limit,
            reply
        })
        .unwrap_or_else(|e| LogRead::NotNow {
            why: format!("the store's logs did not answer: {e}"),
        })
    }
}

/// A log read, as Cassini delivered it.
pub enum LogReadMessage {
    Take {
        payload: Vec<u8>,
        published_by: Option<String>,
    },
}

/// Answers log reads one at a time, each sender on its own topic.
pub struct LogReadActor;

pub struct LogReadState {
    pub reader: LogReader,
    pub client: ractor::ActorRef<cassini_client::TcpClientMessage>,
}

#[ractor::async_trait]
impl ractor::Actor for LogReadActor {
    type Msg = LogReadMessage;
    type State = LogReadState;
    type Arguments = LogReadState;

    async fn pre_start(
        &self,
        _myself: ractor::ActorRef<Self::Msg>,
        state: LogReadState,
    ) -> Result<Self::State, ractor::ActorProcessingErr> {
        Ok(state)
    }

    async fn handle(
        &self,
        _myself: ractor::ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ractor::ActorProcessingErr> {
        let LogReadMessage::Take {
            payload,
            published_by,
        } = message;
        let Some((topic, answer)) = state.reader.take(published_by.as_deref(), &payload).await
        else {
            return Ok(());
        };
        if let Err(e) = state
            .client
            .send_message(cassini_client::TcpClientMessage::publish(
                topic.clone(),
                encode_log_read(&answer),
                None,
            ))
        {
            tracing::error!(error = %e, topic, "cannot answer a log read");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{RepoAcl, StaticAcl};
    use crate::logs::{LogsActor, LogsArgs};
    use polar_git_server_common::{SCHEDULES_REPO, encode_read_log};
    use ractor::Actor;

    const ORIGIN: &str = "polar-git-server.polar.serviceaccount.cluster.local";
    const OBSERVER: &str = "polar-scheduler-observer.polar.serviceaccount.cluster.local";
    const STRANGER: &str = "stranger.polar.serviceaccount.cluster.local";

    async fn reader(limit: usize) -> (tempfile::TempDir, LogReader) {
        let dir = tempfile::tempdir().unwrap();
        let (logs, _) = Actor::spawn(
            None,
            LogsActor,
            LogsArgs {
                root: dir.path().to_path_buf(),
                origin: ORIGIN.into(),
                signer: std::sync::Arc::new(crate::logs::testing::KeySigner::new(ORIGIN)),
            },
        )
        .await
        .unwrap();
        let mut acl = StaticAcl::default();
        acl.repos.insert(
            SCHEDULES_REPO.to_string(),
            RepoAcl {
                readers: [OBSERVER.to_string()].into(),
                writers: Default::default(),
            },
        );
        (
            dir,
            LogReader {
                logs,
                authorizer: Arc::new(acl),
                limit,
            },
        )
    }

    fn request(log: &str, from: u64) -> Vec<u8> {
        encode_read_log(&Envelope {
            correlation_id: "r1".into(),
            payload: ReadLog {
                log: log.into(),
                from,
            },
        })
    }

    /// A reader of polar-schedules is answered on its own topic, with the correlation id it sent; nothing is witnessed
    /// yet, so the answer says so.
    #[tokio::test]
    async fn a_reader_of_the_repository_is_answered_on_its_own_topic() {
        let (_dir, reader) = reader(cassini_types::MAX_PAYLOAD_BYTES).await;
        let (topic, answer) = reader
            .take(Some(OBSERVER), &request("schedules", 0))
            .await
            .unwrap();
        assert_eq!(
            topic,
            polar_git_server_common::SCHEDULER_OBSERVER_LOG_READ_REPLIES_TOPIC
        );
        assert_eq!(answer.correlation_id, "r1");
        assert!(
            matches!(&answer.payload, LogRead::Entries { leaves, witnessed: false, .. } if leaves.is_empty()),
            "{:?}",
            answer.payload
        );
    }

    /// Who is not a reader of the log's repository, or asks for a log no repository governs, is refused alike, before
    /// whether the log exists is said.
    #[tokio::test]
    async fn who_may_not_read_the_repository_is_refused_whatever_the_log() {
        let (_dir, reader) = reader(cassini_types::MAX_PAYLOAD_BYTES).await;
        for (who, log) in [
            (STRANGER, "schedules"),
            (OBSERVER, "evidence"),
            (OBSERVER, "no-such-log"),
        ] {
            let (_, answer) = reader.take(Some(who), &request(log, 0)).await.unwrap();
            assert!(
                matches!(&answer.payload, LogRead::Refused { why } if why.contains(who)),
                "{who} {log}: {:?}",
                answer.payload
            );
        }
    }

    /// No sender the broker stamped, one that names no workload, and bytes that are not a request get no answer.
    #[tokio::test]
    async fn what_cannot_be_answered_is_dropped() {
        let (_dir, reader) = reader(cassini_types::MAX_PAYLOAD_BYTES).await;
        assert!(reader.take(None, &request("schedules", 0)).await.is_none());
        assert!(
            reader
                .take(Some("polar-scheduler-observer"), &request("schedules", 0))
                .await
                .is_none()
        );
        assert!(
            reader
                .take(Some(OBSERVER), b"not a request")
                .await
                .is_none()
        );
    }
}
