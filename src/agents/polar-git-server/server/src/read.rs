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

//! Reads over Cassini (docs/architecture/git-server.md, "Inside the boundary"): an agent inside Polar's boundary asks what
//! a repository's `main` holds on `polar-git-read-requests`, and is answered on its own topic, so no agent reads with `git`
//! or holds a key to reach the server. Who may read is the repository's readers, judged on the identity the broker
//! stamped, as a fetch over HTTP is judged on its certificate's; a refusal is said before whether the repository exists,
//! so a sender learns nothing of one it may not read. An answer is at most what one message carries.

use crate::access::{Access, Authorizer, Identity};
use crate::store::{ReadOfMain, RepoStore, StoreError};
use polar_git_server_common::{
    Envelope, MainRead, ReadMain, decode_read, encode_main_read, read_replies_topic,
};
use std::sync::Arc;
use tracing::warn;

/// The most an answer may be: what one Cassini message carries, its envelope's allowance aside.
pub const READ_LIMIT: usize = cassini_types::MAX_PAYLOAD_BYTES;

/// What the server needs to answer reads: the repositories, and who may read them.
pub struct Reader {
    pub store: RepoStore,
    pub authorizer: Arc<dyn Authorizer>,
    /// The most an answer may be, in bytes ([`READ_LIMIT`]).
    pub limit: usize,
}

impl Reader {
    /// The answer to a request `published_by` sent, and the topic it goes to; none when there is nobody to answer (no
    /// identity the broker stamped, or one that names no workload) or no request to answer (bytes that are not one),
    /// each said in a warning.
    pub async fn take(
        &self,
        published_by: Option<&str>,
        payload: &[u8],
    ) -> Option<(String, Envelope<MainRead>)> {
        let Some(sender) = published_by else {
            warn!("dropped a read with no sender the broker stamped");
            return None;
        };
        let Some(workload) = cert_issuer_common::identity::workload_of(sender) else {
            warn!(
                sender,
                "dropped a read from an identity that names no workload"
            );
            return None;
        };
        let request = match decode_read(payload) {
            Ok(request) => request,
            Err(why) => {
                warn!(sender, "dropped a read: {why}");
                return None;
            }
        };
        let repo = request.payload.repo.clone();
        let mut answer = Envelope {
            correlation_id: request.correlation_id,
            payload: self.read(sender, request.payload).await,
        };
        // The files were bounded as they were read; what wraps them is counted here.
        if encode_main_read(&answer).len() > self.limit {
            answer.payload = too_large(&repo, self.limit);
        }
        if let MainRead::Refused { why } | MainRead::NotNow { why } = &answer.payload {
            warn!(sender, repo, "a read was not answered: {why}");
        }
        Some((read_replies_topic(workload), answer))
    }

    async fn read(&self, sender: &str, request: ReadMain) -> MainRead {
        let ReadMain { repo, paths, have } = request;
        if !self
            .authorizer
            .allows(&Identity(sender.to_string()), &repo, Access::Read)
        {
            return MainRead::Refused {
                why: format!("{sender} may not read {repo}"),
            };
        }
        match self.store.read_main(&repo, paths, have, self.limit).await {
            Ok(ReadOfMain::Files { commit, files }) => MainRead::Files { commit, files },
            Ok(ReadOfMain::Unchanged { commit }) => MainRead::Unchanged { commit },
            Ok(ReadOfMain::NoMain) => MainRead::NoMain,
            Ok(ReadOfMain::TooLarge { limit }) => too_large(&repo, limit),
            Err(StoreError::Missing(_) | StoreError::BadName(_)) => MainRead::Refused {
                why: format!("there is no repository {repo}"),
            },
            Err(e) => MainRead::NotNow { why: e.to_string() },
        }
    }
}

fn too_large(repo: &str, limit: usize) -> MainRead {
    MainRead::Refused {
        why: format!(
            "what {repo} holds under the paths asked for is more than one message carries ({limit} bytes): ask for less"
        ),
    }
}

/// A read, as Cassini delivered it.
pub enum ReadMessage {
    Take {
        payload: Vec<u8>,
        published_by: Option<String>,
    },
}

/// Answers reads one at a time, in an actor of its own so a read never waits on a push, each sender on its own
/// topic.
pub struct ReadActor;

pub struct ReadState {
    pub reader: Reader,
    pub client: ractor::ActorRef<cassini_client::TcpClientMessage>,
}

#[ractor::async_trait]
impl ractor::Actor for ReadActor {
    type Msg = ReadMessage;
    type State = ReadState;
    type Arguments = ReadState;

    async fn pre_start(
        &self,
        _myself: ractor::ActorRef<Self::Msg>,
        state: ReadState,
    ) -> Result<Self::State, ractor::ActorProcessingErr> {
        Ok(state)
    }

    async fn handle(
        &self,
        _myself: ractor::ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ractor::ActorProcessingErr> {
        let ReadMessage::Take {
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
                encode_main_read(&answer),
                None,
            ))
        {
            tracing::error!(error = %e, topic, "cannot answer a read");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{RepoAcl, StaticAcl};
    use polar_git_server_common::{FileAt, FileKind, decode_main_read, encode_read};

    const OBSERVER: &str = "polar-scheduler-observer.polar.serviceaccount.cluster.local";
    const STRANGER: &str = "stranger.polar.serviceaccount.cluster.local";

    struct Fixture {
        _dir: tempfile::TempDir,
        reader: Reader,
        main: String,
    }

    async fn fixture(limit: usize) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let seed = dir.path().join("seed");
        std::fs::create_dir_all(seed.join("permanent")).unwrap();
        std::fs::write(seed.join("permanent/a.dhall"), "a").unwrap();
        std::fs::write(seed.join("README.md"), "schedules\n").unwrap();
        let store = RepoStore::new(dir.path().join("repos"));
        store.create("polar-schedules").await.unwrap();
        store.seed("polar-schedules", &seed).await.unwrap();
        let main = store
            .resolve_ref("polar-schedules", "refs/heads/main")
            .await
            .unwrap();
        let mut acl = StaticAcl::default();
        for repo in ["polar-schedules", "declared-but-gone"] {
            acl.repos.insert(
                repo.to_string(),
                RepoAcl {
                    readers: [OBSERVER.to_string()].into(),
                    writers: Default::default(),
                },
            );
        }
        Fixture {
            _dir: dir,
            reader: Reader {
                store,
                authorizer: Arc::new(acl),
                limit,
            },
            main,
        }
    }

    fn request(repo: &str, paths: &[&str], have: Option<&str>) -> Vec<u8> {
        encode_read(&Envelope {
            correlation_id: "c1".into(),
            payload: ReadMain {
                repo: repo.into(),
                paths: paths.iter().map(|p| p.to_string()).collect(),
                have: have.map(str::to_string),
            },
        })
    }

    async fn answer(f: &Fixture, sender: &str, payload: Vec<u8>) -> (String, MainRead) {
        let (topic, answer) = f.reader.take(Some(sender), &payload).await.unwrap();
        // What goes on the wire comes back as it was sent.
        let sent = decode_main_read(&encode_main_read(&answer)).unwrap();
        assert_eq!(sent.correlation_id, "c1");
        (topic, sent.payload)
    }

    #[tokio::test]
    async fn a_reader_is_answered_with_mains_files_on_its_own_topic() {
        let f = fixture(READ_LIMIT).await;
        let (topic, read) = answer(
            &f,
            OBSERVER,
            request("polar-schedules", &["permanent"], None),
        )
        .await;
        assert_eq!(
            topic,
            polar_git_server_common::SCHEDULER_OBSERVER_READ_REPLIES_TOPIC
        );
        assert_eq!(
            read,
            MainRead::Files {
                commit: f.main.clone(),
                files: vec![FileAt {
                    path: "permanent/a.dhall".into(),
                    kind: FileKind::Plain,
                    content: b"a".to_vec(),
                }],
            }
        );
        let (_, read) = answer(&f, OBSERVER, request("polar-schedules", &[], Some(&f.main))).await;
        assert_eq!(
            read,
            MainRead::Unchanged {
                commit: f.main.clone()
            }
        );
    }

    /// Who may not read is told so before whether the repository exists; who may, of a repository that is not there, that
    /// it is not.
    #[tokio::test]
    async fn a_sender_who_may_not_read_is_refused_before_anything_is_said_of_the_repository() {
        let f = fixture(READ_LIMIT).await;
        for repo in ["polar-schedules", "no-such-repository"] {
            let (topic, read) = answer(&f, STRANGER, request(repo, &[], None)).await;
            assert_eq!(topic, "polar-git-read-replies.stranger");
            assert_eq!(
                read,
                MainRead::Refused {
                    why: format!("{STRANGER} may not read {repo}")
                }
            );
        }
        let (_, read) = answer(&f, OBSERVER, request("declared-but-gone", &[], None)).await;
        assert_eq!(
            read,
            MainRead::Refused {
                why: "there is no repository declared-but-gone".into()
            }
        );
    }

    #[tokio::test]
    async fn more_than_one_message_carries_is_refused_and_says_to_ask_for_less() {
        let f = fixture(64).await;
        let (_, read) = answer(&f, OBSERVER, request("polar-schedules", &[], None)).await;
        let MainRead::Refused { why } = read else {
            panic!("{read:?}")
        };
        assert!(
            why.contains("more than one message carries (64 bytes)"),
            "{why}"
        );
    }

    #[tokio::test]
    async fn with_nobody_to_answer_or_no_request_nothing_is_answered() {
        let f = fixture(READ_LIMIT).await;
        assert!(
            f.reader
                .take(None, &request("polar-schedules", &[], None))
                .await
                .is_none()
        );
        assert!(
            f.reader
                .take(Some("alice"), &request("polar-schedules", &[], None))
                .await
                .is_none(),
            "a person's identity names no workload, so no topic to answer on"
        );
        assert!(f.reader.take(Some(OBSERVER), b"not a read").await.is_none());
    }
}
