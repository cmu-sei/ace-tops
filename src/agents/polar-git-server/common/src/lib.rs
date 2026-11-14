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

//! What the Polar git server says to the rest of Polar, and the topics it says it on.
//! Design: `docs/architecture/git-server.md`.

use rkyv::{Archive, Deserialize, Serialize};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

pub mod schedules;

/// Published after a push has been accepted, once per ref that moved. The scheduler's observer
/// subscribes, so against the managed server it need not poll.
pub const POLAR_GIT_REPO_CHANGED_TOPIC: &str = "polar-git-repo-changed";

/// The smart-HTTP route a push arrives on, whose acceptance the server announces on [`POLAR_GIT_REPO_CHANGED_TOPIC`].
/// Written once, so the server's router and its topic declaration name the same route
/// (docs/architecture/authority-model.md, "Decisions": the vocabulary of causes).
pub const RECEIVE_PACK_ROUTE: &str = "/:repo/git-receive-pack";

/// A ref of a hosted repository now points somewhere new. `pusher` is the identity from the
/// client's verified certificate.
#[derive(
    Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Archive, SerdeDeserialize, SerdeSerialize,
)]
pub struct RepoChangedEvent {
    pub repo: String,
    pub refname: String,
    pub old: String,
    pub new: String,
    pub pusher: String,
}

pub use polar::request_reply::Envelope;

/// The repository signed evidence records are kept in (docs/architecture/git-server.md, "Inside the boundary").
pub const EVIDENCE_REPO: &str = "polar-evidence";

/// Where a collector that is a workload sends a signed evidence record for the server to add to [`EVIDENCE_REPO`], so no
/// agent pushes with `git`. Each answer goes to the sender's own topic, [`evidence_replies_topic`].
pub const EVIDENCE_REQUESTS_TOPIC: &str = "polar-git-evidence-requests";

/// The attestation agent's reply topic. Those who add evidence are named, as the attestation agent's askers are, so the
/// server's certificate names their topics and no family over every workload.
pub const ATTESTATION_AGENT_EVIDENCE_REPLIES_TOPIC: &str =
    "polar-git-evidence-replies.attestation-agent";

/// The reply topic of the workload `workload`.
pub fn evidence_replies_topic(workload: &str) -> String {
    format!("polar-git-evidence-replies.{workload}")
}

/// A signed evidence record, as its signer wrote it: the server verifies it, and names its file by the digest of
/// exactly these bytes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Archive)]
pub struct AddRecord {
    pub record: String,
}

/// What became of a record.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Archive)]
pub enum RecordAdded {
    /// It was committed at `path`, as `commit`.
    Committed { path: String, commit: String },
    /// The repository holds it already: the same bytes are at `path`.
    AlreadyThere { path: String },
    /// It was not added, and never will be as it is: the sender may not add evidence, or it is no verifying record.
    Refused { why: String },
    /// It could not be added now, through no fault of the record (the repository could not be written): the sender
    /// keeps it and sends it again.
    NotNow { why: String },
}

/// The bytes of a request, as it is published.
pub fn encode_add(envelope: &Envelope<AddRecord>) -> Vec<u8> {
    rkyv::to_bytes::<rkyv::rancor::Error>(envelope)
        .expect("a request of owned strings always serializes")
        .into_vec()
}

/// The bytes of an answer, as it is published.
pub fn encode_added(envelope: &Envelope<RecordAdded>) -> Vec<u8> {
    rkyv::to_bytes::<rkyv::rancor::Error>(envelope)
        .expect("an answer of owned strings always serializes")
        .into_vec()
}

/// The request in `payload`, or why it is not one. The bytes are validated before anything is read from them.
pub fn decode_add(payload: &[u8]) -> Result<Envelope<AddRecord>, String> {
    let mut aligned = rkyv::util::AlignedVec::<16>::new();
    aligned.extend_from_slice(payload);
    rkyv::from_bytes::<Envelope<AddRecord>, rkyv::rancor::Error>(&aligned)
        .map_err(|e| format!("not a record to add: {e}"))
}

/// The answer in `payload`, or why it is not one.
pub fn decode_added(payload: &[u8]) -> Result<Envelope<RecordAdded>, String> {
    let mut aligned = rkyv::util::AlignedVec::<16>::new();
    aligned.extend_from_slice(payload);
    rkyv::from_bytes::<Envelope<RecordAdded>, rkyv::rancor::Error>(&aligned)
        .map_err(|e| format!("not an answer about a record: {e}"))
}

/// Where an agent asks the server for what a repository's `main` holds, so no agent reads with `git`
/// (docs/architecture/git-server.md, "Inside the boundary"). Each answer goes to the sender's own topic, [`read_replies_topic`].
pub const READ_REQUESTS_TOPIC: &str = "polar-git-read-requests";

/// The scheduler observer's reply topic: it reads `polar-schedules` and the deployment record. Those who read are named, as
/// those who add evidence are, so the server's certificate names their topics and no family over every workload.
pub const SCHEDULER_OBSERVER_READ_REPLIES_TOPIC: &str =
    "polar-git-read-replies.polar-scheduler-observer";

/// The read reply topic of the workload `workload`.
pub fn read_replies_topic(workload: &str) -> String {
    format!("polar-git-read-replies.{workload}")
}

/// What a repository's `main` holds, asked for: the files under `paths` (a path names a file, or a directory and all under
/// it; none names every file), unless `main` is still the commit `have`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Archive)]
pub struct ReadMain {
    pub repo: String,
    pub paths: Vec<String>,
    pub have: Option<String>,
}

/// What a file is, as git records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Archive)]
pub enum FileKind {
    Plain,
    Executable,
    /// A symbolic link, whose content is where it points.
    Link,
}

/// One file of a commit.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Archive)]
pub struct FileAt {
    pub path: String,
    pub kind: FileKind,
    pub content: Vec<u8>,
}

/// The answer to a [`ReadMain`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Archive)]
pub enum MainRead {
    /// `main` is `commit`, and these are its files under the paths asked for, by path.
    Files { commit: String, files: Vec<FileAt> },
    /// `main` is still the commit the asker has.
    Unchanged { commit: String },
    /// The repository has no `main` yet.
    NoMain,
    /// Not answered, and never will be as it is: the sender may not read the repository, there is none, or what it asked
    /// for is more than one message carries.
    Refused { why: String },
    /// Not answered now, through no fault of the request (the repository could not be read): the sender asks again.
    NotNow { why: String },
}

/// The bytes of a read request, as it is published.
pub fn encode_read(envelope: &Envelope<ReadMain>) -> Vec<u8> {
    rkyv::to_bytes::<rkyv::rancor::Error>(envelope)
        .expect("a request of owned strings always serializes")
        .into_vec()
}

/// The bytes of a read answer, as it is published.
pub fn encode_main_read(envelope: &Envelope<MainRead>) -> Vec<u8> {
    rkyv::to_bytes::<rkyv::rancor::Error>(envelope)
        .expect("an answer of owned data always serializes")
        .into_vec()
}

/// The read request in `payload`, or why it is not one. The bytes are validated before anything is read from them.
pub fn decode_read(payload: &[u8]) -> Result<Envelope<ReadMain>, String> {
    let mut aligned = rkyv::util::AlignedVec::<16>::new();
    aligned.extend_from_slice(payload);
    rkyv::from_bytes::<Envelope<ReadMain>, rkyv::rancor::Error>(&aligned)
        .map_err(|e| format!("not a read request: {e}"))
}

/// The read answer in `payload`, or why it is not one.
pub fn decode_main_read(payload: &[u8]) -> Result<Envelope<MainRead>, String> {
    let mut aligned = rkyv::util::AlignedVec::<16>::new();
    aligned.extend_from_slice(payload);
    rkyv::from_bytes::<Envelope<MainRead>, rkyv::rancor::Error>(&aligned)
        .map_err(|e| format!("not an answer to a read: {e}"))
}

/// The repository the agents' signed configuration is kept in.
pub const SCHEDULES_REPO: &str = "polar-schedules";

/// The log the store keeps beside `repo`, which holds what it holds (docs/architecture/record-store.md); none for a
/// repository without one.
pub fn log_of_repo(repo: &str) -> Option<&'static str> {
    match repo {
        EVIDENCE_REPO => Some("evidence"),
        SCHEDULES_REPO => Some(schedules::SCHEDULES_LOG),
        _ => None,
    }
}

/// Where an agent asks the store for a log's entries (docs/architecture/record-store.md, "Bite 6"), answered on the
/// sender's own topic, [`log_read_replies_topic`].
pub const LOG_READ_REQUESTS_TOPIC: &str = "polar-log-read-requests";

/// The scheduler observer's reply topic for the schedules log: named, as its reads of a repository are.
pub const SCHEDULER_OBSERVER_LOG_READ_REPLIES_TOPIC: &str =
    "polar-log-read-replies.polar-scheduler-observer";

/// The log read reply topic of the workload `workload`.
pub fn log_read_replies_topic(workload: &str) -> String {
    format!("polar-log-read-replies.{workload}")
}

/// Published when the witness's co-signature over a log grows, so a reader reads what it may now see.
pub const LOG_WITNESSED_TOPIC: &str = "polar-log-witnessed";

/// A log's latest co-signed checkpoint now covers `size` leaves.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Archive)]
pub struct LogWitnessed {
    pub log: String,
    pub size: u64,
}

/// A log's leaves from `from`, asked for.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Archive)]
pub struct ReadLog {
    pub log: String,
    pub from: u64,
}

/// The answer to a [`ReadLog`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Archive)]
pub enum LogRead {
    /// A checkpoint of the log (a signed note) and its leaves from the one asked for, each a leaf's encoding, up to the
    /// checkpoint's size, as many as one message carries; a reader given fewer asks again from where they end.
    /// `witnessed`: the checkpoint is the latest the witness co-signed, and no leaf past it is given. Not witnessed:
    /// the witness has never co-signed the log, and the checkpoint is the store's own, now. That is a fresh cluster's
    /// first moments, before the witness and the store are pinned in each other through this very log, and a reader
    /// that holds the keys takes nothing from it (docs/architecture/record-store.md, "Bite 6").
    Entries {
        checkpoint: String,
        leaves: Vec<Vec<u8>>,
        witnessed: bool,
    },
    /// Not answered, and never will be as it is: the sender may not read the log, there is none, or it asked from past
    /// the checkpoint.
    Refused { why: String },
    /// Not answered now, through no fault of the request: the sender asks again.
    NotNow { why: String },
}

/// The bytes of a log read request, as it is published.
pub fn encode_read_log(envelope: &Envelope<ReadLog>) -> Vec<u8> {
    rkyv::to_bytes::<rkyv::rancor::Error>(envelope)
        .expect("a request of owned strings always serializes")
        .into_vec()
}

/// The bytes of a log read answer, as it is published.
pub fn encode_log_read(envelope: &Envelope<LogRead>) -> Vec<u8> {
    rkyv::to_bytes::<rkyv::rancor::Error>(envelope)
        .expect("an answer of owned data always serializes")
        .into_vec()
}

/// The bytes of a witnessed announcement, as it is published.
pub fn encode_witnessed(event: &LogWitnessed) -> Vec<u8> {
    rkyv::to_bytes::<rkyv::rancor::Error>(event)
        .expect("an event of owned data always serializes")
        .into_vec()
}

/// The log read request in `payload`, or why it is not one.
pub fn decode_read_log(payload: &[u8]) -> Result<Envelope<ReadLog>, String> {
    let mut aligned = rkyv::util::AlignedVec::<16>::new();
    aligned.extend_from_slice(payload);
    rkyv::from_bytes::<Envelope<ReadLog>, rkyv::rancor::Error>(&aligned)
        .map_err(|e| format!("not a log read request: {e}"))
}

/// The log read answer in `payload`, or why it is not one.
pub fn decode_log_read(payload: &[u8]) -> Result<Envelope<LogRead>, String> {
    let mut aligned = rkyv::util::AlignedVec::<16>::new();
    aligned.extend_from_slice(payload);
    rkyv::from_bytes::<Envelope<LogRead>, rkyv::rancor::Error>(&aligned)
        .map_err(|e| format!("not an answer to a log read: {e}"))
}

/// The witnessed announcement in `payload`, or why it is not one.
pub fn decode_witnessed(payload: &[u8]) -> Result<LogWitnessed, String> {
    let mut aligned = rkyv::util::AlignedVec::<16>::new();
    aligned.extend_from_slice(payload);
    rkyv::from_bytes::<LogWitnessed, rkyv::rancor::Error>(&aligned)
        .map_err(|e| format!("not a witnessed log: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_event_survives_the_wire() {
        let event = RepoChangedEvent {
            repo: "polar-schedules".into(),
            refname: "refs/heads/main".into(),
            old: "a".repeat(40),
            new: "b".repeat(40),
            pusher: "alice".into(),
        };
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&event).unwrap();
        let back = rkyv::from_bytes::<RepoChangedEvent, rkyv::rancor::Error>(&bytes).unwrap();
        assert_eq!(back, event);
    }

    #[test]
    fn the_scheduler_observers_read_topic_is_the_one_it_is_answered_on() {
        assert_eq!(
            read_replies_topic("polar-scheduler-observer"),
            SCHEDULER_OBSERVER_READ_REPLIES_TOPIC
        );
    }

    #[test]
    fn what_is_not_a_read_or_its_answer_is_refused() {
        for garbage in [&b""[..], b"\x00\x01\x02", b"not rkyv at all, just text"] {
            assert!(decode_read(garbage).is_err());
            assert!(decode_main_read(garbage).is_err());
            assert!(decode_read_log(garbage).is_err());
            assert!(decode_log_read(garbage).is_err());
            assert!(decode_witnessed(garbage).is_err());
        }
    }

    #[test]
    fn the_scheduler_observers_log_read_topic_is_the_one_it_is_answered_on() {
        assert_eq!(
            log_read_replies_topic("polar-scheduler-observer"),
            SCHEDULER_OBSERVER_LOG_READ_REPLIES_TOPIC
        );
    }

    #[test]
    fn each_repository_with_a_log_names_it_and_no_other_does() {
        assert_eq!(log_of_repo(EVIDENCE_REPO), Some("evidence"));
        assert_eq!(log_of_repo(SCHEDULES_REPO), Some(schedules::SCHEDULES_LOG));
        assert_eq!(log_of_repo("deployment"), None);
    }

    mod props {
        use super::super::*;
        use proptest::prelude::*;

        fn text() -> impl Strategy<Value = String> {
            "[a-z0-9/._-]{0,12}"
        }

        fn file() -> impl Strategy<Value = FileAt> {
            (
                text(),
                prop_oneof![
                    Just(FileKind::Plain),
                    Just(FileKind::Executable),
                    Just(FileKind::Link)
                ],
                proptest::collection::vec(any::<u8>(), 0..64),
            )
                .prop_map(|(path, kind, content)| FileAt {
                    path,
                    kind,
                    content,
                })
        }

        fn answer() -> impl Strategy<Value = MainRead> {
            prop_oneof![
                (text(), proptest::collection::vec(file(), 0..4))
                    .prop_map(|(commit, files)| MainRead::Files { commit, files }),
                text().prop_map(|commit| MainRead::Unchanged { commit }),
                Just(MainRead::NoMain),
                text().prop_map(|why| MainRead::Refused { why }),
                text().prop_map(|why| MainRead::NotNow { why }),
            ]
        }

        fn log_answer() -> impl Strategy<Value = LogRead> {
            prop_oneof![
                (
                    text(),
                    proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..16), 0..4),
                    any::<bool>()
                )
                    .prop_map(|(checkpoint, leaves, witnessed)| LogRead::Entries {
                        checkpoint,
                        leaves,
                        witnessed
                    }),
                text().prop_map(|why| LogRead::Refused { why }),
                text().prop_map(|why| LogRead::NotNow { why }),
            ]
        }

        proptest! {
            /// A log read, every answer to it, and the announcement come back from the wire as they went.
            #[test]
            fn a_log_read_its_answer_and_the_announcement_survive_the_wire(
                id in text(),
                log in text(),
                from in any::<u64>(),
                answer in log_answer(),
            ) {
                let read = Envelope { correlation_id: id.clone(), payload: ReadLog { log: log.clone(), from } };
                let back = decode_read_log(&encode_read_log(&read)).unwrap();
                prop_assert_eq!((back.correlation_id, back.payload), (read.correlation_id, read.payload));
                let answered = Envelope { correlation_id: id, payload: answer };
                let back = decode_log_read(&encode_log_read(&answered)).unwrap();
                prop_assert_eq!((back.correlation_id, back.payload), (answered.correlation_id, answered.payload));
                let witnessed = LogWitnessed { log, size: from };
                prop_assert_eq!(decode_witnessed(&encode_witnessed(&witnessed)).unwrap(), witnessed);
            }

            /// A request and every answer come back from the wire as they went.
            #[test]
            fn a_read_and_its_answer_survive_the_wire(
                id in text(),
                repo in text(),
                paths in proptest::collection::vec(text(), 0..4),
                have in proptest::option::of(text()),
                answer in answer(),
            ) {
                let read = Envelope { correlation_id: id.clone(), payload: ReadMain { repo, paths, have } };
                let back = decode_read(&encode_read(&read)).unwrap();
                prop_assert_eq!((back.correlation_id, back.payload), (read.correlation_id, read.payload));
                let answered = Envelope { correlation_id: id, payload: answer };
                let back = decode_main_read(&encode_main_read(&answered)).unwrap();
                prop_assert_eq!((back.correlation_id, back.payload), (answered.correlation_id, answered.payload));
            }
        }
    }
}
