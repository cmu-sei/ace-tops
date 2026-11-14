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

//! Keeps the checkout as the store's schedules log says polar-schedules is (docs/architecture/record-store.md, "Bite
//! 6"): on an interval and whenever told, it asks the store for the leaves past those it holds, over Cassini
//! (src/reads.rs), and writes the tree they make (src/checkout.rs).
//!
//! What it holds to:
//! - With its keys, the store's and the witness's, it writes only a log whose leaves make the root of a checkpoint the
//!   store signed and the witness co-signed. A log that is not the one it held, whose leaves do not make the root, ends
//!   it: it delivers nothing more until it is started again.
//! - Its keys come from its own settings, which arrive through itself: from each answer it takes its own settings
//!   document and hands it to its configuration actor, which verifies it as every agent does. The store cannot put keys
//!   of its own there, since an administrator signs them.
//! - Without keys it writes nothing a witness co-signed until it has them. A log the witness has never co-signed is a
//!   fresh cluster's first moments, before the store and the witness are pinned in each other through this very log:
//!   that is written as the store's word, as polar-schedules' `main` was before the log, and said; with keys, it is not.
//! - A critical entry it does not know stops the tree there; the checkout holds the tree before it, and it says so.
//!
//! Until its first read has been answered it asks again with a growing wait, since the store may not answer yet; a
//! refusal then is final, since asking again cannot change it, and ends the observer. After that a failed read is
//! said, and the next one tries again.

use crate::reads::ReadsLog;
use polar_git_server_common::schedules::{Tree, replay};
use polar_git_server_common::{FileAt, FileKind, LogRead};
use polar_log::checkpoint::{Checkpoint, NoteVerifier, open_witnessed};
use polar_log::merkle::{Hash, leaf_hash, root};
use ractor::{Actor, ActorProcessingErr, ActorRef};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

/// The first wait before asking again, and the longest.
const FIRST_RETRY: Duration = Duration::from_secs(2);
const LONGEST_RETRY: Duration = Duration::from_secs(30);

/// The observer's own settings: where they are in the tree, how they reach its configuration actor, and the keys they
/// pin as they change.
#[ractor::async_trait]
pub trait OwnSettings: Send + Sync {
    /// The place of the observer's own settings document in the tree.
    fn place(&self) -> String;
    /// Hands the document to the observer's configuration actor, which verifies it as every agent does: what became of
    /// it, said.
    async fn submit(&self, document: serde_json::Value) -> Result<String, String>;
    /// The keys pinned now, the store's and the witness's; each change after arrives as [`SyncMessage::StoreKey`] or
    /// [`SyncMessage::WitnessKey`].
    async fn follow(
        &self,
        myself: &ActorRef<SyncMessage>,
    ) -> Result<(Option<String>, Option<String>), String>;
}

/// The observer's own settings, through its configuration handle.
pub struct OwnConfiguration {
    pub agent: String,
    pub configuration: polar_agent_builder::ConfigurationHandle,
}

#[ractor::async_trait]
impl OwnSettings for OwnConfiguration {
    fn place(&self) -> String {
        format!("permanent/{}/configuration.dhall", self.agent)
    }

    async fn submit(&self, document: serde_json::Value) -> Result<String, String> {
        self.configuration
            .submit(document)
            .await
            .map(|outcome| format!("{outcome:?}"))
            .map_err(|e| e.to_string())
    }

    async fn follow(
        &self,
        myself: &ActorRef<SyncMessage>,
    ) -> Result<(Option<String>, Option<String>), String> {
        use crate::settings::{STORE_KEY, WITNESS_KEY};
        use polar_env::Described;
        let store = self
            .configuration
            .follow(&STORE_KEY, myself, SyncMessage::StoreKey)
            .await
            .map_err(|e| format!("cannot follow {}: {e}", STORE_KEY.desc().name))?;
        let witness = self
            .configuration
            .follow(&WITNESS_KEY, myself, SyncMessage::WitnessKey)
            .await
            .map_err(|e| format!("cannot follow {}: {e}", WITNESS_KEY.desc().name))?;
        Ok((store, witness))
    }
}

pub struct GitSyncActor;

pub struct GitSyncArgs {
    pub repo_path: PathBuf,
    /// The log read: the one the store keeps beside the schedules repository.
    pub log: String,
    pub reads: Arc<dyn ReadsLog>,
    /// Read on this interval as well; none means only [`SyncMessage::Now`] reads.
    pub interval: Option<Duration>,
    /// Told after each read that brought the checkout up to date, so what it brought is read: the watcher rescans.
    pub pulled: Option<Pulled>,
    pub own: Arc<dyn OwnSettings>,
}

/// What is told that a read brought the checkout up to date.
pub type Pulled = std::sync::Arc<dyn Fn() + Send + Sync>;

/// What the keys pinned allow.
#[derive(Debug)]
enum Keys {
    /// None is pinned: the observer's settings have not arrived, or pin none.
    None,
    Pinned {
        store: NoteVerifier,
        witness: NoteVerifier,
    },
    /// Something is pinned that cannot be held to: one key and not the other, or a key that is not one.
    Broken(String),
}

pub struct GitSyncState {
    repo_path: PathBuf,
    log: String,
    reads: Arc<dyn ReadsLog>,
    pulled: Option<Pulled>,
    own: Arc<dyn OwnSettings>,
    /// The leaves the checkout was written from, in order, and their hashes.
    held: Vec<Vec<u8>>,
    hashes: Vec<Hash>,
    store_key: Option<String>,
    witness_key: Option<String>,
    /// The bytes of the observer's own settings last handed to its configuration actor.
    submitted: Option<Vec<u8>>,
    /// Whether a read has been answered yet.
    answered: bool,
    /// Whether the checkout has been written from the log yet.
    written: bool,
    /// Whether an unwitnessed log was said to be written as the store's word.
    said_unwitnessed: bool,
    /// How long until the first read is asked again.
    retry: Duration,
}

#[derive(Debug, Clone)]
pub enum SyncMessage {
    /// The interval elapsed.
    Tick,
    /// The store said the log changed, or the observer joined Cassini.
    Now,
    /// The first read was not answered, and is asked again.
    Retry,
    /// The store's key in force changed.
    StoreKey(Option<String>),
    /// The witness's key in force changed.
    WitnessKey(Option<String>),
}

/// The checkpoint a note states, its signatures not looked at: only how far to read.
fn stated(note: &str) -> Result<Checkpoint, String> {
    let end = note
        .find("\n\n")
        .ok_or("the checkpoint is not a signed note")?;
    Checkpoint::parse(&note[..=end]).map_err(|e| e.to_string())
}

/// The JSON a rendered Dhall document is, with nothing left to resolve (an import is refused, as the watcher refuses it).
pub fn evaluate(text: &str) -> Result<serde_json::Value, String> {
    let simple: serde_dhall::SimpleValue = serde_dhall::from_str(text)
        .imports(false)
        .parse()
        .map_err(|e| format!("Dhall error: {e}"))?;
    serde_json::to_value(&simple).map_err(|e| e.to_string())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl GitSyncState {
    fn keys(&self) -> Keys {
        match (&self.store_key, &self.witness_key) {
            (None, None) => Keys::None,
            (Some(store), Some(witness)) => {
                match (NoteVerifier::parse(store), NoteVerifier::parse(witness)) {
                    (Ok(store), Ok(witness)) => Keys::Pinned { store, witness },
                    (Err(e), _) => Keys::Broken(format!("the store's key is not one: {e}")),
                    (_, Err(e)) => Keys::Broken(format!("the witness's key is not one: {e}")),
                }
            }
            _ => Keys::Broken("one key is pinned and not the other".to_string()),
        }
    }

    /// Asks for every leaf past those held, page by page: the last answer's checkpoint, whether it is witnessed, and the
    /// leaves; or why the asking failed, and whether that is a refusal.
    async fn read(&self) -> Result<(String, bool, Vec<Vec<u8>>), (String, bool)> {
        let mut leaves = Vec::new();
        loop {
            let from = (self.held.len() + leaves.len()) as u64;
            match self.reads.read_log(&self.log, from).await {
                Ok(LogRead::Entries {
                    checkpoint,
                    leaves: page,
                    witnessed,
                }) => {
                    let size = stated(&checkpoint).map_err(|why| (why, false))?.size;
                    let given = page.len() as u64;
                    leaves.extend(page);
                    if from + given >= size || given == 0 {
                        return Ok((checkpoint, witnessed, leaves));
                    }
                }
                Ok(LogRead::Refused { why }) => return Err((why, true)),
                Ok(LogRead::NotNow { why }) => return Err((why, false)),
                Err(why) => return Err((why, false)),
            }
        }
    }

    /// Hands the observer's own settings, as the leaves read make them, to its configuration actor, when they changed:
    /// whether they were handed on now.
    async fn submit_own(&mut self, leaves: &[Vec<u8>]) -> bool {
        let all: Vec<Vec<u8>> = self.held.iter().chain(leaves).cloned().collect();
        let (tree, _) = replay(&all);
        let place = self.own.place();
        let Some(bytes) = tree.files().get(&place) else {
            return false;
        };
        if self.submitted.as_ref() == Some(bytes) {
            return false;
        }
        self.submitted = Some(bytes.clone());
        let document = std::str::from_utf8(bytes)
            .map_err(|e| e.to_string())
            .and_then(evaluate);
        match document {
            Ok(document) => match self.own.submit(document).await {
                Ok(outcome) => info!(%place, %outcome, "the observer's own settings, from the log"),
                Err(why) => warn!(%place, %why, "the observer's own settings were not taken"),
            },
            Err(why) => warn!(%place, %why, "the observer's own settings cannot be read"),
        }
        true
    }

    /// Holds the leaves read to the checkpoint under the keys: none of them taken unless, with those held, they make
    /// the root of the checkpoint the store signed and the witness co-signed. A root they do not make is the store
    /// changing the log under the observer: an error, which ends it.
    fn hold(
        &mut self,
        note: &str,
        leaves: Vec<Vec<u8>>,
        store: &NoteVerifier,
        witness: &NoteVerifier,
    ) -> Result<bool, ActorProcessingErr> {
        let checkpoint = match open_witnessed(note, store, witness, now()) {
            Ok(checkpoint) => checkpoint,
            Err(why) => {
                warn!(log = %self.log, %why, "the log's checkpoint is not the pinned store's and witness's: nothing delivered");
                return Ok(false);
            }
        };
        let mut hashes = self.hashes.clone();
        hashes.extend(leaves.iter().map(|l| leaf_hash(l)));
        if hashes.len() as u64 != checkpoint.size {
            warn!(log = %self.log, given = hashes.len(), size = checkpoint.size, "the store did not give the checkpoint's leaves: nothing delivered");
            return Ok(false);
        }
        if root(&hashes) != checkpoint.root {
            return Err(format!(
                "the log {} is not the one held: its {} leaves do not make the root its witnessed checkpoint states; \
                 nothing more is delivered",
                self.log, checkpoint.size
            )
            .into());
        }
        self.held.extend(leaves);
        self.hashes = hashes;
        Ok(true)
    }

    /// Writes the tree the leaves held make into the checkout, and tells.
    async fn write(&mut self) -> Result<Option<String>, ActorProcessingErr> {
        let (tree, stop) = replay(&self.held);
        if let Some(stop) = stop {
            error!(log = %self.log, %stop, "the checkout holds the log as it stood before this entry");
        }
        let files = files_of(&tree);
        let dir = self.repo_path.clone();
        match tokio::task::spawn_blocking(move || crate::checkout::apply(&dir, &files))
            .await
            .map_err(|e| ActorProcessingErr::from(e.to_string()))?
        {
            Ok(_) => {
                self.written = true;
                info!(log = %self.log, leaves = self.held.len(), "the checkout holds the log");
                if let Some(tell) = &self.pulled {
                    tell();
                }
                Ok(None)
            }
            Err(why) => Ok(Some(why)),
        }
    }
}

fn files_of(tree: &Tree) -> Vec<FileAt> {
    tree.files()
        .iter()
        .map(|(path, bytes)| FileAt {
            path: path.clone(),
            kind: FileKind::Plain,
            content: bytes.clone(),
        })
        .collect()
}

#[ractor::async_trait]
impl Actor for GitSyncActor {
    type Msg = SyncMessage;
    type State = GitSyncState;
    type Arguments = GitSyncArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: GitSyncArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        match args.interval {
            Some(interval) => {
                info!(
                    "GitSyncActor starting, will read the log {} every {}s and when told",
                    args.log,
                    interval.as_secs()
                );
                myself.send_interval(interval, || SyncMessage::Tick);
            }
            None => info!(
                "GitSyncActor starting, will read the log {} when told",
                args.log
            ),
        }
        let (store_key, witness_key) = args.own.follow(&myself).await?;
        Ok(GitSyncState {
            repo_path: args.repo_path,
            log: args.log,
            reads: args.reads,
            pulled: args.pulled,
            own: args.own,
            held: Vec::new(),
            hashes: Vec::new(),
            store_key,
            witness_key,
            submitted: None,
            answered: false,
            written: false,
            said_unwitnessed: false,
            retry: FIRST_RETRY,
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        msg: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match msg {
            SyncMessage::StoreKey(key) => {
                state.store_key = key;
                myself.send_message(SyncMessage::Now)?;
                return Ok(());
            }
            SyncMessage::WitnessKey(key) => {
                state.witness_key = key;
                myself.send_message(SyncMessage::Now)?;
                return Ok(());
            }
            SyncMessage::Tick | SyncMessage::Now | SyncMessage::Retry => {}
        }
        info!(?msg, log = %state.log, "reading the log");
        let failed = match state.read().await {
            Ok((note, witnessed, leaves)) => {
                state.answered = true;
                let handed_on = state.submit_own(&leaves).await;
                match (state.keys(), witnessed) {
                    (Keys::Pinned { store, witness }, true) => {
                        let new = !leaves.is_empty();
                        if state.hold(&note, leaves, &store, &witness)? && (new || !state.written) {
                            state.write().await?
                        } else {
                            None
                        }
                    }
                    (Keys::Pinned { .. }, false) => {
                        info!(log = %state.log, "the log is not witnessed yet: nothing is delivered until it is");
                        None
                    }
                    (Keys::None, false) => {
                        if !state.said_unwitnessed {
                            warn!(
                                log = %state.log,
                                "the witness has never co-signed the log, and the observer holds no keys: it is delivered as \
                                 the store's word until the observer's settings pin them"
                            );
                            state.said_unwitnessed = true;
                        }
                        let new = !leaves.is_empty();
                        state.hashes.extend(leaves.iter().map(|l| leaf_hash(l)));
                        state.held.extend(leaves);
                        if new || !state.written {
                            state.write().await?
                        } else {
                            None
                        }
                    }
                    // The keys its settings pin arrive as their own messages, and each asks for a read.
                    (Keys::None, true) if handed_on => {
                        info!(log = %state.log, "the observer's settings were handed on: the log is read again once the keys they pin are in force");
                        None
                    }
                    (Keys::None, true) => {
                        warn!(
                            log = %state.log,
                            "the observer holds no keys to hold the witnessed log to: nothing is delivered until its \
                             settings pin them (up.nu's seed signs them)"
                        );
                        None
                    }
                    (Keys::Broken(why), _) => {
                        error!(log = %state.log, %why, "the keys pinned cannot be held to: nothing is delivered");
                        None
                    }
                }
            }
            Err((why, true)) if !state.answered => {
                return Err(
                    format!("the store refused to read the log {}: {why}", state.log).into(),
                );
            }
            Err((why, true)) => {
                error!(log = %state.log, "the store refused a read: {why}");
                None
            }
            Err((why, false)) => Some(why),
        };
        if let Some(why) = failed {
            if !state.answered {
                warn!(
                    "the log does not answer yet ({why}); asking again in {}s",
                    state.retry.as_secs()
                );
                myself.send_after(state.retry, || SyncMessage::Retry);
                state.retry = (state.retry * 2).min(LONGEST_RETRY);
            } else {
                warn!("could not read the log ({why}); the next read tries again");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Takes the keys' changes and does nothing with them.
    struct Sink;

    #[ractor::async_trait]
    impl Actor for Sink {
        type Msg = SyncMessage;
        type State = ();
        type Arguments = ();
        async fn pre_start(&self, _: ActorRef<Self::Msg>, _: ()) -> Result<(), ActorProcessingErr> {
            Ok(())
        }
    }

    /// The observer's own settings, through its configuration handle: their place is its own agent's, the keys in
    /// force are what follow gives, and a document handed on is judged by the configuration actor, an unsigned one
    /// refused.
    #[tokio::test]
    async fn the_own_settings_are_the_agent_s_place_its_keys_in_force_and_its_judge() {
        let (sink, _) = Actor::spawn(None, Sink, ()).await.unwrap();
        let env: std::collections::HashMap<String, String> = [
            (
                "POLAR_SCHEDULER_STORE_KEY".to_string(),
                "store-key".to_string(),
            ),
            (
                "POLAR_SCHEDULER_WITNESS_KEY".to_string(),
                "witness-key".to_string(),
            ),
        ]
        .into();
        let configuration = polar_agent_builder::ConfigurationHandle::spawn(
            None,
            "polar-scheduler-observer",
            polar_env::Config::builder(&env)
                .register(&crate::settings::SECTION)
                .build(),
            None,
            sink.get_cell(),
        )
        .await
        .unwrap();
        let own = OwnConfiguration {
            agent: "polar-scheduler-observer".into(),
            configuration,
        };
        assert_eq!(
            own.place(),
            "permanent/polar-scheduler-observer/configuration.dhall"
        );
        assert_eq!(
            own.follow(&sink).await.unwrap(),
            (Some("store-key".into()), Some("witness-key".into()))
        );
        let outcome = own
            .submit(serde_json::json!({ "payload": {}, "signature": {} }))
            .await
            .unwrap();
        assert!(outcome.starts_with("Refused"), "{outcome}");
    }
}
