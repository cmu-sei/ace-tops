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

//! The sync actor keeps the checkout as the store's schedules log says polar-schedules is (docs/architecture/
//! record-store.md, "Bite 6"), asked through a store scripted here, which signs and co-signs its checkpoints as the
//! store and the witness would.

use p256::ecdsa::SigningKey;
use polar_git_server_common::LogRead;
use polar_git_server_common::schedules::Change;
use polar_log::checkpoint::{Checkpoint, Cosigner, NoteSigner};
use polar_log::entry::{Entry, Leaf};
use polar_log::merkle::{leaf_hash, root};
use polar_scheduler_observer::reads::ReadsLog;
use polar_scheduler_observer::sync_actor::{GitSyncActor, GitSyncArgs, OwnSettings, SyncMessage};
use ractor::{Actor, ActorRef};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

const ORIGIN: &str = "polar-git-server.polar.serviceaccount.cluster.local";
const WITNESS: &str = "attestation-agent.polar.serviceaccount.cluster.local/witness";
const OWN: &str = "permanent/polar-scheduler-observer/configuration.dhall";

fn signer() -> NoteSigner {
    NoteSigner::new(
        &format!("{ORIGIN}/checkpoint"),
        SigningKey::from_slice(&[3; 32]).unwrap(),
    )
    .unwrap()
}

fn cosigner(seed: u8) -> Cosigner {
    Cosigner::new(WITNESS, SigningKey::from_slice(&[seed; 32]).unwrap()).unwrap()
}

fn leaf(change: Change) -> Vec<u8> {
    let entry: Entry = change.entry("3.1.0 x86_64-unknown-linux-musl");
    Leaf {
        entry: entry.encode(),
        admitted_at_ms: 1,
        submitter: "alice".into(),
    }
    .encode()
}

fn file(path: &str, text: &str) -> Vec<u8> {
    leaf(Change::File {
        path: path.into(),
        bytes: text.into(),
    })
}

/// What the scripted store holds: its leaves, how far the witness co-signed them (none: never), and with which key.
struct Held {
    leaves: Vec<Vec<u8>>,
    witnessed: Option<usize>,
    witness: Cosigner,
}

/// A store, answering as the real one does: up to the co-signed checkpoint and none past it, or the store's own
/// checkpoint of everything when the witness never co-signed; `page` leaves at most to an answer. Scripted failures go
/// first.
struct Store {
    held: Mutex<Held>,
    page: usize,
    failures: Mutex<VecDeque<Result<LogRead, String>>>,
    asked: Mutex<Vec<u64>>,
}

impl Store {
    fn new(leaves: Vec<Vec<u8>>, witnessed: Option<usize>, page: usize) -> Arc<Self> {
        Arc::new(Self {
            held: Mutex::new(Held {
                leaves,
                witnessed,
                witness: cosigner(9),
            }),
            page,
            failures: Mutex::default(),
            asked: Mutex::default(),
        })
    }

    fn set(&self, leaves: Vec<Vec<u8>>, witnessed: Option<usize>) {
        let mut held = self.held.lock().unwrap();
        held.leaves = leaves;
        held.witnessed = witnessed;
    }
}

#[ractor::async_trait]
impl ReadsLog for Store {
    async fn read_log(&self, log: &str, from: u64) -> Result<LogRead, String> {
        assert_eq!(log, "schedules");
        self.asked.lock().unwrap().push(from);
        if let Some(failure) = self.failures.lock().unwrap().pop_front() {
            return failure;
        }
        let held = self.held.lock().unwrap();
        let size = held.witnessed.unwrap_or(held.leaves.len());
        let hashes: Vec<_> = held.leaves[..size].iter().map(|l| leaf_hash(l)).collect();
        let text = Checkpoint {
            origin: format!("{ORIGIN}/schedules"),
            size: size as u64,
            root: root(&hashes),
        }
        .text();
        let mut checkpoint = signer().sign(&text);
        if held.witnessed.is_some() {
            checkpoint.push_str(&held.witness.cosign_line(&text, 1_700_000_000));
        }
        let from = from as usize;
        Ok(LogRead::Entries {
            checkpoint,
            leaves: held.leaves[from.min(size)..size.min(from + self.page)].to_vec(),
            witnessed: held.witnessed.is_some(),
        })
    }
}

/// The observer's own settings, as a test sees them: each document submitted is kept, and the keys are what the test
/// says.
#[derive(Default)]
struct Own {
    submitted: Mutex<Vec<serde_json::Value>>,
}

#[ractor::async_trait]
impl OwnSettings for Own {
    fn place(&self) -> String {
        OWN.to_string()
    }
    async fn submit(&self, document: serde_json::Value) -> Result<String, String> {
        self.submitted.lock().unwrap().push(document);
        Ok("applied".into())
    }
    async fn follow(
        &self,
        _: &ActorRef<SyncMessage>,
    ) -> Result<(Option<String>, Option<String>), String> {
        Ok((None, None))
    }
}

struct Syncing {
    actor: ActorRef<SyncMessage>,
    handle: ractor::concurrency::JoinHandle<()>,
    told: Arc<AtomicUsize>,
    own: Arc<Own>,
}

async fn syncing(checkout: &std::path::Path, store: Arc<Store>) -> Syncing {
    let told = Arc::new(AtomicUsize::new(0));
    let counted = told.clone();
    let own = Arc::new(Own::default());
    let (actor, handle) = Actor::spawn(
        None,
        GitSyncActor,
        GitSyncArgs {
            repo_path: checkout.to_path_buf(),
            log: "schedules".into(),
            reads: store,
            interval: None,
            pulled: Some(Arc::new(move || {
                counted.fetch_add(1, SeqCst);
            })),
            own: own.clone(),
        },
    )
    .await
    .expect("GitSyncActor should spawn");
    Syncing {
        actor,
        handle,
        told,
        own,
    }
}

/// Pins the store's and the witness's keys, as the observer's configuration actor would on applying its settings.
fn pin(actor: &ActorRef<SyncMessage>, witness: &Cosigner) {
    actor
        .cast(SyncMessage::StoreKey(Some(signer().verifier_key())))
        .unwrap();
    actor
        .cast(SyncMessage::WitnessKey(Some(witness.verifier_key())))
        .unwrap();
}

async fn until(what: impl Fn() -> bool) {
    for _ in 0..80 {
        if what() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(200)).await;
}

/// A fresh cluster: the witness has never co-signed the log and the observer holds no keys, so the log is written as
/// the store's word, as `main` was before it; and the observer's own settings in it are handed to its configuration
/// actor.
#[tokio::test]
async fn a_log_never_witnessed_is_written_as_the_stores_word_until_keys_are_pinned() {
    let work = TempDir::new().unwrap();
    let checkout = work.path().join("checkout");
    let store = Store::new(
        vec![
            file("permanent/a/configuration.dhall", "1"),
            file(OWN, "{ x = 1 }"),
        ],
        None,
        10,
    );
    let s = syncing(&checkout, store.clone()).await;
    s.actor.cast(SyncMessage::Now).unwrap();
    until(|| s.told.load(SeqCst) == 1).await;
    assert!(checkout.join("permanent/a/configuration.dhall").exists());
    assert_eq!(
        *s.own.submitted.lock().unwrap(),
        [serde_json::json!({ "x": 1 })]
    );

    // Pinned now: what the witness has not co-signed is not taken, however much the store adds.
    pin(&s.actor, &cosigner(9));
    store.set(
        vec![
            file("permanent/a/configuration.dhall", "1"),
            file(OWN, "{ x = 1 }"),
            file("permanent/b/configuration.dhall", "2"),
        ],
        None,
    );
    s.actor.cast(SyncMessage::Now).unwrap();
    settle().await;
    assert!(!checkout.join("permanent/b/configuration.dhall").exists());

    // Co-signed, it is held to the keys and written, the leaves taken before among what the root covers.
    store.set(
        vec![
            file("permanent/a/configuration.dhall", "1"),
            file(OWN, "{ x = 1 }"),
            file("permanent/b/configuration.dhall", "2"),
        ],
        Some(3),
    );
    s.actor.cast(SyncMessage::Now).unwrap();
    until(|| checkout.join("permanent/b/configuration.dhall").exists()).await;
    assert!(checkout.join("permanent/b/configuration.dhall").exists());
    assert_eq!(
        s.own.submitted.lock().unwrap().len(),
        1,
        "unchanged, not handed again"
    );
    s.actor.stop(None);
    s.handle.await.unwrap();
}

/// A started observer on a witnessed log holds no keys yet: it writes nothing, hands its own settings on, and once the
/// keys they pin arrive it reads the log again, page by page, holds it to them and writes it.
#[tokio::test]
async fn a_witnessed_log_is_written_only_once_the_keys_it_is_held_to_are_pinned() {
    let work = TempDir::new().unwrap();
    let checkout = work.path().join("checkout");
    let store = Store::new(
        vec![
            file(OWN, "{ x = 2 }"),
            file("a.dhall", "1"),
            file("b.dhall", "2"),
            leaf(Change::Removal {
                path: "a.dhall".into(),
            }),
        ],
        Some(4),
        1,
    );
    let s = syncing(&checkout, store.clone()).await;
    s.actor.cast(SyncMessage::Now).unwrap();
    until(|| !s.own.submitted.lock().unwrap().is_empty()).await;
    settle().await;
    assert_eq!(s.told.load(SeqCst), 0, "nothing written without the keys");
    assert!(!checkout.exists() || std::fs::read_dir(&checkout).unwrap().next().is_none());

    store.asked.lock().unwrap().clear();
    pin(&s.actor, &cosigner(9));
    until(|| checkout.join("b.dhall").exists()).await;
    assert!(checkout.join("b.dhall").exists());
    assert!(
        !checkout.join("a.dhall").exists(),
        "removed after it was written"
    );
    // Each key's arrival asks for a read: the first asks page by page and stops at the checkpoint's size, the second
    // asks once from there.
    until(|| store.asked.lock().unwrap().len() >= 5).await;
    settle().await;
    assert_eq!(
        *store.asked.lock().unwrap(),
        [0, 1, 2, 3, 4],
        "each page asked once"
    );
    s.actor.stop(None);
    s.handle.await.unwrap();
}

/// A checkpoint the pinned witness did not co-sign is not taken, and the observer goes on.
#[tokio::test]
async fn a_checkpoint_another_witness_co_signed_is_not_taken() {
    let work = TempDir::new().unwrap();
    let checkout = work.path().join("checkout");
    let store = Store::new(vec![file("a.dhall", "1")], Some(1), 10);
    let s = syncing(&checkout, store.clone()).await;
    pin(&s.actor, &cosigner(7));
    s.actor.cast(SyncMessage::Now).unwrap();
    settle().await;
    assert_eq!(s.told.load(SeqCst), 0);
    assert!(!checkout.join("a.dhall").exists());
    assert!(!s.handle.is_finished(), "the observer goes on");
    s.actor.stop(None);
    s.handle.await.unwrap();
}

/// A log that is not the one held, whose leaves do not make the witnessed root, ends the observer.
#[tokio::test]
async fn a_log_that_is_not_the_one_held_ends_the_observer() {
    let work = TempDir::new().unwrap();
    let checkout = work.path().join("checkout");
    let store = Store::new(vec![file("a.dhall", "1")], Some(1), 10);
    let s = syncing(&checkout, store.clone()).await;
    pin(&s.actor, &cosigner(9));
    until(|| checkout.join("a.dhall").exists()).await;
    // The store rewrites its first leaf and co-signs the rewritten log of two.
    store.set(
        vec![file("a.dhall", "other"), file("b.dhall", "2")],
        Some(2),
    );
    s.actor.cast(SyncMessage::Now).unwrap();
    tokio::time::timeout(Duration::from_secs(5), s.handle)
        .await
        .expect("the observer ends")
        .unwrap();
    assert!(!checkout.join("b.dhall").exists());
}

/// A critical entry of a type the observer does not know stops the tree there: the checkout holds what came before.
#[tokio::test]
async fn an_unknown_critical_entry_stops_the_tree_there() {
    let work = TempDir::new().unwrap();
    let checkout = work.path().join("checkout");
    let mut unknown: Entry = Change::File {
        path: "x".into(),
        bytes: b"x".to_vec(),
    }
    .entry("w");
    unknown.kind = "schedules-something-newer".into();
    let unknown = Leaf {
        entry: unknown.encode(),
        admitted_at_ms: 1,
        submitter: "alice".into(),
    }
    .encode();
    let store = Store::new(
        vec![file("a.dhall", "1"), unknown, file("b.dhall", "2")],
        Some(3),
        10,
    );
    let s = syncing(&checkout, store).await;
    pin(&s.actor, &cosigner(9));
    until(|| s.told.load(SeqCst) == 1).await;
    assert!(checkout.join("a.dhall").exists());
    assert!(!checkout.join("b.dhall").exists());
    s.actor.stop(None);
    s.handle.await.unwrap();
}

/// A refusal before any read was answered (this workload may not read the log) cannot change by asking again: it ends
/// the actor, and the observer with it.
#[tokio::test]
async fn a_refusal_of_the_first_read_ends_the_actor() {
    let dir = TempDir::new().unwrap();
    let store = Store::new(vec![], None, 10);
    store
        .failures
        .lock()
        .unwrap()
        .push_back(Ok(LogRead::Refused {
            why: "polar-scheduler-observer may not read the log schedules".into(),
        }));
    let s = syncing(dir.path(), store).await;
    s.actor.cast(SyncMessage::Now).unwrap();
    tokio::time::timeout(Duration::from_secs(5), s.handle)
        .await
        .expect("the actor ends")
        .unwrap();
}

/// A first read nothing answered (the store is not up yet) is asked again, unbidden, until it is answered; an empty log
/// is written as an empty checkout, which starts the watcher.
#[tokio::test]
async fn an_unanswered_first_read_is_asked_again_until_it_is_answered() {
    let work = TempDir::new().unwrap();
    let checkout = work.path().join("checkout");
    let store = Store::new(vec![], None, 10);
    store
        .failures
        .lock()
        .unwrap()
        .push_back(Err("timed out waiting for a reply".into()));
    let s = syncing(&checkout, store.clone()).await;
    s.actor.cast(SyncMessage::Now).unwrap();
    for _ in 0..80 {
        if s.told.load(SeqCst) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        s.told.load(SeqCst),
        1,
        "asked again after its wait, and answered"
    );
    assert_eq!(*store.asked.lock().unwrap(), [0, 0]);
    s.actor.stop(None);
    s.handle.await.unwrap();
}

/// Nothing new: nothing is written again, and nothing is told.
#[tokio::test]
async fn a_log_that_did_not_grow_leaves_the_checkout_alone() {
    let work = TempDir::new().unwrap();
    let checkout = work.path().join("checkout");
    let store = Store::new(vec![file("a.dhall", "1")], Some(1), 10);
    let s = syncing(&checkout, store.clone()).await;
    pin(&s.actor, &cosigner(9));
    until(|| s.told.load(SeqCst) == 1).await;
    s.actor.cast(SyncMessage::Now).unwrap();
    s.actor.cast(SyncMessage::Tick).unwrap();
    settle().await;
    assert_eq!(s.told.load(SeqCst), 1);
    assert_eq!(
        store.asked.lock().unwrap().last(),
        Some(&1),
        "asked from what it holds"
    );
    s.actor.stop(None);
    s.handle.await.unwrap();
}

/// A refusal after a read was answered is said, and the observer goes on: what it holds is still the log's word.
#[tokio::test]
async fn a_refusal_after_the_first_answer_does_not_end_the_observer() {
    let work = TempDir::new().unwrap();
    let checkout = work.path().join("checkout");
    let store = Store::new(vec![file("a.dhall", "1")], None, 10);
    let s = syncing(&checkout, store.clone()).await;
    s.actor.cast(SyncMessage::Now).unwrap();
    until(|| s.told.load(SeqCst) == 1).await;
    store
        .failures
        .lock()
        .unwrap()
        .push_back(Ok(LogRead::Refused {
            why: "no longer a reader".into(),
        }));
    s.actor.cast(SyncMessage::Now).unwrap();
    until(|| store.failures.lock().unwrap().is_empty()).await;
    settle().await;
    assert!(!s.handle.is_finished(), "the observer goes on");
    assert!(checkout.join("a.dhall").exists());
    s.actor.stop(None);
    s.handle.await.unwrap();
}

/// Before any key, a log never witnessed that grows is written again with what it grew by.
#[tokio::test]
async fn a_log_never_witnessed_that_grows_is_written_again_before_any_key() {
    let work = TempDir::new().unwrap();
    let checkout = work.path().join("checkout");
    let store = Store::new(vec![file("a.dhall", "1")], None, 10);
    let s = syncing(&checkout, store.clone()).await;
    s.actor.cast(SyncMessage::Now).unwrap();
    until(|| s.told.load(SeqCst) == 1).await;
    store.set(vec![file("a.dhall", "1"), file("b.dhall", "2")], None);
    s.actor.cast(SyncMessage::Now).unwrap();
    until(|| checkout.join("b.dhall").exists()).await;
    assert!(checkout.join("b.dhall").exists());
    assert_eq!(s.told.load(SeqCst), 2);
    s.actor.stop(None);
    s.handle.await.unwrap();
}
