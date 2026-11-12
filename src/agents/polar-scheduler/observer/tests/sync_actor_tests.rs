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

//! The sync actor keeps the checkout as the git server says main is, asked through a reader scripted here as the server
//! would answer over Cassini.

use polar_git_server_common::{FileAt, FileKind, MainRead};
use polar_scheduler_observer::reads::ReadsMain;
use polar_scheduler_observer::sync_actor::{GitSyncActor, GitSyncArgs, SyncMessage};
use ractor::{Actor, ActorRef};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

/// Answers each read with the next of its answers, and with "unchanged" once they are spent; and keeps what it was asked.
#[derive(Default)]
struct Scripted {
    answers: Mutex<VecDeque<Result<MainRead, String>>>,
    asked: Mutex<Vec<(String, Option<String>)>>,
}

impl Scripted {
    fn with(answers: Vec<Result<MainRead, String>>) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.into()),
            asked: Mutex::default(),
        })
    }
}

#[ractor::async_trait]
impl ReadsMain for Scripted {
    async fn read_main(
        &self,
        repo: &str,
        _paths: &[String],
        have: Option<&str>,
    ) -> Result<MainRead, String> {
        self.asked
            .lock()
            .unwrap()
            .push((repo.to_string(), have.map(str::to_string)));
        self.answers
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(MainRead::Unchanged {
                commit: "unchanged".into(),
            }))
    }
}

fn files(commit: &str, names: &[&str]) -> Result<MainRead, String> {
    Ok(MainRead::Files {
        commit: commit.into(),
        files: names
            .iter()
            .map(|n| FileAt {
                path: n.to_string(),
                kind: FileKind::Plain,
                content: b"1".to_vec(),
            })
            .collect(),
    })
}

async fn syncing(
    checkout: &std::path::Path,
    reads: Arc<Scripted>,
    interval: Option<Duration>,
) -> (
    ActorRef<SyncMessage>,
    ractor::concurrency::JoinHandle<()>,
    Arc<AtomicUsize>,
) {
    let told = Arc::new(AtomicUsize::new(0));
    let counted = told.clone();
    let (actor, handle) = Actor::spawn(
        None,
        GitSyncActor,
        GitSyncArgs {
            repo_path: checkout.to_path_buf(),
            repo: "polar-schedules".into(),
            reads,
            interval,
            // Each read that brings the checkout up to date is told, so the watcher reads what it brought.
            pulled: Some(Arc::new(move || {
                counted.fetch_add(1, SeqCst);
            })),
        },
    )
    .await
    .expect("GitSyncActor should spawn");
    (actor, handle, told)
}

async fn until(what: impl Fn() -> bool) {
    for _ in 0..80 {
        if what() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn test_sync_actor_spawns() {
    let dir = TempDir::new().unwrap();
    let (actor, handle, _) = syncing(
        dir.path(),
        Scripted::with(vec![]),
        Some(Duration::from_secs(3600)),
    )
    .await;
    actor.stop(None);
    handle.await.unwrap();
}

/// A read that fails (nothing answered) is said and does not end the actor.
#[tokio::test]
async fn test_sync_actor_receives_tick_unanswered() {
    let dir = TempDir::new().unwrap();
    let reads = Scripted::with(vec![Err("timed out waiting for a reply".into())]);
    let (actor, handle, told) = syncing(dir.path(), reads, Some(Duration::from_secs(3600))).await;
    actor.cast(SyncMessage::Tick).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(told.load(SeqCst), 0);
    actor.stop(None);
    handle.await.unwrap();
}

#[tokio::test]
async fn test_sync_actor_multiple_ticks_no_crash() {
    let dir = TempDir::new().unwrap();
    let reads = Scripted::with(
        (0..5)
            .map(|_| Err("timed out waiting for a reply".into()))
            .collect(),
    );
    let (actor, handle, _) = syncing(dir.path(), reads, Some(Duration::from_secs(3600))).await;
    for _ in 0..5 {
        actor.cast(SyncMessage::Tick).unwrap();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    actor.stop(None);
    handle.await.unwrap();
}

/// With no interval at all, a `Now` is what brings a new commit in: the path the git server's announcement takes. Each
/// read gives the commit the checkout has.
#[tokio::test]
async fn test_sync_actor_pulls_when_told_and_never_on_its_own() {
    let work = TempDir::new().unwrap();
    let checkout = work.path().join("checkout");
    let reads = Scripted::with(vec![
        files("c1", &["first.dhall"]),
        files("c2", &["first.dhall", "second.dhall"]),
    ]);
    let (actor, handle, told) = syncing(&checkout, reads.clone(), None).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        reads.asked.lock().unwrap().is_empty(),
        "nothing asked it to read"
    );

    actor.cast(SyncMessage::Now).unwrap();
    until(|| checkout.join("first.dhall").exists()).await;
    assert!(checkout.join("first.dhall").exists());
    actor.cast(SyncMessage::Now).unwrap();
    until(|| checkout.join("second.dhall").exists()).await;
    assert!(
        checkout.join("second.dhall").exists(),
        "Now should read the new commit"
    );
    until(|| told.load(SeqCst) == 2).await;
    assert_eq!(
        told.load(SeqCst),
        2,
        "each read that changed the checkout is told"
    );
    assert_eq!(
        *reads.asked.lock().unwrap(),
        [
            ("polar-schedules".to_string(), None),
            ("polar-schedules".to_string(), Some("c1".to_string()))
        ]
    );

    actor.stop(None);
    handle.await.unwrap();
}

/// Main unchanged: nothing is written, and nothing is told.
#[tokio::test]
async fn an_unchanged_main_leaves_the_checkout_alone() {
    let work = TempDir::new().unwrap();
    let checkout = work.path().join("checkout");
    let reads = Scripted::with(vec![files("c1", &["first.dhall"])]);
    let (actor, handle, told) = syncing(&checkout, reads.clone(), None).await;
    actor.cast(SyncMessage::Now).unwrap();
    until(|| told.load(SeqCst) == 1).await;
    actor.cast(SyncMessage::Now).unwrap();
    until(|| reads.asked.lock().unwrap().len() == 2).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(told.load(SeqCst), 1);
    assert!(checkout.join("first.dhall").exists());
    actor.stop(None);
    handle.await.unwrap();
}

/// A refusal before any read was answered (this workload may not read the repository) cannot change by asking again:
/// it ends the actor, and the observer with it.
#[tokio::test]
async fn a_refusal_of_the_first_read_ends_the_actor() {
    let dir = TempDir::new().unwrap();
    let reads = Scripted::with(vec![Ok(MainRead::Refused {
        why: "polar-scheduler-observer may not read polar-schedules".into(),
    })]);
    let (actor, handle, _) = syncing(dir.path(), reads, None).await;
    actor.cast(SyncMessage::Now).unwrap();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("the actor ends")
        .unwrap();
}

/// A first read nothing answered (the server is not up yet) is asked again, unbidden, until it is answered.
#[tokio::test]
async fn an_unanswered_first_read_is_asked_again_until_it_is_answered() {
    let work = TempDir::new().unwrap();
    let checkout = work.path().join("checkout");
    let reads = Scripted::with(vec![
        Err("timed out waiting for a reply".into()),
        files("c1", &["first.dhall"]),
    ]);
    let (actor, handle, told) = syncing(&checkout, reads.clone(), None).await;
    actor.cast(SyncMessage::Now).unwrap();
    for _ in 0..80 {
        if told.load(SeqCst) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        told.load(SeqCst),
        1,
        "asked again after its wait, and answered"
    );
    assert!(checkout.join("first.dhall").exists());
    actor.stop(None);
    handle.await.unwrap();
}
