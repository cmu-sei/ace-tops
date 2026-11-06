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

//! What a pull brings into the checkout reaches the scheduler: after each pull the watcher rescans, and publishes each file
//! whose text changed, each created, and each gone, once (bite 6's live check on u7c found pushed documents undelivered:
//! docs/architecture/http-observers.md). A record that a migration was applied, under `migrations/`, is a schedule file too.

use cassini_client::TcpClientMessage;
use polar_scheduler_common::{
    ConfigurationNotification, GitScheduleChange, SCHEDULER_IN_TOPIC, configuration_topic,
};
use polar_scheduler_observer::watcher::{GitWatcherActor, GitWatcherMsg};
use ractor::{Actor, ActorProcessingErr, ActorRef};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

type Published = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

struct Cassini(Published);

#[ractor::async_trait]
impl Actor for Cassini {
    type Msg = TcpClientMessage;
    type State = Published;
    type Arguments = ();
    async fn pre_start(
        &self,
        _: ActorRef<Self::Msg>,
        _: (),
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(self.0.clone())
    }
    async fn handle(
        &self,
        _: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        if let TcpClientMessage::Publish { topic, payload, .. } = message {
            state.lock().unwrap().push((topic, payload));
        }
        Ok(())
    }
}

fn document(kind: &str, id: &str, agent: &str, version: u64, extra: &str) -> String {
    format!(
        r#"{{ payload = {{ type = "{kind}", id = "{id}", target = {{ agent = "{agent}" }}, version = {version}{extra} }}
           , signature = {{ algorithm = "ed25519", value = "AAAA", certificate_chain = [ "x" ] }} }}"#
    )
}

fn settings(id: &str, agent: &str, version: u64) -> String {
    document(
        "configuration",
        id,
        agent,
        version,
        ", changes = [] : List { name : Text, value : Text }",
    )
}

fn write(dir: &Path, relative: &str, text: &str) {
    let path = dir.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// What the watcher sent the scheduler, as changes, in order.
fn changes(published: &Published) -> Vec<GitScheduleChange> {
    published
        .lock()
        .unwrap()
        .iter()
        .filter(|(topic, _)| topic == SCHEDULER_IN_TOPIC)
        .map(|(_, payload)| {
            rkyv::from_bytes::<GitScheduleChange, rkyv::rancor::Error>(payload).unwrap()
        })
        .collect()
}

fn file_of(change: &GitScheduleChange) -> (&'static str, String) {
    let (kind, path) = match change {
        GitScheduleChange::Create { path, .. } => ("create", path),
        GitScheduleChange::Update { path, .. } => ("update", path),
        GitScheduleChange::Delete { path } => ("delete", path),
    };
    (
        kind,
        Path::new(path)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
    )
}

async fn settle() {
    tokio::time::sleep(Duration::from_secs(2)).await;
}

#[tokio::test]
async fn what_a_pull_changes_is_published_once_by_the_rescan_that_follows_it() {
    let dir = tempfile::Builder::new()
        .prefix("checkout")
        .tempdir()
        .unwrap();
    write(
        dir.path(),
        "permanent/a.dhall",
        &settings("item-a", "agent-a", 2),
    );
    write(
        dir.path(),
        "permanent/b.dhall",
        &settings("item-b", "agent-b", 1),
    );
    write(dir.path(), "README.md", "not a schedule");
    let published = Arc::new(Mutex::new(Vec::new()));
    let (cassini, _) = Actor::spawn(None, Cassini(published.clone()), ())
        .await
        .unwrap();
    let (watcher, _) = Actor::spawn(
        None,
        GitWatcherActor,
        (dir.path().to_string_lossy().into_owned(), cassini),
    )
    .await
    .unwrap();
    watcher.cast(GitWatcherMsg::PerformInitialScan).unwrap();
    settle().await;
    let mut first: Vec<(&str, String)> = changes(&published).iter().map(file_of).collect();
    first.sort();
    assert_eq!(
        first,
        [
            ("create", "a.dhall".to_string()),
            ("create", "b.dhall".to_string())
        ]
    );

    // What a pull does to the checkout: a document changed, a record of an applied migration added, a document gone.
    write(
        dir.path(),
        "permanent/a.dhall",
        &settings("item-a", "agent-a", 3),
    );
    write(
        dir.path(),
        "migrations/agent-a/m1.applied.dhall",
        &document(
            "migration-applied",
            "m1-applied",
            "agent-a",
            1,
            r#", section = "repositories", migration = { id = "m1", sha256 = "aa" }, applied_at_unix_secs = 1, report = "done""#,
        ),
    );
    std::fs::remove_file(dir.path().join("permanent/b.dhall")).unwrap();
    watcher.cast(GitWatcherMsg::Rescan).unwrap();
    settle().await;
    let mut after: Vec<(&str, String)> = changes(&published)[2..].iter().map(file_of).collect();
    after.sort();
    assert_eq!(
        after,
        [
            ("create", "m1.applied.dhall".to_string()),
            ("delete", "b.dhall".to_string()),
            ("update", "a.dhall".to_string()),
        ]
    );

    // Nothing changed: nothing published.
    let before = changes(&published).len();
    watcher.cast(GitWatcherMsg::Rescan).unwrap();
    settle().await;
    assert_eq!(changes(&published).len(), before);

    // A replay serves the checkout as it is now.
    watcher
        .cast(GitWatcherMsg::Replay {
            agent: "agent-a".to_string(),
        })
        .unwrap();
    settle().await;
    let sent: Vec<String> = published
        .lock()
        .unwrap()
        .iter()
        .filter(|(topic, _)| *topic == configuration_topic("agent-a"))
        .map(|(_, payload)| {
            rkyv::from_bytes::<ConfigurationNotification, rkyv::rancor::Error>(payload)
                .unwrap()
                .document_json
        })
        .collect();
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert!(sent.iter().any(|d| d.contains("\"version\":3")), "{sent:?}");
    assert!(
        sent.iter().any(|d| d.contains("migration-applied")),
        "{sent:?}"
    );
}

/// A watcher over `checkout`, publishing to a broker that keeps what it is sent.
async fn watching(checkout: &Path) -> (ActorRef<GitWatcherMsg>, Published) {
    let published = Arc::new(Mutex::new(Vec::new()));
    let (cassini, _) = Actor::spawn(None, Cassini(published.clone()), ())
        .await
        .unwrap();
    let (watcher, _) = Actor::spawn(
        None,
        GitWatcherActor,
        (checkout.to_string_lossy().into_owned(), cassini),
    )
    .await
    .unwrap();
    (watcher, published)
}

fn files(published: &Published) -> Vec<(&'static str, String)> {
    let mut files: Vec<_> = changes(published).iter().map(file_of).collect();
    files.sort();
    files
}

/// A schedule is a Dhall file under `permanent`, `adhoc`, `ephemeral` or `migrations` in the checkout. A Dhall file
/// anywhere else, or another file in one of them, is not, though it would evaluate; nor is one in a hidden folder such
/// as `.git`; and a folder of that name above the checkout does not count.
#[tokio::test]
async fn only_a_dhall_file_under_a_schedule_folder_of_the_checkout_is_read() {
    let above = tempfile::tempdir().unwrap();
    let checkout = above.path().join("permanent").join("checkout");
    let text = settings("item", "agent-a", 1);
    for schedule in [
        "permanent/a.dhall",
        "adhoc/b.dhall",
        "ephemeral/c.dhall",
        "migrations/agent-a/d.dhall",
    ] {
        write(&checkout, schedule, &text);
    }
    for not_one in [
        "e.dhall",
        "other/f.dhall",
        "permanent/g.txt",
        "permanently/h.dhall",
        ".git/permanent/i.dhall",
        "permanent/.hidden/j.dhall",
    ] {
        write(&checkout, not_one, &text);
    }
    let (watcher, published) = watching(&checkout).await;
    watcher.cast(GitWatcherMsg::PerformInitialScan).unwrap();
    settle().await;
    assert_eq!(
        files(&published),
        [
            ("create", "a.dhall".to_string()),
            ("create", "b.dhall".to_string()),
            ("create", "c.dhall".to_string()),
            ("create", "d.dhall".to_string()),
        ]
    );
}

/// Before the first scan there is nothing to compare with: a rescan asked for then reads nothing, and the first scan
/// still publishes each file once.
#[tokio::test]
async fn a_rescan_asked_for_before_the_first_scan_does_nothing() {
    let dir = tempfile::Builder::new()
        .prefix("checkout")
        .tempdir()
        .unwrap();
    write(
        dir.path(),
        "permanent/a.dhall",
        &settings("item-a", "agent-a", 1),
    );
    let (watcher, published) = watching(dir.path()).await;
    watcher.cast(GitWatcherMsg::Rescan).unwrap();
    settle().await;
    assert_eq!(files(&published), []);
    watcher.cast(GitWatcherMsg::PerformInitialScan).unwrap();
    settle().await;
    assert_eq!(files(&published), [("create", "a.dhall".to_string())]);
}

/// A checkout no pull changes (a local directory) is watched on disk: a schedule written there is published with no
/// message asking for a rescan.
#[tokio::test]
async fn a_schedule_written_on_disk_is_published_without_a_pull() {
    let dir = tempfile::Builder::new()
        .prefix("checkout")
        .tempdir()
        .unwrap();
    std::fs::create_dir_all(dir.path().join("permanent")).unwrap();
    let (watcher, published) = watching(dir.path()).await;
    watcher.cast(GitWatcherMsg::PerformInitialScan).unwrap();
    settle().await;
    assert_eq!(files(&published), []);
    write(
        dir.path(),
        "permanent/a.dhall",
        &settings("item-a", "agent-a", 1),
    );
    for _ in 0..20 {
        if !files(&published).is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(files(&published), [("create", "a.dhall".to_string())]);
}

/// Hidden folders inside the checkout are skipped, and the checkout itself is read whatever it is named: one whose
/// folder starts with a dot was skipped whole, so nothing in it was ever published.
#[tokio::test]
async fn a_checkout_whose_folder_starts_with_a_dot_is_read() {
    let above = tempfile::tempdir().unwrap();
    let checkout = above.path().join(".schedules");
    write(
        &checkout,
        "permanent/a.dhall",
        &settings("item-a", "agent-a", 1),
    );
    let (watcher, published) = watching(&checkout).await;
    watcher.cast(GitWatcherMsg::PerformInitialScan).unwrap();
    settle().await;
    assert_eq!(files(&published), [("create", "a.dhall".to_string())]);
}
