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

//! polar-schedules on the store's schedules log (docs/architecture/record-store.md, "Bite 6"). The repository is a tree
//! of files, so the log carries the changes that make its tree (`polar_git_server_common::schedules`): a push appends
//! what makes the log's tree the tree of `main`'s new tip, as the pusher's, before any ref moves; the store's start
//! appends what makes it `main`'s tree as it is, as the store's own, so the first start fills the log after an entry
//! naming the commit it carries on from, and a start after an older store took pushes catches the log up. A link is
//! never an entry: a push that brings one is refused, and one already there is left out and said.

use crate::logs::{LogsMessage, TreeAppended};
use crate::pktline::RefUpdate;
use crate::store::RepoStore;
use polar_git_server_common::schedules::SCHEDULES_LOG;
use polar_git_server_common::{FileAt, FileKind, SCHEDULES_REPO};
use polar_log::entry::Continuation;
use std::collections::BTreeMap;
use tracing::{info, warn};

/// The branch the scheduler observer reads, and the log holds.
const MAIN: &str = "refs/heads/main";

/// The files of a tree as the log holds them, by path, and the path of each link left out.
pub fn tree_of(files: Vec<FileAt>) -> (BTreeMap<String, Vec<u8>>, Vec<String>) {
    let mut tree = BTreeMap::new();
    let mut links = Vec::new();
    for file in files {
        if file.kind == FileKind::Link {
            links.push(file.path);
        } else {
            tree.insert(file.path, file.content);
        }
    }
    (tree, links)
}

/// The tree of `main`'s new tip, when the push moves `main`; none when it does not. `repo` holds the push's objects
/// in quarantine. A link refuses the push.
pub fn pushed_tree(
    repo: &gix::Repository,
    updates: &[RefUpdate],
) -> Result<Option<BTreeMap<String, Vec<u8>>>, String> {
    let Some(update) = updates.iter().find(|u| u.refname == MAIN) else {
        return Ok(None);
    };
    let new = gix::ObjectId::from_hex(update.new.as_bytes())
        .map_err(|e| format!("{} is not an object id: {e}", update.new))?;
    if new.is_null() {
        return Ok(Some(BTreeMap::new()));
    }
    let files = crate::store::files_of(repo, new, &[], usize::MAX)
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let (tree, links) = tree_of(files);
    if let Some(link) = links.first() {
        return Err(format!(
            "{link} is a link, and {SCHEDULES_REPO} takes none: nothing reads one"
        ));
    }
    Ok(Some(tree))
}

/// Appends what makes the schedules log's tree `main`'s, as `origin`'s, at the store's start: nothing when they agree
/// or the repository has no `main`. What was appended, or why the logs could not take it, which refuses the start.
pub async fn catch_up(
    store: &RepoStore,
    logs: &ractor::ActorRef<LogsMessage>,
    origin: &str,
) -> Result<TreeAppended, String> {
    if !store.exists(SCHEDULES_REPO) {
        return Ok(TreeAppended::default());
    }
    let Some((commit, commits, files)) = store
        .main_tree(SCHEDULES_REPO)
        .await
        .map_err(|e| format!("{SCHEDULES_REPO} cannot be read: {e}"))?
    else {
        return Ok(TreeAppended::default());
    };
    let (tree, links) = tree_of(files);
    for link in &links {
        warn!(path = %link, "a link in {SCHEDULES_REPO} is left out of the schedules log: nothing reads one");
    }
    let continues = Continuation {
        old_kind: "git".to_string(),
        alg: "sha1".to_string(),
        digest: commit.as_bytes().to_vec(),
        count: commits,
    };
    let done = ractor::call!(logs, |reply| LogsMessage::AppendTree {
        log: SCHEDULES_LOG.to_string(),
        to: tree,
        continues: Some(continues),
        submitter: origin.to_string(),
        strict: false,
        reply,
    })
    .map_err(|e| format!("the store's logs did not answer: {e}"))??;
    for (path, why) in &done.left_out {
        warn!(%path, %why, "a file of {SCHEDULES_REPO} is left out of the schedules log");
    }
    if !done.appended.is_empty() {
        info!(
            %commit,
            appended = done.appended.len(),
            "the schedules log was brought to {SCHEDULES_REPO}'s main"
        );
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logs::{LogsActor, LogsArgs};
    use polar_git_server_common::schedules::{Change, replay};
    use ractor::Actor;

    const ORIGIN: &str = "polar-git-server.polar.serviceaccount.cluster.local";

    async fn repository(dir: &std::path::Path, files: &[(&str, &str)]) -> RepoStore {
        let seed = dir.join("seed");
        for (path, text) in files {
            let at = seed.join(path);
            std::fs::create_dir_all(at.parent().unwrap()).unwrap();
            std::fs::write(at, text).unwrap();
        }
        let store = RepoStore::new(dir.join("repos"));
        store.create(SCHEDULES_REPO).await.unwrap();
        if !files.is_empty() {
            store.seed(SCHEDULES_REPO, &seed).await.unwrap();
        }
        store
    }

    async fn logs(dir: &std::path::Path) -> ractor::ActorRef<LogsMessage> {
        Actor::spawn(
            None,
            LogsActor,
            LogsArgs {
                root: dir.join("logs"),
                origin: ORIGIN.into(),
                signer: std::sync::Arc::new(crate::logs::testing::KeySigner::new(ORIGIN)),
            },
        )
        .await
        .unwrap()
        .0
    }

    async fn leaves(logs: &ractor::ActorRef<LogsMessage>) -> Vec<polar_log::entry::Leaf> {
        let mut leaves = Vec::new();
        for seq in 0.. {
            match ractor::call!(logs, |reply| LogsMessage::Leaf {
                log: SCHEDULES_LOG.into(),
                seq,
                reply
            })
            .unwrap()
            {
                Ok(Some(leaf)) => leaves.push(leaf),
                _ => break,
            }
        }
        leaves
    }

    /// docs/architecture/record-store.md, "Bite 6": the store's first start fills the log with `main`'s tree after an
    /// entry naming the commit and how many it held, as the store's own; a start again appends nothing.
    #[tokio::test]
    async fn the_first_start_fills_the_log_with_main_after_naming_it_and_the_next_adds_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = repository(
            dir.path(),
            &[("permanent/a/configuration.dhall", "1"), ("README.md", "r")],
        )
        .await;
        let logs = logs(dir.path()).await;
        let done = catch_up(&store, &logs, ORIGIN).await.unwrap();
        assert_eq!(done.appended, vec![0, 1, 2]);
        let held = leaves(&logs).await;
        assert!(held.iter().all(|l| l.submitter == ORIGIN));
        let first = polar_log::entry::Entry::decode(&held[0].entry).unwrap();
        let continues = Continuation::decode(&first.event).unwrap();
        let main = store.resolve_ref(SCHEDULES_REPO, MAIN).await.unwrap();
        assert_eq!(hex(&continues.digest), main);
        assert_eq!(
            (
                continues.old_kind.as_str(),
                continues.alg.as_str(),
                continues.count
            ),
            ("git", "sha1", 1)
        );
        let (tree, stop) = replay(&held.iter().map(|l| l.encode()).collect::<Vec<_>>());
        assert_eq!(stop, None);
        assert_eq!(
            tree.files().keys().collect::<Vec<_>>(),
            ["README.md", "permanent/a/configuration.dhall"]
        );
        assert_eq!(
            catch_up(&store, &logs, ORIGIN).await.unwrap(),
            TreeAppended::default()
        );
    }

    #[tokio::test]
    async fn a_repository_with_no_main_or_none_at_all_appends_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let logs = logs(dir.path()).await;
        let none = RepoStore::new(dir.path().join("none"));
        assert_eq!(
            catch_up(&none, &logs, ORIGIN).await.unwrap(),
            TreeAppended::default()
        );
        let empty = repository(dir.path(), &[]).await;
        assert_eq!(
            catch_up(&empty, &logs, ORIGIN).await.unwrap(),
            TreeAppended::default()
        );
        assert!(leaves(&logs).await.is_empty());
    }

    /// A start after the repository moved without the log (an older store took a push) appends the difference, a
    /// removal among it, and no second continuation.
    #[tokio::test]
    async fn a_start_after_the_repository_moved_without_the_log_catches_it_up() {
        let dir = tempfile::tempdir().unwrap();
        let store = repository(dir.path(), &[("a", "1"), ("b", "2")]).await;
        let logs = logs(dir.path()).await;
        catch_up(&store, &logs, ORIGIN).await.unwrap();
        // What an older store would have taken: a commit with `a` changed and `b` gone.
        let moved = TreeAppended {
            appended: vec![3, 4],
            left_out: vec![],
        };
        let seed = dir.path().join("moved");
        std::fs::create_dir_all(&seed).unwrap();
        std::fs::write(seed.join("a"), "2").unwrap();
        let other = RepoStore::new(dir.path().join("other"));
        other.create(SCHEDULES_REPO).await.unwrap();
        other.seed(SCHEDULES_REPO, &seed).await.unwrap();
        assert_eq!(catch_up(&other, &logs, ORIGIN).await.unwrap(), moved);
        let held = leaves(&logs).await;
        let changes: Vec<_> = held[3..]
            .iter()
            .map(|l| {
                Change::of(&polar_log::entry::Entry::decode(&l.entry).unwrap())
                    .unwrap()
                    .unwrap()
            })
            .collect();
        assert_eq!(
            changes,
            vec![
                Change::Removal { path: "b".into() },
                Change::File {
                    path: "a".into(),
                    bytes: b"2".to_vec()
                }
            ]
        );
    }

    /// A link is left out of the tree and named; every other file is in it with its bytes.
    #[test]
    fn a_link_is_left_out_of_the_tree_and_named() {
        let file = |path: &str, kind| FileAt {
            path: path.into(),
            kind,
            content: path.as_bytes().to_vec(),
        };
        let (tree, links) = tree_of(vec![
            file("a", FileKind::Plain),
            file("l", FileKind::Link),
            file("x", FileKind::Executable),
        ]);
        assert_eq!(tree.keys().collect::<Vec<_>>(), ["a", "x"]);
        assert_eq!(tree["x"], b"x");
        assert_eq!(links, ["l"]);
    }

    /// A push that does not move `main` gives no tree, since the log holds only what `main` holds.
    #[tokio::test]
    async fn a_push_that_does_not_move_main_gives_no_tree() {
        let dir = tempfile::tempdir().unwrap();
        let store = repository(dir.path(), &[("a", "1")]).await;
        let repo = gix::open(store.path(SCHEDULES_REPO).unwrap()).unwrap();
        let main = store.resolve_ref(SCHEDULES_REPO, MAIN).await.unwrap();
        let other = RefUpdate {
            old: "0".repeat(40),
            new: main.clone(),
            refname: "refs/heads/other".into(),
        };
        assert_eq!(
            pushed_tree(&repo, std::slice::from_ref(&other)).unwrap(),
            None
        );
        let moved = RefUpdate {
            refname: MAIN.into(),
            ..other
        };
        assert_eq!(
            pushed_tree(&repo, &[moved]).unwrap(),
            Some(BTreeMap::from([("a".to_string(), b"1".to_vec())]))
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
