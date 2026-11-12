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

use polar_scheduler_observer::git_ops::{GitTls, Remote, copy_main};
use std::path::Path;
use tempfile::TempDir;

fn remote(path: &Path) -> Remote {
    Remote {
        url: format!("file://{}", path.display()),
        tls: GitTls::default(),
    }
}

/// A bare repository, as a server holds, with `main` as its branch.
fn bare(dir: &Path) -> git2::Repository {
    let mut options = git2::RepositoryInitOptions::new();
    options.bare(true).initial_head("main");
    git2::Repository::init_opts(dir, &options).unwrap()
}

/// A commit on `main` of `repo`. Says its id.
fn commit(repo: &git2::Repository, message: &str) -> git2::Oid {
    let sig = git2::Signature::now("test", "test@test.com").unwrap();
    let tree = repo
        .find_tree(repo.treebuilder(None).unwrap().write().unwrap())
        .unwrap();
    let parent = repo
        .find_reference("refs/heads/main")
        .ok()
        .map(|r| r.peel_to_commit().unwrap());
    let parents: Vec<&git2::Commit> = parent.iter().collect();
    repo.commit(
        Some("refs/heads/main"),
        &sig,
        &sig,
        message,
        &tree,
        &parents,
    )
    .unwrap()
}

fn head(repo: &git2::Repository) -> Option<git2::Oid> {
    repo.find_reference("refs/heads/main")
        .ok()
        .and_then(|r| r.target())
}

/// A commit on `main` of `repo` whose tree holds one file.
#[test]
fn the_history_is_copied_to_an_empty_repository_with_the_same_ids() {
    let (from, to, work) = (
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
    );
    let source = bare(from.path());
    let target = bare(to.path());
    let first = commit(&source, "one");
    let second = commit(&source, "two");
    copy_main(&remote(from.path()), &remote(to.path()), work.path()).unwrap();
    assert_eq!(head(&target), Some(second));
    assert!(
        target.find_commit(first).is_ok(),
        "the whole history, since each commit is judged"
    );
}

#[test]
fn copying_again_takes_what_is_new_and_changes_nothing_otherwise() {
    let (from, to, work) = (
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
    );
    let source = bare(from.path());
    let target = bare(to.path());
    commit(&source, "one");
    copy_main(&remote(from.path()), &remote(to.path()), work.path()).unwrap();
    let again = copy_main(&remote(from.path()), &remote(to.path()), work.path()).unwrap();
    assert_eq!(Some(again), head(&target).map(|id| id.to_string()));
    let second = commit(&source, "two");
    copy_main(&remote(from.path()), &remote(to.path()), work.path()).unwrap();
    assert_eq!(head(&target), Some(second));
}

/// It only ever moves `main` forward: a target that has gone its own way is not overwritten.
#[test]
fn a_target_that_has_diverged_is_left_alone_and_reported() {
    let (from, to, work) = (
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
    );
    let source = bare(from.path());
    let target = bare(to.path());
    commit(&source, "one");
    let theirs = commit(&target, "someone else's");
    assert!(copy_main(&remote(from.path()), &remote(to.path()), work.path()).is_err());
    assert_eq!(head(&target), Some(theirs));
}

#[test]
fn a_source_that_cannot_be_read_is_an_error_and_changes_nothing() {
    let (to, work) = (TempDir::new().unwrap(), TempDir::new().unwrap());
    let target = bare(to.path());
    let missing = to.path().join("nothing-here");
    assert!(copy_main(&remote(&missing), &remote(to.path()), work.path()).is_err());
    assert_eq!(head(&target), None);
}
