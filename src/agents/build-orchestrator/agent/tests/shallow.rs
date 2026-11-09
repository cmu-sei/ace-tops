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

//! A git dependency as a shallow repository (D3a), from a real repository: it opens as a bare repository whose one ref is the
//! commit, which it holds with all of its tree, and none of the commit's history; and it is the same bytes made twice.

use build_orchestrator::shallow::{REF, repository};
use git2::{Repository, Signature, Time};
use std::path::Path;

/// A repository of two commits, the second with a file in a directory; the second's id, and the first's.
fn two_commits(dir: &Path) -> (Repository, String, String) {
    let repository = Repository::init_bare(dir).unwrap();
    let who = Signature::new("polar", "polar@example.org", &Time::new(1_800_000_000, 0)).unwrap();
    let commit = |files: &[(&str, &[u8])], parents: &[&git2::Commit<'_>]| {
        let mut tree = repository.treebuilder(None).unwrap();
        for (name, bytes) in files {
            tree.insert(name, repository.blob(bytes).unwrap(), 0o100644)
                .unwrap();
        }
        let mut sub = repository.treebuilder(None).unwrap();
        sub.insert(
            "lib.rs",
            repository.blob(b"pub fn x() {}\n").unwrap(),
            0o100644,
        )
        .unwrap();
        tree.insert("src", sub.write().unwrap(), 0o040000).unwrap();
        let tree = repository.find_tree(tree.write().unwrap()).unwrap();
        repository
            .commit(None, &who, &who, "a commit", &tree, parents)
            .unwrap()
    };
    let first = commit(&[("Cargo.toml", b"one\n")], &[]);
    let second = {
        let parent = repository.find_commit(first).unwrap();
        commit(&[("Cargo.toml", b"two\n")], &[&parent])
    };
    (repository, second.to_string(), first.to_string())
}

fn unpacked(bytes: &[u8], into: &Path) -> Repository {
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(bytes));
    tar.unpack(into).unwrap();
    Repository::open_bare(into).unwrap()
}

#[test]
fn a_dependency_is_its_commit_and_tree_and_none_of_its_history() {
    let dir = tempfile::tempdir().unwrap();
    let (origin, commit, parent) = two_commits(dir.path());
    let bytes = repository(&origin, &commit, usize::MAX).unwrap();
    assert_eq!(
        repository(&origin, &commit, usize::MAX).unwrap(),
        bytes,
        "the same bytes again"
    );
    let out = tempfile::tempdir().unwrap();
    let shallow = unpacked(&bytes, out.path());
    assert!(shallow.is_shallow());
    assert_eq!(
        shallow
            .find_reference(REF)
            .unwrap()
            .target()
            .unwrap()
            .to_string(),
        commit
    );
    assert_eq!(
        shallow.head().unwrap().target().unwrap().to_string(),
        commit
    );
    let found = shallow
        .find_commit(git2::Oid::from_str(&commit).unwrap())
        .unwrap();
    let tree = found.tree().unwrap();
    let lib = tree.get_path(Path::new("src/lib.rs")).unwrap();
    assert_eq!(
        shallow.find_blob(lib.id()).unwrap().content(),
        b"pub fn x() {}\n"
    );
    assert!(
        shallow
            .find_commit(git2::Oid::from_str(&parent).unwrap())
            .is_err(),
        "no history"
    );
}

#[test]
fn a_dependency_past_its_bound_or_not_in_the_repository_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (origin, commit, _) = two_commits(dir.path());
    assert!(
        repository(&origin, &commit, 10)
            .unwrap_err()
            .contains("bound")
    );
    assert!(
        repository(&origin, &"3".repeat(40), usize::MAX)
            .unwrap_err()
            .contains("no commit")
    );
    // And the clone is left as it was found.
    assert!(!origin.path().join("polar-shallow").exists());
}
