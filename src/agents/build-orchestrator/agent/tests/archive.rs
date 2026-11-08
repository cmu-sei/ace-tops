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

//! A build's source archive (O3b), from real repositories: it is the commit's tree, read back exactly by the fetch's own
//! `unpack`, the same bytes from any repository that holds the commit, and refused past its bound or when the fetch would
//! refuse it.

use build_orchestrator::archive::{ArchiveError, archive};
use git2::{Oid, Repository, Signature, Time};
use proptest::prelude::*;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    File(Vec<u8>),
    Executable(Vec<u8>),
    Link(String),
}

/// A tree: each file by its path.
type Files = BTreeMap<PathBuf, Kind>;

fn bare() -> (tempfile::TempDir, Repository) {
    let dir = tempfile::tempdir().unwrap();
    let repository = Repository::init_bare(dir.path()).unwrap();
    (dir, repository)
}

/// The tree of `files` under `under`, its entries inserted in `reversed` order or not: a tree's own order is git's.
fn tree_of(repository: &Repository, files: &Files, under: &Path, reversed: bool) -> Oid {
    let mut names: BTreeMap<String, Option<&Kind>> = BTreeMap::new();
    for (path, kind) in files {
        let Ok(rest) = path.strip_prefix(under) else {
            continue;
        };
        let mut parts = rest.components();
        let first = parts
            .next()
            .unwrap()
            .as_os_str()
            .to_string_lossy()
            .to_string();
        let leaf = parts.next().is_none();
        names.insert(first, if leaf { Some(kind) } else { None });
    }
    let mut builder = repository.treebuilder(None).unwrap();
    let mut entries: Vec<_> = names.into_iter().collect();
    if reversed {
        entries.reverse();
    }
    for (name, kind) in entries {
        match kind {
            Some(Kind::File(bytes)) => {
                builder.insert(&name, repository.blob(bytes).unwrap(), 0o100644)
            }
            Some(Kind::Executable(bytes)) => {
                builder.insert(&name, repository.blob(bytes).unwrap(), 0o100755)
            }
            Some(Kind::Link(target)) => {
                builder.insert(&name, repository.blob(target.as_bytes()).unwrap(), 0o120000)
            }
            None => builder.insert(
                &name,
                tree_of(repository, files, &under.join(&name), reversed),
                0o040000,
            ),
        }
        .unwrap();
    }
    builder.write().unwrap()
}

fn commit_of(repository: &Repository, tree: Oid) -> String {
    let who = Signature::new("polar", "polar@example.org", &Time::new(1_800_000_000, 0)).unwrap();
    let tree = repository.find_tree(tree).unwrap();
    repository
        .commit(None, &who, &who, "a commit", &tree, &[])
        .unwrap()
        .to_string()
}

/// What `dir` holds, as files by path, read as a build's pod would find it.
fn read_back(dir: &Path, under: &Path, into: &mut Files) {
    for entry in std::fs::read_dir(dir.join(under)).unwrap() {
        let entry = entry.unwrap();
        let path = under.join(entry.file_name());
        let meta = std::fs::symlink_metadata(entry.path()).unwrap();
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(entry.path()).unwrap();
            into.insert(path, Kind::Link(target.to_string_lossy().to_string()));
        } else if meta.is_dir() {
            read_back(dir, &path, into);
        } else {
            let bytes = std::fs::read(entry.path()).unwrap();
            let executable = meta.permissions().mode() & 0o111 != 0;
            into.insert(
                path,
                if executable {
                    Kind::Executable(bytes)
                } else {
                    Kind::File(bytes)
                },
            );
        }
    }
}

fn unpacked(bytes: &[u8]) -> Files {
    let work = tempfile::tempdir().unwrap();
    let file = work.path().join("source.tar.gz");
    std::fs::write(&file, bytes).unwrap();
    let into = work.path().join("workspace");
    std::fs::create_dir(&into).unwrap();
    build_fetch::unpack(&file, &into).unwrap();
    let mut files = Files::new();
    read_back(&into, Path::new(""), &mut files);
    files
}

/// Files whose paths do not collide (none is a directory of another), each a file, an executable or a link to a name
/// beside it.
fn files() -> impl Strategy<Value = Files> {
    let segment = "[a-z]{1,4}";
    let kind = prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..48).prop_map(Kind::File),
        proptest::collection::vec(any::<u8>(), 0..48).prop_map(Kind::Executable),
        "[a-z]{1,4}".prop_map(Kind::Link),
    ];
    proptest::collection::vec((proptest::collection::vec(segment, 1..4), kind), 1..12).prop_map(
        |items| {
            let mut files = Files::new();
            for (segments, kind) in items {
                let path: PathBuf = segments.iter().collect();
                let collides = files
                    .keys()
                    .any(|held| held.starts_with(&path) || path.starts_with(held));
                if !collides {
                    files.insert(path, kind);
                }
            }
            files
        },
    )
}

proptest! {
    /// Any tree: its archive is the same bytes from a repository that built it in another order, and the fetch's own
    /// unpacking gives back exactly its files, their contents, which are executable, and where each link points.
    #[test]
    fn a_commits_archive_is_its_tree_and_the_same_from_any_repository(files in files()) {
        let (_a, one) = bare();
        let (_b, other) = bare();
        let commit = commit_of(&one, tree_of(&one, &files, Path::new(""), false));
        prop_assert_eq!(commit_of(&other, tree_of(&other, &files, Path::new(""), true)), commit.clone());
        let bytes = archive(&one, &commit, usize::MAX).unwrap();
        prop_assert_eq!(&archive(&other, &commit, usize::MAX).unwrap(), &bytes);
        prop_assert_eq!(&archive(&one, &commit, usize::MAX).unwrap(), &bytes, "and again, the same");
        prop_assert_eq!(unpacked(&bytes), files);
    }

    /// An archive is refused past its bound, and taken at it.
    #[test]
    fn an_archive_past_its_bound_is_refused(files in files()) {
        let (_dir, repository) = bare();
        let commit = commit_of(&repository, tree_of(&repository, &files, Path::new(""), false));
        let whole = archive(&repository, &commit, usize::MAX).unwrap();
        prop_assert_eq!(archive(&repository, &commit, whole.len()).unwrap(), whole.clone());
        prop_assert_eq!(archive(&repository, &commit, whole.len() - 1), Err(ArchiveError::TooLarge(whole.len() - 1)));
    }
}

#[test]
fn a_link_that_leaves_the_tree_is_refused() {
    for target in ["../outside", "/etc/passwd", "a/../../outside"] {
        let (_dir, repository) = bare();
        let files = Files::from([(PathBuf::from("link"), Kind::Link(target.into()))]);
        let commit = commit_of(
            &repository,
            tree_of(&repository, &files, Path::new(""), false),
        );
        assert!(
            matches!(
                archive(&repository, &commit, usize::MAX),
                Err(ArchiveError::LinkLeaves(_))
            ),
            "{target}"
        );
    }
    // Within it, however deep it goes first, a link is taken.
    let (_dir, repository) = bare();
    let files = Files::from([
        (PathBuf::from("a/b/link"), Kind::Link("../../c".into())),
        (PathBuf::from("c"), Kind::File(vec![])),
    ]);
    let commit = commit_of(
        &repository,
        tree_of(&repository, &files, Path::new(""), false),
    );
    assert!(archive(&repository, &commit, usize::MAX).is_ok());
}

#[test]
fn a_name_the_fetch_would_refuse_is_refused_here() {
    let (_dir, repository) = bare();
    let blob = repository.blob(b"x").unwrap();
    // libgit2's builders refuse such a name, so the tree is written as its bytes: what a hostile repository could hold.
    for name in ["..", "."] {
        let mut raw = format!("100644 {name}\0").into_bytes();
        raw.extend_from_slice(blob.as_bytes());
        let tree = repository
            .odb()
            .unwrap()
            .write(git2::ObjectType::Tree, &raw)
            .unwrap();
        let commit = commit_of(&repository, tree);
        assert_eq!(
            archive(&repository, &commit, usize::MAX),
            Err(ArchiveError::NotAName),
            "{name}"
        );
    }
}

#[test]
fn a_submodule_is_not_in_the_archive_and_an_unknown_commit_is_none() {
    let (_dir, repository) = bare();
    let mut builder = repository.treebuilder(None).unwrap();
    builder
        .insert("file", repository.blob(b"x").unwrap(), 0o100644)
        .unwrap();
    builder
        .insert("module", Oid::from_str(&"1".repeat(40)).unwrap(), 0o160000)
        .unwrap();
    let commit = commit_of(&repository, builder.write().unwrap());
    let files = unpacked(&archive(&repository, &commit, usize::MAX).unwrap());
    assert_eq!(
        files,
        Files::from([(PathBuf::from("file"), Kind::File(b"x".to_vec()))])
    );
    assert!(matches!(
        archive(&repository, &"2".repeat(40), usize::MAX),
        Err(ArchiveError::NoCommit(_))
    ));
    assert!(matches!(
        archive(&repository, "main", usize::MAX),
        Err(ArchiveError::NoCommit(_))
    ));
}
