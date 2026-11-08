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

//! A build's source as the build's pod gets it (docs/architecture/build-orchestrator.md, O3b): a commit's tree as a gzipped
//! tar, read from the clone the git handler brought up to date. Deterministic, so a commit is always one archive and one
//! digest, whatever clone it was read from: entries in the tree's own order (git keeps a tree's entries sorted), every time
//! the commit's, owner 0, modes git's own (0644, 0755, a link), and a gzip header with no time or name in it.
//!
//! What the fetch would refuse is refused here, before anything is pushed: a name that is not one (empty, `.`, `..`, or with
//! a `/` or a NUL in it), and a link whose target is absolute or leaves the tree. A submodule (a commit in the tree) is not
//! in the archive: its source is another repository's. Past `bound` bytes the archive is refused, as it is being written.

use flate2::{Compression, GzBuilder};
use git2::{ObjectType, Oid, Repository, Tree};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use tar::{EntryType, Header};

/// Why there is no archive.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArchiveError {
    #[error("the repository has no commit {0}")]
    NoCommit(String),
    #[error("the repository could not be read: {0}")]
    Git(String),
    #[error("the source is larger than its bound ({0} bytes)")]
    TooLarge(usize),
    #[error("the tree holds a name that is not one")]
    NotAName,
    #[error("the tree holds a link that leaves it: {0}")]
    LinkLeaves(String),
}

const DIRECTORY: i32 = 0o040000;
const FILE: i32 = 0o100644;
const EXECUTABLE: i32 = 0o100755;
const LINK: i32 = 0o120000;
const SUBMODULE: i32 = 0o160000;

/// The archive of `commit`'s tree in `repository`, at most `bound` bytes.
pub fn archive(
    repository: &Repository,
    commit: &str,
    bound: usize,
) -> Result<Vec<u8>, ArchiveError> {
    let oid = Oid::from_str(commit).map_err(|_| ArchiveError::NoCommit(commit.to_string()))?;
    let commit = repository
        .find_commit(oid)
        .map_err(|_| ArchiveError::NoCommit(oid.to_string()))?;
    let tree = commit
        .tree()
        .map_err(|e| ArchiveError::Git(e.message().to_string()))?;
    let time = u64::try_from(commit.time().seconds()).unwrap_or(0);
    let gzip = GzBuilder::new()
        .mtime(0)
        .write(Bounded::new(bound), Compression::default());
    let mut tar = tar::Builder::new(gzip);
    add(repository, &tree, Path::new(""), time, bound, &mut tar)?;
    let gzip = tar.into_inner().map_err(|e| written(e, bound))?;
    let bounded = gzip.finish().map_err(|e| written(e, bound))?;
    Ok(bounded.bytes)
}

fn written(e: std::io::Error, bound: usize) -> ArchiveError {
    if e.kind() == std::io::ErrorKind::FileTooLarge {
        ArchiveError::TooLarge(bound)
    } else {
        ArchiveError::Git(e.to_string())
    }
}

fn add<W: Write>(
    repository: &Repository,
    tree: &Tree<'_>,
    under: &Path,
    time: u64,
    bound: usize,
    tar: &mut tar::Builder<W>,
) -> Result<(), ArchiveError> {
    for entry in tree.iter() {
        let name = entry.name_bytes();
        if name.is_empty()
            || name == b"."
            || name == b".."
            || name.contains(&b'/')
            || name.contains(&0)
        {
            return Err(ArchiveError::NotAName);
        }
        let path = under.join(std::ffi::OsStr::from_bytes(name));
        let mode = entry.filemode();
        let mut header = Header::new_gnu();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(time);
        match (mode, entry.kind()) {
            (DIRECTORY, Some(ObjectType::Tree)) => {
                header.set_entry_type(EntryType::Directory);
                header.set_mode(0o755);
                header.set_size(0);
                tar.append_data(&mut header, &path, std::io::empty())
                    .map_err(|e| written(e, bound))?;
                let subtree = repository
                    .find_tree(entry.id())
                    .map_err(|e| ArchiveError::Git(e.message().to_string()))?;
                add(repository, &subtree, &path, time, bound, tar)?;
            }
            (FILE | EXECUTABLE, Some(ObjectType::Blob)) => {
                let blob = repository
                    .find_blob(entry.id())
                    .map_err(|e| ArchiveError::Git(e.message().to_string()))?;
                header.set_entry_type(EntryType::Regular);
                header.set_mode(if mode == EXECUTABLE { 0o755 } else { 0o644 });
                header.set_size(blob.content().len() as u64);
                tar.append_data(&mut header, &path, blob.content())
                    .map_err(|e| written(e, bound))?;
            }
            (LINK, Some(ObjectType::Blob)) => {
                let blob = repository
                    .find_blob(entry.id())
                    .map_err(|e| ArchiveError::Git(e.message().to_string()))?;
                let target = PathBuf::from(std::ffi::OsStr::from_bytes(blob.content()));
                let base = path.parent().unwrap_or(Path::new(""));
                if target.is_absolute() || !stays_inside(&base.join(&target)) {
                    return Err(ArchiveError::LinkLeaves(path.display().to_string()));
                }
                header.set_entry_type(EntryType::Symlink);
                header.set_mode(0o777);
                header.set_size(0);
                tar.append_link(&mut header, &path, &target)
                    .map_err(|e| written(e, bound))?;
            }
            (SUBMODULE, _) => {}
            _ => {
                return Err(ArchiveError::Git(format!(
                    "{} is of no kind an archive holds",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

/// Whether `path`, relative, stays under where it starts: the fetch's own rule (build-orchestrator/fetch).
fn stays_inside(path: &Path) -> bool {
    let mut depth: i64 = 0;
    for component in path.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

/// Bytes in memory, refused past a bound as they are written, so an archive past it is never held whole.
struct Bounded {
    bytes: Vec<u8>,
    bound: usize,
}

impl Bounded {
    fn new(bound: usize) -> Self {
        Self {
            bytes: Vec::new(),
            bound,
        }
    }
}

impl Write for Bounded {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len() + buf.len() > self.bound {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "past the archive's bound",
            ));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
