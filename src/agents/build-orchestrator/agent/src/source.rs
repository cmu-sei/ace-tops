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

//! A build's source step (docs/architecture/build-orchestrator.md, decision 1, O3c, D2): the commit fetched through the
//! orchestrator's git protocol handler into its clone of the repository, read into an archive (`archive`), and pushed to the
//! registry in the cluster as a blob and a manifest by commit (`push`), for the build's fetch to unpack by its digest. The
//! credential, if the mapping names one, is the handler's to present and goes nowhere else; the build's pod gets none.
//!
//! Then its dependencies (D2), decision 1 carried to them: the locks its mapping names, read from the same commit's tree in
//! the same fetch (`lock`), their git dependencies fetched at the commits they pin and archived as a source is, and all of
//! them brought into the registry by digest (`deps`), so the build's pod reaches none of their origins.
//!
//! A trait, so a build's actor is tested without a repository or a registry.

use crate::archive::archive;
use crate::deps::{self, HeldGit};
use crate::lock::{self, Dependencies};
use crate::push;
use crate::shallow;
use orchestrator_core::types::{SourceArchive, SourceRef};
use polar_agent_builder::protocol::git::{Fetched, Git, Request};
use polar_agent_builder::protocol::{
    Credential, Location, Operation, OperationDecl, ProtocolHandle, ProtocolKind, ReadFailure,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// What a build's source step is asked to do, from its mapping and the settings in force when it started.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct How {
    /// The credential its source is fetched with, by name.
    pub credential: Option<String>,
    /// The Cargo locks in its tree whose dependencies it is given.
    pub locks: Vec<String>,
    /// The largest its source archive may be.
    pub max_source: usize,
    /// The most its dependencies may come to.
    pub max_dependencies: u64,
}

#[ractor::async_trait]
pub trait Source: Send + Sync {
    /// The archive `source` is in, with its dependencies' index, prepared as `how` says, or why there is none.
    async fn prepare(&self, source: &SourceRef, how: &How) -> Result<SourceArchive, String>;
}

/// A mapped repository that names its credential goes where that credential's signed binding allows.
pub const FETCH: OperationDecl = OperationDecl {
    name: "git.fetch",
    doc: "brings up to date a mapped repository that names its credential, at a host the credential is bound to",
    protocol: ProtocolKind::GIT,
    location: Location::Bound {
        credential: Credential::Chosen,
    },
};

/// One that names none goes to the address its signed mapping gives, with nothing to present.
pub const FETCH_PUBLIC: OperationDecl = OperationDecl {
    name: "git.fetch-public",
    doc: "brings up to date a mapped repository that names no credential, at the address its signed mapping gives",
    protocol: ProtocolKind::GIT,
    location: Location::Arbitrary,
};

/// The remote a repository is fetched from.
const REMOTE: &str = "origin";

/// What a fetch is for: the clone brought up to date, then `commit` read from it, as `as_` says.
struct Asked {
    request: Request,
    commit: String,
    bound: usize,
    as_: Reading,
}

/// How a fetched commit is read.
#[derive(Clone)]
enum Reading {
    /// A build's source: its archive, and what its `locks` pin.
    Source { locks: Vec<String> },
    /// A git dependency: the shallow repository of it (`shallow`).
    Dependency,
}

/// What a fetch read: the archive, and what its locks pin.
type Read = Result<(Vec<u8>, Dependencies), String>;

impl Asked {
    fn read(&self, reply: &Fetched) -> Read {
        let Reading::Source { locks } = &self.as_ else {
            let repository = shallow::repository(&reply.repository, &self.commit, self.bound)
                .map_err(|why| format!("the dependency could not be packed: {why}"))?;
            return Ok((repository, Dependencies::default()));
        };
        let archived = archive(&reply.repository, &self.commit, self.bound)
            .map_err(|why| format!("the source could not be archived: {why}"))?;
        let mut pinned = Vec::new();
        for path in locks {
            let text = lock_at(&reply.repository, &self.commit, path)?;
            pinned.push(lock::read(&text).map_err(|problems| {
                format!(
                    "the lock {path} pins what a build is not given: {}",
                    problems.join("; ")
                )
            })?);
        }
        Ok((archived, lock::union(pinned)))
    }
}

/// The lock at `path` in `commit`'s tree, as text, at most `lock::MAX_LOCK` bytes.
fn lock_at(repository: &git2::Repository, commit: &str, path: &str) -> Result<String, String> {
    let missing = || format!("the commit has no lock at {path}");
    let commit = git2::Oid::from_str(commit)
        .ok()
        .and_then(|oid| repository.find_commit(oid).ok())
        .ok_or_else(missing)?;
    let tree = commit.tree().map_err(|e| e.message().to_string())?;
    let entry = tree.get_path(Path::new(path)).map_err(|_| missing())?;
    if entry.filemode() != 0o100644 && entry.filemode() != 0o100755 {
        return Err(missing());
    }
    let blob = repository.find_blob(entry.id()).map_err(|_| missing())?;
    if blob.content().len() > lock::MAX_LOCK {
        return Err(format!(
            "the lock at {path} is larger than {} bytes",
            lock::MAX_LOCK
        ));
    }
    String::from_utf8(blob.content().to_vec())
        .map_err(|_| format!("the lock at {path} is not text"))
}

struct WithCredential {
    credential: String,
    asked: Asked,
}

impl Operation for WithCredential {
    type Protocol = Git;
    type Output = Read;
    const DECL: OperationDecl = FETCH;
    fn request(&self) -> Request {
        self.asked.request.clone()
    }
    fn credential(&self) -> Option<String> {
        Some(self.credential.clone())
    }
    fn read(&self, reply: &Fetched) -> Result<Self::Output, ReadFailure> {
        Ok(self.asked.read(reply))
    }
}

struct Public(Asked);

impl Operation for Public {
    type Protocol = Git;
    type Output = Read;
    const DECL: OperationDecl = FETCH_PUBLIC;
    fn request(&self) -> Request {
        self.0.request.clone()
    }
    fn read(&self, reply: &Fetched) -> Result<Self::Output, ReadFailure> {
        Ok(self.0.read(reply))
    }
}

/// The source step as the orchestrator runs it.
pub struct GitSource {
    protocols: ProtocolHandle,
    /// Where each repository's clone is kept.
    clones: PathBuf,
    /// The registry's address, `http(s)://host:port`.
    registry: String,
    /// One fetch of a repository at a time: two builds of it share its clone.
    held: Mutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>>,
}

impl GitSource {
    pub fn new(
        protocols: ProtocolHandle,
        clones: impl Into<PathBuf>,
        registry: impl Into<String>,
    ) -> Self {
        Self {
            protocols,
            clones: clones.into(),
            registry: registry.into(),
            held: Mutex::default(),
        }
    }

    /// Where `url`'s clone is: named by its digest, so no URL makes a path of its own.
    fn clone_of(&self, url: &str) -> PathBuf {
        let digest = push::digest_of(url.as_bytes());
        self.clones
            .join(format!("{}.git", &digest["sha256:".len()..]))
    }

    fn lock_of(&self, clone: &Path) -> Arc<tokio::sync::Mutex<()>> {
        self.held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(clone.to_path_buf())
            .or_default()
            .clone()
    }
}

impl GitSource {
    /// Fetches `url` at `commit` into its clone, one fetch of it at a time, and reads it as `asked` says.
    async fn fetch(
        &self,
        url: String,
        commit: String,
        credential: Option<String>,
        bound: usize,
        as_: Reading,
    ) -> Read {
        let clone = self.clone_of(&url);
        let lock = self.lock_of(&clone);
        let _held = lock.lock().await;
        let asked = Asked {
            request: Request::new(url.clone(), &clone, vec![REMOTE.to_string()], None),
            commit,
            bound,
            as_,
        };
        let fetched = match credential {
            Some(credential) => {
                self.protocols
                    .ask(WithCredential { credential, asked })
                    .await
            }
            None => self.protocols.ask(Public(asked)).await,
        };
        fetched.map_err(|failure| format!("{url} could not be fetched: {failure}"))?
    }

    /// The source's dependencies in the registry, and the index of them; `None` when it has none.
    async fn dependencies(
        &self,
        commit: &str,
        pinned: &Dependencies,
        bound: u64,
    ) -> Result<Option<String>, String> {
        if pinned.crates.is_empty() && pinned.git.is_empty() {
            return Ok(None);
        }
        let each = usize::try_from(bound).unwrap_or(usize::MAX);
        let mut git = Vec::new();
        for source in &pinned.git {
            // A git dependency is public for now: one that is not fails here, with the reason (D2, for review). It goes as a
            // shallow repository of its commit, which Cargo's source replacement points at in the pod (D3).
            let (archived, _) = self
                .fetch(
                    source.url.clone(),
                    source.commit.clone(),
                    None,
                    each,
                    Reading::Dependency,
                )
                .await
                .map_err(|why| format!("a git dependency: {why}"))?;
            let what = format!("git dependency {} at {}", source.url, source.commit);
            push::blob(&self.protocols, deps::REPOSITORY, &archived, &what).await?;
            git.push(HeldGit {
                git: source.clone(),
                digest: push::digest_of(&archived),
                size: archived.len() as u64,
            });
        }
        let index = deps::store(&self.protocols, commit, pinned, &git, bound).await?;
        Ok(Some(index))
    }
}

#[ractor::async_trait]
impl Source for GitSource {
    async fn prepare(&self, source: &SourceRef, how: &How) -> Result<SourceArchive, String> {
        let SourceRef::Git { url, commit_sha } = source else {
            return Err("only a git repository's source is fetched".into());
        };
        let (archived, pinned) = self
            .fetch(
                url.clone(),
                commit_sha.clone(),
                how.credential.clone(),
                how.max_source,
                Reading::Source {
                    locks: how.locks.clone(),
                },
            )
            .await
            .map_err(|why| format!("the repository could not be fetched: {why}"))?;
        let digest = push::push(&self.protocols, commit_sha, &archived)
            .await
            .map_err(|why| format!("the source could not be pushed: {why}"))?;
        let mut pinned_archive =
            SourceArchive::new(push::reference(&self.registry, push::REPOSITORY, &digest))
                .map_err(|why| why.to_string())?;
        if let Some(index) = self
            .dependencies(commit_sha, &pinned, how.max_dependencies)
            .await
            .map_err(|why| format!("the source's dependencies could not be had: {why}"))?
        {
            pinned_archive = pinned_archive
                .with_dependencies(push::reference(&self.registry, deps::REPOSITORY, &index))
                .map_err(|why| why.to_string())?;
        }
        Ok(if self.registry.starts_with("http://") {
            pinned_archive.over_http()
        } else {
            pinned_archive
        })
    }
}
