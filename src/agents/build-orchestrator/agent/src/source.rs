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

//! A build's source step (docs/architecture/build-orchestrator.md, decision 1, O3c): the commit fetched through the
//! orchestrator's git protocol handler into its clone of the repository, read into an archive (`archive`), and pushed to the
//! registry in the cluster as a blob and a manifest by commit (`push`), for the build's fetch to unpack by its digest. The
//! credential, if the mapping names one, is the handler's to present and goes nowhere else; the build's pod gets none.
//!
//! A trait, so a build's actor is tested without a repository or a registry.

use crate::archive::{ArchiveError, archive};
use crate::push;
use orchestrator_core::types::{SourceArchive, SourceRef};
use polar_agent_builder::protocol::git::{Fetched, Git, Request};
use polar_agent_builder::protocol::{
    Credential, Location, Operation, OperationDecl, ProtocolHandle, ProtocolKind, ReadFailure,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[ractor::async_trait]
pub trait Source: Send + Sync {
    /// The archive `source` is in, fetched with `credential` (a name, if the mapping gives one) and no larger than `bound`
    /// bytes, or why there is none.
    async fn prepare(
        &self,
        source: &SourceRef,
        credential: Option<&str>,
        bound: usize,
    ) -> Result<SourceArchive, String>;
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

/// What a fetch is for: the clone brought up to date, then `commit`'s archive read from it.
struct Asked {
    request: Request,
    commit: String,
    bound: usize,
}

impl Asked {
    fn read(&self, reply: &Fetched) -> Result<Vec<u8>, ArchiveError> {
        archive(&reply.repository, &self.commit, self.bound)
    }
}

struct WithCredential {
    credential: String,
    asked: Asked,
}

impl Operation for WithCredential {
    type Protocol = Git;
    type Output = Result<Vec<u8>, ArchiveError>;
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
    type Output = Result<Vec<u8>, ArchiveError>;
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

#[ractor::async_trait]
impl Source for GitSource {
    async fn prepare(
        &self,
        source: &SourceRef,
        credential: Option<&str>,
        bound: usize,
    ) -> Result<SourceArchive, String> {
        let SourceRef::Git { url, commit_sha } = source else {
            return Err("only a git repository's source is fetched".into());
        };
        let clone = self.clone_of(url);
        let archived = {
            let lock = self.lock_of(&clone);
            let _held = lock.lock().await;
            let asked = Asked {
                request: Request::new(url.clone(), &clone, vec![REMOTE.to_string()], None),
                commit: commit_sha.clone(),
                bound,
            };
            let fetched = match credential {
                Some(name) => {
                    self.protocols
                        .ask(WithCredential {
                            credential: name.to_string(),
                            asked,
                        })
                        .await
                }
                None => self.protocols.ask(Public(asked)).await,
            };
            fetched
                .map_err(|failure| format!("the repository could not be fetched: {failure}"))?
                .map_err(|why| format!("the source could not be archived: {why}"))?
        };
        let digest = push::push(&self.protocols, commit_sha, &archived)
            .await
            .map_err(|why| format!("the source could not be pushed: {why}"))?;
        let pinned = SourceArchive::new(push::reference(&self.registry, &digest))
            .map_err(|why| why.to_string())?;
        Ok(if self.registry.starts_with("http://") {
            pinned.over_http()
        } else {
            pinned
        })
    }
}
