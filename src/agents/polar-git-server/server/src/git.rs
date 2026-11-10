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

//! git's smart protocol for smart HTTP, served in process by gix-serve (the maintainer's gitoxide fork,
//! docs/architecture/runtime-attestation.md, C2): `upload-pack` and `receive-pack` in their stateless-RPC form. No program
//! is run. Each request works on a blocking thread, on the repository opened with its own configuration and nothing else
//! of the host's, and is stopped where it is when it runs past its time.

use gix_serve::receive_pack::Command;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    UploadPack,
    ReceivePack,
}

impl Service {
    /// The `service` query value of `info/refs` (`git-upload-pack`).
    pub fn from_query(value: &str) -> Option<Self> {
        match value {
            "git-upload-pack" => Some(Self::UploadPack),
            "git-receive-pack" => Some(Self::ReceivePack),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::UploadPack => "git-upload-pack",
            Self::ReceivePack => "git-receive-pack",
        }
    }

    fn what(self) -> &'static str {
        match self {
            Self::UploadPack => "upload-pack",
            Self::ReceivePack => "receive-pack",
        }
    }

    fn served(self) -> gix_serve::Service {
        match self {
            Self::UploadPack => gix_serve::Service::UploadPack,
            Self::ReceivePack => gix_serve::Service::ReceivePack,
        }
    }

    pub fn content_type(self) -> String {
        format!("application/x-{}-result", self.name())
    }

    pub fn advertisement_content_type(self) -> String {
        format!("application/x-{}-advertisement", self.name())
    }
}

#[derive(Debug, Error)]
pub enum GitError {
    #[error("git {0} timed out")]
    Timeout(&'static str),
    #[error("git {0} failed: {1}")]
    Failed(&'static str, String),
}

#[derive(Debug, Clone)]
pub struct GitRunner {
    pub timeout: Duration,
}

impl Default for GitRunner {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(120),
        }
    }
}

impl GitRunner {
    /// The `GET info/refs?service=...` response body, in the protocol version the request's `Git-Protocol` header asks
    /// for.
    pub async fn advertise(
        &self,
        repo: &Path,
        service: Service,
        git_protocol: Option<&str>,
    ) -> Result<Vec<u8>, GitError> {
        let protocol = gix_serve::Protocol::from_header(git_protocol);
        self.run(service.what(), repo, move |repo, _| {
            let mut out = Vec::new();
            gix_serve::advertise(&repo, service.served(), protocol, &mut out)?;
            Ok(out)
        })
        .await
    }

    /// The `POST git-upload-pack` response body for a request body.
    pub async fn upload_pack(
        &self,
        repo: &Path,
        git_protocol: Option<&str>,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, GitError> {
        let protocol = gix_serve::Protocol::from_header(git_protocol);
        self.run("upload-pack", repo, move |repo, stop| {
            let mut out = Vec::new();
            gix_serve::upload_pack::serve(&repo, protocol, &body, &mut out, stop)?;
            Ok(out)
        })
        .await
    }

    /// The `POST git-receive-pack` response body for a request body, and the updates it made: all of the request's or
    /// none. `allow` judges the push after git's own rules (the repository's `receive.denyDeletes` and
    /// `receive.denyNonFastForwards`, and every object the new history needs being there) and before anything is taken,
    /// on the repository with the pushed objects in quarantine beside it; its refusal is the reason each ref reports.
    pub async fn receive_pack(
        &self,
        repo: &Path,
        body: Vec<u8>,
        allow: impl FnOnce(&gix::Repository, &[Command]) -> Result<(), String> + Send + 'static,
    ) -> Result<(Vec<u8>, Vec<Command>), GitError> {
        self.run("receive-pack", repo, move |repo, stop| {
            let mut out = Vec::new();
            let made = gix_serve::receive_pack::serve(&repo, &body, &mut out, stop, allow)?;
            Ok((out, made))
        })
        .await
    }

    /// Runs `work` on the repository at `path` on a blocking thread, and stops it when it runs past the timeout. It is
    /// waited for even then, so what it leaves (a quarantine) is gone before the answer; and if it finished all the same
    /// (it was past the last point it stops at, moving refs), its answer is the answer, so a push that was taken is never
    /// reported as failed.
    async fn run<T: Send + 'static>(
        &self,
        what: &'static str,
        path: &Path,
        work: impl FnOnce(gix::Repository, &AtomicBool) -> Result<T, gix_serve::Error> + Send + 'static,
    ) -> Result<T, GitError> {
        let stop = Arc::new(AtomicBool::new(false));
        let path = path.to_path_buf();
        let flag = Arc::clone(&stop);
        let mut task = tokio::task::spawn_blocking(move || {
            let repo = gix::open_opts(&path, gix::open::Options::isolated())
                .map_err(|e| format!("the repository cannot be opened: {e}"))?;
            work(repo, &flag).map_err(|e| e.to_string())
        });
        let done = match tokio::time::timeout(self.timeout, &mut task).await {
            Ok(done) => done,
            Err(_) => {
                stop.store(true, Ordering::Relaxed);
                match task.await {
                    Ok(Ok(finished)) => return Ok(finished),
                    _ => return Err(GitError::Timeout(what)),
                }
            }
        };
        done.map_err(|e| GitError::Failed(what, e.to_string()))?
            .map_err(|why| GitError::Failed(what, why))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::RepoStore;

    #[test]
    fn only_the_two_services_are_recognised() {
        assert_eq!(
            Service::from_query("git-upload-pack"),
            Some(Service::UploadPack)
        );
        assert_eq!(
            Service::from_query("git-receive-pack"),
            Some(Service::ReceivePack)
        );
        assert_eq!(Service::from_query("git-shell"), None);
    }

    #[tokio::test]
    async fn the_advertisement_names_main_once_seeded() {
        let dir = tempfile::tempdir().unwrap();
        let tree = tempfile::tempdir().unwrap();
        std::fs::write(tree.path().join("x"), "x").unwrap();
        let store = RepoStore::new(dir.path());
        store.create("r").await.unwrap();
        store.seed("r", tree.path()).await.unwrap();

        let body = GitRunner::default()
            .advertise(&store.path("r").unwrap(), Service::UploadPack, None)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.starts_with("001e# service=git-upload-pack\n0000"),
            "{text}"
        );
        assert!(text.contains("refs/heads/main"), "{text}");
    }
}
