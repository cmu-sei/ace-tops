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

//! A build's dependencies brought into the registry in the cluster (docs/architecture/build-orchestrator.md, D2), so its pod
//! builds offline from them by their digests: decision 1, carried to what the source depends on.
//!
//! A crates.io crate's blob in `build-dependencies` is the very sha256 its lock pins. So a crate is asked of the registry
//! first, and only one it does not hold is downloaded (through a declared operation, at the host the orchestrator's
//! configuration names, with no credential), checked against that digest and pushed: each crate once, across every build and
//! every repository. Then an index of them, and a manifest by the commit naming the index and every blob, so the registry's
//! garbage collection keeps them (the "blob plus a manifest" rule of a build's source).

use crate::lock::{Crate, Dependencies, GitSource};
use crate::push::{self, EMPTY, EMPTY_TYPE, MANIFEST_TYPE, digest_of};
use crate::settings::CRATES_VAR;
use futures::stream::{self, StreamExt, TryStreamExt};
use polar_agent_builder::protocol::http::{Http, Reply, Request, StatusCode};
use polar_agent_builder::protocol::{
    Failure, Location, Operation, OperationDecl, ProtocolHandle, ProtocolKind, ReadFailure,
};

/// Downloads a crate from where the orchestrator's configuration says crates come from, and only there.
pub const DOWNLOAD: OperationDecl = OperationDecl {
    name: "crates.download",
    doc: "downloads a crate a build's lock pins, by its name and version, from the host the orchestrator's configuration \
          names, to be checked against the lock's sha256",
    protocol: ProtocolKind::HTTP,
    location: Location::Configured {
        variable: CRATES_VAR,
        credential: None,
    },
};

/// Where every build's dependencies go.
pub const REPOSITORY: &str = "build-dependencies";
/// What a build's dependencies' manifest is an artifact of.
pub const ARTIFACT_TYPE: &str = "application/vnd.polar.build-dependencies.v1";
/// The index: what the build depends on, and the digest of each.
pub const INDEX_TYPE: &str = "application/vnd.polar.build-dependencies.index.v1+json";
/// A crate as crates.io serves it: a gzipped tar of `<name>-<version>/`.
pub const CRATE_TYPE: &str = "application/vnd.polar.crate.v1.tar+gzip";
/// A git dependency: its commit's tree, archived as a build's source is.
pub const GIT_TYPE: &str = "application/vnd.polar.git-source.v1.tar+gzip";
/// How many crates are asked about, or downloaded, at once.
const AT_ONCE: usize = 8;

/// A git dependency, as the registry holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldGit {
    pub git: GitSource,
    pub digest: String,
    pub size: u64,
}

/// Where crates.io serves a crate.
pub fn crate_path(c: &Crate) -> String {
    format!("/crates/{0}/{0}-{1}.crate", c.name, c.version)
}

/// The index of a build's dependencies: each crate by its name, version and sha256, and each git dependency by its source,
/// commit, packages and archive's digest. Canonical: the same dependencies are the same bytes, whatever order they came in.
pub fn index(crates: &[Crate], git: &[HeldGit]) -> Vec<u8> {
    let mut crates = crates.to_vec();
    crates.sort();
    crates.dedup();
    let mut git = git.to_vec();
    git.sort_by(|a, b| a.git.cmp(&b.git));
    serde_json::to_vec(&serde_json::json!({
        "crates": crates.iter().map(|c| serde_json::json!({
            "name": c.name, "version": c.version, "sha256": c.sha256,
        })).collect::<Vec<_>>(),
        "git": git.iter().map(|g| serde_json::json!({
            "source": g.git.source, "url": g.git.url, "commit": g.git.commit,
            "packages": g.git.packages, "digest": g.digest,
        })).collect::<Vec<_>>(),
    }))
    .expect("an index is JSON")
}

/// The manifest that keeps a build's dependencies: the index, then each crate and each git dependency, by digest and size.
pub fn manifest(index: &[u8], crates: &[(String, u64)], git: &[HeldGit]) -> Vec<u8> {
    let mut layers = vec![serde_json::json!({
        "mediaType": INDEX_TYPE, "digest": digest_of(index), "size": index.len(),
    })];
    let mut crates = crates.to_vec();
    crates.sort();
    crates.dedup();
    layers.extend(crates.iter().map(|(digest, size)| {
        serde_json::json!({ "mediaType": CRATE_TYPE, "digest": digest, "size": size })
    }));
    let mut git = git.to_vec();
    git.sort_by(|a, b| a.digest.cmp(&b.digest));
    git.dedup_by(|a, b| a.digest == b.digest);
    layers.extend(
        git.iter().map(
            |g| serde_json::json!({ "mediaType": GIT_TYPE, "digest": g.digest, "size": g.size }),
        ),
    );
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST_TYPE,
        "artifactType": ARTIFACT_TYPE,
        "config": { "mediaType": EMPTY_TYPE, "digest": digest_of(EMPTY), "size": EMPTY.len() },
        "layers": layers,
    }))
    .expect("a manifest is JSON")
}

/// What crates.io answered: its status and the body.
struct Downloaded {
    status: StatusCode,
    body: Vec<u8>,
}

struct Download(Request);

impl Operation for Download {
    type Protocol = Http;
    type Output = Downloaded;
    const DECL: OperationDecl = DOWNLOAD;
    fn request(&self) -> Request {
        self.0.clone()
    }
    fn read(&self, reply: &Reply) -> Result<Downloaded, ReadFailure> {
        Ok(Downloaded {
            status: reply.status,
            body: reply.body.clone(),
        })
    }
}

/// `c` in the registry, by the digest its lock pins: held already, or downloaded, checked and pushed. Its size.
async fn one(protocols: &ProtocolHandle, c: &Crate) -> Result<(String, u64), String> {
    let what = format!("crate {} {}", c.name, c.version);
    let digest = format!("sha256:{}", c.sha256);
    if let Some(size) = push::held(protocols, REPOSITORY, &digest, &what).await? {
        return Ok((digest, size));
    }
    let got = protocols
        .ask(Download(Request::get(crate_path(c))))
        .await
        .map_err(|failure: Failure| format!("{what} could not be downloaded: {failure}"))?;
    if got.status != StatusCode::OK {
        return Err(format!(
            "{what} could not be downloaded: the host answered {}",
            got.status
        ));
    }
    if digest_of(&got.body) != digest {
        return Err(format!(
            "{what}: what was downloaded is not what the lock pins"
        ));
    }
    push::blob(protocols, REPOSITORY, &got.body, &what).await?;
    Ok((digest, got.body.len() as u64))
}

/// Brings `crates` into the registry, a few at a time, and gives each one's digest and size; past `bound` bytes in all, the
/// build's dependencies are refused.
pub async fn crates(
    protocols: &ProtocolHandle,
    crates: &[Crate],
    bound: u64,
) -> Result<Vec<(String, u64)>, String> {
    let held: Vec<(String, u64)> = stream::iter(crates)
        .map(|c| one(protocols, c))
        .buffered(AT_ONCE)
        .try_collect()
        .await?;
    let total: u64 = held.iter().map(|(_, size)| size).sum();
    if total > bound {
        return Err(format!(
            "the build's dependencies come to {total} bytes, past their bound of {bound}"
        ));
    }
    Ok(held)
}

/// A build's dependencies in the registry, kept by a manifest tagged `tag` (its commit): the crates, the git dependencies
/// already archived and pushed (`git`), and the index of them. The index's digest, which the build's fetch is given.
pub async fn store(
    protocols: &ProtocolHandle,
    tag: &str,
    dependencies: &Dependencies,
    git: &[HeldGit],
    bound: u64,
) -> Result<String, String> {
    if !push::is_tag(tag) {
        return Err("the tag is not one a registry takes".into());
    }
    let mut held = crates(protocols, &dependencies.crates, bound).await?;
    let total =
        held.iter().map(|(_, size)| size).sum::<u64>() + git.iter().map(|g| g.size).sum::<u64>();
    if total > bound {
        return Err(format!(
            "the build's dependencies come to {total} bytes, past their bound of {bound}"
        ));
    }
    held.sort();
    let index = index(&dependencies.crates, git);
    push::blob(protocols, REPOSITORY, &index, "dependencies' index").await?;
    push::blob(protocols, REPOSITORY, EMPTY, "empty config").await?;
    push::put_manifest(protocols, REPOSITORY, tag, manifest(&index, &held, git)).await?;
    Ok(digest_of(&index))
}
