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

//! A build's source pushed to the registry in the cluster (docs/architecture/build-orchestrator.md, O3a): the archive as a
//! blob, and a small OCI manifest pointing at it, tagged by the commit, in `build-sources` (the maintainer, "Blob plus a
//! manifest": safe from the registry's garbage collection, found by commit). Through the HTTP protocol handler, to the host
//! the orchestrator's configuration names and no other, with no credential: the build's pod reads it anonymously, and its
//! integrity is its digest, which the pod checks before it unpacks.
//!
//! A blob goes as the distribution registry takes one (found on u7c's, `registry:2.8.3`): a POST opens an upload and a PUT
//! with the digest ends it; a blob already there (a HEAD says so) is not sent again, so an unchanged commit costs nothing.

use crate::settings::REGISTRY_VAR;
use polar_agent_builder::protocol::http::{Http, Reply, Request, StatusCode};
use polar_agent_builder::protocol::{
    Failure, Location, Operation, OperationDecl, ProtocolHandle, ProtocolKind, ReadFailure,
};
use sha2::{Digest, Sha256};

/// Pushes to the registry in the cluster, and only there.
pub const PUSH: OperationDecl = OperationDecl {
    name: "registry.source.push",
    doc: "pushes a build's source archive and its dependencies, and manifests pointing at them, to the registry the \
          orchestrator's configuration names",
    protocol: ProtocolKind::HTTP,
    location: Location::Configured {
        variable: REGISTRY_VAR,
        credential: None,
    },
};

/// Where every build's source goes.
pub const REPOSITORY: &str = "build-sources";
/// What a source's manifest is an artifact of.
pub const ARTIFACT_TYPE: &str = "application/vnd.polar.build-source.v1";
/// What its one layer is: the archive the build's pod unpacks.
pub const ARCHIVE_TYPE: &str = "application/vnd.polar.build-source.v1.tar+gzip";
pub(crate) const MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
/// OCI's empty descriptor: an artifact's config when it has none to say.
pub(crate) const EMPTY_TYPE: &str = "application/vnd.oci.empty.v1+json";
pub(crate) const EMPTY: &[u8] = b"{}";

/// `sha256:` and the lower-case hex of `bytes`' digest.
pub fn digest_of(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// The manifest of a source whose archive has `digest` and `size`: an OCI image manifest of one layer, the archive.
pub fn manifest(digest: &str, size: usize) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST_TYPE,
        "artifactType": ARTIFACT_TYPE,
        "config": { "mediaType": EMPTY_TYPE, "digest": digest_of(EMPTY), "size": EMPTY.len() },
        "layers": [{ "mediaType": ARCHIVE_TYPE, "digest": digest, "size": size }],
    }))
    .expect("a manifest is JSON")
}

/// The archive as a build's pod names it, `host:port/build-sources@sha256:<hex>`, from the registry's address.
pub fn reference(registry: &str, digest: &str) -> String {
    let host = registry
        .strip_prefix("http://")
        .or_else(|| registry.strip_prefix("https://"))
        .unwrap_or(registry);
    format!("{host}/{REPOSITORY}@{digest}")
}

/// Whether `tag` is one a registry takes: a letter, digit or `_`, then up to 127 of those, `.` and `-`.
pub fn is_tag(tag: &str) -> bool {
    let mut bytes = tag.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
        && tag.len() <= 128
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
}

/// The path and query of where an upload goes on: the registry names it in `Location`, as a path or a whole address. The
/// request goes to the configured host whatever host the address names.
fn path_of(location: &str) -> Option<String> {
    if location.starts_with('/') {
        return Some(location.to_string());
    }
    let rest = location.split_once("://")?.1;
    let at = rest.find('/')?;
    Some(rest[at..].to_string())
}

/// What a registry answered: its status, where an upload goes on, and how large what it holds is.
struct Answered {
    status: StatusCode,
    location: Option<String>,
    length: Option<u64>,
}

struct Call(Request);

impl Operation for Call {
    type Protocol = Http;
    type Output = Answered;
    const DECL: OperationDecl = PUSH;
    fn request(&self) -> Request {
        self.0.clone()
    }
    fn read(&self, reply: &Reply) -> Result<Answered, ReadFailure> {
        Ok(Answered {
            status: reply.status,
            location: reply
                .headers
                .get("location")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            length: reply
                .headers
                .get("content-length")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok()),
        })
    }
}

async fn ask(protocols: &ProtocolHandle, request: Request, step: &str) -> Result<Answered, String> {
    protocols
        .ask(Call(request))
        .await
        .map_err(|failure: Failure| format!("{step}: {failure}"))
}

/// How large the blob `digest` of `repository` is, if the registry holds it.
pub async fn held(
    protocols: &ProtocolHandle,
    repository: &str,
    digest: &str,
    what: &str,
) -> Result<Option<u64>, String> {
    let there = ask(
        protocols,
        Request::head(format!("/v2/{repository}/blobs/{digest}")),
        &format!("asking whether the {what} is there"),
    )
    .await?;
    if there.status != StatusCode::OK {
        return Ok(None);
    }
    Ok(Some(there.length.ok_or_else(|| {
        format!("asking whether the {what} is there: the registry said not how large it is")
    })?))
}

/// `bytes` as a blob of `repository`, unless it is there already.
pub async fn blob(
    protocols: &ProtocolHandle,
    repository: &str,
    bytes: &[u8],
    what: &str,
) -> Result<(), String> {
    let digest = digest_of(bytes);
    if held(protocols, repository, &digest, what).await?.is_some() {
        return Ok(());
    }
    let opened = ask(
        protocols,
        Request::post(format!("/v2/{repository}/blobs/uploads/"), Vec::new()),
        &format!("opening the {what}'s upload"),
    )
    .await?;
    if opened.status != StatusCode::ACCEPTED {
        return Err(format!(
            "opening the {what}'s upload: the registry answered {}",
            opened.status
        ));
    }
    let Some(path) = opened.location.as_deref().and_then(path_of) else {
        return Err(format!(
            "opening the {what}'s upload: the registry said nowhere to send it"
        ));
    };
    let joined = if path.contains('?') { '&' } else { '?' };
    let put = ask(
        protocols,
        Request::put(format!("{path}{joined}digest={digest}"), bytes.to_vec())
            .header("content-type", "application/octet-stream"),
        &format!("sending the {what}"),
    )
    .await?;
    if put.status != StatusCode::CREATED {
        return Err(format!(
            "sending the {what}: the registry answered {}",
            put.status
        ));
    }
    Ok(())
}

/// Pushes `archive` as the source tagged `tag` (its commit) and gives its digest: the blob, the empty config, and the
/// manifest, in that order, so a manifest never names what is not there.
pub async fn push(protocols: &ProtocolHandle, tag: &str, archive: &[u8]) -> Result<String, String> {
    if !is_tag(tag) {
        return Err("the tag is not one a registry takes".into());
    }
    blob(protocols, REPOSITORY, archive, "archive").await?;
    blob(protocols, REPOSITORY, EMPTY, "empty config").await?;
    let digest = digest_of(archive);
    put_manifest(protocols, REPOSITORY, tag, manifest(&digest, archive.len())).await?;
    Ok(digest)
}

/// `body`, an OCI image manifest, as `repository`'s `tag`.
pub async fn put_manifest(
    protocols: &ProtocolHandle,
    repository: &str,
    tag: &str,
    body: Vec<u8>,
) -> Result<(), String> {
    let put = ask(
        protocols,
        Request::put(format!("/v2/{repository}/manifests/{tag}"), body)
            .header("content-type", MANIFEST_TYPE),
        "sending the manifest",
    )
    .await?;
    if put.status != StatusCode::CREATED {
        return Err(format!(
            "sending the manifest: the registry answered {}",
            put.status
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_upload_goes_on_at_the_path_the_registry_names_on_any_host() {
        assert_eq!(
            path_of("/v2/r/blobs/uploads/u?_state=x").as_deref(),
            Some("/v2/r/blobs/uploads/u?_state=x")
        );
        assert_eq!(
            path_of("http://elsewhere.invalid:5000/v2/r/blobs/uploads/u?_state=x").as_deref(),
            Some("/v2/r/blobs/uploads/u?_state=x")
        );
        assert_eq!(path_of("elsewhere"), None);
        assert_eq!(path_of("http://elsewhere"), None);
    }

    #[test]
    fn a_commit_is_a_tag_and_what_a_registry_refuses_is_not() {
        assert!(is_tag(&"a".repeat(40)));
        assert!(is_tag("_v1.0-rc"));
        for not in ["", ".x", "-x", "a/b", "a:b", &"a".repeat(129)] {
            assert!(!is_tag(not), "{not:?}");
        }
    }

    #[test]
    fn a_pod_names_the_archive_by_the_registrys_host() {
        let digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            reference(
                "http://registry.polar-registry.svc.cluster.local:5000",
                &digest
            ),
            format!("registry.polar-registry.svc.cluster.local:5000/build-sources@{digest}")
        );
    }
}
