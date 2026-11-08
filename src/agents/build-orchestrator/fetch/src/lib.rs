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

#![deny(clippy::disallowed_methods)]

//! The build pod's side of a build's source (docs/architecture/build-orchestrator.md, decision 1): the source archive is a
//! blob in Polar's registry, pinned by its digest. It is read anonymously from inside the cluster, checked against its digest
//! as it is written, and only then unpacked into the workspace, every entry inside it. The pod holds no credential and never
//! reaches the source's origin.

use futures::StreamExt;
use polar_env::{Config, Defaulted, Described, Required, Section};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

/// The most of an archive read: past it the fetch is refused, since what nothing bounds could fill the workspace. To review.
pub const MAX_ARCHIVE: u64 = 4 * 1024 * 1024 * 1024;
/// How long a connection to the registry has to open.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the whole read has.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(15 * 60);

pub static SOURCE_BLOB: Required<String> = Required::text(
    "CYCLOPS_SOURCE_BLOB",
    "the source archive: a blob in Polar's registry, `host/repository@sha256:<hex>`",
);
pub static SOURCE_SHA256: Required<String> = Required::text(
    "CYCLOPS_SOURCE_SHA256",
    "the archive's sha256, lower-case hex, which it is checked against before it is unpacked",
);
pub static WORKSPACE: Required<String> = Required::text(
    "CYCLOPS_WORKSPACE",
    "where the archive is unpacked: the workspace the pipeline builds in",
);
pub static INSECURE: Defaulted<bool> = Defaulted::flag(
    "CYCLOPS_REGISTRY_INSECURE",
    "whether the registry is spoken to over plain http: the cluster's own registry, read from inside it",
    "false",
);

static VARIABLES: &[&dyn Described] = &[&SOURCE_BLOB, &SOURCE_SHA256, &WORKSPACE, &INSECURE];

/// The section build-fetch reads.
pub static SECTION: Section = Section {
    name: "build-fetch",
    vars: VARIABLES,
    relations: |_| Vec::new(),
};

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("the source archive `{0}` is not a blob pinned by its full sha256 digest")]
    Unpinned(String),
    #[error("the blob is named by {named}, and the archive was to have {expected}")]
    OtherDigest { named: String, expected: String },
    #[error("the registry did not give the archive: {0}")]
    Unread(String),
    #[error("the archive's digest is {actual}, and {expected} was named: nothing was unpacked")]
    WrongDigest { actual: String, expected: String },
    #[error("the archive passed its bound of {0} bytes: nothing was unpacked")]
    TooLarge(u64),
    #[error(
        "the archive's entry `{0}` is not inside the workspace, or not a file, directory or link: nothing more was unpacked"
    )]
    Escapes(String),
    #[error("the archive could not be written or read: {0}")]
    Io(#[from] std::io::Error),
}

/// Where a blob is read from: its registry's `/v2/` blob address, over http only when the registry is named insecure.
pub fn blob_url(reference: &str, insecure: bool) -> Result<String, FetchError> {
    let unpinned = || FetchError::Unpinned(reference.to_string());
    let (name, hex) = reference.rsplit_once("@sha256:").ok_or_else(unpinned)?;
    if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(unpinned());
    }
    let (host, repository) = name.split_once('/').ok_or_else(unpinned)?;
    if host.is_empty() || repository.is_empty() {
        return Err(unpinned());
    }
    let scheme = if insecure { "http" } else { "https" };
    Ok(format!(
        "{scheme}://{host}/v2/{repository}/blobs/sha256:{hex}"
    ))
}

/// Reads the archive at `url` into `into`, hashing it as it is written: an archive with another digest than `sha256`, or
/// past `max` bytes, is refused, and `into` removed.
pub async fn fetch(
    client: &reqwest::Client,
    url: &str,
    sha256: &str,
    max: u64,
    into: &Path,
) -> Result<(), FetchError> {
    let result = fetch_into(client, url, sha256, max, into).await;
    if result.is_err() {
        let _ = std::fs::remove_file(into);
    }
    result
}

async fn fetch_into(
    client: &reqwest::Client,
    url: &str,
    sha256: &str,
    max: u64,
    into: &Path,
) -> Result<(), FetchError> {
    let response = client
        .get(url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| FetchError::Unread(e.to_string()))?;
    let mut file = std::fs::File::create(into)?;
    let mut hasher = Sha256::new();
    let mut read: u64 = 0;
    let mut body = response.bytes_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|e| FetchError::Unread(e.to_string()))?;
        read += chunk.len() as u64;
        if read > max {
            return Err(FetchError::TooLarge(max));
        }
        hasher.update(&chunk);
        file.write_all(&chunk)?;
    }
    file.sync_all()?;
    let actual = format!("{:x}", hasher.finalize());
    if actual != sha256 {
        return Err(FetchError::WrongDigest {
            actual,
            expected: sha256.to_string(),
        });
    }
    Ok(())
}

/// Unpacks the gzipped tar at `archive` into `into`. Every entry is a file, a directory or a link, and goes inside `into`:
/// an absolute path, a `..`, or a link that would take a later entry outside it is refused, and the unpacking stops.
pub fn unpack(archive: &Path, into: &Path) -> Result<(), FetchError> {
    let file = std::fs::File::open(archive)?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
    tar.set_preserve_permissions(false);
    tar.set_overwrite(true);
    for entry in tar.entries()? {
        let mut entry = entry?;
        let path: PathBuf = entry.path()?.into_owned();
        let shown = path.display().to_string();
        let kind = entry.header().entry_type();
        let allowed = kind.is_file() || kind.is_dir() || kind.is_symlink() || kind.is_hard_link();
        let inside = path
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
        if !allowed || !inside {
            return Err(FetchError::Escapes(shown));
        }
        if let Some(target) = entry.link_name()? {
            let base = path.parent().unwrap_or(Path::new(""));
            if !stays_inside(&base.join(&target)) || target.is_absolute() {
                return Err(FetchError::Escapes(shown));
            }
        }
        // `unpack_in` refuses, as false, what would land outside `into` once the links already written are followed.
        if !entry.unpack_in(into)? {
            return Err(FetchError::Escapes(shown));
        }
    }
    Ok(())
}

/// Whether a relative path, its `..` taken as they come, stays at or below where it starts.
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

/// What the binary does: reads its section, fetches the archive into the workspace, checks it, unpacks it, removes it.
pub async fn run(config: &Config) -> Result<(), FetchError> {
    let reference = config
        .read(&SOURCE_BLOB)
        .map_err(|e| FetchError::Unread(e.to_string()))?;
    let sha256 = config
        .read(&SOURCE_SHA256)
        .map_err(|e| FetchError::Unread(e.to_string()))?;
    let workspace = PathBuf::from(
        config
            .read(&WORKSPACE)
            .map_err(|e| FetchError::Unread(e.to_string()))?,
    );
    let insecure = config
        .read(&INSECURE)
        .map_err(|e| FetchError::Unread(e.to_string()))?;
    let url = blob_url(&reference, insecure)?;
    let named = url
        .rsplit_once("sha256:")
        .map(|(_, hex)| hex)
        .unwrap_or_default();
    if named != sha256 {
        return Err(FetchError::OtherDigest {
            named: named.to_string(),
            expected: sha256,
        });
    }
    let client = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|e| FetchError::Unread(e.to_string()))?;
    let archive = workspace.join(".polar-source.tar.gz");
    fetch(&client, &url, &sha256, MAX_ARCHIVE, &archive).await?;
    let unpacked = unpack(&archive, &workspace);
    let _ = std::fs::remove_file(&archive);
    unpacked
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::path;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// A gzipped tar of these files.
    fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (name, body) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *body).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    /// A gzipped tar of one entry whose name is written as it is, which `tar::Builder` would refuse to write.
    fn hostile(name: &str, kind: tar::EntryType, link: Option<&str>) -> Vec<u8> {
        let mut header = tar::Header::new_old();
        header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
        if let Some(link) = link {
            header.as_old_mut().linkname[..link.len()].copy_from_slice(link.as_bytes());
        }
        header.set_entry_type(kind);
        header.set_size(0);
        header.set_mode(0o644);
        header.set_cksum();
        let mut tar = Vec::new();
        tar.extend_from_slice(header.as_bytes());
        tar.extend_from_slice(&[0u8; 1024]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar).unwrap();
        gz.finish().unwrap()
    }

    fn sha256(body: &[u8]) -> String {
        format!("{:x}", Sha256::digest(body))
    }

    async fn serving(body: Vec<u8>) -> (MockServer, String) {
        let server = MockServer::start().await;
        Mock::given(path(format!("/v2/build-sources/blobs/sha256:{HEX}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&server)
            .await;
        let url = format!("{}/v2/build-sources/blobs/sha256:{HEX}", server.uri());
        (server, url)
    }

    #[test]
    fn a_blob_is_read_at_its_registrys_address_and_only_when_pinned() {
        let reference = format!("registry.local:5000/build-sources@sha256:{HEX}");
        assert_eq!(
            blob_url(&reference, true).unwrap(),
            format!("http://registry.local:5000/v2/build-sources/blobs/sha256:{HEX}")
        );
        assert!(blob_url(&reference, false).unwrap().starts_with("https://"));
        for unpinned in [
            "registry.local:5000/build-sources:latest".to_string(),
            "registry.local:5000/build-sources@sha256:abc".to_string(),
            format!("build-sources@sha256:{HEX}"),
            format!(
                "registry.local:5000/build-sources@sha256:{}",
                HEX.to_uppercase()
            ),
        ] {
            assert!(blob_url(&unpinned, true).is_err(), "{unpinned}");
        }
    }

    #[tokio::test]
    async fn an_archive_with_its_digest_is_unpacked_and_then_removed() {
        let body = archive(&[
            ("src/main.rs", b"fn main() {}"),
            ("Cargo.toml", b"[package]"),
        ]);
        let (_server, url) = serving(body.clone()).await;
        let workspace = tempfile::tempdir().unwrap();
        let into = workspace.path().join(".polar-source.tar.gz");
        fetch(
            &reqwest::Client::new(),
            &url,
            &sha256(&body),
            MAX_ARCHIVE,
            &into,
        )
        .await
        .unwrap();
        unpack(&into, workspace.path()).unwrap();
        assert_eq!(
            std::fs::read(workspace.path().join("src/main.rs")).unwrap(),
            b"fn main() {}"
        );
        assert_eq!(
            std::fs::read(workspace.path().join("Cargo.toml")).unwrap(),
            b"[package]"
        );
    }

    /// What has another digest than the one named is refused, and nothing of it is left to unpack.
    #[tokio::test]
    async fn an_archive_with_another_digest_is_refused_and_nothing_is_left() {
        let body = archive(&[("evil.sh", b"rm -rf /")]);
        let (_server, url) = serving(body).await;
        let workspace = tempfile::tempdir().unwrap();
        let into = workspace.path().join(".polar-source.tar.gz");
        let refused = fetch(&reqwest::Client::new(), &url, HEX, MAX_ARCHIVE, &into).await;
        assert!(
            matches!(refused, Err(FetchError::WrongDigest { .. })),
            "{refused:?}"
        );
        assert!(!into.exists());
        assert_eq!(std::fs::read_dir(workspace.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn an_archive_past_its_bound_is_refused() {
        let body = archive(&[("big", &[7u8; 4096])]);
        let (_server, url) = serving(body.clone()).await;
        let workspace = tempfile::tempdir().unwrap();
        let into = workspace.path().join(".polar-source.tar.gz");
        let refused = fetch(&reqwest::Client::new(), &url, &sha256(&body), 64, &into).await;
        assert!(
            matches!(refused, Err(FetchError::TooLarge(64))),
            "{refused:?}"
        );
        assert!(!into.exists());
    }

    /// An entry outside the workspace, by an absolute path, a `..`, or a link that leads out, is refused.
    #[test]
    fn an_entry_that_would_leave_the_workspace_is_refused() {
        for (name, kind, link) in [
            ("../outside", tar::EntryType::Regular, None),
            ("/etc/outside", tar::EntryType::Regular, None),
            ("a/../../outside", tar::EntryType::Regular, None),
            ("escape", tar::EntryType::Symlink, Some("../../etc")),
            ("escape", tar::EntryType::Symlink, Some("/etc")),
            ("fifo", tar::EntryType::Fifo, None),
            ("device", tar::EntryType::Char, None),
        ] {
            let workspace = tempfile::tempdir().unwrap();
            let into = workspace.path().join("source.tar.gz");
            std::fs::write(&into, hostile(name, kind, link)).unwrap();
            let refused = unpack(&into, workspace.path());
            assert!(
                matches!(refused, Err(FetchError::Escapes(_))),
                "{name}: {refused:?}"
            );
        }
    }

    #[test]
    fn a_link_that_stays_inside_is_kept() {
        let workspace = tempfile::tempdir().unwrap();
        let into = workspace.path().join("source.tar.gz");
        std::fs::write(
            &into,
            hostile("docs/latest", tar::EntryType::Symlink, Some("v1")),
        )
        .unwrap();
        unpack(&into, workspace.path()).unwrap();
        assert_eq!(
            std::fs::read_link(workspace.path().join("docs/latest")).unwrap(),
            PathBuf::from("v1")
        );
    }

    /// A registry that accepts and never answers ends the fetch at its deadline, as every call out is bounded.
    #[tokio::test]
    async fn a_registry_that_never_answers_ends_the_fetch_at_its_deadline() {
        let server = MockServer::start().await;
        Mock::given(path(format!("/v2/build-sources/blobs/sha256:{HEX}")))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(600)))
            .mount(&server)
            .await;
        let url = format!("{}/v2/build-sources/blobs/sha256:{HEX}", server.uri());
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(300))
            .build()
            .unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let started = std::time::Instant::now();
        let refused = fetch(&client, &url, HEX, MAX_ARCHIVE, &workspace.path().join("a")).await;
        assert!(matches!(refused, Err(FetchError::Unread(_))), "{refused:?}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn the_section_is_sound_and_its_defaults_parse() {
        assert_eq!(SECTION.defaults_problems(), Vec::<String>::new());
    }
}
