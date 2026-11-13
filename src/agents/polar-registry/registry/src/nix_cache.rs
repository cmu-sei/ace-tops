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

//! The Nix face (docs/plans/registry/nix-cache.md): Nix's binary cache protocol over the content store. A path enters
//! with what is known of it (its hash, size, references, the signatures it came with) and its archive; the archive
//! becomes a blob, and the path's narinfo is written, signed with Polar's key, only once its blob is held. The cache
//! answers `nix-cache-info`, a path's narinfo by its hash part, and an archive by its plain hash, as it is kept
//! (zstd); any other request is refused, so nothing a reader asks for names anything but a path or an archive.

use crate::blobs::{Blobs, Expect, PutError, temp_name};
use axum::Router;
use axum::body::Body;
use axum::extract::{Path as UrlPath, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use polar_registry_nix::hash::Sha256;
use polar_registry_nix::narinfo::{NarInfo, cache_info};
use polar_registry_nix::signature::{SecretKey, Signature};
use polar_registry_nix::store_path::{StorePath, is_hash_part};
use polar_registry_nix::{FormatError, nix32};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_util::io::ReaderStream;

/// The priority the cache states: Nix asks caches of lower numbers first (cache.nixos.org states 40).
pub const PRIORITY: u32 = 40;

/// What is known of a path before its archive enters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathInfo {
    pub store_path: StorePath,
    pub nar_hash: Sha256,
    pub nar_size: u64,
    pub references: BTreeSet<StorePath>,
    pub deriver: Option<StorePath>,
    pub ca: Option<String>,
    /// The signatures it came with, kept beside Polar's.
    pub sigs: Vec<Signature>,
}

/// A path's archive, as it arrives.
pub enum Archive<R> {
    /// Compressed with zstd elsewhere: kept as it is.
    Zstd(R),
    /// Plain: compressed here.
    Plain(R),
}

/// Why a path did not enter.
#[derive(Debug, thiserror::Error)]
pub enum EnterError {
    #[error(transparent)]
    Blob(#[from] PutError),
    #[error("{0} is held already, with another archive ({1})")]
    HeldOtherwise(StorePath, Sha256),
    #[error("the cache could not be written: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Format(#[from] FormatError),
}

/// The Nix cache: its narinfos, beside the content store its archives are in.
pub struct NixCache {
    blobs: Arc<Blobs>,
    infos: PathBuf,
    tmp: PathBuf,
    key: SecretKey,
    priority: u32,
}

impl NixCache {
    /// The cache in `root`, its archives in `blobs`, signing with `key`.
    pub fn open(root: &Path, blobs: Arc<Blobs>, key: SecretKey, priority: u32) -> io::Result<Self> {
        let infos = root.join("nix");
        let tmp = root.join("nix-tmp");
        fs::create_dir_all(&infos)?;
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp)?;
        Ok(Self {
            blobs,
            infos,
            tmp,
            key,
            priority,
        })
    }

    fn info_file(&self, hash_part: &str) -> PathBuf {
        self.infos.join(format!("{hash_part}.narinfo"))
    }

    /// The narinfo of the path whose hash part is `hash_part`, if the cache holds it.
    pub fn narinfo(&self, hash_part: &str) -> io::Result<Option<NarInfo>> {
        if !is_hash_part(hash_part) {
            return Ok(None);
        }
        match fs::read_to_string(self.info_file(hash_part)) {
            Ok(text) => NarInfo::parse(&text).map(Some).map_err(io::Error::other),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Takes in a path: its archive, held to `info`'s hash and size, then its narinfo, signed. A path held already with
    /// the same archive is left as it is; one held with another archive is refused, since a store path names one.
    /// Blocking: the archive is read, checked and written here.
    pub fn enter(
        &self,
        info: PathInfo,
        archive: Archive<impl Read>,
    ) -> Result<NarInfo, EnterError> {
        if let Some(held) = self.narinfo(info.store_path.hash_part())? {
            if held.store_path == info.store_path && held.nar_hash == info.nar_hash {
                return Ok(held);
            }
            return Err(EnterError::HeldOtherwise(held.store_path, held.nar_hash));
        }
        let expect = Expect {
            digest: info.nar_hash,
            size: info.nar_size,
        };
        let blob = match archive {
            Archive::Zstd(r) => self.blobs.put_zstd(r, expect)?,
            Archive::Plain(r) => self.blobs.put_plain(r, expect)?,
        };
        let mut narinfo = NarInfo {
            url: format!("nar/{}.nar.zst", blob.digest.nix32()),
            compression: "zstd".into(),
            file_hash: Some(blob.file_hash),
            file_size: Some(blob.file_size),
            store_path: info.store_path,
            nar_hash: info.nar_hash,
            nar_size: info.nar_size,
            references: info.references,
            deriver: info.deriver,
            sigs: info.sigs,
            ca: info.ca,
        };
        narinfo.sign(&self.key);
        let tmp = self.tmp.join(temp_name());
        let written = (|| {
            let mut f = File::create(&tmp)?;
            f.write_all(narinfo.render().as_bytes())?;
            f.sync_all()?;
            fs::rename(&tmp, self.info_file(narinfo.store_path.hash_part()))?;
            File::open(&self.infos)?.sync_all()
        })();
        if written.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        written?;
        Ok(narinfo)
    }
}

/// The cache's routes.
pub fn router(cache: Arc<NixCache>) -> Router {
    Router::new()
        .route("/nix-cache-info", get(info))
        .route("/:file", get(narinfo))
        .route("/nar/:file", get(nar))
        .with_state(cache)
}

fn not_held() -> Response {
    (StatusCode::NOT_FOUND, "not held\n").into_response()
}

fn failed(e: impl std::fmt::Display) -> Response {
    tracing::error!("the Nix cache could not answer: {e}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "the cache could not answer\n",
    )
        .into_response()
}

async fn info(State(cache): State<Arc<NixCache>>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/x-nix-cache-info")],
        cache_info(cache.priority),
    )
        .into_response()
}

async fn narinfo(State(cache): State<Arc<NixCache>>, UrlPath(file): UrlPath<String>) -> Response {
    let Some(hash_part) = file.strip_suffix(".narinfo") else {
        return not_held();
    };
    let hash_part = hash_part.to_string();
    let found = tokio::task::spawn_blocking(move || cache.narinfo(&hash_part)).await;
    match found {
        Ok(Ok(Some(info))) => (
            [(header::CONTENT_TYPE, "text/x-nix-narinfo")],
            info.render(),
        )
            .into_response(),
        Ok(Ok(None)) => not_held(),
        Ok(Err(e)) => failed(e),
        Err(e) => failed(e),
    }
}

async fn nar(State(cache): State<Arc<NixCache>>, UrlPath(file): UrlPath<String>) -> Response {
    let Some(digest) = file
        .strip_suffix(".nar.zst")
        .and_then(|h| nix32::decode::<32>(h).ok())
        .map(Sha256)
    else {
        return not_held();
    };
    let blob = match cache.blobs.get(&digest) {
        Ok(Some(blob)) => blob,
        Ok(None) => return not_held(),
        Err(e) => return failed(e),
    };
    let file = match tokio::fs::File::open(cache.blobs.file(&digest)).await {
        Ok(f) => f,
        Err(e) => return failed(e),
    };
    (
        [
            (header::CONTENT_TYPE, "application/x-nix-nar".to_string()),
            (header::CONTENT_LENGTH, blob.file_size.to_string()),
        ],
        Body::from_stream(ReaderStream::new(file)),
    )
        .into_response()
}

/// Serves the cache on `listener` until it fails.
pub async fn serve(listener: tokio::net::TcpListener, cache: Arc<NixCache>) -> io::Result<()> {
    axum::serve(listener, router(cache)).await
}
