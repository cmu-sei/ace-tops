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

//! Faults (docs/plans/registry/nix-cache.md): a path the cache does not hold, asked for by its hash part, is looked for
//! at the cache's upstreams, in order. An upstream's narinfo is taken only when it is for the path asked for, signed by
//! the key that upstream is trusted by, and names its archive by a place under the upstream (never another host); the
//! archive is fetched, held to the narinfo's hash and size as it enters the content store, and the path's narinfo is
//! signed with Polar's key beside the upstream's. Every fault is recorded, whatever came of it, in `faults.jsonl`: the
//! path, who asked, and what each upstream said, so that the faults of a build are the list of its inputs.
//!
//! Faults can be switched off. Then a path not held is refused, and the refusal is recorded: with faults off, the record
//! is the list of what a build lacked.
//!
//! Fetching is `Fetch`'s, so the cache goes out only as its agent does (the builder's protocol handlers). A narinfo comes
//! whole; an archive comes in pieces, each written into the content store as it arrives, so what a fault holds in memory
//! is a few pieces, not the archive.

use crate::nix_cache::{Archive, NixCache, PathInfo};
use polar_registry_nix::narinfo::NarInfo;
use polar_registry_nix::signature::PublicKey;
use polar_registry_nix::store_path::is_hash_part;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// The largest narinfo read from an upstream.
pub const MAX_NARINFO: u64 = 64 * 1024;

/// How the cache reaches its upstreams.
#[async_trait::async_trait]
pub trait Fetch: Send + Sync {
    /// The body at `path` (from `/`) under `upstream`, at most `limit` bytes; `None` when the upstream does not hold it.
    async fn get(
        &self,
        upstream: &Upstream,
        path: &str,
        limit: u64,
    ) -> Result<Option<Vec<u8>>, String>;

    /// The archive at `path` under `upstream`, in pieces, at most `limit` bytes in all; `None` when the upstream does not
    /// hold it. Unless a way out says otherwise, the body whole, as one piece.
    async fn archive(
        &self,
        upstream: &Upstream,
        path: &str,
        limit: u64,
    ) -> Result<Option<Pieces>, String> {
        let Some(body) = self.get(upstream, path, limit).await? else {
            return Ok(None);
        };
        let (give, pieces) = tokio::sync::mpsc::channel(1);
        give.try_send(Ok(body)).expect("a channel of one holds one");
        Ok(Some(pieces))
    }
}

/// An archive as it arrives: its pieces in order, the stream closing after the last; a failure is the last it says.
pub type Pieces = tokio::sync::mpsc::Receiver<Result<Vec<u8>, String>>;

/// How many pieces of an archive wait between the network and the content store.
pub const PIECES_WAITING: usize = 4;

/// Reads an archive's pieces as one stream of bytes, for the content store, which writes on a thread of its own: each
/// piece is taken off the channel only when the last has been read.
pub struct PieceReader {
    pieces: Pieces,
    piece: Vec<u8>,
    at: usize,
}

impl PieceReader {
    pub fn new(pieces: Pieces) -> Self {
        Self {
            pieces,
            piece: Vec::new(),
            at: 0,
        }
    }
}

impl io::Read for PieceReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.at == self.piece.len() {
            match self.pieces.blocking_recv() {
                None => return Ok(0),
                Some(Ok(piece)) => {
                    self.piece = piece;
                    self.at = 0;
                }
                Some(Err(why)) => return Err(io::Error::other(why)),
            }
        }
        let n = buf.len().min(self.piece.len() - self.at);
        buf[..n].copy_from_slice(&self.piece[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

/// Fetches nothing: a cache with no upstreams.
pub struct NoFetch;

#[async_trait::async_trait]
impl Fetch for NoFetch {
    async fn get(&self, _: &Upstream, _: &str, _: u64) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }
}

/// A binary cache the cache fetches from, and the key it is trusted by.
#[derive(Debug, Clone)]
pub struct Upstream {
    /// Its address, as the record names it.
    pub url: String,
    pub key: PublicKey,
    /// The operation the agent declares that reaches it (`upstream`), which goes to the address its own variable holds.
    pub via: &'static str,
}

/// What became of one fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// Fetched, checked and held.
    Entered,
    /// No upstream holds it.
    Absent,
    /// An upstream offered it and it was refused, and no other gave it.
    Refused,
    /// Faults are off.
    Off,
}

#[derive(Serialize)]
struct Tried {
    upstream: String,
    said: String,
}

#[derive(Serialize)]
struct Record {
    at_unix_ms: u128,
    hash_part: String,
    requester: Option<String>,
    outcome: Outcome,
    store_path: Option<String>,
    nar_hash: Option<String>,
    nar_size: Option<u64>,
    tried: Vec<Tried>,
}

/// The cache, with what it faults from.
pub struct Faults {
    cache: Arc<NixCache>,
    upstreams: Vec<Upstream>,
    fetch: Arc<dyn Fetch>,
    on: AtomicBool,
    max_archive: AtomicU64,
    log: Mutex<File>,
    faulting: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

/// Whether `url`, a narinfo's `URL`, is a place under its cache: a relative path of plain characters, never `..`.
pub fn is_archive_place(url: &str) -> bool {
    (1..=256).contains(&url.len())
        && !url.starts_with('/')
        && url
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
        && url
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

impl Faults {
    /// `cache`, faulting from `upstreams` through `fetch` while `on`, its record in `root`.
    pub fn new(
        cache: Arc<NixCache>,
        root: &Path,
        upstreams: Vec<Upstream>,
        fetch: Arc<dyn Fetch>,
        on: bool,
        max_archive: u64,
    ) -> io::Result<Self> {
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("faults.jsonl"))?;
        Ok(Self {
            cache,
            upstreams,
            fetch,
            on: AtomicBool::new(on),
            max_archive: AtomicU64::new(max_archive),
            log: Mutex::new(log),
            faulting: Mutex::new(HashMap::new()),
        })
    }

    /// The cache faults are taken into.
    pub fn cache(&self) -> &Arc<NixCache> {
        &self.cache
    }

    /// Switches faults on or off.
    pub fn set_on(&self, on: bool) {
        self.on.store(on, Ordering::SeqCst);
    }

    /// Sets the largest archive a fault fetches.
    pub fn set_max_archive(&self, bytes: u64) {
        self.max_archive.store(bytes, Ordering::SeqCst);
    }

    async fn held(&self, hash_part: &str) -> io::Result<Option<NarInfo>> {
        let (cache, hash_part) = (self.cache.clone(), hash_part.to_string());
        tokio::task::spawn_blocking(move || cache.narinfo(&hash_part))
            .await
            .map_err(io::Error::other)?
    }

    /// The narinfo of the path whose hash part is `hash_part`: held, or faulted in, or none.
    pub async fn lookup(
        self: &Arc<Self>,
        hash_part: &str,
        requester: Option<SocketAddr>,
    ) -> io::Result<Option<NarInfo>> {
        if !is_hash_part(hash_part) {
            return Ok(None);
        }
        if let Some(info) = self.held(hash_part).await? {
            return Ok(Some(info));
        }
        if !self.on.load(Ordering::SeqCst) {
            self.record(hash_part, requester, Outcome::Off, None, Vec::new())
                .await?;
            return Ok(None);
        }
        // One fault for a path at a time; whoever waited finds it held.
        let lock = self
            .faulting
            .lock()
            .expect("the fault table is never poisoned")
            .entry(hash_part.to_string())
            .or_default()
            .clone();
        let _faulting = lock.lock().await;
        let found = self.fault(hash_part, requester).await;
        self.faulting
            .lock()
            .expect("the fault table is never poisoned")
            .remove(hash_part);
        found
    }

    async fn fault(
        self: &Arc<Self>,
        hash_part: &str,
        requester: Option<SocketAddr>,
    ) -> io::Result<Option<NarInfo>> {
        if let Some(info) = self.held(hash_part).await? {
            return Ok(Some(info));
        }
        let mut tried = Vec::new();
        for upstream in &self.upstreams {
            match self.from(upstream, hash_part).await {
                Ok(Some(info)) => {
                    tried.push(Tried {
                        upstream: upstream.url.clone(),
                        said: format!("entered, signed by {}", upstream.key.name),
                    });
                    self.record(hash_part, requester, Outcome::Entered, Some(&info), tried)
                        .await?;
                    return Ok(Some(info));
                }
                Ok(None) => tried.push(Tried {
                    upstream: upstream.url.clone(),
                    said: "not held".into(),
                }),
                Err(why) => {
                    tracing::warn!(upstream = %upstream.url, hash_part, "a fault was refused: {why}");
                    tried.push(Tried {
                        upstream: upstream.url.clone(),
                        said: why,
                    })
                }
            }
        }
        let outcome = if tried.iter().all(|t| t.said == "not held") {
            Outcome::Absent
        } else {
            Outcome::Refused
        };
        self.record(hash_part, requester, outcome, None, tried)
            .await?;
        Ok(None)
    }

    /// The path from `upstream`, checked and entered; `None` when it does not hold it; why not, when it is refused.
    async fn from(&self, upstream: &Upstream, hash_part: &str) -> Result<Option<NarInfo>, String> {
        let Some(text) = self
            .fetch
            .get(upstream, &format!("/{hash_part}.narinfo"), MAX_NARINFO)
            .await?
        else {
            return Ok(None);
        };
        let text = String::from_utf8(text).map_err(|_| "a narinfo that is not text".to_string())?;
        let info = NarInfo::parse(&text).map_err(|e| e.to_string())?;
        if info.store_path.hash_part() != hash_part {
            return Err(format!("a narinfo for another path, {}", info.store_path));
        }
        if !info.signed_by(&upstream.key) {
            return Err(format!("not signed by {}", upstream.key.name));
        }
        let zstd = match info.compression.as_str() {
            "zstd" => true,
            "none" => false,
            other => {
                return Err(format!(
                    "its archive is compressed with {other}, which is not taken yet"
                ));
            }
        };
        if !is_archive_place(&info.url) {
            return Err("its archive is not at a place under the cache".into());
        }
        let max_archive = self.max_archive.load(Ordering::SeqCst);
        if info.file_size.is_some_and(|size| size > max_archive) {
            return Err(format!("its archive is larger than {max_archive} bytes"));
        }
        let archive = self
            .fetch
            .archive(upstream, &format!("/{}", info.url), max_archive)
            .await?
            .ok_or_else(|| "its narinfo is held and its archive is not".to_string())?;
        let path = PathInfo {
            store_path: info.store_path,
            nar_hash: info.nar_hash,
            nar_size: info.nar_size,
            references: info.references,
            deriver: info.deriver,
            ca: info.ca,
            sigs: info.sigs,
        };
        let cache = self.cache.clone();
        tokio::task::spawn_blocking(move || {
            let archive = PieceReader::new(archive);
            cache.enter(
                path,
                if zstd {
                    Archive::Zstd(archive)
                } else {
                    Archive::Plain(archive)
                },
            )
        })
        .await
        .map_err(|e| e.to_string())?
        .map(Some)
        .map_err(|e| e.to_string())
    }

    async fn record(
        self: &Arc<Self>,
        hash_part: &str,
        requester: Option<SocketAddr>,
        outcome: Outcome,
        info: Option<&NarInfo>,
        tried: Vec<Tried>,
    ) -> io::Result<()> {
        let record = Record {
            at_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
            hash_part: hash_part.to_string(),
            requester: requester.map(|a| a.to_string()),
            outcome,
            store_path: info.map(|i| i.store_path.to_string()),
            nar_hash: info.map(|i| i.nar_hash.to_string()),
            nar_size: info.map(|i| i.nar_size),
            tried,
        };
        let mut line = serde_json::to_vec(&record).map_err(io::Error::other)?;
        line.push(b'\n');
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut log = this.log.lock().expect("the fault record is never poisoned");
            log.write_all(&line)?;
            log.sync_data()
        })
        .await
        .map_err(io::Error::other)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn pieces_read_as_one_stream_through_any_buffer_and_a_failure_is_an_error() {
        let (give, pieces) = tokio::sync::mpsc::channel(8);
        for piece in [b"0123456789".to_vec(), Vec::new(), b"abc".to_vec()] {
            give.try_send(Ok(piece)).unwrap();
        }
        drop(give);
        let mut reader = PieceReader::new(pieces);
        let mut read = Vec::new();
        let mut buf = [0u8; 3];
        loop {
            let n = reader.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            read.extend_from_slice(&buf[..n]);
        }
        assert_eq!(read, b"0123456789abc");

        let (give, pieces) = tokio::sync::mpsc::channel(8);
        give.try_send(Ok(b"part".to_vec())).unwrap();
        give.try_send(Err("the upstream went silent".into()))
            .unwrap();
        let mut whole = Vec::new();
        let err = PieceReader::new(pieces)
            .read_to_end(&mut whole)
            .unwrap_err();
        assert_eq!(err.to_string(), "the upstream went silent");
    }
}
