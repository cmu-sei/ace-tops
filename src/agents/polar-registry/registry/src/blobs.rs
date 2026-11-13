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

//! The content store (docs/plans/registry/nix-cache.md): each blob named by the SHA-256 of its plain content, and kept
//! compressed with zstd, as git names an object by its content and keeps it compressed. Nothing enters without saying
//! what it must be (its plain hash and size), and nothing is kept that is not: decoding stops the moment the content
//! passes the size it was said to have, every blob is decoded and hashed before it is kept (what an upstream sent as
//! zstd as it arrives, what is compressed here once it is written), and a blob is renamed into place only once it is
//! whole, checked and on disk. So what the store holds under a name is always what the name says.
//!
//! Beside each blob, `<hex>.json` says how it is kept: its plain size, and the hash and size of the compressed file,
//! which a cache states as `FileHash` and `FileSize`. A blob counts as held only once both are in place.

use polar_registry_nix::hash::{Hashing, Sha256};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use structured_zstd::decoding::StreamingDecoder;
use structured_zstd::encoding::{CompressionLevel, StreamingEncoder};

/// The zstd level content that arrives plain is compressed at (measured: docs/plans/registry/nix-cache.claude.md).
pub const DEFAULT_LEVEL: i32 = 9;

/// What a blob must be: the hash and size of its plain content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expect {
    pub digest: Sha256,
    pub size: u64,
}

/// A blob the store holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blob {
    /// The hash of its plain content, which is its name.
    pub digest: Sha256,
    /// The size of its plain content.
    pub size: u64,
    /// The hash of the compressed file, as it is kept and sent.
    pub file_hash: Sha256,
    /// The size of the compressed file.
    pub file_size: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Kept {
    size: u64,
    file_sha256: String,
    file_size: u64,
}

/// Why a blob was not kept.
#[derive(Debug, thiserror::Error)]
pub enum PutError {
    #[error("the content is not what it was said to be: {0}")]
    NotAsSaid(String),
    #[error("the compressed content does not decode: {0}")]
    Undecodable(String),
    #[error("the store could not be written: {0}")]
    Io(#[from] io::Error),
}

/// The content store, in a directory of its own.
pub struct Blobs {
    blobs: PathBuf,
    tmp: PathBuf,
    level: i32,
}

/// A name for a temporary file that no other write in this process uses.
pub(crate) fn temp_name() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// Reads from `inner`, and writes everything it reads to `copy` as well.
struct Tee<R, W> {
    inner: R,
    copy: W,
}

impl<R: Read, W: Write> Read for Tee<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.copy.write_all(&buf[..n])?;
        Ok(n)
    }
}

/// Copies `from` into `to`, refusing to go past `bound` bytes; a read that fails is `undecodable`'s.
fn copy_bounded(
    from: &mut impl Read,
    to: &mut impl Write,
    bound: u64,
    undecodable: bool,
) -> Result<(), PutError> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut count = 0u64;
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if undecodable => return Err(PutError::Undecodable(e.to_string())),
            Err(e) => return Err(PutError::Io(e)),
        };
        count += n as u64;
        if count > bound {
            return Err(PutError::NotAsSaid(format!(
                "longer than its {bound} bytes"
            )));
        }
        to.write_all(&buf[..n])?;
    }
}

/// The hash and size of what `zstd` decodes to, read no further than `expect` allows, and held to it.
fn check_decoded(zstd: impl Read, expect: Expect) -> Result<(), PutError> {
    let mut decoder = StreamingDecoder::new(zstd);
    let mut plain = Hashing::new(io::sink());
    copy_bounded(&mut decoder, &mut plain, expect.size, true)?;
    let (digest, size, _) = plain.finish();
    if (digest, size) != (expect.digest, expect.size) {
        return Err(PutError::NotAsSaid(format!(
            "{size} bytes hashing to {digest}, not {} bytes hashing to {}",
            expect.size, expect.digest
        )));
    }
    Ok(())
}

/// The most a zstd stream of `size` plain bytes is read for: zstd's own bound (a block stored as it is costs a few bytes
/// per 128 KiB) with room for its headers, and more besides.
pub fn compressed_bound(size: u64) -> u64 {
    size + size / 128 + (1 << 20)
}

impl Blobs {
    /// The store in `root`, compressing what arrives plain at `level`. A write left unfinished by a stop is removed.
    pub fn open(root: &Path, level: i32) -> io::Result<Self> {
        let blobs = root.join("blobs");
        let tmp = root.join("tmp");
        fs::create_dir_all(&blobs)?;
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp)?;
        Ok(Self { blobs, tmp, level })
    }

    /// Where the blob named `digest` is kept, compressed.
    pub fn file(&self, digest: &Sha256) -> PathBuf {
        self.blobs.join(format!("{}.zst", digest.hex()))
    }

    fn kept(&self, digest: &Sha256) -> PathBuf {
        self.blobs.join(format!("{}.json", digest.hex()))
    }

    /// The blob named `digest`, if the store holds it.
    pub fn get(&self, digest: &Sha256) -> io::Result<Option<Blob>> {
        let text = match fs::read_to_string(self.kept(digest)) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let kept: Kept = serde_json::from_str(&text).map_err(io::Error::other)?;
        let file_hash = format!("sha256:{}", kept.file_sha256)
            .parse()
            .map_err(io::Error::other)?;
        Ok(Some(Blob {
            digest: *digest,
            size: kept.size,
            file_hash,
            file_size: kept.file_size,
        }))
    }

    /// The blob held under `expect`'s name, if there is one, held to `expect`'s size.
    fn held(&self, expect: Expect) -> Result<Option<Blob>, PutError> {
        match self.get(&expect.digest)? {
            Some(blob) if blob.size == expect.size => Ok(Some(blob)),
            Some(blob) => Err(PutError::NotAsSaid(format!(
                "{} is held as {} bytes, not {}",
                expect.digest, blob.size, expect.size
            ))),
            None => Ok(None),
        }
    }

    /// Keeps `zstd`, content compressed elsewhere, exactly as it arrives, once it decodes to what `expect` says. No more
    /// is read of it than any compression of that much content needs (`compressed_bound`): a stream that would go on
    /// past it, with frames that decode to nothing, is cut there and refused.
    pub fn put_zstd(&self, zstd: impl Read, expect: Expect) -> Result<Blob, PutError> {
        let zstd = zstd.take(compressed_bound(expect.size));
        if let Some(blob) = self.held(expect)? {
            return Ok(blob);
        }
        let tmp = self.tmp.join(temp_name());
        let written = (|| {
            let mut file = Hashing::new(BufWriter::new(File::create(&tmp)?));
            check_decoded(
                Tee {
                    inner: zstd,
                    copy: &mut file,
                },
                expect,
            )?;
            let (file_hash, file_size, file) = file.finish();
            file.into_inner().map_err(|e| e.into_error())?.sync_all()?;
            self.commit(&tmp, expect, file_hash, file_size)
        })();
        if written.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        written
    }

    /// Keeps `plain` compressed at the store's level, once it is what `expect` says and what was written decodes to it.
    pub fn put_plain(&self, mut plain: impl Read, expect: Expect) -> Result<Blob, PutError> {
        if let Some(blob) = self.held(expect)? {
            return Ok(blob);
        }
        let tmp = self.tmp.join(temp_name());
        let written = (|| {
            let file = Hashing::new(BufWriter::new(File::create(&tmp)?));
            let mut encoder = StreamingEncoder::new(file, CompressionLevel::from_level(self.level));
            let mut hashed = Hashing::new(&mut encoder);
            copy_bounded(&mut plain, &mut hashed, expect.size, false)?;
            let (digest, size, _) = hashed.finish();
            if (digest, size) != (expect.digest, expect.size) {
                return Err(PutError::NotAsSaid(format!(
                    "{size} bytes hashing to {digest}, not {} bytes hashing to {}",
                    expect.size, expect.digest
                )));
            }
            let (file_hash, file_size, file) = encoder.finish()?.finish();
            file.into_inner().map_err(|e| e.into_error())?.sync_all()?;
            // What this store wrote is held to what it was given, as an upstream's zstd is.
            check_decoded(File::open(&tmp)?, expect)?;
            self.commit(&tmp, expect, file_hash, file_size)
        })();
        if written.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        written
    }

    /// Puts the checked, synced file `tmp` in place as `expect`'s blob, and then says how it is kept.
    fn commit(
        &self,
        tmp: &Path,
        expect: Expect,
        file_hash: Sha256,
        file_size: u64,
    ) -> Result<Blob, PutError> {
        fs::rename(tmp, self.file(&expect.digest))?;
        let kept = serde_json::to_vec(&Kept {
            size: expect.size,
            file_sha256: file_hash.hex(),
            file_size,
        })
        .map_err(io::Error::other)?;
        let kept_tmp = self.tmp.join(temp_name());
        let mut f = File::create(&kept_tmp)?;
        f.write_all(&kept)?;
        f.sync_all()?;
        fs::rename(&kept_tmp, self.kept(&expect.digest))?;
        File::open(&self.blobs)?.sync_all()?;
        Ok(Blob {
            digest: expect.digest,
            size: expect.size,
            file_hash,
            file_size,
        })
    }
}
