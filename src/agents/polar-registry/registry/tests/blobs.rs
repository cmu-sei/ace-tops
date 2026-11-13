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

//! The content store: what it keeps is what it was told, kept as it came or compressed here, and what it refuses
//! leaves nothing behind.

use polar_registry::blobs::{Blobs, Expect, PutError};
use polar_registry_nix::hash::Sha256;
use std::io::Read;
use std::path::Path;
use std::process::Command;
use structured_zstd::decoding::StreamingDecoder;
use structured_zstd::encoding::{CompressionLevel, compress_to_vec};

fn expect(content: &[u8]) -> Expect {
    Expect {
        digest: Sha256::of(content),
        size: content.len() as u64,
    }
}

fn decoded(path: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    StreamingDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut out)
        .unwrap();
    out
}

/// What a store's unfinished writes directory holds: nothing, once every write has ended.
fn leftovers(root: &Path) -> usize {
    std::fs::read_dir(root.join("tmp")).unwrap().count()
}

fn content() -> Vec<u8> {
    (0..200_000u32)
        .flat_map(|i| (i % 251).to_le_bytes())
        .collect()
}

#[test]
fn plain_content_is_kept_compressed_under_its_plain_hash() {
    let dir = tempfile::tempdir().unwrap();
    let blobs = Blobs::open(dir.path(), 3).unwrap();
    let content = content();
    assert_eq!(blobs.get(&Sha256::of(&content)).unwrap(), None);
    let blob = blobs.put_plain(&content[..], expect(&content)).unwrap();
    let file = std::fs::read(blobs.file(&blob.digest)).unwrap();
    assert!(file.len() < content.len() / 4, "{} bytes kept", file.len());
    assert_eq!(
        (blob.file_hash, blob.file_size),
        (Sha256::of(&file), file.len() as u64)
    );
    assert_eq!(decoded(&blobs.file(&blob.digest)), content);
    assert_eq!(blobs.get(&blob.digest).unwrap(), Some(blob));
    assert_eq!(
        Blobs::open(dir.path(), 3)
            .unwrap()
            .get(&blob.digest)
            .unwrap(),
        Some(blob)
    );
    assert_eq!(leftovers(dir.path()), 0);
}

#[test]
fn zstd_is_kept_byte_for_byte_as_it_came() {
    let dir = tempfile::tempdir().unwrap();
    let blobs = Blobs::open(dir.path(), 3).unwrap();
    let content = content();
    let zstd = compress_to_vec(&content[..], CompressionLevel::from_level(1));
    let blob = blobs.put_zstd(&zstd[..], expect(&content)).unwrap();
    assert_eq!(std::fs::read(blobs.file(&blob.digest)).unwrap(), zstd);
    assert_eq!(blob.file_hash, Sha256::of(&zstd));
}

#[test]
fn zstd_from_the_reference_tool_is_kept_as_it_came() {
    let dir = tempfile::tempdir().unwrap();
    let blobs = Blobs::open(dir.path(), 3).unwrap();
    let content = content();
    let plain = dir.path().join("plain");
    std::fs::write(&plain, &content).unwrap();
    let out = match Command::new("zstd")
        .args(["-19", "-q", "-c"])
        .arg(&plain)
        .output()
    {
        Ok(out) if out.status.success() => out.stdout,
        _ => {
            eprintln!("skipped: the zstd tool is not on the PATH");
            return;
        }
    };
    let blob = blobs.put_zstd(&out[..], expect(&content)).unwrap();
    assert_eq!(std::fs::read(blobs.file(&blob.digest)).unwrap(), out);
}

#[test]
fn content_that_is_not_what_it_was_said_to_be_is_refused_and_leaves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let blobs = Blobs::open(dir.path(), 3).unwrap();
    let content = content();
    let zstd = compress_to_vec(&content[..], CompressionLevel::from_level(1));
    let other = Expect {
        digest: Sha256::of(b"other"),
        size: content.len() as u64,
    };
    let shorter = Expect {
        size: content.len() as u64 - 1,
        ..expect(&content)
    };
    let longer = Expect {
        size: content.len() as u64 + 1,
        ..expect(&content)
    };
    for e in [other, shorter, longer] {
        assert!(
            matches!(
                blobs.put_plain(&content[..], e),
                Err(PutError::NotAsSaid(_))
            ),
            "{e:?}"
        );
        assert!(
            matches!(blobs.put_zstd(&zstd[..], e), Err(PutError::NotAsSaid(_))),
            "{e:?}"
        );
        assert_eq!(blobs.get(&e.digest).unwrap(), None);
    }
    assert_eq!(leftovers(dir.path()), 0);
    assert_eq!(
        std::fs::read_dir(dir.path().join("blobs")).unwrap().count(),
        0
    );
}

#[test]
fn decoding_stops_at_the_size_it_was_told() {
    // A small archive that decodes to 64 MiB of zeros, said to be 1 KiB: refused without decoding it all.
    let dir = tempfile::tempdir().unwrap();
    let blobs = Blobs::open(dir.path(), 3).unwrap();
    let bomb = compress_to_vec(&vec![0u8; 64 << 20][..], CompressionLevel::from_level(1));
    assert!(bomb.len() < 64 << 10);
    let said = Expect {
        digest: Sha256::of(&[0u8; 1024]),
        size: 1024,
    };
    let err = blobs.put_zstd(&bomb[..], said).unwrap_err();
    assert!(
        matches!(err, PutError::NotAsSaid(ref why) if why.contains("longer")),
        "{err}"
    );
}

#[test]
fn what_is_not_zstd_or_holds_more_after_it_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let blobs = Blobs::open(dir.path(), 3).unwrap();
    let content = content();
    let mut zstd = compress_to_vec(&content[..], CompressionLevel::from_level(1));
    assert!(matches!(
        blobs.put_zstd(&content[..], expect(&content)),
        Err(PutError::Undecodable(_))
    ));
    zstd.extend_from_slice(b"trailing");
    assert!(matches!(
        blobs.put_zstd(&zstd[..], expect(&content)),
        Err(PutError::Undecodable(_))
    ));
    assert_eq!(leftovers(dir.path()), 0);
}

#[test]
fn a_blob_held_is_held_to_its_size() {
    let dir = tempfile::tempdir().unwrap();
    let blobs = Blobs::open(dir.path(), 3).unwrap();
    let content = content();
    let blob = blobs.put_plain(&content[..], expect(&content)).unwrap();
    // Held: the content is not read again.
    assert_eq!(
        blobs.put_plain(&b"unread"[..], expect(&content)).unwrap(),
        blob
    );
    let wrong = Expect {
        size: 1,
        ..expect(&content)
    };
    assert!(matches!(
        blobs.put_plain(&content[..], wrong),
        Err(PutError::NotAsSaid(_))
    ));
}

#[test]
fn a_write_left_unfinished_is_removed_at_open() {
    let dir = tempfile::tempdir().unwrap();
    Blobs::open(dir.path(), 3).unwrap();
    std::fs::write(dir.path().join("tmp/partial"), b"cut short").unwrap();
    Blobs::open(dir.path(), 3).unwrap();
    assert_eq!(leftovers(dir.path()), 0);
}

#[test]
fn writes_at_once_each_keep_their_own_content() {
    let dir = tempfile::tempdir().unwrap();
    let blobs = std::sync::Arc::new(Blobs::open(dir.path(), 1).unwrap());
    let threads: Vec<_> = (0..16u8)
        .map(|i| {
            let blobs = blobs.clone();
            std::thread::spawn(move || {
                let content: Vec<u8> = (0..300_000u32)
                    .map(|n| (n as u8) ^ i.wrapping_mul(37))
                    .collect();
                let blob = blobs.put_plain(&content[..], expect(&content)).unwrap();
                (blob, content)
            })
        })
        .collect();
    for t in threads {
        let (blob, content) = t.join().unwrap();
        assert_eq!(decoded(&blobs.file(&blob.digest)), content);
    }
    assert_eq!(leftovers(dir.path()), 0);
}

/// A reader that is interrupted once, then gives `content`; or that fails, if `content` is None.
struct Uneven {
    interrupted: bool,
    content: Option<std::io::Cursor<Vec<u8>>>,
}

impl Read for Uneven {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        match &mut self.content {
            Some(c) => c.read(buf),
            None => Err(std::io::Error::other("the source failed")),
        }
    }
}

#[test]
fn an_interrupted_read_is_taken_again_and_a_failed_one_is_the_source_s() {
    let dir = tempfile::tempdir().unwrap();
    let blobs = Blobs::open(dir.path(), 3).unwrap();
    let content = content();
    let source = Uneven {
        interrupted: false,
        content: Some(std::io::Cursor::new(content.clone())),
    };
    blobs.put_plain(source, expect(&content)).unwrap();
    let failing = Uneven {
        interrupted: false,
        content: None,
    };
    let other = expect(b"other");
    assert!(matches!(
        blobs.put_plain(failing, other),
        Err(PutError::Io(_))
    ));
    let zstd = compress_to_vec(&content[..], CompressionLevel::from_level(1));
    let source = Uneven {
        interrupted: false,
        content: Some(std::io::Cursor::new(zstd)),
    };
    let dir2 = tempfile::tempdir().unwrap();
    Blobs::open(dir2.path(), 3)
        .unwrap()
        .put_zstd(source, expect(&content))
        .unwrap();
}

#[test]
fn a_record_that_cannot_be_read_is_an_error_not_an_absence() {
    let dir = tempfile::tempdir().unwrap();
    let blobs = Blobs::open(dir.path(), 3).unwrap();
    let digest = Sha256::of(b"x");
    std::fs::create_dir(dir.path().join(format!("blobs/{}.json", digest.hex()))).unwrap();
    assert!(blobs.get(&digest).is_err());
}

#[test]
fn zstd_is_read_no_further_than_its_content_could_need() {
    use polar_registry::blobs::compressed_bound;
    assert_eq!(compressed_bound(0), 1 << 20);
    assert_eq!(
        compressed_bound(128 << 20),
        (128 << 20) + (1 << 20) + (1 << 20)
    );
    // A frame of the content, then frames that decode to nothing (skippable: magic, length, bytes) past the bound.
    let dir = tempfile::tempdir().unwrap();
    let blobs = Blobs::open(dir.path(), 3).unwrap();
    let content = b"a little content".to_vec();
    let mut zstd = compress_to_vec(&content[..], CompressionLevel::from_level(1));
    let skippable = |len: u32| {
        let mut f = 0x184D2A50u32.to_le_bytes().to_vec();
        f.extend_from_slice(&len.to_le_bytes());
        f.extend(std::iter::repeat_n(0u8, len as usize));
        f
    };
    let mut within = zstd.clone();
    within.extend(skippable(1024));
    blobs.put_zstd(&within[..], expect(&content)).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let blobs = Blobs::open(dir.path(), 3).unwrap();
    zstd.extend(skippable(2 << 20));
    assert!(blobs.put_zstd(&zstd[..], expect(&content)).is_err());
    assert_eq!(leftovers(dir.path()), 0);
}
