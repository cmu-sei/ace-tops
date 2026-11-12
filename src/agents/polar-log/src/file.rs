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

//! A log kept in a file on an agent's own volume (docs/architecture/record-store.md, "The shape": the credentials
//! ledger's): leaves appended and synced before an append returns, and replayed whole when the log is opened. Each leaf
//! is framed as its length (four bytes, big-endian), a check of that length (the first four bytes of its SHA-256), its
//! bytes, and its RFC 9162 leaf hash, so damage is found where it is. The recovery rule: a frame cut short at the end
//! of the file, which is what a write that did not finish leaves, is cut back to the last whole frame and said; a
//! frame whose length or hash does not check, anywhere, refuses the log, since that is no write that stopped. A write
//! that stops leaves a prefix of its frame, so a length that is there is right: without its check, a damaged length
//! that claimed more than the file holds would pass for a cut-short write and take every frame after it away. *(The frames, rather than tiles, are this session's choice, for review:
//! the same leaves, hashes and checkpoints; tiles are made from them where a log is served.)*

use crate::entry::{Entry, Leaf};
use crate::merkle::{Hash, leaf_hash, root};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// The longest leaf a frame holds: room for a deployment's pack.
pub const MAX_LEAF: usize = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum LogError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path}: the frame at byte {at} is damaged ({why}): the log is not read")]
    Damaged {
        path: PathBuf,
        at: u64,
        why: &'static str,
    },
    #[error("a leaf of {0} bytes is longer than a frame holds")]
    TooLong(usize),
    /// Another holder has the log open: two writers would fork it, so it is opened by one at a time.
    #[error("{path}: the log is held open by another process")]
    Held { path: PathBuf },
}

/// Reads exactly `buf.len()` bytes at `offset`, leaving the file's position where appending wants it.
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::read_exact_at(file, buf, offset)
    }
}

/// A frame's header: its length, and the length's check.
const HEADER: usize = 8;

/// The check of a frame's length: the first four bytes of its SHA-256.
fn length_check(len: [u8; 4]) -> [u8; 4] {
    use sha2::{Digest, Sha256};
    Sha256::digest(len)[..4].try_into().expect("four bytes")
}

/// What replaying a frame gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Replayed {
    /// A leaf and the entry in it, both read.
    Entry { seq: u64, leaf: Leaf, entry: Entry },
    /// A frame whose hash is right, whose bytes are not a leaf or hold no entry: written so, by a writer at fault. The
    /// caller never passes over one as it may an entry of a type it does not know.
    Malformed { seq: u64, why: String },
}

/// A file-backed log, open for appending.
#[derive(Debug)]
pub struct FileLog {
    path: PathBuf,
    file: File,
    hashes: Vec<Hash>,
    /// Where each leaf's bytes begin in the file, and how many there are.
    spans: Vec<(u64, u32)>,
    /// Where the next frame goes.
    end: u64,
}

/// What opening a log found.
#[derive(Debug)]
pub struct Opened {
    pub log: FileLog,
    /// Every frame, in order.
    pub replayed: Vec<Replayed>,
    /// The bytes of a frame cut short at the end, cut back: what a write that did not finish left.
    pub torn: Option<u64>,
}

impl FileLog {
    /// The log at `path`, made empty (mode 0600) if there is none, locked for this holder alone, and replayed; while
    /// another holds it, [`LogError::Held`].
    pub fn open(path: &Path) -> Result<Opened, LogError> {
        let io = |source| LogError::Io {
            path: path.to_path_buf(),
            source,
        };
        let mut options = OpenOptions::new();
        options.read(true).append(true).create(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(path).map_err(io)?;
        // Locked before it is read, so what is replayed is not being appended to; the operating system lets go of the
        // lock when its holder ends, however it ends.
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(LogError::Held {
                    path: path.to_path_buf(),
                });
            }
            Err(std::fs::TryLockError::Error(e)) => return Err(io(e)),
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(io)?;

        let mut at = 0usize;
        let mut hashes = Vec::new();
        let mut spans = Vec::new();
        let mut replayed = Vec::new();
        let mut torn = None;
        while at < bytes.len() {
            let left = bytes.len() - at;
            if left < HEADER {
                torn = Some(left as u64);
                break;
            }
            let len_bytes: [u8; 4] = bytes[at..at + 4].try_into().expect("four bytes");
            if bytes[at + 4..at + HEADER] != length_check(len_bytes) {
                return Err(LogError::Damaged {
                    path: path.to_path_buf(),
                    at: at as u64,
                    why: "its length does not check",
                });
            }
            let len = u32::from_be_bytes(len_bytes) as usize;
            if len > MAX_LEAF {
                return Err(LogError::Damaged {
                    path: path.to_path_buf(),
                    at: at as u64,
                    why: "its length is longer than any leaf",
                });
            }
            if left < HEADER + len + 32 {
                torn = Some(left as u64);
                break;
            }
            let leaf_bytes = &bytes[at + HEADER..at + HEADER + len];
            let stored: Hash = bytes[at + HEADER + len..at + HEADER + len + 32]
                .try_into()
                .expect("thirty-two bytes");
            let hash = leaf_hash(leaf_bytes);
            if hash != stored {
                return Err(LogError::Damaged {
                    path: path.to_path_buf(),
                    at: at as u64,
                    why: "its hash is not its bytes'",
                });
            }
            let seq = hashes.len() as u64;
            hashes.push(hash);
            spans.push(((at + HEADER) as u64, len as u32));
            replayed.push(
                match Leaf::decode(leaf_bytes)
                    .and_then(|leaf| Entry::decode(&leaf.entry).map(|e| (leaf, e)))
                {
                    Ok((leaf, entry)) => Replayed::Entry { seq, leaf, entry },
                    Err(e) => Replayed::Malformed {
                        seq,
                        why: e.to_string(),
                    },
                },
            );
            at += HEADER + len + 32;
        }
        if torn.is_some() {
            file.set_len(at as u64).map_err(io)?;
            file.sync_data().map_err(io)?;
        }
        file.seek(SeekFrom::End(0)).map_err(io)?;
        Ok(Opened {
            log: FileLog {
                path: path.to_path_buf(),
                file,
                hashes,
                spans,
                end: at as u64,
            },
            replayed,
            torn,
        })
    }

    /// Appends `leaf`, synced before it returns: its sequence number.
    pub fn append(&mut self, leaf: &Leaf) -> Result<u64, LogError> {
        self.append_all(std::slice::from_ref(leaf))?;
        Ok(self.hashes.len() as u64 - 1)
    }

    /// Appends `leaves` in order, synced once, before it returns: how many leaves the log holds then. A copy of a log
    /// appends thousands at once; a write that stops part way leaves a prefix, as [`FileLog::open`] says.
    pub fn append_all(&mut self, leaves: &[Leaf]) -> Result<u64, LogError> {
        let mut frames = Vec::new();
        let mut added = Vec::with_capacity(leaves.len());
        for leaf in leaves {
            let bytes = leaf.encode();
            if bytes.len() > MAX_LEAF {
                return Err(LogError::TooLong(bytes.len()));
            }
            let hash = leaf_hash(&bytes);
            let len_bytes = (bytes.len() as u32).to_be_bytes();
            let at = self.end + frames.len() as u64;
            frames.extend_from_slice(&len_bytes);
            frames.extend_from_slice(&length_check(len_bytes));
            frames.extend_from_slice(&bytes);
            frames.extend_from_slice(&hash);
            added.push((hash, (at + HEADER as u64, bytes.len() as u32)));
        }
        let io = |source| LogError::Io {
            path: self.path.clone(),
            source,
        };
        self.file.write_all(&frames).map_err(io)?;
        self.file.sync_data().map_err(io)?;
        for (hash, span) in added {
            self.hashes.push(hash);
            self.spans.push(span);
        }
        self.end += frames.len() as u64;
        Ok(self.hashes.len() as u64)
    }

    /// The leaf at `seq`, read back from the file and checked against its hash; none past the end.
    pub fn leaf(&self, seq: u64) -> Result<Option<Leaf>, LogError> {
        let Some(&(offset, len)) = self.spans.get(seq as usize) else {
            return Ok(None);
        };
        let mut bytes = vec![0u8; len as usize];
        read_at(&self.file, &mut bytes, offset).map_err(|source| LogError::Io {
            path: self.path.clone(),
            source,
        })?;
        if leaf_hash(&bytes) != self.hashes[seq as usize] {
            return Err(LogError::Damaged {
                path: self.path.clone(),
                at: offset - HEADER as u64,
                why: "its bytes changed since it was read",
            });
        }
        Leaf::decode(&bytes)
            .map(Some)
            .map_err(|_| LogError::Damaged {
                path: self.path.clone(),
                at: offset - HEADER as u64,
                why: "its bytes are no leaf",
            })
    }

    /// How many leaves it holds.
    pub fn size(&self) -> u64 {
        self.hashes.len() as u64
    }

    /// The leaf hashes, in order: what proofs and checkpoints are made from.
    pub fn hashes(&self) -> &[Hash] {
        &self.hashes
    }

    /// The tree's root over every leaf.
    pub fn root(&self) -> Hash {
        root(&self.hashes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(n: u8) -> Leaf {
        Leaf {
            entry: Entry {
                kind: "credentials.grant".to_string(),
                version: 1,
                critical: true,
                writer: "3.1.0 x86_64-unknown-linux-musl".to_string(),
                event: vec![n; 3],
            }
            .encode(),
            admitted_at_ms: 1_000 + u64::from(n),
            submitter: "credentials-agent".to_string(),
        }
    }

    #[test]
    fn what_is_appended_is_replayed_in_order_and_the_root_is_the_same() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let mut opened = FileLog::open(&path).unwrap();
        assert!(opened.replayed.is_empty());
        for n in 0..3 {
            assert_eq!(opened.log.append(&leaf(n)).unwrap(), u64::from(n));
        }
        let root = opened.log.root();
        drop(opened);
        let again = FileLog::open(&path).unwrap();
        assert_eq!(again.torn, None);
        assert_eq!(again.log.size(), 3);
        assert_eq!(again.log.root(), root);
        let events: Vec<Vec<u8>> = again
            .replayed
            .iter()
            .map(|r| match r {
                Replayed::Entry { entry, .. } => entry.event.clone(),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(events, [vec![0; 3], vec![1; 3], vec![2; 3]]);
        assert_eq!(again.log.leaf(1).unwrap(), Some(leaf(1)));
        assert_eq!(again.log.leaf(3).unwrap(), None);
    }

    #[test]
    fn a_leaf_appended_reads_back_by_its_sequence_and_a_changed_one_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let mut opened = FileLog::open(&path).unwrap();
        for n in 0..3 {
            opened.log.append(&leaf(n)).unwrap();
        }
        for n in 0..3u8 {
            assert_eq!(opened.log.leaf(u64::from(n)).unwrap(), Some(leaf(n)));
        }
        // Changed under it after it was opened: not read as a leaf.
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 40;
        bytes[last] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        assert!(opened.log.leaf(2).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_log_one_holder_has_open_cannot_be_opened_by_another_until_it_is_let_go() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let first = FileLog::open(&path).unwrap();
        match FileLog::open(&path) {
            Err(LogError::Held { path: held }) => assert_eq!(held, path),
            other => panic!("a second holder opened the log: {other:?}"),
        }
        drop(first);
        FileLog::open(&path).unwrap();
    }

    #[test]
    fn the_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        FileLog::open(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn a_frame_cut_short_at_the_end_is_cut_back_and_said_and_appending_goes_on() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let mut opened = FileLog::open(&path).unwrap();
        opened.log.append(&leaf(0)).unwrap();
        opened.log.append(&leaf(1)).unwrap();
        drop(opened);
        let whole = std::fs::metadata(&path).unwrap().len();
        let one = FileLog::open(&dir.path().join("one.log")).unwrap();
        drop(one);
        // Cut the second frame short.
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(whole - 10).unwrap();
        drop(file);
        let mut again = FileLog::open(&path).unwrap();
        assert!(again.torn.is_some());
        assert_eq!(again.log.size(), 1);
        again.log.append(&leaf(2)).unwrap();
        drop(again);
        let last = FileLog::open(&path).unwrap();
        assert_eq!(last.torn, None);
        assert_eq!(last.log.size(), 2);
    }

    #[test]
    fn a_frame_damaged_before_the_end_refuses_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let mut opened = FileLog::open(&path).unwrap();
        opened.log.append(&leaf(0)).unwrap();
        opened.log.append(&leaf(1)).unwrap();
        drop(opened);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[10] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            FileLog::open(&path),
            Err(LogError::Damaged { at: 0, .. })
        ));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            bytes,
            "nothing is cut from a damaged log"
        );
    }

    /// One frame, written as `append` writes it, holding `bytes`.
    fn frame(bytes: &[u8]) -> Vec<u8> {
        let len = (bytes.len() as u32).to_be_bytes();
        [&len[..], &length_check(len), bytes, &leaf_hash(bytes)].concat()
    }

    /// A leaf whose bytes change after the log was opened, or that never were a leaf, is refused where its frame starts.
    #[test]
    fn a_leaf_that_is_not_what_was_replayed_is_refused_where_its_frame_starts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        std::fs::write(
            &path,
            [frame(b"no leaf"), frame(&leaf(1).encode())].concat(),
        )
        .unwrap();
        let opened = FileLog::open(&path).unwrap();
        assert!(matches!(
            opened.replayed[0],
            Replayed::Malformed { seq: 0, .. }
        ));
        assert!(matches!(
            opened.log.leaf(0),
            Err(LogError::Damaged {
                at: 0,
                why: "its bytes are no leaf",
                ..
            })
        ));
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[HEADER] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            opened.log.leaf(0),
            Err(LogError::Damaged {
                at: 0,
                why: "its bytes changed since it was read",
                ..
            })
        ));
        assert_eq!(opened.log.root(), crate::merkle::root(opened.log.hashes()));
        assert_ne!(opened.log.root(), Hash::default());
    }

    /// A tail of a whole header whose length does not check is damage, not a write cut short.
    #[test]
    fn a_header_alone_at_the_end_that_does_not_check_refuses_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        std::fs::write(
            &path,
            [frame(&leaf(0).encode()), vec![0, 0, 0, 9, 1, 2, 3, 4]].concat(),
        )
        .unwrap();
        assert!(matches!(
            FileLog::open(&path),
            Err(LogError::Damaged {
                why: "its length does not check",
                ..
            })
        ));
    }

    /// The last frame's length made larger is damage, not a write cut short: without its check it would pass for one,
    /// and the leaf would be cut away.
    #[test]
    fn the_last_frames_length_changed_refuses_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let mut bytes = frame(&leaf(0).encode());
        bytes[3] += 1;
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            FileLog::open(&path),
            Err(LogError::Damaged {
                at: 0,
                why: "its length does not check",
                ..
            })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    /// A leaf of MAX_LEAF bytes is appended and one longer is not; a header claiming more is damage, and one claiming
    /// exactly that with the bytes missing is a write cut short.
    #[test]
    fn a_leaf_is_at_most_max_leaf_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let mut opened = FileLog::open(&path).unwrap();
        let sized = |event: usize| Leaf {
            entry: vec![0; event],
            ..leaf(0)
        };
        let overhead = sized(MAX_LEAF - 64).encode().len() - (MAX_LEAF - 64);
        let longest = sized(MAX_LEAF - overhead);
        assert_eq!(longest.encode().len(), MAX_LEAF);
        assert!(matches!(
            opened.log.append(&sized(MAX_LEAF - overhead + 1)),
            Err(LogError::TooLong(_))
        ));
        assert_eq!(opened.log.append(&longest).unwrap(), 0);
        drop(opened);
        assert_eq!(FileLog::open(&path).unwrap().log.size(), 1);

        for (claimed, refused) in [(MAX_LEAF as u32 + 1, true), (MAX_LEAF as u32, false)] {
            let len = claimed.to_be_bytes();
            std::fs::write(&path, [&len[..], &length_check(len), b"short"].concat()).unwrap();
            let opened = FileLog::open(&path);
            if refused {
                assert!(matches!(
                    opened,
                    Err(LogError::Damaged {
                        why: "its length is longer than any leaf",
                        ..
                    })
                ));
            } else {
                assert_eq!(opened.unwrap().torn, Some(HEADER as u64 + 5));
            }
        }
    }

    #[test]
    fn a_frame_whose_bytes_are_no_entry_is_said_and_never_taken_for_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let mut opened = FileLog::open(&path).unwrap();
        opened
            .log
            .append(&Leaf {
                entry: b"not cbor".to_vec(),
                admitted_at_ms: 1,
                submitter: "credentials-agent".to_string(),
            })
            .unwrap();
        drop(opened);
        let again = FileLog::open(&path).unwrap();
        assert!(matches!(
            again.replayed[..],
            [Replayed::Malformed { seq: 0, .. }]
        ));
    }
}
