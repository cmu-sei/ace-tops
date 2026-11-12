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

//! A log as C2SP tlog-tiles (<https://c2sp.org/tlog-tiles>, read 2026-11-10), the layout a reader outside Cassini
//! fetches it in: its checkpoint, its hash tiles and its entry bundles, each at a path the spec fixes. A tile of level 0
//! holds up to 256 leaf hashes; one of level `L` above it holds the roots of full tiles of the level below; an entry
//! bundle holds the leaves themselves, each after its length as a big-endian `u16`. A tile not yet full is served
//! with its width (`.p/<W>`), and a full tile never changes, so a mirror is a directory of these files and a reader
//! checks what it fetched against a checkpoint, not the place it fetched it from.
//!
//! A path is read only in the one form [`Tile::path`] writes, so a tile has one name.

use crate::checkpoint::{Checkpoint, NoteVerifier, open_witnessed};
use crate::merkle::{Hash, leaf_hash, root};
use thiserror::Error;

/// How many hashes a full tile holds, and how many entries a full bundle.
pub const TILE_WIDTH: u64 = 256;

/// The longest entry a bundle carries: its length prefix is two bytes.
pub const MAX_ENTRY: usize = u16::MAX as usize;

/// The highest level the spec names.
pub const MAX_LEVEL: u8 = 63;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TileError {
    #[error("an entry of {0} bytes is longer than a bundle carries ({MAX_ENTRY})")]
    TooLong(usize),
    #[error("the bundle ends inside an entry")]
    Short,
    #[error("the bundle holds more than its {0} entries")]
    Trailing(u64),
    #[error("there is no {0}")]
    Missing(String),
    #[error("{0} could not be fetched: {1}")]
    Fetch(String, String),
    #[error("the entries do not make the tree the checkpoint signs")]
    Root,
    #[error("the checkpoint does not open with the log's key: {0}")]
    Unsigned(String),
    #[error("{0}: {1}")]
    Write(String, String),
}

/// Which tiles: the hashes at a level, or the entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Level {
    Hashes(u8),
    Entries,
}

/// A tile, or an entry bundle: its level, its index within the level, and how many hashes or entries it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tile {
    level: Level,
    index: u64,
    width: u64,
}

impl Tile {
    /// The tile, if it is one: a level the spec names, and a width from 1 to 256.
    pub fn new(level: Level, index: u64, width: u64) -> Option<Self> {
        let level_fits = match level {
            Level::Hashes(l) => l <= MAX_LEVEL,
            Level::Entries => true,
        };
        (level_fits && (1..=TILE_WIDTH).contains(&width)).then_some(Self {
            level,
            index,
            width,
        })
    }

    pub fn level(&self) -> Level {
        self.level
    }

    pub fn index(&self) -> u64 {
        self.index
    }

    pub fn width(&self) -> u64 {
        self.width
    }

    /// Its path under the log's prefix: `tile/<L>/<N>[.p/<W>]` or `tile/entries/<N>[.p/<W>]`, the index in three-digit
    /// groups, all but the last starting with `x`.
    pub fn path(&self) -> String {
        let level = match self.level {
            Level::Hashes(l) => l.to_string(),
            Level::Entries => "entries".to_string(),
        };
        let mut n = self.index;
        let mut groups = vec![format!("{:03}", n % 1000)];
        n /= 1000;
        while n > 0 {
            groups.push(format!("x{:03}", n % 1000));
            n /= 1000;
        }
        groups.reverse();
        let partial = if self.width < TILE_WIDTH {
            format!(".p/{}", self.width)
        } else {
            String::new()
        };
        format!("tile/{level}/{}{partial}", groups.join("/"))
    }

    /// The tile `path` names, if it is written as [`Tile::path`] writes it. The numbers are read loosely and the tile
    /// is then written back: only a path that is its own writing is one, so leading zeros, a signed number, a `.p/256`
    /// or an `x000` group never name a tile.
    pub fn parse(path: &str) -> Option<Self> {
        let rest = path.strip_prefix("tile/")?;
        let mut parts: Vec<&str> = rest.split('/').collect();
        let level = match parts.first()? {
            &"entries" => Level::Entries,
            l => Level::Hashes(l.parse().ok()?),
        };
        parts.remove(0);
        let mut width = TILE_WIDTH;
        if parts.len() >= 2 && parts[parts.len() - 2].ends_with(".p") {
            width = parts.pop()?.parse().ok()?;
            let last = parts.len() - 1;
            parts[last] = parts[last].strip_suffix(".p")?;
        }
        let (last, groups) = parts.split_last()?;
        let mut index: u64 = 0;
        for group in groups {
            let group: u64 = group.strip_prefix('x')?.parse().ok()?;
            index = index.checked_mul(1000)?.checked_add(group)?;
        }
        index = index.checked_mul(1000)?.checked_add(last.parse().ok()?)?;
        let tile = Self::new(level, index, width)?;
        (tile.path() == path).then_some(tile)
    }
}

/// The bytes of `tile` of hashes, in a tree whose leaves hash to `leaves`; none if the tree has not those nodes yet.
/// Each hash is the root of the leaves under it, so a tile above level 0 holds the roots of full tiles below.
pub fn hash_tile(leaves: &[Hash], tile: Tile) -> Option<Vec<u8>> {
    let Level::Hashes(level) = tile.level else {
        return None;
    };
    let span = TILE_WIDTH.checked_pow(u32::from(level))?;
    let mut bytes = Vec::with_capacity(tile.width as usize * 32);
    for j in 0..tile.width {
        let node = tile.index.checked_mul(TILE_WIDTH)?.checked_add(j)?;
        let start = node.checked_mul(span)?;
        let end = start.checked_add(span)?;
        if end > leaves.len() as u64 {
            return None;
        }
        bytes.extend_from_slice(&root(&leaves[start as usize..end as usize]));
    }
    Some(bytes)
}

/// The bundle of `entries`, each after its length.
pub fn entry_bundle<E: AsRef<[u8]>>(entries: &[E]) -> Result<Vec<u8>, TileError> {
    let mut bytes = Vec::new();
    for entry in entries {
        let entry = entry.as_ref();
        let length = u16::try_from(entry.len()).map_err(|_| TileError::TooLong(entry.len()))?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(entry);
    }
    Ok(bytes)
}

/// The `width` entries of a bundle, and nothing after them.
pub fn parse_entry_bundle(mut bytes: &[u8], width: u64) -> Result<Vec<Vec<u8>>, TileError> {
    let mut entries = Vec::new();
    for _ in 0..width {
        let (length, rest) = bytes.split_first_chunk::<2>().ok_or(TileError::Short)?;
        let length = usize::from(u16::from_be_bytes(*length));
        if rest.len() < length {
            return Err(TileError::Short);
        }
        let (entry, rest) = rest.split_at(length);
        entries.push(entry.to_vec());
        bytes = rest;
    }
    if !bytes.is_empty() {
        return Err(TileError::Trailing(width));
    }
    Ok(entries)
}

/// The entry bundles of a log of `size` leaves, in order: the full ones, then the partial one, if any.
pub fn entry_tiles(size: u64) -> Vec<Tile> {
    let full = size / TILE_WIDTH;
    let mut tiles: Vec<Tile> = (0..full)
        .map(|n| Tile {
            level: Level::Entries,
            index: n,
            width: TILE_WIDTH,
        })
        .collect();
    if !size.is_multiple_of(TILE_WIDTH) {
        tiles.push(Tile {
            level: Level::Entries,
            index: full,
            width: size % TILE_WIDTH,
        });
    }
    tiles
}

/// Every leaf of the tree `checkpoint` states, read from its entry bundles: `fetch` gives a path's bytes, none where
/// there is nothing at it. The leaves are given back only when they make the checkpoint's root, so what was fetched,
/// from wherever, is the log the checkpoint's signer stated; whether that signer is trusted is the caller's, who opened
/// the note.
pub fn read_log<F>(checkpoint: &Checkpoint, mut fetch: F) -> Result<Vec<Vec<u8>>, TileError>
where
    F: FnMut(&str) -> Result<Option<Vec<u8>>, String>,
{
    let mut leaves = Vec::new();
    for tile in entry_tiles(checkpoint.size) {
        let path = tile.path();
        let bytes = fetch(&path)
            .map_err(|e| TileError::Fetch(path.clone(), e))?
            .ok_or_else(|| TileError::Missing(path.clone()))?;
        leaves.extend(parse_entry_bundle(&bytes, tile.width)?);
    }
    let hashes: Vec<Hash> = leaves.iter().map(|l| leaf_hash(l)).collect();
    if root(&hashes) != checkpoint.root {
        return Err(TileError::Root);
    }
    Ok(leaves)
}

/// What [`mirror`] did: the checkpoint the mirror now holds, and how many bundles it fetched for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mirrored {
    pub checkpoint: Checkpoint,
    pub fetched: usize,
}

/// Brings the mirror in `dir` up to the log `fetch` serves (a path under the log's prefix to its bytes, or none): its
/// checkpoint, which must be signed by the pinned `store` key and co-signed by the pinned `witness`, dated no more than
/// a minute past `now` (`open_witnessed`; record-store.md, "Bite 5"), and every entry bundle the checkpoint's tree needs. A full
/// bundle already in the mirror is not fetched again, since what it holds never changes; the partial one is. Nothing is
/// written unless the bundles make the root the checkpoint signs, and the checkpoint is written last, each file whole
/// or not at all: so the mirror is always a log some checkpoint states, the one before or this one. Whether this log is
/// the one read before, grown, is its reader's to judge.
pub fn mirror<F>(
    dir: &std::path::Path,
    store: &NoteVerifier,
    witness: &NoteVerifier,
    now: u64,
    mut fetch: F,
) -> Result<Mirrored, TileError>
where
    F: FnMut(&str) -> Result<Option<Vec<u8>>, String>,
{
    let note = fetch("checkpoint")
        .map_err(|e| TileError::Fetch("checkpoint".to_string(), e))?
        .ok_or_else(|| TileError::Missing("checkpoint".to_string()))?;
    let note =
        String::from_utf8(note).map_err(|_| TileError::Unsigned("it is not text".to_string()))?;
    let checkpoint = open_witnessed(&note, store, witness, now)
        .map_err(|e| TileError::Unsigned(e.to_string()))?;
    let mut bundles = std::collections::BTreeMap::new();
    let mut fetched = Vec::new();
    for tile in entry_tiles(checkpoint.size) {
        let path = tile.path();
        let held = if tile.width == TILE_WIDTH {
            std::fs::read(dir.join(&path)).ok()
        } else {
            None
        };
        let bytes = match held {
            Some(bytes) => bytes,
            None => {
                let bytes = fetch(&path)
                    .map_err(|e| TileError::Fetch(path.clone(), e))?
                    .ok_or_else(|| TileError::Missing(path.clone()))?;
                fetched.push(path.clone());
                bytes
            }
        };
        bundles.insert(path, bytes);
    }
    read_log(&checkpoint, |path| Ok(bundles.get(path).cloned()))?;
    for path in &fetched {
        write_whole(&dir.join(path), &bundles[path])?;
    }
    write_whole(&dir.join("checkpoint"), note.as_bytes())?;
    Ok(Mirrored {
        checkpoint,
        fetched: fetched.len(),
    })
}

/// Writes `bytes` to `path` whole or not at all: a file beside it, renamed over it.
fn write_whole(path: &std::path::Path, bytes: &[u8]) -> Result<(), TileError> {
    let failed = |e: std::io::Error| TileError::Write(path.display().to_string(), e.to_string());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(failed)?;
    }
    let mut next = path.as_os_str().to_owned();
    next.push(".next");
    std::fs::write(&next, bytes).map_err(failed)?;
    std::fs::rename(&next, path).map_err(failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tile(level: Level, index: u64, width: u64) -> Tile {
        Tile::new(level, index, width).unwrap()
    }

    /// The spec's own example, and the forms around it.
    #[test]
    fn a_tile_is_named_as_the_spec_names_it() {
        assert_eq!(
            tile(Level::Hashes(0), 1_234_067, 256).path(),
            "tile/0/x001/x234/067"
        );
        assert_eq!(tile(Level::Hashes(3), 0, 256).path(), "tile/3/000");
        assert_eq!(tile(Level::Entries, 5, 7).path(), "tile/entries/005.p/7");
        assert_eq!(
            tile(Level::Hashes(1), 1000, 255).path(),
            "tile/1/x001/000.p/255"
        );
        assert_eq!(
            Tile::parse("tile/0/x001/x234/067"),
            Some(tile(Level::Hashes(0), 1_234_067, 256))
        );
        assert_eq!(
            Tile::parse("tile/entries/005.p/7"),
            Some(tile(Level::Entries, 5, 7))
        );
        assert_eq!(
            Tile::parse("tile/63/000"),
            Some(tile(Level::Hashes(63), 0, 256))
        );
    }

    /// A tile has one name: every other spelling of it, and everything that names no tile, is refused.
    #[test]
    fn only_the_one_name_is_read() {
        for path in [
            "tile/0/x000/067",
            "tile/0/67",
            "tile/0/0067",
            "tile/00/000",
            "tile/64/000",
            "tile/256/000",
            "tile/-1/000",
            "tile/0/000.p/256",
            "tile/0/000.p/0",
            "tile/0/000.p/05",
            "tile/0/000.p/",
            "tile/0/000.p",
            "tile/0/x067",
            "tile/0/000/",
            "tile/0/",
            "tile/entry/000",
            "tile/0/0a0",
            "tile/0/x1/000",
            "tiles/0/000",
            "/tile/0/000",
            "tile/0/x018/x446/x744/x073/x709/x551/616",
            "tile/+0/000",
            "tile/0/+67",
            "tile/0/x+01/000",
            "tile/0/000.p/+5",
            "tile/0/x001/1000",
            "",
        ] {
            assert_eq!(Tile::parse(path), None, "{path}");
        }
        assert_eq!(
            Tile::parse("tile/0/x018/x446/x744/x073/x709/x551/615"),
            Some(tile(Level::Hashes(0), u64::MAX, 256))
        );
    }

    #[test]
    fn a_tile_is_a_level_the_spec_names_and_a_width_from_one_to_256() {
        assert!(Tile::new(Level::Hashes(64), 0, 1).is_none());
        assert!(Tile::new(Level::Hashes(0), 0, 0).is_none());
        assert!(Tile::new(Level::Hashes(0), 0, 257).is_none());
        let t = tile(Level::Hashes(2), 9, 1);
        assert_eq!((t.level(), t.index(), t.width()), (Level::Hashes(2), 9, 1));
    }

    /// Level 0 holds the leaf hashes; level 1 the roots of full level-0 tiles; nothing is served that the tree has not.
    #[test]
    fn hash_tiles_hold_leaf_hashes_then_roots_of_full_tiles() {
        let leaves: Vec<Hash> = (0..600u32).map(|i| leaf_hash(&i.to_be_bytes())).collect();
        let zero = hash_tile(&leaves, tile(Level::Hashes(0), 2, 88)).unwrap();
        assert_eq!(zero, leaves[512..600].concat());
        assert_eq!(hash_tile(&leaves, tile(Level::Hashes(0), 2, 89)), None);
        assert_eq!(hash_tile(&leaves, tile(Level::Hashes(0), 2, 256)), None);
        let one = hash_tile(&leaves, tile(Level::Hashes(1), 0, 2)).unwrap();
        assert_eq!(
            one,
            [root(&leaves[..256]), root(&leaves[256..512])].concat()
        );
        assert_eq!(hash_tile(&leaves, tile(Level::Hashes(1), 0, 3)), None);
        assert_eq!(hash_tile(&leaves, tile(Level::Entries, 0, 1)), None);
        assert_eq!(
            hash_tile(&leaves, tile(Level::Hashes(63), u64::MAX, 1)),
            None
        );
    }

    #[test]
    fn a_bundle_carries_entries_up_to_its_length_prefix() {
        let longest = vec![7u8; MAX_ENTRY];
        let bytes = entry_bundle(&[b"".to_vec(), longest.clone()]).unwrap();
        assert_eq!(&bytes[..4], &[0, 0, 0xff, 0xff]);
        assert_eq!(
            parse_entry_bundle(&bytes, 2).unwrap(),
            vec![vec![], longest]
        );
        assert_eq!(
            entry_bundle(&[vec![0u8; MAX_ENTRY + 1]]),
            Err(TileError::TooLong(MAX_ENTRY + 1))
        );
        assert_eq!(parse_entry_bundle(&bytes, 3), Err(TileError::Short));
        assert_eq!(parse_entry_bundle(&bytes, 1), Err(TileError::Trailing(1)));
        assert_eq!(parse_entry_bundle(&[0], 1), Err(TileError::Short));
        assert_eq!(parse_entry_bundle(&[0, 2, 1], 1), Err(TileError::Short));
    }

    #[test]
    fn a_log_is_its_full_bundles_then_its_partial_one() {
        assert!(entry_tiles(0).is_empty());
        assert_eq!(entry_tiles(256), vec![tile(Level::Entries, 0, 256)]);
        assert_eq!(
            entry_tiles(513),
            vec![
                tile(Level::Entries, 0, 256),
                tile(Level::Entries, 1, 256),
                tile(Level::Entries, 2, 1)
            ]
        );
    }

    /// A log served from `leaves`, its checkpoint signed by `signer`: every path it serves, and its bytes.
    fn served(
        leaves: &[Vec<u8>],
        signer: &crate::checkpoint::NoteSigner,
    ) -> std::collections::BTreeMap<String, Vec<u8>> {
        let hashes: Vec<Hash> = leaves.iter().map(|l| leaf_hash(l)).collect();
        let mut served: std::collections::BTreeMap<String, Vec<u8>> =
            entry_tiles(leaves.len() as u64)
                .into_iter()
                .map(|t| {
                    let from = (t.index * TILE_WIDTH) as usize;
                    (
                        t.path(),
                        entry_bundle(&leaves[from..from + t.width as usize]).unwrap(),
                    )
                })
                .collect();
        let text = Checkpoint {
            origin: "example.org/log".to_string(),
            size: leaves.len() as u64,
            root: root(&hashes),
        }
        .text();
        let note = format!("{}{}", signer.sign(&text), witness().cosign_line(&text, T));
        served.insert("checkpoint".to_string(), note.into_bytes());
        served
    }

    const T: u64 = 1_731_300_000;

    fn witness() -> crate::checkpoint::Cosigner {
        crate::checkpoint::Cosigner::new(
            "example.org/witness",
            p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap(),
        )
        .unwrap()
    }

    /// The store's key and the witness's, as a reader pins them.
    fn pinned(key: &crate::checkpoint::NoteSigner) -> (NoteVerifier, NoteVerifier) {
        (
            NoteVerifier::parse(&key.verifier_key()).unwrap(),
            NoteVerifier::parse(&witness().verifier_key()).unwrap(),
        )
    }

    fn signer(seed: u8) -> crate::checkpoint::NoteSigner {
        crate::checkpoint::NoteSigner::new(
            "example.org/key",
            p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap(),
        )
        .unwrap()
    }

    /// A mirror is brought up to the log: full bundles it holds are not fetched again, the partial one is, and what it
    /// holds after reads back as the log its checkpoint states.
    #[test]
    fn a_mirror_fetches_what_it_lacks_and_reads_back_as_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let key = signer(1);
        let (store, witness) = pinned(&key);
        let leaves: Vec<Vec<u8>> = (0..600u32).map(|i| i.to_be_bytes().to_vec()).collect();

        let log = served(&leaves[..300], &key);
        let mut asked = Vec::new();
        let done = mirror(dir.path(), &store, &witness, T, |p| {
            asked.push(p.to_string());
            Ok(log.get(p).cloned())
        })
        .unwrap();
        assert_eq!((done.checkpoint.size, done.fetched), (300, 2));
        assert_eq!(
            asked,
            ["checkpoint", "tile/entries/000", "tile/entries/001.p/44"]
        );

        let log = served(&leaves, &key);
        let mut asked = Vec::new();
        let done = mirror(dir.path(), &store, &witness, T, |p| {
            asked.push(p.to_string());
            Ok(log.get(p).cloned())
        })
        .unwrap();
        assert_eq!((done.checkpoint.size, done.fetched), (600, 2));
        assert_eq!(
            asked,
            ["checkpoint", "tile/entries/001", "tile/entries/002.p/88"]
        );
        let from_disk = |p: &str| Ok(std::fs::read(dir.path().join(p)).ok());
        let note =
            String::from_utf8(std::fs::read(dir.path().join("checkpoint")).unwrap()).unwrap();
        let checkpoint = open_witnessed(&note, &store, &witness, T).unwrap();
        assert_eq!(read_log(&checkpoint, from_disk).unwrap(), leaves);
    }

    /// Nothing is written from a log that is not the one its checkpoint states, or whose checkpoint another key signed:
    /// the mirror stays as it was.
    #[test]
    fn a_mirror_is_left_as_it_was_by_a_log_that_does_not_check() {
        let dir = tempfile::tempdir().unwrap();
        let key = signer(1);
        let (store, witness) = pinned(&key);
        let leaves: Vec<Vec<u8>> = (0..10u32).map(|i| i.to_be_bytes().to_vec()).collect();
        mirror(dir.path(), &store, &witness, T, |p| {
            Ok(served(&leaves[..5], &key).get(p).cloned())
        })
        .unwrap();
        let before = std::fs::read(dir.path().join("checkpoint")).unwrap();

        let mut changed = served(&leaves, &key);
        changed.get_mut("tile/entries/000.p/10").unwrap()[3] ^= 1;
        assert_eq!(
            mirror(dir.path(), &store, &witness, T, |p| Ok(changed
                .get(p)
                .cloned())),
            Err(TileError::Root)
        );
        let other = served(&leaves, &signer(2));
        assert!(matches!(
            mirror(dir.path(), &store, &witness, T, |p| Ok(other
                .get(p)
                .cloned())),
            Err(TileError::Unsigned(_))
        ));
        // The store's checkpoint without the witness's co-signature is not taken.
        let mut unwitnessed = served(&leaves, &key);
        let text = String::from_utf8(unwitnessed["checkpoint"].clone()).unwrap();
        let (signed, _) = text.split_at(text.rfind('\u{2014}').unwrap());
        assert_eq!(
            signed.matches('\u{2014}').count(),
            1,
            "the store's line alone"
        );
        unwitnessed.insert("checkpoint".to_string(), signed.as_bytes().to_vec());
        assert!(matches!(
            mirror(dir.path(), &store, &witness, T, |p| Ok(unwitnessed
                .get(p)
                .cloned())),
            Err(TileError::Unsigned(_))
        ));
        assert_eq!(
            mirror(dir.path(), &store, &witness, T, |_| Ok(None)),
            Err(TileError::Missing("checkpoint".to_string()))
        );
        assert_eq!(
            mirror(dir.path(), &store, &witness, T, |_| Err(
                "refused".to_string()
            )),
            Err(TileError::Fetch(
                "checkpoint".to_string(),
                "refused".to_string()
            ))
        );
        assert_eq!(
            std::fs::read(dir.path().join("checkpoint")).unwrap(),
            before
        );
        assert!(!dir.path().join("tile/entries/000.p/10").exists());
        let names: Vec<String> = std::fs::read_dir(dir.path().join("tile/entries"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, ["000.p"]);
    }

    /// A reader gets the leaves only when they make the checkpoint's root, and says which bundle was missing or failed.
    #[test]
    fn a_log_is_read_whole_and_checked_against_its_checkpoint() {
        let leaves: Vec<Vec<u8>> = (0..300u32).map(|i| i.to_be_bytes().to_vec()).collect();
        let hashes: Vec<Hash> = leaves.iter().map(|l| leaf_hash(l)).collect();
        let checkpoint = Checkpoint {
            origin: "example.org/log".to_string(),
            size: 300,
            root: root(&hashes),
        };
        let served = |path: &str| -> Result<Option<Vec<u8>>, String> {
            Ok(match path {
                "tile/entries/000" => Some(entry_bundle(&leaves[..256]).unwrap()),
                "tile/entries/001.p/44" => Some(entry_bundle(&leaves[256..]).unwrap()),
                _ => None,
            })
        };
        assert_eq!(read_log(&checkpoint, served).unwrap(), leaves);

        let other = Checkpoint {
            root: root(&hashes[..299]),
            ..checkpoint.clone()
        };
        assert_eq!(read_log(&other, served), Err(TileError::Root));
        let larger = Checkpoint {
            size: 301,
            ..checkpoint.clone()
        };
        assert_eq!(
            read_log(&larger, served),
            Err(TileError::Missing("tile/entries/001.p/45".to_string()))
        );
        assert_eq!(
            read_log(&checkpoint, |_| Err("refused".to_string())),
            Err(TileError::Fetch(
                "tile/entries/000".to_string(),
                "refused".to_string()
            ))
        );
        let empty = Checkpoint {
            size: 0,
            root: root(&[]),
            ..checkpoint
        };
        assert_eq!(read_log(&empty, served).unwrap(), Vec::<Vec<u8>>::new());
    }
}
