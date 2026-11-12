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

//! Properties of the log's format (docs/architecture/record-store.md): one encoding for each value, proofs that hold
//! exactly for the tree they were made from, a file log whose recovery keeps a prefix and refuses damage, and tiles that
//! have one name each and give back exactly the log their checkpoint states.

use polar_log::checkpoint::{Checkpoint, Cosigner, NoteSigner, NoteVerifier, open, open_signed};
use polar_log::entry::{Continuation, Entry, Leaf};
use polar_log::file::FileLog;
use polar_log::merkle::{
    Hash, consistency_proof, inclusion_proof, leaf_hash, node_hash, root, verify_consistency,
    verify_inclusion,
};
use polar_log::tiles::{
    Level, TILE_WIDTH, Tile, TileError, entry_bundle, entry_tiles, hash_tile, parse_entry_bundle,
    read_log,
};
use proptest::prelude::*;

fn entry() -> impl Strategy<Value = Entry> {
    (
        "[a-z0-9.-]{1,24}",
        any::<u64>(),
        any::<bool>(),
        "[ -~]{1,40}",
        proptest::collection::vec(any::<u8>(), 0..64),
    )
        .prop_map(|(kind, version, critical, writer, event)| Entry {
            kind,
            version,
            critical,
            writer,
            event,
        })
}

fn leaf() -> impl Strategy<Value = Leaf> {
    (entry(), any::<u64>(), "[ -~]{1,40}").prop_map(|(e, admitted_at_ms, submitter)| Leaf {
        entry: e.encode(),
        admitted_at_ms,
        submitter,
    })
}

/// The root by another road: complete subtrees merged as a binary counter merges, then folded right to left, as
/// RFC 9162's own description of an append-only tree builds it. Agreeing with `root` for every size is the check.
fn root_by_counter(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return root(&[]);
    }
    // (hash, height)
    let mut stack: Vec<(Hash, u32)> = Vec::new();
    for l in leaves {
        let mut node = (*l, 0);
        while let Some(&(top, h)) = stack.last() {
            if h != node.1 {
                break;
            }
            stack.pop();
            node = (node_hash(&top, &node.0), h + 1);
        }
        stack.push(node);
    }
    let mut acc = stack.pop().expect("one").0;
    while let Some((left, _)) = stack.pop() {
        acc = node_hash(&left, &acc);
    }
    acc
}

fn hashes(n: usize) -> Vec<Hash> {
    (0..n)
        .map(|i| leaf_hash(&(i as u64).to_be_bytes()))
        .collect()
}

proptest! {
    #[test]
    fn an_entry_a_leaf_and_a_continuation_have_one_encoding_each(e in entry(), l in leaf(), count in any::<u64>(), digest in proptest::collection::vec(any::<u8>(), 0..40)) {
        prop_assert_eq!(Entry::decode(&e.encode()), Ok(e.clone()));
        prop_assert_eq!(Leaf::decode(&l.encode()), Ok(l.clone()));
        let c = Continuation { old_kind: "git".to_string(), alg: "sha1".to_string(), digest, count };
        prop_assert_eq!(Continuation::decode(&c.encode()), Ok(c));
    }

    // Deterministic: whatever bytes decode are the one encoding of what they decode to, and no bytes make a decoder
    // panic.
    #[test]
    fn bytes_that_decode_are_the_one_encoding_of_what_they_hold(bytes in proptest::collection::vec(any::<u8>(), 0..96), e in entry()) {
        if let Ok(decoded) = Entry::decode(&bytes) {
            prop_assert_eq!(decoded.encode(), bytes.clone());
        }
        if let Ok(decoded) = Leaf::decode(&bytes) {
            prop_assert_eq!(decoded.encode(), bytes.clone());
        }
        // One byte changed or cut from a real entry is never read as another encoding of it.
        let mut real = e.encode();
        if !real.is_empty() {
            let i = bytes.first().copied().unwrap_or(0) as usize % real.len();
            real[i] ^= 0x01;
            if let Ok(other) = Entry::decode(&real) {
                prop_assert_eq!(other.encode(), real.clone());
                prop_assert_ne!(other, e.clone());
            }
            let cut = &e.encode()[..e.encode().len() - 1];
            prop_assert!(Entry::decode(cut).is_err());
        }
    }

    #[test]
    fn the_root_is_the_one_an_append_only_tree_builds(n in 0usize..80) {
        let h = hashes(n);
        prop_assert_eq!(root(&h), root_by_counter(&h));
    }

    // An inclusion proof holds for its leaf, its index and its tree, and for nothing else.
    #[test]
    fn an_inclusion_proof_holds_for_its_leaf_and_tree_only(n in 1usize..70, pick in any::<usize>(), flip in any::<usize>()) {
        let h = hashes(n);
        let r = root(&h);
        let i = pick % n;
        let proof = inclusion_proof(i, &h).unwrap();
        prop_assert!(verify_inclusion(i as u64, n as u64, &h[i], &proof, &r));
        prop_assert!(!verify_inclusion(i as u64, n as u64, &leaf_hash(b"another"), &proof, &r));
        if n > 1 {
            let j = (i + 1 + flip % (n - 1)) % n;
            prop_assert!(!verify_inclusion(j as u64, n as u64, &h[i], &proof, &r));
        }
        // A proof is checked against the size and root a signed checkpoint states, never a size on its own: the real
        // tree of one more leaf has another root, and the proof does not hold for it.
        let mut grown = h.clone();
        grown.push(leaf_hash(b"one more"));
        prop_assert!(!verify_inclusion(i as u64, n as u64 + 1, &h[i], &proof, &root(&grown)));
        if !proof.is_empty() {
            let mut bad = proof.clone();
            let k = flip % bad.len();
            bad[k][0] ^= 1;
            prop_assert!(!verify_inclusion(i as u64, n as u64, &h[i], &bad, &r));
        }
        prop_assert!(inclusion_proof(n, &h).is_none());
    }

    // A consistency proof shows the older tree is the first part of the newer, and fails for any other older tree.
    #[test]
    fn a_consistency_proof_holds_for_a_prefix_and_fails_otherwise(n in 1usize..70, pick in any::<usize>(), flip in any::<usize>()) {
        let h = hashes(n);
        let m = 1 + pick % n;
        let (old, new) = (root(&h[..m]), root(&h));
        let proof = consistency_proof(m, &h).unwrap();
        prop_assert!(verify_consistency(m as u64, n as u64, &old, &new, &proof));
        let mut forged = h[..m].to_vec();
        forged[flip % m][0] ^= 1;
        prop_assert!(!verify_consistency(m as u64, n as u64, &root(&forged), &new, &proof));
        if m < n {
            prop_assert!(!verify_consistency(m as u64, n as u64, &old, &root(&h[..n - 1]), &proof));
            let mut bad = proof.clone();
            let k = flip % bad.len();
            bad[k][0] ^= 1;
            prop_assert!(!verify_consistency(m as u64, n as u64, &old, &new, &bad));
        }
        prop_assert!(consistency_proof(0, &h).is_none());
        prop_assert!(consistency_proof(n + 1, &h).is_none());
    }

    #[test]
    fn a_signed_checkpoint_opens_as_itself_and_a_changed_one_does_not(origin in "[a-z][a-z./-]{0,30}", size in any::<u64>(), r in any::<[u8; 32]>(), seed in 1u8..255) {
        let c = Checkpoint { origin, size, root: r };
        let key = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let signer = NoteSigner::new("polar.local/store", key).unwrap();
        let pinned = NoteVerifier::parse(&signer.verifier_key()).unwrap();
        let note = signer.sign(&c.text());
        let (text, _) = open(&note, std::slice::from_ref(&pinned)).unwrap();
        prop_assert_eq!(Checkpoint::parse(&text), Ok(c.clone()));
        let other = Checkpoint { size: size.wrapping_add(1), ..c };
        let forged = format!("{}{}", other.text(), &note[note.rfind("\n\n").unwrap() + 1..]);
        prop_assert!(open(&forged, &[pinned]).is_err());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    // Whatever a write that stopped leaves, opening gives back a prefix of what was appended, and appending goes on.
    #[test]
    fn a_cut_anywhere_leaves_a_prefix_and_appending_goes_on(leaves in proptest::collection::vec(leaf(), 1..6), cut in any::<usize>()) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let mut opened = FileLog::open(&path).unwrap();
        for l in &leaves {
            opened.log.append(l).unwrap();
        }
        drop(opened);
        let len = std::fs::metadata(&path).unwrap().len();
        let keep = (cut as u64) % (len + 1);
        std::fs::OpenOptions::new().write(true).open(&path).unwrap().set_len(keep).unwrap();
        let mut again = FileLog::open(&path).unwrap();
        let n = again.log.size() as usize;
        prop_assert!(n <= leaves.len());
        let full: Vec<Hash> = leaves.iter().map(|l| leaf_hash(&l.encode())).collect();
        prop_assert_eq!(again.log.hashes(), &full[..n]);
        again.log.append(&leaves[0]).unwrap();
        drop(again);
        prop_assert_eq!(FileLog::open(&path).unwrap().log.size() as usize, n + 1);
    }

    // Leaves appended together make the same file as each appended alone, and come back the same.
    #[test]
    fn leaves_appended_together_are_as_if_appended_one_by_one(before in proptest::collection::vec(leaf(), 0..3), leaves in proptest::collection::vec(leaf(), 0..6)) {
        let dir = tempfile::tempdir().unwrap();
        let (one, all) = (dir.path().join("one"), dir.path().join("all"));
        let mut by_one = FileLog::open(&one).unwrap().log;
        let mut together = FileLog::open(&all).unwrap().log;
        for l in &before {
            by_one.append(l).unwrap();
            together.append(l).unwrap();
        }
        for l in &leaves {
            by_one.append(l).unwrap();
        }
        prop_assert_eq!(together.append_all(&leaves).unwrap(), by_one.size());
        prop_assert_eq!(together.hashes(), by_one.hashes());
        drop((by_one, together));
        prop_assert_eq!(std::fs::read(&one).unwrap(), std::fs::read(&all).unwrap());
        let again = FileLog::open(&all).unwrap().log;
        for (seq, l) in before.iter().chain(&leaves).enumerate() {
            prop_assert_eq!(again.leaf(seq as u64).unwrap(), Some(l.clone()));
        }
    }

    // A byte changed anywhere in a whole frame refuses the log; nothing is cut from it.
    #[test]
    fn a_byte_changed_in_a_whole_frame_refuses_the_log(leaves in proptest::collection::vec(leaf(), 1..6), at in any::<usize>(), bit in 0u8..8) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let mut opened = FileLog::open(&path).unwrap();
        for l in &leaves {
            opened.log.append(l).unwrap();
        }
        drop(opened);
        let mut bytes = std::fs::read(&path).unwrap();
        let i = at % bytes.len();
        bytes[i] ^= 1 << bit;
        std::fs::write(&path, &bytes).unwrap();
        prop_assert!(FileLog::open(&path).is_err());
        prop_assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}

fn level() -> impl Strategy<Value = Level> {
    prop_oneof![(0u8..=63).prop_map(Level::Hashes), Just(Level::Entries)]
}

proptest! {
    /// Every tile is read back from its path.
    #[test]
    fn a_tiles_path_reads_back_as_the_tile(level in level(), index in any::<u64>(), width in 1u64..=256) {
        let tile = Tile::new(level, index, width).unwrap();
        prop_assert_eq!(Tile::parse(&tile.path()), Some(tile));
    }

    /// A path read as a tile is that tile's one name: no second spelling reaches the same tile.
    #[test]
    fn a_path_read_as_a_tile_is_its_one_name(path in "tile/(entries|[0-9]{1,3})(/x?[0-9]{1,4}){1,4}(\\.p/[0-9]{1,3})?") {
        if let Some(tile) = Tile::parse(&path) {
            prop_assert_eq!(tile.path(), path);
        }
    }

    /// A bundle gives back its entries, and a bundle cut anywhere short is refused.
    #[test]
    fn a_bundle_gives_back_its_entries_and_a_cut_one_is_refused(entries in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..40), 0..8), cut in any::<usize>()) {
        let bytes = entry_bundle(&entries).unwrap();
        prop_assert_eq!(parse_entry_bundle(&bytes, entries.len() as u64).unwrap(), entries.clone());
        if !bytes.is_empty() {
            let cut = cut % bytes.len();
            prop_assert!(parse_entry_bundle(&bytes[..cut], entries.len() as u64).is_err());
        }
    }

    /// Above level 0, each hash is the root of the full tile below it, as the spec defines; level 0 is the leaf hashes.
    #[test]
    fn each_tile_hash_is_the_root_of_the_full_tile_below(n in 0usize..1100, pick in any::<u64>()) {
        let leaves: Vec<Hash> = (0..n as u32).map(|i| leaf_hash(&i.to_be_bytes())).collect();
        let below = (n as u64) / TILE_WIDTH;
        if below > 0 {
            let width = pick % below.min(TILE_WIDTH) + 1;
            let bytes = hash_tile(&leaves, Tile::new(Level::Hashes(1), 0, width).unwrap()).unwrap();
            for j in 0..width {
                let full = hash_tile(&leaves, Tile::new(Level::Hashes(0), j, TILE_WIDTH).unwrap()).unwrap();
                let hashes: Vec<Hash> = full.chunks(32).map(|c| c.try_into().unwrap()).collect();
                prop_assert_eq!(&bytes[j as usize * 32..(j as usize + 1) * 32], &root(&hashes)[..]);
            }
            // One hash more than the tree has full tiles for is not served.
            if below < TILE_WIDTH {
                prop_assert!(hash_tile(&leaves, Tile::new(Level::Hashes(1), 0, below + 1).unwrap()).is_none());
            }
        }
        if n > 0 {
            let at = pick % n as u64;
            let tile = Tile::new(Level::Hashes(0), at / TILE_WIDTH, at % TILE_WIDTH + 1).unwrap();
            let bytes = hash_tile(&leaves, tile).unwrap();
            prop_assert_eq!(&bytes[bytes.len() - 32..], &leaves[at as usize][..]);
        }
    }

    /// A log served as its bundles is read back whole; a byte changed in any bundle is never read as the log.
    #[test]
    fn a_log_read_from_its_bundles_is_the_log_and_a_changed_byte_is_refused(n in 0usize..600, at in any::<usize>(), bit in 0u8..8) {
        let leaves: Vec<Vec<u8>> = (0..n as u32).map(|i| i.to_be_bytes().repeat(1 + i as usize % 3)).collect();
        let hashes: Vec<Hash> = leaves.iter().map(|l| leaf_hash(l)).collect();
        let checkpoint = Checkpoint { origin: "example.org/log".to_string(), size: n as u64, root: root(&hashes) };
        let mut served: std::collections::BTreeMap<String, Vec<u8>> = entry_tiles(n as u64)
            .into_iter()
            .map(|t| {
                let from = (t.index() * TILE_WIDTH) as usize;
                (t.path(), entry_bundle(&leaves[from..from + t.width() as usize]).unwrap())
            })
            .collect();
        prop_assert_eq!(read_log(&checkpoint, |p| Ok(served.get(p).cloned())).unwrap(), leaves);
        if n > 0 {
            let total: usize = served.values().map(Vec::len).sum();
            let mut at = at % total;
            for bytes in served.values_mut() {
                if at < bytes.len() {
                    bytes[at] ^= 1 << bit;
                    break;
                }
                at -= bytes.len();
            }
            let read = read_log(&checkpoint, |p| Ok(served.get(p).cloned()));
            prop_assert!(matches!(read, Err(TileError::Root | TileError::Short | TileError::Trailing(_))), "{:?}", read);
        }
    }

    /// A co-signature verifies over the exact checkpoint and time it signed, and over no other.
    #[test]
    fn a_co_signature_holds_for_its_checkpoint_and_time_and_no_other(origin in "[a-z][a-z./-]{0,30}", size in any::<u64>(), r in any::<[u8; 32]>(), time in any::<u64>(), seed in 1u8..255) {
        let c = Checkpoint { origin, size, root: r };
        let store = NoteSigner::new("polar.local/checkpoint", p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap()).unwrap();
        let witness = Cosigner::new("polar.local/witness", p256::ecdsa::SigningKey::from_slice(&[0x42; 32]).unwrap()).unwrap();
        let pinned = [NoteVerifier::parse(&store.verifier_key()).unwrap(), NoteVerifier::parse(&witness.verifier_key()).unwrap()];
        let line = witness.cosign_line(&c.text(), time);
        let opened = open_signed(&format!("{}{}", store.sign(&c.text()), line), &pinned).unwrap();
        prop_assert_eq!(opened.by.len(), 2);
        prop_assert_eq!(opened.by[1].cosigned_at, Some(time));
        let other = Checkpoint { size: size.wrapping_add(1), ..c.clone() };
        let moved = format!("{}{}", store.sign(&other.text()), line);
        prop_assert!(open(&moved, &pinned).is_err());
        let later = witness.cosign_line(&c.text(), time.wrapping_add(1));
        prop_assert_ne!(later, line);
    }
}
