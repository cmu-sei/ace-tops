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

//! The Merkle tree of RFC 9162, section 2.1, over a log's leaves: a leaf hashed as `SHA-256(0x00 || leaf)`, a node as
//! `SHA-256(0x01 || left || right)`, so a node can never pass for a leaf. An inclusion proof shows a leaf is in a tree
//! of a given size; a consistency proof shows a tree of one size is the first part of a larger one, which is what makes
//! "append only" something a reader checks rather than trusts. The proofs are made as section 2.1.3.1 and 2.1.4.1
//! define them and checked by the algorithms of 2.1.3.2 and 2.1.4.2, step for step.

use sha2::{Digest, Sha256};

/// A SHA-256 hash.
pub type Hash = [u8; 32];

/// The hash of a leaf's bytes.
pub fn leaf_hash(leaf: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(leaf);
    h.finalize().into()
}

/// The hash of a node over two subtrees.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The largest power of two less than `n`, for `n > 1`: where a tree of `n` leaves splits.
fn split(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// The root of the tree over `leaves` (their leaf hashes): MTH of RFC 9162, the hash of nothing for no leaves.
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// The inclusion proof of the leaf at `index` in the tree over `leaves`: PATH(m, D[n]). None if there is no such leaf.
pub fn inclusion_proof(index: usize, leaves: &[Hash]) -> Option<Vec<Hash>> {
    if index >= leaves.len() {
        return None;
    }
    let mut proof = Vec::new();
    path(index, leaves, &mut proof);
    Some(proof)
}

fn path(m: usize, d: &[Hash], proof: &mut Vec<Hash>) {
    let n = d.len();
    if n <= 1 {
        return;
    }
    let k = split(n);
    if m < k {
        path(m, &d[..k], proof);
        proof.push(root(&d[k..]));
    } else {
        path(m - k, &d[k..], proof);
        proof.push(root(&d[..k]));
    }
}

/// Whether `proof` shows the leaf hashed `leaf` is at `index` in the tree of `size` leaves whose root is `root`: RFC
/// 9162, section 2.1.3.2.
pub fn verify_inclusion(index: u64, size: u64, leaf: &Hash, proof: &[Hash], root: &Hash) -> bool {
    if index >= size {
        return false;
    }
    let (mut fnode, mut snode) = (index, size - 1);
    let mut r = *leaf;
    for p in proof {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(p, &r);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && r == *root
}

/// The consistency proof that the tree of the first `old` of `leaves` is the first part of the tree over all of them:
/// PROOF(m, D[n]). None unless `0 < old <= n`; empty when `old == n`.
pub fn consistency_proof(old: usize, leaves: &[Hash]) -> Option<Vec<Hash>> {
    if old == 0 || old > leaves.len() {
        return None;
    }
    let mut proof = Vec::new();
    subproof(old, leaves, true, &mut proof);
    Some(proof)
}

fn subproof(m: usize, d: &[Hash], b: bool, proof: &mut Vec<Hash>) {
    let n = d.len();
    if m == n {
        if !b {
            proof.push(root(d));
        }
        return;
    }
    let k = split(n);
    if m <= k {
        subproof(m, &d[..k], b, proof);
        proof.push(root(&d[k..]));
    } else {
        subproof(m - k, &d[k..], false, proof);
        proof.push(root(&d[..k]));
    }
}

/// Whether `proof` shows the tree of `old` leaves with root `old_root` is the first part of the tree of `new` leaves
/// with root `new_root`: RFC 9162, section 2.1.4.2. Equal sizes need an empty proof and equal roots.
pub fn verify_consistency(
    old: u64,
    new: u64,
    old_root: &Hash,
    new_root: &Hash,
    proof: &[Hash],
) -> bool {
    if old == 0 || old > new {
        return false;
    }
    if old == new {
        return proof.is_empty() && old_root == new_root;
    }
    if proof.is_empty() {
        return false;
    }
    let mut path: Vec<Hash> = Vec::with_capacity(proof.len() + 1);
    if old.is_power_of_two() {
        path.push(*old_root);
    }
    path.extend_from_slice(proof);
    let (mut fnode, mut snode) = (old - 1, new - 1);
    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }
    let (mut fr, mut sr) = (path[0], path[0]);
    for c in &path[1..] {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    fr == *old_root && sr == *new_root && snode == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(h: &Hash) -> String {
        h.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The eight leaves of the test vectors RFC 6962's implementations share (certificate-transparency-go's
    /// `merkle_test.go`, Go's `sumdb/tlog`).
    fn vector_leaves() -> Vec<Vec<u8>> {
        vec![
            vec![],
            vec![0x00],
            vec![0x10],
            vec![0x20, 0x21],
            vec![0x30, 0x31],
            vec![0x40, 0x41, 0x42, 0x43],
            vec![0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57],
            (0x60..=0x6f).collect(),
        ]
    }

    /// RFC 9162 defines a consistency proof from a tree of at least one leaf to one no smaller; none other verifies,
    /// the empty tree's to itself among them.
    #[test]
    fn there_is_no_consistency_from_an_empty_tree_or_to_a_smaller_one() {
        let empty = root(&[]);
        assert!(!verify_consistency(0, 0, &empty, &empty, &[]));
        let one = root(&[leaf_hash(b"a")]);
        assert!(!verify_consistency(0, 1, &empty, &one, &[]));
        assert!(!verify_consistency(2, 1, &one, &one, &[]));
        assert!(verify_consistency(1, 1, &one, &one, &[]));
    }

    #[test]
    fn the_roots_are_those_of_the_shared_test_vectors() {
        let hashes: Vec<Hash> = vector_leaves().iter().map(|l| leaf_hash(l)).collect();
        assert_eq!(
            hex(&root(&[])),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&root(&hashes[..1])),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
        assert_eq!(
            hex(&root(&hashes)),
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"
        );
    }
}
