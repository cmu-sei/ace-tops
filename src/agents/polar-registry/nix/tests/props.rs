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

//! Properties of Nix's formats: every value has one spelling, and reads back from it; whatever is read writes back as
//! it was; and a signature holds for exactly what it signed.

use polar_registry_nix::hash::Sha256;
use polar_registry_nix::nar::{self, Node};
use polar_registry_nix::narinfo::NarInfo;
use polar_registry_nix::nix32;
use polar_registry_nix::signature::SecretKey;
use polar_registry_nix::store_path::{self, StorePath};
use proptest::collection::{btree_map, btree_set, vec};
use proptest::prelude::*;
use std::collections::BTreeMap;

fn name() -> impl Strategy<Value = String> {
    "[A-Za-z0-9+._?=-]{1,40}".prop_filter("Nix refuses . and ..", |n| store_path::is_name(n))
}

fn store_path() -> impl Strategy<Value = StorePath> {
    (any::<[u8; 20]>(), name()).prop_map(|(hash, name)| {
        StorePath::from_base(&format!("{}-{name}", nix32::encode(&hash))).unwrap()
    })
}

fn entry_name() -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 1..12).prop_filter("an entry's name", |n| nar::is_entry_name(n))
}

fn node() -> impl Strategy<Value = Node> {
    let leaf = prop_oneof![
        (any::<bool>(), vec(any::<u8>(), 0..40)).prop_map(|(executable, contents)| Node::Regular {
            executable,
            contents
        }),
        vec(1u8..=255, 1..20).prop_map(|target| Node::Symlink { target }),
    ];
    leaf.prop_recursive(4, 32, 5, |inner| {
        btree_map(entry_name(), inner, 0..5).prop_map(|m: BTreeMap<_, _>| Node::Directory(m))
    })
}

fn narinfo() -> impl Strategy<Value = NarInfo> {
    (
        store_path(),
        any::<[u8; 32]>(),
        any::<u64>(),
        btree_set(store_path(), 0..4),
        proptest::option::of(store_path()),
        proptest::option::of((any::<[u8; 32]>(), any::<u64>())),
        prop_oneof![Just("none"), Just("xz"), Just("zstd")],
    )
        .prop_map(
            |(store_path, nar, nar_size, references, deriver, file, compression)| NarInfo {
                url: format!("nar/{}.nar", nix32::encode(&nar)),
                store_path,
                compression: compression.into(),
                file_hash: file.map(|(h, _)| Sha256(h)),
                file_size: file.map(|(_, s)| s),
                nar_hash: Sha256(nar),
                nar_size,
                references,
                deriver,
                sigs: Vec::new(),
                ca: None,
            },
        )
}

proptest! {
    #[test]
    fn a_hash_reads_back_from_its_spelling(bytes in any::<[u8; 32]>(), short in any::<[u8; 20]>()) {
        prop_assert_eq!(nix32::decode::<32>(&nix32::encode(&bytes)).unwrap(), bytes);
        prop_assert_eq!(nix32::decode::<20>(&nix32::encode(&short)).unwrap(), short);
        let hash = Sha256(bytes);
        prop_assert_eq!(hash.to_string().parse::<Sha256>().unwrap(), hash);
    }

    #[test]
    fn a_spelling_that_reads_is_the_one_spelling(text in "[0-9a-z]{52}") {
        if let Ok(bytes) = nix32::decode::<32>(&text) {
            prop_assert_eq!(nix32::encode(&bytes), text);
        }
    }

    #[test]
    fn a_store_path_reads_back_from_its_spelling(path in store_path()) {
        prop_assert_eq!(path.to_string().parse::<StorePath>().unwrap(), path.clone());
        prop_assert_eq!(StorePath::from_base(path.base()).unwrap(), path);
    }

    #[test]
    fn a_string_that_reads_as_a_store_path_prints_as_it_was(text in "/nix/store/[0-9a-z]{32}-[ -~]{0,12}") {
        if let Ok(path) = text.parse::<StorePath>() {
            prop_assert_eq!(path.to_string(), text);
        }
    }

    #[test]
    fn a_tree_reads_back_from_its_archive(tree in node()) {
        let archive = nar::encode(&tree);
        prop_assert_eq!(archive.len() % 8, 0);
        prop_assert_eq!(nar::decode(&archive).unwrap(), tree);
    }

    #[test]
    fn whatever_reads_as_an_archive_is_the_one_archive_of_its_tree(
        tree in node(),
        flips in vec((any::<prop::sample::Index>(), any::<u8>()), 1..4),
        cut in any::<prop::sample::Index>(),
    ) {
        let archive = nar::encode(&tree);
        let mut changed = archive.clone();
        for (at, byte) in flips {
            let at = at.index(changed.len());
            changed[at] = byte;
        }
        for candidate in [&changed[..], &archive[..cut.index(archive.len())]] {
            if let Ok(read) = nar::decode(candidate) {
                prop_assert_eq!(nar::encode(&read), candidate.to_vec());
            }
        }
    }

    #[test]
    fn a_narinfo_reads_back_from_what_it_writes(mut info in narinfo(), seed in any::<[u8; 32]>()) {
        info.sign(&SecretKey::from_seed("polar-test-1", seed).unwrap());
        prop_assert_eq!(NarInfo::parse(&info.render()).unwrap(), info);
    }

    #[test]
    fn a_signature_holds_for_what_it_signed_and_nothing_else(
        mut info in narinfo(),
        seed in any::<[u8; 32]>(),
        other in any::<[u8; 32]>(),
        size in any::<u64>(),
        reference in store_path(),
    ) {
        let key = SecretKey::from_seed("polar-test-1", seed).unwrap();
        info.sign(&key);
        prop_assert!(info.signed_by(&key.public()));
        if other != seed {
            prop_assert!(!info.signed_by(&SecretKey::from_seed("polar-test-1", other).unwrap().public()));
        }
        let mut changed = info.clone();
        changed.nar_size = size;
        prop_assert_eq!(changed.signed_by(&key.public()), size == info.nar_size);
        let mut changed = info.clone();
        let added = changed.references.insert(reference);
        prop_assert_eq!(changed.signed_by(&key.public()), !added);
    }
}
