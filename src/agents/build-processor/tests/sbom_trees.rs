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

//! The falsifiability test (Blitz's risk-gradients.md, "Verification"). For adjacent ACE commits with a Cargo.lock
//! change, the tree each real cargo-cyclonedx SBOM asserts must be what `cargo tree` resolves, at both commits, apart
//! from the SBOM; a root cargo resolves the same at both must assert the same tree, and one it resolves differently a
//! different one; and the change between them must agree with `git diff Cargo.lock`.
//!
//! The fixtures are made on the host, in ACE's dev shell, by `tests/fixtures/sbom-trees/make.nu`; until they are
//! committed the test is ignored. Run it with `cargo test -p build-processor --test sbom_trees -- --ignored`.

use build_processor::project::outputs::asserted_tree;
use polar::SbomGraphFragment;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sbom-trees")
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn strings(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("not a list: {value}"))
        .iter()
        .map(|s| {
            s.as_str()
                .unwrap_or_else(|| panic!("not a string: {s}"))
                .to_string()
        })
        .collect()
}

/// A package as `cargo tree` names it: `pkg:cargo/itoa@1.0.18`, with whatever qualifiers, is `itoa@1.0.18`.
fn named(purl: &str) -> String {
    let bare = purl
        .strip_prefix("pkg:cargo/")
        .unwrap_or_else(|| panic!("not a cargo purl: {purl}"));
    bare.split('?').next().unwrap_or(bare).to_string()
}

#[test]
#[ignore = "needs the fixtures tests/fixtures/sbom-trees/make.nu makes on the host"]
fn an_asserted_tree_is_what_cargo_resolves_and_its_change_is_the_lock_files() {
    let mut pairs_seen = 0;
    for entry in std::fs::read_dir(fixtures()).unwrap() {
        let dir = entry.unwrap().path();
        if !dir.is_dir() {
            continue;
        }
        pairs_seen += 1;
        let manifest: Value = read(&dir.join("manifest.json"));
        let lock_added = strings(&manifest["lock"]["added"]);
        let lock_removed = strings(&manifest["lock"]["removed"]);
        let roots = manifest["roots"].as_array().expect("roots");
        assert!(
            roots.iter().any(|r| r["touched"] == true),
            "{}: no root the change touched",
            dir.display()
        );

        for root in roots {
            let name = root["name"].as_str().expect("a root's name");
            let touched = root["touched"].as_bool().expect("touched");
            let mut sides = vec![];
            for which in ["base", "head"] {
                let at = format!("{} {name} at {which}", dir.display());
                let fragment: SbomGraphFragment =
                    read(&dir.join(which).join(format!("{name}.fragment.json")));
                let cargo: Value = read(&dir.join(which).join(format!("{name}.cargo-tree.json")));
                let tree = asserted_tree(&fragment).unwrap_or_else(|| panic!("{at}: no root"));
                assert!(tree.complete, "{at}: incomplete, {:?}", tree.gaps);

                let packages: BTreeSet<String> = tree.packages.iter().map(|p| named(p)).collect();
                let pairs: BTreeSet<(String, String)> = tree
                    .pairs
                    .iter()
                    .map(|(from, to)| (named(from), named(to)))
                    .collect();
                let cargo_pairs: BTreeSet<(String, String)> = cargo["pairs"]
                    .as_array()
                    .expect("pairs")
                    .iter()
                    .map(|p| {
                        (
                            p[0].as_str().unwrap().to_string(),
                            p[1].as_str().unwrap().to_string(),
                        )
                    })
                    .collect();
                assert_eq!(packages, strings(&cargo["packages"]), "{at}: the packages");
                assert_eq!(pairs, cargo_pairs, "{at}: the dependencies");
                sides.push((tree.digest, packages));
            }
            let [(base_digest, base), (head_digest, head)] = <[_; 2]>::try_from(sides).unwrap();
            assert_eq!(
                base_digest != head_digest,
                touched,
                "{name}: cargo resolves it {}, and its digests are {base_digest} and {head_digest}",
                if touched { "differently" } else { "the same" },
            );

            // The change agrees with the lock file's: a package the lock gained that the tree now holds was added
            // to the tree, and one the lock lost that the tree held was removed from it.
            let added = &head - &base;
            let removed = &base - &head;
            for package in head.intersection(&lock_added) {
                assert!(
                    added.contains(package),
                    "{name}: {package} is new to the lock but not to the tree"
                );
            }
            for package in base.intersection(&lock_removed) {
                assert!(
                    removed.contains(package),
                    "{name}: {package} left the lock but not the tree"
                );
            }
        }
    }
    assert!(
        pairs_seen > 0,
        "no fixtures: run tests/fixtures/sbom-trees/make.nu on the host"
    );
}
