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

//! The falsifiability tests for asserted trees (Blitz's risk-gradients.md, "Verification"), on real cargo-cyclonedx SBOMs of
//! adjacent ACE commits with a Cargo.lock change. Two claims, kept apart:
//!
//! - **(A), slice 2b's:** the tree an SBOM asserts is exactly what the SBOM says, read again here from the raw `.cdx.json`
//!   by a parse of its own, apart from `extract-graph-fragment` and `asserted_tree`; one digest exactly when two SBOMs say
//!   the same tree; and its change agrees with the lock file's.
//! - **(B), the SBOM's:** what the SBOM says is what `cargo tree -e normal,build` resolves for the crate. It is not, and (B)
//!   stays ignored: cargo-cyclonedx reads `cargo metadata` over the whole workspace, where features are unified across
//!   every member, dev-dependencies included, so a crate's SBOM holds optional dependencies only other crates switch on
//!   (git-repo-observer's: wiremock, through `polar-agent-builder/testing`, which dev-dependencies ask for; quinn,
//!   rayon, pkcs5 and others, through features of crates outside its own tree). (B) reports every root that differs.
//!
//! The fixtures are made on the host, in ACE's dev shell, by `tests/fixtures/sbom-trees/make.nu`:
//! `cargo test -p build-processor --test sbom_trees -- --ignored`.

use build_processor::project::outputs::{AssertedTree, asserted_tree};
use polar::SbomGraphFragment;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
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

/// A package as `cargo tree` and the lock name it: `pkg:cargo/itoa@1.0.18`, with whatever qualifiers, is `itoa@1.0.18`.
fn named(purl: &str) -> String {
    let bare = purl
        .strip_prefix("pkg:cargo/")
        .unwrap_or_else(|| panic!("not a cargo purl: {purl}"));
    bare.split('?').next().unwrap_or(bare).to_string()
}

/// One commit pair's directory: its manifest, and each root it kept.
struct Pair {
    dir: PathBuf,
    manifest: Value,
    roots: Vec<(String, bool)>,
}

fn pairs() -> Vec<Pair> {
    let mut found: Vec<Pair> = std::fs::read_dir(fixtures())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .map(|dir| {
            let manifest: Value = read(&dir.join("manifest.json"));
            let roots = manifest["roots"]
                .as_array()
                .expect("roots")
                .iter()
                .map(|r| {
                    let name = r["name"].as_str().expect("a root's name").to_string();
                    (name, r["touched"].as_bool().expect("touched"))
                })
                .collect();
            Pair {
                dir,
                manifest,
                roots,
            }
        })
        .collect();
    found.sort_by(|a, b| a.dir.cmp(&b.dir));
    assert!(
        !found.is_empty(),
        "no fixtures: run tests/fixtures/sbom-trees/make.nu on the host"
    );
    found
}

/// The tree a raw CycloneDX document says, read apart from the pipeline and the processor: each bom-ref taken to the purl
/// of the entry it names, a ref no entry gives a purl for left out, as the extraction's contract says
/// (scripts/pipeline/core/sbom.nu, `extract-graph-fragment`), and nothing else assumed.
#[derive(Debug, PartialEq, Eq)]
struct Said {
    root: String,
    packages: BTreeSet<String>,
    pairs: BTreeSet<(String, String)>,
    /// Every component names a purl, and the root has an entry of its own (or there is nothing else in the tree).
    complete: bool,
}

fn said(doc: &Value) -> Said {
    let root = &doc["metadata"]["component"];
    let root_purl = root["purl"].as_str().expect("the root's purl").to_string();
    let components = doc["components"].as_array().cloned().unwrap_or_default();
    let mut purl_of: BTreeMap<String, String> = BTreeMap::new();
    for entry in std::iter::once(root).chain(components.iter()) {
        if let (Some(bom_ref), Some(purl)) = (entry["bom-ref"].as_str(), entry["purl"].as_str())
            && !bom_ref.is_empty()
            && !purl.is_empty()
        {
            purl_of.insert(bom_ref.to_string(), purl.to_string());
        }
    }
    let every_component_named = components
        .iter()
        .all(|c| c["purl"].as_str().is_some_and(|p| p.starts_with("pkg:")));
    let mut pairs = BTreeSet::new();
    let mut root_listed = false;
    for entry in doc["dependencies"].as_array().cloned().unwrap_or_default() {
        let Some(from) = entry["ref"].as_str().and_then(|r| purl_of.get(r)) else {
            continue;
        };
        for to in entry["dependsOn"].as_array().cloned().unwrap_or_default() {
            if let Some(to) = to.as_str().and_then(|r| purl_of.get(r)) {
                pairs.insert((from.clone(), to.clone()));
                root_listed |= *from == root_purl;
            }
        }
    }
    let packages: BTreeSet<String> = components
        .iter()
        .filter_map(|c| c["purl"].as_str())
        .filter(|p| p.starts_with("pkg:"))
        .map(str::to_string)
        .chain(pairs.iter().flat_map(|(a, b)| [a.clone(), b.clone()]))
        .filter(|p| *p != root_purl)
        .collect();
    let complete = every_component_named && (root_listed || packages.is_empty());
    Said {
        root: root_purl,
        packages,
        pairs,
        complete,
    }
}

/// (A): what each kept root's SBOM asserts, at both commits, is what its raw SBOM says.
#[test]
#[ignore = "needs the raw SBOMs (<root>.cdx.json), which tests/fixtures/sbom-trees/make.nu keeps from 2026-11-11: rerun it on the host"]
fn an_asserted_tree_is_what_its_sbom_says_and_its_change_is_the_lock_files() {
    for pair in pairs() {
        let lock_added = strings(&pair.manifest["lock"]["added"]);
        let lock_removed = strings(&pair.manifest["lock"]["removed"]);
        for (name, _) in &pair.roots {
            let mut sides: Vec<(AssertedTree, Said)> = vec![];
            for which in ["base", "head"] {
                let at = format!("{} {name} at {which}", pair.dir.display());
                let dir = pair.dir.join(which);
                let fragment: SbomGraphFragment = read(&dir.join(format!("{name}.fragment.json")));
                let raw: Value = read(&dir.join(format!("{name}.cdx.json")));
                let tree = asserted_tree(&fragment).unwrap_or_else(|| panic!("{at}: no root"));
                let said = said(&raw);
                assert_eq!(tree.root, said.root, "{at}: the root");
                assert_eq!(tree.packages, said.packages, "{at}: the packages");
                assert_eq!(tree.pairs, said.pairs, "{at}: the dependencies");
                assert_eq!(
                    tree.complete, said.complete,
                    "{at}: complete, {:?}",
                    tree.gaps
                );
                sides.push((tree, said));
            }
            let [(base, base_said), (head, head_said)] = <[_; 2]>::try_from(sides).unwrap();
            assert_eq!(
                base.digest == head.digest,
                base_said == head_said,
                "{name}: the SBOMs say {} tree, and its digests are {} and {}",
                if base_said == head_said {
                    "the same"
                } else {
                    "another"
                },
                base.digest,
                head.digest,
            );

            // The change agrees with the lock file's: a package the lock gained that the tree now holds was added to
            // the tree, and one the lock lost that the tree held was removed from it.
            let base: BTreeSet<String> = base.packages.iter().map(|p| named(p)).collect();
            let head: BTreeSet<String> = head.packages.iter().map(|p| named(p)).collect();
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
}

/// (B): what each kept root's SBOM says, against what `cargo tree -e normal,build` resolves for the crate. Every root that
/// differs is reported, then the test fails.
#[test]
#[ignore = "cargo-cyclonedx's workspace SBOM overstates a crate: it reads `cargo metadata` over the whole workspace, \
            where features are unified across members, dev-dependencies included"]
fn what_an_sbom_says_is_what_cargo_tree_resolves() {
    let mut differs: Vec<String> = vec![];
    for pair in pairs() {
        for (name, _) in &pair.roots {
            for which in ["base", "head"] {
                let at = format!(
                    "{} {name} at {which}",
                    pair.dir.file_name().unwrap().to_string_lossy()
                );
                let dir = pair.dir.join(which);
                let fragment: SbomGraphFragment = read(&dir.join(format!("{name}.fragment.json")));
                let cargo: Value = read(&dir.join(format!("{name}.cargo-tree.json")));
                let tree = asserted_tree(&fragment).unwrap_or_else(|| panic!("{at}: no root"));
                let packages: BTreeSet<String> = tree.packages.iter().map(|p| named(p)).collect();
                let pairs: BTreeSet<(String, String)> = tree
                    .pairs
                    .iter()
                    .map(|(from, to)| (named(from), named(to)))
                    .collect();
                let cargo_packages = strings(&cargo["packages"]);
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
                if packages == cargo_packages && pairs == cargo_pairs {
                    continue;
                }
                let only_sbom: Vec<&String> = packages.difference(&cargo_packages).collect();
                let only_cargo: Vec<&String> = cargo_packages.difference(&packages).collect();
                differs.push(format!(
                    "{at}: SBOM {} packages, cargo tree {}; only in the SBOM ({}): {only_sbom:?}; only in cargo tree ({}): \
                     {only_cargo:?}; dependencies only in the SBOM: {}, only in cargo tree: {}",
                    packages.len(),
                    cargo_packages.len(),
                    only_sbom.len(),
                    only_cargo.len(),
                    pairs.difference(&cargo_pairs).count(),
                    cargo_pairs.difference(&pairs).count(),
                ));
            }
        }
    }
    for line in &differs {
        eprintln!("{line}");
    }
    assert!(
        differs.is_empty(),
        "{} of the roots' SBOMs differ from cargo tree (above)",
        differs.len()
    );
}
