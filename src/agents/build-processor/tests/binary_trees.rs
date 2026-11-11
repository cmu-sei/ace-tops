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

//! What a binary's build compiled, against what the workspace SBOM of its package names (build-inspect-ship, S2). Two
//! claims with different subjects: the cargo log is the record of one build, the binary's; the SBOM is a claim about
//! the source tree at a commit, the package as the whole workspace resolves it. Two package sets, each `name@version`, the
//! binary's own package left out:
//!
//! - **compiled:** every package the binary's Nix build compiled a unit of, from its cargo log (`compiler-artifact`
//!   messages), build-time units (proc-macros, build scripts and what they need) included, as the SBOM includes
//!   build-dependencies: the ground truth of the build;
//! - **SBOM:** the workspace SBOM of the binary's package, from cargo-cyclonedx.
//!
//! Every difference is reported: a package the SBOM names that the build did not compile (it overstates the binary), and
//! one compiled that it leaves out (it understates). cargo-cyclonedx reads `cargo metadata` over the whole workspace, where
//! features are unified across members (`sbom_trees`, claim B), so it is expected to overstate; this says by how much, and
//! which. (cargo-auditable was tried as a third source and dropped: 0.6.2's record of cassini-server was the SBOM's, 492
//! packages against 466 compiled.)
//!
//! The fixtures are made on the host, in ACE's dev shell, by `tests/fixtures/binary-trees/make.nu`:
//! `cargo test -p build-processor --test binary_trees -- --ignored --nocapture`.

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/binary-trees")
}

fn read_text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn read(path: &Path) -> Value {
    serde_json::from_str(&read_text(path)).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The package a cargo package id names, as `name@version`: `source#name@version`, `source#version` when the name is
/// the last segment of the source's path, or before cargo 1.77 `name version (source)`.
fn package_of_id(id: &str) -> String {
    if !id.contains('#')
        && let Some((name, rest)) = id.split_once(' ')
        && let Some((version, _)) = rest.split_once(' ')
    {
        return format!("{name}@{version}");
    }
    let (source, spec) = id
        .rsplit_once('#')
        .unwrap_or_else(|| panic!("not a package id: {id}"));
    if spec.contains('@') {
        spec.to_string()
    } else {
        let path = source.split('?').next().unwrap_or(source);
        let name = path.rsplit('/').next().unwrap_or(path);
        format!("{name}@{spec}")
    }
}

/// A package as a purl names it, `name@version`, whatever qualifiers follow (`?…`).
fn named(purl: &str) -> String {
    let bare = purl
        .strip_prefix("pkg:cargo/")
        .unwrap_or_else(|| panic!("not a cargo purl: {purl}"));
    bare.split('?').next().unwrap_or(bare).to_string()
}

/// The packages a CycloneDX document names, `name@version`, its root left out.
fn components(doc: &Value) -> BTreeSet<String> {
    doc["components"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|c| c["purl"].as_str().map(named))
        .collect()
}

/// Every package the build compiled a unit of, from its cargo log.
fn compiled(log: &str) -> BTreeSet<String> {
    log.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|m| m["reason"] == "compiler-artifact")
        .filter_map(|m| m["package_id"].as_str().map(package_of_id))
        .collect()
}

#[test]
fn package_ids_and_purls_are_read_in_each_form() {
    for (id, named) in [
        (
            "path+file:///build/source/cassini/broker#cassini-broker@1.0.0",
            "cassini-broker@1.0.0",
        ),
        ("path+file:///build/source/logger#1.0.0", "logger@1.0.0"),
        (
            "registry+https://github.com/rust-lang/crates.io-index#itoa@1.0.18",
            "itoa@1.0.18",
        ),
        (
            "git+https://github.com/x/neo4rs?rev=4117f5a#neo4rs@0.9.0-rc.10",
            "neo4rs@0.9.0-rc.10",
        ),
        (
            "cassini-broker 1.0.0 (path+file:///build/source/cassini/broker)",
            "cassini-broker@1.0.0",
        ),
    ] {
        assert_eq!(package_of_id(id), named, "{id}");
    }
    for (purl, name) in [
        ("pkg:cargo/itoa@1.0.18", "itoa@1.0.18"),
        (
            "pkg:cargo/polar@1.0.0?download_url=file://../lib",
            "polar@1.0.0",
        ),
    ] {
        assert_eq!(named(purl), name, "{purl}");
    }
}

#[test]
#[ignore = "needs the fixtures tests/fixtures/binary-trees/make.nu makes on the host; the workspace SBOM overstates a \
            binary (cargo-cyclonedx resolves the whole workspace), which this reports"]
fn the_workspace_sbom_is_what_the_binarys_build_compiled() {
    let mut differs: Vec<String> = vec![];
    let mut seen = 0;
    for entry in std::fs::read_dir(fixtures()).unwrap() {
        let dir = entry.unwrap().path();
        if !dir.is_dir() {
            continue;
        }
        seen += 1;
        let manifest = read(&dir.join("manifest.json"));
        let binary = manifest["binary"].as_str().expect("binary");
        let package = manifest["package"].as_str().expect("package");

        let mut built = compiled(&read_text(&dir.join(format!("{binary}.cargo-build.json"))));
        let own = built
            .iter()
            .find(|p| p.starts_with(&format!("{package}@")))
            .cloned()
            .unwrap_or_else(|| {
                panic!("{binary}: its package {package} is not in its own build's log")
            });
        built.remove(&own);
        let sbom = components(&read(&dir.join(format!("{package}.cdx.json"))));

        eprintln!(
            "{binary} ({own}): compiled {}, workspace SBOM {}",
            built.len(),
            sbom.len()
        );
        let over: Vec<&String> = sbom.difference(&built).collect();
        let under: Vec<&String> = built.difference(&sbom).collect();
        if !over.is_empty() {
            differs.push(format!(
                "{binary}: the workspace SBOM names {} not compiled: {over:?}",
                over.len()
            ));
        }
        if !under.is_empty() {
            differs.push(format!(
                "{binary}: the workspace SBOM leaves out {} compiled: {under:?}",
                under.len()
            ));
        }
    }
    assert!(
        seen > 0,
        "no fixtures: run tests/fixtures/binary-trees/make.nu on the host"
    );
    for line in &differs {
        eprintln!("{line}");
    }
    assert!(differs.is_empty(), "{} differences (above)", differs.len());
}
