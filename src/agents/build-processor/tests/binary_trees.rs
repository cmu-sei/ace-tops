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

//! What a binary's own dependency record says it holds, against what its build compiled (build-inspect-ship, S2). For a
//! binary built with cargo-auditable, three package sets, each `name@version`, the binary's own package left out:
//!
//! - **compiled:** every package the binary's Nix build compiled a unit of, from its cargo log (`compiler-artifact`
//!   messages): the ground truth;
//! - **auditable:** the record cargo-auditable embedded in the binary, written out by auditable2cdx;
//! - **SBOM:** the workspace SBOM of the binary's package, from cargo-cyclonedx.
//!
//! Every difference is reported, against the compiled set: a package a record names that was not compiled (it
//! overstates), one compiled that it leaves out (it understates), and a proc-macro, which runs at build time, that the
//! auditable record does not mark as a build dependency. The record this nixpkgs' cargo-auditable writes (0.6.2, format
//! 0) is taken from `cargo metadata`, and its crate documents that it may name more than the build used and that it
//! records proc-macros as runtime dependencies; this test says by how much, and which.
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

/// A package as a purl names it, `name@version`, whatever qualifiers follow: `?…` as a purl writes them, or `&…` as
/// auditable2cdx 0.1.0 writes a local package's (`pkg:cargo/x@1.0.0&download_url=redacted`).
fn named(purl: &str) -> String {
    let bare = purl
        .strip_prefix("pkg:cargo/")
        .unwrap_or_else(|| panic!("not a cargo purl: {purl}"));
    bare.split(['?', '&']).next().unwrap_or(bare).to_string()
}

/// The packages a CycloneDX document names, `name@version`, its root left out; and those of them it marks as build
/// dependencies (auditable2cdx's `cdx:rustc:dependency_kind` property).
fn components(doc: &Value) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut all = BTreeSet::new();
    let mut build = BTreeSet::new();
    for c in doc["components"].as_array().cloned().unwrap_or_default() {
        let Some(purl) = c["purl"].as_str() else {
            continue;
        };
        let package = named(purl);
        let is_build = c["properties"].as_array().is_some_and(|ps| {
            ps.iter()
                .any(|p| p["name"] == "cdx:rustc:dependency_kind" && p["value"] == "build")
        });
        if is_build {
            build.insert(package.clone());
        }
        all.insert(package);
    }
    (all, build)
}

/// What the build compiled, from its cargo log: every package it compiled a unit of, and those it compiled a
/// proc-macro of.
fn compiled(log: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut all = BTreeSet::new();
    let mut proc_macros = BTreeSet::new();
    for line in log.lines() {
        let Ok(message) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if message["reason"] != "compiler-artifact" {
            continue;
        }
        let Some(id) = message["package_id"].as_str() else {
            continue;
        };
        let package = package_of_id(id);
        let kinds = message["target"]["kind"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if kinds.iter().any(|k| k == "proc-macro") {
            proc_macros.insert(package.clone());
        }
        all.insert(package);
    }
    (all, proc_macros)
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
        ("pkg:cargo/polar@1.0.0&download_url=redacted", "polar@1.0.0"),
    ] {
        assert_eq!(named(purl), name, "{purl}");
    }
}

#[test]
#[ignore = "needs the fixtures tests/fixtures/binary-trees/make.nu makes on the host; the record may overstate the \
            binary (cargo-auditable 0.6.2 writes format 0, from `cargo metadata`), which this reports"]
fn a_binarys_own_record_is_what_its_build_compiled() {
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

        let (mut built, proc_macros) =
            compiled(&read_text(&dir.join(format!("{binary}.cargo-build.json"))));
        let own = built
            .iter()
            .find(|p| p.starts_with(&format!("{package}@")))
            .cloned()
            .unwrap_or_else(|| {
                panic!("{binary}: its package {package} is not in its own build's log")
            });
        built.remove(&own);
        let (recorded, recorded_build) =
            components(&read(&dir.join(format!("{binary}.auditable.cdx.json"))));
        let (sbom, _) = components(&read(&dir.join(format!("{package}.cdx.json"))));

        eprintln!(
            "{binary} ({own}): compiled {}, auditable record {}, workspace SBOM {}",
            built.len(),
            recorded.len(),
            sbom.len()
        );
        for (claim, said) in [("auditable record", &recorded), ("workspace SBOM", &sbom)] {
            let over: Vec<&String> = said.difference(&built).collect();
            let under: Vec<&String> = built.difference(said).collect();
            if !over.is_empty() {
                differs.push(format!(
                    "{binary}: the {claim} names {} not compiled: {over:?}",
                    over.len()
                ));
            }
            if !under.is_empty() {
                differs.push(format!(
                    "{binary}: the {claim} leaves out {} compiled: {under:?}",
                    under.len()
                ));
            }
        }
        let runtime_macros: Vec<&String> = proc_macros
            .iter()
            .filter(|p| recorded.contains(*p) && !recorded_build.contains(*p))
            .collect();
        if !runtime_macros.is_empty() {
            differs.push(format!(
                "{binary}: the auditable record has {} proc-macros as runtime dependencies: {runtime_macros:?}",
                runtime_macros.len()
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
