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

//! What the tests against Nix share: running `nix`, the two input-addressed paths they copy, and the stores they copy
//! into. Each test says it skipped where `nix` is not on the PATH; Polar's CI image has it.

#![allow(dead_code)]

use polar_registry::faults::{Faults, NoFetch};
use polar_registry::nix_cache::{NixCache, PathInfo};
use polar_registry_nix::nar;
use polar_registry_nix::store_path::StorePath;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;

pub fn nix(args: &[&str]) -> Option<Output> {
    match Command::new("nix")
        .args(args)
        .env("NIX_CONFIG", "experimental-features = nix-command flakes")
        .output()
    {
        Ok(out) => Some(out),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipped: nix is not on the PATH");
            None
        }
        Err(e) => panic!("nix: {e}"),
    }
}

pub fn ok(out: Output) -> String {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// Two input-addressed paths, `a` referring to `b`, built with the bash on the PATH as their builder.
pub fn oracle_paths() -> Option<(StorePath, StorePath)> {
    let bash = std::fs::canonicalize(ok(Command::new("sh")
        .args(["-c", "command -v bash"])
        .output()
        .ok()?))
    .ok()?;
    let bash = bash.ancestors().nth(2)?.to_str()?.to_string();
    let expr = format!(
        r#"let bash = builtins.storePath "{bash}";
               build = name: script: derivation {{ inherit name; system = builtins.currentSystem;
                 builder = "${{bash}}/bin/bash"; args = [ "-c" script ]; }};
               b = build "polar-registry-oracle-b" "echo b > $out";
           in build "polar-registry-oracle-a" "echo ${{b}} > $out""#
    );
    let a: StorePath = ok(nix(&[
        "build",
        "--impure",
        "--no-link",
        "--print-out-paths",
        "--expr",
        &expr,
    ])?)
    .parse()
    .unwrap();
    let info = info_of(&a);
    let b = info.references.iter().next().unwrap().clone();
    Some((a, b))
}

/// What the machine's Nix says of `path`.
pub fn info_of(path: &StorePath) -> PathInfo {
    let json = ok(nix(&[
        "path-info",
        "--json-format",
        "1",
        "--json",
        &path.to_string(),
    ])
    .unwrap());
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let v = &v[path.to_string()];
    PathInfo {
        store_path: path.clone(),
        nar_hash: v["narHash"].as_str().unwrap().parse().unwrap(),
        nar_size: v["narSize"].as_u64().unwrap(),
        references: v["references"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap().parse().unwrap())
            .collect(),
        deriver: v["deriver"].as_str().map(|d| d.parse().unwrap()),
        ca: v["ca"].as_str().map(str::to_string),
        sigs: Vec::new(),
    }
}

pub fn dumped(path: &StorePath) -> Vec<u8> {
    let mut out = Vec::new();
    nar::dump(Path::new(&path.to_string()), &mut out).unwrap();
    out
}

/// Copies `path` from the cache at `url` into a store of its own under `root`, trusting `key`. Nix keeps what caches
/// answered for 30 days, by their URL, and a test's cache is at a port the next test may be given: so each copy has a
/// cache of its own under `root`, and asks the cache under test.
pub fn copy(url: &str, path: &StorePath, root: &Path, key: &str) -> Output {
    let to = format!("local?root={}", root.display());
    let out = Command::new("nix")
        .args([
            "copy",
            "--from",
            url,
            "--to",
            &to,
            "--option",
            "trusted-public-keys",
            key,
        ])
        .arg(path.to_string())
        .env("NIX_CONFIG", "experimental-features = nix-command flakes")
        .env("XDG_CACHE_HOME", root.join("xdg-cache"))
        .output();
    match out {
        Ok(out) => out,
        Err(e) => panic!("nix: {e}"),
    }
}

pub fn no_faults(root: &Path, cache: Arc<NixCache>) -> Arc<Faults> {
    Arc::new(Faults::new(cache, root, Vec::new(), Arc::new(NoFetch), true, 1 << 30).unwrap())
}

/// A store Nix made under `root` is read-only; made writable so that it can be removed.
pub fn writable(root: &Path) {
    let _ = Command::new("chmod").args(["-R", "u+w"]).arg(root).status();
}
