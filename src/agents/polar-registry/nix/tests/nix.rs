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

//! This crate held to Nix itself: the same input given to `nix` and to this crate gives the same archive, hash, narinfo
//! and signature. Each test says it skipped where `nix` is not on the PATH; Polar's CI image has it.

use polar_registry_nix::hash::Sha256;
use polar_registry_nix::narinfo::NarInfo;
use polar_registry_nix::signature::{PublicKey, SecretKey};
use polar_registry_nix::store_path::StorePath;
use polar_registry_nix::{nar, nix32};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;

/// Nix's own output for `args`, or None where Nix is not here.
fn nix(program: &str, args: &[&str]) -> Option<Vec<u8>> {
    let out = match Command::new(program)
        .args(args)
        .env("NIX_CONFIG", "experimental-features = nix-command flakes")
        .output()
    {
        Ok(out) => out,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipped: {program} is not on the PATH");
            return None;
        }
        Err(e) => panic!("{program}: {e}"),
    };
    assert!(
        out.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(out.stdout)
}

fn text(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap().trim_end().to_string()
}

/// A tree with each kind of node, an empty file, an executable, names Nix sorts by byte, and a nested directory.
fn tree(root: &Path) {
    std::fs::create_dir_all(root.join("bin")).unwrap();
    std::fs::create_dir_all(root.join("share/a/b")).unwrap();
    std::fs::write(root.join("empty"), b"").unwrap();
    std::fs::write(root.join("eight..."), b"12345678").unwrap();
    std::fs::write(root.join("B"), b"capital first").unwrap();
    std::fs::write(root.join("share/a/b/deep"), vec![0xffu8; 4097]).unwrap();
    let tool = root.join("bin/tool");
    std::fs::write(&tool, b"#!/bin/sh\necho hi\n").unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    // Nix reads a file as executable when its owner may execute it, whoever else may.
    for (name, mode) in [("bin/owner-only", 0o700), ("bin/others-only", 0o645)] {
        std::fs::write(root.join(name), name).unwrap();
        std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(mode)).unwrap();
    }
    symlink("../share/a", root.join("bin/link")).unwrap();
    symlink("/nowhere/at/all", root.join("dangling")).unwrap();
}

#[test]
fn an_archive_is_byte_for_byte_nix_s() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("t");
    tree(&root);
    let Some(theirs) = nix("nix-store", &["--dump", root.to_str().unwrap()]) else {
        return;
    };
    let mut ours = Vec::new();
    nar::dump(&root, &mut ours).unwrap();
    assert_eq!(ours, theirs);
    assert_eq!(nar::encode(&nar::decode(&ours).unwrap()), ours);
    let hashed = text(
        nix(
            "nix",
            &["hash", "path", "--type", "sha256", root.to_str().unwrap()],
        )
        .unwrap(),
    );
    assert_eq!(hashed.parse::<Sha256>().unwrap(), Sha256::of(&ours));
}

#[test]
fn hashes_are_spelled_as_nix_spells_them() {
    for seed in 0u8..8 {
        let bytes: [u8; 32] = std::array::from_fn(|i| {
            (i as u8)
                .wrapping_mul(31)
                .wrapping_add(seed.wrapping_mul(97))
        });
        let hex = hex_of(&bytes);
        let Some(theirs) = nix(
            "nix",
            &[
                "hash",
                "convert",
                "--hash-algo",
                "sha256",
                "--to",
                "nix32",
                &hex,
            ],
        ) else {
            return;
        };
        assert_eq!(nix32::encode(&bytes), text(theirs));
    }
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The store path of the `nix` on the PATH, which came from cache.nixos.org and refers to others.
fn nix_s_own_path() -> Option<StorePath> {
    let exe = std::fs::canonicalize(text(nix("sh", &["-c", "command -v nix"])?)).ok()?;
    let mut parts = exe.components().take(4).collect::<std::path::PathBuf>();
    parts = parts.iter().collect();
    parts.to_str()?.parse().ok()
}

#[test]
fn a_path_cache_nixos_org_signed_verifies_under_its_key() {
    let Some(path) = nix_s_own_path() else {
        return;
    };
    let info = nix(
        "nix",
        &[
            "path-info",
            "--json-format",
            "1",
            "--json",
            "--sigs",
            &path.to_string(),
        ],
    )
    .unwrap();
    let info = String::from_utf8(info).unwrap();
    let field = |name: &str| -> String {
        let at = info.find(&format!("\"{name}\":")).unwrap() + name.len() + 3;
        info[at..]
            .split(['"', ',', '}'])
            .find(|s| !s.is_empty())
            .unwrap()
            .to_string()
    };
    let sigs = info[info.find("\"signatures\":[").unwrap()..]
        .split('"')
        .filter(|s| s.starts_with("cache.nixos.org-1:"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    if sigs.is_empty() {
        eprintln!("skipped: {path} carries no signature of cache.nixos.org");
        return;
    }
    let references = info[info.find("\"references\":[").unwrap() + 14..]
        .split(']')
        .next()
        .unwrap()
        .split(',')
        .map(|r| r.trim_matches('"').parse::<StorePath>().unwrap())
        .collect();
    let narinfo = NarInfo {
        store_path: path.clone(),
        url: "nar/x.nar".into(),
        compression: "none".into(),
        file_hash: None,
        file_size: None,
        nar_hash: field("narHash").parse().unwrap(),
        nar_size: field("narSize").parse().unwrap(),
        references,
        deriver: None,
        sigs: sigs.iter().map(|s| s.parse().unwrap()).collect(),
        ca: None,
    };
    let key: PublicKey = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
        .parse()
        .unwrap();
    assert!(narinfo.signed_by(&key), "{narinfo:?}");
    let mut other = narinfo.clone();
    other.nar_size -= 1;
    assert!(!other.signed_by(&key));
}

#[test]
fn a_cache_nix_writes_is_read_rewritten_and_signed_as_nix_does() {
    let dir = tempfile::tempdir().unwrap();
    let Some(path) = nix_s_own_path() else {
        return;
    };
    let secret = dir.path().join("secret");
    let public = dir.path().join("public");
    let written = nix(
        "nix",
        &["key", "generate-secret", "--key-name", "polar-oracle-1"],
    )
    .unwrap();
    std::fs::write(&secret, &written).unwrap();
    let ours: SecretKey = text(written).parse().unwrap();
    let theirs = text(
        nix(
            "sh",
            &[
                "-c",
                &format!("nix key convert-secret-to-public < {}", secret.display()),
            ],
        )
        .unwrap(),
    );
    std::fs::write(&public, &theirs).unwrap();
    assert_eq!(ours.public().to_string(), theirs);

    let cache = dir.path().join("cache");
    let to = format!(
        "file://{}?compression=none&secret-key={}",
        cache.display(),
        secret.display()
    );
    nix(
        "nix",
        &["copy", "--no-check-sigs", "--to", &to, &path.to_string()],
    )
    .unwrap();
    let written =
        std::fs::read_to_string(cache.join(format!("{}.narinfo", path.hash_part()))).unwrap();
    let info = NarInfo::parse(&written).unwrap();
    assert_eq!(
        info.render(),
        written,
        "the narinfo is written back as Nix wrote it"
    );
    assert!(info.signed_by(&ours.public()));
    let mut ours_signed = info.clone();
    ours_signed.sign(&ours);
    assert_eq!(
        ours_signed.sigs, info.sigs,
        "Ed25519 gives one signature: ours is Nix's"
    );

    let archive = std::fs::read(cache.join(&info.url)).unwrap();
    assert_eq!(Sha256::of(&archive), info.nar_hash);
    assert_eq!(archive.len() as u64, info.nar_size);
    let mut dumped = Vec::new();
    nar::dump(Path::new(&path.to_string()), &mut dumped).unwrap();
    assert_eq!(dumped, archive);
    assert_eq!(nar::encode(&nar::decode(&archive).unwrap()), archive);
}
