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

//! The Nix cache, held to Nix itself: Nix copies a path and its references from it, accepts Polar's signature when it
//! trusts Polar's key and refuses the paths when it does not, and refuses an archive that is not what its narinfo says.
//! The paths are two tiny derivations built here, one referring to the other, so that they are input-addressed: Nix
//! takes a content-addressed path without any signature, which would prove nothing about Polar's. Each test says it
//! skipped where `nix` is not on the PATH (`common`).

mod common;

use common::{copy, dumped, info_of, no_faults, oracle_paths, writable};
use polar_registry::blobs::Blobs;
use polar_registry::nix_cache::{Archive, NixCache, PRIORITY, PathInfo, serve};
use polar_registry_nix::signature::SecretKey;
use polar_registry_nix::store_path::StorePath;
use std::sync::Arc;
use structured_zstd::encoding::{CompressionLevel, compress_to_vec};

#[tokio::test(flavor = "multi_thread")]
async fn nix_copies_a_path_and_its_references_trusting_polar_s_key_and_refuses_otherwise() {
    let Some((a, b)) = oracle_paths() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let key = SecretKey::from_seed("polar-test-1", [7; 32]).unwrap();
    let public = key.public().to_string();
    let blobs = Arc::new(Blobs::open(dir.path(), 3).unwrap());
    let cache = Arc::new(NixCache::open(dir.path(), blobs.clone(), key, PRIORITY).unwrap());
    // `a` arrives plain and is compressed here; `b` arrives as zstd and is kept as it came.
    let entered_a = cache
        .enter(info_of(&a), Archive::Plain(&dumped(&a)[..]))
        .unwrap();
    let b_zstd = compress_to_vec(&dumped(&b)[..], CompressionLevel::from_level(1));
    let entered_b = cache
        .enter(info_of(&b), Archive::Zstd(&b_zstd[..]))
        .unwrap();
    assert_eq!(
        entered_b.file_hash,
        Some(polar_registry_nix::hash::Sha256::of(&b_zstd))
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(serve(listener, no_faults(dir.path(), cache.clone())));

    let client = reqwest::Client::new();
    let info = client
        .get(format!("{url}/nix-cache-info"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        info.text().await.unwrap(),
        "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n"
    );
    let served = client
        .get(format!("{url}/{}.narinfo", a.hash_part()))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(served, entered_a.render());
    for refused in [
        "/".to_string(),
        "/x.narinfo".into(),
        format!("/{}.narinfo", "0".repeat(32)),
        format!("/nar/{}.nar", entered_a.nar_hash.nix32()),
        format!("/nar/{}.nar.zst", "0".repeat(52)),
        "/nar/../blobs".into(),
    ] {
        let status = client
            .get(format!("{url}{refused}"))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, reqwest::StatusCode::NOT_FOUND, "{refused}");
    }

    let (url2, a2, public2) = (url.clone(), a.clone(), public.clone());
    let trusted = tempfile::tempdir().unwrap();
    let root = trusted.path().to_path_buf();
    let out = tokio::task::spawn_blocking(move || copy(&url2, &a2, &root, &public2))
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for p in [&a, &b] {
        let copied = trusted.path().join(p.to_string().trim_start_matches('/'));
        assert_eq!(
            std::fs::read(copied).unwrap(),
            std::fs::read(p.to_string()).unwrap()
        );
    }
    writable(trusted.path());

    let other = SecretKey::from_seed("polar-test-1", [8; 32])
        .unwrap()
        .public()
        .to_string();
    let untrusted = tempfile::tempdir().unwrap();
    let (url2, a2, root) = (url.clone(), a.clone(), untrusted.path().to_path_buf());
    let out = tokio::task::spawn_blocking(move || copy(&url2, &a2, &root, &other))
        .await
        .unwrap();
    assert!(
        !out.status.success(),
        "a path signed by a key Nix does not trust was copied"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("signature"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    writable(untrusted.path());
}

#[tokio::test(flavor = "multi_thread")]
async fn nix_refuses_an_archive_that_is_not_what_its_narinfo_says() {
    let Some((a, b)) = oracle_paths() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let key = SecretKey::from_seed("polar-test-1", [7; 32]).unwrap();
    let public = key.public().to_string();
    let blobs = Arc::new(Blobs::open(dir.path(), 3).unwrap());
    let cache = Arc::new(NixCache::open(dir.path(), blobs.clone(), key, PRIORITY).unwrap());
    cache
        .enter(info_of(&b), Archive::Plain(&dumped(&b)[..]))
        .unwrap();
    let entered = cache
        .enter(info_of(&a), Archive::Plain(&dumped(&a)[..]))
        .unwrap();
    // The kept archive of `a` replaced by another path's: well-formed zstd, the wrong content.
    let other = compress_to_vec(&dumped(&b)[..], CompressionLevel::from_level(1));
    std::fs::write(blobs.file(&entered.nar_hash), other).unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(serve(listener, no_faults(dir.path(), cache)));
    let target = tempfile::tempdir().unwrap();
    let root = target.path().to_path_buf();
    let out = tokio::task::spawn_blocking(move || copy(&url, &a, &root, &public))
        .await
        .unwrap();
    assert!(
        !out.status.success(),
        "an archive that is not its narinfo's was accepted"
    );
    writable(target.path());
}

#[test]
fn a_path_held_with_another_archive_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let key = SecretKey::from_seed("polar-test-1", [7; 32]).unwrap();
    let blobs = Arc::new(Blobs::open(dir.path(), 3).unwrap());
    let cache = NixCache::open(dir.path(), blobs, key, PRIORITY).unwrap();
    let path: StorePath = "/nix/store/pzi5n9fkld7d4baq2iyvapk6213plrcv-x"
        .parse()
        .unwrap();
    let info = |content: &[u8]| PathInfo {
        store_path: path.clone(),
        nar_hash: polar_registry_nix::hash::Sha256::of(content),
        nar_size: content.len() as u64,
        references: Default::default(),
        deriver: None,
        ca: None,
        sigs: Vec::new(),
    };
    let first = cache
        .enter(info(b"one"), Archive::Plain(&b"one"[..]))
        .unwrap();
    assert_eq!(
        cache
            .enter(info(b"one"), Archive::Plain(&b"unread"[..]))
            .unwrap(),
        first
    );
    assert!(
        cache
            .enter(info(b"two"), Archive::Plain(&b"two"[..]))
            .is_err()
    );
    assert_eq!(cache.narinfo(path.hash_part()).unwrap(), Some(first));
}

#[test]
fn a_narinfo_that_cannot_be_read_is_an_error_not_an_absence() {
    let dir = tempfile::tempdir().unwrap();
    let key = SecretKey::from_seed("polar-test-1", [7; 32]).unwrap();
    let blobs = Arc::new(Blobs::open(dir.path(), 3).unwrap());
    let cache = NixCache::open(dir.path(), blobs, key, PRIORITY).unwrap();
    let hash_part = "pzi5n9fkld7d4baq2iyvapk6213plrcv";
    std::fs::create_dir(dir.path().join(format!("nix/{hash_part}.narinfo"))).unwrap();
    assert!(cache.narinfo(hash_part).is_err());
}

#[tokio::test]
async fn a_narinfo_the_cache_cannot_read_is_answered_as_its_own_failure() {
    let dir = tempfile::tempdir().unwrap();
    let key = SecretKey::from_seed("polar-test-1", [7; 32]).unwrap();
    let blobs = Arc::new(Blobs::open(dir.path(), 3).unwrap());
    let cache = Arc::new(NixCache::open(dir.path(), blobs, key, PRIORITY).unwrap());
    let hash_part = "pzi5n9fkld7d4baq2iyvapk6213plrcv";
    std::fs::write(
        dir.path().join(format!("nix/{hash_part}.narinfo")),
        "not a narinfo\n",
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(serve(listener, no_faults(dir.path(), cache)));
    let status = reqwest::get(format!("{url}/{hash_part}.narinfo"))
        .await
        .unwrap()
        .status();
    assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
}
