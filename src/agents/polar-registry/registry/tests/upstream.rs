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

//! Faults through the builder's protocol handler, as the agent makes them: the real handler, judging and recording each
//! request of the one operation the registry declares, to an upstream Polar cache served here. Nix copies the faulted
//! paths from the registry trusting its key alone; every request the faults made is on the handler's record, allowed,
//! to the configured host; and where the operation's variable is not set, the handler refuses and the fault says why.

mod common;

use common::{copy, dumped, info_of, no_faults, oracle_paths, writable};
use polar_agent_builder::protocol::testing::{git_ca, http_handle};
use polar_registry::blobs::Blobs;
use polar_registry::faults::{Faults, Upstream};
use polar_registry::nix_cache::{Archive, NixCache, PRIORITY, serve};
use polar_registry::upstream::{Handled, NIX_UPSTREAM, OPERATIONS, UPSTREAM_VAR};
use polar_registry_nix::signature::SecretKey;
use std::path::Path;
use std::sync::Arc;

fn upstream_key() -> SecretKey {
    SecretKey::from_seed("upstream-test-1", [9; 32]).unwrap()
}

fn polar_key() -> SecretKey {
    SecretKey::from_seed("polar-test-1", [7; 32]).unwrap()
}

/// A Polar cache holding `paths`, signed with `upstream_key`, served here; its address.
async fn upstream_cache(
    root: &Path,
    paths: &[&polar_registry_nix::store_path::StorePath],
) -> String {
    let blobs = Arc::new(Blobs::open(root, 3).unwrap());
    let cache = Arc::new(NixCache::open(root, blobs, upstream_key(), PRIORITY).unwrap());
    for path in paths {
        cache
            .enter(info_of(path), Archive::Plain(&dumped(path)[..]))
            .unwrap();
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(serve(listener, no_faults(root, cache)));
    url
}

/// The registry under test, faulting through `fetch` from `upstream_url`.
fn registry(root: &Path, upstream_url: &str, fetch: Handled) -> Arc<Faults> {
    let blobs = Arc::new(Blobs::open(root, 3).unwrap());
    let cache = Arc::new(NixCache::open(root, blobs, polar_key(), PRIORITY).unwrap());
    let upstreams = vec![Upstream {
        url: upstream_url.to_string(),
        key: upstream_key().public(),
        via: NIX_UPSTREAM.name,
    }];
    Arc::new(Faults::new(cache, root, upstreams, Arc::new(fetch), true, 1 << 28).unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn faults_go_through_the_handler_judged_and_recorded_and_nix_takes_what_they_brought() {
    let Some((a, b)) = oracle_paths() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let upstream = upstream_cache(&dir.path().join("upstream"), &[&a, &b]).await;
    let site = http_handle(
        &git_ca().pem,
        OPERATIONS,
        vec![(UPSTREAM_VAR, upstream.clone())],
        None,
    )
    .await;
    let faults = registry(
        &dir.path().join("polar"),
        &upstream,
        Handled(site.handle.clone()),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(serve(listener, faults));

    let target = tempfile::tempdir().unwrap();
    let (u, a2, root, key) = (
        url,
        a.clone(),
        target.path().to_path_buf(),
        polar_key().public().to_string(),
    );
    let out = tokio::task::spawn_blocking(move || copy(&u, &a2, &root, &key))
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for path in [&a, &b] {
        let copied = target.path().join(path.to_string().trim_start_matches('/'));
        assert_eq!(
            std::fs::read(copied).unwrap(),
            std::fs::read(path.to_string()).unwrap()
        );
    }
    writable(target.path());

    // Each path's narinfo and then its archive: four requests, each of the one declared operation, to the configured
    // host, allowed, with no credential.
    let records = site.records.lock().unwrap().clone();
    assert_eq!(records.len(), 4, "{records:?}");
    for r in &records {
        assert_eq!(
            (r.operation, r.protocol, r.host.as_str()),
            ("nix.upstream", "http", "127.0.0.1"),
            "{r:?}"
        );
        assert_eq!(
            (r.verdict.as_str(), &r.credential, r.arbitrary),
            ("allowed", &None, false),
            "{r:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn where_the_operation_has_no_address_the_handler_refuses_and_the_fault_says_why() {
    let dir = tempfile::tempdir().unwrap();
    let site = http_handle(&git_ca().pem, OPERATIONS, Vec::new(), None).await;
    let faults = registry(
        &dir.path().join("polar"),
        "http://127.0.0.1:9",
        Handled(site.handle.clone()),
    );
    assert!(
        faults
            .lookup(&"0".repeat(32), None)
            .await
            .unwrap()
            .is_none()
    );
    let last: serde_json::Value = std::fs::read_to_string(dir.path().join("polar/faults.jsonl"))
        .unwrap()
        .lines()
        .last()
        .map(|l| serde_json::from_str(l).unwrap())
        .unwrap();
    assert_eq!(last["outcome"], "refused");
    let said = last["tried"][0]["said"].as_str().unwrap();
    assert!(said.contains("not set"), "{said}");
    let records = site.records.lock().unwrap().clone();
    assert_eq!(records.len(), 1);
    assert_ne!(records[0].verdict, "allowed");
}

#[tokio::test]
async fn an_upstream_no_declared_operation_reaches_is_refused_before_the_handler() {
    let site = http_handle(&git_ca().pem, OPERATIONS, Vec::new(), None).await;
    let elsewhere = Upstream {
        url: "https://elsewhere.invalid".into(),
        key: upstream_key().public(),
        via: "not.declared",
    };
    use polar_registry::faults::Fetch;
    let refused = Handled(site.handle.clone())
        .get(&elsewhere, "/x.narinfo", 1024)
        .await;
    assert!(refused.unwrap_err().contains("no operation"));
    assert!(site.records.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_reply_is_taken_to_its_limit_and_no_further() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = upstream_cache(dir.path(), &[]).await;
    let site = http_handle(
        &git_ca().pem,
        OPERATIONS,
        vec![(UPSTREAM_VAR, upstream.clone())],
        None,
    )
    .await;
    let fetch = Handled(site.handle.clone());
    let via = Upstream {
        url: upstream,
        key: upstream_key().public(),
        via: NIX_UPSTREAM.name,
    };
    use polar_registry::faults::Fetch;
    let info = polar_registry_nix::narinfo::cache_info(PRIORITY);
    let len = info.len() as u64;
    assert_eq!(
        fetch.get(&via, "/nix-cache-info", len).await,
        Ok(Some(info.into_bytes()))
    );
    let refused = fetch
        .get(&via, "/nix-cache-info", len - 1)
        .await
        .unwrap_err();
    assert_eq!(refused, format!("larger than {} bytes", len - 1));
    assert_eq!(
        fetch
            .get(&via, &format!("/{}.narinfo", "0".repeat(32)), len)
            .await,
        Ok(None)
    );
}

/// Bytes no compressor shrinks, the same each time: xorshift, read as a stream so that nothing holds them whole.
struct Noise {
    left: u64,
    state: u64,
}

impl Noise {
    fn new(size: u64) -> Self {
        Self {
            left: size,
            state: 0x9E37_79B9_7F4A_7C15,
        }
    }
}

impl std::io::Read for Noise {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = (buf.len() as u64).min(self.left) as usize & !7;
        let n = if n == 0 {
            (buf.len() as u64).min(self.left) as usize
        } else {
            n
        };
        for chunk in buf[..n].chunks_mut(8) {
            self.state ^= self.state << 13;
            self.state ^= self.state >> 7;
            self.state ^= self.state << 17;
            chunk.copy_from_slice(&self.state.to_le_bytes()[..chunk.len()]);
        }
        self.left -= n as u64;
        Ok(n)
    }
}

/// The most this process has held in memory at once, from the kernel's own count.
fn peak_resident() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|l| l.starts_with("VmHWM:")).unwrap();
    line.split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<u64>()
        .unwrap()
        * 1024
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "release only, as it moves 320 MiB: cargo test --release -p polar-registry --test upstream -- --ignored"]
async fn an_archive_larger_than_a_whole_reply_may_be_faults_in_piece_by_piece() {
    const SIZE: u64 = 320 << 20;
    let mut hashing = polar_registry_nix::hash::Hashing::new(std::io::sink());
    std::io::copy(&mut Noise::new(SIZE), &mut hashing).unwrap();
    let (nar_hash, nar_size, _) = hashing.finish();
    let path: polar_registry_nix::store_path::StorePath =
        "/nix/store/0c1pnia4x2gwdsfpi6d98mjrqh6ma91n-polar-registry-large"
            .parse()
            .unwrap();
    let info = polar_registry::nix_cache::PathInfo {
        store_path: path.clone(),
        nar_hash,
        nar_size,
        references: Default::default(),
        deriver: None,
        ca: None,
        sigs: Vec::new(),
    };

    let dir = tempfile::tempdir().unwrap();
    let up = dir.path().join("upstream");
    let blobs = Arc::new(Blobs::open(&up, 1).unwrap());
    let cache = Arc::new(NixCache::open(&up, blobs, upstream_key(), PRIORITY).unwrap());
    let entered = cache.enter(info, Archive::Plain(Noise::new(SIZE))).unwrap();
    assert!(
        entered.file_size.unwrap() > polar_agent_builder::protocol::http::MAX_BODY as u64,
        "the archive must be larger than a whole reply may be"
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(serve(listener, no_faults(&up, cache)));

    let site = http_handle(
        &git_ca().pem,
        OPERATIONS,
        vec![(UPSTREAM_VAR, upstream.clone())],
        None,
    )
    .await;
    let faults = registry(
        &dir.path().join("polar"),
        &upstream,
        Handled(site.handle.clone()),
    );
    faults.set_max_archive(1 << 30);
    let before = peak_resident();
    let held = faults
        .lookup(path.hash_part(), None)
        .await
        .unwrap()
        .expect("faulted in");
    assert_eq!((held.nar_hash, held.nar_size), (nar_hash, SIZE));
    let peak = peak_resident();
    eprintln!(
        "peak resident: {} MiB before the fault, {} MiB after",
        before >> 20,
        peak >> 20
    );
    assert!(
        peak < 160 << 20,
        "the fault held {} MiB at once",
        peak >> 20
    );
    assert_eq!(site.records.lock().unwrap().len(), 2);
}
