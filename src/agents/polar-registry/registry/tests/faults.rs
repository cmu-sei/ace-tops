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

//! Faults, held to Nix: upstream caches are made by `nix copy` itself, signed with a key of the test's, in each
//! compression Nix writes; Polar's cache faults paths in from them and Nix copies the paths from Polar's cache,
//! trusting Polar's key alone. Every way an upstream's answer can be wrong is refused and recorded. One test goes to
//! cache.nixos.org, and says it skipped where it cannot reach it.

mod common;

use common::{copy, nix, ok, oracle_paths, writable};
use polar_registry::blobs::Blobs;
use polar_registry::faults::{Faults, Fetch, Upstream};
use polar_registry::nix_cache::{NixCache, PRIORITY, serve};
use polar_registry_nix::signature::SecretKey;
use polar_registry_nix::store_path::StorePath;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const UPSTREAM: &str = "http://upstream.invalid";

/// An upstream cache in a directory, as `nix copy --to file://` wrote it, reached at `UPSTREAM`; each body passed
/// through `change` first, so a test can make the upstream answer wrongly.
type Change = Box<dyn Fn(&str, Vec<u8>) -> Vec<u8> + Send + Sync>;

struct FromDir {
    dir: PathBuf,
    change: Change,
}

#[async_trait::async_trait]
impl Fetch for FromDir {
    async fn get(&self, url: &str, limit: u64) -> Result<Option<Vec<u8>>, String> {
        let rest = url
            .strip_prefix(&format!("{UPSTREAM}/"))
            .ok_or("another host")?;
        let body = match std::fs::read(self.dir.join(rest)) {
            Ok(body) => (self.change)(rest, body),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        // The bound holds for what the upstream gives, changed or not.
        if body.len() as u64 > limit {
            return Err(format!("larger than {limit} bytes"));
        }
        Ok(Some(body))
    }
}

fn unchanged(_: &str, body: Vec<u8>) -> Vec<u8> {
    body
}

/// The upstream key's secret.
fn upstream_key() -> SecretKey {
    SecretKey::from_seed("upstream-test-1", [9; 32]).unwrap()
}

/// An upstream cache of `a`'s closure, compressed with `compression`, signed with `upstream_key`.
fn upstream(dir: &Path, a: &StorePath, compression: &str) -> PathBuf {
    let key = dir.join("upstream.secret");
    std::fs::write(&key, upstream_key().to_nix()).unwrap();
    let cache = dir.join(format!("upstream-{compression}"));
    let to = format!(
        "file://{}?compression={compression}&secret-key={}",
        cache.display(),
        key.display()
    );
    ok(nix(&["copy", "--no-check-sigs", "--to", &to, &a.to_string()]).unwrap());
    cache
}

struct Polar {
    faults: Arc<Faults>,
    blobs: Arc<Blobs>,
    root: PathBuf,
}

fn polar(root: &Path, fetch: impl Fetch + 'static, trusted: &SecretKey, max_archive: u64) -> Polar {
    let blobs = Arc::new(Blobs::open(root, 3).unwrap());
    let key = SecretKey::from_seed("polar-test-1", [7; 32]).unwrap();
    let cache = Arc::new(NixCache::open(root, blobs.clone(), key, PRIORITY).unwrap());
    let upstreams = vec![Upstream {
        url: UPSTREAM.into(),
        key: trusted.public(),
    }];
    let faults = Faults::new(cache, root, upstreams, Arc::new(fetch), true, max_archive).unwrap();
    Polar {
        faults: Arc::new(faults),
        blobs,
        root: root.to_path_buf(),
    }
}

/// What the cache recorded of its faults.
fn records(root: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(root.join("faults.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn faults_bring_a_path_and_its_references_in_and_nix_takes_them_on_polar_s_key_alone() {
    let Some((a, b)) = oracle_paths() else {
        return;
    };
    for compression in ["zstd", "none"] {
        let dir = tempfile::tempdir().unwrap();
        let up = upstream(dir.path(), &a, compression);
        let p = polar(
            &dir.path().join("polar"),
            FromDir {
                dir: up.clone(),
                change: Box::new(unchanged),
            },
            &upstream_key(),
            1 << 30,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(serve(listener, p.faults.clone()));

        let polar_key = SecretKey::from_seed("polar-test-1", [7; 32])
            .unwrap()
            .public()
            .to_string();
        let target = tempfile::tempdir().unwrap();
        let (u, a2, root) = (url.clone(), a.clone(), target.path().to_path_buf());
        let out = tokio::task::spawn_blocking(move || copy(&u, &a2, &root, &polar_key))
            .await
            .unwrap();
        assert!(
            out.status.success(),
            "{compression}: {}",
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

        let held = p.faults.cache().narinfo(a.hash_part()).unwrap().unwrap();
        let names: Vec<_> = held.sigs.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["upstream-test-1", "polar-test-1"], "{compression}");
        if compression == "zstd" {
            let theirs =
                std::fs::read_to_string(up.join(format!("{}.narinfo", a.hash_part()))).unwrap();
            let theirs = polar_registry_nix::narinfo::NarInfo::parse(&theirs).unwrap();
            assert_eq!(
                std::fs::read(p.blobs.file(&held.nar_hash)).unwrap(),
                std::fs::read(up.join(&theirs.url)).unwrap(),
                "an upstream's zstd is kept as it came"
            );
        }
        let entered: Vec<_> = records(&p.root)
            .into_iter()
            .filter(|r| r["outcome"] == "entered")
            .map(|r| {
                assert!(
                    r["requester"].as_str().unwrap().starts_with("127.0.0.1:"),
                    "{r}"
                );
                r["store_path"].as_str().unwrap().to_string()
            })
            .collect();
        let mut expected = vec![a.to_string(), b.to_string()];
        expected.sort();
        let mut entered = entered;
        entered.sort();
        assert_eq!(entered, expected, "{compression}");
    }
}

/// What the cache said when `hash_part` was asked of it: whether it was held after, the outcome recorded, and what the
/// upstream was recorded to have said.
async fn ask(p: &Polar, hash_part: &str) -> (bool, String, String) {
    let found = p.faults.lookup(hash_part, None).await.unwrap();
    let last = records(&p.root).pop().unwrap();
    let said = last["tried"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["said"].as_str().unwrap().to_string())
        .collect::<Vec<_>>()
        .join("; ");
    (
        found.is_some(),
        last["outcome"].as_str().unwrap().to_string(),
        said,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn every_wrong_answer_from_an_upstream_is_refused_and_recorded() {
    let Some((a, b)) = oracle_paths() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let up = upstream(dir.path(), &a, "zstd");
    let xz = upstream(dir.path(), &a, "xz");
    let fresh = |name: &str, fetch: FromDir, trusted: &SecretKey, max: u64| {
        polar(&dir.path().join(name), fetch, trusted, max)
    };
    let from = |dir: &Path, change: Change| FromDir {
        dir: dir.to_path_buf(),
        change,
    };

    let p = fresh(
        "xz",
        from(&xz, Box::new(unchanged)),
        &upstream_key(),
        1 << 30,
    );
    assert_eq!(
        ask(&p, a.hash_part()).await,
        (
            false,
            "refused".into(),
            "its archive is compressed with xz, which is not taken yet".into()
        )
    );

    let other = SecretKey::from_seed("upstream-test-1", [10; 32]).unwrap();
    let p = fresh("untrusted", from(&up, Box::new(unchanged)), &other, 1 << 30);
    assert_eq!(
        ask(&p, a.hash_part()).await,
        (
            false,
            "refused".into(),
            "not signed by upstream-test-1".into()
        )
    );

    // b's narinfo, signed and whole, given for a's hash part.
    let b_narinfo = std::fs::read(up.join(format!("{}.narinfo", b.hash_part()))).unwrap();
    let a_narinfo = format!("{}.narinfo", a.hash_part());
    let swapped: Change = Box::new(move |rest, body| {
        if rest == a_narinfo {
            b_narinfo.clone()
        } else {
            body
        }
    });
    let p = fresh("swapped", from(&up, swapped), &upstream_key(), 1 << 30);
    let (held, outcome, said) = ask(&p, a.hash_part()).await;
    assert_eq!((held, outcome.as_str()), (false, "refused"));
    assert!(said.starts_with("a narinfo for another path"), "{said}");

    // An archive's place is not signed, so an upstream may name any; one outside it is refused.
    fn elsewhere(rest: &str, body: Vec<u8>) -> Vec<u8> {
        if rest.ends_with(".narinfo") {
            let text = String::from_utf8(body).unwrap();
            let text = text
                .lines()
                .map(|l| {
                    if l.starts_with("URL: ") {
                        "URL: ../outside.nar.zst".to_string()
                    } else {
                        l.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            return text.into_bytes();
        }
        body
    }
    let p = fresh(
        "elsewhere",
        from(&up, Box::new(elsewhere)),
        &upstream_key(),
        1 << 30,
    );
    assert_eq!(
        ask(&p, a.hash_part()).await,
        (
            false,
            "refused".into(),
            "its archive is not at a place under the cache".into()
        )
    );

    // Refused by the size its narinfo states, before the archive is fetched; one exactly at the bound is taken.
    let p = fresh("small", from(&up, Box::new(unchanged)), &upstream_key(), 16);
    assert_eq!(
        ask(&p, a.hash_part()).await,
        (
            false,
            "refused".into(),
            "its archive is larger than 16 bytes".into()
        )
    );
    let stated = polar_registry_nix::narinfo::NarInfo::parse(
        &std::fs::read_to_string(up.join(format!("{}.narinfo", a.hash_part()))).unwrap(),
    )
    .unwrap()
    .file_size
    .unwrap();
    let p = fresh(
        "exact",
        from(&up, Box::new(unchanged)),
        &upstream_key(),
        stated,
    );
    assert!(ask(&p, a.hash_part()).await.0);

    // A narinfo is read to its bound: a long one is taken, a longer one refused. Keys Nix does not write are passed
    // over, and nothing signed changes.
    fn padded(by: usize) -> Change {
        Box::new(move |rest, mut body| {
            if rest.ends_with(".narinfo") {
                body.extend_from_slice(format!("Padding: {}\n", "x".repeat(by)).as_bytes());
            }
            body
        })
    }
    let p = fresh("long", from(&up, padded(4096)), &upstream_key(), 1 << 30);
    assert!(ask(&p, a.hash_part()).await.0);
    let p = fresh(
        "too-long",
        from(&up, padded(polar_registry::faults::MAX_NARINFO as usize)),
        &upstream_key(),
        1 << 30,
    );
    let (held, outcome, said) = ask(&p, a.hash_part()).await;
    assert_eq!((held, outcome.as_str()), (false, "refused"));
    assert!(said.contains("larger than 65536 bytes"), "{said}");

    let p = fresh(
        "absent",
        from(&up, Box::new(unchanged)),
        &upstream_key(),
        1 << 30,
    );
    assert_eq!(
        ask(&p, &"0".repeat(32)).await,
        (false, "absent".into(), "not held".into())
    );
}

#[tokio::test]
async fn a_cache_with_no_upstreams_has_what_it_holds_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let blobs = Arc::new(Blobs::open(dir.path(), 3).unwrap());
    let key = SecretKey::from_seed("polar-test-1", [7; 32]).unwrap();
    let cache = Arc::new(NixCache::open(dir.path(), blobs, key, PRIORITY).unwrap());
    let faults = Arc::new(
        Faults::new(
            cache,
            dir.path(),
            Vec::new(),
            Arc::new(polar_registry::faults::NoFetch),
            true,
            1 << 30,
        )
        .unwrap(),
    );
    assert!(
        faults
            .lookup(&"0".repeat(32), None)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(records(dir.path()).pop().unwrap()["outcome"], "absent");
    // NoFetch, asked directly, holds nothing.
    assert_eq!(
        polar_registry::faults::NoFetch.get("http://x/y", 10).await,
        Ok(None)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn with_faults_off_what_is_not_held_is_refused_and_recorded() {
    let Some((a, _)) = oracle_paths() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let up = upstream(dir.path(), &a, "zstd");
    let p = polar(
        &dir.path().join("polar"),
        FromDir {
            dir: up,
            change: Box::new(unchanged),
        },
        &upstream_key(),
        1 << 30,
    );
    p.faults.set_on(false);
    assert_eq!(
        ask(&p, a.hash_part()).await,
        (false, "off".into(), String::new())
    );
    p.faults.set_on(true);
    assert_eq!(
        ask(&p, a.hash_part()).await,
        (
            true,
            "entered".into(),
            "entered, signed by upstream-test-1".into()
        )
    );
    // Held now: off, it is still served, and nothing more is recorded.
    p.faults.set_on(false);
    let before = records(&p.root).len();
    assert!(
        p.faults
            .lookup(a.hash_part(), None)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(records(&p.root).len(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn asked_at_once_a_path_is_faulted_once() {
    let Some((a, _)) = oracle_paths() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let up = upstream(dir.path(), &a, "zstd");
    let p = polar(
        &dir.path().join("polar"),
        FromDir {
            dir: up,
            change: Box::new(unchanged),
        },
        &upstream_key(),
        1 << 30,
    );
    let asks: Vec<_> = (0..8)
        .map(|_| {
            let (faults, h) = (p.faults.clone(), a.hash_part().to_string());
            tokio::spawn(async move { faults.lookup(&h, None).await.unwrap() })
        })
        .collect();
    for ask in asks {
        assert!(ask.await.unwrap().is_some());
    }
    assert_eq!(records(&p.root).len(), 1);
}

/// cache.nixos.org, over HTTPS.
struct Https(reqwest::Client);

#[async_trait::async_trait]
impl Fetch for Https {
    async fn get(&self, url: &str, limit: u64) -> Result<Option<Vec<u8>>, String> {
        let reply = self.0.get(url).send().await.map_err(|e| e.to_string())?;
        if reply.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let body = reply
            .error_for_status()
            .map_err(|e| e.to_string())?
            .bytes()
            .await
            .map_err(|e| e.to_string())?;
        if body.len() as u64 > limit {
            return Err(format!("larger than {limit} bytes"));
        }
        Ok(Some(body.to_vec()))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_path_faults_in_from_cache_nixos_org_as_nix_has_it() {
    // The nix on the PATH came from cache.nixos.org; what Polar faults in must be what Nix holds.
    let Some(out) = nix(&["--version"]) else {
        return;
    };
    let _ = ok(out);
    let exe = std::fs::canonicalize(ok(std::process::Command::new("sh")
        .args(["-c", "command -v nix"])
        .output()
        .unwrap()))
    .unwrap();
    let path: StorePath = exe
        .ancestors()
        .nth(2)
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .unwrap();
    if client
        .get("https://cache.nixos.org/nix-cache-info")
        .send()
        .await
        .is_err()
    {
        eprintln!("skipped: cache.nixos.org cannot be reached");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let blobs = Arc::new(Blobs::open(dir.path(), 3).unwrap());
    let key = SecretKey::from_seed("polar-test-1", [7; 32]).unwrap();
    let cache = Arc::new(NixCache::open(dir.path(), blobs, key, PRIORITY).unwrap());
    let upstreams = vec![Upstream {
        url: "https://cache.nixos.org".into(),
        key: "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
            .parse()
            .unwrap(),
    }];
    let faults = Arc::new(
        Faults::new(
            cache,
            dir.path(),
            upstreams,
            Arc::new(Https(client)),
            true,
            1 << 30,
        )
        .unwrap(),
    );
    let Some(info) = faults.lookup(path.hash_part(), None).await.unwrap() else {
        let said = records(dir.path())
            .pop()
            .map(|r| r["tried"].to_string())
            .unwrap_or_default();
        eprintln!("skipped: cache.nixos.org did not give {path}: {said}");
        return;
    };
    let ours = common::info_of(&path);
    assert_eq!(
        (info.nar_hash, info.nar_size, &info.references),
        (ours.nar_hash, ours.nar_size, &ours.references)
    );
    let names: Vec<_> = info.sigs.iter().map(|s| s.name.as_str()).collect();
    assert!(
        names.contains(&"cache.nixos.org-1") && names.contains(&"polar-test-1"),
        "{names:?}"
    );
}
