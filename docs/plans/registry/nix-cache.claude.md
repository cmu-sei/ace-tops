<!--
  ACE Tool

  Copyright 2026 Carnegie Mellon University.

  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS
  FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
  EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE
  MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
  TRADEMARK, OR COPYRIGHT INFRINGEMENT.

  Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu
  for full terms.

  [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited
  distribution.  Please see Copyright notice for non-US Government use and distribution.

  This Software includes and/or makes use of Third-Party Software each subject to its own license.

  DM26-0670
-->

# nix-cache — Claude's side

PAIR: `nix-cache.md` (people). Same plan, two forms; change together.
SPLIT: people side has no dates, attributions, quotes, codenames or branch/process status; those live here.
PARENT: `../registry.claude.md`. AS-OF main a9ef59e4 (2026-11-12). STATUS: proposed; NC1 done; cleared to build by the
maintainer's "write up the proposal and then just start implementing this" (2026-11-12). Steps NC1-NC5 below.

## PROTOCOL FACTS (Nix binary cache; check each against `nix` itself in tests)
- GET /nix-cache-info: `StoreDir: /nix/store\nWantMassQuery: 1\nPriority: N\n`.
- GET /<hashpart>.narinfo (hashpart = 32 chars nix32 of store path). Fields: StorePath, URL, Compression, FileHash,
  FileSize, NarHash, NarSize, References (basenames, space-sep, may be empty), Deriver (basename, optional), Sig
  (repeatable, `name:base64(ed25519 sig)`), CA (optional). 404 when absent.
- Fingerprint signed: `1;<store path>;<NarHash sha256:nix32>;<NarSize>;<refs as full paths, comma-sep>`.
- Keys: secret `name:base64(64 bytes seed||pub)`, public `name:base64(32)` (nix-store --generate-binary-cache-key).
- NAR: strings = u64 LE len + bytes + zero pad to 8. `nix-archive-1` `(` `type` regular [`executable` ``] `contents`
  <bytes> `)`; directory `(` `type` `directory` {`entry` `(` `name` n `node` <node> `)`}* sorted by name bytes `)`;
  symlink `(` `type` `symlink` `target` t `)`.
- nix32 alphabet `0123456789abcdfghijklmnpqrsvwxyz`, least-significant first (verify vs `nix hash convert`).
- cache.nixos.org key `cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=`; its NARs xz (some zstd).

## DESIGN (mine, for review)
- CAS (revised 2026-11-12, maintainer: "Yes, plan it that way. It should also improve read performance, too"; the
  first draft kept NARs uncompressed, and the maintainer took a NAR to be compressed already, which it is not: plain
  serialization; caches compress on top, FileHash/FileSize of the compressed file, NarHash/NarSize of the plain NAR,
  shown by NC1's oracle, compression=none .nar == NarSize/NarHash): git-object style. Blob NAMED by sha256 of the
  UNCOMPRESSED content (= NarHash for a NAR), STORED zstd. Write: stream in → decompress-check (hash + size of plain
  bytes must equal the name / NarHash) → zstd-compressed temp file → fsync → rename. Per blob keep the compressed
  file's sha256 + size (FileHash/FileSize). narinfo: URL `nar/<nix32 narhash>.nar.zst`, Compression zstd, FileHash/
  FileSize of the stored file; served as stored, never recompressed per read. Upstream faults: zstd kept AS RECEIVED (decoded
  once to check); none encoded here; xz (older cache.nixos.org paths) decoded with pure-Rust `lzma-rust2` (Apache-2.0)
  and encoded zstd, added when the first xz path faults, refused with a clear reason until then. zstd level, and whether other faces' blobs (OCI layers are
  already gzip/zstd) are stored as-is: decide in NC2 / the images feature.
- zstd library: DECIDED 2026-11-12. First "not a fan of adding a C library. We did it for the allocator because
  there's not any real option to it" (C `zstd` 0.14 rejected); then, shown measurements, "If that's the best library
  in a rust crate for zstd, perhaps we should look at other compressions"; then "Let's try structured zstd".
  Measured (scratchpad bench, release, 1 thread, x86_64; glibc-2.44-25 NAR 35.6 MB; nix NAR 4.1 MB ranked alike):
  C zstd -3 3.47 / 567 MB/s / dec 1859; C zstd -19 4.34 / 8; structured-zstd 0.3.0 L3 3.47 / 577 / 2315, L9 3.80 /
  163 / 2465, L19 4.27 / 10 / 1922; ruzstd 0.9.1 Fastest (only level) 2.21 / 154 / 698, its decoder on L3 628;
  brotli 9.1.1 q5 3.80 / 74 / 717, q9 4.00 / 12 / 758, q11 4.55 / 1 / 669; lzma-rust2 0.25 xz6 4.75 / 7 / 137;
  flate2+zlib-rs gzip9 2.95 / 35 / 856. cache.nixos.org's own zstd of glibc: 3.41. Nix 2.34 writes caches in br,
  gzip, xz, zstd (lz4: "Using external lz4 program", refused).
  CHOSEN `structured-zstd` =0.3.0 (Apache-2.0; github structured-world/structured-zstd; first published 2026-03-25,
  0.3.0 on 2026-11-08, ~87k downloads vs ruzstd's ~21M; claims CI interop with C zstd both ways). I recommended
  brotli (mature) + ruzstd decoder; maintainer chose to try structured-zstd. RISKS recorded: young; ~1374 `unsafe`
  occurrences in src (encoder matchers, ringbuffer, SIMD copy; not only kernels). Features: default-features=false,
  ["std", "hash", "kernel-scalar", "kernel-avx2", "kernel-neon"]: drops `legacy` (v0.5-0.7 frames: less decoder
  surface for untrusted upstream bytes), `dict-builder` (and fastrand), `ldm`, sve/simd128. Same speed as default
  (L9 166 / 2429); scalar-only costs ~10% decode. Deps then: twox-hash (MIT). Mitigations to build in: decoding
  bounded by the narinfo's NarSize (refuse past it: no bomb), oracle tests both ways (Nix substitutes our .nar.zst;
  we decode cache.nixos.org's and C zstd CLI's), property round trips and mutated-input-never-panics. Revisit with
  age; brotli is the fallback.
  Read 2026-11-12 (the maintainer: "The agents.md in the structured zstd repo seems instructive"): its AGENTS.md is
  a performance-review checklist with Polar-like discipline: claims in time against upstream C zstd in the same
  harness and run, a control arm under ~1.5% (layout noise), checked_* not saturating_* (fail at the cause), a
  provable removed check becomes debug_assert, kernels present regardless of baseline (#[target_feature(enable)]),
  chosen by runtime detection once above the loop, scalar fallback, a test sweeping every tier the CPU supports
  against scalar for bit-identical output; cfg(target_feature) only for architectural facts (NEON on aarch64, SSE2
  on x86_64). That runtime dispatch is what keeps one artifact per target. Lineage: GitHub contributors
  KillingSpark (ruzstd's author) 429, polaz 309, release bot 63, paolobarbolini 30, Shnatsel 10: ruzstd's history
  carried forward with a full encoder, not new code; repo created 2026-03-25, 13 stars. By its own standard my
  bench is indicative only (one run, one host; C figures from the CLI, not the same harness). Encoding level for plain inputs: 9 by default (measured), a setting.
- C already in the workspace (told the maintainer): git2 → libgit2-sys, libssh2-sys, libz-sys; static OpenSSL
  (workspace.nix OPENSSL_*); ring's C/asm. gitoxide is the way off libgit2.
- Path records: per hashpart, a JSON record {store_path, nar_hash, nar_size, references, deriver?, ca?, upstream
  sigs, entered_at, from}; narinfo rendered from it + Polar's sig (signed at entry; key rotation → re-sign on read?
  open).
- Faults: upstream list ordered (signed setting): {url, key} binary caches; fetch narinfo → verify sig by that key →
  fetch URL → decompress per Compression (none/xz/zstd/bzip2?) → check FileHash (if given) and NarHash/NarSize while
  streaming into CAS → record → sign. Through builder HTTP handler (declared op, Location::Configured).
- Host mode: same binary, `serve-local` against /nix/store; path info from host's Nix (`nix path-info --json` or DB
  read-only; pick in NC4), NAR made by our writer and its hash checked vs Nix's narHash before serving; signs with host
  key; cluster registry trusts that key as an upstream. No hostPath anywhere.
- Fault switch: Dynamic bool, default on? (vendored test = off). Default for review: on in dev, off where unset? → ask
  when NC3 lands.
- Records: NC3 append-only faults.jsonl on the volume (git-server push-log precedent), Cassini event when cassini
  capability provided (later, records feature).
- Uploads (nix copy --to, PUT narinfo/nar): mTLS + policy; not in NC1-NC5 unless needed.

## STEPS
- NC1 formats crate. DONE 2026-11-12: `src/agents/polar-registry/nix` (package polar-registry-nix; deps only
  existing workspace ones: ed25519-dalek 2.2, sha2, base64, hex, thiserror). nix32 (decode refuses stray high bits:
  one spelling), Sha256 (reads sha256:nix32|hex and SRI; prints sha256:nix32), StorePath (base-name kept, orders as
  Nix; names per Nix 2.34 probed: `.foo` `-a` `...` ok; `.` `..` space 212 chars refused), NAR (Node model;
  `dump` from fs as nix-store --dump, exec = owner x bit; strict `decode`: zero padding, entry names, strict order,
  MAX_DEPTH 256, no trailing bytes, link target non-empty no NUL), NarInfo (parse strict on required/dup keys,
  unknown keys dropped as Nix ignores them; render in Nix's order; fingerprint; sign replaces same-name sig),
  signature (Nix key/sig spellings; verify_strict; SecretKey Debug hides key), cache_info.
  Oracle (tests/nix.rs, real nix 2.34.8, skips loudly if absent): nix-store --dump bytes == ours for a tree with
  every node kind and owner-only/others-only exec; nix hash path; nix32 vs `nix hash convert`; cache.nixos.org-1 sig
  on nix's own path verifies under our fingerprint; `nix copy --to file://…?compression=none&secret-key=` narinfo
  parses and renders byte-identical, our Ed25519 sig == Nix's, its .nar == our dump. Props (tests/props.rs, 8).
  cargo-mutants (package only, POLAR_VERSION=1.0.0): 242 mutants, 225 caught, 16 unviable, 1 missed =
  nix32.rs encode `|`→`^` (equivalent: bit ranges disjoint; commented). First run missed 30; closed with tests.
  `just static-analysis`: geiger (needs absolute manifest path), semver-checks (pkcs1 doc error on logger), udeps
  (other crates only), mutants (workspace copy lacks VERSION) fail — all pre-existing, none in this crate.
- NC2 CAS + Nix face. DONE 2026-11-12: `src/agents/polar-registry/registry` (package polar-registry; axum 0.7 as
  the other Polar servers; structured-zstd workspace dep). `blobs.rs`: Blobs{root/blobs/<hex>.zst + <hex>.json
  (size, file_sha256, file_size), root/tmp cleared at open}; put_zstd keeps bytes as received (tee → file while
  decoding, decode bounded by Expect.size, hash/size checked), put_plain encodes at level (DEFAULT_LEVEL 9) then
  DECODES THE WRITTEN FILE back and checks (young-encoder guard); commit = rename blob, then sidecar, fsync dir;
  held blob → not read again, held to its size. `nix_cache.rs`: NixCache{root/nix/<hashpart>.narinfo,
  root/nix-tmp}; enter(PathInfo, Archive::{Zstd,Plain}) → blob, narinfo URL nar/<nix32>.nar.zst Compression zstd
  FileHash/FileSize of kept file, upstream sigs kept + Polar sig; same path+NarHash → returned as held, other
  NarHash → HeldOtherwise; routes /nix-cache-info, /:file (.narinfo), /nar/:file (.nar.zst, nix32 of plain hash),
  everything else 404, unreadable narinfo → 500; PRIORITY 40; `serve(listener, cache)`.
  Oracle (tests/nix.rs): two input-addressed derivations built in the test (bash builder, a refers to b) — CA paths
  (toFile) would pass Nix's signature check vacuously; a entered plain, b as zstd kept as received; `nix copy --from
  http://127.0.0.1:P --to local?root=…` with trusted-public-keys = Polar's copies both, files identical; another key
  → refused ("signature"); blob replaced by another path's zstd → refused. Mutation-checked: dropping the signing
  fails it. Store tests: refusals leave nothing in tmp or blobs, a 64 MiB zstd bomb said to be 1 KiB refused, C
  `zstd -19` output kept as received, 16 concurrent writes, interrupted/failing readers, unreadable record = error.
  cargo-mutants polar-registry: 55, 43 caught + 2 timeouts (an infinite retry: caught), 9 unviable, 0 missed after
  sharing temp_name (the duplicate's mutant was the last one).
- NC3 faults. DONE 2026-11-12: `faults.rs`. trait Fetch (async_trait; get(url, limit) → Option<Vec<u8>>; whole
  bodies because polar-agent-builder's HTTP handler Reply.body is Vec<u8> — NC5 implements Fetch over it; NoFetch
  for none). Upstream{url, key}. Faults{cache, upstreams, fetch, on: AtomicBool (set_on), max_archive, faults.jsonl
  appended + sync_data per record, per-hash-part tokio Mutex so concurrent asks fault once}. lookup(hash_part,
  requester): held → serve; off → record Off, 404; else each upstream in order: narinfo ≤ MAX_NARINFO 64 KiB, must be
  for the hash part asked, signed_by(upstream.key), Compression zstd (kept as received) | none (encoded here) | other
  refused "not taken yet" (xz), URL a place under the cache (is_archive_place: relative, [A-Za-z0-9._-/], no `..`
  or empty segment; URL is UNSIGNED so this matters), FileSize > max_archive refused before fetch, archive ≤
  max_archive, enter() with upstream sigs kept + Polar's. FileHash is unsigned and not relied on (NarHash is).
  Outcomes Entered/Absent/Refused/Off; record {at_unix_ms, hash_part, requester (ConnectInfo), outcome,
  store_path, nar_hash, nar_size, tried[{upstream, said}]}. Eager: a narinfo miss fetches the archive too (a fresh
  build pod asks narinfo only for what it will fetch; a query-only client would cause downloads — noted).
  blobs::compressed_bound(size) = size + size/128 + 1 MiB: put_zstd reads no more (skippable frames can't stall).
  Router state is Arc<Faults>; serve(listener, faults) with ConnectInfo.
  Tests (tests/faults.rs; tests/common/mod.rs shared): upstreams made by `nix copy --to file://…?compression=
  {zstd,none,xz}&secret-key=` signed by a test key; Polar faults a+b in and `nix copy` from Polar trusting ONLY
  Polar's key takes both, identical; narinfo sigs [upstream-test-1, polar-test-1]; zstd blob == upstream's .nar.zst
  bytes; records entered with requester 127.0.0.1. Refusals with exact reasons: xz, untrusted key, b's narinfo for
  a's hash part, URL `../outside.nar.zst`, FileSize over bound (exact bound accepted), narinfo over 64 KiB (4 KiB
  padding with an unknown key accepted, sigs unaffected), absent. Off → "off" recorded; held still served when off,
  nothing recorded. 8 concurrent asks → one record. LIVE: nix's own path faulted from https://cache.nixos.org via a
  reqwest Fetch (test-only), NarHash/NarSize/References == local `nix path-info`, sigs contain cache.nixos.org-1 +
  polar (skips when unreachable). cargo-mutants: 99, 83 caught + 2 timeouts, 14 unviable, 0 missed.
  FOUND (flaky 1/15 under the mutation baseline): Nix's narinfo disk cache (~/.cache/nix, keyed by cache URL,
  positive TTL 30 days) answered for a reused 127.0.0.1 port, so no fault happened and the NAR 404'd. Tests give each
  copy its own XDG_CACHE_HOME. Real-world: a reset registry at the same URL meets stale clients (dev machines; build
  pods start empty). Options later: answer a NAR miss by faulting if the narinfo is known, or per-instance URLs.
  OPEN for NC5: faults default on or off (ask then); max_archive and the upstream list as Dynamic signed settings.
- NC3b (inserted 2026-11-13, maintainer: "Youve implemented all of this so far without using the protocol handler?";
  I had put the riskiest integration last; moved forward on "Yes"). DONE: the registry as a PolarAgent
  (`agent.rs`: Registry, NAME polar-registry, Role::Service, Cassini client — FOUND: ServiceBuilder (non-Cassini
  services) gets ProtocolSetup::default(), no handlers, lib.rs:802; so a registry that faults must be a full agent;
  OPERATIONS = upstream::OPERATIONS; bin `polar-registry`, Scudo), `settings.rs` (Static: POLAR_REGISTRY_ROOT
  WriteDir, POLAR_REGISTRY_LISTEN 0.0.0.0:5000, POLAR_REGISTRY_NIX_KEY ReadFile, POLAR_REGISTRY_NIX_UPSTREAM
  https://cache.nixos.org, POLAR_REGISTRY_NIX_UPSTREAM_KEY cache.nixos.org-1; Dynamic: POLAR_REGISTRY_NIX_FAULTS
  default FALSE (mine, for review: closed unless a signed setting opens it), POLAR_REGISTRY_NIX_MAX_ARCHIVE default
  268435456 = handler MAX_BODY, relations refuse 0 or > MAX_BODY; upstream URL `http(s)://host[:port]` only; key must
  parse) — upstream URL Static by the orchestrator's POLAR_ORCHESTRATOR_CRATES precedent. `upstream.rs`: OperationDecl
  `nix.upstream` HTTP Location::Configured{POLAR_REGISTRY_NIX_UPSTREAM, no credential}; Handled(ProtocolHandle)
  implements Fetch by Request::get(path) under the configured address (one request, whole reply ≤ 256 MiB, 120 s:
  polar-agent-builder/src/protocol/http.rs:52-57); Upstream.via names the operation, an upstream no declared operation
  reaches is refused before the handler. Fetch trait now (upstream, path, limit). Faults.max_archive is an AtomicU64
  (set_max_archive). `supervisor.rs`: AgentBuilder, follow_group(TUNING) → set_on/set_max_archive, opens store/cache
  (key from file)/faults, axum::serve with graceful shutdown, PrepareShutdown drains ≤ 120 s then ProceedWithShutdown
  (git server's pattern). Egress section is implied by the builder for any agent (agent.rs:620).
  Tests: tests/upstream.rs with polar_agent_builder::protocol::testing::http_handle (the real handler): upstream = a
  Polar NixCache served here, signed by a test key; Nix copies a+b from the registry trusting only Polar's key; the
  handler's records: exactly 4 (2 narinfo + 2 archive), each nix.upstream/http/127.0.0.1/allowed/no credential/not
  arbitrary. Variable unset → handler refuses ("not set"), fault recorded refused, one handler record not allowed.
  Scaffold (`polar-registry --scaffold`): one operation, configured at POLAR_REGISTRY_NIX_UPSTREAM; filesystem only
  /etc/resolv.conf, /etc/hosts; sections builder, health, logging, cassini-client, polar-registry, egress.
  Also: Handled takes a reply to its limit and no further (exact limit Some, limit-1 refused, 404 None);
  set_max_archive lowered at run time holds for the next fault.
  cargo-mutants (whole crate 141: 104 caught + 2 timeouts, 23 unviable, 12 missed; 6 closed by those tests and a
  SHUTDOWN_BUDGET test). LEFT, 6, all needing a live agent (Cassini, a cluster): main → Default, Registry::start → Ok,
  supervisor handle → Ok, its Registered and TransportError arms, handle_supervisor_evt → Ok. To be exercised in NC5
  (the git server's and orchestrator's supervisors are in the same position).
  NOT RUN: the supervisor (needs Cassini and a cluster: NC5).
- NC3c STREAMING (2026-11-13, maintainer: "I feel like making the handler stream is important now"). DONE:
  polar-agent-builder: `http::Request::in_pieces(most, stall)`; perform → `in_pieces()`: head Reply (status, headers,
  empty body) then each `response.chunk()` as a Reply (empty headers), each via Exchange::reply (paced), stall per
  chunk via tokio::time::timeout, total > most → Failure, per-request `.timeout(PIECES_DEADLINE)` (1 h) overriding the
  client's 120 s; MAX_BODY not its bound. `ProtocolHandle::pieces(op) -> Pieces<T>` (mpsc(1) + end oneshot, `next()`),
  closes after the last piece; failure is the last item (run() always sends Err before returning on failure). No
  struct changed (resolver tests build Reply literally; acp may too) — additive. Docs: protocol-handlers.md, "An HTTP
  reply can come in pieces". Builder tests (http.rs): 3 MiB → head + >1 pieces, one record allowed; most=1000 →
  failure, exact most whole; raw TCP site sends head + "some" then silence → failure "no piece... came in" fast;
  plain request via pieces → one then None. Registry: Fetch::archive (default = get as one piece), Pieces =
  mpsc::Receiver<Result<Vec<u8>,String>>, PieceReader (blocking_recv) feeds enter() in spawn_blocking; Handled::archive
  = pieces(Get(in_pieces(limit, STALL 60 s))), head status 200/404/other, forwarding task into mpsc(PIECES_WAITING 4).
  POLAR_REGISTRY_NIX_MAX_ARCHIVE default now 4 GiB (mine, for review; bounds the volume a fault fills, not memory),
  only ≥ 1 checked. EVIDENCE (release, #[ignore] test): 320 MiB incompressible archive (> MAX_BODY) faulted through the
  real handler, process peak RSS (VmHWM) 20 MiB before → 25 MiB after (36 MiB on a rerun after the forwarder change); 2 handler records.
  Checks: builder suite 689 pass; workspace `cargo check --all-targets` clean; builder mutants (in place: its tests
  read ../../../../infra/seeds, outside the copy cargo-mutants makes) on in_pieces/pieces/next: 18, 12 caught, 6
  unviable; registry mutants on faults/upstream/settings: 2 missed → PieceReader small-buffer test added, the
  forwarder's redundant `|| failed` removed (a failure is always last); recheck 22: 18 caught, 2 timeouts, 2 unviable.
- NC4 host mode.
- NC5 catalog workload (ns polar-registry), PVC, key, settings, builds' policy port, u7c.

## OPEN
- Key custody (memory credentials-agent-certifies-workload-keys): Nix keys are raw ed25519, not X.509 — how the
  credentials agent "certifies" one is undefined. First: key on the volume, public key published via signed config.
- polar-ci's Nix in a build pod: separate feature.
