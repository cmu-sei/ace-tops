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
  age; brotli is the fallback. Encoding level for plain inputs: 9 by default (measured), a setting.
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
- NC2 CAS + Nix face server (hyper-util, plain http read), Polar sig; test: `nix copy --from http://127.0.0.1:P
  --to <tmp store>` with trusted-public-keys = Polar's.
- NC3 faults from a binary cache (test upstream = a second instance / static dir made by `nix copy --to file://`),
  switch off; network-gated test vs cache.nixos.org.
- NC4 host mode.
- NC5 catalog workload (ns polar-registry), PVC, key, settings, builds' policy port, u7c.

## OPEN
- Key custody (memory credentials-agent-certifies-workload-keys): Nix keys are raw ed25519, not X.509 — how the
  credentials agent "certifies" one is undefined. First: key on the volume, public key published via signed config.
- polar-ci's Nix in a build pod: separate feature.
