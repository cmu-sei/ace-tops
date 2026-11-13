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
  FileSize of the stored file; served as stored, never recompressed per read. Upstream faults: decompress whatever
  upstream sent (xz/zstd/bzip2/none), recompress zstd. zstd level, and whether other faces' blobs (OCI layers are
  already gzip/zstd) are stored as-is: decide in NC2 / the images feature.
- zstd library: DECIDED 2026-11-12, maintainer: "not a fan of adding a C library. We did it for the allocator because
  there's not any real option to it" → `ruzstd` (pure Rust, MIT, 0.9.1 of 2026-10-11). Rejected: `zstd` 0.14 (C
  libzstd 1.5.7 via zstd-sys; would have built with workspace.nix's static musl CC). ruzstd 0.9.1: decoder complete
  (1.4-3.5x slower than C, its README); encoder only Uncompressed and Fastest (~level 1; Default/Better/Best
  UNIMPLEMENTED per docs.rs). So: an upstream's zstd bytes are stored AS RECEIVED (decoded once to check NarHash,
  never re-encoded); only plain (or xz) upstreams are encoded, at Fastest. cache.nixos.org now serves zstd (sampled
  2026-11-12: nix-2.34.8 4113736 → 1240540, glibc-2.44-25 35578272 → 10427318, both `.nar.zst`), so most content is
  never encoded here. xz (older cache paths): pure-Rust `lzma-rs` (MIT, last release 2023-01) when the first xz path
  faults; refuse with a clear reason until then.
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
