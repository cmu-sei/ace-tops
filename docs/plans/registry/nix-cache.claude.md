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
- CAS: blobs/<sha256 hex>, temp file + fsync + rename, hash checked while writing; NAR uncompressed so blob digest ==
  NarHash; narinfo URL `nar/<nix32 narhash>.nar`, Compression none, FileHash = NarHash, FileSize = NarSize.
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
