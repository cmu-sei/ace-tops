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

# F1 verified-before-applied — Claude's side

PAIR: `verified-before-applied.md` (people). Same plan, two forms; change together.
SPLIT: people side has no dates, attributions, quotes, codenames or branch/process status; those live here.
PARENT: `../deployer.claude.md` (F1). AS-OF main 1dd68a49, 2026-11-12. Re-verify lines.
STATUS: proposal; nothing built; first feature; shadow-mode first.

## INVARIANT (what "verified" means; all required, refuse whole)
V1 sig: verify_commit(raw, deploy_trust, "pipeline", t) ok.
V2 tree: commit msg trailer `Provenance-Sha256: <hex>` == sha256(provenance.json); every applied file listed with
   matching sha256; unlisted file ⇒ refuse.
V3 forward: head descends from applied ⇒ else Rewound (refuse, report, keep applied).
V4 walk: every commit applied..head verified (not head only; publish signs atop whatever server holds,
   deploy-repo.nu publish).
V5 cluster: provenance.target == own; cluster_inputs.cluster_ca_sha256 (if present) == sha256(own polar-ca).
V6 time: head new to cluster at wall clock; walk + applied at own signing time (CMS signingTime if gpgsm writes it,
   unchecked; else committer date).
V7 one parse: verify_commit returns VerifiedCommit{tree,parents,committer_time,signing_time,message} from verified
   bytes; refuse dup `tree`/malformed header.
V8 refusal monotone: no prune/recreate/restart; report commit, reason, lag.

## FACTS@main
- verify_commit sig polar-signing/src/commit.rs:86-91 → SignerInfo; checks digest(:98-101), chain at now (:114,
  :422-441), CN==signer (:116-127), KU digitalSignature if present (:128-132), P-256 only (:133-137), ECDSA
  (:139-145). NO EKU check. Tests: polar-signing/tests/commit_signature.rs (single-bit flips).
- push check: polar-git-server/server/src/signed.rs check_push :101-113 (new commits + ref heads), checked_at
  :188-193 (head now, older committer time); called http.rs:255-260; opt-in signed_by git-server.nuon:52.
- operator verify once: infra/flux.nu fetch_verified :285-299, install :312-316 (gpgsm).
- Flux GitRepository: no verify (infra/deploy-objects.nu:148-178).
- provenance.json: deploy-repo.nu:449-451 (per-file sha256), :463-475 (cluster_inputs incl cluster_ca_sha256),
  :606-616 (target, deployment_ca_sha256, signer). schema 1. commit msg :654 (no trailer).
- pipeline cert: P-256 (deploy-repo.nu:193), EKU clientAuth only (:86-92,:181-184), 365d (:232); ca.key beside it
  (:74-76,:209-232); no expiry warning (remaining-work.md:1273).
- Cassini read: polar-git-server common lib.rs ReadMain{repo,paths,have} :71-75 → MainRead::{Files{commit,files},
  Unchanged,NoMain,Refused,NotNow} :96-108. NO raw commits, NO history ⇒ GAP G3.
- rule: agents reach Polar services via Cassini only (maintainer 2026-11-09). Text missing from main git-server.md
  (see ../deployer.claude.md DOC DRIFT).

## GAPS (build order)
G1 publish writes trailer (deploy-repo.nu commit msg :654) + tests (infra/tests/deploy-repo.nu).
G2 VerifiedCommit from verify_commit (+ round-trip, malformed-refusal properties; no second parser anywhere).
G3 git server read over Cassini: raw signed commits from `have` to head + head files (new request type beside
   ReadMain; reply topic per reader; size bound = Cassini payload; page if needed).
G4 verifier pure core (deployer/common): V1-V8; props: any byte change refused; never non-descendant regardless of
   read order; other target refused; parse==verified.
G5 shadow wiring: verdict per commit reported over Cassini beside Flux's applied revision.
G6 later: signing EKU on pipeline cert (documentSigning or own) + verifier checks it; expiry warning.

## ALTERNATIVES rejected
push-check only (server trusted) | Flux spec.verify (no x509) | head-only (unsigned parent hole) | recompute SHA-1
trees (weak, no gain) | direct git/mTLS read (breaks Cassini rule, needs credential) | gateway = same feature, other
consumer → decided at capability level.

## MET WHEN
every commit a cluster applies passed V1-V8 at apply time ⇒ needs gateway or takeover (capability Q1).

## OPEN
- trailer name/format final? (proposal: `Provenance-Sha256: <hex>`).
- G3 shape: reuse ReadMain with a flag vs new request; history depth bound.
- V6: does gpgsm write CMS signingTime? unchecked.
- record (attestation) verified at now ⇒ expired pipeline cert stops new records (inferred) — same expiry gap as G6.
