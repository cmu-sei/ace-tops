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

# to-main — Claude's side

PAIR: `to-main.md` (people). Same plan, two forms; change together.
SPLIT: people side has no dates, attributions, quotes, codenames or branch/process status; those live here.
PARENT: `../record-store.claude.md`. Branch store-to-main (from ace-remote/main b998a245); taken by polar-89.
STATUS: PROPOSAL 2026-11-13, not cleared. Decision behind it: maintainer "Bring the store to main" (2026-11-13).
FLOW per bite: polar-cc prepares on a branch from main (tests pass there, capped: systemd-run MemoryMax=24G) →
polar-89 takes onto main → deploys u7c (up.nu sandbox-local --dev, no --under-test gitlab) → next bite.

## ACP CODE SINCE MERGE BASE a4c1c984 (git diff --shortstat)
- polar-git-server: 20 files, +6967/−92. New on acp: server/src/{logs,log_read,reply,evidence,schedules,witness}.rs;
  plus settings/supervisor/agent/lib changes, common request types. Main has none of the six files.
- attestation: 13 files, +2788/−41: agent/src/{witness.rs 1211, evidence.rs 536}, supervisor +538, settings;
  common/src/{witness.rs 235, report.rs, record.rs, proof.rs}.
- polar-scheduler: 15 files, +2145/−263: observer sync_actor/reads/settings/supervisor/agent, common running.rs;
  plus 3 .elide.dhall (STAY on acp).
- polar-records-client: +533 (new crate). git-remote-polar: +642 (new crate; belongs with polar-git).
- infra/seed.nu +54 (witness_pins :355-382, settings_path, key_in_logs); infra/up.nu +49/−2.
- polar-log: no diff (main = acp). Evidence catch-up 7f02484c is acp-only (not in main).
- builder person floor (floor.rs) for store topics: acp (check exact commits at bite 4).
- Total ≈ 15k lines incl. tests (69 files counting polar-git, which stays).

## ALREADY ON MAIN (don't re-port)
polar-log; ledger L1/L2 (130fe680, 2e06f8f7, b57f7c0f, 402e7958); bite S + K1 (record signer in CryptoActor,
9a2cc593); K2 (5594e2a9); K3a TlsHandle (d7654f65); K3b git server over CryptoActor TLS (b998a245);
policy schema context.addressed + Repository + git-* actions (2cc50d72).

## BITES (dependency order)
B1 logs + log reads over Cassini + evidence intake appends + catch-up at start (7f02484c) + attestation evidence.rs
   (verdicts as records) + record-store.md brought current on main. Open logs as found on polar-git-server-data PVC
   (u7c UID 50bb1772 as of 11-12): never re-init; catch-up appended 44 missing records live 2026-11-12.
B2 witness: attestation witness.rs/common witness.rs + git-server witness.rs + seed pins for git-server & attestation.
B3 schedules on log: git-server schedules.rs + scheduler observer (reads log, both keys pinned) + seed pins for
   observer. Ends the 4 refused updates.
B4 people's tools: person floor (builder floor.rs), polar-records-client, polar-sign over Cassini (no --repo).
   polar-eden fetch-log/collect --push stay on acp (polar-eden stays).

## RULES APPLIED
- K3: ported code takes TLS from TlsHandle / CryptoActor; no own rustls config; custody only via CryptoActor.
- main-and-acp-stay-compatible: same kind+version = same bytes; u7c state carries over unwiped.
- custody scope (maintainer 2026-11-13): keyring-like; checkpoint key placement is an OPEN decision (file on volume
  today: settings.rs:48 "the directory the store's signed logs and its checkpoint key live in").

## STAYS ON ACP (user to confirm)
.elide.dhall intents; polar-eden; polar-git (source server, direct connections) + git-remote-polar.

## RISKS
size (~15k lines; each bite reviewed alone); record-store.md on main stale (acp +76 lines); u7c evidence log (44+
records caught up 2026-11-12) and schedules log must survive; acp tests that assume acp-only crates must be split out.

## OPEN (before B1)
1. confirm what stays on acp. 2. checkpoint key: volume file vs custody named key (crypto-actor rules).
