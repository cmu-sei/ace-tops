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

# record-store — Claude's side

PAIR: `record-store.md` (people). Same plan, two forms; change together.
SPLIT: people side has no dates, attributions, quotes, codenames or branch/process status; those live here.
LEVEL: capability. Features: `record-store/<feature>.{md,claude.md}`.
AS-OF: main b998a245 (K3b) 2026-11-13; acp agentic-control-plane (merge base a4c1c984). Re-verify `file:line`.
DESIGN: docs/architecture/record-store.md (on main, ~76 lines behind acp's; acp's is current: bites 1–6, L1–L2, witness).
OWNER: polar-cc (acp) designs/prepares; polar-89 (main) takes onto main and deploys u7c.

## DECISIONS (maintainer, dated)
- 2026-11-10 decisions 1–11 (record-store.md "Decided"): store replaces git, presents as git (degraded, deploy-time),
  CBOR entries, P-256 checkpoint key certified by credentials agent (2026-11-11), witness = attestation agent, readers
  require co-signature (2026-11-11), polar-git-server becomes the store (acp ownership), ledger stays agent's own file.
- 2026-11-11 revised: source code → `polar-git` (separate service, direct connections, Cedar per op); store takes no
  direct connections at nominal; people's tools over Cassini ("We can adjust our own tools").
- 2026-11-12 "record-store.md stays on your branch for now" — SUPERSEDED 2026-11-13.
- 2026-11-13 "Bring the store to main" (AskUserQuestion, recommended option): the store's runtime is shared infra →
  coordinated port to main, then acp merges main. Trigger: acp seed.nu `witness_pins` writes 4 settings
  (POLAR_GIT_SERVER_WITNESS_KEY; POLAR_ATTESTATION_WITNESSED_STORE; POLAR_SCHEDULER_STORE_KEY,
  POLAR_SCHEDULER_WITNESS_KEY) into 3 agents' permanent/<agent>/configuration.dhall on u7c; main declares none, so
  polar-git-server, attestation-agent, polar-scheduler-observer refuse their v1 update ("not declared by any registered
  section"); main loses no setting (main writes none for them), error repeats per delivery (polar-89 checked u7c, main).

## FEATURES
| feature | where | status |
|---|---|---|
| polar-log format crate | main (src/agents/polar-log) | on main |
| ledger L1–L2 (CBOR events, signed checkpoints, checkpoint cert) | main 130fe680, 2e06f8f7, 402e7958… | on main |
| store to main | record-store/to-main.* | PROPOSED 2026-11-13, not cleared |
| deployment log (bite 7) | — | waits for deployer |
| repos moved in, git off (bites 8–9) | — | not started |
| ledger checkpoints into store (bite 10 / L3) | record-store.md "plan for L3" | planned on acp |
| large records as blobs | polar-eden follow-up (237 KB run record > MAX_ENTRY 65,535) | not written |

- 2026-11-13 (maintainer, via coordinator): polar-git + git-remote-polar move to main (bite B5); intents and
  polar-eden stay on acp; checkpoint key "a file now, custody later" (named escrowed custody key when trusted-remotes
  step 3 lands); polar-89's 3 conditions (base ≥ 7e43bb92; every key use via CryptoActor; per-bite state).

## OPEN
- record-store.md: move acp's current text to main with bite 1 (main's copy is stale).
