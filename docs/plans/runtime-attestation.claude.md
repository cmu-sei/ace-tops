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

# runtime-attestation — Claude's side

PAIR: `runtime-attestation.md` (people). Same plan, two forms; change together.
SPLIT: people side has no dates, attributions, quotes, codenames or branch/process status; those live here.
LEVEL: capability. Features: `runtime-attestation/<feature>.{md,claude.md}`. Design history:
`docs/architecture/runtime-attestation.md` (main 512 lines; agentic-control-plane 879 lines — branch holds the C2/C3
text, lines 1–424 identical in both).
AS-OF: main 355a8a22 (2026-11-12). Re-verify lines. OWNER: this session (slice C end to end; works on MAIN).
ORDER: main's order of work step 8 (remaining-work.md:32-102); step 10 lifecycle follows ("After slice C, sure").

## INTENT
each pod holding a Polar cert is the pod signed for: signed image, run as the signed record says, unaltered.
threat = foothold (not exfiltration first): make hard, DETECT (crash by signal = gold), operate through, shut down at
own choosing. Trust base: k8s control plane, cert-issuer CA key, signed deployment, attestation agent, node sensor.

## FOUND (people part 2, dated)
- design work 2026-10-26 onward (arch runtime-attestation.md).
- cert path: token proves whose workload, not which pod.
- 2026-11-10 pods inspected: none read-only/seccomp, agent checked none → C1.
- 2026-11-08 build-orchestrator review: build pod reaches everything.

## NAMES (people side → id)
Judging each pod=A, Watching=B, Hardening held to the record=C1, No agent runs git…=C2, Each agent locks itself=C3,
Network enforcement=C4-net (+N1,N2), The node sensor=C4-sensor, Sessions bound to the pod's address=C5.

## DECISIONS (maintainer, dated; arch doc line = both versions unless marked)
- 2026-10-26 sensor read-only on every node; separate identity from attestation agent (:58-68).
- 2026-10-28 address check: not Polar's to defend (token in trust base).
- 2026-11-02 attestation agent pool: core (main:494-497).
- 2026-11-03 slice B report only, acts on nothing (:376).
- 2026-11-10 no code hash: sensor uid 1000, no caps, reads /proc/<pid>/status+maps; /proc/<pid>/mem needs
  CAP_SYS_PTRACE, separate later decision (:390-394).
- 2026-11-10 no runtime challenges (:397-399).
- 2026-11-10 Canal with the sensor, both node work in nix-usernetes; N1/N2 follow (:402-404).
- 2026-11-10 C5: address written into cert at issuance; Cassini refuses other source (:400-401).
- fallback policy: run, report, signed policy may require (:406-410); per-feature fallback table (:412-420).
- 2026-11-11 C4 kept as planned vs Landlock port rules (ports not destinations) (main:469-473).
- 2026-11-11 no more dependence on k8s: lock knows nothing of how k8s delivers a file (branch:533-534).

## FEATURES
| id | feature | status | where |
|---|---|---|---|
| A | agent answers; signed record; askers refuse | done | arch doc slices A |
| B | watching: altered pods, crashes; report only | done | arch doc slice B |
| C1 | hardening held to record (schema 3) | done, live 2026-11-10 | main:425-441 |
| C2 | git in process (gix-serve), reads over Cassini (O1/O2), up.nu copy (O3), egress probe (O4) | on main 2026-11-12 (port); live only from branch | branch:434-492; main commits 19af7c43..8c0aed07 |
| C3a | seccomp lock at start | on main; live from branch 2026-11-11 | main:443-464 |
| C3b | Landlock, files by build's declarations | on main; live from branch | branch:527-728; main 821c6d1c.. |
| C4-net | network enforcement + N1 builds policy + N2 canary | PLANNED | runtime-attestation/network-enforcement.{md,claude.md} |
| C4-sensor | node sensor DaemonSet (new catalog kind) | outline | :156-163, :418, open :503-505 |
| C5 | session bound to pod address via cert | outline | :400-401, :420; open main:510 |

## FACTS@main
- no `attestation/sensor` crate; catalog kinds agent/run/ca/service/template, no DaemonSet kind
  (infra/config/workloads/*.nuon); DaemonSet only read in render.nu:343, rules.nu:162, deploy-objects.nu:106.
- Polar renders no NetworkPolicy for polar/polar-graph/polar-auth/polar-builds; only agent-pods.nu:80-87 deny-all in
  throwaway check namespace; Flux's 3 stock policies in flux-controllers.yaml:39-96.
- dev clusters enforce no NetworkPolicy (see feature doc FACTS).

## DOC DRIFT (fix when reached)
- arch runtime-attestation.md on main lacks C2/C3 text (branch has it); main says C1 seen live, branch says not yet.
- cert-issuer-isolation.md:91 "No NetworkPolicy anywhere in the repository" (stale: agent-pods.nu, flux);
  :94-102 stale vs nix-usernetes (k8s 1.33→1.37.1, single node→u7c multi-node, ptp ipMasq→false, flannel not in devShell).
- see ../deployer.claude.md DOC DRIFT for git-server.md "Inside the boundary" missing etc.

## OPEN (beyond features)
- sensor pod spec beyond hostPID (main:503-505).
- /proc/<pid>/mem (CAP_SYS_PTRACE) — later decision.
- Landlock denial audit readable by sensor under rootless? (branch:621-623).
