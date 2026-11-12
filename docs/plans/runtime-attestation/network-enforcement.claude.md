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

# C4-net network-enforcement — Claude's side

PAIR: `network-enforcement.md` (people). Same plan, two forms; change together.
SPLIT: people side has no dates, attributions, quotes, codenames or branch/process status; those live here.
PARENT: `../runtime-attestation.claude.md` (C4-net). Old names: C4 Canal, N1 policy, N2 canary, N3 engine
(build-orchestrator.md:963-992). AS-OF main 355a8a22 + nix-usernetes 10f3bcd (2026-11-02). Re-verify lines.
STATUS: planned; nothing built; Q-flannel DECIDED 2026-11-12 (Calico policy-only first). u7c busy (branch proof).

## FOUND (people part 2, dated)
- 2026-11-08 orchestrator review, verbatim: "No NetworkPolicy covers `polar-builds`, and u7c's network plugin enforces
  none" (build-orchestrator.md:725).
- 2026-10-13 cert-issuer isolation: dev cluster enforces nothing; maintainer: run on fallback, engine later.
- 2026-11-12 nix-usernetes read (FACTS below).
People side: Canal = "the engine chosen", terms = "unprivileged, on nftables, without IPv6" (unattributed there).

## INVARIANT
build pod (polar-builds): ingress none; egress only registry pods:port; no DNS (hostAliases from orchestrator).
enforcement PROVED by canary (orchestrator-run, under builds' own policy): reach registry ✓, API svc addr ✗, outside ✗;
at orchestrator start + before admit if proof older than Dynamic bound; unproved ⇒ build refused w/ reason; publish.
standard networking.k8s.io/v1 NetworkPolicy only (portable: Calico, Cilium, cloud, kube-router/k3s, RKE2 Canal).
until proved: no mapping names a repo Polar doesn't control; no registry archive built (build-orchestrator.md:986-989).

## DECISIONS
- 2026-10-13 dev cluster runs on no-enforcement fallback; engine later (cert-issuer-isolation.md:847-849,:863).
- 2026-11-08 "A policy engine on u7c is the maintainer's to approve" (build-orchestrator.md:732).
- 2026-11-09 Canal on u7c: "I want it to work unprivileged, using nftables, and no requirement for ipv6"
  (build-orchestrator.md:963-964). Canal = Flannel VXLAN + Calico nftables dataplane (nftablesMode: Enabled, GA 3.31),
  IPv4 only (Felix IPv6 off), kube-proxy nftables as is (:979-985). Deferred same day for Vaughn's port (:986).
- 2026-11-10 Canal with the sensor, node work in nix-usernetes (runtime-attestation.md:402-404).
- 2026-11-11 kept as planned vs Landlock port rules (runtime-attestation.md main:469-473).
- N1 revision: orchestrator resolves registry name itself → hostAliases, not fixed cluster IP (build-orchestrator.md:989-992).
- N2 differs from cert-issuer-isolation layer-4 canary (installer-run, :213-217): orchestrator-run, "Polar's own checks
  are the guard".

## FACTS (nix-usernetes, read 2026-11-12, no cluster touched)
- CNI conflist template flake.nix:485-514: ptp (ipMasq:false) + host-local (@POD_CIDR@) + tuning (arp) + portmap
  (nftables backend). Rendered at boot flake.nix:806-807. Plugins pkgs.cni-plugins (~1.9.1 inferred), cniVersion 1.0.0.
- k8s 1.37.1 (flake.nix:31); kube-proxy --proxy-mode=nftables (:335); pod masquerade nft table ip u7s-masquerade
  (:454-461). No iptables path (xt_* missing; kernel w/o IPv6: no `inet` family) flake.nix:440-447.
- NO policy engine anywhere (grep canal|calico|kube-router|cilium|kube-network-policies|vxlan: none). API accepts
  NetworkPolicy, admission only NodeRestriction (flake.nix:254).
- u7c: cluster.dhall:419-435; 5 containers (cp no kubelet + core/observers/writers tainted + services); bridge br0
  10.77.0.1/24 in hub, nodes 10.77.0.(11+i), pod CIDR 10.244.i.0/24, static routes to other nodes' CIDRs
  (cluster.sh:94-123). NO overlay, NO VXLAN. All inside podman unshare. One host kernel (whitey 7.3, no IPv6, xt
  limited to addrtype/conntrack/mark/policy/state; commit 561a5ee).
- u7s: single node, slirp4netns (Justfile:50-53).
- flannel only in an inherit list (flake.nix:69), unused; upstream flannel removed (commit 51976ce).
- modules: host /lib/modules mounted ro (cluster.sh:175 workers); only `modprobe overlay`. vxlan not loaded anywhere.

## FACTS@main (Polar)
- no NetworkPolicy rendered for polar/polar-graph/polar-auth/polar-builds; agent-pods.nu:80-87 deny-all in throwaway
  ns (unenforced); flux stock policies flux-controllers.yaml:39-96.
- builds: polar-builds (cluster.nuon:35-36); PSA warn/audit restricted, enforce none (:43-44; build-orchestrator.md:83-89);
  build pods hold no identity (build-orchestrator.md:200-202); build workload in observers pool (:420-422).
- egress probe = reachability of the way out, not denial (egress.md:121-146).

## GAPS (build order)
G0 done (Q-flannel). G1 spike in nix-usernetes (rootless; modules needed; nftables only; IPv4). G2 enforcement on u7c
(nix-usernetes change; Polar pods unchanged). G3 N1 render (catalog → policy for polar-builds; hostAliases in orchestrator
Jobs). G4 N2 canary in orchestrator (probe mode of fetch image; Dynamic staleness bound; publish result). G5 admission
refuses build when unproved. G6 C5 precondition: pod src addr unchanged to Cassini under the engine. LATER: sensor
egress → Cassini only; cert-issuer layer 4 (cert-issuer-isolation.md:206-218).

## Q-flannel — DECIDED (maintainer, 2026-11-12): "Calico alone first"
spike = Calico policy-only (Felix over u7c's existing ptp + static routes; no Flannel, no vxlan). Canal = fallback.
Canal-vs-Landlock untouched (11-11). Spike must run on whitey's kernel (u7c's host; 7.3, no IPv6) — the `inet` question
is kernel-specific; a throwaway nix-usernetes cluster there, not u7c, avoids the shared cluster.

## ALTERNATIVES
Landlock ports (rejected 11-11) | no enforcement + refuse foreign builds (= fallback now) | kube-router policy-only |
kube-network-policies (nftables) | full Canal from the start (= fallback). Calico policy-only = the plan's first try
(Q-flannel), no longer listed as an alternative on the people side.

## NOT CHECKED
whether Calico/Felix runs in a user namespace (spike); Felix nftables on a kernel without `inet` family (IPv6 absent) —
risk: Felix nftables may need inet tables → MUST check in spike; Flannel nftables mode experimental; C5 under engine.
