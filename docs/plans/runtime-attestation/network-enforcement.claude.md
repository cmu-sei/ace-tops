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
STATUS: planned; nothing built. Spike done 2026-11-12 on u7n: Calico can't run on whitey. Q-engine DECIDED 2026-11-12:
Polar's own enforcer (maintainer picked it over patch-Felix, my recommendation, and kernel-with-IPv6).

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
G0 done (Q-flannel, spike, Q-engine). G1 enforcer: crate, DaemonSet catalog kind, rules vs upstream tests, on u7n first.
G2 enforcer on u7c (no nix-usernetes change). G3 N1 render (catalog → policy for polar-builds; hostAliases in
orchestrator Jobs). G4 N2 canary in orchestrator (probe mode of fetch image; Dynamic staleness bound; publish result).
G5 admission refuses build when unproved. G6 C5 precondition: pod src addr unchanged to Cassini (enforcer no NAT).
LATER: sensor egress → Cassini only; cert-issuer layer 4 (cert-issuer-isolation.md:206-218).

## Q-flannel — DECIDED 2026-11-12 "Calico alone first" → spike run, superseded by Q-engine

## SPIKE (2026-11-12, throwaway cluster u7n on whitey; topology + manifests in session scratchpad, not in any repo)
- u7n = cluster.sh with TOPOLOGY=<scratch>/u7n.dhall: name u7n, apiserverPort 7444, cp + workers a, b (no taints).
  Own hub/bridge/netns (all per-cluster: hub netns holds br0 10.77.0.0/24; netns dir $XDG_RUNTIME_DIR/nix-usernetes/u7n).
  Nodes have NO spec.podCIDR (controller-manager allocates none) → host-local usePodCidr impossible.
- Calico v3.33.0 calico.yaml, policy-only edits: calico_backend none; CLUSTER_TYPE k8s; IPIP Never; NO_DEFAULT_POOLS;
  FELIX_NFTABLESMODE=Enabled; bird probes dropped; portmap backend nftables; per-node IPPools (crd v1) 10.244.{1,2}.0/24
  nodeSelector hostname, blockSize 26 (matches cluster.sh static routes).
- rootless results: install-cni OK (writes /opt/cni/bin, 10-calico.conflist sorts before 10-u7s.conflist → wins).
  ebpf-bootstrap init FAILS ("/sys/fs is mounted on /sys but it is not a shared mount") → removed (eBPF only).
  /sys/kernel/security mount FAILS (mkdir permission denied) → removed; bpffs mount removed.
- Felix: creates v4 table OK, then PANIC felix/nftables/table.go:515 "Failed to create knftables client ... Operation
  not supported": int_dataplane.go:1002 `nftables.NewTable("calico", 6, ..., nftablesEnabled)` — v6 root table
  REQUIRED whenever nftables mode is on, regardless of IPv6Enabled (same in v3.31.0:836, v3.32.0:857). Patch would be:
  required=nftablesEnabled&&IPv6Enabled + guard filterTableV6 uses (:1006, :1158, :1611).
- node probe (`nft -c`): ip ✓, arp ✓, ip6 ✗, inet ✗ (EOPNOTSUPP).
- kube-network-policies v1.1.3: pkg/dataplane/controller.go:568 TableFamilyINet (+ nfqueue) ✗. kube-router: iptables
  + ipset ✗ (xt_* missing). Cilium: eBPF ✗ rootless.
- u7n left UP for enforcer dev (kubeconfig in scratchpad/spike/kubeconfig). Tear down: TOPOLOGY=<u7n.dhall>
  ./cluster.sh reset (nix develop, in nix-usernetes). Told polar-cc it exists.

## Q-engine — DECIDED (maintainer, 2026-11-12): "Polar's own enforcer"
options were: patch Felix (recommended), kernel with IPv6, own enforcer. Chosen: own enforcer.
stance (maintainer, same day): IPv6 has been half-adopted for two decades and may never be; no IPv6 dependency is a
design stance for Polar, not a workaround for whitey's kernel.
also attack surface: many serious upstream kernel vulns in recent years centre on poorly tested IPv6 code (maintainer).

## ENFORCER (my design, FOR REVIEW — decided by standing rules, not asked)
- agent crate (name TBD, likely attestation/enforcer or kubernetes/…); DaemonSet = new catalog kind (sensor needs it too).
- input: k8s API read-only watch NetworkPolicy+Pod+Namespace (rule: k8s is trust base; build pods aren't Polar agents,
  so Polar's own records can't name them). Policies come from the signed deployment via Flux anyway.
- semantics: full networking.k8s.io/v1 NetworkPolicy, IPv4: policyTypes, pod/ns selectors (matchLabels+Expressions),
  ipBlock+except, ports (numeric, named → per-pod containerPort, endPort), default allow for unselected pods.
  Check vs upstream e2e netpol suite (test/e2e/network/netpol) + proptests (decision follows rule for every input).
- dataplane: one `table ip polar-netpol` in node netns; hooks forward (+input/output for node-local?) at priority after
  kube-proxy DNAT (filter); ct state established,related accept; sets/vmaps per pod IP. No NAT, so C5 holds.
- runs hostNetwork, cap NET_ADMIN only, in signed record (hardening schema must allow a declared cap — builder computes
  facts from the build: capability declared by build, not hand). Landlock/seccomp lock: netlink sockets needed.
- library: pure-Rust netlink nftables (one static musl artifact; no nft binary, no libnftnl). Candidates: rustables
  0.9.0 (pure Rust), nftnl 0.9.4 (libnftnl C), nftables 0.6.3 (shells out to nft -j: ✗). Pick in build; dep needs reason.
- reports over Cassini (status, ruleset generation); fails loud not open.
- not deployed where the CNI enforces (cluster fact in catalog/target).
OPEN (for later, not blocking plan): enforcer's own pool/tolerations (every node incl. tainted pools); what the
  attestation agent's verdict says about hostNetwork+NET_ADMIN for this one workload (from signed record).

## ALTERNATIVES
Calico/Canal (spike: v6 table) | patch Felix (not chosen) | kernel w/ IPv6 (rejected: host change, gives up no-IPv6) |
kube-network-policies (inet) | kube-router (xt) | Cilium (eBPF) | Landlock ports (rejected 11-11) |
no enforcement + refuse foreign builds (= fallback now).

## NOT CHECKED
pod→own-node traffic path under ptp (input hook vs forward) for the enforcer; hostNetwork pods (exempt by standard);
NET_ADMIN in node userns enough for nft netlink (kube-proxy does it → expected yes); rustables maturity.
