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
STATUS: u7c ENFORCES (nix-usernetes main 8ef1747, 2026-11-12); Polar side (N1/N2) not built. Spike done 2026-11-12 on u7n: Calico can't run on whitey. Q-engine DECIDED 2026-11-12:
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
G0 done (Q-flannel, spike, Q-engine). G1 kube-nftpolicy built + live on u7n (done); upstream e2e netpol suite (todo).
G2 DONE: nix-usernetes main 8ef1747 pushed; u7c rebuilt and enforcing. G3 N1 render (catalog → policy for polar-builds; hostAliases in
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

## ENFORCER = kube-nftpolicy — DECIDED (maintainer, 2026-11-12, after my Polar-agent design)
"its own project on my public github site; builds from a nix flake; applies cleanly as part of u7's own image build,
as specified by its own nix flake; an independent piece of infrastructure Polar can offer others". Name kube-nftpolicy
(my recommendation), license Apache-2.0 (maintainer's pick over MIT OR Apache-2.0).
SUPERSEDED: enforcer as Polar agent/DaemonSet catalog kind/Cassini reporting/attested (my first design). Not a Polar
agent: no Polar identity, no Cassini, not attested — node infra in the trust base, like kube-proxy; canary is Polar's check.
- repo: ~/Documents/projects/kube-nftpolicy, github daveman1010221/kube-nftpolicy (public; created 2026-11-12).
  commits ebd5811 (feat, all of it), 1d04a64 (share/kube-nftpolicy/{rbac,daemonset}.yaml in package), 6539cdf (fix:
  startup isolation via --pod-cidr/POD_CIDR or Node spec.podCIDRs [rbac: nodes get]; sets pod_ranges+known_pods, forward/
  input drop unknown in range; --remove deletes the table; README Uninstalling).
- FOUND 2026-11-12 on u7n (deny-all ns): new pod's connection at +0s went out; isolated by +1s. K8s docs: a pod an
  already-handled policy selects must be isolated before it starts → conformance bug, fixed in 6539cdf; retested:
  deny-all new pod BLOCKED from +0s; unpoliced new pod OK at +0s (first SYN dropped, retransmit passes).
- Table outlives the process by design (crash/upgrade stays enforcing). Uninstall = --remove. On u7 nodes,
  cluster.sh down removes the node netns, so the table goes with it.
- crate (edition 2024, kube 3.1 rustls+ring, k8s-openapi 0.27 v1_35): model, selector, ranges (ipBlock−except),
  compile (Ruleset: isolated sets + Allow{local,peer Range,Ports}), disjoint (non-overlapping elements: pipapo
  concat sets), nft (script: add/delete/define table ip kube_nftpolicy; chains forward+input → egress/ingress, ct
  established,related accept, counter drop), spec (oracle), kube (conversion; never widens: unreadable ports/peers →
  rule dropped), run (reflectors, settle 200ms, apply via `nft -f -`, MAX_FAILURES 5 → exit), main (--node-name/NODE_NAME,
  --kubeconfig, --table, --nft, --once, --print). Warns on IPv6 pod IPs (dual-stack not enforced).
- tests: 22 unit; props (2000 cases): nodes' rules AND == spec::allows; order independence; block ranges; disjoint
  cover+no overlap. Mutations (ignore except; ignore egress) caught. kernel.rs: unshare -rn nft -f, whitey kernel OK
  (pipapo concat interval sets fine without ip6/inet).
- flake: rustPlatform.buildRustPackage, wrapProgram PATH nftables; packages default/image (buildLayeredImage); checks.
- nix-usernetes main 8ef1747 (pushed; was branch feat/kube-nftpolicy 91bafdc + 8ef1747 pod-cidr): flake input
  (follows nixpkgs/flake-utils); u7s-kube-nftpolicy wrapper (kube-nftpolicy.conf else admin.conf; NODE_NAME else
  /etc/hostname); podScripts; service kubeNftpolicy in node-common.dhall, worker.dhall, node.dhall (after kube-apiserver);
  rbac.yaml copied to /var/lib/cluster-bootstrap (runsControlPlane); cluster.sh nftpolicy_credentials (CN
  system:kube-nftpolicy, pki/nodes/<w>/kube-nftpolicy.*; idempotent, also for already-joined workers); cmd_up hint.
  `just render` done. Test images localhost/nix-usernetes-{worker,control-plane}:nftpolicy-test (1.37.1 tags untouched;
  retag via skopeo docker-archive→docker-archive:<path>:<ref>, then podman load).
- LIVE (u7n, 2026-11-12): DaemonSet and node-service runs both: build pod (builds ns, node a) → registry (reg, node b,
  named port http 5000) OK, near (reg, node a) OK, other (reg) BLOCKED, API 10.96.0.1:443 BLOCKED, 1.1.1.1:443
  BLOCKED, ingress to build BLOCKED, other→registry OK; policy removed → all OK. (agnhost 2.53 netexec/connect;
  scenario files were in session scratchpad, now deleted: namespaces builds/reg, pods registry/near/other/build,
  policy builds = podSelector {} Ingress+Egress, egress to ns reg app=registry port named http.)
- u7c (2026-11-12 ~21:27Z): :1.37.1 rebuilt (old kept :pre-nftpolicy, IDs 56244774f769 cp, f4cdcd1ede0a worker);
  cluster.sh down/up/init issued kube-nftpolicy creds to joined workers. All pods Running (each container restarted
  once); Flux Ready (polar-deploy one fetch refused while git server started). Probe from another ns (pod deleted):
  source-controller :8080 OK, :9090 BLOCKED, polar-git-server OK, internet OK.
- u7n torn down (reset; netns dir gone); test images, dangling first loads and scratchpad spike dir removed (the last
  two by the user; my rmi/rm was classifier-blocked). Kept: :pre-nftpolicy rollback images until the user says.
DONE u7c step (checked on u7n first: Flux fetch+apply under its policies; check pods in deny-all ns). Upstream e2e
netpol suite not yet run. Polar-side "offer" = target
choice deploying the DaemonSet (not designed).

## ALTERNATIVES
Calico/Canal (spike: v6 table) | patch Felix (not chosen) | kernel w/ IPv6 (rejected: host change, gives up no-IPv6) |
kube-network-policies (inet) | kube-router (xt) | Cilium (eBPF) | Landlock ports (rejected 11-11) |
enforcer as Polar agent (my first design; superseded by own project) | no enforcement + refuse foreign builds
(= fallback now).

## NOT CHECKED
pod→own-node traffic path under ptp (input hook vs forward) for the enforcer; hostNetwork pods (exempt by standard);
NET_ADMIN in node userns enough for nft netlink (kube-proxy does it → expected yes); rustables maturity.
