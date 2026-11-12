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

# Network enforcement

> **This document has a twin.** [`network-enforcement.claude.md`](network-enforcement.claude.md) says the same thing,
> written for Claude. This one is written for people. They are two sides of one plan, and they are changed together.
>
> A **feature-level plan**, part of [runtime attestation](../runtime-attestation.md). It describes Polar's `main` as it
> is.

**Status: planned, not built.**

## 1. The need

A pod should reach only what its job needs, and the cluster, not the pod's own good behaviour, should be what stops
it. Polar must also **know** the cluster enforces this, rather than assume it.

The first and most pressing case is **builds of foreign code.** The build orchestrator runs other people's pipelines
in the `polar-builds` namespace. Such a pod holds no Polar credential, but today it can reach:

- the internet;
- Cassini, Neo4j and cert-issuer;
- the image registry, which takes a push from any pod without a login.

A build pod should reach the registry's port and nothing else.

The same enforcement then serves two later cases:

- **the node sensor**, whose traffic should be limited to Cassini;
- **cert-issuer**, whose isolation becomes formal with network policy.

## 2. How the need was found

- **Reviewing the build orchestrator** found the network open: no NetworkPolicy covers `polar-builds`, and u7c's
  network plugin enforces none (`build-orchestrator.md`).
- **Isolating cert-issuer** found that the development cluster enforces no NetworkPolicy. The Kubernetes API accepts a
  policy and nothing acts on it, so a policy alone proves nothing. The development cluster has run without enforcement
  since, with a policy engine to follow.
- **Reading the cluster's own configuration** (`nix-usernetes`) confirms it. Each node's pods use the plain
  reference plugins (`ptp`, `host-local`, `tuning`, `portmap`), which have no policy function, and nothing else
  enforces one. u7c's nodes reach each other's pods over a bridge with static routes, with no overlay network.

## 3. The plan

Four steps, each seen working before the next.

1. **A spike of the enforcement engine, rootless,** in `nix-usernetes`. The engine must work unprivileged, on
   nftables, and without IPv6. The engine chosen is **Canal**: Flannel for the pod network and Calico for policy, on
   Calico's nftables dataplane.

   **The spike tries Calico for policy alone first.** u7c already routes pod traffic between its nodes, so Calico can
   enforce policy over that routing, with no Flannel overlay and no `vxlan`
   module. Full Canal is the fallback if that fails. The spike answers what nobody has published:
   - whether it runs inside a user namespace at all;
   - which kernel modules the host must provide;
   - whether Calico's nftables dataplane needs nftables' `inet` table family. u7c's kernel has no IPv6, and so no
     `inet` family, which is already why one of the cluster's own plugins cannot use its nftables mode. If Calico
     needs it too, it cannot run on this kernel as it is.
2. **Enforcement on u7c,** as a change to `nix-usernetes`, with Polar's pods still running as before.
3. **The builds' policy,** rendered from the catalog for `polar-builds`:
   - no ingress;
   - egress only to the registry's pods, on its port;
   - no DNS, since a name server that forwards upstream is a way out. The orchestrator resolves the registry's name
     itself and gives the pod the address directly.
4. **A canary that proves enforcement.** The build orchestrator runs it in `polar-builds`, under the builds' own
   policy. It must reach the registry, and must **fail** to reach the Kubernetes API and an address outside the
   cluster. It runs when the orchestrator starts, and again before a build when the last proof is older than a set
   bound. Where enforcement is not proved, a build is refused with the reason, and the result is published.

Polar writes only **standard NetworkPolicy**, so the policies and the canary carry to any cluster whose network plugin
enforces them: Calico, Cilium, a cloud provider's, or k3s's. The engine on Polar's own clusters only has to make the
canary pass.

Until the canary passes, the rule already in force holds: **no build names a repository Polar does not control.**

## 4. Alternatives considered

1. **Landlock's port rules,** computed by the agent builder per agent, with no Kubernetes involved. Rejected: rules by
   port cannot say where traffic goes, only which ports.
2. **No enforcement, and refuse foreign builds.** That is today's position, and it stays the fallback wherever
   enforcement is not proved. But it leaves the build orchestrator unable to do its job.
3. **Another policy engine:** kube-router in policy-only mode, or `kube-network-policies` (the Kubernetes network
   group's small engine, which uses nftables). Both are candidates, untried.
4. **Full Canal from the start,** with Flannel's overlay. Kept as the fallback: u7c already routes pod traffic between
   its nodes, so on u7c the overlay would only add a moving part and a kernel module.

## 5. Why this plan

- **Calico is mature,** enforces standard NetworkPolicy, and its nftables dataplane fits a cluster that already runs
  without iptables.
- **Standard policy keeps Polar off any one engine,** so what is proved here carries to a customer's cluster.
- **The canary makes enforcement a fact Polar checks,** not a property of the cluster it assumes. That is the same rule
  as everywhere else in runtime attestation: Polar's own checks are the guard.
- **Running the canary in the orchestrator,** not once at install, means a cluster that stops enforcing is noticed
  before the next build, not never.

## 6. How much of the need is met now

None of it is enforced:

- **The clusters enforce no NetworkPolicy.**
- **Polar renders no policy for its own namespaces.** The one policy it does make is a deny-all for a throwaway
  namespace where it runs check pods, and that too goes unenforced.
- **The egress probe tests the other direction.** It checks that the way *out* works for an agent that needs it, so it
  proves nothing about denial.
- **What holds the line is a rule,** not enforcement: no build names a repository Polar does not control. A build is
  offline today only because Cargo has no reason to go out, not because anything stops it.

## 7. What is left before this is met

- **The spike, then enforcement on u7c.**
- **The builds' policy, and the canary,** in the orchestrator and the render.
- **Refusing a build where enforcement is not proved.**
- **Checking that pod addresses reach Cassini unchanged** under the new engine. Binding sessions to a pod's address,
  a later feature, depends on it.

It is met when the canary passes on u7c and a build of foreign code reaches only the registry.
