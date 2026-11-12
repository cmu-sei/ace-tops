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
- **Trying Calico on the development host** showed that no existing engine can run there. Calico's node agent always
  creates an IPv6 nftables table, even with IPv6 support turned off, and the host's kernel is built without IPv6, so it
  has neither the `ip6` nor the `inet` table family. Canal runs the same agent. The other engines need the `inet` family
  (`kube-network-policies`), iptables extensions the kernel lacks (kube-router), or eBPF programs, which a rootless
  cluster cannot load (Cilium). The same try showed what does work rootless: an agent on the node's own network, with
  the capability to change it, programs `ip`-family nftables tables, as kube-proxy already does.

## 3. The plan

Polar enforces NetworkPolicy itself, with a small **enforcer** of its own, on clusters that have no engine. Four steps,
each seen working before the next.

1. **The enforcer.** One on every node, built and run as a Polar agent.
   - **What it reads.** NetworkPolicy, pods and namespaces, from the Kubernetes API, read-only.
   - **What it enforces.** Standard NetworkPolicy, with its standard meaning: ingress and egress; selection by pod and
     namespace labels; address blocks with exceptions; ports, named or numbered, and port ranges. It is checked against
     the Kubernetes project's own network policy tests, so what a policy means is upstream's meaning, not Polar's
     reading of it.
   - **Where it acts.** Every pod's traffic passes through its node's network namespace: between pods on one node,
     between nodes, and out of the cluster. The enforcer filters it there, in nftables, in the IPv4 (`ip`) table family
     only, after Kubernetes has translated service addresses, so a policy speaks of the pods actually reached. Replies
     to a permitted connection are let through.
   - **What it needs.** No IPv6, no iptables, no eBPF, and no kernel module beyond nftables. It runs on the node's
     network with one capability, the one to change it (`NET_ADMIN`). That is written in its signed record and held to
     it, like every other Polar pod's hardening.
   - **What it reports.** Over Cassini: what it enforces, and when that last changed. It fails loudly, not open, when
     it cannot program its rules.
   - **Where it does not run.** On a cluster whose network plugin enforces NetworkPolicy, the enforcer is not deployed,
     and that cluster's engine enforces the same policies.
2. **Enforcement on u7c.** The enforcer on every node, with Polar's pods still running as before. Nothing changes in
   `nix-usernetes`.
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
enforces them: Calico, Cilium, a cloud provider's, or k3s's. On Polar's own clusters the enforcer is the engine, and
the canary checks it the same way it would check any other.

Until the canary passes, the rule already in force holds: **no build names a repository Polar does not control.**

## 4. Alternatives considered

1. **Calico, alone or as Canal.** Tried on the development host: its node agent requires an IPv6 table, which that
   kernel cannot give it (part 2).
2. **Calico with a small patch,** skipping the IPv6 table when IPv6 is off, offered upstream. It would meet every
   condition, but Polar would carry its own build of Calico's node image until upstream took the fix, and would rely on
   a large outside agent, privileged on every node, for a small job.
3. **Building the host's kernel with IPv6.** Stock Calico would then run. Rejected: it changes the host, and gives up
   the condition that enforcement needs no IPv6.
4. **Other engines.** `kube-network-policies` needs the `inet` family, kube-router needs iptables extensions, and
   Cilium needs to load eBPF programs. None runs on the development host.
5. **Landlock's port rules,** computed by the agent builder per agent, with no Kubernetes involved. Rejected: rules by
   port cannot say where traffic goes, only which ports.
6. **No enforcement, and refuse foreign builds.** That is today's position, and it stays the fallback wherever
   enforcement is not proved. But it leaves the build orchestrator unable to do its job.

## 5. Why this plan

- **It needs no IPv6.** Polar does not depend on IPv6 anywhere. After two decades IPv6 is still only half adopted
  across systems, network gear and software. A kernel built without it is a fair place for Polar to run, and a
  smaller target: the kernel's IPv6 code has been the site of serious vulnerabilities, and code left out cannot be
  attacked.
- **It runs where nothing else does:** IPv4 nftables only, in a rootless cluster, with no change to the host.
- **The privileged thing on every node is Polar's own.** The enforcer is hardened, locked, attested and reporting,
  like every Polar agent. An outside engine would be the one privileged agent on each node that Polar could not hold to
  its own checks.
- **The job is small:** one table on one node, from a standard whose meaning is fixed and has upstream tests to check
  against.
- **Standard policy keeps Polar off any one engine,** so what is proved here carries to a customer's cluster, with or
  without the enforcer.
- **The canary makes enforcement a fact Polar checks,** not a property of the cluster it assumes. That is the same rule
  as everywhere else in runtime attestation: Polar's own checks are the guard.
- **Running the canary in the orchestrator,** not once at install, means a cluster that stops enforcing is noticed
  before the next build, not never.

## 6. How much of the need is met now

None of it is enforced. What is settled is how: no existing engine runs on Polar's development host, so Polar
enforces policy itself.


- **The clusters enforce no NetworkPolicy.**
- **Polar renders no policy for its own namespaces.** The one policy it does make is a deny-all for a throwaway
  namespace where it runs check pods, and that too goes unenforced.
- **The egress probe tests the other direction.** It checks that the way *out* works for an agent that needs it, so it
  proves nothing about denial.
- **What holds the line is a rule,** not enforcement: no build names a repository Polar does not control. A build is
  offline today only because Cargo has no reason to go out, not because anything stops it.

## 7. What is left before this is met

- **The enforcer:** its crate; one pod on every node, which the catalog has no kind for yet (the node sensor will need
  it too); its rules, checked against upstream's network policy tests.
- **Enforcement on u7c.**
- **The builds' policy, and the canary,** in the orchestrator and the render.
- **Refusing a build where enforcement is not proved.**
- **Checking that pod addresses reach Cassini unchanged** under the enforcer. Binding sessions to a pod's address, a
  later feature, depends on it. The enforcer translates no address, so this is expected to hold.

It is met when the canary passes on u7c and a build of foreign code reaches only the registry.
