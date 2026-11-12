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

**Status: u7c enforces NetworkPolicy; Polar's side (the builds' policy and the canary) is not built.**

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

Where a cluster has no engine, NetworkPolicy is enforced by **kube-nftpolicy**, a small enforcer that is a project of
its own (`github.com/daveman1010221/kube-nftpolicy`), not part of Polar. Polar offers it as one way to meet its network
requirements, on Polar's own clusters and on anyone else's. Four steps, each seen working before the next.

1. **The enforcer, kube-nftpolicy.** One on every node that runs pods.
   - **What it reads.** NetworkPolicy, pods and namespaces, from the Kubernetes API, read-only, under a role that
     allows nothing else.
   - **What it enforces.** Standard NetworkPolicy, with its standard meaning: ingress and egress; selection by pod and
     namespace labels; address blocks with exceptions; ports, named or numbered, and port ranges. Its tests hold the
     rules it computes to a direct statement of that meaning, for every generated cluster and packet.
   - **Where it acts.** Every pod's traffic passes through its node's network namespace: between pods on one node,
     between nodes, and out of the cluster. The enforcer filters it there, in one nftables table of the IPv4 (`ip`)
     family, after Kubernetes has translated service addresses, so a policy speaks of the pods actually reached.
     Replies to a permitted connection are let through.
   - **What it needs.** No IPv6, no iptables, no eBPF, and no kernel module beyond nftables: only the capability to
     change the node's tables (`NET_ADMIN`).
   - **How it is deployed.** It is built from its own Nix flake. On Polar's development clusters it is part of the node
     image (`nix-usernetes`), a service of the node like kube-proxy, with credentials of its own. On other clusters it
     runs as a DaemonSet, from the image its flake builds. Where a cluster's network plugin already enforces
     NetworkPolicy, it is not deployed.
   - **A new pod starts isolated.** A pod starts before the API reports its address, and Kubernetes requires a pod
     that an existing policy selects to be isolated before it starts. So within the node's pod range, an address that
     is no pod the enforcer knows is refused until its rules are written. Every new pod has no network for a moment
     (under a second); TCP's retries cover it.
   - **What it does on failure.** It fails loudly, not open: a table it cannot write is retried, and after repeated
     failures the enforcer exits for its supervisor to restart, with the last table still in force. The table outlives
     the enforcer on purpose, so that a crash or an upgrade leaves the node enforcing; uninstalling it therefore
     includes removing its table (`kube-nftpolicy --remove`).
2. **Enforcement on u7c.** u7c's node images rebuilt with the enforcer, with Polar's pods still running as before. The
   policies already in the cluster then take effect: Flux's own, and Polar's deny-all for the namespace where it runs
   check pods. Done.
3. **The builds' policy,** rendered from the catalog for `polar-builds`:
   - no ingress;
   - egress only to the registry's pods, on its port;
   - no DNS, since a name server that forwards upstream is a way out. The orchestrator resolves the registry's name
     itself and gives the pod the address directly.
4. **A canary that proves enforcement.** The build orchestrator runs it in `polar-builds`, under the builds' own
   policy. It must reach the registry, and must **fail** to reach the Kubernetes API and an address outside the
   cluster. It runs when the orchestrator starts, and again before a build when the last proof is older than a set
   bound. Where enforcement is not proved, a build is refused with the reason, and the result is published.

Polar writes only **standard NetworkPolicy**, so the policies and the canary carry to any cluster that enforces them:
with Calico, Cilium, a cloud provider's engine, k3s's, or kube-nftpolicy. The canary checks each the same way.

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
6. **The enforcer as a Polar agent,** a Polar pod on every node, reporting over Cassini and attested like every other.
   Not chosen: it would tie a piece of general infrastructure to Polar, and put a privileged pod on every node where a
   node service does the same job.
7. **No enforcement, and refuse foreign builds.** That is today's position, and it stays the fallback wherever
   enforcement is not proved. But it leaves the build orchestrator unable to do its job.

## 5. Why this plan

- **It needs no IPv6.** Polar does not depend on IPv6 anywhere. After two decades IPv6 is still only half adopted
  across systems, network gear and software. A kernel built without it is a fair place for Polar to run, and a
  smaller target: the kernel's IPv6 code has been the site of serious vulnerabilities, and code left out cannot be
  attacked.
- **It runs where nothing else does:** IPv4 nftables only, in a rootless cluster, with no change to the host.
- **It is part of the node, not of Polar.** Like kube-proxy, it belongs to the node, which Kubernetes' trust base
  already includes. Polar's own check of enforcement is the canary, which does not trust the enforcer's word.
- **It stands on its own.** Anyone can run it on a cluster that needs it, with or without Polar, and Polar's
  requirements do not bind it to Polar's release cycle.
- **The job is small:** one table on one node, from a standard whose meaning is fixed and has upstream tests to check
  against.
- **Standard policy keeps Polar off any one engine,** so what is proved here carries to a customer's cluster, with or
  without the enforcer.
- **The canary makes enforcement a fact Polar checks,** not a property of the cluster it assumes. That is the same rule
  as everywhere else in runtime attestation: Polar's own checks are the guard.
- **Running the canary in the orchestrator,** not once at install, means a cluster that stops enforcing is noticed
  before the next build, not never.

## 6. How much of the need is met now

u7c enforces NetworkPolicy; Polar renders none of its own yet.

- **kube-nftpolicy works on a rootless cluster whose kernel has no IPv6.** On a throwaway three-node cluster, both
  as a DaemonSet and as a node service in the node image, a policy limiting a pod to one server's named port let that
  through, across nodes and within one, and blocked another pod, the Kubernetes API and the internet, and ingress to
  the pod. Pods no policy selects were unaffected. A new pod in a deny-all namespace was refused from its first
  connection. Flux kept fetching and applying under its own three policies, and Polar's check pods ran as before in a
  deny-all namespace.
- **u7c enforces NetworkPolicy.** Its node images run the enforcer on every worker, and Polar came back on them with
  every pod running. Flux's policies are in force there: another namespace reaches source-controller's metrics, but not
  its artifacts.
- **Polar renders no policy for its own namespaces.** The one policy it does make is a deny-all for a throwaway
  namespace where it runs check pods, which is now enforced.
- **The egress probe tests the other direction.** It checks that the way *out* works for an agent that needs it, so it
  proves nothing about denial.
- **What holds the line is a rule,** not enforcement: no build names a repository Polar does not control. A build is
  offline today only because Cargo has no reason to go out, not because anything stops it.

## 7. What is left before this is met

- **The enforcer against upstream's own network policy tests,** beside its property tests.
- **Offering the enforcer from Polar** for clusters without an engine: a choice in a target's configuration that
  deploys its DaemonSet.
- **The builds' policy, and the canary,** in the orchestrator and the render.
- **Refusing a build where enforcement is not proved.**
- **Checking that pod addresses reach Cassini unchanged** under the enforcer. Binding sessions to a pod's address, a
  later feature, depends on it. The enforcer translates no address, so this is expected to hold.

It is met when the canary passes on u7c and a build of foreign code reaches only the registry.
