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

# Polar's network needs, from what each agent is built to use

> **This document has a twin.** [`network-needs.claude.md`](network-needs.claude.md) says the same thing, written for
> Claude. This one is written for people. They are two sides of one plan, and they are changed together.
>
> A **feature-level plan**, part of [runtime attestation](../runtime-attestation.md), following
> [network enforcement](network-enforcement.md). It describes Polar's `main` as it is.

**Status: proposed, not built.**

## 1. The need

Every Polar pod should reach only what its job needs, so that an attacker who gets code running in one cannot use it
to reach the rest: the graph, the certificate issuer, the git server, other agents, or the internet. Polar's
development cluster now enforces NetworkPolicy, but Polar declares none for its own workloads, so today any Polar pod
can reach any other, and the internet.

What each pod may reach has to come from facts Polar already holds about how each agent is built, not from a second,
hand-kept list that drifts from the code.

## 2. How the need was found

- **Turning enforcement on** showed the gap. The enforcer enforces whatever policy the cluster holds, and Polar's only
  policy is a deny-all for the throwaway namespace where it runs check pods.
- **Asking how Polar's network needs reach the enforcer** found that the chain exists from the policy onward (the
  render writes policies into the signed deployment, Flux applies them, the enforcer on each node enforces them), but
  not before it: nothing turns what Polar knows about its workloads into policies.
- **Reading the catalog** found that the facts are already there. Each capability an agent's code holds names the
  in-cluster services it is wired to (`infra/config/capabilities.nuon`, `infra/config/services.nuon`): the `cassini`
  capability gives an agent Cassini's address, the graph capabilities Neo4j's, and so on. An agent that goes outside
  the cluster declares an `egress` section, which the render already uses to give it its way out (`infra/egress.nu`).

## 3. The plan

The render derives each workload's policy from the services its capabilities name, and from its `egress` section.
Nothing is declared twice.

1. **Every Polar namespace starts closed:** a policy that selects every pod in it and allows nothing. What a pod may
   do is then only what its own policies add.
2. **Each workload may reach the in-cluster services its capabilities name,** on their ports, and the cluster's DNS
   to find them. An agent with the `cassini` capability reaches Cassini; one with a graph capability reaches Neo4j;
   the credentials agent reaches cert-issuer; and so on.
3. **Each service accepts the workloads whose capabilities name it,** and no others. Cassini accepts every agent;
   Neo4j accepts the graph's readers and writers.
4. **Inside the cluster, everything else is refused.** Agents reach Polar's other services only through Cassini, so
   an agent needs little more than Cassini.
5. **Outside the cluster, only an agent that declares `egress` may go,** and only outside the cluster's own address
   ranges, or only to the proxy where the target sets one. *Where* outside it goes is not policy. An observer's target
   comes to it at run time in its signed configuration, and NetworkPolicy can name addresses but not hosts. Policy
   draws the boundary; the signed configuration chooses within it.
6. **Consumers outside the catalog are declared where they are made:** Flux reading the deployment from Polar's git
   server, and any other the render wires itself. Each is written next to the wiring that creates it, so that the
   policy and the wiring change together. An administrator's port-forward needs nothing: it comes from the node, which
   NetworkPolicy does not restrict.
7. **Rolled out one namespace at a time on u7c,** each checked with the agents still working, and the egress probe and
   a denial check passing, before the next.

## 4. Alternatives considered

1. **Hand-written policies per workload.** Simple to start, but a second list of what each agent talks to, which
   drifts from the code that does the talking.
2. **Policies updated at run time from the signed configuration,** naming each observer's real target. It would put
   render-time objects downstream of run-time configuration, against the rule that control travels signed at run
   time, and NetworkPolicy still cannot name a host.
3. **All egress through the proxy,** so that the proxy, not policy, decides which hosts are reachable. A stronger
   boundary where a cluster has a proxy, and compatible with this plan: a target that sets a proxy gets exactly that.
   It is not required, since many targets have none.
4. **One coarse policy for all of Polar,** closed to the outside and open within. It stops nothing once an attacker
   is inside a Polar pod, which is the threat this capability is for.

## 5. Why this plan

- **The facts already exist** and the render already reads them; the policy follows from them, as the agent's
  environment and roles already do.
- **It holds the boundary the threat model needs:** a pod taken over reaches Cassini and its own services, not the
  graph, the issuer or the internet, unless its job needs them.
- **It respects how control travels:** policy is fixed when the deployment is signed; run-time choices stay in the
  signed run-time configuration.
- **It is standard NetworkPolicy,** so it holds on any cluster that enforces it, with kube-nftpolicy or any other
  engine.

## 6. How much of the need is met now

None of it:

- u7c enforces NetworkPolicy, but Polar renders none for its own workloads.
- The facts the policies would come from exist: capabilities naming services, and the `egress` section.
- The egress probe checks that the way out works for an agent that needs it, not that anything is refused.

## 7. What is left before this is met

- **The derivation in the render,** from capabilities and the `egress` section to policies, with tests that every
  workload's policy follows from its facts, and that a workload whose facts name nothing reaches nothing.
- **An inventory of consumers outside the catalog,** each declared beside its wiring.
- **The rollout on u7c,** namespace by namespace, with a denial check beside the egress probe.
- **The open question of DNS.** Agents find services by name, so they need the cluster's DNS, and a name server that
  forwards upstream is a way out. Builds of foreign code get none for that reason; whether agents should resolve
  names some other way is to be settled before the rollout.

It is met when every Polar pod on u7c reaches only what its capabilities and `egress` section name, and a check
proves it.
