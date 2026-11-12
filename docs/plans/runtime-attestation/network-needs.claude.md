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

# network-needs — Claude's side

PAIR: `network-needs.md` (people). Same plan, two forms; change together.
SPLIT: people side has no dates, attributions, quotes, codenames or branch/process status; those live here.
PARENT: `../runtime-attestation.claude.md`; follows `network-enforcement.claude.md` (enforcement exists on u7c).
AS-OF main 811e23f1 (2026-11-12). STATUS: proposed (maintainer asked for the write-up 2026-11-12); not cleared.
ORDER: an OPTION among the next pieces (see network-enforcement part 7); maintainer picks.

## ORIGIN
2026-11-12 maintainer asked "how does polar's declared network needs end up being enforced by kubernetes' node
enforcer?" Answer: chain exists policy→Flux→API→kube-nftpolicy→nftables (+ canary); nothing produces Polar policies
from facts. I proposed boundary-shaped derivation; maintainer: "Yes, write it up in the plan."

## DESIGN (mine, for review)
- source facts: capability → services. capabilities.nuon: env placeholders {svc.addr|url|dns} and
  `dependency.service` (cassini: {cassini.addr}, dependency cassini; graph-write/graph-read: bolt+s://{neo4j.addr};
  tracing: {jaeger.url} at :355; cert-issuer via polar-init :250). services.nuon: cassini polar:8080, neo4j graph:7687,
  cert-issuer polar:8443, polar-git-server polar:8443, credentials-agent-observer polar:8080 (polar-init, plain http),
  jaeger polar:4318. Capabilities are held by the agent's code (attested.nu:108-120 "the agent's code holds a
  capability") — builder-computed, per principle. egress: agents registering polar::egress::SECTION (jira observe
  agent.rs:269, supervisor.rs:734; git-repo-observer) → egress.nu gives the way out.
- render: per Polar ns default-deny (podSelector {}, Ingress+Egress); per workload egress allow to each named
  service's pods:port + kube-dns 53/UDP+TCP; per service ingress from workloads naming it; egress agents: ipBlock
  0.0.0.0/0 except cluster pod CIDR + service CIDR (or only the proxy address when cluster.egress.proxy set).
- non-catalog consumers declared beside their wiring: Flux source-controller → polar-git-server (deploy repo
  GitRepository, deploy-objects.nu git_repository); check others in harvest (polar-init's request to
  credentials-agent-observer is a capability path; jaeger from every traced workload).
- rollout per namespace on u7c; denial check beside egress probe (egress.nu).
- tests: every workload's policy follows from its facts (property: computed set = union of its capabilities' services;
  order-independent); a workload naming nothing reaches nothing.

## OPEN
- DNS: agents resolve service names via kube-dns, which forwards upstream (exfil path; builds get none). Options:
  hostAliases from render (addresses are ClusterIPs, known after Service creation — chicken/egg at render), CoreDNS
  without upstream for Polar namespaces, or accept DNS. Settle before rollout.
- polar-builds, polar-bootstrap, polar-registry, polar-auth (keycloak/postgres), polar-graph: non-agent workloads'
  needs from catalog kinds service/run/ca/template — inventory.
- kubelet/registry pulls are node traffic: unaffected.
- breaking-change check vs agentic-control-plane (main-and-acp-stay-compatible): policies are render output on main;
  acp's extra workloads (witness, evidence) would need their capabilities to name services or be refused — coordinate
  with polar-cc before rollout.
