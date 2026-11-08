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

# Placement: Polar's workloads by node

Status, 2026-10-28: the plan, cleared by the maintainer, built, and seen on the five-node `u7c` ("On the cluster").

*Where it is going (the maintainer, 2026-11-02, replacing the two exemplar targets of 2026-10-28):* one target, on one node or
many. "It should be possible to deploy the same target on either a single node or to lay out a multi-node topology." `local` and
`local-minimal` are retired; every deployment goes through Flux and the signed deployment repository.

## Why

The maintainer wants Polar's workloads separated by node, on a cluster that carries placement marks, and Polar's
deployment to honor them. The low-trust and high-trust halves already exist in the design: an observer is what the
outside reaches, and the consumer owns the state (`credentials-agent-architecture.md`, "Consumer (high-trust)" and
"Observer (low-trust)"). Separate nodes put them on
separate hosts' kernels and volumes, so a compromised observer is not on the host that holds a writer's key or the
graph's volume.

## What the cluster gives (nix-usernetes `b14d71b`, `822d2b0`)

`u7c`, from `~/Documents/projects/nix-usernetes/cluster.dhall`: `cp` runs etcd and the control plane and is no
Kubernetes node (no pod runs there), and four workers, each one pool, labelled `polar.dev/pool=<pool>`:

| Node | Pool | Taint |
|---|---|---|
| `core` | Polar's core | `polar.dev/pool=core:NoSchedule` |
| `observers` | the low-trust side | `polar.dev/pool=observers:NoSchedule` |
| `writers` | the high-trust side, what writes the graph | `polar.dev/pool=writers:NoSchedule` |
| `services` | what Polar relies on and is not Polar proper, and CoreDNS | none |

A pod goes to a dedicated pool only with both a `nodeSelector` on the label and a toleration of the taint (a selector
alone stays Pending, "untolerated taint"); a pod that asks for no pool lands on `services`. Workers register already
carrying their label and taint. `u7s`, the single node, has no pool labels, so a selector would leave a pod Pending
there: placement is the target's to declare.

## The mapping

| Pool | Workloads | Why |
|---|---|---|
| core | credentials-agent, cert-issuer, cassini | the maintainer, by name |
| core | git-repo-controller | decides what is observed, holds no graph password (`git-controller.md`): off the writers' host, the power to decide and the graph password stay apart. *Decided, the maintainer, 2026-10-28* |
| core | polar-git-server | serves signed authority (the schedules, the policy). *Decided, the maintainer, 2026-10-28* |
| core | build-orchestrator | decides what builds run and makes their Jobs, holding no graph password; it reads what builds print only through its locked-down reader (`build-orchestrator.md`). *Decided by the agent that built it, 2026-11-08, by the git controller's row; for review* |
| observers | git-repo-observer, jira-observer, kube-observer, polar-scheduler-observer, credentials-agent-observer, openapi-observer | the low-trust side; the credentials agent's observer is its low-trust gateway |
| observers | oci-registry-resolver | reads registries outside the cluster and holds no graph password. *Decided by the agent that placed it, for review, 2026-11-02* |
| writers | kube-consumer, git-repo-processor, jira-processor, polar-scheduler, openapi-processor | the graph writers (polar-scheduler writes the ledger to the graph, `git-controller.md`) |
| writers | soft-state-observer | reads the graph for other agents (`soft-state.md`) and so holds the graph password, which stays on the writers' pool and off the observers'. *Decided by the agent that built it, 2026-10-30, by the rule of the row above; to confirm* |
| writers | soft-state-processor | the state agent's writer: asks every agent about its health and writes `AgentHealth` (`soft-state.md`, "As built: pulled health"), so it holds the graph password. *Decided by the agent that built it, 2026-11-01, by the writers' rule; to confirm* |
| writers | Neo4j (hand chart) | beside its only writers, off the observers' host. *Decided, the maintainer, 2026-10-28* |
| services | ace (hand chart) | not Polar proper, faces people, holds no Polar authority. *Decided, the maintainer, 2026-10-28* |
| services | Flux, Jaeger, Postgres, Keycloak, the in-cluster registry, harness-producer, harness-sink | not Polar proper: the open pool, by its rule; nothing is rendered for them |

## The design

1. *The pool is the workload's, in the catalog.* Each entry in `infra/config/workloads/*.nuon` that belongs to a
   dedicated pool says `pool: "<pool>"`; one that says none is the open pool's. What a workload is decides its pool,
   not the target.
2. *The layouts are the target's.* A target names the topologies it deploys in, each the dedicated pools it places by, and
   the one it deploys in by default: `cluster: { placement: { topology: "single", topologies: { single: [], separated: ["core"
   "observers" "writers"] } } }` in `targets/sandbox-local/config.nuon`. A layout with no pools places nothing. A cluster chooses
   another with `up.nu --topology <name>`, recorded in `cluster-inputs.nuon`, so its later runs and renders keep it and the signed
   provenance records it (`resolve.nu`, `load_cluster`; `rules.nu`, `placement_in_force`). A name the target does not list is
   refused. *Decided by the agent that built it, for review: the default is `single`, since it is what a new cluster can run; a
   layout is a list of pools, with no mapping of a pool onto another's node, until one is wanted.*
3. *Rendered only when declared.* `resolve.nu` gives the pod record `placement: { pool }` when the target declares the
   workload's pool, else nothing; `schema/agent.dhall` renders the `nodeSelector` and the toleration from it. The key
   is `polar.dev/pool`, nix-usernetes' (`cluster.dhall`, `poolKey`), one constant in `resolve.nu`.
4. *A pool the target lacks is refused* when the target declares placement: a workload asking for `writers` on a target
   that declares only `core` names itself and the pool, rather than landing on the open pool unseen (as the render
   refuses escrow without custody). A target that declares no placement places nothing and refuses nothing. Before anything
   is deployed, `up.nu`'s preflight refuses a topology whose pool no node carries (`pools_without_nodes`), and says so when a
   cluster's nodes carry pools the topology in force does not use. A deployed cluster whose volumes are bound to nodes cannot
   change layout (`topology_change_problem`, which reads what is deployed from the workloads' selectors, since this machine's own
   record can be another cluster's, or gone): tried on `u7c`, 2026-11-02, from `separated` to `single`, cert-issuer's volume
   stayed on the tainted `core` node, its new pod stayed Pending, and every Flux layer after it waited, while pods already running
   were untouched. A topology is chosen on a fresh cluster.
5. *Neo4j, the one hand chart placed.* Its pool, `writers`, is in its `values.dhall`; `render.nu` hands the chart the
   target's declared pools, and `statefulset.dhall` renders the selector and toleration when `writers` is among them.
   The other hand charts are the open pool's and do not change.

## Seen on the clusters (2026-11-02)

From the 3.0.0 images, at `168e1e55`:
- *`separated` on the five-node `u7c`:* every pod on the node of its pool, all six Flux layers ready, no restarts.
- *`single`, the default, on a fresh single-node `u7s`:* no flag needed, 28 pods running, no restarts, about 11 minutes, about 9 GB of memory at
  rest against about 6.5 GB for `local-minimal` measured the same way, so about 2 GB for Flux, the deployment git server and the resolver.
- *`local-minimal` moved in place:* `docs/operations/moving-to-sandbox-local.md`.
- *A change of layout on a deployed `u7c`:* with the refusal not yet in, `cert-issuer` stranded as described above; put back, the cluster recovered with
  no restarts. Since then, with this machine's record of `u7c` gone and no flag, `up.nu` reads the pools from the cluster and refuses.

## Tests first

- `infra/tests/rules.nu`: the placement rule (declared, not declared, a pool the target lacks).
- `infra/tests/resolve.nu`: under `separated`, every enabled workload's pod record has the pool of the mapping
  above and nothing for the open pool's; under `single`, none has any; a cluster's choice overrides the target's both ways; a topology
  the target does not name refused; a pool the target lacks refused.
- `infra/tests/charts.nu`: Neo4j's StatefulSet with the selector and toleration under `sandbox-local`, without under
  `local`.
- Render determinism, when this was built (2026-10-28): `local` and `local-minimal` rendered byte for byte as before; `sandbox-local`'s diff was the
  selectors and tolerations alone.
- Mutations: the toleration left out (the pod would stay Pending); the selector rendered on a target that declares no
  placement; a pool the target lacks let through.

## Built (2026-10-28)

- *The rule* (`infra/rules.nu`): `POOL_KEY`, `placement_of` and `placement_problems`, beside the render's other rules,
  so the resolver and Neo4j's chart share them (the plan had the key in `resolve.nu`).
- *The catalog:* `pool:` on the fourteen entries of the mapping; none on the harness, the secret harness or
  oci-registry-resolver, which are the open pool's (the last two are not in `sandbox-local`; a target that runs them on
  pools would decide theirs).
- *The resolver* (`infra/resolve.nu`): the record's `placement`, refused when the target lacks the pool, and refused
  when a target sets a workload's `pool` itself; `resolve.nu placement` gives the target's declared pools, for
  `render.nu` to hand Neo4j's chart.
- *The templates:* `functions.placementOf` (`infra/schema/functions.dhall`) makes the selector and the toleration from
  an `Optional Placement`; `agent.dhall`, `ca.dhall` (cert-issuer) and Neo4j's `statefulset.dhall` use it.
- *The target:* `sandbox-local` declares `placement: { pools: ["core" "observers" "writers"] }`.
- *Tests:* the rule (`tests/rules.nu`); under `sandbox-local` every workload in the mapping's pool and the open pool's
  in none, under `local-minimal` none, a pool the target lacks refused, a target setting a pool refused, and the
  rendered pod's selector and toleration in both templates (`tests/resolve.nu`, 60 of 61 pass: the one that fails, "workloads
  still asking cert-issuer are listed as pending", fails the same way before this change); Neo4j's StatefulSet placed,
  not placed, and refused (`tests/charts.nu`). Mutations caught: the toleration left out; placement on a target that
  declares none; a pool the target lacks let through.
- *Renders before and after:* `local` the same byte for byte; `local-minimal` the same; `sandbox-local` differs by the
  fourteen pods' and Neo4j's selectors and tolerations alone.

## On the cluster

u7c is reset onto the new layout (`just cluster-reset && just cluster-up && just cluster-init && just
cluster-kubeconfig` in nix-usernetes), which wipes it: done only when the maintainer says. Then `up.nu sandbox-local
--dev`, and checked: every pod on its pool's node (`kubectl get pods -o wide`), nothing Pending, every PVC bound, and
the agents registered and the custodians fetched as before. The result goes to the nix-usernetes session.

*Done (2026-10-28), on the five-node `u7c`* (nix-usernetes `d26c6e7`: reset, up, init, kubeconfig; then `up.nu
sandbox-local --dev` at `34be7533`, stopped at the browser step, Mullvad connected throughout):
- *Every pod on its pool's node:* core has cassini, cert-issuer, the credentials agent, git-repo-controller and the git
  server; observers the four observers and the credentials agent's; writers the four graph writers and Neo4j; services
  ace, Jaeger, Keycloak, Postgres, Flux, the registry, the deployment git server, local-path and CoreDNS. Nothing
  Pending.
- *Every volume bound, on its pod's node:* the credentials agent's, cert-issuer's and the git server's on core,
  Neo4j's three on writers, the rest on services. local-path's helper pods managed the tainted nodes (the open
  question below, answered).
- *The rest as before:* every workload and daemon registered once and was refused nothing, every custodian fetched
  everything (kube-consumer's and git-repo-observer's the escrow key), and the graph writers reach Neo4j on its node
  with their keys the daemon's. jira-observer fails on the target's placeholder Jira, as always.

## Open, and assumed

- *local-path's helper pods on a tainted node* (untested by nix-usernetes; *answered 2026-10-28: they work*, above): the provisioner creates a volume's
  directory with a helper pod on the volume's node. Three volumes land on tainted nodes: the credentials agent's ledger
  and the git server's repositories (core) and Neo4j's (writers). If one of their PVCs hangs, the helper pod is the
  first place to look, and its tolerations are the provisioner's configuration, nix-usernetes'.
- *Checked 2026-10-28:* the in-cluster registry's NodePort (30500), which every node's kubelet pulls
  from at `localhost:30500`, answers on every worker, as it did on one node and on `cp` and `core`.
- *Not in this plan:* placement for the other targets (no cluster of theirs has pools), and anything finer than a
  node (per-pod user namespaces, `hostUsers: false`, are a separate item).
