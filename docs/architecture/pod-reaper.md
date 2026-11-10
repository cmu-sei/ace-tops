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

# Reaping Failed pods

Status, 2026-10-20: a design for review. Nothing here is built. Drawn, shaded: [`pod_reaper`](sequences/general/pod_reaper.mmd).

**Update, 2026-10-26 (the maintainer):** the pod observer's role is taken by the attestation agent
(`runtime-attestation.md`), which needs the same rights over pods; one agent holds them rather than two. What this
document says of the pod observer (its inventory of Failed pods, its Role, its reports) is the attestation agent's.
The Reaper stays a separate agent that only deletes. With the agents moving to Deployments that restart in place
(`runtime-attestation.md`, "Deployments, next"), Failed pods mostly stop accumulating; the Reaper stays for clusters
older than that.

**Update, 2026-10-28:** the move is done (`deployments.md`, step 4, seen on `u7c` and on a single-node `u7s`): every agent
is a Deployment of one whose pod restarts in place at every ending, so an ending leaves no Failed pod, and the Jira observer
without a Jira restarts in place instead of piling up. Clusters older than 1.36 are no longer supported (the maintainer,
2026-10-28), so the reason the Reaper was kept is gone. What can still leave a Failed pod: an eviction (disk pressure, which
is what filled a node before; the evicted pod object stays, its Deployment making another), and the load harness's Jobs
(`load-harness.nu` deletes them after a run). Whether that is worth an agent is open; until then, `just cluster-prune-failed`.

**Update, 2026-10-30 (the maintainer): the Reaper is wanted, with a wider job.** Polar applies its own housekeeping
policies to the infrastructure it runs on, beside whatever Kubernetes does, as a first, modest step in controlling that
stack. Kubernetes keeps its own policies; Polar's are its own, and they act on what is noise and poor housekeeping. The
order is fixed: what is to be removed is first recorded in the graph as an observable (by the attestation agent, which
holds the pod observer's role), and only then cleaned up. To be addressed when the Reaper is worked on; until then the
cleanup is by hand. The Reaper's work, as it stands:

- **Failed Jobs' pods,** as designed below (most were not real failures: endings by rejuvenation).
- **Evicted pods of Deployments.** Seen 2026-10-30 on u7c: a build filled `/home`, the kubelet evicted 18 pods on
  ephemeral storage, and each Deployment made a replacement; the evicted pod objects stay (phase Failed, reason Evicted,
  shown as `ContainerStatusUnknown` or `Error`) until the cluster holds 12,500 terminated pods (the controller manager's
  `--terminated-pod-gc-threshold`). The observable: the pod, its owner, the eviction's reason and message (which
  resource, the threshold, what was left), and when. The admission policy below widens from "owned by a Job" to "owned
  by a Polar workload" (a Job, or a ReplicaSet of a Polar Deployment).
- **A Deployment's old ReplicaSets** (its rollout history). Every change to the pod template leaves the previous
  ReplicaSet scaled to 0, kept for `kubectl rollout undo` up to `revisionHistoryLimit` (10 by default; Polar's charts do
  not set it). On u7c, `cassini` had eleven after the allocator and memcpy experiments changed its image about a dozen
  times, and 28 empty ReplicaSets were across the cluster. With Flux, a rollback is a revert in the deployment
  repository, so the history adds little. Decided: this is the Reaper's policy, not a `revisionHistoryLimit` in the
  charts. The observable: each revision (its number, image digests, pod-template hash, when it was replaced); the
  Reaper then keeps the newest N (to be settled) and deletes the rest. It needs `delete` on `replicasets` in Polar's
  namespaces, and the admission policy refuses a ReplicaSet that has replicas, is the Deployment's current revision, or
  is not owned by a Polar Deployment.
- **Superseded images** (the maintainer, 2026-11-08). Every bring-up pushes a new set of every agent image (32 of 41 on
  u7c each time, `build-orchestrator.md`, E3), and nothing removes the old ones: each node's containerd store keeps every
  version it pulled (u7c's node volumes held 129 GB on 2026-11-08, `/home` at 95%), and the registry in the cluster keeps
  every pushed blob (13.3 GB then, nearly all earlier versions of the agent images; the builds' own repositories,
  `build-sources` and `build-dependencies`, and `polar-ci` were small). The observable: each image set a deployment
  record named, which digests the next record dropped, and when. The Reaper deletes what no record in force (or kept)
  names: registry manifests by digest through the registry's API, then the registry's garbage collection for the blobs
  (which wants the registry read-only while it runs); and on each node, the images no container uses. The admission policy
  refuses an image a running pod or the record in force names.
- **Every kind of stale object, as one job** (the maintainer, 2026-11-08, with u7c's list: about ten empty ReplicaSets
  for each of 27 Polar Deployments, one per bring-up, since every bring-up changes every image and Kubernetes keeps ten;
  and in `flux-system` (3) and `local-path-storage` (1)). Old ReplicaSets, superseded images, Failed and evicted pods and
  finished Jobs are all "superseded by a newer deployment", so they are one job with one trigger, not a mechanism each:
  the deployment record coming into force. The record is read already: the configuration agent reads it from the
  deployment repository on Polar's own git server and publishes it on a topic of its own every 30 s
  (`runtime-attestation.md`, "Continually, the Deployments against the signed record"; `deployment_record.rs`). The
  maintainer: the Reaper is told when a new set is deployed, not left to poll on a schedule. So the attestation agent,
  hearing a record newer than the last, records in the graph what it superseded (the observable, first), then announces it
  as a non-sensitive notice on a fixed topic (`announce, then ask`); the Reaper acts on the notice, by policy per kind. A
  new kind is a line of policy and an observable, not another mechanism.
- By hand until then: `just cluster-prune-failed` for Failed pods; for empty ReplicaSets, `kubectl get rs -A --no-headers
  | awk '$3==0 && $4==0 {print $1, $2}' | while read ns rs; do kubectl -n "$ns" delete rs "$rs"; done` (both were run on
  u7c on 2026-10-30: 18 pods and 28 ReplicaSets).

## The problem (as it was, until 2026-10-28)

Every agent ends a pod by exiting 1, so that its Job (`restartPolicy: Never`, `backoffLimit` 1000000) replaces it
(`health-and-shutdown.md`). Rejuvenation does this about hourly per agent, and every ending leaves a pod in phase Failed
next to its replacement. An agent that cannot start (the Jira observer with no Jira to reach) leaves one every few
minutes. Nothing removes them: `ttlSecondsAfterFinished` acts only when a Job finishes, which these never do, and the
cluster's own pod garbage collection is a controller-manager setting outside Polar's reach. The only cleanup is
`just cluster-prune-failed`, by hand; a weekend of failed Jira observer pods once filled a node until it tainted itself
with disk pressure.

## The shape

Two agents, so that the right to see and the right to act are held by different identities, and each holds the least it
needs.

- **The pod observer** takes an inventory of the Failed pods of Polar's Jobs in Polar's namespaces, on a schedule the
  scheduler agent can change. For each it reports what anyone who cares about the failure needs: the pod and its UID, its
  Job, when it failed, each container's exit code and reason, and the end of its log, which is gone once the pod is. It
  answers a request for the current set, so a Reaper that restarts asks instead of waiting for the next round.
- **The Reaper** decides retention and deletes. It keeps the newest one or two Failed pods of each Job, for long enough that
  their logs and graph edges can be taken (a setting of its signed configuration), and deletes the rest. It acts only on
  what the pod observer reported, and reports what it deleted and why.
- **The graph** gets a node for each failure (the pod, its Job, its exit code and reason, the log's end) when the
  observer reports it, and an edge from it to the reaping when the Reaper reports that. A failure stays walkable after its
  pod is gone.

Nothing outside Polar's namespaces is seen or touched: the boundary is enforced by Kubernetes (below), not only by the
agents' code.

## Controls, at each layer

| Layer | Pod observer | Reaper |
|---|---|---|
| Kubernetes RBAC | a namespaced Role in each Polar namespace: `pods` get, list, watch; `pods/log` get | a namespaced Role in each Polar namespace: `pods` delete, nothing else (not even get) |
| Kubernetes admission | | a ValidatingAdmissionPolicy that refuses the Reaper's identity any delete of a pod that is not Failed, not owned by a Job, or not labelled as a Polar workload |
| The Polar certificate | a capability that says it may report pods for reaping | a capability that says it may reap |
| Cedar | | `PolicyLookup` before each delete: `Action::"reap"` on `Pod::"<namespace>/<name>"`, with the pod's phase, owner and age as facts |
| Cassini | | acts only on a report whose `published_by` is the pod observer's identity, and whose publisher holds the observer's capability |

The ValidatingAdmissionPolicy (built into Kubernetes since 1.30) is what makes "only Failed pods" a fact of the cluster and
not of the Reaper's code: RBAC can say `delete` on `pods`, but cannot look at a pod's phase, and admission can (a delete's
`oldObject` is the pod being deleted). Each delete also carries `preconditions.uid` from the report, so a pod that was
replaced under the same name is not the one deleted.

## What exists, and what each control needs

- **Kubernetes RBAC.** The catalog's capabilities produce a ClusterRole and ClusterRoleBinding only
  (`infra/schema/resources.dhall`), and the only one is `kube-api-read`, `*/*` get, list and watch, cluster-wide (since
  2026-11-10 every role holds only what its agent declares: `protocol-handlers.md`, "A role is what the operations declare"). Both
  agents need namespaced Roles with narrow rules, so `resources.dhall` gains a Role and a RoleBinding per namespace, and the
  catalog gains two capabilities (with their `Capability` variants in `polar-agent-builder`, which a test keeps in step).
- **Admission.** None exists in the repository. The policy and its binding would be rendered with the Reaper's chart, in a
  layer before the Reaper, and checked by `render.nu`.
- **The certificate.** A workload certificate carries its identity and, from a ledger grant, `p:` permissions; `c:`
  capabilities are a closed set of administrative powers, minted only on `/internal/issue` and in practice only for
  accounts (`cert-issuer-isolation.md`). There is no workload capability yet, and grants are single-use, so a pod that
  rejuvenates hourly would lose one. This is the open design question below.
- **Cedar.** `polar-policy` evaluates the cluster's one rule set, which the credentials agent publishes; any builder agent
  can ask it (`PolicyLookup`). There is no `Pod` vocabulary yet, and the facts (phase, owner, age) are the asker's to give.
- **Cassini.** The broker does not decide who may publish or subscribe to a topic (`remaining-work.md` lists it as a gap to
  be addressed). It stamps the verified sender's identity on each message (`published_by`), which receivers can check, as
  the authority updates already are (`AuthorityCore::from_the_credentials_agent`).

## Open questions

1. **The capability in the certificate.** Two ways to give a workload a capability that rejuvenation does not lose:
   (a) from the catalog: a workload's capabilities are declared in its entry, rendered into cert-issuer's per-workload
   floor as server names are today, and written into each certificate it is issued; or (b) from the ledger: a standing grant
   (not single-use) on the credentials agent, signed by an administrator with `c:grant`, so that giving an agent an
   infrastructure privilege is an act someone signs and the ledger records. (b) fits "an infrastructure privilege is
   granted, not configured"; (a) needs no administrator at bring-up.
2. **The Kubernetes credential.** Today an agent's Kubernetes token is a Secret the catalog renders, mounted into its pod.
   Should the Reaper's instead be held by the credentials agent and released only to a certificate holding the reap
   capability, under Cedar? That ties the Kubernetes privilege to the Polar one, at the cost of the Reaper depending on the
   credentials agent to act.
3. **Retention.** Keep the newest N Failed pods of each Job (N = 2?) for at least T (an hour?), and delete the rest, and any
   Failed pod older than T' (a day?) whatever N says?
4. **What is kept of a log.** The end of each container's log goes into the failure's graph node: how much (200 lines? 64
   KiB?), and is a log a thing the graph should hold, or should it go to a store of its own with an edge to it?
5. **Names.** `pod-observer` and `reaper`, as their workloads, identities and crates?
6. **How many earlier sets are kept,** for a rollback (a revert in the deployment repository with Flux): the image sets
   of the last N records, and the ReplicaSets that ran them?
7. **Reaching a node's images.** The Reaper has no presence on a node, and a node's containerd is reached only from it: a
   privileged piece on each node (a DaemonSet, its own identity and admission), or the kubelet's own image garbage
   collection told what to keep? The first is Polar's own housekeeping; the second leans on Kubernetes' policy.
8. **Infrastructure Polar installs but does not write.** Flux's and the local-path provisioner's ReplicaSets are in
   namespaces Polar deploys (`flux-system`, `local-path-storage`) and are owned by Deployments Polar did not write: within
   the Reaper's reach, or left to their own charts?
9. **The registry's garbage collection** wants the registry read-only: when, on a cluster whose builds push to it (between
   builds, with the orchestrator's admission holding new ones)?
