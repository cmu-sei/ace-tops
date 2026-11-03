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

# The deployer: a GitOps controller of Polar's own

Status, 2026-11-02: a proposal for review. Nothing is built, and nothing here is decided until the maintainer says so. Decisions the agent that wrote this made by the Design Principles (`AGENTS.md`) are marked
*(for review)*. The review of Flux it rests on is in [`gitops-controller-edge-cases.md`](gitops-controller-edge-cases.md), whose entries are cited here as E6, C1 and so on.

Citations to Polar are `file:line`, at `eada654b`. No Flux code and no code of this design was built or run. Section 23 says what was not checked.

## 1. Why

What the maintainer wants (2026-11-02) and Flux cannot give:

- **Every commit verified before anything is applied, with no gpgsm.** Flux's `spec.verify` takes OpenPGP and SSH (K5), Polar signs with x509, and so "whoever can write to the repository can deploy anything" (`docs/architecture/cluster-bootstrap.md:125`, `:160`). After the handoff the repository is on Polar's own git server, so a compromised Polar could then write what Polar is made from. Verifying at push (`cluster-bootstrap.md:125-127`) closes write access by others. It does not close the server itself.
- **No credential in a Secret.** Flux reads its client key from one, and nothing renews it (`cluster-bootstrap.md:130`, `infra/flux.nu:220-225`, H13).
- **Identity, custody and attestation like any agent**, and the attestation agent told before anything changes.
- **The apply's decisions in Polar's hands**: what may be pruned, and what happens to a claim holding the ledger.

The review adds a reason the list above did not have. Flux's generality costs Polar in ways that matter here: any 422 under `force` deletes the object (C1), an object moved to a later layer is deleted and recreated (E6), fields newer than its compiled types vanish before the apply (B1), and a layer whose build is empty is pruned whole (E1). Most of its code is for things Polar does not do.

## 2. What the review found, and what is worth doing to Flux today

112 edge cases, of which 74 apply to what Polar renders: 60 fully, 14 in part. The list is the document beside this one. Most of what makes Flux long is out of scope here: Polar's layers are 111 objects of 13 kinds, with no CRD, no Job and no webhook, and the 7 CRDs and the NetworkPolicies in the render are Flux's own and leave with it (`gitops-controller-edge-cases.md`, "How to read it").

These do not need the deployer, are cheap, and are worth doing whatever is decided below *(for review; each is a small change of its own)*:

| Finding | Change, on today's Flux |
|---|---|
| H1 | The gate `CancelHealthCheckOnNewRevision` cancels a health wait on a new revision or spec, and is off. Set it in `flux-controllers.yaml` through `flux.nu export`, try it, and if it holds, drop the controller restart (`infra/flux.nu:266-273`). Read, not run. |
| E12 | Render `kustomize.toolkit.fluxcd.io/prune: disabled` on the claims and namespaces. 7 claims hold the ledger, the certificate record, the repositories and the graph. |
| C1, C2 | `force` deletes on any 409 or 422. No layer has it today, because no layer holds a Job. Remove `has_job`'s branch (`infra/deploy-objects.nu:65-68,138`) so a future Job cannot bring it back silently. |
| H13 | `ensure_pki` remakes a certificate for its names and never for its age (`infra/deploy-repo.nu:206-209,215`). `flux` and `pipeline` expire after 365 days, and nothing says so. |
| E1 | `layer_problems` refuses a layer with no files (`infra/layers.nu:62-64`). Extend it to a layer with no objects. |
| E6 | `publish` compares with the previous `provenance.json`, and refuses a file moved to a later layer unless told. |
| B1 | Know that a Kubernetes 1.37 field in a manifest is dropped by Flux 1.36's types before the apply, and that no error says so. |
| J2 | `cluster-bootstrap.md:98` says the render has no Secret documents. It has two, service-account-token placeholders. |

### Speed: the maintainer's complaint, measured

*The maintainer, 2026-11-02:* "I find it horribly slow... that's something I'd like to work on in a new impl." So speed is a requirement here, not a side benefit.

Flux's own logs on `u7s` for one full rollout of all six layers, 2026-11-02, single node (`kustomize-controller`, `source-controller`):

| Layer | Became eligible | Reconcile took |
|---|---|---|
| platform | 21:28:54 | 0.11 s |
| cert-issuer | 21:29:23 | 5.07 s (a health check) |
| data | 21:29:53 | 0.08 s |
| cassini | 21:30:23 | 5.07 s (a health check) |
| identity | 21:30:54 | 10.10 s (a health check) |
| agents | 21:31:24 | 0.19 s |

**About 20 of those 151 seconds are work; about 130 are waiting.** Server-side apply takes 60 to 200 ms per layer. A layer whose dependency is not yet ready is asked again only after `--requeue-dependency`, 30 seconds by default (`kc:main.go:116`), and each layer waits for the one before, so six layers wait five times. Before that, a new commit waits for the source's poll: `interval: 1m` (`infra/deploy-objects.nu`), seen at 5, 12 and 28 seconds on three commits. Nothing here says what else is slow when a cluster is under load, or on other rollouts: this is one run, read from logs.

**So the deployer must not poll for anything it can be told.** Requirements:
- The next layer starts as soon as the one before is healthy, from a watch of what it applied. No dependency timer.
- A new commit is seen from the git server's `RepoChanged` over Cassini, with a slow poll only as the fallback for when Cassini is away, as it is at bootstrap.
- A measured target for milestone M1: shadow mode reports how long this plan would take beside what Flux took, on the same commit. A guess at what it should reach on this rollout is about 25 seconds: the same health waits, no idle ones.
- Health waits themselves are not to be cut: what a pod needs to come up is what it needs.

*The maintainer's direction, 2026-11-02:* "We're not trying to build something general purpose, bound to Kubernetes' limitations. If we can get the core up fast, we should be able to take notifications from Cassini on everything else." So readiness has two sources, and this is a Polar controller rather than a Kubernetes one:
- **The core, before Cassini exists,** is watched through the Kubernetes API, since nothing else can say: up to and including Cassini and what vouches for certificates.
- **Everything after it** says so itself over Cassini. An agent's start, its health and its registration are already published and asked for (`soft-state.md`, "As built: pulled health"), so the deployer is told rather than asking. What this must settle: whether a workload that never registers is told apart from one still starting, which is a deadline per workload rather than a poll; and what stands in for a service that is not a Polar agent (Neo4j, Keycloak), which a Kubernetes watch can keep doing.

*Cheap on today's Flux, for review:* `--requeue-dependency=5s` in `flux.nu export` should take this rollout from 151 seconds to about 45, by the same arithmetic. Not tried.

### Ordering: a dependency graph, not layers

*The maintainer, 2026-11-02:* agents declare their dependencies, and the infrastructure works out the right order for the entire cluster, "no need for shit like layers". There is no such graph yet: the layers are hand-kept in `target.nu`, and `INFRA.md` already says they should be derived. The raw material exists: an agent's `NEEDS` (its scaffold's `requires`, computed by the builder), each capability's `dependency` (`infra/config/capabilities.nuon`: Cassini, Neo4j, the state agent), a workload's `issuer`, and who publishes and subscribes which topic.

*What it has to get right (from reading the comments and the catalog, not yet checked against a run):* the edges are not all one kind, because taken as one kind they have cycles. Neo4j's certificate comes through the credentials agent, and the credentials agent has `graph-write`, but its graph is a best-effort projection of its ledger; cert-issuer has the `cassini` capability and Cassini's certificate comes from cert-issuer. So an edge is either *cannot start without* (the issuer of its certificate) or *uses when it is there*. The first kind must form no cycle, which the render can refuse, and only it orders anything.

*It may also need far less ordering than the layers imply.* A pod already waits in `polar-init` for its own certificate, and an agent already tolerates what it uses being away. If so, everything can be started at once, and the only real ordering is the issuance chain. To be measured, not assumed.

*It does not need the deployer.* The same graph can generate today's `apply_layers` and Flux's `dependsOn`, so it can come first and be proved on Flux.

## 3. What it is, and its name

**`deployer`**: one agent that reads the signed deployment repository and makes the cluster match it. *(for review)* The name says what it does. "Controller" is taken (`git-repo-controller`), "reconciler" describes a mechanism, and any name with "flux" or "gitops" in it would date. Its crates follow `attestation/`: `deployer/common` (the pure core and the protocol), `deployer/agent` (the workload) and `deployer/record` (the graph writer, section 14). This file keeps the name `gitops-controller.md` because `cluster-bootstrap.md:130` already points here.

It is a Rust static musl binary on the agent builder, its parts supervised actors, a workload in the catalog (`infra/config/workloads/deployer.nuon`), on the `core` pool beside what it deploys first (`docs/architecture/placement.md`) *(for review)*. It has no volume and needs no storage class: everything it must remember is in the API (section 5), so it still runs when storage is what is broken.

## 4. Scope

It applies a closed table of kinds, in the code, each with group, version, plural, scope, the order it applies in, its health rule and what may be recreated. *(for review)*

| Kinds | In the layers today | Notes |
|---|---|---|
| Namespace, ServiceAccount, StorageClass, Role, ClusterRole, RoleBinding, ClusterRoleBinding, Deployment, ConfigMap, PersistentVolumeClaim, Service, StatefulSet | yes | |
| Secret | 2, as `type: kubernetes.io/service-account-token` with no data | Any other Secret, or any with `data` or `stringData`, refuses the commit: secrets are never in the render. |
| NetworkPolicy, ResourceQuota | no; Flux's own | In the table because they are cheap: no status to judge, nothing immutable. |
| Job, CustomResourceDefinition | not in any layer | **Not in the table** (C5, D3, G5). A layer naming one refuses the commit. `load-harness.nu` keeps applying its Jobs. If `polar-operator` brings a CRD, a row and a stage are added then. |

Not done, each on purpose: Helm, OCI, overlays, Kustomize, substitution, SOPS, webhooks, multi-tenancy, other clusters, CEL (section M of the edge cases). A file is applied only if `provenance.json` lists it. A namespaced object must be in a namespace the tree declares, so a commit cannot reach `kube-system` by mistake *(for review)*.

## 5. Shape

**A pure core, and thin actors.** Everything that decides is a function of its inputs in `deployer/common`, and every property test is on those:

| Function | Takes | Gives |
|---|---|---|
| `parse_tree` | a tree's files and `provenance.json` | the desired set, or why the commit is refused, whole |
| `source_choice` | the commit applied, and each transport's verified head | the commit to work on, or a refusal such as `Rewound` |
| `stages` | the desired set | a total order of stages |
| `classify_dry_run` | a live object and a dry-run result | `Create`, `Configure(paths)` or `Unchanged` |
| `classify_refusal` | an API status | `Retry`, `Hold` or `Immutable(paths)` |
| `recreate_allowed` | a kind and field paths | whether, and how |
| `health` | a kind and a live object | `Current`, `InProgress` or `Failed(why)` |
| `prune` | the trees applied and attempted, the next tree, what is live, the bounds | what to delete, what to keep and report, or a refusal |
| `next` | the state record and an event | the next state and the effects to perform |

**Actors**, under a domain supervisor, exchanging messages and writing nothing of each other's:

```
deployer supervisor
├── InfrastructureSupervisor   the builder's: health, shutdown, and when it has an identity Cassini's client (section 10)
├── SourceActor                reads each transport, verifies, and tells who cares about a verified commit
├── ApplyActor                 one plan, one commit: its stages, its waits, its prune. Told of a newer commit, it stops at the next object.
├── DriftActor                 dry-runs the commit applied, on an interval, and asks ApplyActor to correct what differs
├── LedgerActor                the only writer of the state ConfigMap, by compare-and-swap
└── ReportActor                what happened, out to Cassini when there is one (section 14)
```

**One plan per commit, not one reconciler per layer.** This single choice avoids most of what Flux had to absorb about layers. An object named anywhere in a tree is not stale (E6). A later layer's fix arrives with the same plan as the rest (D7). A layer with no change has nothing to wait for (G11). The layers remain, as the order things are applied and gated in, declared by the signed commit.

**What it remembers,** in three ConfigMaps in `polar`, each read fresh and never from a cache (H2) *(for review)*:

- `deployer-state`, the record: `{ schema, applied: <commit>, attempted: [<commit>...], holder: <pod uid>, holds: { <layer>: { reason, until } }, reported_to: <height> }`. Written before the first write of an attempt. It is the fence too: each stage begins with a compare-and-swap on it, so a second instance loses at its next stage (H7).
- `deployer-snapshot`, the last commit applied, its tree and commit as a git pack. It lets a restarted pod correct drift while the git server is down. Verified at every read; it confers nothing.
- `deployer-seed`, the same format, written by the operator (section 7).

Losing any of them is safe: no record means no prune and a report (E13); no snapshot means waiting for a source. A pod restart at any moment is harmless, which is an invariant tested by killing it at every step (section 19). That is also what makes the rejuvenation in section 10 cheap.

Nothing here tries to protect these objects from someone with Kubernetes credentials: Kubernetes is the trust base (`runtime-attestation.md`), and what they could do through these is less than what they could do directly.

## 6. Trust: what verifying a commit means

`polar_signing::commit::verify_commit(raw, trust, "pipeline", now)` (`src/agents/polar-signing/src/commit.rs:89-94`) says a commit's bytes were signed by a certificate named `pipeline`, chaining to the pinned deployment CA, valid at `now`. It uses no `gpgsm`, and any single-bit change is refused (`src/agents/polar-signing/tests/commit_signature.rs`). It is the root of the chain below, and it says nothing about the rest of the chain, which is what this section adds. *(All for review.)*

| Question | Answer |
|---|---|
| **Is the tree the one signed?** | A commit names its tree by SHA-1. To carry SHA-256 all the way, `publish` adds a trailer, `Provenance-Sha256: <hex>`, to the signed commit message. `provenance.json` already lists every file's SHA-256 (`infra/deploy-repo.nu:402`). The deployer checks the trailer against the file, each listed file against its digest, and refuses a file not listed. |
| **Is it going forwards?** | A head must descend from the commit applied, or it is `Rewound`: refused, reported, and drift correction goes on from the commit applied (K2). Signatures alone do not stop this: an old commit is still signed. |
| **Is every commit signed?** | Every commit from the one applied to the head is verified, not only the head. `publish` commits on top of whatever the server holds (`infra/deploy-repo.nu:490-505`), so an unsigned commit pushed first would get a signed child. The walk refuses it; `publish` should also refuse to sign on top of one. So a fetch is full, never shallow (K1). |
| **Is it for this cluster?** | `provenance.target` must be the deployer's own, and `cluster_inputs.cluster_ca_sha256`, when present, the sha256 of the `polar-ca` it can read (`infra/deploy-repo.nu:418-424`). The PKI is per target (`:70-72`), and a target can run on several clusters, so a signature alone would let one cluster's commit be replayed on another. The check is on the head: a mirror's history may hold another cluster's commits. |
| **Who is trusted?** | The pin comes from `up.nu`, as a ConfigMap `deployer-trust` made from `ca.pem`, mounted, read at start, a Static trust setting as `CERT_ISSUER_ISSUERS` is (`remaining-work.md:594-596`). It cannot come from the tree (that would be circular), and a commit naming that ConfigMap is refused. `provenance.deployment_ca_sha256` (`deploy-repo.nu:479`) must agree with it. `Trust::from_pem` takes several anchors, which is the CA's rollover. |

**What it needs of `verify_commit`:**

1. *It returns what it verified.* Today it returns `SignerInfo`. It should also return a `VerifiedCommit { tree, parents, committer_time, signing_time, message }`, parsed from the exact bytes verified, refusing a duplicated `tree` or a malformed header. A caller who parses the commit a second time can disagree with it about what was signed. A parser differential is the classic hole in this kind of check. Round-trip and malformed-input properties go on it.
2. *Which time.* `valid_at(leaf, now)` (`commit.rs:434`, `verify.rs:129-137`) checks the certificate at `now`, and the pipeline's lasts 365 days (`deploy-repo.nu:215`). So: the **head, when it is new to this cluster,** is verified at the wall clock, strictly. The commits **before it in the walk, and the commit already applied** when it is read back from the snapshot or the source, are verified at their own signing time (the CMS `signingTime` if `gpgsm` writes one, which was not checked, or else the committer's date; both are signed). Refusing an applied commit a year on would stop drift correction for no gain: it was accepted already, and it can bring nothing new. A clock that is wrong makes new commits wait, which is reported as such (H12), and nothing is deleted. `publish` refuses a certificate within a margin of its end, and `ensure` remakes it (H13).
3. *A purpose on the certificate.* `pipeline` has `extendedKeyUsage=clientAuth` (`deploy-repo.nu:85,179`), the same key signing commits and pushing over TLS. `verify_authority_certificate` holds its signer to a document-signing purpose (`verify.rs:192-196`). A separate signing certificate, with that purpose and checked, is cheap at this stage and worth doing. Not needed for the first milestones.
4. *Revocation does not exist in the deployment PKI.* If the `pipeline` key leaks, the answer is a new CA and a new pin, by hand. That key lies beside the CA's on the operator's machine (`deploy-repo.nu:195-205,214`), so losing one means losing both. It should be said plainly and accepted, or the CA's key moved. Open question 11.

**A refusal never makes anything worse.** A head that does not verify holds the deployer on the commit applied, through `HealthHandle::hold` (`docs/architecture/soft-state.md`, "A standing problem"). It does not prune, recreate or restart. It reports the commit, the reason, and how far it is behind.

## 7. Where a commit comes from

**A transport is not trusted, so there can be several.** That is what the handoff decided: "trust does not move with the hosting" (`cluster-bootstrap.md:117`). Three transports feed one rule: *take the furthest-ahead verified commit that descends from the one applied* (`source_choice`).

| Transport | Used | Auth |
|---|---|---|
| Polar's git server, `deploy-T` | at nominal | the deployer's Polar identity, mTLS, its key in the custody daemon |
| `deployer-seed` ConfigMap | at bootstrap and in recovery | none; it is data, and the operator's kubeconfig wrote it |
| `deployer-snapshot` ConfigMap | across a restart | none, likewise |

**At nominal.** The deployer polls `deploy-T` every minute (Dynamic), and `RepoChanged` over Cassini wakes it sooner. That is a hint: it causes a fetch and proves nothing. A server that answers nothing, or is empty, means no new commit (K4), and nothing else.

**At bootstrap.** *(for review)* The deployer must run before Polar, the bootstrap server's mTLS needs a client credential, and the deployment CA's key stays on the operator's machine, so the only ways to hand it a credential are a Secret or a ceremony. The seed needs neither:

1. As today: preflight, images, render, namespaces, the cluster CA, the secrets (`docs/architecture/cluster-bootstrap.md`, steps 1 to 7).
2. `publish`, signing locally, into `mirror.git` (`infra/deploy-repo.nu:78`). Today it clones from the server first and pushes before it updates the mirror (`:490-516`); it gains an `--offline` path that needs no server.
3. `infra/deployer.nu install`: verifies the head locally as `flux.nu` does (`infra/flux.nu:178-192`); makes `deployer-trust`; applies the deployer's own layer with `kubectl apply --server-side --field-manager=deployer`; writes `deployer-seed`.
4. The deployer starts with no identity (section 10), reads the seed, verifies it, and applies the layers in order. `infra/deployer.nu wait` follows `deployer-state`, as `flux.nu wait` follows the Kustomizations, and needs none of its stale-wait logic (H1).
5. Phase 3 is unchanged. The second publish, with the first admin's identity, goes the same way: signed, into the mirror, written as a seed.
6. **The handoff.** Once Polar's git server is up, the history is given to it: the admin's certificate pushes `mirror.git` to `deploy-T` (`cluster-bootstrap.md:132`). The deployer's URL has pointed there from the start, so at its next poll it finds the same commit and goes on. Nothing is switched over, and no bootstrap server needs to exist.

The seed is a pack of the head's whole tree and the commits back to the last one applied. The render is 706 KB as text and 64 KB compressed (measured, Flux's own controllers and the harness left out), against a ConfigMap's 1 MiB (*Kubernetes, from memory*), so it has room. A test keeps that margin visible.

*This changes something decided.* `cluster-bootstrap.md:128` has the configuration agent copy the repository from the bootstrap server. That was decided for Flux. With the seed there is no bootstrap server to copy from, so the deployment git server (step 8) could go. Open question 2.

**Recovery from a bad commit that stops the server** (`cluster-bootstrap.md:120`). Running pods keep running, the deployer keeps running, and if it restarts it has the snapshot. The way back is through the API server, because it is the one path the deployer needs anyway, and a bad commit that broke Services, DNS or a NetworkPolicy leaves a bootstrap server unreachable too.

1. The operator, with `mirror.git` and the PKI, makes the fix: `deploy-repo.nu revert <last-good> --offline`, a new signed commit, on top of the bad one, with the good one's tree. It needs no render, and a render would need the cluster (`cluster-bootstrap.md`, step 3).
2. `infra/deployer.nu seed <target>` writes `deployer-seed` with their kubeconfig.
3. The deployer verifies it, finds it descends from the commit applied, tells the attestation agent, and applies it. Polar's git server comes back.
4. The server's history is behind: `SourceBehind`, reported. The operator pushes the mirror. The fix descends from what the server holds, so `receive.denyNonFastForwards` (`store.rs:105-112`) takes it. They remove the seed.

A drill of this on a cluster is a milestone (section 20). A commit that cuts the deployer off from the API server, a NetworkPolicy say, is outside this: the operator has `kubectl`, and the deployer's report stops, which is itself the alarm. The doc's way back, a bootstrap server with the controller pointed at it (`cluster-bootstrap.md:120-121`), would work too, but it needs a credential, a Service, a volume and an image pull at the worst moment. Open question 2.

## 8. How a commit is applied

For each commit, in `ApplyActor`, with every step recorded so a restart resumes or repeats it harmlessly:

1. **Verify and parse** (section 6). Refuse the whole commit on any problem, before any write: an unknown kind, a Secret with data, a scope mismatch (B8), a document that is not an object (B4), an ambiguous YAML scalar (B6), an object over size (A9), a `wait_for` naming nothing (G13), a commit that would remove what the deployer itself needs (section 13).
2. **Record the attempt**: add the commit to `attempted` in `deployer-state` (E3).
3. **Announce it** to the attestation agent (section 11).
4. **Layer by layer**, in the order the commit declares, skipping one with no difference:
   - *Dry-run each object*, server-side, `fieldManager=deployer`, forced, `fieldValidation=Strict`, with no typed conversion on the way (B1). Compare the result with the live object, not the manifest (F1), and only labels, annotations, and everything but `metadata` and `status` (F2). What a stage's dry-run cannot yet judge, because its namespace is new, is said so (D6).
   - *Apply what differs*, stage by stage: Namespaces; Roles, ClusterRoles and classes; bindings; the rest in the table's total order (D1, D2, D4, D5). Force, since the signed commit is the authority (A1), and the report names any manager that lost a field.
   - *A refused write* is classified (`classify_refusal`). `Retry` backs off with a cap. `Hold` stops the layer, with the reason as structured causes and no values (J1), until a new commit: the same commit will not improve (H5).
   - *A change to an immutable field* is `Immutable(paths)`, and only a kind and path on the allowlist may recreate (C1, C6). A workload goes with foreground deletion and the new one waits until it is gone (C4). A claim is never recreated (C2).
   - *Wait*, if the layer's `wait_for` names something changed. The rules are ported from kstatus for the kinds used, with the generation rule first (G2, G3, G4), a read with no cache, and a deadline (G14). A forbidden read holds at once (G10).
5. **Prune** (section 9), after health, except an old workload with the same identity as a new one, which goes first (E2).
6. **Its own layer, last** (section 13).
7. **Finish:** `applied` moves on and `attempted` clears, the snapshot is written, and the report goes out.

**A newer commit ends a wait at once.** It is a message to `ApplyActor`; a wait is just `select`-ing on it. The current object finishes, and the plan is made again for the new commit, in which what was already done is `Unchanged`. This is the whole of what `flux.nu`'s restart (`infra/flux.nu:266-273`) works around (H1).

**Between commits,** `DriftActor` dry-runs the commit applied every 10 minutes (Dynamic), and asks for what differs to be applied. *A drift round may not prune or recreate*, and health holds nothing: a bad state found between commits is reported. So the only destructive things happen in answer to a signed commit. Each round also lists fields in pod templates owned by another manager, reports them, and leaves them (A7). `kubectl rollout restart` is therefore left alone (A3).

**A hold** is a per-layer entry in `deployer-state` with a reason and an expiry, read before each stage and between objects (H10). `neo4j-load.nu` and `load-harness.nu` set it where they suspend a Kustomization today (F7). The deployer acknowledges one by writing back the generation it saw, so the script knows it took. Holds are kept out of the signed path deliberately: they are an operator's, on their kubeconfig, for minutes, and they expire. *(for review)*

## 9. What may be deleted

**What is stale comes from signed trees alone.** `prune(applied_tree, attempted_trees, next_tree, live, bounds)`: an object is a candidate only if it is named in the tree of the commit applied or a commit attempted since, and in no layer of the next tree. An object no signed tree ever named can never be deleted. Nothing an attacker writes to the state record can name one. It covers what a failed apply created (E3), and what a failed delete left (E4), and moving between layers is nothing at all (E6). A commit in `attempted` that does not verify is ignored and reported. If a tree it needs cannot be fetched, as when the server is down, the prune waits: not pruning is always safe.

A candidate is deleted only if, read just before, it carries the deployer's label and its `managedFields` entry, and the delete carries `preconditions.uid` (the Reaper's rule, `docs/architecture/pod-reaper.md:110`). One that does not is an orphan, kept and reported each round (E5). Flux's labels do not count until its takeover is done (section 17).

**Never deleted by the deployer, and its role has no such verb:** *(for review)*

| Kind | Why |
|---|---|
| PersistentVolumeClaim | it is the data; `reclaimPolicy: Delete` on both classes |
| Namespace | it is everything in it |
| PersistentVolume | not rendered, and worse than a claim |
| CustomResourceDefinition | deleting one deletes every object of its kind; not in the table anyway |
| StorageClass | new claims would stop binding; never needed in a hurry |
| what `up.nu` creates (`cert-issuer-ca`, `polar-ca`, the secrets) | in no tree, so they are not candidates, and each is also named on a deny list that a commit naming one trips |
| the deployer's own objects, and `deployer-trust` | it would lock itself out (section 13) |

The instruction to delete one of these is a person, with their own credentials, after the deployer has reported it as an orphan and given the command. *(for review; open question 5.)* The maintainer asked for "explicit instruction". A signed `retire:` list in the commit would be the richer answer, but it would need the verb, and the verb is what makes a bug able to lose the data. These deletions are rare enough to be done by hand.

**Bounds.** A layer with no objects is refused (E1). A commit that would delete more than a set share of what is live, default 10%, is held and reported until a commit says so explicitly (`prune_limit` in `provenance.json`). A Dynamic setting can only narrow it.

## 10. Identity, and the builder

The deployer must start before Polar exists: it deploys the CA and Cassini. So identity and reporting are optional at start, and signature checking depends only on the deployment CA. Cert-issuer is the precedent (`src/agents/cert-issuer/server/src/agent.rs:39-44`): an agent that speaks over Cassini without depending on it. But it signs itself a certificate first, and the deployer cannot.

**The pod.** Kind `deployer`, extending `agent` in `infra/config/kinds.nuon`:

```
custody daemon     native sidecar, as in every pod
polar-init         native sidecar, not an init container (new)
deployer           the workload
```

`polar-init` already "never exits non-zero due to transient failures" and polls until the system is ready (`src/agents/polar-init/src/main.rs:34-36`). As an init container that would block the pod until cert-issuer exists, a deadlock. As a native sidecar it runs alongside, patiently, until the credentials agent can issue, and then stays. *(for review)*

**The builder's change.** Decided so that each state is one the builder already runs and tests:

1. `const LATE_IDENTITY: bool` on `PolarAgent` (`src/agents/polar-agent-builder/src/agent.rs:88`). With it, `Cassini` is optional as for the git server (`polar-git-server/server/src/agent.rs:37-38`, `polar-agent-builder/src/agent.rs:119-126`), and `effective_of` (`polar-agent-builder/src/agent.rs:425-434`) also asks whether the identity is here: the client certificate exists and the custody daemon holds it. Decided at the start of the process, like the existing choice.
2. **No identity:** it builds with `ServiceBuilder`: health, signals, the shutdown handshake, no client. `POLAR_HEALTH_CERTS` and `POLAR_CUSTODY_SOCKET` are not judged, so neither a missing file (`polar-health/src/certs.rs:51-54`) nor an empty daemon (`polar-health/src/machine.rs:164-166`) ends it. An `IdentityWatcher`, a small builder actor, notices the certificate.
3. **It becomes a client by restarting its container once.** On a certificate arriving, an orderly exit with code 75. The container's restart rule is `RestartAllContainers` on every exit *but* 75, so the kubelet restarts it alone, with the sidecars and key intact, and at its start it finds an identity. Attaching a client tree to a running process was considered: it would add a third state to the supervisor, and would make every domain handle a client that comes later. A restart is already safe (section 5). *(for review; open question 7.)*
4. **With an identity:** `AgentBuilder`, with `DEPENDS_ON_CASSINI = false` and `SELF_TEST = false` (`cert-issuer/server/src/agent.rs:42-44`), so a lost broker never fails it, which it must not while it replaces the broker.
5. **Rejuvenation** is as for any agent: a verdict, an exit, and the whole pod restarts. If the certificate runs out and nothing can issue, the floor's verdict restarts the pod, which starts with no identity, and goes on deploying: an outage of the credentials agent cannot stop the deployer. So the hourly restart costs seconds, and it is the same path every time.
6. `POLAR_START_MARKER` is not set for this kind (`src/agents/polar-agent-builder/src/start_marker.rs:36-39`): a container restarted alone is expected here.
7. `in_place_problems` (`infra/rules.nu:81-96`) learns the kind's exception, and `declaration_problems` (`polar-agent-builder/src/agent.rs:885-978`) refuses `LATE_IDENTITY` with `DEPENDS_ON_CASSINI = true`.
8. `polar-init` gains a flag to stay running once it has issued.
9. A capability, `KubeApiDeploy`, in `Capability` (`polar-agent-builder/src/capability.rs:41-60`) and `infra/config/capabilities.nuon`, kept in step by the existing test. Unlike `kube-api-read`, it uses the projected, expiring service-account token and **not** a `{workload}-sa-token` Secret (`capabilities.nuon:156-163`). Its rules are generated from the table of kinds, so that no one declares them twice.

**At nominal it is an agent like any other:** a certificate through `polar-init` and the credentials agent, the key in the daemon, attested by the attestation agent, in `polar`, so that `{polar-namespaces}` covers it (`infra/config/workloads/attestation.nuon`). Before that its pod is attested after the fact, like the core's (`runtime-attestation.md:91`). The identity is `deployer.polar.serviceaccount.cluster.local`, a reader of `deploy-T` and nothing else, on that server. No credential is in a Secret: the key is the daemon's, the Kubernetes token is projected, and the seed path has no credential at all.

It pulls with `IfNotPresent` by digest (`infra/rules.nu:178-186` allows this), so that a dead registry cannot stop it restarting. *(for review)*

## 11. Telling the attestation agent

Today (`runtime-attestation.md:217-236`): at issuance a pod is checked against its Deployment, and continually the Deployments against a signed record that `publish` writes, that the configuration agent reads and sends down the configuration path. "A pin changed behind Flux gets a certificate first and is caught at the next comparison", and before the handoff every identity is `CannotSay`.

**What the deployer adds:** step 3 of section 8 publishes the commit it is about to apply, before it writes anything. The attestation agent verifies it itself, and is not trusting the deployer, which is why this can be the same record and not a second one.

**What changes in `runtime-attestation.md`** *(for review)*:

1. *How the record arrives.* From the deployer directly, on `polar-deployment-intents`, instead of through the configuration agent and scheduler observer. One path fewer, and the window closes: what is about to run is known before it runs, and a pin that is neither in the applied record nor in an announced one is a mismatch at once. It reaches the agent while Cassini is up, and the deployer announces once per commit, before the first layer, so before anything can replace Cassini.
2. *What the record is.* The doc says "a `polar-signing` document ... signed by the `pipeline` certificate" (`:232`). **That cannot work as written:** `polar-signing` documents are Ed25519 or P-256 (`src/agents/polar-signing/src/document.rs:77-80`), and the pipeline's key is RSA 3072 (`deploy-repo.nu:214`). Instead: the raw commit and `provenance.json`, with the workload facts added to it. The agent runs `verify_commit` and checks the trailer (section 6). No second signing path, and one record. This affects step 3 of the order of work, whatever is decided here.
3. *The trust.* Unchanged: the agent trusts the deployment CA for this alone, and the CA's certificate reaches it through the signed render.
4. *Its version* is the commit's height, as written.

**The two checks stay two,** with the same reasoning as `:224-229`. The issuance check still compares a pod with its Deployment, since an agent's new pod may need a certificate before anyone could have told it anything. Nothing about a rollout now waits on the attestation agent.

**The announcement is asked and answered with a deadline.** Request and reply with a correlation id, as `attestation-instance-requests` is, 10 seconds by default (Dynamic). No answer, or no Cassini, and the apply goes on, recorded as "applied without acknowledgement". The attestation agent then attests after the fact. The maintainer decided this rule for its absence on 2026-11-02 (`runtime-attestation.md:268`), and it is what lets a commit that fixes the attestation agent reach it. An answer is believed only from the broker-stamped identity `attestation-agent`. A restarted attestation agent asks the deployer for the current commit, on the same topics.

## 12. Privilege, honestly

**It stays close to cluster-admin.** It creates ClusterRoles, and creating a ClusterRole means holding what it grants, or holding `escalate`. `kube-observer-read` grants get, list and watch on `*/*` (`infra/config/capabilities.nuon:164-165`). Flux's reconciler is bound to `cluster-admin` today (`flux-controllers.yaml:291`). The deployer's role is better written, not much safer against someone who has taken over its process.

| Verb | On | |
|---|---|---|
| get, list, create, patch | the kinds in the table, Secrets apart | named kinds, not `*` |
| delete | Deployment, StatefulSet, Service, ConfigMap, ServiceAccount, Role, RoleBinding, ClusterRole, ClusterRoleBinding | section 9: not claims, namespaces or classes |
| escalate, bind | roles, clusterroles | what makes it nearly cluster-admin (D5) |
| create, and get and patch by name | Secrets: the two named, or none (J2) | no `list` or `watch` on Secrets |
| get | Flux's Kustomizations, and only while it is here | section 17 |
| no verb | pods/exec, serviceaccounts/token, impersonate, nodes, admission configuration | |

**Honest limits.** With `escalate` a compromised deployer can grant itself the rest, so missing verbs stop a bug and not an attacker. What stops an attacker is that the process is small, runs no shell, holds its key out of reach, and is attested, and the sensor and the seccomp lock of slice C apply to it as to any agent (`runtime-attestation.md`, "Slice C"). Also, Polar's trust base already includes "the signed deployment", and a stolen pipeline key deploys anything with or without this agent.

A `ValidatingAdmissionPolicy` is the cheap second lock, a fact of the cluster and not of the deployer's code (the precedent is `pod-reaper.md:103,108`). It would refuse the deployer's identity a delete of a claim or a namespace, a write outside Polar's namespaces, and, in shadow mode, anything that is not a dry-run (section 16). It is applied by `up.nu`, in no layer, so the deployer cannot change it without first granting itself the right. It is not security against a takeover. It is a seat belt against our own bugs, and the operator owns it. *(for review)*

## 13. How it updates itself

It cannot replace itself mid-apply, so its own layer is last, and alone. *(for review)*

1. Its objects are a layer of their own (`deployer`), published in the tree, unlike Flux's (`infra/deploy-objects.nu:36-37`). So what it runs is signed and recorded like everything else. `up.nu` applies this layer the first time only.
2. In a plan its layer goes after all the others have settled. Its ClusterRole and ConfigMap go first, its Deployment last.
3. The commit is recorded as `applied` for everything else, with `self: pending`, *before* the Deployment is written. If the new version never starts, the record says what happened. The old version, still there, keeps working.
4. The roll is `RollingUpdate`, `maxSurge: 1`, `maxUnavailable: 0`, so the new pod must be ready before the old one goes. Ready means: it has verified the current commit, read its record and parsed its tree. It does not take the fence until the old pod has gone. A new image that cannot pull, crashes or cannot read its own state never gets there, the old pod stays, and the report says so.
5. A broken new version is fixed by a new commit naming the old image, which the old pod applies.
6. **What this does not catch:** a new version that is Ready and wrong, and prunes the wrong thing or corrupts its state. Against that: the bounds of section 9, missing verbs, the shadow run of a new version beside the old before it applies (section 16's mode remains available), and the operator's way back: `up.nu` applying the previous layer by hand. Rolling a state schema forward needs both versions to read it for one release.

It is checked that a commit does not remove what the deployer needs: a pure check refuses a commit whose ClusterRole for the deployer lacks what the table of kinds needs, or that drops its ServiceAccount, its binding, its Deployment or its ConfigMaps.

**This breaks a rule, so it is a question.** "No two pods of one identity at once" is decided (`docs/architecture/deployments.md:89`, `infra/rules.nu:94-96`). `instances: "many"` exists for several pods of one identity, each with its own certificate (`kinds.nuon:41-45`), and the fence means only one acts. The alternative keeps `Recreate`, runs the new image's `--check` as a scratch pod first (`infra/agent-pods.nu`'s way), and accepts that an image which passes that and then fails leaves no deployer until the operator comes. Open question 6.

## 14. Reporting, the record, settings

**It reports over Cassini, if there is one; it never needs to.** Exact topics, declared in `TOPICS`, with implied ones computed by the builder *(names for review)*:

| Topic | Access | What |
|---|---|---|
| `polar-deployment-intents` | publish | section 11's announcement |
| `polar-deployment-intent-replies.deployer` | subscribe | its acknowledgement, believed by broker-stamped identity |
| `polar-deployment-reports` | publish | each commit's outcome, each drift, refusal, hold and orphan; in shadow mode, what it would do |
| `polar-git-repo-changed` | subscribe | a hint to fetch (`polar_git_server_common::POLAR_GIT_REPO_CHANGED_TOPIC`) |

**The record** follows the project's shape: what acts does not hold the graph password, and what writes the graph writes only its own labels (`soft-state.md:161-177`). `deployer/record`, a small `NEEDS [GraphWrite]` agent on the `writers` pool like `soft-state-processor`, subscribes to the reports and owns `DeploymentCommit` (height, id, signer's serial, the source commit, when applied), `DeploymentObject` and `DeploymentEvent`, with an edge to the Kubernetes nodes `kube-consumer` already writes. The deployer stays out of the graph: it must work with Neo4j down, and a graph it could read would be a hint at best.

**What happened before Polar existed is not lost** (the provenance trail is not negotiable). `reported_to` is a height in `deployer-state`. On connecting, `ReportActor` walks the history from there, signed, and reports each commit. Drift seen while offline is logged only.

**Health** is the health actor's, and answered by the infrastructure (`soft-state.md`, "Self-state and introspection"), with `Hold` for a standing refusal. What it is doing is the domain's, and it makes that known by publishing it, not by being asked.

**Settings** *(for review)*:

| Setting | Mutability | Why |
|---|---|---|
| poll interval, drift interval, retry cap, health deadline, intent deadline, log level | Dynamic, through `polar-schedules` | non-secret, and each only narrows the bound the commit carries; a hint never widens a signed bound |
| prune share | Dynamic, narrowing only | |
| the repository URL | Static | "a wrong value cuts off the path its correction arrives on" (`remaining-work.md:594-595`) |
| the trust pin, signer name, target | Static | trust settings |
| layer order, `wait_for`, who applies which layer, `prune_limit` | **in the commit** | the deployment CA's word, so that a Polar administrator cannot widen what Polar is made from |

Before Polar exists they have their defaults, and the deployer must run with no scheduler: note 3 of the ConfigurationActor's design (`remaining-work.md:644`) already says so.

## 15. Protocol handlers, and the order of work

`protocol-handlers.md` fits the deployer closely, and the deployer is the strongest case yet for two of its open rows.

- **Git.** A handler that fetches with mTLS through the custody daemon, with the domain's callback given the fetched objects (`protocol-handlers.md:75`). The deployer's verify and parse are that callback: a pure function with no credential, its value returned as a message (`:88-96`). It is the only way to reach Polar's server with a custody key, since libgit2 cannot present a client certificate at all (K7). That also ends a recorded degradation: the scheduler observer is on key files only for this reason (`infra/config/workloads/scheduler.nuon:51-53`, `key-custody.md`, "Degraded operation", item 4).
- **Kubernetes.** The open question at `protocol-handlers.md:118` answers itself here: the domain should never see a token that can do this much, and apply, dry-run and retry are the same for every caller. It should be a handler, built with the deployer, read-only agents moving onto it later.
- **What differs.** A handler must work before Polar exists: with no Cassini, no held-report path, and no credentials section. That is a real requirement on the handlers' design, and worth stating before the HTTP handler is built (step 4).

**The order** (`remaining-work.md:32-45`). The deployer is not in it, and nothing in it should wait. *(for review; open question 10.)*

| Order of work | The deployer |
|---|---|
| 1 to 3: attestation and the handoff | Unchanged. The handoff goes ahead with Flux and the `flux` identity, as decided. Section 11's record format is worth settling at step 3. |
| 4: the HTTP handler | Comes first. The git handler shares its TLS, retry and redaction. |
| After 4 | M1 can run alongside 5 to 8, one person part-time. M1a can start sooner. It needs nothing from those steps. |
| 6: Dynamic settings | Its settings are declared Dynamic from the start, with the one reaction that step designs. |
| 8: slice C | The deployer gets the builder's lock with everyone. |

## 16. Shadow mode: the first thing it does

It runs beside Flux, reads, verifies and reports. It applies nothing. It is deployed as an ordinary agent with an identity (the bootstrap work of section 10 is not needed yet).

**What it reports,** each round and for each commit, per layer: every object's `Create`, `Configure(paths)` or `Unchanged`; what it would prune and what it would refuse to; each commit's signature, ancestry and digest result; drift, with the managers involved; its health verdict against Flux's; and its plan against Flux's `status.inventory`, which it reads.

**How the dry-run tells the truth.** A dry-run under its own manager name cannot show that a field would be removed, because Flux still owns it. So in shadow mode it dry-runs with `fieldManager=kustomize-controller` and Flux's two labels added, which is exactly the request Flux would make, and persists nothing. *(for review)* It needs the role's `patch` and `create`, because a dry-run is authorised as the real thing (*Kubernetes, from memory, not checked here*).

**Making "applies nothing" a fact.** A `ValidatingAdmissionPolicy` refuses every non-dry-run write by its identity (`request.dryRun`; *from memory, to confirm*). Its role has no `delete` yet. A cluster test tries to write and is refused.

**What it should be seen to get right before anything else happens,** on `u7c`, with each drill done on purpose:

- a `kubectl edit` of a field the manifest names, and of one it does not;
- a Deployment deleted by hand;
- a file added, a file removed, and an object moved between layers;
- a new digest, and a changed ConfigMap with its `polar.dev/config-hash`;
- a change to an immutable field, and an invalid manifest;
- an unsigned head, a tampered tree, a rewound branch, a commit from another target;
- the git server down, Cassini down, the deployer restarted during each;
- a rejuvenation during a health wait.

**To leave shadow mode, per layer:** every difference from Flux explained, and each explained one written down, for 14 days and 20 published commits on `u7c`, and the drills above. Those numbers are a starting point for the maintainer to change. What shadow mode is expected to find first: whether the port protocol still matters (B2), whether YAML parsing agrees (B6), and what strict validation says about the render (I3).

It stays useful afterwards: a new version of the deployer can be run in shadow beside the running one before it is trusted (section 13).

## 17. Takeover, migration, and the way back

From 3.0.0 a breaking change carries a migration (`remaining-work.md:28`). This is that migration, per layer, written up as `docs/operations/moving-to-the-deployer.md` and tried in place as `moving-to-sandbox-local.md` was. *(all for review)*

**The order is the reverse of the dependency chain:** `agents`, `identity`, `cassini`, `data`, `cert-issuer`, `platform`. A Flux layer's `dependsOn` reads its dependency's Kustomization (`kc:controller.go:595-599`), so a dependency cannot leave before what depends on it. `agents` is also the one whose failure stops the least: nothing depends on it, and it holds one claim. `platform` goes last, though it changes least, since everything sits on it. While both run, the deployer treats a Flux layer before its own as a dependency: it waits for that Kustomization to be Ready at the same revision, and reads no more of it than that. It prunes only in layers that are its own in both the old commit and the new.

**For one layer `L`**, each step reversible, with the deployer's shadow report clean for `L` at the start:

1. **A signed commit says so.** `provenance.layers[L].applied_by` changes to `deployer`, in the normal way. Before it applies anything the deployer checks its plan for `L` is `Unchanged` for all objects, or holds.
2. **`infra/deployer.nu adopt L`, the operator's:**
   a. Suspend the Kustomization (`spec.suspend: true`). A reconcile in flight carries on (H10), so wait for its `Reconciling` condition to clear, or restart kustomize-controller as `flux.nu` does.
   b. Save its `status.inventory` as a file beside the mirror, and into the report. That list is not an input to any decision. It is compared with the tree, and a difference is an orphan for a person.
3. **The deployer takes the fields**, for each object, with a precondition on `resourceVersion`:
   a. Server-side apply as `deployer`, forced, with Flux's two labels still in the manifest, so it co-owns everything.
   b. A JSON patch removes the `kustomize-controller` entry from `managedFields` (the technique of `ssa:patch.go:114-171`; A4 for the trap). The deployer is now sole owner, so a later removal from Git really removes (A2). `up.nu`'s kubectl entries go the same way, and a `last-applied-configuration` annotation is dropped (A9).
   c. An apply without Flux's labels, with its own label. The labels go, since no one owns them now. Nothing in a pod template changes.
   
   **The check:** no workload's `metadata.generation` moves, and no pod restarts. It is asserted on a cluster, and the takeover stops on a violation.
4. **The Kustomization stays suspended** for a soak, a week by default, as the way back. Then `adopt --finish`: delete it. It is suspended, so the finalizer deletes nothing (`kc:controller.go:1198-1201`, E7), and the test for that is on a cluster, with live claims under it, before any real run.

**The way back, for one layer:**

1. A signed commit sets `applied_by: flux`, or in a hurry, `infra/deployer.nu release L` with a hold. The deployer stops touching `L`.
2. Give the fields back. The JSON patch renames `deployer` to `kustomize-controller` in `managedFields`; or Flux does it, given `--override-manager=deployer` (`kc:main.go:125`, `kc:controller.go:958-968`), which exists for this kind of takeover. The deployer's name must not start with `kubectl`, which Flux's rule would eat (A3).
3. Unsuspend. Its inventory is intact, or if the Kustomization had been deleted, `flux.nu install` remakes it from the commit: an empty inventory prunes nothing and adopts by force (E13). What was added and then removed while the deployer held the layer is an orphan, reported.

**The way back has an end.** Until the last step below, a cluster can go back layer by layer. After it, a cluster goes back by the previous release's `up.nu`, which keeps Flux's chart and images for one release.

**Last, when every layer has moved:** delete the GitRepository; then the controllers, their ServiceAccounts, RBAC, NetworkPolicies, ResourceQuota, the CRDs when no custom resource is left, Secret `deploy-repo-auth`, and namespace `flux-system`. All by the migration script, since none of it is in any layer. In the repository, in that release: `flux` out of `sandbox-local`'s layers and charts; `flux.nu` and `deploy-objects.nu`'s Flux objects removed; the two mirror rows out of `images.nuon`.

**What else knows about Flux,** found while reading, and to change with it:

- `infra/neo4j-load.nu:32,55-59,104-105,124`, `infra/load-harness.nu:460-472`, and the `Justfile:498` recipe: suspend, to become holds.
- `src/agents/kubernetes/common/src/flux/` and `kubernetes/consume/src/supervisor.rs:254`: kube-consumer records Kustomizations and sources in the graph, to become `DeploymentCommit` and friends.
- `infra/up.nu`'s `flux` and `flux-wait` steps (`:970-971`), and `plan.nu:75-78`.
- The docs: `cluster-bootstrap.md` throughout, with its diagrams; the `runtime-attestation.md` section above; `placement.md:72`.

**A cluster on 3.0.0** moves the same way, by a step of the release that carries this, as `cluster-bootstrap.md:133` already says for the repository.

## 18. The costs, honestly

**This is permanent, critical code,** written by a small team, for a pod that can delete anything. It is written once and then kept: every Kubernetes minor (a new field, a new default, a removed version) is ours to read, and every Flux bug fix is one nobody hands us. Flux's maintainers have spent years on this list, and much of it was learned from other people's outages. The list above is what they found; we have not yet found what they have not, and a bug in our version is found on our clusters, first.

**What it costs in concentration.** It needs someone who understands server-side apply's field ownership deeply, and that person will be the only one for a while. With one senior engineer and a couple of part-time mid-level engineers, the deployer is one more thing only the senior engineer can change safely, and it competes with the items already in the order of work. The tests below, and the pure core, are what would let a mid-level engineer change it safely. They are not free.

**What it does not buy.** It does not make Polar safe from a stolen pipeline key, or from Kubernetes. It does not give health checks that mean more than Flux's on day one (G15). Flux stays in every cluster for months, so for that time there are two appliers, and more moving parts than today.

**A cheaper way to most of the security.** *(for review; open question 1.)* Stop after the source half, as a **verifying gateway**. The deployer's `SourceActor`, section 6's checks and section 11's announcement run as they are, and only a verified head is pushed to a read-only repository that Flux reads. Flux then cannot see an unverified commit. This keeps Flux's apply, with section 2's fixes around its edges. It gets: verified before applied, from Polar's own server, without trusting it; no rewinds; the attestation agent told first; identity and custody for the part that holds a credential. It does not get: one plan per commit, so E6 and D7 stay; a Polar-shaped prune; nor the removal of two Go controllers, which with the deployment git server and the resolver account for about 2 GB (`placement.md`, "Seen on the clusters"). Flux's own client credential goes too, if that repository needs none, being verified and not secret. It is perhaps a quarter of the work, and it is the first half of this plan anyway.

**What would make this not worth doing:**

1. *The threat is not worth it.* Verifying at push, plus Kubernetes as the trust base, leaves one gap: a compromised git server. If the maintainer judges that gap acceptable, or the gateway closes it well enough, then what remains is convenience, and convenience does not justify this code.
2. *Shadow mode does not converge.* If after a few months it still shows unexplained differences from Flux on 111 objects of plain YAML, that is evidence the problem is larger than this document thinks, and the answer is to stop, keeping the gateway.
3. *One data-losing bug on a development cluster during takeover.* That would say the design's main promise is not being kept. Stop and rethink, not patch.
4. *Polar's render grows:* Helm, CRDs with conversion, overlays, tenants, other clusters. Each makes Flux's generality worth its cost. The `polar-operator` conversation is the one to watch.
5. *No one can own it.* If it would be only one person's, indefinitely, the bus factor on the thing that can delete the cluster is the wrong trade.
6. *Upstream closes the gap.* If Flux gains x509 verification and file-based credentials, the top of section 1 falls away, and with it most of the case.

**The agent's own view, for what it is worth.** Build M1, the shadow (section 20): it is useful alone, risks nothing, and tells everyone what the rest costs. Decide about takeover with shadow mode's numbers in hand.

## 19. Tests, written first

As `AGENTS.md` asks, tests first, and properties beside the examples (`deployer/common/tests/props.rs`). These are the properties, each an invariant of the code, not of its generator.

**Parsers and encoders**

- `VerifiedCommit` parse: for any commit bytes, what it returns is what was verified; a duplicated `tree`, or any malformed header, is refused. No input panics.
- Typed object key: round trip; a malformed one is refused.
- State record and seed: round trip; a changed byte in a seed is refused, by digest or by signature, and never read as other content.
- Strict YAML: for any document in the subset, YAML to JSON matches the API's reading (a corpus from the render, plus generated scalars); anything outside it is refused, never read differently.

**Decisions**

- `prune`: for any trees, live set and bounds: only objects a signed tree named are candidates; nothing in the next tree is ever deleted; no claim, namespace, class or own object is ever in the result; an object without the deployer's label and entry is reported and not deleted; an empty next layer is refused; over the share is refused.
- `source_choice`: never chooses a commit that does not descend from the applied one; independent of the order of transports; a transport's failure changes nothing.
- Verification chain: for any change to a file, a trailer, a commit in the walk or a parent, refused. A commit for another target is refused.
- `classify_dry_run`: changing an excluded field (`resourceVersion`, `generation`, `managedFields`, `status`) is `Unchanged`; changing any included one is `Configure`.
- `classify_refusal` and `recreate_allowed`: a 409 or 422 without an allowlisted path is never `Immutable` (the opposite of C1); a claim is never recreated, for any status.
- `health`: with `observedGeneration` behind, never `Current`, for any status; with `deletionTimestamp`, never `Current`.
- A report: for any live Secret, no field of any report, log line or error contains a value of its `data` (J2).

**Computed sets**

- The desired set and `stages`: deterministic, independent of file and document order, and the union of the layers.
- The deployer's role: generated from the table, and it holds exactly what the table asks.
- Self-preservation: a commit whose role for the deployer lacks what the table needs is refused.

**State machines** (`next`)

- For any sequence of events, a crash at any point included: `applied` only moves forward along history; nothing is written before the attempt is recorded; nothing is pruned before health or before the record; a drift round never prunes or recreates; its own layer is last; after any crash and resume, the union of `applied` and `attempted` covers everything that may have been written.
- The takeover: for any sequence of steps and crashes, no step deletes, and each is safe to repeat.

**Mutations to be caught,** each by a named test: `IsImmutableError`'s test copied over (any 422 recreates); verifying only the head; verifying the head but not the trailer; verifying at `now` on the applied commit; prune before the attempt record; prune computed per layer; a drift round allowed to prune; `delete` granted on claims; the fence not checked; a Secret's `data` in `Debug`; a typed round trip (a field the types do not know is dropped); ignoring a hold; own layer not last; the announcement after the first write; `LATE_IDENTITY` making a missing certificate a verdict.

**On a real API server** (a throwaway one in containers, as the graph tests use Neo4j, needing `DOCKER_HOST`): each row of the immutable table (C6); Role and RoleBinding as a non-admin (D5); strategy change (C7); dry-run response of a token Secret (J2); `fieldValidation=Strict`; deleting a suspended Kustomization with claims under it (E7).

**On `u7c` and a fresh `u7s`:** section 16's drills; kill the process at every step of a real commit; takeover and the way back, for each layer, with no generation moving; a bring-up from nothing with no Flux; the recovery drill from `mirror.git`; a self-update, one with a good image and one with a bad one. Anything timed in release builds only.

## 20. Milestones, in order

Each is reported before the next, tests first. **M1, the shadow, is first, and changes nothing on a cluster.** It is the point to stop and decide. It is large, so it is taken in three bites, and each is useful alone.

| | Milestone | Needs | Outcome |
|---|---|---|---|
| M1a | **Shadow, the record and the core.** `publish`: trailer, provenance schema 2 (layer order, `wait_for`, workload facts), no signing on an unsigned parent, certificate margin. `deploy-repo.nu publish --offline` and `revert`. `verify_commit` returns `VerifiedCommit`. `deployer/common`: parse, the verification chain, the pure functions, properties. | nothing | No cluster. Section 2's fixes alongside. |
| M1b | **Shadow, the verifying source.** The git handler with custody; `deployer/agent` as an ordinary agent, reading, verifying, reporting; `deployer/record`. | the HTTP handler (step 4) | Every commit's verdict reported. The gateway is possible from here (section 18). |
| M1c | **Shadow, the plan.** Dry-runs, plan, prune plan, health, drift, comparison with Flux. The admission policy. The drills. | M1b | The numbers that decide the rest. **Decision point.** |
| M2 | **Telling attestation.** The intent and its answer; the record format. | M1b; order of work step 3 | The window in `runtime-attestation.md` closes, with Flux still applying. |
| M3 | **The apply engine,** on a scratch cluster and a scratch layer, none of Polar's. Crash tests. Real API server tests. | M1c | Confidence without risk. |
| M4 | **Takeover of `agents`,** on `u7c`, with the way back shown. Holds replace `suspend` for this layer. | M3 | The first real writes. Soak. |
| M5 | **`LATE_IDENTITY`,** the kind, `polar-init` as a sidecar. | M4 | It can restart with the core down, which the next needs. |
| M6 | **Takeover of `identity`, `cassini`, `data`, `cert-issuer`, `platform`,** one at a time, each soaked. | M5 | No layer left on Flux on `u7c`. |
| M7 | **Bootstrap with no Flux:** the seed, `deployer.nu install`, self-update, the recovery drill. | M6 | A fresh cluster, and a broken one, from nothing but `mirror.git`. |
| M8 | **Flux out:** the migration document, tried in place; the release that carries it; the other code that knew about Flux. | M7 | Done, after one more release with the way back. |

## 21. Size, as a guess

*A guess.* Its basis: Polar's own `soft-state/process` is about 1,800 lines and `polar-git-server/server` about 2,700 (counted). What is replaced in Flux is about 1,470 (the controller), 2,200 (the apply, diff, delete, wait, sort, patch and normalize of `ssa`), 730 (kstatus's rules) and 1,420 (the git reconciler), much of it for features out of scope here.

| Part | Lines of Rust, tests included |
|---|---|
| `deployer/common`: table, parse, chain, plan, prune, health, state machine | 3,000 to 4,000 |
| `deployer/agent` | 2,000 to 2,500 |
| `deployer/record` | 500 |
| git and Kubernetes handlers | 1,000 to 1,500 |
| builder, `polar-init`, `verify_commit` | 500 |
| `infra/`: `deployer.nu`, `publish`, the kind, the policy, in Nushell and Dhall | 800 |

About 8,000 to 10,000 lines. For one senior engineer alone, about four to six months' full-time work for all of it, half of that for M1; with the time actually available among other work, perhaps 9 to 12 months elapsed, longer with soaks. Afterwards, perhaps one or two days a month of upkeep, more in the month of a Kubernetes minor. The gateway alone is perhaps a quarter of this. None of these numbers has been tested by anything.

## 22. Open questions for the maintainer

Each with a recommendation. Asked one at a time, when reached.

1. **Is the goal the deployer, or is the gateway enough for now?** *Recommendation:* build M1 either way, since the gateway is on the way, then decide with shadow mode's numbers. The security gain is in M1b. The rest is mostly the benefit of one plan per commit and removing two controllers.
2. **The seed, and the bootstrap server.** With the seed there is no credential to find, and recovery needs only the API server. But `cluster-bootstrap.md` has a bootstrap server, a copy by the configuration agent (`:128`), and a way back through that server (`:120`). *Recommendation:* the seed, for bootstrap and recovery; retire the deployment git server at M7. *Else:* keep the server and let its deployment repository be read without a client certificate, since what is in it is verified and not secret; that changes `polar-git-server`'s rule that every connection authenticates (`tls.rs:28`).
3. **The record as commit plus trailer, rather than a `polar-signing` document** (section 11). The document as written cannot be signed with the pipeline's RSA key. *Recommendation:* the trailer, and settle it at order-of-work step 3, which needs an answer anyway. *Else:* a P-256 signing certificate in the deployment PKI.
4. **Does Polar want the deployment facts in `provenance.json`,** or a file of their own beside it? *Recommendation:* in it, schema 2. One record, one digest.
5. **Deleting a claim or a namespace.** "Explicit instruction" as a person with `kubectl` after a report, with no verb for the deployer; or a signed `retire:` list and the verb. *Recommendation:* the person. Reopen if it is ever frequent.
6. **A rolling update for the deployer alone,** against "one pod of an identity at a time" (section 13). *Recommendation:* allow it, by `instances: "many"` and the fence: a `Recreate` with a bad image leaves no deployer at the moment one is most needed. *Else:* `Recreate` with a scratch-pod check first.
7. **Becoming a client by restarting one container (exit 75),** or attaching one in-process. *Recommendation:* the restart, as simpler and already safe.
8. **Drift: correct it, or only report it?** *Recommendation:* correct what the manifest names, as Flux does and as Polar has relied on; report what it does not name, and remove nothing of that (A7). *Worth asking:* for `data` and `cert-issuer`, should correction wait for a person?
9. **Is a Deployment's `Available` enough, or should a layer gate ask the agent's own health actor?** No agent has a readiness probe (G15), so `Available` says little. *Recommendation:* same as Flux through takeover, for a fair comparison; then, once Cassini is up, a `wait_for` can ask `agent.<name>.health`, the infrastructure's own answer. Before Cassini, the old rule. It is the one real improvement in reliability on offer here.
10. **Where in the order of work?** *Recommendation:* M1a alongside step 3, since the record format is shared; M1b after step 4; the rest as the maintainer chooses, and no step already listed waits for it.
11. **The deployment CA's key, and the `pipeline` key, in one directory** (section 6). Today that is one failure. *Recommendation:* accept it for now and write it down; move the CA's key off the working machine before anyone runs this outside development.
12. **The shadow exit: 14 days and 20 commits, per layer?** *Recommendation:* those, as a floor, and the maintainer's judgement over them.
13. **The namespace rule of section 4,** refusing an object outside the tree's namespaces. *Recommendation:* yes, cheap, and it catches a real mistake.

## 23. What was not checked

- **Nothing ran.** No Flux code, no deployer code, no cluster. Findings marked "read, not run" or "derived from the code" are readings, and H1's gate especially should be tried before anyone relies on it.
- **Kubernetes itself was not read.** Statements about its behaviour are marked where they are from memory: ConfigMap and annotation limits, immutability by kind, what a dry-run needs and returns, `request.dryRun` in admission, list-map ownership. M3's tests against a real API server are there to settle them.
- **The `kube` crate was not read for this.** The agent uses it (`attestation/agent/src/supervisor.rs:133-135`), and it is assumed to expose server-side apply, dry-run and `fieldValidation`. The workspace pins `k8s-openapi` to 1.35 features (`src/agents/Cargo.toml:126`), and the plan uses dynamic objects, so that should not matter.
- **Flux, partly.** Read: the kustomize controller, `ssa`, kstatus's rules and readers, the runtime's reconcile wrapper and Job reader, the git reconciler and clone, artifact storage and fetch, the changelogs. Skimmed or not read: the SOPS decryptor, Helm, OCI and bucket reconcilers, go-git, Kustomize itself, `runtime/patch`, `kstatus/watcher`, and the Kustomization API's documentation. The issue tracker: only #187, #734 and #1664 were read, with a few searches. Stated absences ("no handling found") could be wrong for that reason.
- **The render** was read as it stood in the main checkout on 2026-11-02, not regenerated. Its counts will drift.
- **Libgit2 at musl with an in-memory or pack-only store** was not tried. Its use in `git/observe` and `polar-scheduler/observer` suggests it builds, but not that this use works.
- **Does the seed's size margin hold with history?** Measured for one tree only.
- **Whether a NetworkPolicy is enforced** on Polar's clusters was not checked; no decision here rests on it.
- **The restart rule with an exception.** `RestartAllContainers` was tried on a cluster with `NotIn []` (`deployments.md`, step 4), not `NotIn [75]`. Section 10 rests on it, and M5 tries it first.
- **Sizes and durations** in section 21 are guesses.
