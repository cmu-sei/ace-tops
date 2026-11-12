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

# What Flux has absorbed: apply, ownership and reconciliation edge cases

> **Evidence for [the deployer's plan](../deployer.md).** Written 2026-11-02 for an earlier form of that plan, then called
> `gitops-controller.md`; references to its sections ("section 8", "`gitops-controller.md`, section 2") are to that
> version, which is in this file's history (`git log --follow`). Citations of Polar's code are at `eada654b` and have
> drifted; the plan's Claude side (`../deployer.claude.md`, FACTS@main) holds the current ones.

Status, 2026-11-02: a review for the proposal in `gitops-controller.md`. Nothing here is built. It was made by reading Flux's source at the versions Polar pins. No Flux code
was built or run for it, so "what goes wrong" is what the code says would happen, unless an entry says it was seen. The maintainer: this list alone justifies the review.

## How to read it

Polar pins Flux 2.9.6 with controllers v1.9.6 (`infra/layers/1-platform/services/flux/flux-controllers.yaml:22,2637,3563`). The module versions come from the controllers' own `go.mod`
(`kc:go.mod:21-36`, `sc:go.mod:25-45`), and each clone's commit was checked against `git ls-remote`.

| Short | Repository and directory | Version | Commit |
|---|---|---|---|
| `kc:` | fluxcd/kustomize-controller | v1.9.6 | `060e0d8d` |
| `kc:controller.go` | the same, `internal/controller/kustomization_controller.go` | | |
| `sc:` | fluxcd/source-controller | v1.9.6 | `456fa323` |
| `sc:gitrepo.go` | the same, `internal/controller/gitrepository_controller.go` | | |
| `ssa:` | fluxcd/pkg, `ssa/` | ssa/v0.76.2 | `e6a5381e` |
| `rt:` | fluxcd/pkg, `runtime/` | runtime/v0.110.3 | `0a4cdb46` |
| `git:` | fluxcd/pkg, `git/` | git/v0.52.0 | `3f9f27f0` |
| `art:` | fluxcd/pkg, `artifact/` | artifact/v0.18.3 | `e6a5381e` |
| `kz:` | fluxcd/pkg, `kustomize/` | kustomize/v1.35.7 | `ac8d40bc` |
| `fetch:` | fluxcd/pkg, `http/fetch/` and `sourceignore/` | http/fetch/v0.25.0, sourceignore/v0.18.0 | `f3ad4b56` |
| `cu:` | fluxcd/cli-utils (a fork; `kstatus` is not read from kubernetes-sigs/cli-utils) | v1.2.3 | `8155c124` |

Each entry says what goes wrong, how Flux handles it, whether it applies to what Polar renders, and what the controller must do: **handle** it, **avoid** it by construction, or **not support** it,
with why. Section numbers such as "section 8" are `gitops-controller.md`'s.

What Polar renders was read from `manifests/` in the main checkout, as rendered on 2026-11-02 at 17:49 (not rendered again for this): 135 objects of 17 kinds. Of those, Flux's own controllers are 22, and all 7
CustomResourceDefinitions, all 3 NetworkPolicies and the one ResourceQuota are among them. They are in no layer Flux reconciles (`infra/deploy-objects.nu:37`). The two Jobs are `rendered_only` (`infra/targets/sandbox-local/target.nu:194`).
So the layers Flux applies today are 111 objects of 13 kinds: Namespace, ServiceAccount, StorageClass, Role, ClusterRole, RoleBinding, ClusterRoleBinding, Deployment, ConfigMap, PersistentVolumeClaim, Service, StatefulSet and Secret.

The issue tracker was reachable through GitHub's API. Only the issues cited were read, and the search was not exhaustive. Statements about Kubernetes that are not from Flux's code are marked *(Kubernetes, from memory, not checked here)*.

## The count

112 entries: 60 apply to what Polar renders, 14 in part, and 38 do not. Of the 105 that are not grouped under M: the controller handles 57, avoids 34 by construction, and does not support 14.

## A. Field ownership and takeover

**A1. A conflict never stops an apply.**
*Wrong:* another manager owns a field the manifest sets, and server-side apply answers 409.
*Flux:* every dry-run and every apply is sent with force ownership, so Flux always wins and a conflict never shows (`ssa:manager_apply.go:422-437`).
*Applies:* Yes. `up.nu` applies namespaces with `kubectl`, and an operator's `kubectl edit` is another manager.
*We:* **Handle.** Force too: the signed commit is the authority. Read the live `managedFields` first, and report which manager lost which field.

**A2. A field removed from the manifest stays, because another manager also owns it.**
*Wrong:* an object first made by `kubectl apply` is co-owned by `kubectl-client-side-apply`. Removing the field from Git removes Flux's claim and not kubectl's, so the field stays forever.
*Flux:* before each apply it rewrites the entries of `kubectl*` (Apply and Update), `before-first-apply` and its own Update entries into its own Apply entry, merging the field sets (`kc:controller.go:935-956`, `ssa:patch.go:114-171`, `ssa:manager_apply.go:476-517`).
*Applies:* Yes. `up.nu` applies `namespaces.yaml` with `kubectl apply` before Flux runs (`infra/up.nu:964`, `docs/architecture/cluster-bootstrap.md:149`), and `flux.nu install` applies with `kubectl` (`infra/flux.nu:213`).
*We:* **Avoid** on a new cluster: `up.nu` applies with `--server-side --field-manager=deployer`, so there is no second manager. **Handle** at takeover, once, as a named step (section 17). No standing rule rewrites another manager's fields.

**A3. Rewriting by prefix also undoes `kubectl rollout restart`.**
*Wrong:* the prefix `kubectl` matches every Update entry with no subresource whose manager starts with it (`ssa:patch.go:71-80`), so `kubectl-rollout`, `kubectl-edit` and `kubectl-annotate` too. The annotation `kubectl rollout restart` sets in a pod template becomes Flux's, is absent from the manifest, and the next apply removes it, which rolls the workload a second time. Read, not run.
*Flux:* intended for edits; the comment says "to undo changes made with 'kubectl apply'" (`kc:controller.go:942-945`). The restart is a side effect.
*Applies:* Yes. Polar's own message tells an operator to run `rollout restart` after a secret changes (`infra/secrets-lib.nu:105`).
*We:* **Avoid.** No prefix rule. An operator's restart stands, and is reported as a foreign field.

**A4. An empty `managedFields` is ignored, so it takes one empty entry to clear it.**
*Wrong:* removing every manager with an empty list does nothing.
*Flux:* it sends a list of one empty entry (`ssa:patch.go:105-107`).
*Applies:* Partly. Only if the takeover ever clears the list, which section 17 does not plan.
*We:* **Handle.** The takeover rewrites entries and never empties the list; a cluster test pins what it leaves.

**A5. Ownership labels on every object.**
*Wrong:* something must say which applier an object is for, or one layer's prune could delete another's object.
*Flux:* it adds `kustomize.toolkit.fluxcd.io/name` and `/namespace` to every object's own metadata, not its pod template (`ssa:manager.go:66-78`, `kc:controller.go:478`), and deletes only what carries them (`kc:controller.go:1450`, `ssa:manager_delete.go:77-85`).
*Applies:* Yes. Every object on a running cluster carries them, and `infra/neo4j-load.nu:57-58` reads them to find what to suspend.
*We:* **Handle.** Prune requires the deployer's own label and its entry in `managedFields`. Flux's labels are removed in the takeover's last step, and they do not touch a pod template, so no pod restarts.

**A6. An annotation on the live object turns Flux off for it.**
*Wrong:* `reconcile: disabled`, `ssa: Ignore`, `ssa: IfNotPresent`, `force: enabled` and `prune: disabled` are all read from the live object as well as the manifest, case-insensitively (`kc:controller.go:901-910,1451-1455`, `ssa:manager_apply.go:543-561`, `ssa:utils/meta.go:61-71`). Anyone who can annotate an object can stop it being managed, and the only trace is a `skipped` entry.
*Flux:* a feature; `ssa: Merge` also skips the manager cleanup (`kc:controller.go:983-985`).
*Applies:* No. `infra/` sets none of them (searched `.nu`, `.dhall` and `.nuon`).
*We:* **Avoid.** Control travels signed: what the deployer may skip is in the commit. The one exception is a per-layer hold an operator sets in the state ConfigMap (entry H10), which is logged and reported.

**A7. What another manager adds is never drift.**
*Wrong:* a sidecar or an environment variable added by another manager merges into the dry-run result as well as the live object, so comparing the two shows nothing. A list-map item, such as a container, has its own owner (*Kubernetes, from memory, not checked here*).
*Flux:* by design: it compares the merged result with the live object (`ssa:manager_diff.go:141-163`).
*Applies:* Yes. Polar's attestation rests on Deployments matching the signed record (`docs/architecture/runtime-attestation.md:224-231`).
*We:* **Handle, by reporting.** Each round lists fields in a pod template owned by a manager other than the deployer. It removes nothing: whoever can do that is inside the trust base, and the attestation agent compares each container with the record anyway.

**A8. A `managedFields` entry at an old API version fails the apply.**
*Wrong:* after a CRD adds a defaulted field in a new version, an entry at the old version makes the server answer "field not declared in schema".
*Flux:* an opt-in gate rewrites every entry's `apiVersion` (`ssa:manager_apply.go:439-471`, `ssa:patch.go:186-211`, `kc:internal/features/features.go:59-69`, `kc:CHANGELOG.md:211-214`).
*Applies:* No. It is a CRD problem, and no layer holds a CRD.
*We:* **Not support**, until Polar renders a versioned CRD.

**A9. Client-side apply's annotation hits a size limit.**
*Wrong:* `kubectl apply` keeps the object in `last-applied-configuration`, limited with the object's other annotations to 256 KiB (*Kubernetes, from memory, not checked here*). `polar/credentials-agent-config` is 170,601 bytes as rendered, two-thirds of the way there.
*Flux:* it applies server-side, and removes the annotation from what it adopts (`kc:controller.go:971-977`).
*Applies:* Yes. It is what makes a large ConfigMap safe today.
*We:* **Avoid.** Server-side apply only. The verifier refuses an object over 1 MiB, the limit a ConfigMap has (*Kubernetes, from memory, not checked here*), naming it, so a render that grows finds out before the cluster does.

**A10. Older Flux's labels and annotations.**
*Wrong:* objects from old Flux versions carry `fluxcd.io/sync-*`.
*Flux:* removed on sight (`kc:controller.go:974-981`).
*Applies:* No. Polar was never on those versions.
*We:* **Not support.** Nothing to do.

## B. Reading what was rendered

**B1. A round trip through typed objects drops what the types do not know.**
*Wrong:* before applying, Flux converts every object except Role and ClusterRole to its Go type and back (`ssa:normalize/normalize.go:47-62,96-101,124-136`, `kc:controller.go:891`). The conversion is not strict, so a field newer than the compiled types is dropped without a word. The types are Kubernetes 1.36 (`kc:go.mod:49`), and Polar's cluster is 1.37.1 (`docs/architecture/runtime-attestation.md:148`). Roles are skipped because the round trip reset their rules (`kc:CHANGELOG.md:710-714`, issue #1041).
*Flux:* accepted; a Flux upgrade brings new types.
*Applies:* Yes. A 1.37 field in a manifest would be applied by nothing, today, and say so nowhere. Read, not run.
*We:* **Avoid.** No typed round trip. YAML becomes JSON and goes to the API as written, with `fieldValidation=Strict`, so the server that knows its own version refuses what it does not know.

**B2. A port with no protocol.**
*Wrong:* a port without `protocol` caused server-side apply trouble because `protocol` is a list key (structured-merge-diff issue 130, cited in the code).
*Flux:* it writes `TCP` into Service and container ports (`ssa:normalize/normalize.go:208-229`). Flux does not do it for init containers.
*Applies:* Partly. 9 rendered documents with container ports name no protocol. Whether the problem remains on Kubernetes 1.36 and later was not checked.
*We:* **Handle.** Shadow mode answers it (section 16). If it is still there, `rules.nu` requires the field in the render, rather than a step at apply time rewriting it.

**B3. `status` and an empty `creationTimestamp` in a manifest.**
*Wrong:* they cause refusals or false differences.
*Flux:* removed, except a CRD's `status`, which kstatus reads (`ssa:normalize/normalize.go:154-163`).
*Applies:* No. No rendered object carries a top-level `status` (checked).
*We:* **Avoid.** The verifier refuses a manifest with `status`, rather than editing it.

**B4. A document that is not an object is dropped silently.**
*Wrong:* a YAML document with no kind or name disappears, and a `List` is flattened (`ssa:utils/object.go:44-77`). What vanished is then stale and pruned.
*Flux:* intended; the build step would usually fail first (`kc:controller.go:835-840`).
*Applies:* Partly. The render makes none, but a render bug could.
*We:* **Avoid.** Every document must be one of the kinds in the table, or the commit is refused, whole.

**B5. Kustomize runs on plain YAML.**
*Wrong:* Flux generates a `kustomization.yaml` in any directory (`kz:kustomize_generator.go:525-570`), including an empty placeholder (`:559-563`), and a `kustomization.yaml` in a subdirectory is taken as a base (`:588-596`), so a stray file changes what is built. Kustomize can panic on bad data, which Flux recovers from twice (`:615-622,688-695`), and needs a process-wide mutex (`:683-686`).
*Flux:* contains it.
*Applies:* No. It is machinery Polar does not use: Polar renders no overlays.
*We:* **Avoid.** No Kustomize. A file is applied only if `provenance.json` lists it with its digest, and one it does not list refuses the commit.

**B6. Go and Rust read YAML differently.**
*Wrong:* the API's YAML is 1.1-flavoured (`yes`, `on` and some octals are not strings); a YAML 1.2 parser, such as the workspace's `serde_yaml` (`src/agents/Cargo.toml:159`), reads them otherwise (*from memory, not checked here*). A value could reach the API as a string where `kubectl` would have sent a boolean, and duplicate keys need a decision.
*Flux:* it is on the Go side, so it does not have the problem.
*Applies:* Yes, for us alone.
*We:* **Handle.** The parser takes a strict subset: it refuses any plain scalar on which the two differ, and duplicate keys. A test runs over every rendered file, and shadow mode compares the result with Flux's on the cluster.

**B7. `stringData` looks like drift.**
*Wrong:* `stringData` never comes back from the API, so an object with it always differs.
*Flux:* it moves `stringData` into `data` (`ssa:normalize/normalize.go:231-243`).
*Applies:* No. The render's two Secrets are service-account-token placeholders with neither field.
*We:* **Not support.** A manifest Secret with `data` or `stringData` is refused: secrets are never in the render (section 8).

**B8. A namespace on a cluster-scoped object, or none on a namespaced one.**
*Wrong:* the server strips it, the inventory's identity no longer matches the object, and the object looks stale. A regression of this class deleted and recreated non-namespaced objects on every reconcile (`kc:CHANGELOG.md:195-197`, `ssa:manager_apply.go:538-548`). A namespaced object with none answers "not found" (`ssa:errors/errors.go:54-57`, `kc:CHANGELOG.md:710-711`).
*Flux:* prefers the live object's identity for skipped entries, and improves the message.
*Applies:* No. Checked: every namespaced object in the render names its namespace.
*We:* **Avoid.** The closed table of kinds gives each its scope, and a mismatch refuses the commit.

**B9. A CRD with an invalid CA bundle.**
*Wrong:* Kubernetes 1.31 and later refuses it.
*Flux:* removes it before applying (`ssa:utils/cert_validation.go:62-66`, `ssa:manager_apply.go:232`).
*Applies:* No. No CRD in any layer, and no conversion webhook.
*We:* **Not support.**

## C. Immutable fields and recreating

**C1. "Immutable" means any 409 or 422.**
*Wrong:* `IsImmutableError` is true for every Conflict and every Invalid (`ssa:errors/immutable.go:32-37`). So with `force`, a manifest with any validation error has its running object **deleted**, and then fails to create. The code knows: "the check for ImmutableError returns false positives" (`ssa:manager_apply.go:254-257`). Issue #734 is a Service lost this way. A Flux maintainer there: "No Flux Kustomization should have `force: true` in the spec on the long run", and a reporter: "it triggers a recreate on an object if something like a label reports a validation error".
*Flux:* documented advice to set it briefly, or per object by annotation.
*Applies:* Yes, on Polar's Flux until recently. `publish` set `force: true` on a layer holding a Job, for good (`infra/deploy-objects.nu:65-68,138`, `infra/deploy-repo.nu:397`). No layer holds a Job now, so no layer has it (checked against the render), but a Job added to a layer would bring it back with no warning.
*We:* **Handle.** A recreate needs a kind and a field path on an allowlist, read from the structured causes of the 422, and judged by a pure function. Any other refusal holds the layer and reports. Today: give `has_job`'s `force` a test that fails when it fires, or remove it (`gitops-controller.md`, section 2).

**C2. `force` reaches everything in the layer, a claim included.**
*Wrong:* `force` is per Kustomization (`kc:controller.go:900`), and four of Polar's layers hold a PersistentVolumeClaim beside workloads. A class or size change on a claim is refused with 422 (*Kubernetes, from memory, not checked here*), so under `force` the claim, and the data behind it if its class deletes on release, goes. `reclaimPolicy: Delete` is what `local-path` and `managed-csi` say (`manifests/local-path-provisioner.yaml:142`, `manifests/storage-class.yaml:7`).
*Flux:* no special case for claims.
*Applies:* Yes, with C1.
*We:* **Avoid.** The deployer's role has no `delete` on claims or namespaces, so no bug of ours can do it (section 9).

**C3. Waiting for a recreate's deletion has no deadline.**
*Wrong:* after the delete it polls until the object is gone, under the reconcile's context (`ssa:manager_apply.go:264-277`), and that context has no deadline: `MaxConcurrentReconciles` and `RecoverPanic` are all the controller sets (`kc:main.go:235-238`). A stuck finalizer holds a worker for good. `spec.timeout` reaches only the health wait (`kc:controller.go:1102-1107`), though the status message says otherwise.
*Flux:* none, beyond restarting.
*Applies:* Yes. A pod's or a claim's protection finalizer can hold.
*We:* **Handle.** Every step has a bound, and an overrun is a report and a hold.

**C4. A recreate's background delete leaves the old pods running.**
*Wrong:* the owner goes at once and its pods later (`ssa:manager_apply.go:259`), so the new workload's pod runs beside the old one. For one identity with one ledger that is how Polar's ledger fork of 2026-10-26 happened (`docs/architecture/deployments.md:34`).
*Flux:* background always.
*Applies:* Yes. Polar's rule is one pod of an identity at a time (`infra/rules.nu:89-96`).
*We:* **Handle.** A workload is recreated with foreground deletion, and the new one is applied only when the old is gone.

**C5. A Job's pod template cannot change.**
*Wrong:* so a changed Job can only be replaced.
*Flux:* with `force`, and it needs `has_job` to ask for it.
*Applies:* No. No layer holds a Job since the move to Deployments (`docs/architecture/deployments.md`, step 4).
*We:* **Not support.** The table of kinds has no Job, so a Job in a layer refuses the commit. A `run` kind's Jobs are applied by `load-harness.nu`, as now.

**C6. What is immutable, kind by kind.**
*Wrong:* a Deployment's selector, a StatefulSet's spec other than a few fields, a Service's `clusterIP` once set, a binding's `roleRef`, nearly all of a StorageClass, a Secret's `type`, and a claim's spec other than growing its size (*Kubernetes, from memory, not checked here*).
*Flux:* treats them alike, with C1's test.
*Applies:* Yes. All of them are rendered. Neo4j's and Postgres's claims are objects of their own and not `volumeClaimTemplates`, so a StatefulSet can be recreated without touching them (checked against the render).
*We:* **Handle.** A table in the pure core: recreate for the Deployment selector, StatefulSet, Service, the bindings, a StorageClass and a service-account-token Secret; never for a claim. Each row has a test against a real API server.

**C7. A strategy change leaves the old strategy's defaults behind.**
*Wrong:* moving a Deployment to `Recreate` leaves a defaulted `rollingUpdate`, owned by no one, and the server refuses the pair (*Kubernetes, from memory, not checked here*).
*Flux:* no handling found; it would surface as a 422, which C1 makes dangerous under `force`.
*Applies:* Partly. Every agent is `Recreate` already, and the deployer's own Deployment may differ (section 13).
*We:* **Handle.** A test with a real API server, and the render states both fields explicitly if one is needed.

## D. Order

**D1. A namespace must exist before what goes in it.**
*Wrong:* a dry-run of an object in a namespace not yet made answers NotFound.
*Flux:* stages (next entry).
*Applies:* Yes, in `platform`, which holds both the Namespaces and the ServiceAccounts in them.
*We:* **Handle.** Stages, in the plan, as a pure ordering.

**D2. Stages, and waiting between them.**
*Wrong:* a definition and what uses it, in one pass.
*Flux:* CRDs, ClusterRoles and Namespaces first, waited for; then anything whose kind ends in `Class`, waited for; then custom stages; then the rest (`ssa:manager_apply.go:347-420`, `ssa:utils/is.go:28-39,54-56`). The wait is the default 60 seconds (`ssa:manager_apply.go:111-118`).
*Applies:* Yes.
*We:* **Handle.** The same order, with no CRD stage: Namespaces, then cluster-scoped RBAC and classes, then the rest.

**D3. A CRD and its custom resources in one apply.**
*Wrong:* the custom resource's kind is not known until the CRD is established.
*Flux:* the CRD stage waits for `Established` (`cu:pkg/kstatus/status/core.go:601-627`), and the mapper finds new kinds on a miss (`rt:client/client.go:89-93`, `cu:pkg/kstatus/polling/engine/engine.go:87-97`).
*Applies:* No. All 7 CRDs are Flux's own, and leave with it.
*We:* **Not support.** Add a stage and a table row if `polar-operator` brings one (`remaining-work.md:45`). It is small; it is left out so that nothing untested is carried.

**D4. Order within a stage is a list of kinds, ignoring the group.**
*Wrong:* a kind not in the list has index 0 and goes after everything in `First` (`ssa:sort.go:36-66,119-121`), so a PersistentVolumeClaim, a NetworkPolicy and a Job follow the Deployments, and a kind called `Service` in another group sorts as a Service (`ssa:sort.go:127-137`).
*Flux:* harmless for it: nothing waits inside a stage.
*Applies:* Partly. A Deployment is applied before its claim, and its pod waits.
*We:* **Handle.** A total order on the closed table, in the pure core, deterministic and independent of input order (a property).

**D5. A Role and its RoleBinding in one dry-run, without cluster-admin.**
*Wrong:* every dry-run in a stage runs before any apply (`ssa:manager_apply.go:226-319`), so the binding is judged before its Role exists, and a controller that is not cluster-admin is refused. Flux added a flag for exactly this (`kc:CHANGELOG.md:285-288`).
*Flux:* it is cluster-admin here (`infra/layers/1-platform/services/flux/flux-controllers.yaml:291`), so it does not arise.
*Applies:* Yes, for a deployer with less. 4 Roles and 4 RoleBindings are in layers.
*We:* **Handle.** Roles get a stage before bindings, and the role holds `bind` and `escalate` (section 12). A test on a real API server, as a non-admin.

**D6. All dry-runs first, so one bad object stops the stage before anything is written.**
*Wrong:* without it a bad object leaves half a stage applied.
*Flux:* dry-run the whole stage concurrently, then apply one at a time, stopping at the first failure (`ssa:manager_apply.go:226-333`). An earlier stage has already been written by then.
*Applies:* Yes.
*We:* **Handle.** Stronger: dry-run every stage it can before the first write. Those it cannot yet are the ones whose namespace is new, reported as such.

**D7. A later layer's fix waits behind an earlier layer's failure, and each new commit walks every layer.**
*Wrong:* a Kustomization waits until each dependency is Ready at the *same revision* (`kc:controller.go:638-643`), so every commit makes every layer reconcile and pass again in order, and one stuck early layer holds the fix for a later one.
*Flux:* intended; `readyExpr` can relax it (`kc:controller.go:602-616`).
*Applies:* Yes. `platform` to `agents` is six in a chain (`infra/targets/sandbox-local/target.nu:35-159`).
*We:* **Handle.** A plan per commit: layers with no change have nothing to wait for, and a later layer's fix is in the same plan as the rest. Health still gates what changed, in order.

**D8. Webhooks last, so a broken webhook does not block its own Deployment.**
*Wrong:* a webhook applied before its server refuses what follows.
*Flux:* `MutatingWebhookConfiguration` and `ValidatingWebhookConfiguration` sort last (`ssa:sort.go:62-65`).
*Applies:* No. None rendered.
*We:* **Not support.** Not in the table. A ValidatingAdmissionPolicy (section 12) is the operator's, outside the layers.

## E. Prune and inventory

**E1. A build with no objects prunes the whole layer.**
*Wrong:* a directory that exists and yields no objects is success (`kc:CHANGELOG.md:706-708`, `kz:kustomize_generator.go:559-563`). The apply is skipped (`kc:controller.go:1000`), the new inventory is empty, everything in the old is stale, and it is deleted (`kc:controller.go:498-526`). A layer's directory with only a README in it would do it. Git does not track an empty directory, so only that case reaches it. Read, not run.
*Flux:* `spec.prune` is all there is.
*Applies:* Yes. All layers have `prune: true` (`infra/deploy-objects.nu:131`).
*We:* **Avoid.** A layer with no objects, or a commit whose prune set is more than a set share of what is live, is refused and reported; the share is a signed bound that a Dynamic setting can only narrow (section 9).

**E2. Prune runs before the health check.**
*Wrong:* old objects are deleted before the new ones are known to work (`kc:controller.go:521` then `:530`). A bad commit has no old copy to fall back on. The move from Jobs to Deployments did this: "Flux applied the Deployments and pruned the Jobs in one reconcile" (`docs/architecture/deployments.md:440`).
*Flux:* by design.
*Applies:* Yes.
*We:* **Handle.** Apply, health, then prune; but for a workload whose replacement has the same identity (the same `name` label on its pods), prune first and wait for it to be gone, since two at once is the worse failure (C4). A pure function decides which.

**E3. What a failed apply created is in no inventory.**
*Wrong:* the inventory is written only after a whole apply succeeds (`kc:controller.go:489-507`), and the partial change set is discarded (`kc:controller.go:1015-1017`). So an object created by a failed apply of commit A, and removed from Git by commit B, is in neither old nor new inventory: never pruned, forever, labelled as Flux's. Derived from the code, not run.
*Flux:* the fix for issue #1664 keeps failed *prunes* in the inventory (E4), which does not cover this one.
*Applies:* Yes.
*We:* **Avoid.** What may be stale comes from the signed trees of every commit attempted since the last one applied, and the attempt is recorded before the first write (section 9).

**E4. A prune the server refused leaves an orphan.**
*Wrong:* the inventory moved on past an object a webhook refused to delete.
*Flux:* since 1.9 it puts what failed back in the inventory (`kc:controller.go:521-526,1172-1193`, `kc:internal/inventory/inventory.go:58-77`, issue #1664, `kc:CHANGELOG.md:138-140`).
*Applies:* Yes.
*We:* **Avoid**, as E3: nothing is forgotten until a later commit is fully applied and the object is confirmed gone.

**E5. A skipped prune is forgotten, silently.**
*Wrong:* an object with its owner label removed, or `prune: disabled`, is `Skipped`, and counts as settled (`ssa:manager_delete.go:83-89`, `kc:controller.go:1149-1156`). It leaves the inventory and no one is told again.
*Flux:* intended.
*Applies:* Yes.
*We:* **Handle.** Kept and reported every round as an orphan, until someone removes it or a commit names it again.

**E6. Moving an object to a later layer deletes and recreates it.**
*Wrong:* each layer prunes on its own. Move a manifest from layer A to a later layer B: A reconciles first, X is stale in A and still labelled A, so it is deleted; then B creates it (`kc:controller.go:510-526,1450`, `kc:controller.go:638-643`). For a claim that is the data. The other way round is safe: B's apply relabels it first, and A's prune skips it. Derived from the code, not run.
*Flux:* no check across Kustomizations. Search of the tracker found nothing on it; the search was not exhaustive.
*Applies:* Yes. Files do move between layers: the broker has been in both `polar-agents` and `polar-cassini` (`infra/load-harness.nu:464-465`). That move, to an earlier layer, is the safe direction; a claim moved the other way would not be.
*We:* **Avoid.** One plan for the whole commit. An object named anywhere in the tree is not stale. This is the strongest argument for one plan over one reconciler per layer.

**E7. Deleting a Kustomization deletes what it applied.**
*Wrong:* the finalizer prunes the inventory under the default `MirrorPrune` when `prune` is true (`kc:controller.go:1198-1217,1225-1307`). `kubectl delete kustomization polar-data` removes the claims. Only `suspend` first prevents it (`:1199`).
*Flux:* intended; `deletionPolicy: Orphan` exists (`kc:api/v1/kustomization_types.go:37-40`).
*Applies:* Yes. It is the sharpest edge of the migration.
*We:* **Handle.** The takeover suspends and confirms before any delete, and a test on a cluster deletes one with live claims under it (section 17). The deployer has no custom resource to delete.

**E8. Deletion order.**
*Wrong:* the reverse of apply order (`ssa:manager_delete.go:101`), so kinds not in the list go first: a claim before its StatefulSet. Its protection finalizer holds it until the pods go (*Kubernetes, from memory, not checked here*).
*Flux:* background propagation, no wait (`kc:controller.go:1449`).
*Applies:* Partly. It is safe by accident.
*We:* **Handle.** A stated reverse order; a claim is never deleted (E12).

**E9. Terminating objects are not waited for, and can be re-added while going.**
*Wrong:* an object deleted by prune and named again by the next commit finds a Terminating object: the dry-run says unchanged, then it goes. It comes back only at the next interval.
*Flux:* `WaitForTermination` exists for finalization only (`kc:controller.go:1277-1287`).
*Applies:* Partly. Rare here.
*We:* **Handle.** A plan treats `deletionTimestamp` as "wait", and it stays in the attempted set until gone.

**E10. Skipped objects in the inventory.**
*Wrong:* an object skipped by `ssa: IfNotPresent` or `Ignore` was recorded and then pruned or re-evaluated.
*Flux:* fixed in several releases (`kc:CHANGELOG.md:195-197,415-417`).
*Applies:* No. Polar does not use them (A6).
*We:* **Avoid.** No skip annotations.

**E11. An identity encoded in a string.**
*Wrong:* a colon in an RBAC name must become `__` and be turned back, with `_` as the separator (`cu:pkg/object/objmetadata.go:32-35,68-93`).
*Flux:* handled with care.
*Applies:* No. It is its format, in a CR's status.
*We:* **Avoid.** A typed key (group, kind, namespace, name), which a property round-trips.

**E12. Nothing is protected by default.**
*Wrong:* a claim, a namespace or a StorageClass that leaves the render is deleted with everything else. Deleting a namespace deletes what is in it.
*Flux:* the `prune: disabled` annotation, if someone thought to set it (`kc:controller.go:1452`).
*Applies:* Yes. 7 claims hold the ledger, the certificate record, the repositories and the graph. No rendered object carries the annotation.
*We:* **Avoid.** No delete verb for them at all (section 9). Today: render the annotation on claims and namespaces (`gitops-controller.md`, section 2).

**E13. Losing the inventory loses the ability to prune, safely.**
*Wrong:* recreate a Kustomization and its old inventory is empty, so nothing is ever stale, and what was removed in the meantime stays.
*Flux:* safe failure (`kc:controller.go:338-341`).
*Applies:* Yes. It is what a rollback relies on (section 17).
*We:* **Handle.** A lost state record likewise means no prune; orphans by label are listed for a person.

## F. Drift and dry-run

**F1. Compare the dry-run with the live object, not the manifest with the live object.**
*Wrong:* a manifest never equals a live object: defaults, webhook mutations, server-normalised quantities, the service-account token's `data`, a claim's `volumeName`.
*Flux:* server-side dry-run with force, then compare (`ssa:manager_apply.go:252-253,294`). It avoids an apply when nothing differs, so `resourceVersion` does not move (`:170-179`).
*Applies:* Yes. It is why there is no perpetual diff on any of the kinds rendered. No admission webhook is rendered.
*We:* **Handle.** The same. It is the one idea to copy whole.

**F2. What the comparison looks at.**
*Wrong:* a generous comparison sees `resourceVersion`, `generation` and `managedFields` as drift.
*Flux:* labels, annotations, and everything but `metadata` and `status` (`ssa:manager_diff.go:141-174`). So `ownerReferences` and `finalizers` are not compared.
*Applies:* Yes.
*We:* **Handle.** The same set, stated as a pure function with a property: for any object, changing an excluded field is no difference and changing an included one is.

**F3. If normalising fails, the comparison quietly uses the unnormalised object.**
*Wrong:* `prepareObjectForDiff` returns the original on an error (`ssa:manager_diff.go:166-174`), which then still has its `status`.
*Flux:* in practice HPAs only.
*Applies:* No.
*We:* **Avoid.** No such step.

**F4. Fields that another controller owns.**
*Wrong:* an autoscaler changes `replicas`, and the applier sets it back.
*Flux:* `spec.ignore` with JSON pointers, then a careful strip-or-adopt per field, per manager (`ssa:manager_apply.go:563-919`, `kc:CHANGELOG.md:130-132`), about 350 lines.
*Applies:* No. Polar runs no autoscaler, and the `replicas` of every agent is one by rule (`infra/rules.nu:91`).
*We:* **Not support.** A manifest that should leave a field to someone else omits the field.

**F5. An HPA's dry-run duplicates a metric on old Kubernetes.**
*Wrong:* a false difference on every reconcile, on Kubernetes before 1.27.
*Flux:* dedupes (`ssa:normalize/normalize.go:170-205`).
*Applies:* No. No HPA; Polar requires 1.36.
*We:* **Not support.**

**F6. Drift is found only at the interval.**
*Wrong:* a deleted Deployment or an edit stands until the next reconcile: 10 minutes here (`infra/deploy-objects.nu:127`), with 5% jitter (`rt:jitter/interval.go:30-31`).
*Flux:* no watch on what it applied; a watch would be costly at scale.
*Applies:* Yes.
*We:* **Handle.** The same interval, a Dynamic setting. A drift round may re-apply a changed object or create a missing one. It may not prune or recreate: those happen only for a new commit (section 8).

**F7. Drift during a manual operation.**
*Wrong:* a person scales Neo4j to 0 to load a dump, and the reconcile scales it back halfway through. Polar has met this: `infra/neo4j-load.nu:32-33`, and `infra/load-harness.nu:460-472` ("the first allocator set found it put the rendered broker back mid-run").
*Flux:* `spec.suspend`, per Kustomization.
*Applies:* Yes.
*We:* **Handle.** A per-layer hold in the state ConfigMap, with a reason and an expiry, that both scripts set in place of `suspend` (H10).

**F8. A diff shows Secret values.**
*Wrong:* a values-in-a-diff leak.
*Flux:* `Diff` masks `data` (`ssa:manager_diff.go:128-132`, `ssa:sanitize.go:36-76`).
*Applies:* Yes (J2).
*We:* **Handle.** See J2.

## G. Health

**G1. The rules per kind.**
*Wrong:* "ready" means a different thing per kind.
*Flux:* kstatus: a table (`cu:pkg/kstatus/status/core.go:22-39`), with ConfigMap, Secret and CronJob always ready; a Service ready unless a LoadBalancer has no IP (`:581-599`); and an unknown kind `Current` unless it has a `Ready` condition (`cu:pkg/kstatus/status/status.go:115-138`).
*Applies:* Yes, for the 13 kinds.
*We:* **Handle.** Port only the rows used: Deployment and StatefulSet judged, the rest `Current` once they exist. An unknown kind cannot occur.

**G2. Stale status.**
*Wrong:* just after an apply the status describes the old spec, and looks healthy.
*Flux:* if `status.observedGeneration` differs from `metadata.generation`, in progress, before any other rule; `deletionTimestamp` means Terminating (`cu:pkg/kstatus/status/generic.go:22-41,73-99`). It reads uncached, so that what it reads is not older still (`kc:internal/features/features.go:85-87`, `kc:main.go:269-272`).
*Applies:* Yes. It is the most important rule on the list for a health gate.
*We:* **Handle.** Copied, a read with no cache, and a property: with any status whose generation lags, the verdict is never healthy.

**G3. A Deployment.**
*Wrong:* a Deployment can be `Available` mid-rollout with the old pods.
*Flux:* `ProgressDeadlineExceeded` is Failed; else too few replicas, updated, available or ready, or too many, are in progress; Available must be true (`cu:pkg/kstatus/status/core.go:158-250`).
*Applies:* Yes. 22 Deployments in layers. All are `Recreate` but Jaeger's, Keycloak's and the local-path provisioner's (checked against the render).
*We:* **Handle.** Port it. Polar's in-place restart (next but one) adds a case.

**G4. A StatefulSet.**
*Wrong:* a rolling update with a Pending pod looked failed; OnDelete sets are "Current" at once.
*Flux:* no conditions to read, so replicas, ready, current, partition and revision (`cu:pkg/kstatus/status/core.go:83-152`). A pod that has failed fails the set early, except one being deleted or unschedulable (`cu:pkg/kstatus/polling/statusreaders/pod_controller.go:64-83,98-119`, `kc:CHANGELOG.md:254-259`).
*Applies:* Yes. Neo4j and Postgres. `data` has no `wait_for` today, because Neo4j cannot be Ready until a later layer is up (`infra/targets/sandbox-local/target.nu:75-78`).
*We:* **Handle.** Port the rules, without the pod-failure early exit at first: a crash-looping pod still fails at the layer's timeout.

**G5. A Job.**
*Wrong:* kstatus calls a running Job Current (`cu:pkg/kstatus/status/core.go:573-577`). Flux needs it complete, so it has its own reader (`rt:statusreaders/job.go:61-144`), and TTL Jobs that vanish count as done (`ssa:manager_wait.go:118-122,168-175`, `ssa:utils/job.go:28-41`).
*Flux:* as above. It cost Polar a day: `docs/architecture/cluster-bootstrap.md:153`.
*Applies:* No. No Job in any layer.
*We:* **Not support** (C5).

**G6. The order of status readers.**
*Wrong:* a CEL expression on a Job is never consulted, because Flux registers its Job reader first (`kc:controller.go:1405-1409`).
*Flux:* intended. CEL can replace other kinds' rules (`rt:cel/status_evaluator.go:87-126`).
*Applies:* Partly. `infra/deploy-objects.nu:113-117` still builds an Endpoints expression for a case that no layer reaches any more.
*We:* **Not support.** No expression language. Rules are Rust, in the pure core, one per kind, tested.

**G7. Waiting on a claim with `WaitForFirstConsumer`.**
*Wrong:* such a claim stays Pending until a pod uses it, so `wait: true` on a layer deadlocks if its consumer comes later (`cu:pkg/kstatus/status/core.go:391-405`). Both of Polar's classes bind this way (`manifests/storage-class.yaml:8`, `manifests/local-path-provisioner.yaml:141`).
*Flux:* no special case.
*Applies:* Yes, were claims waited for. Polar names workloads in `wait_for` and does not use `wait: true`.
*We:* **Avoid.** Only what `wait_for` names is waited for; a claim is never `wait_for` (the verifier refuses it).

**G8. A failed Pod counts as Current.**
*Wrong:* a health check on a Pod passes on a failure.
*Flux:* "Pod has completed, but not successfully" is Current (`cu:pkg/kstatus/status/core.go:423-428`).
*Applies:* No. Polar does not render Pods, and the StatefulSet path uses the separate reader.
*We:* **Not support.** Not in the table.

**G9. Stop waiting when nothing can change.**
*Wrong:* a wait with one failed object goes on to the timeout.
*Flux:* if only Failed and Current remain, or any Failed with fail-fast, which is on (`ssa:manager_wait.go:129-152`, `kc:main.go:274-277`).
*Applies:* Yes.
*We:* **Handle.** The same, as a pure function over statuses.

**G10. A read error looks like waiting.**
*Wrong:* a forbidden read or a server error becomes status `Unknown` with an error (`cu:pkg/kstatus/polling/statusreaders/common.go:192-211`), so a wrong role is a ten-minute timeout, whose message is what shows it (`ssa:manager_wait.go:176-186`). A mapper failure is "can't determine status" (`:167-172`).
*Flux:* surfaces it at the end.
*Applies:* Yes.
*We:* **Handle.** A forbidden read is a hold at once, by name.

**G11. Health is run on every reconcile, changed or not, and marks the layer not ready meanwhile.**
*Wrong:* every 10 minutes each layer goes to Ready Unknown for the length of a reconcile (`kc:controller.go:331`), and those with a check (`cert-issuer`, `cassini`, `identity`) wait for it, whether or not anything changed (`:529-548`), so a dependent sees "not ready" (`:623`). Polar's agents restart themselves about hourly (`docs/architecture/deployments.md`, step 4), so a broker in mid-rejuvenation holds up `identity` and `agents` for the moment that takes. Read, not seen.
*Flux:* it is what "continuous" means there.
*Applies:* Yes.
*We:* **Avoid.** Health gates a change, once. Between commits it is read and reported, and holds nothing. Whether a workload is healthy is the health actor's to say, and the state agent's to record.

**G12. Whether in-place restarts read as failure.**
*Wrong:* during `RestartAllContainers` a pod is not ready, so a Deployment is briefly in progress; the kubelet's own exit 137 and `AllContainersRestarting` are what it shows (`docs/architecture/deployments.md`, "On the cluster"). kstatus knows nothing of them.
*Flux:* treats it as in progress; fine, unless it overlaps a deadline.
*Applies:* Yes.
*We:* **Handle.** The same reading. A cluster test restarts an agent during a health wait.

**G13. A health check on what does not exist yet.**
*Wrong:* NotFound is not terminal, so a typo in a health check waits out the timeout (`ssa:manager_wait.go:137-143`). `publish` does refuse a `wait_for` that matches nothing (`infra/deploy-objects.nu:92,108`).
*Flux:* waits.
*Applies:* Partly.
*We:* **Avoid.** A `wait_for` must name an object in the tree; if it does not, the verifier refuses the commit.

**G14. The health timeout's default.**
*Wrong:* a default that moves with another setting.
*Flux:* `interval - 30s`, floor 30 s, unless `timeout` is set (`kc:api/v1/kustomization_types.go:383-392`). Polar sets 10 minutes (`infra/deploy-objects.nu:128`).
*Applies:* Yes.
*We:* **Handle.** Its own bound, a Dynamic setting within a limit the commit carries.

**G15. Health does not say the agent works.**
*Wrong:* a Deployment's readiness comes from its probe, and no catalog agent has a `readinessProbe` (checked against the render), so an agent is "ready" as soon as its container starts. Flux's green says little more than that the process is up.
*Flux:* out of its scope.
*Applies:* Yes. It already limits what `wait_for` means today.
*We:* **Handle, later.** Same rule at first, for the same behaviour during takeover. See open question 9: asking the health actor would be a real improvement, once Cassini is up.

## H. A reconcile's life

**H1. A reconcile finishes under the spec it began with.**
*Wrong:* a health wait runs out its timeout, up to ten minutes, before a new revision or spec is read. Polar's workaround restarts the controller (`docs/architecture/cluster-bootstrap.md:144-148`, `infra/flux.nu:111-136,266-273`).
*Flux:* **the gate `CancelHealthCheckOnNewRevision` does this and is off by default** (`kc:internal/features/features.go:50-57,103-105`). With it, any watch event that enqueues the object cancels the wait, a changed spec included (`kc:internal/controller/kustomization_manager.go:144-157`, `rt:controller/builder.go:55-75`, `rt:controller/reconciler.go:97-113`, `kc:controller.go:1101-1110`, `kc:CHANGELOG.md:279-283`). Polar's controllers do not set it (`infra/layers/1-platform/services/flux/flux-controllers.yaml:3548-3552`). Read, not run.
*Applies:* Yes.
*We:* **Handle.** A new commit is a message to the actor that applies, and ends a wait at once. Today: try the gate, and if it holds, drop the restart from `flux.nu` (`gitops-controller.md`, section 2).

**H2. A cancelled reconcile leaves a stale cache.**
*Wrong:* a cancelled wait, with a cached read of the source, could drop the request and stick.
*Flux:* requeue at once after a cancel (`kc:controller.go:295-299`, `kc:CHANGELOG.md:226-231`).
*Applies:* No. Its shape is the cause.
*We:* **Avoid.** No informer cache in any decision: each read goes to the API.

**H3. The same revision enqueued while it is being reconciled.**
*Wrong:* needless restarts of the work, which with a cancel gate would be an endless one.
*Flux:* skipped if Ready or Reconciling at that revision (`kc:internal/controller/kustomization_indexers.go:60-65`, `kc:CHANGELOG.md:237-242`).
*Applies:* No.
*We:* **Avoid.** A plan is for one commit, and a message for the commit in hand is dropped.

**H4. Only the health wait has a timeout.**
*Wrong:* the fetch, the build, and the apply have none of their own: the status says "with a timeout of 10m" while applying, but that is only the health wait's (`kc:controller.go:330,391,482,1102-1107`). A hung API call hangs a worker.
*Flux:* HTTP client defaults only.
*Applies:* Yes.
*We:* **Handle.** A deadline for every API call, and for each stage.

**H5. How failures retry.**
*Wrong:* a bad commit retries the same refused write at full rate forever, or stops when it could go on.
*Flux:* a failed reconcile requeues at `retryInterval` (`kc:controller.go:303-311`), 1 minute here (`infra/deploy-objects.nu:129`); a transient error at the workqueue's exponential rate, 750 ms to 15 minutes (`rt:controller/rate_limiter.go:27-32,57-59`); a dependency at 30 s (`kc:main.go:116`); panics are recovered (`kc:main.go:237`); a "terminal" error stops (`kc:controller.go:196-204`).
*Applies:* Yes.
*We:* **Handle.** A refusal the same commit cannot cure holds until the next commit, with no retrying. A transient error backs off with a cap. Which is which is a pure classification with a property.

**H6. A restart mid-apply.**
*Wrong:* the applied half is not recorded (E3), and temporary directories were left behind until 1.9.5 (`kc:CHANGELOG.md:32-45`, `kc:internal/controller/tmpdir.go:33-71`, `kc:main.go:406-428`).
*Flux:* state is in the objects, and the next reconcile redoes the work; the apply is idempotent. Polar relies on that when it restarts the controller.
*Applies:* Yes.
*We:* **Handle.** Crash safety is an invariant, not a mechanism: a test kills the process at every step and checks what follows (section 19). No temporary files: the tree is in memory, within a bound.

**H7. Two controllers at once.**
*Wrong:* during a rollout or a partition, two instances apply and prune.
*Flux:* leader election (`kc:main.go:214-219`; on in Polar's render, `flux-controllers.yaml:3552`).
*Applies:* Yes. `Recreate` is no guarantee on a lost node.
*We:* **Handle.** A fence: a compare-and-swap on the state ConfigMap before each stage (section 5). A Lease would add a kind and a verb, and the state write is needed anyway.

**H8. Adding the finalizer first.**
*Wrong:* an object deleted between creation and the finalizer loses its garbage collection.
*Flux:* add, requeue, then work (`kc:controller.go:180-187`).
*Applies:* No. The deployer has no custom resource, so nothing to finalize.
*We:* **Avoid.**

**H9. Status patch conflicts and ownership of conditions.**
*Wrong:* losing a status write.
*Flux:* a serial patcher, with conditions owned by name and a separate status manager, `gotk-kustomize-controller` (`kc:controller.go:1363-1393`, `kc:main.go:381`).
*Applies:* No. No custom resource.
*We:* **Avoid.** One writer for one ConfigMap, by compare-and-swap.

**H10. Suspending is checked only at the start of a reconcile.**
*Wrong:* a suspend during a reconcile does not stop it (`kc:controller.go:190-193`). `neo4j-load.nu` suspends and goes straight on.
*Flux:* so it is.
*Applies:* Yes.
*We:* **Handle.** A hold is read before each stage and between objects. The hold's writer reads back that the deployer has seen it (its generation in the state ConfigMap) before going on.

**H11. Concurrency.**
*Wrong:* unbounded parallel calls flatten a small API server.
*Flux:* 4 reconciles and 4 concurrent dry-runs by default (`kc:main.go:114-115`), one apply at a time within a set, and one Kustomize build at a time.
*Applies:* Partly. A hundred objects, on small clusters.
*We:* **Handle.** A bound from what the machine has, not a constant. The default is small; it is not raised by a hint.

**H12. Which clock.**
*Wrong:* kstatus compares `time.Now()` with a server timestamp to give a pod 15 s to schedule (`cu:pkg/kstatus/status/core.go:451`), and the artifact collector uses file times (`art:storage/gc.go:49,66-72`).
*Flux:* tolerated.
*Applies:* Partly, for us by another door. `verify_commit` takes `now`, and a node with a wrong clock refuses a good commit (`src/agents/polar-signing/src/commit.rs:434`, `verify.rs:129-137`).
*We:* **Handle.** `now` is passed in, so the decision is pure. A refusal for time is reported as such and holds, and nothing is deleted (section 6).

**H13. Certificate expiry stops the source, silently.**
*Wrong:* `deploy-repo.nu` makes `flux` and `pipeline` certificates for 365 days (`infra/deploy-repo.nu:215`) and never remakes one for age, only for its names (`:206-209`). So after a year the source stops being able to read, and a new `publish` signs with an expired certificate.
*Flux:* reports a failed fetch and goes on with the old artifact.
*Applies:* Yes, today. The Flux target dates from 2026-10, so no cluster has met it yet.
*We:* **Handle.** `publish` refuses a certificate within a margin, and `ensure` remakes it (section 6). Today: the same fix is needed for Flux.

## I. API discovery

**I1. A kind the mapper does not know yet.**
*Wrong:* new kinds fail with a stale cache; too much discovery floods the server.
*Flux:* a lazy, dynamic mapper that looks again on a miss (`rt:client/client.go:89-93`, `kc:main.go:263`, `kc:CHANGELOG.md:535`), and a poller that skips a kind it cannot resolve (`cu:pkg/kstatus/polling/engine/engine.go:91-95`).
*Applies:* No. Its kinds are built in.
*We:* **Avoid.** A closed table with each kind's group, version, plural and scope, in the code. No discovery. An unknown kind refuses the commit before anything is written.

**I2. A version that the server has removed.**
*Wrong:* an old manifest's `apiVersion` is gone after a cluster upgrade. A bug around deprecated versions logged spuriously and sometimes failed health checks (`kc:CHANGELOG.md:525-527`).
*Flux:* error from the API; an inventory entry keeps its version so the old object can be found (`kc:internal/inventory/inventory.go:124-131`).
*Applies:* Partly. All 13 kinds are at stable versions.
*We:* **Handle.** Keys have no version. The table gives the version to talk to, and preflight compares it with the server once at start, so a removed one stops the start with a name.

**I3. Unknown fields.**
*Wrong:* a server told to warn drops a misspelt field, and the result is compared for ever after.
*Flux:* not set to strict in what was read, and B1 hides it first.
*Applies:* Yes.
*We:* **Handle.** `fieldValidation=Strict`, with shadow mode confirming every rendered object passes.

## J. Secrets

**J1. The API echoes a value in its error.**
*Wrong:* a validation error quotes what was sent, and the message goes to status, events and logs.
*Flux:* masks substituted values in the message (`kc:controller.go:764-786,491`, `kc:CHANGELOG.md:5-11`), after two earlier fixes of the same class (`kc:CHANGELOG.md:499,533`).
*Applies:* Partly. No secret value is ever in Polar's manifests, so there is nothing to echo.
*We:* **Avoid.** The verifier refuses a Secret with data, and API errors are reduced to the structured causes, with no value, before they are logged or reported. `polar-health`'s `sanitize` also applies.

**J2. A dry-run response carries a live Secret.**
*Wrong:* a diff, a log line or a report of a Secret shows its values. For Polar this is real without any secret in the render: a dry-run of `kube-observer-sa-token` or `attestation-agent-sa-token` answers with the token the controller put in it (*Kubernetes, from memory, not checked here*).
*Flux:* masks `data` in `Diff` (`ssa:manager_diff.go:128-132`, `ssa:sanitize.go:36-76`), and never logs the object.
*Applies:* Yes. 2 such Secrets in the render, and the bootstrap document's "no Secret documents" is out of date (`docs/architecture/cluster-bootstrap.md:98`).
*We:* **Handle.** Live objects are held in a type whose `Debug` shows no `data`, with no path into a report (a property), and the service-account-token Secrets are created if missing, read by metadata alone if the API allows it (to check), and never diffed.

**J3. Reading Secrets means caching Secrets.**
*Wrong:* a whole cluster's Secrets in a controller's memory.
*Flux:* Secrets and ConfigMaps are not cached unless asked for (`kc:main.go:195-203`).
*Applies:* Yes.
*We:* **Avoid.** No `list` or `watch` on Secrets; `get` by name only, on the two named, or none (J2).

**J4. SOPS decryption.**
*Wrong:* a key in a Secret, plaintext in memory.
*Flux:* about 1,150 lines (`kc:internal/decryptor/decryptor.go`), with its own redaction. Not read in detail.
*Applies:* No. SOPS stops on the operator's machine (`infra/targets/*/secrets.nu`).
*We:* **Not support.** A secret travels as Polar's escrow does, in signed configuration.

## K. The git source

**K1. Every clone is shallow.**
*Wrong:* a clone of depth 1 knows nothing of a commit's parents.
*Flux:* `ShallowClone: true`, always (`sc:gitrepo.go:1016-1019`, `git:gogit/clone.go:70-73`).
*Applies:* Yes. It is why it cannot tell a rewind from an update (next).
*We:* **Handle.** A full fetch, on purpose. The repository is small: about 64 KB compressed per tree today (measured on the render, `tar` and `gzip`, Flux's own controllers and the harness left out), and one commit per publish that changed something (`infra/deploy-repo.nu:498`).

**K2. A force push or a rewind is taken as an update.**
*Wrong:* the revision is compared for equality alone (`sc:gitrepo.go:645-654`). A branch moved to an old commit is applied, and with a signature check it would still pass: old commits are signed too.
*Flux:* no ancestry check is possible on a depth-1 clone.
*Applies:* Yes. Polar's server refuses a non-fast-forward (`src/agents/polar-git-server/server/src/store.rs:105-118`), but a server reset gets its history from `mirror.git` (`infra/deploy-repo.nu:301-305`), and the mirror itself is pushed with `--force` (`:515`).
*We:* **Handle.** A head must descend from the last commit applied, or it is refused and reported, and drift correction goes on from the commit applied.

**K3. An unchanged head skips the clone, and verification with it.**
*Wrong:* the optimisation asks the remote for the head and, if it is the same, builds a partial commit with no content (`git:gogit/clone.go:52-68`, `sc:gitrepo.go:593-616`). The code's own comment: "TODO: Find out if such condition setting is needed when commit signature verification is enabled" (`:613-614`).
*Flux:* forces a full run if verification was just turned on (`sc:gitrepo.go:1312-1314`).
*Applies:* No. Flux's verifier cannot read Polar's signatures anyway (K5).
*We:* **Avoid.** A tree read from anywhere, snapshot and seed included, is verified at each read; the signature costs one RSA check.

**K4. An empty repository, or a missing branch.**
*Wrong:* an empty server looks like an empty desired state.
*Flux:* an empty repository is initialised locally and is not an error in the clone; "git repository is empty" is raised after (`git:gogit/clone.go:99-108`, `sc:gitrepo.go:580-587`). A missing branch is an error.
*Applies:* Yes. A new server is empty until it is given the mirror's history (`infra/deploy-repo.nu:299-306`).
*We:* **Handle.** Empty, missing and unreachable are all "no new commit". None of them is a desired state.

**K5. Flux cannot verify these signatures.**
*Wrong:* `spec.verify` takes OpenPGP and SSH only (`sc:gitrepo.go:1146-1157`, `sc:CHANGELOG.md:128-130`), and Polar signs with x509 (`docs/architecture/cluster-bootstrap.md:160`), so nothing checks a deployment commit after install. It would also check HEAD alone (`sc:gitrepo.go:1199-1208`), and keys come from a Secret (`:1136-1137`).
*Flux:* no x509 mode.
*Applies:* Yes. It is why this document exists.
*We:* **Handle.** `verify_commit`, on every commit from the last applied to the head (section 6).

**K6. The credential is in a Secret.**
*Wrong:* a long-lived client key in a Secret, renewed by no one.
*Flux:* `secretRef` (`sc:gitrepo.go:665-677`). Polar's holds the `flux` key (`infra/flux.nu:220-225`).
*Applies:* Yes. `docs/architecture/cluster-bootstrap.md:130`.
*We:* **Handle.** The pod's custody daemon holds the key; there is no credential at all on the seed path (sections 7, 10).

**K7. A git client that cannot use a key it cannot read.**
*Wrong:* libgit2 cannot present a client certificate, so the scheduler observer shells out to `git` (`src/agents/polar-scheduler/observer/src/git_ops.rs:26-27`), and `git` needs a key file, so it is one of the agents with `custody: false` (`infra/config/workloads/scheduler.nuon:51-53`).
*Flux:* go-git over its own transport, with the key from the Secret.
*Applies:* Yes.
*We:* **Handle.** The smart-HTTP fetch is a few hundred lines (a guess) over the rustls custody signer that exists (`polar-custody`, `client.rs`), with libgit2 only for indexing. It is the git handler of `protocol-handlers.md`, and it lets the scheduler observer leave key files too (section 15).

**K8. Submodules, sparse checkout, includes, tags, semver, proxies, GitHub apps, cloud providers.**
*Wrong:* each has its own failures.
*Flux:* each supported, with stalls and retries (`sc:gitrepo.go:517-546,705-805,970-1008,1027-1034`, `sc:CHANGELOG.md:374,390`).
*Applies:* No.
*We:* **Not support.** One branch of one repository.

**K9. The git implementation is a supply chain of its own.**
*Wrong:* go-git has CVEs of its own (`sc:CHANGELOG.md:173-177,201`).
*Flux:* upgrades.
*Applies:* Yes, for whatever we use.
*We:* **Handle.** The Rust fetch reads only from a pinned-CA server, within a size bound, and what it fetched is believed only after the signature. Libgit2 is already in the workspace (`src/agents/Cargo.toml:120`). It parses data from a server, before a signature says anything: it is the deployer's first attack surface and belongs in the fuzz targets.

## L. Artifacts

**L1. Keeping a fetched tree, and trusting it later.**
*Wrong:* a tree changed between fetch and apply.
*Flux:* source-controller tars the tree and serves it over HTTP in the cluster; the digest is in the object's status. Storage checks it on each reconcile, and throws away a bad one; the fetcher checks it again (`sc:gitrepo.go:430-454`, `art:storage/storage.go:123-147`, `fetch:http/fetch/archive_fetcher.go:255-259`).
*Applies:* No, as a store. Yes, as the question it answers.
*We:* **Avoid.** No artifact store and no second process. The snapshot is verified whenever it is read (section 7).

**L2. The artifact disappears.**
*Wrong:* source-controller's `/data` is an `emptyDir` (`infra/layers/1-platform/services/flux/flux-controllers.yaml:2675,2687`), so a restart loses it, and a kustomize-controller gets a 404 until it is rebuilt.
*Flux:* `ErrFileNotFound` requeues; the source notices and rebuilds (`kc:controller.go:276-282`, `sc:gitrepo.go:456-468`, `kc:CHANGELOG.md:802-804`).
*Applies:* No, for us.
*We:* **Avoid.**

**L3. Garbage collection of artifacts, and lock files.**
*Wrong:* a disk fills.
*Flux:* TTL and count, skipping locks, file locks while writing (`art:storage/gc.go:41-90`, `art:storage/storage.go:150-154`).
*Applies:* No.
*We:* **Avoid.**

**L4. An archive as an attack: symlinks, sizes, paths.**
*Wrong:* out-of-tree writes, a disk filled.
*Flux:* archive only regular files and directories (`art:storage/archive.go:111-114`), skip symlinks on untar (`fetch:http/fetch/archive_fetcher.go:269`), secure join for the path (`kc:controller.go:377`). But Polar's route is unlimited: `WithMaxDownloadSize(tar.UnlimitedUntarSize)` (`kc:controller.go:367-368`).
*Applies:* Partly. A git tree can hold a symlink and a large blob.
*We:* **Handle.** No checkout to disk at all. Files are read from objects, a symlink or a submodule entry in a layer refuses the commit, and every read has a size bound.

**L5. Deterministic archives.**
*Wrong:* every rebuild looks new.
*Flux:* zeroes owners, times and modes so the digest is content alone (`art:storage/archive.go:192-209`).
*Applies:* No. A git tree already is.
*We:* **Avoid.**

**L6. An ignore file filters what is applied.**
*Wrong:* `.sourceignore` in the repository, and default patterns, silently remove files from the artifact (`sc:gitrepo.go:912-926`, `fetch:sourceignore/sourceignore.go:34`, which excludes `.sops.yaml`).
*Flux:* a feature.
*Applies:* No, since `publish` writes every file. An attacker with write access to the repository could use it if nothing checked signatures.
*We:* **Avoid.** Exactly the files `provenance.json` lists, by digest.

## M. Grouped: what Polar does not use at all

Read only far enough to see they do not apply. Each is **not support**, because Polar renders plain YAML into one repository for one cluster, and adding any of them later is the case that would change the answer to "is this worth doing" (`gitops-controller.md`, section 18).

**M1. Post-build substitution.** Corrupting CRD schemas, panics on a bad substring, strictness (`kc:CHANGELOG.md:32-35,79-82`, `kc:controller.go:856-872`). *Applies:* No.

**M2. Impersonation and remote clusters.** Per-object clients, a missing account at finalization, self-contained kubeconfigs (`kc:controller.go:397-428,1231-1295`, `kc:CHANGELOG.md:36-40`). *Applies:* No. One cluster, one role.

**M3. Multi-tenancy controls.** Cross-namespace references, default service accounts, remote bases (`kc:controller.go:696-701`, `kc:main.go:159`). *Applies:* No.

**M4. OCI, Helm, buckets and external artifacts as sources.** Cosign verification, index caches, Azure ETags, and most of source-controller's changelog (`sc:CHANGELOG.md:9-18,48-58,138`). *Applies:* No.

**M5. Image automation and notifications.** Commit status events, webhook receivers (`kc:controller.go:164-171`). Polar installs neither, and `--events-addr=` is empty (`flux-controllers.yaml:3548`). *Applies:* No.

**M6. Name prefixes, common metadata, patches, images, components.** `spec.commonMetadata` and the generator's transformers (`kc:controller.go:895-897`, `kz:kustomize_generator.go:349-470`). *Applies:* No.

**M7. Custom health expressions.** CEL, with its own type and compile limits (`rt:cel/status_evaluator.go:37-73`). *Applies:* No (G6).
