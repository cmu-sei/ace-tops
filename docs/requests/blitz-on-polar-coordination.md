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

# Blitz on Polar: what lands when

A reply to "Blitz deploys on Polar's terms: the plan" (decided 2026-11-09), written 2026-11-10 on `main` at `232a05cc` for Vaughn and
the Blitz lanes. It is a proposal for common ground, not a decision: where Blitz's plan and Polar's order of work meet, what works on
`main` today, and which parts of Blitz's design wait for something Polar has not built yet.

## Where we agree

The plan is the right one, and much cleaner than what came before. It takes the nine requirements of the review
(`docs/requests/public-polar-port-deployment-review.md` on the port branch, `bdf2f096`, "Option 2") as they were meant: the signed
render through Polar's git server and Flux, facts from each image's `--scaffold`, no operator, secrets escrowed or in SOPS, control as
signed sections. Several of its own rules are ones Polar keeps too: measure before claiming a saving, offer each piece upstream rather
than run a second pipeline beside Polar's, and record every source tree a render came from.

What follows is about timing. Polar has its own order of work, set by the maintainer, and some of what Blitz's plan asks for lands in
it later than Blitz's phases would like. Where that is so, this says what to do in the meantime.

## Polar's order of work

Each step is taken in small pieces, each tested and reported before the next. The steps are in order; dates are the maintainer's to
set, and none are given here.

**Step A, now: small fixes from the review, and one from your plan.** None waits for anything.
- kube-observer's ClusterRole derived from what it declares it watches. **Done 2026-11-10** (`ca2e635c`): every Kubernetes role is now
  computed by the builder from the agent's declared cluster operations and printed in its scaffold (`roles`), and none may read a
  Secret. A Blitz agent on the Kubernetes API gets its role the same way, with nothing to write in the catalog.
- `up.nu`: the cluster always named (never the kubeconfig's current context), a timed-out wait saying why, the plan naming every secret
  without its value, the graph password's two forms checked to agree before anything is applied. **Built 2026-11-10**: the cluster is
  named by the uid of its `kube-system` namespace (`up.nu <target> --cluster <uid>`; run without it, and it prints the one KUBECONFIG
  reaches), since every kubeadm cluster's context is `kubernetes-admin@kubernetes`. A target's `secrets.nu` now declares its Secrets as
  data (`SECRETS`), which the plan prints; Blitz's overlay targets will want the same shape.
- The bootstrap CA constrained (path length, key usage) for new clusters. **Done 2026-11-10**: path length 0 and key usage
  `keyCertSign`, `cRLSign`, both critical. Name constraints wait for your findings (phase 0, question 5).
- Tests that `polar-sign` and `polar-admin-grant` cannot print a secret. **Done 2026-11-10.** Doing it found that `polar-sign
  runtime` and `configuration` signed a plaintext secret given to them; both are now judged by the agent's scaffold as `sign` is,
  so they need it (`--scaffold`, or `<dir>/scaffolds/<agent>.json`), and refuse a secret not already sealed.
- **New, from your phase 0:** the signed provenance record names every source tree a render was made from (below, "Provenance").

**Step B, in flight: the GitLab agents' move to the builder, then runtime attestation's slice C**
(`docs/architecture/runtime-attestation.md`). Slice C puts an attestation actor in every builder agent, adds runtime challenges and a
node sensor, and has the builder lock each agent's process before it parses any untrusted input, irreversibly: seccomp (no new
programs, no new executable memory) and Landlock (no file access beyond what it opened). For Blitz this means:
- every Blitz agent rebuilt on the new builder when slice C lands, so a second re-pin after your phase 1;
- an agent that runs other programs, or opens files late, will be refused once locked. Agents that stay on `AgentBuilder` and declare
  what they use are what the lock is designed for; tell us early about any Blitz agent that needs more.

**Step C: lifecycle** (`docs/architecture/lifecycle.md`, its decisions taken 2026-11-07). A workload on a cluster has a phase: under
test, deployed, retiring or retired. The phases are one signed document per cluster in polar-schedules, and each agent derives what it
needs from it.
- C1: the lifecycle document and its reader. **The Rust `polar` CLI starts here**; its first verb moves a workload between phases and
  signs the move.
- C2: the agents derive from it (the state agent its `schema` and `agents`, the credentials agent its authority model), and
  `polar-sign check --ask` compares. A `polar status` over the agents' own health answers. Retirement revokes a workload's certificates
  (`Decommissioned`) and releases its secrets.

**Step D: the catalog's split.** Today the catalog holds three things: declarations (what a kind is), a cluster's intent (what runs
here, and how), and facts about what is running. They split by what changes when, and the split is built around lifecycle, which is
why it waits for step C.
- Declarations come from the images' scaffolds, released with their evidence.
- A cluster's intent is step C's signed lifecycle document plus the target (and its configurations under test): which workloads run here,
  in which phase.
- What is running is reported by the agents and recorded in the graph, not kept in files the tooling edits.
- **The downstream layer lands here**: a downstream project's kinds declared by their own images, released into the same evidence, and
  named in a cluster's intent beside Polar's core. Several applications on one core follow from it.
- A dependency graph the catalog derives replaces hand-kept layers, proved on Flux first.
- One check before publish names every problem, and every intent file refuses unknown fields.

**Step E: Polar's own GitOps controller**, reshaped around the phases: a shadow mode first (dry runs, waits that say why, "done" judged
by the agents' invariants), then the transitions carried out (retiring drains, what is left is recorded in the graph first), then Flux
replaced.

**Beside them: the polar package**, a package manager's feel for building an agent and installing it into a cluster.
- Before lifecycle: a **cluster profile** (the capability vocabulary, services, pools, kinds, the platform version, the CA), signed at
  publish beside `deployment-record.json`; `polar new|init`, a skeleton crate on `AgentBuilder`; and `polar check`, what a package still
  lacks against a cluster, offline.
- After step D: `polar add <git>#<rev>`, `polar install` (a move to under test) and `polar promote` (the owner's signed move to deployed).
- A package carries no deployment decisions: source at a rev, its build, the scaffold the build prints, its evidence. Pool, phase,
  runtime sections and secrets are the cluster's intent, which is step D's downstream layer.

## Your plan, phase by phase

| Your phase | Works on `main` today? | Waits for |
|---|---|---|
| 1. Re-pin to main | Yes | Nothing; a second re-pin at slice C (step B) |
| 2. ACE's infra as a derivation, Blitz's catalog laid over it | Yes, with the provenance patch carried | The patch retires at step A; the overlay at step D |
| 2. Scaffolds from the built binaries, offline | Yes (`POLAR_SCAFFOLD_DIR`, `resolve.nu:234`) | Nothing; `polar check` (the package) later replaces the ad hoc check |
| 3. Secrets and runtime configuration | Yes | Nothing |
| 3. Workspaces | No | A design reviewed with us, then a capability added in step with every reader (below) |
| 3. Requirement 7, an image lock | Yes (`kind: external`, `infra/images.nuon:36`; `infra/images.lock.nuon`) | Graph TLS comes with the re-pin |
| 4. Day 0 and day 2 | On nix-usernetes, yes | OrbStack and arm64 nodes are unverified on main (below) |
| 5. Retire what is left behind | Yours | Nothing |
| 6. Rust replacing the scripts | Measuring, yes | The resolver: C1's conventions; the render: step D; `up.nu`: step E (below) |

### Phase 1, the re-pin

Main has changed the builder's surface since `9132832e`. What Blitz's agents meet:
- **The graph:** an agent declares `graph-write` or `graph-read` and gets a `GraphHandle` from the builder's controller
  (`polar-agent-builder/src/graph.rs`). The builder drains queued writes before shutdown, counted in the agent's budget.
- **Shutdown:** an agent registers how it is told before `build()`: `with_drain(|| Msg)` (told, and waited for), `on_shutdown(|| Msg)`
  (told only), or neither. The domain no longer subscribes to an infrastructure events port; that port is gone.
- **A run that finishes** (a Job, a harness) sets `PolarAgent::COMPLETES = true`; `run` exits 0 when `start` returns `Ok`.
- **Scudo** and the static musl build are the rule for every binary that ships: one artifact per target.

Main moves quickly, so pin to a commit this file names as a good point, and move deliberately. We will add each such point below as it
is reached, with what changed since the last.

### Phase 2, the overlay and provenance

The overlay is a sound interim. It keeps Blitz additive, edits nothing of Polar's, and refuses a file that would overwrite one of ours.
Two notes:
- **Provenance.** We will take the change in step A, in this shape: the record carries a list of sources, each with its name, commit,
  description and whether it had changes beside its commit, in place of today's one `source` (`infra/deploy-repo.nu:565`). In your
  overlay, main's tools run in a laid-out derivation, not a git checkout, so the sources cannot come from `git rev-parse HEAD`: they come
  from a manifest the layout writes, and the render refuses a tree that is not a checkout and has no manifest. Until it lands, carry
  your patch, as your plan says, and publish nothing without both commits. **Built 2026-11-10**: the manifest is `sources.json` at the
  tree's root, a list of `{ name, commit, describe?, uncommitted_changes }` with full commit ids and names in lowercase, digits and
  hyphens; the record's `sources` replaces `source`, and a tree that is a checkout and has `sources.json` too is refused.
- **Keycloak's realm and theme as overrides of our charts.** The overlay refuses a file that overwrites ours, so these go through the
  target's overrides (`targets/<target>/overrides.dhall`, read at `infra/render.nu:92`), not as replacement charts. If something you need cannot be said that way, tell us what,
  and we will look at it as a chart value rather than a file to replace.

**Catalog roots are not taken now.** Your phase 0 asks for Polar's tools to read several catalog roots, as the first slice of the
downstream layer. That layer is step D, and step D first decides what a layer holds: declarations from the images, the cluster's intent
signed, running state reported by the agents. Roots built on today's catalog would fix the shape step D is meant to change. Until then
the overlay carries Blitz's entries, and we would like Blitz's needs in step D's design while it is written: you are its first
downstream user.

### Phase 3, workspaces

The build orchestrator is a good precedent, if it is followed all the way. What makes it acceptable is not only that its pods hold no
identity:
- it is a builder agent, its rights to the Kubernetes API derived from the operations it declares (`job-run`,
  `infra/config/capabilities.nuon:200`), and its writes go through the builder's Kubernetes protocol;
- the pods it makes come from a `PodTemplate` in the signed catalog (the `template` kind), so what it can make is signed off with the
  rest;
- it holds no Secret, and a build's source comes by digest.

Workspaces on the same terms would fit: the workspace operator as a builder agent, its pod template in the catalog, its rights derived
from what it declares, its pods holding no Polar identity. A `Workspace` custom resource with its own controller and lifecycle beside the
catalog is what requirement 3 removed, so that part needs its design reviewed with us first. Workspaces differ from builds in ways that
need answers in that design: they live long, they belong to a member, and they are reached from outside over SSH.

**A new capability is a coordinated change.** `Capability` (in `cert-issuer-common`) is a closed enum, and grants are stored archived;
a reader built before a new variant reads a grant holding it as malformed. So a new capability lands in `main` with every reader rebuilt
together, and a cluster that holds it needs a migration note. Ask for it as a request, with the operations it covers, and we will place
it in the order.

### Phase 4, day 0

Main's `up.nu` runs on nix-usernetes. It has not been run on OrbStack or on arm64 nodes, and we cannot measure aarch64 here, so changes
for both targets merge on x86_64 numbers. If your day 0 finds a gap there, report it to us with what failed; a fix that keeps one
artifact per target is welcome upstream.

### Phase 6, Rust in place of the scripts

We want this. Polar's own rule is that a user's flow is a static Rust binary over library crates, not Nushell joining steps, and step C1
starts that work. Two teams writing deployment tools apart is how a second pipeline begins, so we propose doing it together, in this
order:
1. **Measure main's render first**, as your plan says, cold and warm, offline. Yes, now.
2. **The resolver as a Rust library first**: scaffolds in, facts out (topics, groups, the authority model, the floor). Those facts survive
   step D unchanged, so parity with `resolve.nu` is worth proving now, with property tests as well as goldens. It follows C1's
   conventions: the cluster always named, a plan judged offline with every problem named at once, pure decisions tested against fakes,
   secrets that cannot be printed, and one exit code per kind of failure.
3. **The render after step D.** A byte-identical port of `render.nu` would fix in Rust the catalog shape step D is meant to change. The
   render is rewritten once, against the split. Multiple roots belong there.
4. **`up.nu` last**, and only its bootstrap. Step E's controller takes over applying; bootstrap (the registry, the CA, the first account,
   handing off to the git server) stays a tool.

Each piece comes to `main` the way the port's areas did: tests first, one change a commit, on the builder, checked against the
principles in `AGENTS.md` before it is taken.

## What must land before what

| For Blitz to... | Polar must first land |
|---|---|
| Publish a render naming both source trees without a carried patch | Step A, provenance |
| Run on main at all | Nothing; the re-pin |
| Keep running once slice C ships | Step B; then a re-pin and rebuild |
| Deploy without an overlay | Step D, the downstream layer |
| Bring an agent in under test and promote it | Step C, lifecycle; then the package's `install` and `promote` |
| Check a Blitz agent against a cluster before installing it | The cluster profile and `polar check` |
| Run workspaces | A design reviewed with us; any new capability, rolled out with every reader |
| Give Ferron a certificate from the cluster's CA | Step A's constrained CA; the registry-gate and name-constraint findings read together (below) |
| Replace `render.nu` in Rust | Step D |
| Show status and tear down cleanly | Step C2; the rest of teardown in step E |

## Your phase 0 questions, answered

1. **Recording every source tree:** yes, in step A, in the shape above.
2. **Several catalog roots:** not on today's catalog; they arrive as step D's downstream layer, with Blitz as its first user.
3. **Workspaces like the build orchestrator's pods:** yes, on all of the orchestrator's terms. Send the design.
4. **Rust replacing the pipeline:** yes, measured first, the resolver first, the render after step D.
5. **The registry gate and the CA's name constraints:** please send `findings/2026-11-09-cert-issuer-for-ferron-and-the-registry.md`.
   Polar has a design for a gate in front of the registry (`docs/architecture/registry-gate.md`, not built), and constraining the CA is in
   step A, so the two are best decided together. A front that faces browsers on 443 raises its own question: whether its certificate
   should come from the cluster's CA at all.

## Your problem list, on main

- **4, cert-issuer's key group-readable:** on main this is deliberate and documented (`infra/config/capabilities.nuon:296`, the `ca`
  kind's `fs_group` at `infra/config/kinds.nuon:126`): the pod has one container, cert-issuer, with no polar-init and no custody
  sidecar, so only cert-issuer is in that group. What made it a problem in the Dhall plan was the header promising 0600 while the code
  did otherwise.
- **6, the kube observer reading ConfigMaps:** step A, the role derived from what it declares.
- **9, `cluster.local`:** main builds names from `cluster.domain`; nothing to do once Blitz is on main's render.

## How we keep in step

- This file stays on `main` and is updated as steps land: each good pin point, and each change that needs a Blitz rebuild or migration.
- Breaking changes since 3.0.0 carry migrations, and `remaining-work.md` lists the ones ahead.
- Questions and requests come to the maintainer, as this one did, and are answered in writing here.
