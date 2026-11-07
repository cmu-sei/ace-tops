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

# Lifecycle (thinking, 2026-11-07)

**Why.** The GitLab pair's live run under test showed more than a missing entry. Enabled by the test GitLab's configuration under test, the
pair was issued certificates marked `g:under-test`, held to the signed record as under test, and read the test GitLab; and `polar-sign
check --ask` then said the state agent's `schema` names no owner of its labels and its writer's `agents` does not ask its health. Those two
lists know two states, absent and deployed. The pair was in a third, and nothing in Polar has a name for it. The maintainer (2026-11-07):
infrastructure under test "needs to be deployed all the time", "introduced slowly to the environment, as a test of its own behaviors ... as
well as measuring the impact of those new services on the environment"; "test" is "a valid lifecycle state for polar, just like
'deployed' is currently, or 'declared' is for the catalog"; what is missing is "proper acknowledgement of the different phases of life that
an agent transitions through, how we manage each of those, measure their effects, control their environment and accesses in each phase".
And, of the catalog and its scripts: they began as "entirely deployment-time", and are now "increasingly viewed and/or modified to keep
consistent runtime state, which it was never intended to handle", much as tools around the Windows registry do, which it must not become;
with the GitOps controller already proposed, all three are to be considered "in the same light: lifecycle management".

This is a draft to think with, not a plan. Nothing here is decided.

## What there is today (read 2026-11-07)

**No workload has a phase.** Where it is in its life is implied, and by several things at once:
- *Declared*: a catalog entry (`infra/config/workloads/*.nuon`) and the facts its build prints (`--scaffold`). "The catalog is every workload
  there is" (`INFRA.md:664-670`).
- *In a target*: the only switch is `enabled: false` in a target's `config.nuon` (`resolve.nu:126-140`), and the workload's files are
  typed a second time into the target's layers (`targets/sandbox-local/target.nu:36-164`; `remaining-work.md:876` asks for them derived).
- *Under test*: a configuration under test enables it (`under-test.nu`), and the render marks it (`g:under-test`, the record's
  `under_test`, `configurations-under-test.md`, CT2).
- *Deployed*: Flux applied its layer; the signed record names it; the credentials agent's authority model holds it.
- *Gone*: Flux prunes its objects. Nothing else notices.

**Entering a phase is mostly derived; leaving one is not.** What the render computes from the enabled set is recomputed on every render and
reaches the agents through their documents' hash (`deploy-objects.nu:195-220`): the authority model, cert-issuer's floor, the served
workloads, the attested namespaces, the record. What was seeded once is not: the state agent's `schema` and its writer's `agents`
(`seed.nu:39-44`, "only ever the first ... a later change is an author's"), the policy and the groups. And what a workload leaves when it
goes stays: its sections in polar-schedules and its escrowed secrets, its last certificate (`Decommissioned` exists and is never issued,
`credentials-agent/common/src/events.rs:69-77`), its graph data and its `(:AgentHealth)` (`remaining-work.md:481-482`), its names in policy
and groups. Only a configuration under test's documents are taken away with it (`under-test.nu` `left_behind`, built this week).

**What the catalog has become.** Three different things share it:
1. *Declarations*: what kinds exist and what each is (`config-catalog-design.md:29-33`, "what an agent *is*"), most of which the build now
   prints and the catalog only places (`configuration.md:334-340`). These change with the code.
2. *Intent for a cluster*: which of them run here, how, in which topology, under which test (targets, configurations under test, the
   cluster's inputs). These change with a decision about one cluster.
3. *Facts about what is running*: what the render signs into the agents' documents at deploy time, and what up.nu seeds once and people
   then maintain by hand (`agents`, `schema`, groups, credentials). These are runtime state, and the catalog's tooling is how they are kept.

Deployment-time tooling keeping runtime state is the registry smell the maintainer names: a store that everything reads and anyone edits,
whose keys have no owner and no lifecycle, so nothing in it is ever retired. The principle that already exists points the other way:
"what an agent must know about others is a signed runtime section ... never a render-time env var" (`AGENTS.md:71-72`).

**The GitOps controller as proposed** (`gitops-controller.md`, on branch `worktree-agent-a7c38f6253cca72da`, not merged): reconcile
"from desired -> to deployed", the desired state a signed commit read as facts and a dependency graph, done "when invariants hold, not
when objects are applied", in shadow mode first. Its desired state is a deployment; it has no phases either.

## A shape to think about

**Lifecycle as one model, per workload, per cluster.** A workload is in one phase on a cluster at a time; each phase says what it is granted,
how it is watched, what it must show to move on, and what is cleaned up when it leaves. The phases suggested by what exists:

| Phase | Where it is | What it is granted | How it is watched | To move on |
|---|---|---|---|---|
| Declared | the catalog and its code; no cluster | nothing | its own tests, the kit, the catalog checks | built, its evidence signed |
| Released | an image by digest, a scaffold, evidence (`polar-evidence`) | nothing yet | the evidence's invariants | a cluster's intent names it |
| Under test | a cluster, marked (`g:under-test`, the record) | what its test grants; Cedar can keep it from production | apart: attestation, health, invariants report it under test | measured enough, a person promotes it |
| Deployed | a cluster, in service | what its catalog entry declares | as everything | a person demotes or retires it |
| Retiring | still running, withdrawing | reads stopped, writes finished | its drain | drained |
| Retired | gone | nothing: its certificates revoked `Decommissioned`, its secrets released | that nothing of it is left | none |

**The phase is a signed fact of the cluster, not a by-product of a render.** One document (say `lifecycle`, per cluster) names each
workload and its phase, signed by the person who decides it, as the catalog's apply is the sign-off today. Everything that now infers a
phase reads it instead: the render (what to make, how to mark it), the state agent (`schema` and `agents` are then *derived* from it: every
workload under test or deployed, each with its phase, so the GitLab pair is asked and owned, and reported apart), the credentials agent (what
it issues, and `Decommissioned` on retirement), attestation (how it reports), the broker through Cedar (`g:under-test` today becomes the
phase group the certificate carries). A configuration under test is then a way of putting workloads into the under-test phase together,
with the infrastructure their test needs; a target is a cluster's intent for what is deployed.

**The catalog splits by what changes when.** Declarations stay with the code (and could be printed by it altogether). The intent for a
cluster is the signed lifecycle document plus the target and its tests. What is running is reported by the agents and recorded in the
graph, not kept in files the tooling edits. The nu scripts become clients that write signed intent and read reported state, and (`cli-tools
first`) Rust CLI tools over libraries, in time.

**The controller moves workloads between phases.** The GitOps controller's desired state becomes the lifecycle document and the dependency
graph; a transition is its operation; "done" is the phase's invariants holding (the ones `polar-sign check` has, by phase); what a
workload leaves behind on retiring is its job, recorded in the graph first, as the Reaper's is. Derived documents (`schema`, `agents`)
are computed in the same transition from the same signed decision, so nobody signs a fact the build computed (`AGENTS.md`, "nobody
hand-declares them twice").

## What it would mean for the case in hand

The state agent's `schema` and `agents` would not be seeded once, nor kept by hand: they would follow from the cluster's lifecycle, and the
GitLab pair would appear in both as under test. Until a lifecycle document exists, any interim answer is a stand-in for that derivation.

## Open, for the maintainer

1. *Decided* (the maintainer, 2026-11-07, "Two levels"): a kind has declared and released, whatever cluster it is on; a workload on a
   cluster has under test, deployed, retiring and retired, and enters under test only from a released kind. A kind can be released once and
   be under test on one cluster while deployed on another.
2. Who signs a transition: always a person, or some (under test to deployed, after a test's measures hold) by a rule a person signed?
3. Where the lifecycle document lives: polar-schedules (runtime, signed, per cluster) or the deployment repository (deploy-time, the
   pipeline's)?
4. The derived documents: signed by whom, when no person signed that exact body?
5. The order of work: lifecycle first, then the catalog's split, then the controller on top; or the controller's proposal merged and
   reshaped around phases from the start.
6. The interim answer for `schema` and `agents` while this is designed.

## Also found

Doc drift, to fix with whatever comes next: `authority-model.md:377` says neither the policy nor the groups is seeded (both are);
`deployments.md:183` says the revoked set is never pruned (it is); `targets/sandbox-local/target.nu:65` calls cert-issuer a Job (it is a
Deployment); `config-catalog-design.md`'s status line is from 2026-10-02.
