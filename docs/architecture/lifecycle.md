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

A draft to think with; the questions at its end are decided as the maintainer answers them, and the rest is not a plan yet.

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
workload leaves behind on retiring is its job, recorded in the graph first, as the Reaper's is. What follows from a move (the state agent's
`schema` and `agents`, the authority model) is not a document at all: each agent derives it from the signed lifecycle and the kinds'
releases (decision 4), so nobody signs a fact the build computed (`AGENTS.md`, "nobody hand-declares them twice").

## What it would mean for the case in hand

The state agent's `schema` and `agents` would not be seeded once, nor kept by hand: they would follow from the cluster's lifecycle, and the
GitLab pair would appear in both as under test. Until a lifecycle document exists, any interim answer is a stand-in for that derivation.

## From Vaughn's operator (the port's area 4, read 2026-11-09)

Decided 2026-11-07 (`remaining-work.md`, the port's area 4): the operator is not merged; its phases and back-off are taken into this
design. Read on his branch (`ace-remote/port/public-polar-blitz-deploy`, `src/agents/polar-operator/`, commit `0339cc89`, a prototype run
from a laptop with that kubeconfig's rights): a `PolarAgent` resource and a controller that keeps one deployment of an agent alive, a
processor that projects what it saw into the graph. What follows is for this design, not decided.

**It works one level below this document's phases.** Its phases (`crd.rs`, `Phase`: Pending, Starting, Running, Replacing, Ending,
BackingOff, CrashLoop, Suspended) are a deployment's running state, not where a workload is in its life: a workload under test or deployed
is, at any moment, in one of them. They fill this document's "how it is watched" and give "to move on" its measures.

**What is worth taking**, each against what main has:

- *The instance policy as a pure decision* (`lifecycle.rs`, `decide`: what is wanted, the instances seen, what is remembered, the time, in;
  the actions and the status to write, out; tested without a cluster). Its five rules: one instance, never two, a replacement only when no
  pod of the agent exists, terminating ones included; every ending recorded once, then its pod removed; an ending within 30 s of the start
  a failure, failures in a row backing off (2 s, doubling, to 5 min), an ending after a long run (a rejuvenation) replaced at once; five
  failures in a row held (`CrashLoop`), a new spec releasing it; a new spec stopping the instance and starting the next once it is gone.
  Main has part of this from Kubernetes: every agent is a Deployment of one whose pod restarts in place at every ending
  (`deployments.md`, step 4), and an agent ends by its HealthCheckActor's verdict. What main has not: a held state (Kubernetes backs off and
  retries forever), the distinction between a failure and a rejuvenation, and any record of either. Proposed: the controller this document
  plans holds this policy per phase (a workload under test held sooner than one deployed, say), as a pure function in the same shape.
- *Every ending, recorded, with the instance's own account* (`crd.rs`, `Ending`: kind, exit code, Kubernetes' reason, the instance's
  termination message or its last log lines, how long it ran; its contract, every builder agent writing `/dev/termination-log`). This is
  the observable this document's promotion rules need ("its invariants for a stated time, no attestation finding", decision 2) and what the
  attestation threat model calls gold (crash events). Proposed: recorded in the graph by the attestation agent, which holds the pod
  observer's role (`pod-reaper.md`, update 2026-10-26), with his query's shape as an invariant: endings soon after a start, and why.
- *Three levels in the graph* (agent, deployment, instance: `(:PolarAgent {name})`, a target's deployment node, `(:Pod)`, with the phase
  history on the deployment and each ending on its instance). It is decision 1's two levels (a kind; a workload on a cluster) with the
  instance under them. Proposed: the kind and the workload on a cluster as this document names them, the phase history as states keyed on
  the reporter's time, as build-processor's are (B5).
- *A crash loop as a reason to move*: decision 2's rule-driven moves (deployed back to under test, or under test into retiring) can name
  "held in a crash loop" as a measure that broke, so a hold is not only the controller's state but a signed rule's evidence.
- *Its boundary*, already Polar's: "the operator starts processes, the scheduler configures them at runtime ... the operator never delivers
  configuration" (his README) is `AGENTS.md`'s "control travels signed, at run time".

**What is not taken:** the `PolarAgent` resource and a second controller making pods beside Flux and the catalog (two deployment systems);
its own ServiceAccount per agent and its `pod` overlay (the catalog's facts); capabilities in a spec by hand (the builder computes them);
lifecycle events published as a broker client with no identity of its own (`BROKER_ADDR` and a client certificate from the environment);
a controller run from a laptop with that kubeconfig's rights.

**Open, for the maintainer, when the controller is designed:**
- Does the controller hold the instance policy, or is Kubernetes' restart with the HealthCheckActor's verdict enough, the controller
  only recording endings and holding (a held workload scaled to zero) when a signed rule says so?
- The thresholds (30 s to a failure, 2 s to 5 min back-off, 5 failures to a hold): per phase, signed in the lifecycle document, or the
  controller's Dynamic settings?
- Is a hold released by a new signed version of the workload's release (his "a new spec releases it"), by a person's move, or both?

## Open, for the maintainer

1. *Decided* (the maintainer, 2026-11-07, "Two levels"): a kind has declared and released, whatever cluster it is on; a workload on a
   cluster has under test, deployed, retiring and retired, and enters under test only from a released kind. A kind can be released once and
   be under test on one cluster while deployed on another.
2. *Decided* (the maintainer, 2026-11-07, "Both, by transition", then "Promotion by rule too"): a person decides, at the time, a workload's
   move into under test and into retired (its certificates revoked `Decommissioned`, its secrets released). A rule a person signed may
   move it the rest of the way: under test into deployed when the rule's measures hold (its invariants for a stated time, no attestation
   finding, say), and back, deployed to under test or under test into retiring, when they break or attestation condemns it. A move by rule
   names the rule and the evidence it met, so the record says why, and who signed the rule.
3. *Decided* (the maintainer, 2026-11-07, "polar-schedules"): the lifecycle document is signed runtime configuration in polar-schedules,
   as every other control fact, changed without a re-render ("control travels signed, at run time"); the agents read it through the
   scheduler as they read their sections, a move takes effect when its signed version arrives, and the deployment is rendered from it.
4. *Decided* (the maintainer, 2026-11-07, "agents derive them", then "Answered when asked, checked"): there are no derived documents.
   Each agent computes what it needs from what it already believes: the signed lifecycle and the facts of each kind's release (its
   scaffold, by digest, in signed evidence). The state agent derives its `schema` and `agents`, the credentials agent its authority
   model, so nothing is signed twice and nothing drifts from what it follows from. What an agent derived is observable as its
   configuration is: in its answer to "what do you hold in force" (the derived body's digest, and the signed inputs it came from, the
   lifecycle's version and the releases'), and `polar-sign check --ask` derives the same itself and compares, a disagreement a violated
   invariant. The maintainer's question, whether agents should share what they derived somewhere: answered by introspection, as an
   infrastructure actor answers for its configuration, and not stored again.
5. *Decided* (the maintainer, 2026-11-07, "Lifecycle first"): the lifecycle document and its reader first, then the state agent deriving
   its `schema` and `agents` (the GitLab case) and the render reading phases; then the catalog's split around it; then the controller on
   both, its proposal merged and reshaped around phases. Each step usable on its own.
6. *Decided* (the maintainer, 2026-11-07, "Leave them reported"): until the state agent derives them, `one-owner-per-label` and
   `seen-by-health` stay violated on a cluster carrying the GitLab test, and say the truth: Polar does not yet recognize a workload under
   test. Nothing is signed by hand that the derivation will replace.

## Also found

Doc drift, to fix with whatever comes next: `authority-model.md:377` says neither the policy nor the groups is seeded (both are);
`deployments.md:183` says the revoked set is never pruned (it is); `targets/sandbox-local/target.nu:65` calls cert-issuer a Job (it is a
Deployment); `config-catalog-design.md`'s status line is from 2026-10-02.
