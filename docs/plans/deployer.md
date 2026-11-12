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

# The deployer: Polar keeps its own deployment

> **This document has a twin.** [`deployer.claude.md`](deployer.claude.md) says the same thing, written for Claude to
> keep its understanding in the fewest words. This one is written for people. They are two sides of one plan, and
> they are changed together.
>
> This is a **capability-level plan**: the intent, and every feature it needs. Each feature has a plan of its own, in
> [`deployer/`](deployer/). It describes Polar's `main` as it is on 2026-11-12.

**Status: a proposal, not decided.** Nothing of the deployer is built. The maintainer has not yet said whether to
build it, and the order of work puts it after the lifecycle work (part 5).

## 1. The need

Polar is deployed from a signed description of what should run: one commit, signed by the deployment's own
`pipeline` certificate. Something has to make the cluster match that description, keep it matching, and say when it
does. Today that is Flux, an open-source GitOps tool. The maintainer put the need in one line (2026-11-02):

> "Ultimately, what I want from a 'gitops' service is to reconcile a state, from desired -> to deployed."

The need has several parts, each of which Flux falls short of:

- **Nothing is applied unless it was signed.** Polar signs its deployment with x509 certificates; Flux can only check
  OpenPGP or SSH signatures, so it applies whatever the git server gives it.
- **No credential sits in a Kubernetes Secret.** Flux reads its client key from one, and nothing ever renews it.
- **The applier is an agent like any other:** it has a Polar identity, its key is held by the custody daemon, and the
  attestation agent checks it.
- **Polar decides what may be deleted,** above all the storage that holds the ledger, the repositories and the graph.
- **A rollout is fast.** The maintainer: "I find it horribly slow... that's something I'd like to work on."
- **Order comes from what workloads declare they depend on,** not from layers kept by hand.
- **A rollout is finished when Polar's own invariants hold,** not when Kubernetes reports Ready.

## 2. How the need was found

- **From the work of moving the deployment onto Polar's own git server** (`cluster-bootstrap.md`, "Handing off to
  Polar's git server"). Once the deployment is hosted inside Polar, a compromised git server could serve a commit
  nobody signed, and Flux would apply it. The git server checks signatures when a commit is pushed, but Flux checks
  nothing when it applies.
- **From the maintainer's own statements,** 2026-11-02, quoted in this plan and its features.
- **From a review of Flux's code** against what Polar renders: 112 edge cases, 74 of which apply to Polar
  ([`deployer/flux-review.md`](deployer/flux-review.md)). It found where Flux's generality costs Polar. For example,
  an object moved to a later layer is deleted and recreated, and an empty layer is pruned whole.
- **From measuring a rollout** on Polar's development clusters. One rollout of all six layers took 151 seconds, of
  which about 130 were spent waiting on timers rather than working.

## 3. The plan

Build **the deployer**: one Polar agent that reads the signed deployment, verifies it, makes the cluster match it,
and reports what it did over Cassini. It has a small core of pure functions (parse, verify, plan, prune, judge health)
that can be tested exhaustively, and thin actors around it.

It is built in stages, and **the first stage changes nothing on a cluster:**

1. **Shadow.** The deployer runs beside Flux. It reads and verifies every commit, works out what it would do, and
   reports that next to what Flux did. It applies nothing. This is where the decision to go further is made, with
   numbers in hand.
2. **Takeover, one layer at a time,** each with a way back, starting with the layer nothing depends on.
3. **Bootstrap without Flux,** including recovery from a commit that breaks the git server.
4. **Flux removed,** with a migration for clusters already running.

The features it needs, each a plan of its own as it is reached:

| Feature | What it gives | Plan |
|---|---|---|
| **Verified before applied** | every commit is checked against the pipeline's signature, the tree it names, forward history and the cluster it is for, before anything is applied | [`deployer/verified-before-applied.md`](deployer/verified-before-applied.md) |
| The attestation agent told first | what is about to run is known before it runs | not yet written |
| An identity like any agent | no credential in a Secret; it runs before Polar does and joins it later | not yet written |
| Told, not polling | the next step starts the moment the last is healthy | not yet written |
| Order from declared dependencies | no hand-kept layers | not yet written |
| Done when invariants hold | Polar's own checks decide when a rollout has finished, and find drift | not yet written |
| Safe deletion | only what a signed commit once named can be deleted, and never storage or namespaces | not yet written |
| Bootstrap and recovery without a credential | the first commit is handed over through the Kubernetes API, not a server | not yet written |
| Shadow, takeover and Flux out | the stages above, each reversible | not yet written |

## 4. Alternatives considered

1. **Keep Flux, and fix what can be fixed around it.** Some of this is worth doing whatever is decided, and one fix
   is already in: Flux now rechecks a layer's dependencies every 5 seconds instead of 30, which brought a rollout
   from 183 to 77 seconds. But Flux cannot verify an x509 signature, and its credential stays in a Secret.
2. **Flux's own signature check.** Not possible: it accepts OpenPGP and SSH only, and Polar signs with x509.
3. **A verifying gateway.** Build only the first half of the deployer, the part that reads and verifies commits. It
   passes only verified commits to a read-only repository that Flux reads. Flux keeps applying. This gets most of the
   security for about a quarter of the work. It does not get faster rollouts, Polar's own deletion rules, or the
   removal of Flux.
4. **The deployer in full,** as above.

## 5. Why this plan

*Recommended, not decided.* Build the shadow stage first. It is also the first half of the verifying gateway, it
risks nothing, and it measures what the rest would cost. Decide between the gateway and the full deployer with those
measurements.

Two things bear on when:

- The maintainer decided (`lifecycle.md`, decision 5) that the order is: lifecycle first, then the catalog's split,
  then this controller, **reshaped around lifecycle phases**. This plan does not yet have phases.
- Disaster recovery waits for the controller (`remaining-work.md`, the order of work, step 12).

What would make the full deployer not worth building: a compromised git server is judged an acceptable risk; the
shadow never converges with Flux; a data-losing bug during takeover; Polar's render growing into what Flux is good at
(Helm, custom resources, many tenants); no one able to own it; or Flux gaining x509 verification.

## 6. How much of the need is met now

None of the deployer exists. What `main` has toward the need, on Flux:

- **Signed deployment.** The pipeline signs every commit, and Polar's git server refuses any push that is not signed.
  The operator's machine verifies the head once, when Flux is installed. Flux itself verifies nothing.
- **The keys.** The deployment's keys are P-256, as everything else Polar signs with.
- **The deployment hosted inside Polar.** After the hand-off, Flux reads from Polar's own git server, as
  `deployment:flux`.
- **A way back.** A commit that breaks the git server can be undone with `up.nu --bootstrap-again`.
- **The attestation agent knows what should run.** It receives a signed record of what should run, with each
  container's hardening, and holds every pod to it.
- **Faster rollouts.** Flux rechecks dependencies every 5 seconds.

What is still Flux's, and short of the need:

- No signature is checked when a commit is applied.
- The credential sits in a Secret and is never renewed. The deployment's certificates last 365 days, and nothing
  warns before they expire.
- The layers are kept by hand.
- Flux decides what is pruned.
- A rollout is done when Kubernetes says Ready.

## 7. What is left before this is a capability

- **Every feature in part 3.** Each gets its plan when it is reached, starting with *verified before applied*.
- **A decision** between the verifying gateway and the full deployer, after the shadow stage.
- **Reshaping around lifecycle phases,** once the lifecycle work defines them.
- **Open questions,** each to be asked when reached:
  - whether a seed ConfigMap or a bootstrap server carries the first commit;
  - who may delete storage or a namespace;
  - whether the deployer alone may run two pods during its own update;
  - whether drift is corrected or only reported;
  - where the deployment's CA key lives.
- **The deployer becomes a capability** when it applies every layer on a cluster with Flux removed. A capability
  document then says what it is, why it exists, and how it is used.
