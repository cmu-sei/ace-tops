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

# The record store: Polar's signed logs

> **This document has a twin.** [`record-store.claude.md`](record-store.claude.md) says the same thing, written for
> Claude to keep its understanding in the fewest words. This one is written for people. They are two sides of one plan,
> and they are changed together.
>
> This is a **capability-level plan**: the intent, and every feature it needs. Each feature has a plan of its own, in
> [`record-store/`](record-store/). The design is in
> [`docs/architecture/record-store.md`](../architecture/record-store.md). It describes Polar's `main` as it is.

**Status: partly on `main`; most of it is built elsewhere and not yet on `main`.** The shared log format and the
credentials ledger's signed checkpoints are on `main`. The logs in the git server, their reads, the witness, and
schedules on the log are built and have run on a development cluster, but not from `main`. Bringing them to `main` is
the next feature.

## 1. The need

Polar keeps several kinds of signed fact that are only ever added to: evidence records, the agents' signed
configuration (the schedules repository), the deployment and its record, and the credentials agent's ledger. Each needs:

- **append only:** a wrong entry is superseded by a newer one, never changed or removed;
- **its own time:** when an entry was added is the store's word, not the author's;
- **proof:** anyone can check that an entry is in the log, and that the log was only ever added to;
- **a witness:** a second party co-signs what the store says it holds, so the store alone cannot rewrite it;
- **reads from inside Polar over Cassini,** as every agent reaches every Polar service.

## 2. How the need was found

- **Every property was being built on top of git, not given by it.** An evidence record's time was its commit's, which
  is the pusher's word; when it was added was worked out by reading the git history; a push could delete a file and a
  reader of the tree would no longer see it; nothing outside the server could check the server had not rewritten what
  it held.
- **The credentials ledger's entries had no type or version,** so a newer writer stopped an older reader.
- **Git itself was barely used:** agents read and write over Cassini, and nobody branches or merges evidence.
- **Two lines of work share one development cluster.** The store's logs, witness and schedules log were built on one
  line of work only. Its seed writes the witness and store keys into three agents' signed settings, and the other line,
  which does not know those settings, refuses each of those agents' whole configuration update. So the store's runtime
  is shared infrastructure, and has to be in one place.

## 3. The plan

**A store of signed logs replaces git as Polar's system of record,** and can still present as git where git is needed:
at deployment time, and in a degraded mode where a site keeps its deployment in its own git server. The git server
becomes the store. Its logs are Merkle trees of typed, versioned entries in deterministic CBOR, with checkpoints signed
by the store's own key and co-signed by the attestation agent as witness. Agents reach it over Cassini, and people
reach it through their own tools over Cassini, with their own certificates.

Its features, each a plan of its own as it is reached:

| Feature | What it gives | State | Plan |
|---|---|---|---|
| The log format | the entry, the Merkle tree and its proofs, signed checkpoints, and a replay that reports what it cannot read | on `main` | (in the design document) |
| The ledger's checkpoints | the credentials ledger's history signed by a key of its own | on `main` | (in the design document) |
| **The store on `main`** | the logs in the git server, reads over Cassini, the evidence intake, the witness, schedules on the log, people's tools, and the source-code git server, brought to `main` | proposed | [`record-store/to-main.md`](record-store/to-main.md) |
| The deployment on the log | the deployment's commits as log entries, read by the deployer | waits for the deployer | not yet written |
| The repositories moved in, and git off | the development cluster's repositories as logs; the git face turned off where self-hosted | not started | not yet written |
| The ledger's checkpoints in the store | the credentials ledger's checkpoints published as store entries | not started | not yet written |
| Large records as blobs | a record too large for an entry, kept by its digest in the registry | not started | not yet written |

## 4. Alternatives considered

1. **Keep git, and build each property on top of it.** That was the path until now: a push window on the server's
   clock, a reader that reads the history, add-only rules on one repository. Each property cost a mechanism, and none
   could be checked from outside.
2. **An external transparency log.** Proven designs exist, and Polar's format follows them. But Polar needs typed
   entries with a critical flag, its own admission rules, P-256 co-signatures and reads over Cassini, and it would
   still need the git face.
3. **A store of Polar's own, presenting as git,** as above.

## 5. Why this plan

- Each property becomes a property of the store, checked by anyone who reads it, not a rule the server promises to keep.
- One format for every kind of signed fact, the credentials ledger's included.
- The git face keeps what needs git working: deployment time, a site's own git server.
- It is built and has run: what is left is mainly bringing it to `main`, and the parts that wait for other work.

## 6. How much of the need is met now

On `main`, and running on the shared cluster:

- **The format crate** and **the credentials ledger on it**, with signed checkpoints.
- **The logs in the git server**, appended by the evidence intake and by every push and signed section to the schedules
  repository, each checkpoint signed by the git server's crypto actor with a key the credentials agent certifies, and
  read over Cassini.
- **The attestation agent witnessing every checkpoint**, co-signing through its crypto actor, and readers requiring its
  co-signature.
- **The scheduler observer reading schedules from the log**, held to the store's key and the witness's.
- **People's tools reading and writing over Cassini**, the store answering each person on a topic only they may hear.
- **The source-code git server and its git client**, every operation judged by policy and reported.

The repositories are still git repositories beside the logs, and git is still how the deployment is read.

Not met anywhere yet: the deployment on the log, the repositories moved in, git turned off, and records too large for an
entry.

## 7. What is left before this is a capability

- **The features that wait:** the deployment on the log (with the deployer), the repositories moved in and git off,
  the ledger's checkpoints in the store, and large records as blobs.
- **The keys into custody:** the checkpoint key as a named key that outlives its pod, once custody can hold one.
- **The witness's memory:** a witness that loses what it holds but keeps its key starts again empty, and nothing can
  tell; the crypto actor would have to make the key and the record together.
- **A capability document** saying what the store is, why it exists and how it is used, once it is on `main` and the
  git face is the exception.
