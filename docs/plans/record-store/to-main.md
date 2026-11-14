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

# The store on `main`

> **This document has a twin.** [`to-main.claude.md`](to-main.claude.md) says the same thing, written for Claude. This
> one is written for people. They are two sides of one plan, and they are changed together.
>
> A **feature-level plan**, part of [the record store](../record-store.md).

**Status: done.** All five steps are on `main` and running on the shared cluster (section 6); what is left is for
later (section 7).

## 1. The need

The record store's runtime has to be on `main`, so that every line of work deploys the same store to the cluster they
share:

- **the logs in the git server:** evidence and schedules each appended to a signed log, with proofs, read over Cassini;
- **the evidence intake** appending each admitted record to the evidence log;
- **the witness:** the attestation agent co-signs each checkpoint, and readers require its co-signature;
- **schedules on the log:** the scheduler observer reads agents' signed configuration from the schedules log;
- **people's tools over Cassini:** `polar-sign` and the evidence tools reading and writing as the person, with no
  direct connection to the store;
- **the source-code git server,** which holds source code apart from records, with its git client.

And it has to arrive **without wiping the cluster's state:** the evidence log already holds every record the evidence
repository does, and the schedules log holds every signed section.

## 2. How the need was found

The store was built on one line of work. Its seed writes four settings into three agents' signed configuration: the
witness's key into the git server's, the store's key into the attestation agent's, and both into the scheduler
observer's. `main` does not know these settings, so when it is deployed to the shared cluster, each of the three agents
refuses its whole configuration update. Nothing `main` needs is in those updates, so it loses no setting; but the error
repeats on every delivery, and the two lines of work cannot both be right about the same state. The rule for this is
that a change to shared infrastructure goes to `main` first, and other lines of work take it from there.

## 3. The plan

Five steps, in the order each depends on the last. Each is prepared on a branch from `main` as it is now, after its
crypto-actor work on TLS, with its tests passing there. It is then taken onto `main` and deployed to the shared
cluster before the next starts. So `main` runs on the cluster at every step, and each step can be undone on its own.

**Every key is used through the agent's crypto actor,** as everything on `main` now is: the store's checkpoint key,
the witness's co-signing key, and the evidence records' signing key. Nothing brought over talks to custody itself or
builds TLS of its own. Where a step needs the crypto actor to sign something new, the message is added to `main`
before that step, and the actor checks what it is asked to sign, as it already does for evidence records:

- **A checkpoint signature,** for the store. The actor is given a checkpoint's text, and signs it only if it is
  exactly a checkpoint of one of this store's own logs: three lines, the log's origin, its size in decimal and its root
  in base64, with no extension lines. The origin must be the actor's own identity, read from its certificate, then the
  log's name. This is how the store names its logs today, so no setting is needed and none is trusted from the caller.
  The actor returns the signed note's signature line.
- **A co-signature,** for the witness. The actor is given only the checkpoint text. It signs only if the text is a
  checkpoint whose origin is the store the witness was pinned to, and it stamps the time from its own clock, so no
  caller can choose a time and backdate a co-signature. It builds the co-signed message itself (`cosignature/v1`, the
  time, then the text) and returns the co-signature line and the time it stamped. Whether the checkpoint is consistent
  with the last one co-signed stays the witness's own check, before it asks.

**The keys stay where they are.** For now, the store's checkpoint key and the witness's co-signing key are each a key
file on the agent's own volume, as they are today. The crypto actor reads each through a variable of its own, declared
once with the actor's other key files and set by the deployment for its one workload, at today's path. So the keys on
the cluster are kept, and so are the pins that name them. The actor makes a key if its file is absent, readable by the
agent alone, and never replaces one, since a new key would break every pin that names the old one. When custody can hold
a named key that outlives its pod, both move there.

**The store's key is certified by the credentials agent, through the crypto actor.** Today it is not certified at all:
the store makes its key and the pins carry its public half, because no way existed to certify a workload's own lasting
key. In the first step, the crypto actor asks the credentials agent to certify the checkpoint key for checkpoints alone,
over a request topic and an answer topic of their own, and asks again before the certificate expires. The store's own
code never asks. The credentials agent certifies such a key only for a workload the catalog gives that capability (the
git server), judged by the identity the broker stamped on the request, and each answer names who asked and goes to
them alone. The git server can use exactly those two topics because its build says it certifies a checkpoint key, as
every agent's topics follow from how it is built, never declared by hand. The witness's key stays pinned by its public
half, as it is now.

**Before the fourth step:** person's tools on `main` take their TLS from a crypto actor over the person's key files, and
the command-line Cassini client moves to a package of its own. The fourth and fifth steps build on both.

The steps, with what each changes in signed or kept state, and what the running cluster needs to take it:

1. **The logs, their reads and the evidence intake.** The git server opens its logs at start, as they are on its
   volume (a log there already is read, never begun again), and catches the evidence log up with anything the evidence
   repository holds that it does not. The intake appends each admitted record. Reads and proofs are answered over
   Cassini. The attestation agent's verdicts go to the intake as records.
   - *State:* the log files and the checkpoint key on the git server's volume are already there and are kept; the
     evidence log gains the records it was missing. Nothing in the schedules repository changes.
   - *To take it:* the crypto actor's checkpoint signature and its certification request on `main`, with the credentials
     agent's side; an ordinary deployment, with no data wiped.
2. **The witness.** The attestation agent co-signs each checkpoint, and the store serves the latest co-signed one.
   - *State:* the witness's key and what it last co-signed are already on the attestation agent's volume and are
     kept. The pins, each agent's copy of the other's key, are already in the two agents' signed settings, so the seed
     writes nothing new; from this step `main` reads them, and those two agents stop refusing their updates.
   - *To take it:* the crypto actor's co-signature on `main`; an ordinary deployment.
3. **Schedules on the log.** A signed section is appended to the schedules log, then committed to the repository at
   its place. The scheduler observer reads the log, holding it to both keys.
   - *State:* the schedules log is already on the git server's volume; the observer's two pins are already in its
     signed settings. From this step the last refused update is read, and no agent refuses its configuration.
   - *To take it:* an ordinary deployment. The observer must start with both pins, which it has.
4. **People's tools.** A person's floor on Cassini: the store's request topics, and answer topics named for that person
   alone, which policy lets nobody else hear. Then the asking side the tools share, and `polar-sign`'s pushes over
   Cassini when no git repository is named.
   - *State:* the policy that lets a person hear their own answers is already in force on the cluster. Nothing
     persisted changes. The floor is part of every agent, so every agent is rebuilt. The tools add no new signing with a
     key read from a file: the person's signing they do is the signing those tools already did.
   - *To take it:* an ordinary deployment; people's tools updated on their machines.
5. **The source-code git server, and its git client.** A second service holds source code. It takes direct
   connections, as git needs, with Polar certificates saying who and Cedar deciding each operation, and it reports
   everything it does over Cassini. A git remote helper lets plain `git` reach it as the person.
   - *State:* a new workload with a volume of its own for its repositories, new to the cluster. Its TLS key is the
     pod's own, under the same variable names every server on `main` now uses. Who may do what comes from the signed
     groups and policy, under the git operations the policy schema already names.
   - *To take it:* the catalog entry and its volume applied with the deployment; people's git client installed.

**What stays where it is:** the evidence review tool and the intents it reads, which are the other line of work's own.

**Tests first,** as they were written: each step brings its tests and runs them on `main` before it is taken.

## 4. Alternatives considered

1. **Leave the store on the other line of work, and have `main` accept the four settings without using them.** Small,
   but four settings that do nothing on `main`, and two versions of the git server serving the same cluster.
2. **Keep the two apart on the cluster:** the other line of work stops pinning keys there. Its store would run unwitnessed
   on the shared cluster, and its scheduler observer could not read the schedules log, so it would be testing something
   other than what it is building.
3. **Everything at once.** One very large change, with no point between where `main` is known to run on the cluster.
4. **In steps, each deployed before the next,** as above.

## 5. Why this plan

- It follows the rule for shared infrastructure: the change is on `main`, and other lines of work take it from there.
- Each step is small enough to review, deploy and, if needed, undo.
- The cluster's state carries over: the logs are opened as they are, and the evidence log catches up rather than starting
  again.
- Most of the work is already done and tested; what is new is fitting it to `main` as it is now.

## 6. How much of the need is met now

**All five steps are built on `main` and running on the shared cluster**, deployed from the cluster's existing state with
nothing wiped. Every pod is running, and no agent refuses its configuration.

1. **The logs, their reads and the evidence intake** (`871739eb`, `ca14b6d4`, `d77874e1`, `a85157e4`, with `0ab01c5f`).
   The logs on the git server's volume opened as they were; the checkpoint key was kept, and the credentials agent
   certifies it; the evidence log caught up with the repository; the attestation agent's records go through the
   intake.
2. **The witness** (`1381df26`, `bc9880f3`, `7e900ea8`, `bfffd2c9`, `8a6b8eff`, with `7a6363de`). The witness's key and
   what it had co-signed were kept; the record of what it holds now names the key it was made under; the two agents
   took the pins already in their signed settings.
3. **Schedules on the log** (`de708eb8`, `c1592391`, `4f9ea4ef`, `908f4710`). The schedules log opened as it was and
   caught up with the repository; the scheduler observer reads the log, held to both keys, and took its pins.
4. **People's tools over Cassini** (`aee96e78`, `799513d7`, `23f90586`, `a3cdf719`). A person's floor, Cedar told whom
   a topic is addressed to, the store answering a person and taking their signed sections, and `polar-sign`'s pushes
   over Cassini.
5. **The source-code git server and its git client** (`e63282ca`, `a3fd337b`, `ffabeec5`). polar-git's repositories
   opened as they were on its volume. Plain git through the client pushed, cloned and force-pushed as a repository's
   owner, and someone policy says nothing of was refused.

**A fix found in review** (`f06c4022`): a push and a section sent over Cassini both write the schedules repository and
its log, and nothing kept them apart, so the log could part from the repository. Now one writer holds a repository at a
time, a push from an older clone is refused before anything is logged, and if a change was logged and the repository
then did not move, the log is put back to what the repository holds.

Every key is used through the agent's crypto actor, and nothing brought over talks to custody itself or builds TLS of
its own.

A test repository, `f1-bite5-check`, made while checking the fifth step, is left on polar-git's volume on the shared
cluster.

## 7. What is left before this is met

The need as stated is met. Left, each for later and none blocking:

- **The checkpoint key into custody,** as a named key that outlives its pod, once custody can hold one. Until then it
  is a key file on the git server's volume, made and held by the crypto actor.
- **The witness's memory without its key:** if the record of what the witness holds is lost while its key survives,
  the witness starts again empty under the same key, and nothing can tell that from a first start. Closing it needs
  the crypto actor to make the key and the record together.
- **Large records as blobs:** a record larger than a log entry carries still has no place in the log.
- **The evidence intake does not wait for the repository's writer,** by design: a record logged by a push that then
  fails stays in the evidence log only, and that log is meant to hold at least what the repository does.

It is met when `main`, deployed to the shared cluster, runs the store with its logs, its witness and schedules on the
log, from the cluster's existing state, and no agent refuses its configuration.
