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

**Status: a proposal, not decided.** Everything it brings is built and has run on a development cluster, but from
another line of work, not from `main`.

## 1. The need

The record store's runtime has to be on `main`, so that every line of work deploys the same store to the cluster they
share:

- **the logs in the git server:** evidence and schedules each appended to a signed log, with proofs, read over Cassini;
- **the evidence intake** appending each admitted record to the evidence log;
- **the witness:** the attestation agent co-signs each checkpoint, and readers require its co-signature;
- **schedules on the log:** the scheduler observer reads agents' signed configuration from the schedules log;
- **people's tools over Cassini:** `polar-sign` and the evidence tools reading and writing as the person, with no
  direct connection to the store.

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

Four steps, in the order each depends on the last. Each is prepared on a branch from `main`, with its tests passing
there, then taken onto `main` and deployed to the shared cluster before the next starts. So `main` runs on the cluster
at every step, and each step can be undone on its own.

1. **The logs, their reads and the evidence intake.** The git server opens its logs at start, as they are on the
   cluster's volume (a log there already is read, never begun again), and catches the evidence log up with anything the
   evidence repository holds that it does not. The intake appends each admitted record. Reads and proofs are answered
   over Cassini. The attestation agent's verdicts go to the intake as records. The store's checkpoint key comes from
   the credentials agent, as the ledger's does.
2. **The witness.** The attestation agent co-signs each checkpoint. The store serves the latest co-signed one. Each
   pins the other's key in its signed settings, written once by the seed. After this step, two of the four refused
   settings are known to `main`.
3. **Schedules on the log.** A signed section is appended to the schedules log, then committed to the repository at
   its place. The scheduler observer reads the log, holding it to both keys. After this step, all four settings are
   known, and the refused updates end.
4. **People's tools.** A person's floor on Cassini: the store's request topics, and answer topics named for that person
   alone, which policy lets nobody else hear. The asking side the tools share. `polar-sign`'s pushes go over Cassini
   when no git repository is named.

**What stays where it is, unless decided otherwise:**

- **the evidence review tool and the intents it reads,** which are the other line of work's own;
- **the source-code git server and its git remote helper,** a separate service with direct connections, which nothing
  on `main` uses yet.

**How it fits the work on `main` since.** Anything brought over takes its TLS from the agent's crypto actor, as every
agent on `main` now does, and talks to custody only through it. The store's request and answer types are additions: no
existing message changes.

**Tests first,** as they were written: each step brings its tests, and runs them on `main` before it is taken.

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

- **On `main`:** the log format and the credentials ledger's signed checkpoints; the git server's git face over the
  crypto actor's TLS; the policy schema that lets a person's answer topic be judged.
- **Not on `main`:** the logs in the git server, the evidence intake's appends, reads over Cassini, the witness,
  schedules on the log, a person's floor and the tools' asking side.
- **On the cluster:** the logs exist on the git server's volume, written by the other line of work. `main`'s git server
  ignores them today.

## 7. What is left before this is met

- **The four steps,** each taken onto `main` and deployed.
- **The design document brought up to date on `main`.** `main`'s copy of it is behind.
- **Decisions to make before step 1:** what stays on the other line of work (part 3), and where the store's checkpoint
  key is kept under the crypto actor's rules: a key file on the store's volume, as it is now, or a named key held in
  custody.
- **The size:** about fifteen thousand lines across the git server, the attestation agent, the scheduler observer and
  the tools, most of them tests. Each step is reviewed on its own.

It is met when `main`, deployed to the shared cluster, runs the store with its logs, its witness and schedules on the
log, from the cluster's existing state, and no agent refuses its configuration.
