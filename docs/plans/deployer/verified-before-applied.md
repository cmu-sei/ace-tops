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

# Verified before applied

> **This document has a twin.** [`verified-before-applied.claude.md`](verified-before-applied.claude.md) says the same
> thing, written for Claude. This one is written for people. They are two sides of one plan, and they are changed
> together.
>
> A **feature-level plan**, part of [the deployer](../deployer.md). It describes Polar's `main` as it is.

**Status: a proposal, not decided, nothing built.** It is the deployer's first feature, and useful on its own.

## 1. The need

Nothing should be applied to a Polar cluster unless all of these hold for it:

- **It was signed.** The commit was signed by the deployment's `pipeline` certificate, under the deployment's own
  certificate authority.
- **What is applied is what was signed.** The files applied are the files the signed commit names.
- **It moves forward.** The commit descends from the one applied before. An old signed commit must not be replayed to
  roll a cluster back.
- **Every step was signed,** not only the newest commit.
- **It is meant for this cluster.** One cluster's signed commit must not be applied to another.

These have to be checked **by whatever applies the commit, at the moment it applies it.** It is not enough that they
were checked by whatever stored it.

## 2. How the need was found

- **The hand-off decision.** When the deployment moved onto Polar's own git server, the decision was that "trust does
  not move with the hosting" (`cluster-bootstrap.md`, "Handing off to Polar's git server"). The git server stores the
  deployment, but it should not be what the cluster has to trust.
- **What the git server does and does not do.** It refuses any push not signed by the pipeline, checking every new
  commit and every branch head. That stops anyone else from writing the deployment. It does not stop the server
  itself, if it were compromised or simply wrong, from serving something else.
- **What Flux can do.** Flux, which applies the deployment today, can check OpenPGP or SSH signatures only. Polar signs
  with x509 certificates, so Flux applies whatever the server gives it. This was found reviewing Flux's code
  ([`flux-review.md`](flux-review.md), entry K5).
- **One check from the operator's machine.** The operator verifies the head once, when Flux is first installed. After
  that, Flux fetches every minute and checks nothing.

## 3. The plan

A **verifier**, the deployer's first part, which takes a commit only when every check below passes, and refuses it
whole otherwise.

1. **The signature.** Polar already has the check: `polar_signing::commit::verify_commit` confirms a commit's bytes
   were signed by a certificate named `pipeline`, chaining to the pinned deployment CA. It runs here, at apply time.
2. **The files.** A git commit names its tree by a SHA-1 digest, which is weak. So the pipeline adds a line to the
   signed commit message, `Provenance-Sha256: <digest>`, naming the SHA-256 of `provenance.json`.
   - `provenance.json` already lists every file of the deployment with its SHA-256.
   - The verifier checks the line against `provenance.json`, and each file against its listed digest.
   - It refuses any file the list does not name.
3. **Forward only.** The new head must descend from the commit applied last. If not, it is refused as rewound, and
   the cluster stays as it is.
4. **The whole walk.** Every commit from the one applied to the new head is verified, not only the head. Otherwise an
   unsigned commit could slip in under a signed one.
5. **This cluster.** The commit's `provenance.json` must name this cluster's target. When it records the cluster's CA,
   that must be the CA this cluster actually has.
6. **Which time.** A head new to this cluster is checked against the clock. Older commits, and the one already
   applied, are checked as of when they were signed. A year-old applied commit must not suddenly be refused just
   because its certificate has since expired.
7. **One reading of the commit.** `verify_commit` returns what it verified: the tree, parents, times and message,
   parsed once from the exact bytes it checked. Nothing parses the commit a second time and disagrees about it.
8. **A refusal never makes things worse.** A commit that fails any check leaves the cluster on the last good one. It
   deletes nothing, restarts nothing, and reports what failed and how far behind the cluster now is.

**How it gets the commits.** Polar's agents reach Polar's services only through Cassini, never by a direct connection.
The git server already answers reads over Cassini, but a read gives back only the head's
files and its commit name. So **the git server gains a second kind of read**: the raw, signed commits from one commit
to the head, with the files of the head. The verifier trusts none of it until it has checked it.

**Where it runs first.** In the deployer's shadow stage: beside Flux, verifying each commit and reporting the verdict,
applying nothing. A verdict that disagrees with what Flux applied is the first thing to look at.

**Tests first.** Properties on the pure parts:
- any changed byte of a commit, a file, the digest line or a parent is refused;
- the verifier never takes a commit that does not descend from the one applied, whatever order the reads arrive in;
- the parsed commit is exactly the one verified;
- a commit for another target is refused.

## 4. Alternatives considered

1. **Trust the push-time check alone.** This is what main does today. It leaves the git server as something the
   cluster must trust.
2. **Flux's own signature check.** Not possible: no x509.
3. **Check only the newest commit.** Cheaper, but an unsigned commit could sit under a signed one, since the pipeline
   signs on top of whatever the server holds.
4. **Recompute git's tree digests instead of adding the SHA-256 line.** It is possible, but it ties trust to SHA-1, and
   the line costs one row in the commit message.
5. **Read the repository with git, directly.** That breaks the rule that agents reach Polar's services only through
   Cassini, and it needs a client certificate the deployer would have to hold.
6. **A verifying gateway.** Put the verifier in front of Flux: only verified commits reach a repository Flux reads.
   This is this same feature used another way, and the capability plan weighs it.

## 5. Why this plan

- Every check catches something the others do not, and each is small.
- The signature check already exists and is tested against every single-bit change of a real commit.
- The digest line is one line in a commit message the pipeline already writes.
- Reading over Cassini keeps the deployer inside the same rule as every other agent, with no credential of its own
  for git.
- Building it first, in shadow, risks nothing on a cluster and is useful whether or not the rest of the deployer
  follows.

## 6. How much of the need is met now

Partly, but not by whatever applies the commit:

- **The git server checks every push.** It refuses any commit not signed by the pipeline, checking new commits and
  branch heads. A head is checked as of now, an older commit as of its own time.
- **The operator's machine checks the head once,** when Flux is installed.
- **`provenance.json` already has most of what is needed:** each file's SHA-256, the target, the deployment CA's
  digest, and the cluster's CA digest.
- **Flux applies without checking.** Nothing verifies at apply time.
- **The digest line does not exist.** The commit message names layers, not digests.
- **`verify_commit` returns who signed, not what was signed,** and it does not look at the certificate's purpose.
- **The pipeline's certificate is marked for client authentication only,** the same key that also signs. The
  deployment's certificates last 365 days, and nothing warns before they expire.

## 7. What is left before this is met

- The digest line, written by `publish`.
- `verify_commit` returning the verified commit.
- The git server's read of raw commits over Cassini.
- The verifier itself, with its properties, run in the deployer's shadow stage.
- The rewound and wrong-cluster refusals, reported.
- **Later, and smaller:**
  - a signing purpose of its own on the pipeline's certificate, checked by the verifier;
  - a warning before the deployment's certificates expire.

It is met when every commit a cluster applies has passed these checks at the moment of applying. That needs either
the verifying gateway or the deployer's takeover; the capability plan decides which.
