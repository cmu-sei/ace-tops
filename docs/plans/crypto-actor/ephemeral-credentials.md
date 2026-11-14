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

# Credentials opened only while they are used

> **This document has a twin.** [`ephemeral-credentials.claude.md`](ephemeral-credentials.claude.md) says the same
> thing, written for Claude. This one is written for people. They are two sides of one plan, and they are changed
> together.
>
> A **feature-level plan**, part of [the crypto actor](../crypto-actor.md). It describes Polar's `main` as it is.

**Status: a proposal, not decided, nothing built.**

## 1. The need

A credential an agent uses (a token or a password, the user name that goes with it, and a token a registry handed back
for a login) should be readable in the agent's memory only while a request is using it. At rest it should be what it
was when it arrived: sealed to the pod's escrow key, which only custody holds. And the part of the agent that does hold
it, the crypto actor, should be protected the way custody is.

Polar claims zero trust inside its boundary: no component trusts another on the strength of where it runs. A credential
that sits in the clear in an agent's memory for the agent's whole life is trusted to that memory, and that is the trust
this removes.

## 2. How the need was found

Asking what the crypto actor does with a credential once it has one. Today, when an agent's signed configuration names
a credential, the crypto actor opens it with custody once, at registration, and keeps the plaintext for as long as the
credential is registered:

- the secret in a buffer that is wiped when it is dropped, and not before;
- the user name, opened the same way, as ordinary text, which is not wiped at all;
- each token a registry returns for a login, held the same way until it is released.

The process the crypto actor runs in is not hardened as custody is. Custody locks its memory, so nothing of it is
written to swap, and makes itself undumpable, so no core file or same-user debugger can read it. An agent process does
neither. So anything that can read an agent's memory without running code in it finds every credential the agent holds:
a bug that discloses memory, swap, a core file, a checkpoint of the container or a snapshot of the node, or a read of the
process's memory from beside it.

## 3. The plan

**Each credential stays sealed until a request needs it.** The crypto actor keeps the credential in the form it arrived
in, sealed to the pod's escrow key. For each request that carries it, the crypto actor asks custody to open it, puts it
on the request, sends the request, and wipes it. Registration still opens it once, to check that it is well formed and
that its binding is whole, and then wipes it.

**The user name is part of the credential.** It is sealed at rest, opened per use and wiped, exactly as the password or
token is. Nothing about a credential is held in the clear but its name and where it may be used.

**Tokens a registry returns are sealed when they arrive.** The crypto actor seals each to the pod's own escrow key, keeps
only the sealed form, and opens it for each request that presents it.

**Custody's part does not grow.** Opening something sealed to a key it holds is an operation the kernel keyring would
do, and custody already does it for the crypto actor. The escrow key keeps its one purpose: what is sealed to this pod
is opened only here. No new key is made.

**Custody records each open.** How often each credential is opened, and when, becomes something Polar can see. A
credential opened when no request went out, or far more often than the agent's traffic explains, is evidence of
someone in the agent asking for it.

**The crypto actor is protected as custody is,** as far as an agent process allows:

- the process is made undumpable at start, so no core file is written and no other process of the same user can read
  its memory;
- the memory that holds an opened credential is locked, so it is never written to swap, and kept out of any dump. Where
  the kernel offers memory that even the kernel's own mappings cannot read, the opened credential is placed there.

**Tests first.** Properties: at rest, nothing the crypto actor holds is a credential in the clear; every request that
carries one gets it opened once and wiped after; the opens custody records match the requests sent. A measurement of the
cost per request in a release build.

## 4. Alternatives considered

1. **Keep things as they are.** Every credential an agent has stays readable in its memory for the agent's life, to
   anything that can read that memory.
2. **A separate key in custody to wrap the credentials.** Rejected: the escrow key already seals them, for this same
   purpose. A second key would be a second thing to make, certify and rotate, for no gain.
3. **Lock and hide the agent's memory, and nothing else.** Rejected as the whole answer: it keeps credentials out of swap
   and dumps, but not out of a bug that discloses memory, a container checkpoint or a snapshot of the node.
4. **Lock the whole agent's memory, as custody does.** Weighed in part 6: an agent is far larger than custody, and a
   whole-process lock is bounded by what the pod may lock.

## 5. Why this plan

- **It removes standing trust in an agent's memory.** What a read of that memory can find is what a request is using at
  that moment, not every credential the agent has.
- **It costs almost nothing.** Custody has been measured at about 320,000 key operations a second on the maintainer's
  machine, and a credentialed request is a low-rate event. Opening, using and wiping a credential adds well under a
  millisecond to a request that crosses a network.
- **Nothing new can fail.** Custody already answers every TLS handshake the agent makes; a credentialed request depends
  on it no more than before.
- **It adds detection.** Each open is recorded, so a credential being asked for without a reason is visible.
- **Custody stays the keyring it was built to be.** It opens what is sealed to its key; it knows nothing of what the
  credential is for.

## 6. How much of the need is met now

- Credentials reach the crypto actor sealed to the pod's escrow key, and only custody can open them.
- No credential reaches a protocol handler: the crypto actor puts it on the request itself. The one exception is git
  over ssh, where the ssh key is given to the git transport.
- An opened secret is wiped when it is dropped; the user name is not.
- Custody's memory is locked and it is undumpable; the crypto actor's process is neither.
- What still needs checking before the hardening is built: how much memory a pod may lock (the default limit in its
  container), whether the nodes' kernels offer memory hidden from the kernel's own mappings, and whether anything Polar
  relies on reads an agent's core file. Polar's crash detection reads how a process ended, not its core file, so making
  it undumpable should cost nothing there.

## 7. What is left before this is met

- **Credentials kept sealed,** opened per request and wiped, with registration opening each once to check it.
- **The user name sealed with its credential.**
- **Registry tokens sealed when they arrive.**
- **Custody's record of each open,** and a way to read it.
- **The crypto actor's process undumpable,** and the opened credential's memory locked and kept out of dumps.
- **The measurement** of a credentialed request's cost, in a release build.
- **The ssh key** given to the git transport: whether it can be opened per connection in the same way.

What is left even then, stated plainly: during a request the credential passes through the HTTP client's own buffers
(its header values, the TLS records it writes), which this does not wipe, so the exposure is much shorter, not none. And
a foothold that runs code inside the agent can still ask custody to open a credential, as the crypto actor does. Custody's
record of opens is what makes that visible.
