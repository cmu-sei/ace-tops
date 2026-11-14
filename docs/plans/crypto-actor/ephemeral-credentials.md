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

**Status: a proposal, read against the code and found ready; for the maintainer to clear. Nothing built.**

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

The process the crypto actor runs in does not protect those pages. Custody locks its memory, so nothing of it is
written to swap, and makes itself undumpable. An agent process does neither, and nothing keeps a credential out of the
agent's core file. So anything that can read an agent's memory without running code in it finds every credential the
agent holds: a bug that discloses memory, swap, a core file, a checkpoint of the container or a snapshot of the node.

Reading it from beside the process is already closed. Every agent runs under the builder's seccomp lock, which refuses
`ptrace`, `process_vm_readv` and `process_vm_writev` whatever their arguments, so a foothold in an agent cannot read
another process's memory that way, and an agent shares no process namespace with the other containers of its pod.

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
someone in the agent asking for it. First as a log line: one for each open, naming the key, the caller and a digest of
the sealed credential (of the ciphertext, never of anything opened). The crypto actor logs each credentialed request
with the same digest, so the two can be paired. Next, a count for each sealed credential in custody's answer about its
own state. Custody gains no topic for it: an event is published only once something consumes it.

**The secrets stay out of a dump, and the dump stays whole.** An agent's crash is evidence: the attestation agent
reports it, and diagnosing it (something the case missed, tampering, a hardware fault, or unexplained) may need the core
file. So an agent stays dumpable, and only the pages that hold an opened credential or key are kept out:

- they are marked never to be dumped, so a core file is complete for diagnosis and holds no credential at rest and none
  from the crypto actor's own copy;
- they are locked, so they are never written to swap. Only those pages are locked, not the whole agent, and they are
  few: a handful of pages, not megabytes, since how much a process may lock differs from cluster to cluster;
- where the kernel offers memory that is never dumped and is hidden even from the kernel's own mappings, they come from
  there instead, still marked never to be dumped;
- where a cluster lets the process lock less than it needs, the pages are used unlocked, still kept out of dumps, and
  the agent says so once, as custody does when it cannot lock.

Since an agent stays dumpable, these pages are where the crypto actor keeps an opened credential or key, so its own copy
is never in a core file. They do not cover every copy: while a request is in flight, the credential also passes through
the HTTP client's header values and its TLS record buffers, and a core file written at that moment can hold it from
there (what is left, below).

**Tests first.** Properties: at rest, nothing the crypto actor holds is a credential in the clear; every request that
carries one gets it opened once and wiped after; the opens custody records match the requests sent. A measurement of the
cost per request in a release build.

## 4. Alternatives considered

1. **Keep things as they are.** Every credential an agent has stays readable in its memory for the agent's life, to
   anything that can read that memory.
2. **A separate key in custody to wrap the credentials.** Rejected: the escrow key already seals them, for this same
   purpose. A second key would be a second thing to make, certify and rotate, for no gain.
3. **Lock and hide the secrets' pages, and nothing else.** Rejected as the whole answer: it keeps credentials out of
   swap and dumps, but not out of a bug that discloses memory, a container checkpoint or a snapshot of the node.
4. **Make the agent undumpable, as custody is.** Rejected for agents: it blinds crash diagnosis. A crash is the strongest
   counter-evidence the case has, and the core file may be what settles it. Custody keeps it: it holds only keys, and is
   small.
5. **Lock the whole agent's memory, as custody does.** Rejected: an agent is far larger than custody, a whole-process
   lock is bounded by what the pod may lock, and locking the secrets' pages alone gives the same protection for them.

## 5. Why this plan

- **It removes standing trust in an agent's memory.** What a read of that memory can find is what a request is using at
  that moment, not every credential the agent has.
- **It costs almost nothing.** Custody has been measured at about 320,000 key operations a second on the maintainer's
  machine, and a credentialed request is a low-rate event. Opening, using and wiping a credential adds well under a
  millisecond to a request that crosses a network.
- **Nothing new can fail.** Custody already answers every TLS handshake the agent makes; a credentialed request depends
  on it no more than before.
- **It adds detection.** Each open is recorded, so a credential being asked for without a reason is visible.
- **It keeps crash evidence whole.** Polar's threat model counts a crash as evidence worth more than any run that went
  well, so the protection is drawn around the secrets, not around the process: a core file stays complete for
  diagnosis and holds no secret.
- **Custody stays the keyring it was built to be.** It opens what is sealed to its key; it knows nothing of what the
  credential is for.

## 6. How much of the need is met now

- Credentials reach the crypto actor sealed to the pod's escrow key, and only custody can open them.
- No credential reaches a protocol handler: the crypto actor puts it on the request itself. The one exception is git
  over ssh, where the ssh key is given to the git transport.
- An opened secret is wiped when it is dropped; the user name is not.
- Custody's memory is locked and it is undumpable. The crypto actor's secrets are neither locked nor kept out of a
  dump.
- Every agent's seccomp lock already refuses `ptrace` and reading or writing another process's memory.
- Measured on the development cluster, in a pod shaped as Polar's: the pod may lock without limit, and both locking
  pages and locking the whole process succeed; the nodes' kernels offer memory hidden from the kernel's own mappings,
  and it works under the runtime's default system-call filter. The first is that cluster's inherited setting, not a
  promise: another cluster may allow the kernel's default of a few megabytes or less, which is why the pages are few and
  work unlocked if they must.

## 7. What is left before this is met

- **Credentials kept sealed,** opened per request and wiped, with registration opening each once to check it.
- **The user name sealed with its credential.**
- **Registry tokens sealed when they arrive.**
- **Custody's record of each open:** a log line per open, paired with the crypto actor's line per request by the sealed
  credential's digest; then a count in custody's answer about its state.
- **The opened credentials' and keys' pages locked and kept out of dumps,** the agent itself left dumpable.
- **The measurement** of a credentialed request's cost, in a release build.
- **The ssh key** given to the git transport: whether it can be opened per connection in the same way.

What is left even then, stated plainly: during a request the credential passes through the HTTP client's own buffers
(its header values, the TLS records it writes), which this does not wipe, so the exposure is much shorter, not none. And
a foothold that runs code inside the agent can still ask custody to open a credential, as the crypto actor does. Custody's
record of opens is what makes that visible.
