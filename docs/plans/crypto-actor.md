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

# The crypto actor: every key an agent uses, used through one place

> **This document has a twin.** [`crypto-actor.claude.md`](crypto-actor.claude.md) says the same thing, written for
> Claude. This one is written for people. They are two sides of one plan, and they are changed together.
>
> A **capability-level plan**. It describes Polar's `main` as it is.

**Status: approved; being built.**

## 1. The need

Polar's design gives each agent's keys one keeper and one user. The custody daemon keeps them: it holds a key where it
is usable and nowhere else, and does for its agent only what can be done only there (make a key, give its public half,
sign, unwrap), as the kernel keyring would. The agent's crypto actor uses them: it decides what is signed, builds what a
protocol needs signed, checks it, and is the only part of the agent that asks custody for anything. What reaches the
rest of the agent is the result, never a key and never a way to one.

The code does not hold to that. Eight places in the agents' code talk to the custody daemon themselves, five of them
building their own TLS configuration over its keys, each with its own trust store, its own verifier and its own choice
between the daemon and a key file. An agent that does not encrypt has no crypto actor at all, and an agent that has one
starts it last, after the connections that needed its keys were already made. Each of these was built to be reasonable
on its own; together they are a design nobody chose, and each new one has had to be found and explained after the fact.

## 2. How the need was found

Adding the keys that sign ssh logins and Nix narinfos raised where each signing should happen. Answering it meant
listing everything that talks to the custody daemon, and the list was longer than the design allows:

| Where | What it does with custody |
|---|---|
| Cassini's client | builds its TLS client configuration over the client key |
| Cassini's broker | builds its TLS server configuration over the server key; reads a key file or the socket itself |
| the git server | the same, separately |
| the graph client | builds its TLS client configuration over the client key |
| the cert-issuer client (the credentials agent's) | builds its TLS client configuration over the client key |
| the record signer | a separate actor beside the crypto actor, asking custody to sign |
| the crypto actor | unwraps secrets with the escrow key |
| polar-init | installs the pod's keys and certificates (the installer: expected) |
| polar-health | asks custody for a certificate to see that it answers (a probe: expected) |

Cassini's client is also made outside the builder, and each such client builds its own TLS from what its environment
gives it: the client's command-line daemon (a socket for programs in other languages), `cassini-c2`, the tool that asks
a running agent for its configuration, `polar-init`, and a helper in the shared library that gives some agents (the
attestation agent, the build orchestrator's publisher, cert-issuer) a second Cassini client beside the builder's. Only
one of these has a crypto actor (`polar-init`'s), and none of the others has a reason not to.

Two constraints explain some of it. TLS signs in the middle of a handshake, and the TLS library Polar uses (rustls,
chosen because the alternatives are C libraries) asks for that signature synchronously; and the crypto actor reaches the
credentials agent over Cassini, whose own connection needs its handshake signed. Neither requires anything to go
around the crypto actor: the first only means the signer the crypto actor hands to TLS answers synchronously, as it
does now through a local socket; the second only means the crypto actor starts before Cassini and is told how to reach
the credentials agent once Cassini is up.

## 3. The plan

**Every agent has a crypto actor, started first.** The builder starts it before anything that needs a key, in every
agent, encrypting or not. It holds the agent's custody client (or, where a cluster runs without custody, the key files),
and nothing else in the agent does. Once Cassini is connected, it is given the way to the credentials agent, for escrow
and retrieval.

**Every process that uses a key has a crypto actor.** Not only agents: the crypto actor is something any Polar process
starts, and Cassini's client takes its TLS only from one, so that no program can open a Cassini connection with keys of
its own. Where a crypto actor's keys come from is its own business: in a pod, the custody daemon beside it (a deployed
command-line daemon or `cassini-c2` gets the same pod shape as an agent); on a person's machine, that person's key
files; for cert-issuer, which makes its own key as the certificate authority, its files. The one exception is custody
itself, whose custodian signs its own connection with its own key, as a keyring would. The shared library's second
Cassini client goes: those agents use the builder's.

**Every TLS configuration comes from the crypto actor.** Client and server: the agent's certificate, its key's signer,
and the trust it is given. Cassini's client, the broker, the git server, the graph client and the cert-issuer client
take what it gives and build no TLS configuration of their own. The signer it hands to TLS answers synchronously, as TLS
requires; what that signer will sign is the crypto actor's code to decide, not the custody daemon's. The check that a
TLS key signs only TLS 1.3 handshakes moves from custody into it.

**Record signing is one of the crypto actor's operations.** The separate signer actor goes; the domain keeps the same
handle, which now reaches the crypto actor. The record's key stays as it is: made in custody, never escrowed, gone with
the pod.

**The design holds itself.** A test reads the workspace's dependencies and refuses any crate but the crypto actor's, the
installer's and the health probe's that depends on custody's client. A new path around the crypto actor fails the build
rather than waiting to be found.

**Then the new keys go through it from the start.** Custody makes a named key, gives its public half and signs with it;
the crypto actor builds and checks what is signed (an ssh login, a Nix narinfo fingerprint) and shows the public half
to add where it is trusted.

**Then verification.** The builder's configuration actor, the git server, the credentials agent and the broker each
verify signed documents themselves. Moving verification into the crypto actor is the next step after keys, planned on
its own, since it changes how every signed section, commit and certificate is believed.

## 4. Alternatives considered

- **A TLS library that signs asynchronously,** so TLS could wait on the crypto actor. Rejected: the ones that can are
  C libraries (BoringSSL, OpenSSL, s2n-tls), and the synchronous call costs a local round trip, measured at under 25
  microseconds at the 99th percentile.
- **The crypto actor only in agents that encrypt,** as now, with the others reaching custody themselves. Rejected: it is
  how the circumventions came about.
- **Leaving Cassini's client outside the crypto actor,** since the crypto actor rides on Cassini. Rejected: the
  dependency is only on order, and starting the crypto actor first removes it.
- **A rule in review instead of a test.** Rejected: the rule existed, and each circumvention passed review.

## 5. Why this plan

- One place in each agent uses keys, so what a key may do is decided once and seen in one place.
- Custody stays the keyring it was built to be; nothing it does depends on what it signs.
- The test turns the design into something the build checks.
- It is the ground the new keys (ssh, Nix) and the remotes work stand on.

## 6. How much of the need is met now

- The custody daemon holds every agent's keys on a cluster that runs it, and no key leaves it.
- The record signer's key work was moved out of custody: custody signs, the signer builds and checks the record.
- Eight places reach custody; only the crypto actor, the installer and the health probe should.

## 7. What is left before this is met

- **The crypto actor in every agent, started first,** and given the way to the credentials agent once Cassini is up.
- **The crypto actor in every other process that uses a key** (the command-line daemon, `cassini-c2`, the
  configuration tool, cert-issuer), Cassini's client taking TLS only from one, and the library's second client gone.
- **The five TLS configurations from the crypto actor,** and the TLS check moved out of custody.
- **Record signing in the crypto actor.**
- **The dependency test.**
- **The key files of a cluster without custody** held by the crypto actor too, so the degraded mode has the same shape.
- **The credentials agent's own keys** (its authority, escrow and ledger keys) behind its crypto actor. They are held in
  its process today. Its record key, which signs its revocation records, is already the crypto actor's: a key file
  made once on its volume, since custody can hold no signing key for the agent that comes up first.
- **Credentials opened only while they are used,** their pages locked and kept out of dumps: proposed,
  [`crypto-actor/ephemeral-credentials.md`](crypto-actor/ephemeral-credentials.md).
- **Verification in the crypto actor,** planned on its own.
