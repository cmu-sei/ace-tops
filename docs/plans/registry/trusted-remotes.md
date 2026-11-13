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

# Trusted remotes: where Polar's registry fetches from, signed, and sealed where the remote itself is a secret; and credentials used without being seen

> **This document has a twin.** [`trusted-remotes.claude.md`](trusted-remotes.claude.md) says the same thing, written for
> Claude. This one is written for people. They are two sides of one plan, and they are changed together.
>
> A **feature-level plan**, part of [Polar's registry](../registry.md). It describes Polar's `main` as it is.

**Status: proposed.**

## 1. The need

Polar's registry fetches what it does not hold from remotes it trusts: a binary cache such as `cache.nixos.org`, a
developer's own machine, and in time caches that are not public. Which remotes it trusts, and how far, is a decision
someone signs, and it changes while the registry runs.

A credential is the whole of what lets its holder in: a username and its password together, a token, a key. Polar
promises that an agent's own code never has one, and holds to it. But its protocol handler is handed each credential in
plain text for the length of a request, and a username is written in plain text in the signed configuration, beside
the hosts its credential may go to. Credentials should be used without being seen, by anything but what holds them.

Some remotes are secrets in themselves. A non-public cache's address, its name, even that it exists, can say more than
should be written anywhere a reader of Polar's configuration can see. For such a remote, everything about it (its
address, the key its contents are signed with, how its server is recognized, and the credential that opens it) has to
stay sealed, so that the registry's own code reaches it by a name that says nothing.

## 2. How the need was found

- **Building the Nix cache's faults.** Its one upstream is fixed when the registry is deployed, as two settings, its
  address and its key; there is no list of remotes, and changing one means deploying again.
- **Planning the host's own Nix store as an upstream,** which makes a second remote, with a key of its own.
- **Asking where a credential is seen.** The handler gets a request's credential in plain text, to attach it; the design
  records moving it out as a seam left for later. And a username is not sealed with its password.
- **Asking what a non-public cache needs.** Its access credential is a secret, which Polar already seals. But in Polar's
  `credentials` section, only the secret is sealed: the hosts a credential may go to are written in plain text beside
  it. For a remote that is itself a secret, that is not enough.

## 3. The plan

**First, credentials are used without being seen.**

- **Sealed means the whole credential:** a username is sealed with its password, and nothing in the signed
  configuration says who a credential logs in as. Sections written the old way are moved over, once, by re-sealing.
- **A key is used by signing, never handed out.** An ssh key, a client certificate and the registry's own Nix signing
  key are held by the custody daemon, a process apart from the agent, which signs what proving possession needs; no
  part of the agent ever has the key.
- **A shared secret is sent by what holds it.** A token, or a username and password, has to travel inside the request
  itself, so whatever writes those bytes holds the secret. That is the agent's crypto actor, which already keeps the
  opened secrets: the protocol handler gives it the judged request and the credential's name, it sends the request
  with the credential and gives back only the response. The handler and the agent's code never have the secret.

**Then the remotes.**

**A signed `remotes` section for each agent that fetches,** delivered as every signed section is and replaced whole by
each version, so a remote left out is withdrawn. Each remote has a name, which is all anyone sees of a sealed one, and
is either:

- **plain:** its address; the key its contents are signed with; how its server's identity is checked, which is always
  declared in the entry, as a certificate authority of the remote's own or a pinned public key, since no system's list
  of authorities is trusted for a remote; the credential it needs if any (by name, from the `credentials` section); and
  the kinds of content it supplies (Nix paths, crates, images, git), the only kinds it is asked for; or
- **sealed:** all of that, together, as one sealed entry, opened only by the agent's escrow, which is where Polar's
  credentials are already opened. The address never enters the agent's own code.

**The builder's protocol handler gets a way to go to a remote by name.** An operation declares that it goes to the
remotes its agent's `remotes` section names, and nowhere else. The agent's code gives a remote's name and a path; the
handler finds the remote, opening it in escrow if it is sealed, connects with that remote's own trust and credential,
and judges the request as it judges every other: a name the section does not hold is refused. The handler's record
names a sealed remote by its name, never its address. So does the registry's record of faults.

**The agent's code holds no remote's key.** The infrastructure side of the agent, where sealed entries are opened, holds
every remote's signing key, plain or sealed, and checks a path's signature when the agent's code asks, naming the
remote; the code holds only names. The handler's record and the registry's record of faults name a plain remote by its
name and its host, and a sealed one by its name alone.

**A dropped remote's content is quarantined.** Every path the registry holds records which remote it came from (a path
held before that is recorded is traced by the remote's signature it carries). When a signed version of the list drops a
remote, every path that came from it is put under quarantine: kept, not served, and recorded with the version of the
list that dropped it. An archive is withheld when only quarantined paths use it. A quarantined path counts as not held:
if a remote still on the list offers it, it is fetched again and checked under that remote's key, which releases it;
otherwise it is refused, and the refusal recorded. Re-adding the dropped remote does not release its paths by itself,
since a remote is often dropped because it can no longer be trusted: a remote still trusted vouching for a path again,
or a person's signed release, does. Nothing quarantined is deleted except by a person's decision. Both are signed
commands to the registry, allowed by a capability of their own, and each is recorded in its record.

**The Nix cache moves onto it:** its upstreams come from its `remotes` section, in the order the section gives, in
place of its two deployment settings, and change while it runs.

In steps, each tested before the next:

1. **Whole credentials sealed,** and existing sections moved over.
2. **Shared secrets sent by the crypto actor,** for HTTP and for git over HTTPS; the handler no longer receives them.
3. **Keys signed by custody:** ssh keys, client certificates, and the registry's Nix signing key.
4. **The section,** plain remotes only, judged when it arrives; the registry reads its upstreams from it; each path held
   records the remote it came from, and a remote dropped puts its paths under quarantine.
5. **The handler's way to a remote by name,** for plain remotes: judged, recorded, each remote's own trust and
   credential applied.
6. **Sealed remotes:** the sealed entry, made by `polar-sign` as a credential's secret is; opened in escrow; the handler
   resolving a sealed name without the address leaving escrow; records naming it by name.
7. **The host's Nix store as a remote,** the first one after `cache.nixos.org`.

## 4. Alternatives considered

- **The custody daemon sending requests that carry a shared secret,** so the secret never exists in the agent's
  process. Stronger, since it holds against code running inside the agent; set aside for now, because custody, small
  and the most sensitive process Polar has, would then open connections and read servers' replies. It is the next step
  of the work against a foothold in an agent.
- **The handler attaching the credential, as now.** Polar's own code never misuses it, but it is in plain text in the
  handler for each request, beyond what holds it.
- **Each upstream as a deployment setting,** as now. Simple for one, and it puts every change through a deployment,
  with no place for a secret remote.
- **The address in plain text, only the credential sealed,** as credentials work now. Enough for most remotes, which is
  why a remote may be plain; not for one whose existence is the secret.
- **The agent's code holding a sealed remote's key,** never logging it. Rejected: the key stays with the infrastructure
  side, beside the rest of the sealed entry, and the code asks it to check.
- **Checking signatures in the escrow daemon itself.** Every path's description would cross the process boundary to be
  checked; the infrastructure side of the agent already holds what escrow opened.
- **Trusting the system's list of certificate authorities for a remote's server.** Rejected: a remote's trust is
  declared within Polar, signed, and managed there.
- **One list of remotes for the whole cluster.** Rejected: each agent that fetches has its own, as it has its own
  credentials, so an agent learns only the remotes it uses.
- **A remote reached as `Arbitrary`,** the handler's "any host" permission, with the agent checking the host against
  the section itself. The handler's judge would not know the list, and the agent would hold every address.

## 5. Why this plan

- **Where the registry fetches from is signed, and changes as signed configuration does,** without deploying again.
- **Withdrawing trust from a remote withdraws it from what that remote supplied,** without destroying the evidence of
  what it supplied.
- **A secret remote stays secret** from Polar's configuration, its logs and its records, and from the code that uses
  it.
- **The handler's judge holds the list,** as it holds a configured host now, so a remote nobody signed off is refused
  wherever the request comes from.
- **It builds on what exists:** signed sections, escrow, the credentials a remote may need, and the handler's record.

## 6. How much of the need is met now

- An agent's own code has no way to a credential, closed by what it can reach rather than by convention.
- The handler receives a credential in plain text for each request it makes with one, and a username is in plain text
  in the signed configuration.
- The Nix cache has one upstream, its address and key fixed when the registry is deployed.
- Credentials are sealed, with the hosts each may go to in plain text.
- No remote can be sealed, and the handler has no way to a host named by a signed list.

## 7. What is left before this is met

- **The seven steps above.**
- **How git over HTTPS goes through the crypto actor:** the git library makes its own requests, so the crypto actor
  must stand in its path, for instance as a local proxy that adds the credential, rather than being handed a request.
  Settled in its step.
- **What a remote may be used for:** which kinds of content (Nix paths, crates, images), and for which builds. A first
  form is part of step 1; how far it goes is to be settled with the registry's other faces.
- **The registry's own signing key in custody,** signing with Ed25519, before the registry is deployed to any cluster;
  until then its key file is for tests and development runs only.
- **A certificate as a credential kind,** for a remote that admits clients by certificate; today a credential is a
  token, a user and password, or an ssh key.
