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

# Polar's registry: one store for everything a build reads

> **This document has a twin.** [`registry.claude.md`](registry.claude.md) says the same thing, written for Claude to
> keep its understanding in the fewest words. This one is written for people. They are two sides of one plan, and they
> are changed together.
>
> A **capability-level plan**: the intent, and every feature it needs, with where each stands. Each feature gets a plan
> of its own in [`registry/`](registry/). It describes Polar's `main` as it is.

**Status: proposed.** Nothing is built. The first feature, the Nix cache, is being built first.

## 1. The need

A build of foreign code runs in a pod that may reach one thing: Polar's registry in the cluster. Everything the build
reads (its source, its crates, its git dependencies) is brought there first by Polar, checked against a digest, and
recorded. That keeps the pod from reaching the internet or the rest of the cluster, and it keeps a record of exactly
what went into each build.

Today that works only for what Polar fetches ahead of time, and only for Cargo. A build that needs anything else, such
as the Nix store paths an image is built from or the advisory database a scanner reads, cannot get it, and nothing
says which inputs those are until a build fails.

So Polar needs one service, inside its boundary, that:

- holds every input a build may read, each by the digest of its content;
- speaks each tool's own protocol (Nix's binary cache, Cargo's registry, git, container images), so the tools in a
  build need no change beyond being pointed at it;
- when asked for something it does not hold, fetches it from an origin it is allowed to use, checks it, keeps it and
  records it, and only then answers: the build sees a slower first read, and Polar sees every input that entered;
- can be told to fetch nothing, so that a build proves it is complete with what is already held.

The same store serves Polar's other needs for content by digest: the bodies of evidence records, which are kept by
digest in the registry, and the container images Polar's own pods run.

## 2. How the need was found

- **Planning a full build of Polar** through the build orchestrator. Polar's build runs scanners that download their
  databases, and builds its images with Nix, which reads store paths from a binary cache. None of those inputs reach a
  build today, by design: a build reaches only the registry.
- **Asking how a build's outside inputs could be allowed.** Network policy can allow addresses, not host names, and the
  hosts a build needs sit behind large content delivery networks, so allowing them would allow most of the internet. A
  proxy that checks host names is better, but still lets a build fetch whatever it likes from those hosts. Fetching
  on the build's behalf, the way Polar already fetches crates, keeps the build's boundary as it is.
- **Reading the registry Polar runs in the cluster.** It is the upstream `registry:2`, which accepts a push from anyone
  in the cluster. A gate in front of it was designed but not built.
- **Development setups.** Each Polar cluster downloads, and stores again, Nix store paths that the developer's own
  machine already holds.

## 3. The plan

Polar's registry is a Polar service on the builder, like the git server: its own certificate, its outbound fetches
made through the builder's protocol handlers (each one declared, judged and recorded), and its settings signed. It has
one content store underneath, and a face for each protocol.

**Reads are anonymous, and integrity comes from the content.** A build pod holds no Polar identity, and the content it
reads carries its own proof: a Nix path's signature and hash, a crate's checksum in the lock, a git commit's hash, an
image's digest. **Writes need a Polar certificate,** and each is decided by policy and recorded.

**A miss is a fault.** When a reader asks for something the store does not hold, the registry looks for it at the
origins its signed settings allow, in order, checks it against what its protocol says it must be, stores it, records
that it entered and why, and answers. A request names a thing in its protocol's own terms (a store path's hash, a crate
and version, a commit), never a web address, so a build cannot use the registry to reach anywhere else. Faults can be
switched off; then a build gets only what is held.

| Feature | What it gives | Status |
|---|---|---|
| **The Nix cache** | the content store, and Nix's binary cache protocol over it, signed with Polar's own key; faults from the official cache and from the host's own Nix store | proposed, first: [`registry/nix-cache.md`](registry/nix-cache.md) |
| **Trusted remotes** | where the registry fetches from, in a signed list that changes while it runs; a remote that is itself a secret sealed whole, reached by a name that says nothing | proposed: [`registry/trusted-remotes.md`](registry/trusted-remotes.md) |
| **Nix in a build pod** | a build that runs Nix, in a pod that cannot write the image's own store and may not use its node's | to plan |
| **Crates on demand** | Cargo's registry protocol, so a build's crates fault in as it needs them, rather than all being fetched ahead | to plan |
| **Git dependencies on demand** | git's protocol for the repositories a build depends on, at the commits its lock pins | to plan |
| **Images** | the container registry protocol, replacing the upstream registry in the cluster, with pushes decided and recorded | to plan; replaces the registry gate design |
| **Records and retention** | each fault and push recorded where the graph can read it; what no record names may be collected | to plan |

## 4. Alternatives considered

- **Allowing build pods to reach their origins by address.** Rejected: the origins are content delivery networks, and
  an address range that allows one allows most of the internet.
- **An allowlisting proxy.** It checks host names, but a build can still fetch anything those hosts serve, and with a
  shared content delivery network can reach other sites through them. It records host names, not what was read.
- **Fetching everything ahead of time,** as Polar does for crates today. It works where a lock lists every input. Many
  inputs are listed nowhere until a build asks for them, and the registry still needs a face to serve each from.
- **Running existing servers side by side:** a Nix cache server, a Cargo registry, the upstream container registry.
  Each would keep its own store, its own idea of who may write, and its own records, and none fetches on a miss under
  Polar's rules.
- **Mounting the host's Nix store into build pods.** Rejected: a build pod may not use its node's filesystem, what it
  read would not be recorded, and the host's store holds paths no one has checked.

## 5. Why this plan

- **The build's boundary stays as it is:** one destination, inside the cluster. Every outside fetch is Polar's own,
  judged and recorded like every other.
- **One mechanism gives both kinds of build:** one that may fault, whose faults are the list of its inputs, and one
  that may not, which proves the list complete.
- **Tools work unchanged.** Nix, Cargo, git and container runtimes already know how to use a cache or a mirror.
- **One store** means one place for retention, one rule for who writes, and one record, for build inputs, evidence
  bodies and images alike.

## 6. How much of the need is met now

Only through the build orchestrator, and only for Cargo:

- a build's source and its crates and git dependencies are fetched by Polar ahead of the build, checked, and held in
  the cluster's registry by digest;
- the build pod reaches only the registry, and the orchestrator proves it before builds run;
- nothing serves Nix, or any input a lock does not list, and the registry accepts pushes from anyone in the cluster.

## 7. What is left before this is a capability

- **Each feature in the table,** the Nix cache first.
- **A full build of Polar** through the orchestrator, once with faults allowed, then with faults off.
- **A capability document,** saying what the registry is, why it exists and how it is used, once it replaces the
  upstream registry.
