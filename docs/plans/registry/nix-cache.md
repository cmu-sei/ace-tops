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

# The Nix cache: Nix store paths served by Polar, signed by Polar

> **This document has a twin.** [`nix-cache.claude.md`](nix-cache.claude.md) says the same thing, written for Claude.
> This one is written for people. They are two sides of one plan, and they are changed together.
>
> A **feature-level plan**, part of [Polar's registry](../registry.md). It describes Polar's `main` as it is.

**Status: proposed, being built.**

## 1. The need

Polar's images are built with Nix, and a build of them reads hundreds of store paths: compilers, libraries, tools.
Nix gets a path it does not have from a *binary cache*: a web server that answers, for a path, a short signed
description of it (its hash, its size, the paths it refers to) and the path's contents as an archive. Nix accepts
a path only when the description is signed by a key it trusts and the contents match the hash.

A build pod can reach only Polar's registry, so a build that runs Nix needs a binary cache there. Polar should trust
what that cache serves for the same reason it trusts its crates: each path was checked when it entered, and its entry
was recorded. And a developer's cluster should not download again what the developer's own machine already holds.

## 2. How the need was found

- **Planning a full build of Polar.** Building the images runs `nix build`, which needs store paths from
  `cache.nixos.org` and inputs from GitHub; a build pod reaches neither.
- **Asking what a build could read if it believed everything was already vendored.** The answer was a store that
  fetches on a miss, as a page fault does, so that the first build's faults list its inputs.
- **Looking at development setups.** Every Polar cluster on a developer's machine fetches the same Nix paths again,
  and stores them again, though the machine's own Nix store already holds them.

## 3. The plan

A Polar service, the registry, keeps a **content store**: each blob in a file named by the SHA-256 of its contents,
written whole or not at all, and checked as it is written. Over it, the **Nix face** answers Nix's binary cache
protocol:

- `nix-cache-info`, saying which store it serves;
- for a store path, its *narinfo*: the path, the hash and size of its archive, the paths it refers to, and signatures;
- the archive itself, kept uncompressed, so that its name in the store is the hash the narinfo states and Nix checks.

**Every narinfo Polar serves is signed with Polar's own key.** A build's Nix trusts that key alone, so it accepts only
what Polar has checked. Signatures from where a path came from are kept beside Polar's.

**A path the store lacks is a fault.** The registry asks its *upstreams*, in the order its signed settings give, for
the path's narinfo:

- **The official cache,** `cache.nixos.org`, or any binary cache the settings name with the key it signs with. Its
  narinfo must carry a valid signature by that key; the archive is fetched, decompressed, and checked against both the
  hash of what was fetched and the hash of the archive the narinfo states.
- **The host's own Nix store,** in a development setup. The same program, run on the developer's machine in a mode
  that serves the machine's store, is an upstream like any other, with a key of its own. Each path's archive is made
  from the store's files and checked against the hash the machine's Nix recorded before it is served. Nothing of the
  host is mounted into the cluster.

A request can name only a store path's hash, or an archive's hash; there is nothing in it to send the registry
elsewhere. What a fault fetched is checked, stored, recorded (which path, which archive hash, from which upstream,
signed by which key, when, and for which address), signed by Polar, and served. **Faults can be switched off** by a
signed setting; then the cache serves only what it holds.

**Only reads are anonymous.** Adding paths directly, as `nix copy --to` does, needs a Polar certificate allowed to
write, and is recorded in the same way.

In steps, each tested before the next:

1. **Nix's formats, in Polar's own code:** store paths and Nix's base-32 spelling of hashes, the archive format (made
   from files, and hashed as it is read), narinfo, and signatures. Held to Nix itself: the same paths given to Nix and
   to this code give the same archive bytes, hashes, narinfo and signatures.
2. **The content store and the Nix face,** with Polar's signature; Nix copies a path from it and accepts it.
3. **Faults from a binary cache,** checked and recorded; and faults switched off.
4. **The host's store as an upstream.**
5. **In the cluster:** the registry as a catalog workload with its own volume, its key, its settings, and the builds'
   network policy allowing it.

## 4. Alternatives considered

- **An existing Nix cache server.** `harmonia` serves a machine's own store, `attic` is a multi-user cache with
  deduplication, and `nix-serve` is the original. None fetches on a miss under a policy, records what entered, or
  shares a store with the rest of the registry. Harmonia is closest, and its code (MIT-licensed) is read for how Nix's
  formats are handled; its libraries are not on crates.io and bring a different cryptography library and web
  framework from Polar's.
- **`nix-compat`, the Nix formats library from the snix project.** Its licence (GPL-3.0) is not one Polar can ship
  under.
- **Mounting the host's Nix store into the registry or into build pods.** Rejected for build pods: a build pod may not
  use its node's filesystem. For the registry, the host's store would be read without the checks an upstream gets, and
  on a cluster whose nodes are containers the host's filesystem is not the node's. Serving it from the host, as an
  upstream, gives the same saving in downloads.
- **Keeping archives compressed,** as other caches do. Smaller, but then the name in the store is not the hash Nix
  checks, and every read of a path's contents must decompress it. Compression on the wire can come later.
- **Trusting upstream signatures in build pods directly** (`cache.nixos.org`'s key). Then what a build reads is
  trusted because someone else signed it, not because Polar checked and recorded it.

## 5. Why this plan

- **A build trusts one key, Polar's,** and every path signed with it was checked and recorded when it entered.
- **Faults give the list of a build's inputs** without opening the build's network, and switching them off proves the
  list complete.
- **A developer's machine becomes the nearest upstream:** paths it holds are not downloaded again.
- **It is the registry's first face,** and builds the store the other faces share.

## 6. How much of the need is met now

None of it. No Nix cache runs in Polar's clusters, and a build pod cannot run Nix.

## 7. What is left before this is met

- **The five steps above.**
- **Nix in a build pod,** a feature of its own: the pod's own Nix needs a store it can write, inside a pod that may not
  write its image or use its node, and it needs to trust Polar's key alone.
- **Who holds Polar's signing key:** first a key the registry keeps on its own volume; then one certified through the
  credentials agent, as other workload keys are.
- **Sharing storage with the host,** not only downloads: the cluster still keeps its own copy of each path a build
  used. Whether a single-machine setup can share the files themselves is open.
- **Records the graph can read,** and retention, with the rest of the registry.

It is met when a build in a Polar cluster reads its Nix store paths only from Polar's cache, each path's entry is on
the record, and a build with faults switched off succeeds from what is held.
