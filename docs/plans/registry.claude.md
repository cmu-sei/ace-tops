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

# registry — Claude's side

PAIR: `registry.md` (people). Same plan, two forms; change together.
SPLIT: people side has no dates, attributions, quotes, codenames or branch/process status; those live here.
CHILDREN: `registry/nix-cache.claude.md` (first). Others not yet written.
AS-OF main a9ef59e4 (2026-11-12). STATUS: proposed; maintainer said "write up the proposal and then just start
implementing this" (2026-11-12) = cleared to build the Nix cache; the rest of the capability is not cleared.
OWNER: polar-89, on main.

## ORIGIN (2026-11-12, this session)
- Maintainer lifted the "no mapping names a repo Polar doesn't control" rule (canary proves enforcement) and asked for a
  full Polar build through the orchestrator, "we're going to need to whitelist some repos"; later a vendored rerun.
- I said NetworkPolicy can't name hosts (CDN ranges) → proposed an allowlisting proxy. Maintainer: "What if the pod
  believes everything is already vendored?" then "the registry/proxy equivalent of a page fault".
- Maintainer: "a new polar service, our own registry, possibly a fork of an existing rust-based registry project, or
  maybe just used as inspiration and built atop the builder"; "the registry could support CAS and we could mount my
  actual host nix store as a read-only layer to the pod, possibly with an overlay"; "save real space and bandwidth for
  development setups". Then "Fucking hell. A polar nix cache server..." and "write up the proposal and then just start
  implementing this. I do want to test ... a full build but that can wait."
- I pushed back on the host-store mount into build pods (decision 5d no hostPath; reads off the record; host store
  unchecked) → host store becomes an UPSTREAM served by the same program on the host. Maintainer didn't object.

## INVARIANTS (the capability)
- Build pod's boundary unchanged: one destination (the registry), in-cluster. Every outside fetch is the registry's,
  through polar-agent-builder protocol handlers (declared/judged/recorded), like orchestrator deps.rs.
- Requests typed in each protocol's terms (store-path hash part, nar hash, crate+version, commit, digest); never a URL
  → registry is not a proxy to anywhere.
- Faults switchable off (signed Dynamic setting) → vendored build = faults off. Both of maintainer's tests on one mechanism.
- Reads anonymous (build pods hold no Polar identity: build-orchestrator.md "Build pods hold no Polar identity");
  integrity from content (sigs/hashes). Writes need Polar cert + policy, recorded.
- One CAS (sha256-named blobs) under all faces; evidence bodies already decided to live "in the registry" by digest
  (evidence-storage, 2026-11-05) → this is that registry.

## FACTS (main as is)
- Cluster registry: upstream registry:2.8.3 by digest, ns polar-registry, name registry, port 5000, NodePort 30500;
  nodes pull localhost:30500 plain http (infra/cluster-registry.nu:23-50; containerd certs.d via nix-usernetes).
  Anonymous pushes from anywhere in cluster.
- registry-gate.md (2026-10-20, design, unbuilt): gate pod in front of registry:2, pull plain http GET/HEAD, push mTLS
  with deployment PKI. The Images feature supersedes it (say so when that feature plan is written).
- Builds' NetworkPolicy (infra/cluster-registry.nu builds_policy): egress only ns polar-registry pods app=registry TCP
  5000; no DNS; orchestrator gives hostAliases. A new registry workload needs that selector/port changed.
- Orchestrator D2/D3 (build-orchestrator.md 750-848): crates fetched ahead via declared `crates.download` op from
  POLAR_ORCHESTRATOR_CRATES (default https://static.crates.io), checked vs lock sha256, pushed to `build-dependencies`;
  git deps as shallow bare repo tars; fetch lays out vendor dir + Cargo source replacement.
- polar-git-server: builder agent, hyper-util server, mTLS, OPTIONAL cassini, push-log.jsonl (git-server.md). Precedent
  for a direct-connection Polar service. record-store.md "Revised 2026-11-11": polar-git = the one service taking direct
  connections, edge does what the broker does (Cedar per op, reports over Cassini). Registry is a second such service
  (build pods/kubelets can't speak Cassini) — say so when the Images/records features are planned.
- Full-build blockers found reading ci.nu: cargo-deny advisory-db (github), cargo-semver-checks (crates.io baselines;
  Polar crates unpublished → noise), cargo-mutants whole-workspace (days; tests need containers), images via `nix build`
  (polar-ci: NIX_REMOTE="", /nix in image, pod uid 1000 read-only root → can't write /nix), upload (skopeo with creds,
  against decision 1).

## FEATURES (order mine, for review)
1. nix-cache — first (maintainer's excitement; self-contained; replaces nothing).
2. nix-in-build-pod — writable store options: emptyDir store + `--store` chroot (needs userns, blocked by RuntimeDefault?),
   mapping exception, image-volume layers (KEP-4639) + Nix experimental local-overlay-store (needs overlay mount). Open.
3. crates on demand — sparse registry face (index + dl); keep D2 prefetch as an optimisation or drop. Prior art kellnr
   (crates.io proxy mode; license unchecked).
4. git deps on demand — gix-serve (daveman1010221/gitoxide fork) as the face.
5. images — OCI distribution face; replaces registry:2 + registry-gate design; kubelet pulls stay anonymous plain http
   localhost:30500; pushes mTLS + policy. Prior art trow (Rust; state unchecked).
6. records+retention — faults/pushes → Cassini events → graph; record-store logs as GC roots (evidence-storage).

## DECISIONS by standing rules (for review)
- Name `polar-registry` (crate dir src/agents/polar-registry), beside polar-git-server.
- Build on the builder, own code for formats; harmonia (MIT, nix-community, v3.3.0, unpublished crates, aws-lc-rs +
  actix + ed25519-dalek 3.0-rc) read as reference; nix-compat (snix) GPL-3.0-only → unusable; attic Apache-2.0
  (chunked dedupe, FastCDC) as reference for later dedupe.

## OPEN
- Fault attribution: build pods have no identity; record source address → pod via orchestrator's knowledge? Spoofing
  between pods not ruled out by ptp+kube-nftpolicy (unchecked). Per-build read token would be a credential in the pod
  (decision 1 is about source credentials; still ask).
- Covert channel: request names reach upstream logs (low bandwidth; threat model is foothold-first). Record it.
- Space sharing with host (reflinks on same fs) — later.
