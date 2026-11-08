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

# The build orchestrator

**Why.** Polar records builds (build-processor), but nothing of Polar runs one: the pipeline scripts publish what a build did from
wherever it ran. Vaughn's port of upstream (`ace-remote/port/public-polar-blitz-deploy`, ten commits from `69cd7731`, about 9,000
lines, 37% tests) has a build orchestrator that runs a repository's pipeline as a Kubernetes Job against a pinned commit and reports
what ran. His own note: ported with its tests carried, not written red-first, never run on a cluster. It is taken apart and ported by
Polar's rules, as the resolver and build-processor were (`remaining-work.md`, "UPSTREAM'S WORK, BY VAUGHN'S PORT", area 2).

## What his branch has (read 2026-11-07)

- A `PolarAgent` on the builder: subscriptions through `Subscription`, a signed `mappings` section (a repository's URL, its pipeline image
  pinned by digest, its command, the names of its credentials) and an escrowed `credentials` section opened by the CryptoActor. A
  supervisor with a build registry actor, which owns build state and is changed by message, and one build job actor per build.
- A build is triggered by a `RefUpdated` on `GIT_REPOSITORY_EVENTS` (old != new) or a JSON `BuildRequest`; a repository with no mapping,
  and an archive build, are refused. It runs as a Job in `build-jobs`: a clone init container, then the mapping's image. Build pods mount
  no ServiceAccount token. It publishes `ExecutionStarted`, `Completed`, `Failed` and `Cancelled`.
- Against Polar's model: a YAML file rendered into a ConfigMap, any field overridable by `BUILD_ORCHESTRATOR__*` env; object-store keys
  from a Kubernetes Secret, over its own aws-sdk client on plain http; `NEEDS` saying `KubeApiRead` though it creates Jobs and Secrets,
  and its capabilities declared again in Dhall; deployed only through `src/deploy`; `requested_by` taken from the payload; `exit(1)` on an
  essential child's failure; the escrowed git credential written in plaintext into a per-build Secret; a git build's pipeline container
  with its image's own security context; an unbuilt clone image defaulting to `:latest`; the cert-manager era's shared `client-tls`
  fallback; registry push not built; the retention sweep a bare `tokio::spawn`.

## Decisions

Asked, the maintainer, 2026-11-07:

1. **A build's source comes by digest, and no credential reaches the build pod.** The orchestrator fetches the pinned commit through its
   git protocol handler, which holds the credential (`protocol-handlers.md`); the build pod is given the source as a content-addressed
   archive in Polar's registry and checks its digest before it builds. ("Orchestrator fetches, pod gets it by digest".)
2. **A build's pipeline log is a content-addressed blob in the registry**, as evidence bodies are (`evidence-storage`), and its digest
   goes in the build's provenance event. No S3 gateway. ("Registry blobs, by digest".)
3. **Build pods are one multi-instance workload, each pod its own certificate.** Every build shares the workload's grants; its broker-stamped
   identity names the pod, so a build's events are that pod's word, and a `build_id` belongs to the pod that started it (B11's open
   question in `remaining-work.md`). ("One workload, a certificate per pod".)
4. **A build runs hardened unless its signed mapping says otherwise:** non-root, no privilege escalation, every capability dropped, the
   default seccomp profile, writing only its workspace; a mapping may name what more its pipeline needs, so an exception is signed and
   on the record. ("Hardened, a mapping may opt out".)

5a. **Its Kubernetes calls go through the builder's Kubernetes protocol handler** (the maintainer, 2026-11-07, "Through the protocol
   handler"): creating, deleting and listing Jobs, reading their events and a pod's log are operations of that protocol, each declared,
   judged and recorded, as every outbound call is (`protocol-handlers.md`). His backend made them with its own `kube::Client`. The
   handler only watched; the request operations are added (O1c). And a cluster operation's declaration binds what it may do (the
   maintainer, "Yes, judged"): each declares its access (a verb on a group's resource), the judge denies a request whose access is not
   declared, and the builder computes the `job-run` capability from the declared writes, so a list cannot delete and the capability
   cannot drift from the code.

5b. **The build workload's pod setup is a PodTemplate the catalog applies** (the maintainer, 2026-11-07, "A PodTemplate the catalog
   applies"): the catalog renders the build workload (multi-instance, decision 3) as a Kubernetes PodTemplate in the build namespace,
   applied by Flux from the signed deployment like every other manifest, and the orchestrator reads it through its handler (a declared
   `get podtemplates`) and builds each Job's pod from it: its ServiceAccount, its certificate init container, its volumes, mounts and
   env. So the facts stay the catalog's and are said once, as the load harness's runs copy its rendered Job, and a new catalog applies
   without restarting the orchestrator. His read them from JSON in a rendered config file.

Decided by standing rules, for review (`AGENTS.md`, "Design Principles"):

5. Deployment facts (the build namespace, the clone image, by digest) come from the catalog, and run-time settings (the concurrency cap,
   resources, retention, the default command) are Dynamic signed settings; no rendered file and no env overrides.
6. Its capabilities are declared once, in its code, including one that says it creates Jobs and their Secrets, computed by the builder;
   it is a catalog workload, not a `src/deploy` one.
7. Who asked for a build is the broker-stamped publisher of the request; it ends through its HealthCheckActor's verdict; its retention is
   a supervised actor; the shared `client-tls` fallback goes; the clone image is built here.

## Plan, in bites

- **O1** the core and Kubernetes crates (types, backend, the Job spec), with decisions 1 and 4 in the Job and no Secret path; tests first
  for what changes. O1a (the core types) and O1b (the Job spec) DONE 2026-11-07.
- **O1c** the Kubernetes protocol's request operations in `polar-agent-builder` (O1c1), then the backend over them (O1c2). O1c1 DONE
  2026-11-07: a cluster operation declares what it may do and the judge holds it to that (O1c1a); create, get, delete and list, and a
  pod's log, a piece at a time to a 256 MiB bound, with the API's own 404, 409 and 422 for the domain to judge (O1c1b). The capability
  for writes (`job-run`, a Role in the build namespace) comes with the agent, in O2, where the build namespace is a catalog fact. O1c2 DONE
  2026-11-07: the backend over those calls (`orchestrator-backend-k8s`, `backend.rs`), one operation for each, with no client or
  credential of its own; a job's log stays in its pod until O4, so the backend trait has no log.
- **O2** the agent on the builder and in the catalog: 5, 5b, 6 and 7. In bites: O2a the build namespace, the build workload rendered
  as a PodTemplate, and the `job-run` capability (a Role in the build namespace, computed from the declared writes); O2b the Job built
  from the PodTemplate read through the handler; O2c the agent itself (his `agent` crate: supervisor, build registry, a job actor per
  build, the signed `mappings` and escrowed `credentials` sections), on the builder and in the catalog.
- **O3** the source by digest: a fetch through the git handler, an archive pushed to the registry (a registry write the handler does not
  have yet), the clone image that checks and unpacks it.
- **O4** the log as a registry blob and its digest in the provenance event (a wire change).
- **O5** build-processor holds a `build_id` to the pod instance that started it (3).
- **O6** live on u7c: a test repository built end to end, its build in the graph.

Open, to raise when its bite comes: the registry write (an operation on the registry handler, its grant); which event carries the log's
digest; the build Jobs' lifecycle (`lifecycle.md`: they are many short instances of one workload); reading whether a build is still
running from its pod's activity (`remaining-work.md`, B21's direction).
