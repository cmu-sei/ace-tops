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

5c. **The template's container runs the fetch image until a build replaces it** (the maintainer, 2026-11-08, "The fetch image,
   replaced per build"): Kubernetes requires an image on a PodTemplate's container (a server dry run on u7c: `containers[0].image:
   Required value`), so the template carries the fetch init container, its image pinned by digest, and a `pipeline` container with that
   same image, which the orchestrator replaces with the mapping's pipeline image in each Job. The fetch image is read from the template.
5d. **Polar judges what a build pod may ask for; Kubernetes' Pod Security only records it** (the maintainer, 2026-11-08, revising
   "Baseline enforced, restricted warned" of the day before). No build pod may run privileged or reach its node (host namespaces, host
   ports, `hostPath`), whatever its mapping says; a signed mapping's run-as-root or added capabilities (decision 4) still run. That rule
   is Polar's, held where the Job is made: the orchestrator's Kubernetes judge refuses a Job create whose pod asks for more than the
   catalog's template and the repository's signed mapping allow, and the attestation agent judges each build pod against the signed
   record before it is issued a certificate. The build namespace's Pod Security labels warn and audit at `restricted` and enforce
   nothing. Why, below ("Why a build pod is judged by Polar, not by Pod Security").

Decided by standing rules, for review (`AGENTS.md`, "Design Principles"):

5. Deployment facts (the build namespace, the clone image, by digest) come from the catalog, and run-time settings (the concurrency cap,
   resources, retention, the default command) are Dynamic signed settings; no rendered file and no env overrides.
6. Its capabilities are declared once, in its code, including one that says it creates Jobs and their Secrets, computed by the builder;
   it is a catalog workload, not a `src/deploy` one.
7b. For O2a: namespaces are named by their `cluster.namespaces` key wherever the catalog names one (`builds` is `polar-builds`); the
   build workload is `build-runner`, its Jobs `build-runner-<build id>` (the attestation agent finds a Job's pod by the workload's prefix);
   the build namespace is attested, since the credentials agent refuses a pod the attestation agent cannot find; the build workload's
   topics are its catalog entry's, as no Polar binary of its own runs there to print a scaffold; the `job-run` Role's rules are fixed in
   `capabilities.nuon`, mirrored in the builder, which holds every declared access to what the agent's capabilities grant; build pods
   use custody as every agent does. The new namespace gets the CA file every pod reads (`up.nu`, `spread_ca`), which today only Polar's
   first namespaces and `attest_also` get.
7. Who asked for a build is the broker-stamped publisher of the request; it ends through its HealthCheckActor's verdict; its retention is
   a supervised actor; the shared `client-tls` fallback goes; the clone image is built here.

## Why a build pod is judged by Polar, not by Pod Security

Decided by the maintainer, 2026-11-08, with the reasoning here so that it can be checked and defended.

**The claim.** What a build pod may ask of its node is decided in Polar's application layer, from signed inputs, by checks that are
Polar's code, tested and on record. Kubernetes' Pod Security Admission is not part of that decision: it is a coarse, fixed policy that
judges a capability by its name, and it cannot tell a sound request from an unsound one. Polar can, because it knows what each
container is for and who signed for it.

**What showed it.** Decision 5d first had the build namespace enforce Pod Security `baseline`, so that Kubernetes would refuse a
privileged build. Every Polar pod has the custody daemon as a sidecar (`key-custody.md`, step 2), and build pods are no exception
(decision 7b). The daemon keeps every key in its own memory and locks that memory with `mlockall`, so that no key reaches swap
(`polar-custody/daemon/src/lib.rs:72`, `lock_memory`). Locking memory past the default limit needs the `IPC_LOCK` capability. A
server dry run on u7c (2026-11-08) of a pod adding `IPC_LOCK` in `polar-builds` was refused: `violates PodSecurity "baseline:latest":
non-default capabilities (container "c" must not include "IPC_LOCK" in securityContext.capabilities.add)`.

`baseline` refuses it because its list of allowed capabilities is the set Docker grants every container by default, and `IPC_LOCK`
was never in it. Nothing about `IPC_LOCK` is dangerous: it lets a process pin its own pages, still within its cgroup's memory limit;
it reads no other process, touches nothing on the host and raises no privilege. The custody daemon's use is the one it exists for. So
the standard refused a sound request on a technicality, and the only ways to satisfy it were to weaken Polar (drop custody, or drop the
memory lock) or to maintain a copy of the standard with an exception carved into it (an admission policy, considered below).

**The argument.** The case for enforcing Pod Security was that it stops a dangerous pod even if the orchestrator is wrong. Follow how a
dangerous build pod would come to exist:

1. The pod is built only from the catalog's PodTemplate (decision 5b), which is in the signed deployment, and the repository's mapping,
   which is signed configuration (decision 4). The orchestrator has no other source of pod settings.
2. The Job is created only through the orchestrator's Kubernetes protocol handler, whose judge refuses any call the code did not declare
   (decision 5a; `polar-agent-builder/src/protocol/judge.rs`, `Denial::AccessUndeclared`). From O2b, the same judge refuses a Job whose
   pod asks for privileged mode, host namespaces, host ports, `hostPath`, or a capability that the template and the mapping do not name.
   That rule is written once, in Polar's code, with example tests and property tests over generated pod specs. *Not built yet: O2b.*
3. The orchestrator's own process is locked down by the builder (seccomp and Landlock) and attested (`runtime-attestation.md`, the
   table of what an attacker does and what catches it). A blocked call or a crash is evidence, reported. *The attestation of its pod is
   built; the lockdown is designed, not built yet (`key-custody.md`: no pod carries a seccomp profile yet).*
4. Every build pod is judged by the attestation agent against the signed record before the credentials agent issues it a certificate
   (`attestation/common/src/verdict.rs:135`, `judge`: its owner, its ServiceAccount, every container's pinned image). A pod that is not
   what was signed gets no certificate, so it cannot speak on Cassini: it can neither report a build nor publish anything.

A dangerous pod therefore needs signed inputs that ask for it, which a reviewer signed and the record shows, or code running inside a
compromised orchestrator that goes around its own handler. The first is refused by step 2 whatever was signed. The second is the
compromised Polar process, which Polar's threat model already answers: make it hard (the lockdown), notice it (attestation, crash
evidence) and keep operating through it, able to shut it down (`runtime-attestation.md`, "What an attacker is assumed to want"). A
Kubernetes namespace label does not change that answer. It would only have stood in for checks that Polar makes itself, with more
knowledge than the label has.

**Where Kubernetes fits.** Polar must run on Kubernetes and accepts its limits; the regress of "who checks the checker" stops at its
control plane, which is why that control plane is on Polar's written trust base (`runtime-attestation.md`, "The trust base is written
down"). That is acceptance, not reliance: Polar does not hand its security decisions to a Kubernetes feature where it can make them
better itself. Pod Security stays in the build namespace as a record: it warns whoever creates a pod below `restricted`, and writes the
same to the API server's audit log, at no cost.

It also keeps Polar's decisions its own across deployment targets. Polar is built to meet different targets at different levels of
assurance: its identity is its own CA's certificates, judged by Cedar and Cassini; its runtime knowledge is signed configuration;
Kubernetes is one protocol behind the builder's handlers (5a) and one backend behind `BuildBackend`
(`build-orchestrator/core/src/backend.rs`). A rule held in Polar's judge and attestation, from signed intent, applies wherever Polar
is deployed, with the visibility to reason about it. A namespace label applies only where that platform does.

**Alternatives weighed.**

- *Enforce `baseline` and run build pods without custody.* Each build pod's key would be a file in its volume, readable by the
  repository's own build code: the weakest key handling in the pod that runs the most foreign code. Rejected.
- *Enforce `baseline` and drop `IPC_LOCK` from the sidecar there.* The daemon logs the failed lock and runs, but its keys may then reach
  swap. A weaker custody, accepted only to satisfy a label. Rejected.
- *A `ValidatingAdmissionPolicy` that copies `baseline`, allowing `IPC_LOCK` on the custody container alone.* It works (built into the
  API server since 1.30), but Polar would keep a hand copy of a standard that moves with Kubernetes, and it is still Kubernetes deciding
  from pod fields what Polar decides from signed intent. Rejected; it may return as an extra layer if a reviewer asks for one.

**What remains.** Polar's judge (step 2) acts before the Job exists; the attestation agent (step 4) acts after Kubernetes has started
the pod. A pod that got past step 2 (only by a compromised orchestrator) would run until it is judged, without a certificate, and be
reported. That is the window Polar's detection-first threat model accepts for a compromised process anywhere in Polar.

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
  from the PodTemplate read through the handler, and the judge's refusal of a Job whose pod asks for more than its template and mapping
  allow (5d); O2c the agent itself (his `agent` crate: supervisor, build registry, a job actor per
  build, the signed `mappings` and escrowed `credentials` sections), on the builder and in the catalog.
- **O3** the source by digest: a fetch through the git handler, an archive pushed to the registry (a registry write the handler does not
  have yet), the clone image that checks and unpacks it.
- **O4** the log as a registry blob and its digest in the provenance event (a wire change).
- **O5** build-processor holds a `build_id` to the pod instance that started it (3).
- **O6** live on u7c: a test repository built end to end, its build in the graph.

Open, to raise when its bite comes: the registry write (an operation on the registry handler, its grant); which event carries the log's
digest; the build Jobs' lifecycle (`lifecycle.md`: they are many short instances of one workload); reading whether a build is still
running from its pod's activity (`remaining-work.md`, B21's direction).
