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
3. **Revised 2026-11-08: build pods hold no Polar identity; the orchestrator judges what a build prints and relays it** ("Build pods
   hold no Polar identity", below). What it replaced: **Build pods are one multi-instance workload, each pod its own certificate.** Every build shares the workload's grants; its broker-stamped
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
4. Every build pod is judged by the attestation agent before the credentials agent issues it a certificate
   (`attestation/common/src/verdict.rs:135`, `judge`): against its owner, every container must run the image its Job pins by digest,
   with no container added and no ephemeral one (`against_owner`); against the signed record, its owner must be the build workload's
   Job and its ServiceAccount the workload's (`against_record`). A pod that fails gets no certificate, so it cannot speak on Cassini: it
   can neither report a build nor publish anything. *Not yet judged: the pod's security settings against what its template and mapping
   allow; that is step 2's rule, held before the Job exists.*

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

## Build pods hold no Polar identity (revising 3)

Decided by the maintainer, 2026-11-08 ("Approve"), with what was settled below; nothing of it is built yet. On the parsing it adds:
"I can accept added complexity in this area because we reduced so much complexity with this design already." The build pod loses its
identity containers, its issuance, its session and the UID question; the complexity that comes back is one small, verified parser in
one locked-down worker, where foreign bytes meet Polar.

**What 3 decided, and what it costs.** Each build pod is an instance of `build-runner` with its own certificate, so that the pipeline
can publish what the build did to Cassini as that pod's word. For that, every build pod carries the custody daemon and polar-init, asks
the credentials agent for a certificate, is attested before it gets one, and opens a Cassini session. And it raised a question that has
no good answer: the custody daemon signs only for the UIDs it is told (1000 in every pod), so a pipeline that its signed mapping runs as
root or as another user (decision 4) could not use the certificate at all.

**What that identity proves.** The code holding the pod's certificate is the repository's pipeline: foreign code. A signed event from
a build pod proves that something running in that pod said it, and nothing more. The orchestrator already knows that much without a
certificate in the pod: it made the Job, it knows the pod, and it reads the pod's output through its handler (5a, and O4 for the log).

**The decision.**

1. *A build pod holds no Polar identity.* The PodTemplate has no custody daemon, no polar-init, no certificate, no projected token
   and no Cassini client: the fetch, then the pipeline, and nothing of Polar's in between. `build-runner` is not issued and opens no
   session.
2. *The pipeline reports by printing.* `scripts/pipeline/core/events.nu` writes each event to its standard output as one framed JSON
   line, instead of publishing it with `cassini-client`. The log goes to the registry as a blob as before (O4); the framed lines are
   also read as reports.
3. *The orchestrator judges what a build reports, and relays what passes.* For each framed line it reads from the pod it started: it
   must parse as a build event of a kind a pipeline may report, name this build's `build_id` (the orchestrator's, which it stamps;
   the line's own is never believed), and be within a size bound and a count bound per build. What passes is published as a claim the
   build made; what fails is counted, and the build is reported as having said something refused.
4. *What the orchestrator saw is its own word; what the build said is a claim.* That the build started, ran and ended, when, and how
   (the Job's and the pod's status) the orchestrator observes itself, and publishes as its observation. What the build produced and
   found (artifacts, images, binaries, SBOMs, packages, advisories) is the build's claim, relayed. Following B11 ("Split topics by
   whose word"), the two go on separate topics, each believed for its own kinds only (`build-processor`, `project::whose_word`,
   `believed_on`): the topic names are for O2c.

**Why this is not a relay whose word is taken** (`proposals.md`, "The parties"). That rule is about a middleman between two Polar
parties, whose word a receiver must not take in place of checking for itself. Here the orchestrator is the first-hand observer of the
build's output, as the Jira consumer is of an issue: its word is "build X's pod printed this", which it alone can say, and what was
printed stays an untrusted claim in the graph, marked as the build's.

**What it gains.**

- Every build pod is simpler: no identity containers, no certificate issuance or attestation at its start, no session, and no UID
  question, so a mapping may run its pipeline as any user.
- The most foreign code Polar runs holds no Polar credential of any kind.
- Polar decides what a build may say before it is said on Cassini, in the orchestrator, with what it knows of the build: the
  application-layer judgement this design is built on.
- B11's open question closes: only the orchestrator publishes build reports, and it alone assigns `build_id`, so no publisher can
  report for a build it did not start.

**What it changes.**

- Decision 3, as above; and 7b's "build pods use custody as every agent does" goes.
- O2a's template: its identity containers, projected token and client environment go; the `template` kind no longer asks for many
  instances on the credentials agent (its pods are never issued). Whether `polar-builds` stays attested is open: no certificate is
  asked for there, but attestation's checks of a pod against its owner (pinned images, no ephemeral container) still detect tampering.
- 5d's reasoning stands on its own. Its example, the custody daemon's `IPC_LOCK` refused by `baseline`, no longer arises in
  `polar-builds`, since no custody daemon runs there.
- O5 becomes "a `build_id` is the orchestrator's", and is mostly done by step 3.
- `events.nu` changes its transport; the event shapes stay.

**What stays of Vaughn's design.** The orchestrator's structure (the build registry actor, a job actor per build, the backend trait),
the Job spec and its hardening, the signed mappings and escrowed credentials, the pipeline scripts' events, and build-processor's
projection. In his branch the orchestrator published the lifecycle events itself, and the pipeline published the rest from the pod:
under the shared `client-tls` Secret by default, which Polar is removing, or, configured, under an identity per job taken from a pool
of ServiceAccounts (his `agent/src/config.rs`, `identity`; `k8s/src/job.rs`, `CLIENT_TLS_SECRET_NAME`). This keeps the first, and
replaces the second with the relay rather than with a certificate per pod.

**Settled with it** (the maintainer, 2026-11-08):

- *A report line is a fixed prefix and one compact JSON line on standard output*: `polar-report {...}`. Any other line is the build's
  output. Build code may print the prefix, by accident or not; that is no new risk, since any code in the pod can say anything and
  every report is judged. A runtime's split of a long line (16 KiB) is joined again by the kubelet as it serves the log.
- *Bounds, Dynamic signed settings with these defaults* (decision 5): a line 16 MiB (an SBOM report carries a project's whole
  dependency graph, `scripts/pipeline/core/events.nu`, `emit-sbom-analyzed`; Cassini's payload limit is about 64 MiB,
  `cassini/types/src/lib.rs`, `MAX_PAYLOAD_BYTES`); a build 10,000 reports and 64 MiB relayed; the whole log is bounded already
  (256 MiB, O1c1b). What exceeds a bound is refused and counted, and the build is reported as having said something refused.
- *The reports are read after the pod ends*, in the one read that also stores the log (O4): complete, and one read for both.
  Lifecycle does not wait for it, since the orchestrator observes it from the Job's status as it happens; only findings come as late
  as the build is long. Reading as the log is written (`follow`) can come later, if lateness matters.
- *Two topics.* `polar.provenance.events` stays, for the build's relayed claims (stages, artifacts, images, binaries, SBOMs,
  packages, advisories), so build-processor's subscription stands. `polar.provenance.executions` is new, for what the orchestrator
  observes: a build started, completed, failed or was cancelled. build-processor believes each kind on its one topic
  (`whose_word`, `believed_on`), and the orchestrator refuses an execution kind a build prints, since that is not a build's to say.
- *`polar-builds` stays attested.* No certificate is asked for there, so attestation's check at issuance never runs for a build pod;
  but the attestation agent watches every pod of the namespaces it attests on its own, holds each to its owner (pinned images, no
  container added or ephemeral) and reports how each container ended, a crash by signal among them (`runtime-attestation.md`,
  "Slice B"). For the pods that run the most foreign code, that detection is worth the Role it costs.

**How a report is read, so that no byte a build wrote can hurt Polar** (the maintainer, 2026-11-08: "There needs to be zero risk
that whatever we've decided to hand to a json parser is of any threat"). No parser is free of risk; what is in our hands is how little
reaches one, and what a bug in it could do. In layers, the riskiest input meeting the simplest code first:

1. *A gate, before any parser.* Over the raw bytes, with no knowledge of JSON beyond brackets and quotes: the line is within its
   bound, valid UTF-8, holds no NUL or other control character, nests no deeper than a fixed limit (counted by a state machine that
   knows only whether it is inside a string), and holds no string or number longer than its bound. No recursion, and no allocation
   that grows with the input. Deep nesting, huge numbers and giant strings, the usual ways in, end here.
2. *Polar's own parser, for one restricted grammar, into one closed type.* Not serde, and not Polar's event type, whose internally
   tagged enum is buffered whole before a variant is chosen. A `Report` type made for this alone: every field named and typed, an
   unknown field refused, no free-form value anywhere, every list bounded, a duplicate key refused (parsers disagree on which one
   wins, a classic way to make two readers see different things), and integers only: no reportable event carries a float
   (`lib/src/events.rs`), so the grammar has none, and with them goes the part of any JSON parser most often wrong. It parses into
   buffers allocated before it runs, sized by the bounds, and allocates nothing more; that is what lets it run under layer 3, and
   what makes it small enough to verify.
3. *The parse runs in a worker process, forked before anything else and locked down.* The orchestrator's builder forks it before it
   starts its runtime or any thread, since the builder's own lockdown forbids starting a program later (no `execve`, runtime
   attestation). The worker then locks itself as seccomp's strict mode locks a process, by a filter allowing what strict mode allows
   (strict mode itself is refused under a container's default seccomp profile, below): it may read its pipe, write its pipe and
   exit, and nothing else, not even ask for memory; with memory and CPU limits, no file, no network and no credential. It hands back a fixed-layout encoding of
   what it parsed, which the orchestrator checks again as it reads it (rkyv's validation, made for bytes that are not trusted). A
   bug in the parser can at worst kill the worker; the build's reports are then refused, and the crash is evidence, reported as
   any crash by signal is.
4. *Meaning, on typed values only.* The kind is one a build may report; the `build_id` is the orchestrator's, stamped; purls and
   digests are well-formed; the counts and sizes are within their bounds.
5. *What is relayed is what Polar built, never what it read.* The events published are encoded from the validated values. The bytes a
   build wrote never pass the worker: nothing downstream (Cassini, build-processor, Neo4j) sees one.

Shown by: proofs, for every input, on the code that runs (Verus, below: the gate and the parser total, never out of bounds or
overflowing, the tape never past its limit, nesting never past its bound); property tests (every valid report encodes and parses back
to itself; no input of any bytes makes the gate or the parser panic, allocate or exceed a bound; a change that leaves the grammar is
refused); coverage-guided fuzzing of the gate and the parser; and the public corpus of parser edge cases behind "Parsing JSON is a
Minefield" (JSONTestSuite), to be fetched only with the maintainer's leave. The pre-forked, strict-mode worker is a builder facility,
so that any agent that must read foreign bytes can use it.

**Proved with Verus** (the maintainer, 2026-11-08: "Verus for the parser"; a controlled test of whether its constraints on how Rust is
written are ones Polar can live with). Weighed:

- *Kani* (bounded model checking of the Rust as written) needs almost no annotation, but proves only up to a bound: "no panic for lines
  of up to 8 bytes" is not "no panic". Good at finding bugs, weak as an argument. Not used.
- *Verus* (deductive proof of Rust, by an SMT solver) proves a property for every input, on the code that ships: the verified code is
  compiled as written, its proofs and specifications erased. The cost: the code is written in the subset Verus reasons about, and the
  proofs are written with it. Chosen.
- *Lean* would let the grammar be defined and the parser proved against it, round trips and all, but its proofs are of Lean code: the
  Rust would be translated to it (Aeneas, research grade, a subset of safe Rust) or the parser run as Lean. The strongest tie to a
  specification, and the weakest to what runs. Not now.
- *Alloy* models designs, not code: the right tool for the relay's trust (only the orchestrator publishes build reports; a `build_id` is
  only ever its; a refused line reaches nothing downstream), not for the parser. Possible later.

What Verus is today (read 2026-11-08):

- Weekly releases, the latest `0.2026.11.02.8bf68ee` (2 November 2026), with a rolling pre-release from `main`. Prebuilt for Ubuntu
  24.04 x86_64, macOS and Windows; other platforms build from source.
- It verifies with a private Rust toolchain, pinned by its `rust-toolchain.toml`: `1.99.1`, with `rustc-dev` and `llvm-tools`. Polar's
  workspace builds on a nightly (1.101); nixpkgs has `rustc` 1.99.0. Its solver is Z3, pinned at `4.16.0` (`source/tools/get-z3.sh`);
  nixpkgs has 5.1.0.
- `cargo verus` verifies the crates of a workspace that opt in (`[package.metadata.verus] verify = true`); the others compile as before.
  Plain `cargo build` still builds an opted-in crate, its proofs erased; verification is `cargo verus verify -p <crate>`. A crate depends
  on `vstd`, Verus's library of specifications, pinned to the release (`=0.0.0-<date>`), and on its macros.
- Supported, of what the reader needs: structs, enums, `match`, `Option`, `Result` and `?`, `while` and `loop`, early return, `&mut`,
  slices, `Vec`, unsigned arithmetic (every operation proved not to overflow), recursion with a `decreases` measure. Partly: iterators
  and `for` loops, closures (no mutable capture). Strings are reasoned about as sequences of `char` through `vstd::string`, with
  `str::as_bytes` not yet specified as a slice.

What that means for the reader's code (O2d1): the gate and the parser work on bytes (`&[u8]`, a `Seq<u8>` to the proofs), never on
`&str`; UTF-8 is checked by a loop of its own, proved against a definition of a well-formed sequence, not by `std::str::from_utf8`; loops
are `while` loops with their invariants, not iterator chains or closures; the parser's recursion decreases with depth. Decoding a checked
line into owned values (escapes, `String`s) is not proved: it runs after the checks, outside the worker, under the property tests.

Packaging: a flake of its own on the maintainer's GitHub, Verus built from its release tag with the 1.99.1 toolchain and `rustc-dev`
(from a Rust overlay, as nixpkgs' is 1.99.0), and Z3 4.16.0 (nixpkgs' version overridden), so that the solver and the verifier are
pinned with the rest of Polar's toolchain; `vstd` from crates.io at the release's pin. The gominimal package set builds it the same way
(from the tag, the vendored crates, the private toolchain's component tarballs checked against static.rust-lang.org, Z3 pinned).

What it took (O2d1a, 2026-11-08). Packaged: Verus built from its tag needed three things a developer's machine gives it, each
in `nix-verus`'s README (`pkg-config` and `zstd` for a build dependency; a stand-in for `rustup`, which the `verus` crate's build
script asks for the toolchain's name; and a git repository, which `rust_verify`'s reads its version from). `vstd` verifies as it is
built, 2,159 obligations. A crate proved with it still builds with plain `cargo` on Polar's nightly, its proofs erased, with no
warning: the workspace is unchanged but for `vstd` and Verus's macros in its lock.

Proved, `orchestrator-report` (`cargo verus verify -p orchestrator-report`, or `just verify`), for every input and any bounds, with
no precondition on either public function, so that it holds for the unverified callers too:

- `gate`: terminates, never panics, indexes out of bounds or overflows; passes a line only within its length, free of control
  characters, and UTF-8 as `vstd::utf8::valid_utf8` defines it (a scalar at a time, from the front, overlongs and surrogates
  refused), the loop carrying one invariant: what is left is valid exactly when the line is.
- `parse`: terminates (its recursion decreases with depth, by a measure on `value`, `object` and `list` together), never panics or
  overflows; the tape never past its limit nor past what a `u32` counts, and its limit unchanged; every key's and text's span inside
  the line, every container's end inside the tape.

- `check` (O2d1b): terminates, never panics or overflows, and reads nothing outside the line or the tape, whatever tape it is given
  (the parser's, or one made otherwise: every index and span is checked before it is used); its recursion, into a report's
  packages, edges and layers, decreases with each schema's rank. What it accepts: a kind a build may report, named by `type`
  (stage started or completed, a security advisory, a package's status, an artifact, an SBOM, a binary linked, an image
  created; never a build's own execution, which is the orchestrator's to say), and for it every field of Polar's event types,
  typed, at most once, and present where the type says so (an `Option` may be `null` or absent, a serde default absent); an
  unknown field refused, and `build_id` read and never believed. Whether a field is required is said once (`required`).

Not proved, and held by property tests instead (`tests/props.rs`, `tests/reports.rs`): that the gate's UTF-8 agrees with
`std::str::from_utf8` (a differential test of the two definitions on the build that runs); that any value of the grammar, written
as JSON writes it, parses to one token for each value and key; that anything after a report is refused; that any report of any
kind, with any text in its fields, written as the pipeline writes it, reads back as itself (`Report::read`, the decoding, which
allocates and so runs outside the worker); that one renamed among the fields a kind must have is refused.

Fuzzed (`build-orchestrator/report/fuzz`, its own workspace, `cargo fuzz run read`, with nixpkgs' `cargo-fuzz` and `clang`): any
bytes through the gate, the parser, the check and the decoding, none panicking, and whatever reads as a report reading back as
itself once written out again. First run, 2026-11-08: 14.5 million inputs in ten minutes, no failure; its corpus reached deep only
the three kinds it was seeded with, so it is now seeded with one of each kind (`fuzz/seeds`, each read by a test).

What Verus asked of the code, the maintainer's question ("I've long-wondered if I could deal with the constraints it places on how
I write Rust code"):

- Bytes and indexes, `while` loops with their invariants and a `decreases` measure, early returns and `?`, `Vec` push, set and
  clear, fixed arrays, `&mut` parameters: all as ordinary Rust. No iterator chains or closures in what is proved.
- A postcondition names a mutable reference's state after the call `final(x)`, beside `old(x)` (this release's mutable-reference
  support); a variable only the proof uses is `let ghost`, so that a plain build has none.
- A verifier attribute (`loop_isolation`) is not erased from a plain build, so the facts it would carry into an inner loop are
  written as that loop's invariants instead.
- A range test is two comparisons: Verus reasons about the comparisons, not `RangeInclusive::contains` (clippy's
  `manual_range_contains` is allowed for the crate, with that reason).
- The effort: the gate verified on its second run, the parser after five rounds of fixes, two of them for keeping a plain build clean; every failure named the line and the obligation, and
  the fixes were facts the code relied on without saying (the tape only grows; a string consumes its opening quote). One was a
  defect: a tape given more than four billion slots would have truncated a container's end, stored as a `u32`; the tape now refuses
  to grow past what a `u32` counts.

*Sources, read 2026-11-08:* [Verus releases](https://github.com/verus-lang/verus/releases);
[INSTALL.md](https://github.com/verus-lang/verus/blob/main/INSTALL.md);
[the release's rust-toolchain.toml](https://raw.githubusercontent.com/verus-lang/verus/release/0.2026.11.02.8bf68ee/rust-toolchain.toml);
[its get-z3.sh](https://raw.githubusercontent.com/verus-lang/verus/release/0.2026.11.02.8bf68ee/source/tools/get-z3.sh);
[the guide's supported features](https://verus-lang.github.io/verus/guide/features.html),
[strings](https://verus-lang.github.io/verus/guide/strings.html) and [cargo verus](https://verus-lang.github.io/verus/guide/cargo_verus.html);
[vstd's string specifications](https://docs.rs/crate/vstd/latest/source/string.rs) and [slice specifications](https://docs.rs/crate/vstd/latest/source/std_specs/slice.rs);
[gominimal's Verus package](https://github.com/gominimal/pkgs/pull/1245).

## Plan, in bites

- **O1** the core and Kubernetes crates (types, backend, the Job spec), with decisions 1 and 4 in the Job and no Secret path; tests first
  for what changes. O1a (the core types) and O1b (the Job spec) DONE 2026-11-07.
- **O1c** the Kubernetes protocol's request operations in `polar-agent-builder` (O1c1), then the backend over them (O1c2). O1c1 DONE
  2026-11-07: a cluster operation declares what it may do and the judge holds it to that (O1c1a); create, get, delete and list, and a
  pod's log, a piece at a time to a 256 MiB bound, with the API's own 404, 409 and 422 for the domain to judge (O1c1b). The capability
  for writes (`job-run`, a Role in the build namespace) comes with the agent, in O2, where the build namespace is a catalog fact. O1c2 DONE
  2026-11-07: the backend over those calls (`orchestrator-backend-k8s`, `backend.rs`), one operation for each, with no client or
  credential of its own; a job's log stays in its pod until O4, so the backend trait has no log.
- **O2** the agent on the builder and in the catalog: 5, 5b, 6 and 7, and 3 as revised. Reworked 2026-11-08 around revised 3 (the
  maintainer, "Yes, record it and start O2b"):
  - **O2a** the build namespace, the build workload rendered as a PodTemplate, and the `job-run` capability. O2a DONE 2026-11-08: the
    `job-run` capability (O2a1), the build namespace (O2a2), the fetch image (O2a3a), and the `template` kind with `build-runner`'s
    PodTemplate (O2a3b; `infra/config/workloads/build.nuon`, `schema/pod-template.dhall`, on `schema/agent-pod.dhall`, the pod every
    catalog workload shares, split out of `agent.dhall` with every agent's manifest unchanged byte for byte). Server dry run on u7c:
    accepted, with `restricted` warnings for the identity containers alone (below). Decided by standing rules, for review: the build
    workload is in the `observers` pool, with the low-trust side, since it runs foreign code (`placement.md`); its fetch and pipeline
    containers carry decision 4's hardening in the template itself (no privilege escalation, the default seccomp profile).
  - **O2b** the template without an identity: no custody, polar-init, projected token or client environment, the fetch then the
    pipeline; the `template` kind not issued and not a Cassini client, `build-runner` out of the credentials agent's authority model;
    build-processor's events subscription waiting again, for the orchestrator; `events.nu` printing `polar-report` lines. DONE
    2026-11-08: `schema/agent-pod.dhall` split into a `base` every pod has and an agent's `identity` (custody, polar-init), every
    agent's manifest unchanged byte for byte; the template on the base alone, the fetch then the pipeline; a template refused if it
    would hold an identity (a capability, custody), name topics or read a document; `build-runner` out of the authority model and the
    issuer rule; `ci.nu` no longer starts a Cassini daemon. Server dry run on u7c: accepted with no warning, `restricted` in full.
    Left for O2e: `ci.nu` still prints the execution events (started, failed), which revised 3 makes the orchestrator's to say.
  - **O2c** the Job built from the PodTemplate read through the handler (`get podtemplates`), named `build-runner-<build id>`, the
    pipeline's image, command and privileges from the mapping; the builder's judge refusing any pod-bearing create that asks for
    privileged mode, host namespaces, host ports or `hostPath`, for every agent; the orchestrator's check that a Job's pod is its
    template's, changed only where the mapping signed. Property tests for both. DONE 2026-11-08: O2c1, the judge's floor
    (`Denial::ReachesTheNode`; `kubernetes::reaches_node` reads the whole object, so no kind, nesting or container list is a way
    round it, and labels and data are not read for it; `protocol-handlers.md`); O2c2, `orchestrator-backend-k8s`: `build_job`
    makes a build's Job from the template read through `build.podtemplates.get` for each build, and `departures`, said
    independently of it, holds the Job to what a build may change before every create (the pod and the fetch as the template
    says them; the pipeline's image, pinned, command, added plain environment, resources and hardening within what the mapping
    signs; the scratch volume and mount; the workspace's size and read-only). The identity JSON, the fetch image, pull policy
    and CA-bundle options are gone, the template's now. A property test makes the Job from any build and finds no departure,
    and finds each of 21 changes a build may not make whatever the build.
  - **O2d** the report reader ("How a report is read", above): O2d1 the byte gate, the `Report` type and Polar's own parser, with
    property tests, fuzzing and Verus proofs (its flake first, on the maintainer's GitHub). O2d1a DONE 2026-11-08: Verus packaged
    (`github.com/daveman1010221/nix-verus`, in the dev shell; `just verify`), and the gate and the parser proved, 35 obligations
    (`build-orchestrator/report`, below). O2d1b DONE 2026-11-08: the report grammar's check proved too (58 obligations in all),
    decoding a checked line into owned values (not proved; property tests and fuzzing), and a fuzz target through all four
    steps. JSONTestSuite (the maintainer's leave, 2026-11-08): its 318 parsing cases vendored at a pinned commit
    (`build-orchestrator/report/tests/jsontestsuite`), all 188 that JSON refuses refused, the 95 it accepts read or refused only
    for what the grammar leaves out (65 read), no case panicking. O2d1 DONE. O2d2 the pre-forked worker in seccomp
    strict mode, a builder facility, and its validated hand-back; planned 2026-11-08 (the maintainer: "The agent ends and
    restarts"): an agent declares the workers it needs; the builder forks each in `run`, after the configuration is judged and
    before the runtime is built (refusing if the process has more than one thread); the child closes every descriptor but its
    two pipes, sets no-new-privileges and not-dumpable, allocates its buffers at the bounds signed at start (a Dynamic change may
    narrow, never widen, them), enters seccomp's strict mode, and answers length-prefixed requests. A worker that dies (killed by
    seccomp, a crash, a timeout) cannot be forked again once the runtime runs: its death is evidence, the pending reports are
    refused, and the agent ends, its pod restarting with a fresh worker. In three: O2d2a the builder's fork, strict mode and
    pipe protocol, tested in a child of the test binary (the test runner is threaded); O2d2b the async handle and the death's
    verdict; O2d2c the report worker's function and its tape hand-back (16-byte records), re-checked and decoded on the parent's
    side. O2d2a DONE 2026-11-08: `polar_agent_builder::worker` (`fork`, `Work`, `Worker::ask`), tested in a binary of one
    thread (`tests/worker.rs`): a worker answers within its bounds; a system call strict mode does not allow, or memory asked
    of the kernel, kills it; a descriptor the agent had open is closed in it; a forged answer longer than it may give is
    refused and the worker ended; a process with a second thread forks none. Open until O6: that the container runtime's
    default seccomp profile lets the pod set strict mode (`prctl`) and close its descriptors (`close_range`). O2d2b DONE
    2026-11-08: an agent declares `PolarAgent::WORKERS` (`WorkerDecl`: a name, how it is forked from the configuration, how
    long an answer may take); `run` forks them after judging the configuration and before building the runtime, and the
    infrastructure supervisor spawns a `WorkerActor` for each, which the domain asks through `AgentResources::workers`. A
    worker that dies, lies or takes too long refuses the request, is killed, and fails its actor; the supervisor ends the agent
    as it does for any child of the builder's that ends unexpectedly (`shutdown::on_child_death`; its health says it is
    draining). Decided by that precedent, for review: the agent ends through its supervisor's orderly shutdown, not a verdict
    of the health actor's, which has no message for it. Tested in the same binary: a handle's round trip, a request past the
    bound failing nothing, a worker killed from outside and one that spins past its time each failing its actor. O2d2c DONE
    2026-11-08: `orchestrator_report::answer`, proved (70 obligations in the crate now), runs the gate, the parser and the
    check and writes the tape as a 16-byte header (0 or a refusal's code, the kind's code, the count) and a 16-byte record per
    token, never past its buffer, refusing a tape too big for it; `Report::read_answer`, on the agent's side, holds an answer
    to its exact length and the bounds, rebuilds the tape, checks it again, decodes from the line's own bytes, and refuses a
    kind the line is not. A forged tape that passes the check can make the line say only what its author could have written.
    The proof found one bug while it was written: a header zeroed past the width its writer takes. Tested: in process, any
    bytes answered and read give exactly what reading them directly gives, an answer cut short, made longer, past the bound
    or of another kind is refused, a tampered one never panics; and in a real worker in strict mode (`tests/worker.rs`), the
    eight seeds and five refusals each read as directly, the worker alive after them. O2d2 DONE. O2d3 the meaning checks
    and the re-encoding: DONE 2026-11-08, `orchestrator_core::relay`. Every report relayed goes in an envelope,
    `polar::events::BuildReport { build_id, report }` (the maintainer, "An envelope for every relayed report": three kinds'
    event types have no `build_id`, and the stamp belongs beside the facts, not in them); `build_id` is the orchestrator's, in
    the envelope and in the event wherever the event has one, whatever the line said. A `Relay` per build holds it to its
    bounds (10,000 report lines and 64 MiB, refused ones counted, Dynamic settings with the agent in O2e) and judges what the
    values mean: every hash a graph key is made from (an artifact's, an SBOM's, a binary's, a tarball's, a config's, a
    layer's, an image's and a binding's digest when given) is `sha256:` and 64 lower-case hex, as the pipeline writes them,
    or the report is refused naming the field; purls are build-processor's to judge, as an SBOM may name a component by none.
    Then the report re-encoded as Polar's event: what is relayed is what Polar built from the values, never the bytes. Tested:
    the stamp over a line's own `build_id`, each malformed digest refused by field, the bounds, a property that any report
    with well-formed digests relays and its envelope survives rkyv, another that any one digest spoiled is refused; and each
    `Refusal`'s message its own sentence, the same whatever the line (polar-cc's survey, claimed). A wire change, read by
    build-processor in O2e. O2d DONE.
  - **O2e** the agent itself (his `agent` crate: supervisor, build registry, a job actor per build) on the builder as
    `Role::Controller`, its signed `mappings` and escrowed `credentials` sections, its catalog entry and `job-run`;
    `polar.provenance.executions`, and build-processor's `whose_word` split to it; build-processor reading the relayed
    claims as `BuildReport` envelopes, believing the envelope's `build_id`. Planned 2026-11-08 (the maintainer, "Yes, record it and start O2e1"), in
    four: O2e1 the agent on the builder (`Role::Controller`, the backend's operations, the report reader as its worker, Dynamic
    settings for the concurrency cap, the pipeline's resources, retention and the reader's and relay's bounds, the signed
    `mappings` section with decision 4's privileges, its topics), running and building nothing; O2e2 the actors (supervisor,
    admission, the commits already built, the registry, a job actor per build: the Job from the template, its log read once
    the pod ends and its reports relayed through the worker and the relay, its own execution events published), the source
    step behind a trait until O3; O2e3 `polar.provenance.executions` and build-processor reading the envelope and believing
    each kind on its own topic, the pipeline no longer printing execution events; O2e4 the catalog entry, the `job-run` Role in
    `polar-builds`, the render, a live start on u7c. Of Vaughn's crate, kept in shape: the supervisor, admission, the commits
    seen, the registry and the job actor; gone, main having another way: the configuration file (Dynamic settings and catalog
    facts), the object store (the registry, O4), the identity JSON and account pools (no identity in a build pod), the clone
    image (the fetch image), the pipeline-image bootstrap (a mapping pins its image), `KubeApiRead` (`job-run`, computed).
    Decided by standing rules, for review: no build-request topic until something requests builds (a ref update is the one
    trigger now; a requester, when there is one, is the broker-stamped publisher); the `credentials` section comes with the
    git handler that uses it, in O3. O2e1 DONE 2026-11-08: the `build-orchestrator` crate (`build-orchestrator/agent`), a
    `Role::Controller` whose needs are computed (Cassini and `job-run`, from the backend's six operations; no
    `kube-api-read`), with the report reader as its one worker (`reader::DECL`) and a supervisor that holds its configuration
    and builds nothing (a ref update is noted and dropped). Its settings (`settings.rs`): the build namespace and the template,
    Static and with no default, the catalog's to say; and, Dynamic and followed as one group, the concurrency cap (1), the
    pipeline's CPU and memory requests and limits (`PipelineResources`' defaults, each a Kubernetes quantity, a request no more
    than its limit), the workspace's size (8Gi), how long a finished Job is kept (an hour, a day; at least a minute, room for
    the one read after the pod ends), the relay's bounds and the reader's (the crates' defaults), and the default command
    (empty, the image's own). Its `mappings` section (`mappings.rs`, Vaughn's, adapted): an entry's URL is checked as the git
    controller checks one and keyed as the git observer names the repository (`RepoId::from_url`); its image is required and
    pinned by digest; its `privileges` are decision 4's, `Privileges::problems` holding the capabilities; its credentials are
    named as the git observer names one; an empty command is refused (leaving it out means the default), every list bounded,
    and a problem names the entry and the field and never a value, an unknown key included. `polar.provenance.executions` is
    declared in `lib/src/topics.rs` and published `.waiting` until O2e3. Found while writing it: `Report::read_answer` holds an
    answer to the token bound only, so a signed narrowing of the line, string, depth or item bound would not have reached a
    worker that allocated at start. A request to the reader now carries the bounds it is to be read at, ahead of the line; the
    worker reads at the narrower of those and its own (`settings::narrowed`), lowering its tape's limit within what it
    allocated, so a signed update narrows the reader while the agent runs and no request widens it. Decided by standing rules,
    for review: the workspace bound and its default (an unbounded `emptyDir` lets a build fill the node's disk); retention's
    least of a minute. Tested: the settings' defaults, each bad setting named; the mappings, read and refused by example; the
    agent's declaration (`polar_agent_tests!`, its needs exactly Cassini and `job-run`); the reader forked from the
    configuration in a real worker in strict mode (`tests/reader.rs`), reading each line as directly, a narrowed bound
    refusing what it should, a request asking wider read at the worker's own, one without its bounds refused; and properties
    (`tests/props.rs`): any mappings read back as written, any entry spoiled in any of twelve ways refused naming it and never
    the value, a repository mapped twice refused wherever it is, a quantity read as its number and unit, a request above its
    limit refused exactly when it is, and the bounds read at never wider than the worker's or the signed ones.
    O2e2 split in two (the maintainer, 2026-11-08, "Yes, split"): O2e2a a build's life without its log (admission with the
    Dynamic cap, the commits already taken, the registry, a job actor per build making the Job from the template on the
    mapping's image, command and privileges, polling it to its end and publishing its own execution events on
    `polar.provenance.executions`, the sweep of Jobs past their retention, and the source step behind a trait whose one
    implementation refuses until O3, so a build fails at its source and says so); O2e2b the one log read after the pod ends
    (the handler's streamed `pods/log`, each `polar-report` line through the worker at the narrowed bounds and the relay, out
    as a `BuildReport`). O4 is left the log as a registry blob. *A restarted orchestrator adopts the Jobs still running*
    (the maintainer, 2026-11-08, "Adopt running Jobs only"): it lists its own Jobs at start and watches those not ended to
    their end, reading each one's log then; a Job that ended before it started is never read. A log is so read at most once,
    by the orchestrator that saw its pod end, and a log that killed the reader cannot kill it again at every restart, which a
    build could otherwise cause on purpose (a dead worker ends the agent, O2d2). A restarted orchestrator cannot tell a Job
    its predecessor finished with from one that ended unwatched, so of a Job that ended before it started it says nothing,
    and build-processor's aging judges a build lost that was never heard to end. What restarts lose: the reports of a build
    that ends while no orchestrator watches, and the builds waiting for a place. Decided by standing rules, for review: a
    build takes the settings and the mapping in force when it starts (Vaughn's, "deterministic with respect to the config
    snapshot"); a read that kills the worker is published as that build's failure, at the stage of reading its reports, before
    the agent ends: the crash is evidence. O2e2a DONE 2026-11-08: the supervisor turns a moved ref of a mapped repository
    (`build_for`: the mapping found by the repository's `RepoId`, the commit checked, a ref reported unchanged or a commit
    discovered no build) into a build, once per commit (`observed`, Vaughn's: a commit whose build did not succeed may be
    built again), admitted (`admission`, Vaughn's, with the cap a Dynamic setting: a raised cap starts who waits, in order, a
    lowered one stops nobody; an adopted build holds a place whatever the cap), and recorded (`registry`, Vaughn's, bounded:
    the records of ended builds kept to 1,024, his never let one go). A build's actor (`build`, his `BuildJobActor` in shape)
    prepares its source (`Source`, whose one implementation, `NotYet`, refuses until O3), makes its Job from the template
    on the mapping's image, command (or the default) and privileges, through a backend made with the settings in force when
    it starts, polls it to its end, and says so on `polar.provenance.executions` in its own word: `ExecutionStarted` (who
    reported the ref moved, as the broker stamped it, as `triggered_by`), then `ExecutionCompleted` or `ExecutionFailed` at
    `source`, `scheduling` or `execution`. A build quicker than a poll is recorded as having run. At start the supervisor
    adopts its Jobs a poll would find pending or running (`BuildBackend::in_flight`, read from the labels and annotations
    a Job is made with, by the same reading of its status a poll makes, so a Job adopted is one no orchestrator saw end);
    each is watched to its end, its duration counted from its Job's making. Every five minutes the Jobs past their retention
    are removed. At `PrepareShutdown` the running builds' Jobs go on, for the next orchestrator to adopt, and the waiting
    are given up. Of Vaughn's left out: the build-request topic, cancellation (nothing asks for it yet) and his poll's
    unbounded retries stay as they were (a Job that cannot be polled is asked again; build-processor's aging judges a build
    lost that is never heard to end). Tested: the build's actor against a stand-in backend, source and broker at each way a
    build goes (succeeds, quicker than a poll, the default command, its source not had, its Job refused, failed, gone, a
    poll that fails, adopted); a ref update read into a build or none; the registry's state machine and bound; the
    backend's adoption against the stand-in API (its own Jobs, not ended, one that does not say what it builds passed over)
    and a property that any build's Job not ended reads back as made and one ended is never adopted; and a property that
    whatever happens to admission, in any order, no place is idle while a build waits, a build starts once, the waiting
    start in the order they came, and its counts are what started and did not end. O2e2b DONE 2026-11-08: once a build's
    Job ends, however it ended, its actor reads the Job's log once, before it says how the build ended. Through two new
    operations, `build.pods.list` (the pods the Job owns, by its uid, oldest first) and `build.pods.log` (the pipeline
    container's log, streamed by the handler a piece at a time to its 256 MiB bound), both within `job-run`'s grants; a tap
    hands each piece on and holds the handler's delivery until it is taken, so the log is read no faster than its reports
    are (`BuildBackend::log`, `LogPieces`). The report lines are found as the pieces come (`lines`: a line that begins with
    the prefix, kept to the reader's line bound and no further; every other line passed over unkept), each counted against
    the relay's bounds, asked of the worker at the bounds in force when the build started, narrowed to the worker's
    (`request`), read back (`Report::read_answer`), judged and stamped by the relay, and published in its `BuildReport`
    envelope on `polar.provenance.events`. A worker's death fails the build at `reports` and ends the agent; a log that
    cannot be had, or ends in an error, leaves the build as it ended and what was read relayed. Decided by standing rules,
    for review: how many of a build's report lines were refused is logged with the build, and reaches its execution event
    with O4's wire change (the log's digest), which changes the same events; until then the record of a refusal is the
    orchestrator's log. Tested: the log read against the stand-in API (the Job's own pods, oldest first, the pipeline's
    log whole however long, another Job's pod not read; a Job with no pod has no log); the build's actor with the reader's
    own work in process (reports relayed and stamped with the orchestrator's id and published before the build's end,
    the rest passed over or refused, however the log is split; a failed build's reports read too; a reader that dies failing
    the build at `reports`, asked nothing more; a log not had or ending in an error; the line and report bounds, a line past
    its bound never asked of the reader); and a property that whatever a log holds and wherever its pieces split it, the
    lines found are exactly its report lines, each within the bound or known only by its length. O2e2 DONE. O2e3 DONE
    2026-11-08: build-processor believes each kind on its one topic by whose word it is (`whose_word`): a build's
    execution (started, completed, failed, cancelled) the orchestrator's, on `polar.provenance.executions`, which it now
    subscribes to; a build's reports on `polar.provenance.events`, read only as `BuildReport` envelopes and believed for the
    envelope's build, an event that names another build refused (`relayed`, by `build_id_of`); a registry's facts on the
    resolver's topic as before. It reads rkyv alone: its JSON form was the pipelines', and no pipeline publishes since
    build pods hold no identity, so a second wire format is closed with its last sender. The pipeline no longer prints
    execution events (`ci.nu`, `core/events.nu`); the reader refuses one a build prints. `lib/src/topics.rs` and the
    event type's routing note say so. Found, for later: `scripts/pipeline/smoke-test.nu` does not parse (its calls do not
    match the functions they name, and it tests the Cassini daemon route revised 3 removed); left as it was. Tested:
    belief for every kind on each of the three topics; an envelope believed for its build and refused for another, for
    every kind that names one; the build stream reading relayed reports and nothing else (a bare event, archived or JSON,
    refused); its topics; and, against Neo4j, the projection as before. O2e4, the catalog and the image, 2026-11-08: the
    orchestrator is a catalog workload (`config/workloads/build.nuon`, beside the build workload it makes Jobs from),
    told where its builds are as the deployment's facts (decision 5): its namespace by the cluster's name for the
    template's key, through a placeholder resolve now has (`{namespaces.<key>}`; a key the cluster lacks is an error, not
    text left in), and the template's name. Its `job-run` Role in the build namespace is the capability's
    (`capabilities.nuon`), computed from its operations; no ClusterRole. Its certificate comes from the credentials agent
    (sandbox-local's issuer list), its manifests are in sandbox-local's agents layer after the template's, and its image
    is a Nix container like build-processor's (`build-orchestrator/agent/package.nix`, `container.dhall`). On `core`, by the
    git controller's row (`placement.md`): a controller deciding what runs, with no graph password. Decided by that rule,
    for review. build-processor's two waiting notes are gone, its other sides now in the catalog. Tested: resolve (it is told
    `polar-builds` and `build-runner`, and given one Role there with exactly `job-run`'s rules; its pool; its issuer; the
    budget it declares) against scaffolds built from this tree, with facts, rules, topics, the catalog topic cross-check,
    images, layers, egress, agent pods, deploy objects, the deployment repository, graph and document; the image built
    with Nix. Live on u7c, 2026-11-08 (6f1a6b65, `up.nu sandbox-local --dev`, to its browser step): the orchestrator's pod
    ran on `core`, both containers ready, no restart; it registered with Cassini and subscribed to its topics, said
    `namespace=polar-builds template=build-runner cap=1`, and its adoption's list of Jobs went through the handler
    (`build.jobs.list`, allowed). On the node, its reader is a child of one thread with `NoNewPrivs: 1` and `Seccomp: 1`
    (strict mode): the open question of O2d2a answered as far as u7c goes, since the container has no seccomp profile at
    all. The agent's own process shows `Seccomp: 0` and `NoNewPrivs: 0`, the Polar-wide gap recorded below ("Polar's
    identity containers and `restricted`"): its containers set neither `allowPrivilegeEscalation: false` nor a seccomp
    profile, so strict mode under `RuntimeDefault` is still to be seen, when the profiles of the runtime attestation work
    come. O2e4 DONE; O2e DONE. *Seen, 2026-11-10 (slice C's C1 live on u7c): it is refused.* Under `RuntimeDefault` the reader
    died at its lockdown (`exited 12`): the kernel refuses strict mode to a process that has a seccomp filter already, and the
    default profile is one, so the orchestrator restarted every five minutes with its custody daemon. The worker now installs a
    filter allowing what strict mode allows (`read`, `write`, `exit`, `rt_sigreturn` of the agent's architecture; any other
    call kills it, by `SIGSYS`), which stacks on the runtime's (`polar-agent-builder` `worker.rs`, `STRICT`; tested by a
    worker forked under a filter already, which failed as on u7c before the change).
- **O3** the source by digest: a fetch through the git handler, an archive pushed to the registry (a registry write the handler does not
  have yet); the fetch image (O2a3a) checks and unpacks it. Planned 2026-11-08, in four. Found first, on u7c's registry
  (`registry:2.8.3`): it does not take a blob in one POST (`?digest=` with the body answers 202 and opens an upload session), so a
  push is a POST then a PUT, and the HTTP handler has GET and POST alone. O3a the registry write: the handler gains PUT and HEAD;
  the orchestrator declares `registry.blob.push` at the host its configuration names (`Location::Configured`), no credential; a
  push is the blob (HEAD first, so an unchanged commit is not sent again) and a small OCI manifest pointing at it, tagged by
  commit in `build-sources` (the maintainer, 2026-11-08, "Blob plus a manifest": safe from the registry's garbage collection,
  found by commit, and the shape O4's log blobs and Polar's housekeeping follow, as `evidence-storage` keeps bodies); tested
  against a stand-in that behaves as distribution does. O3b the archive: a pure function from a commit's tree to a gzipped tar,
  deterministic (tree order, fixed times and owner, git's modes, a gzip header with no time), so a commit is always one digest;
  property tests that a tree is the same bytes from any clone, that the fetch's own `unpack` gives the tree back, and that a tree
  past the bound is refused. O3c the source step: `GitSource` for `NotYet`, fetching with `git.fetch` (the credential the mapping
  names, bound to its host) or `git.fetch-public`, as the git observer does; the escrowed `credentials` section (the builder's
  shared shape) and `Encryption` with it; one fetch per repository at a time, its clone shared; the cache the `working-checkout`
  capability's; the registry's address as a pod reaches it (a Static setting from the catalog, through a new placeholder, not the
  nodes' `localhost:30500`) and the archive's bound (Dynamic); the template told the registry is plain http (the open "fetch's
  registry", below). O3d live on u7c: a public test repository's commit archived, pushed and fetched by a build pod. Decided by
  standing rules, for review: the in-cluster registry takes pushes from any pod without a login, and the orchestrator is its first
  in-cluster writer; a source's integrity rests on its digest, which the fetch checks before it unpacks, so this is recorded rather
  than the registry given a login now; and an archive is held in memory to its bound, since the handler takes a body whole. For the
  watched build after O3: an archive carries no `.git`, and `scripts/pipeline/core/cargo.nu` asks `git rev-parse --show-toplevel`.
  O3a DONE 2026-11-08: the HTTP handler's requests gain `put` and `head` (`polar_agent_builder::protocol::http::Request`); the
  orchestrator declares `registry.source.push` (`push::PUSH`) at `POLAR_ORCHESTRATOR_REGISTRY`, a Static setting the catalog
  gives it as `{pod-registry}`, which resolve makes the registry in the cluster as a pod reaches it
  (`http://registry.polar-registry.svc.<domain>:5000`, `cluster-registry.nu`, `pod_registry`; a target with no registry in the
  cluster has none, and naming it there is an error). A push (`push::push`) asks whether the archive is there (HEAD), opens an
  upload (POST) and ends it at the path the registry names (PUT with the digest), whatever host `Location` names, the request going
  to the configured one; then OCI's empty config the same way; then the manifest (`push::manifest`: one layer, the archive,
  `application/vnd.polar.build-source.v1.tar+gzip`, artifact type `application/vnd.polar.build-source.v1`) by the commit's tag,
  blobs before manifest so a manifest never names what is not there. Being an HTTP agent now, the orchestrator declares the egress
  section the builder gives one; the registry is a Service, which `.svc` keeps off any proxy (`egress.nu`, `no_proxy_of`).
  Tested: a PUT with its body and a HEAD with none reach the configured host (the handler); against a stand-in registry that
  behaves as distribution's did on u7c (a POST only opens an upload; the upload goes on at a `Location` on another host; a PUT
  whose body is not its digest refused; manifests by tag), a source is its blob and a manifest by its commit naming exactly it,
  every request to the configured host and allowed, an unchanged source sends no blob again, a refused blob leaves no manifest,
  and a tag a registry refuses sends nothing; a property that any archive's manifest and the reference a pod is given name it
  by exactly its digest and size; the address a pod reaches the registry by, and that the orchestrator is told it.
  O3b DONE 2026-11-08: `archive::archive` reads a commit's tree from a repository and writes it as a gzipped tar, at most its
  bound, refused as it is written past it, so an archive past it is never held whole. Deterministic: entries in the tree's own
  order (git keeps a tree sorted), the commit's time on every entry, owner 0, git's modes (0644, 0755, a link), a gzip header
  with no time or name. What the fetch would refuse is refused here first, so a build fails at its source with the reason and
  not in its pod: a name that is not one (empty, `.`, `..`, a `/` or a NUL in it) and a link that is absolute or leaves the
  tree (the fetch's own rule). A submodule is not in the archive: its source is another repository's. The orchestrator has
  `git2` for this, reading the clone the handler brought up to date and nothing more: its `clippy.toml` forbids a fetch, a
  connection, a clone or a push of its own, as the git observer's does, and `domain_has_no_way_out` says so of it. Tested
  against real repositories: a property that any tree's archive is the same bytes from a repository that built it in another
  order, and again, and that the fetch's own `unpack` gives back exactly its files, contents, executable bits and links;
  a property that an archive is taken at its bound and refused one byte under it; links that leave refused and one that
  climbs and stays taken; `.` and `..` refused, written as raw tree bytes since libgit2's builders refuse them; a submodule
  left out; an unknown commit, or a name that is not one, no commit.
  O3c DONE 2026-11-08: `source::GitSource` takes `NotYet`'s place. It fetches a build's commit through the git handler, with
  `git.fetch` (the credential the mapping names, bound to its host) or `git.fetch-public` (none), into the repository's clone
  in `POLAR_ORCHESTRATOR_CLONES` (named by the digest of its URL, so no URL makes a path of its own), one fetch of a repository
  at a time since two builds of it share the clone; reads the archive from that clone in the fetch's `read`, at the build's
  bound (`POLAR_ORCHESTRATOR_MAX_SOURCE_BYTES`, Dynamic, 256 MiB; Polar's own tree is about 6 MB gzipped); pushes it (`push`);
  and gives the build the archive by its digest at the registry, marked plain http when the registry is. The fetch is then
  told so (`CYCLOPS_REGISTRY_INSECURE=true`), the one thing beyond its blob and digest `departures` lets it be told, so whether
  the registry is plain http is said once, by the orchestrator's own registry setting: the open "fetch's registry" item, closed.
  The escrowed `credentials` section is the builder's shared shape (`credentials.rs`), and with it the orchestrator needs
  `encryption`. The catalog gives it the clones' directory on the `working-checkout` volume, an emptyDir as the git observer's,
  since a clone can be fetched again. Decided by standing rules, for review: a mapping names one `credential`, as the git
  controller's repository entry does, in place of Vaughn's list of credentials "a build may be given": no credential reaches a
  build's pod (decision 1), so the fetch is all a mapping names one for (nothing has been signed for the section yet). Tested
  through the real protocols, a stand-in git server and the stand-in registry (`tests/common`): a commit fetched, archived to
  exactly the bytes the origin's own commit archives to, pushed, and given to the build by that digest at the registry, the
  fetch told it is plain http; a commit the repository lacks, or a source past its bound, pushes nothing; two builds of one
  repository at once each get it; a mapping naming a credential the agent does not hold is not fetched without it; only a git
  repository's source is fetched. And: the mapping's credential and the build's bound reach the source step, and an adopted
  build's source is not prepared again (the build's actor); a Job's fetch told the registry is plain http departs from its
  template nowhere, in the departures property too; the agent's two fetches and its needs; the catalog's clones and volume.
  O3d DONE 2026-11-08, live on u7c (9bf8e0f6): the maintainer signed and pushed a `mappings` section (version 1) mapping
  `https://github.com/octocat/Hello-World` to `polar-nu-init` from u7c's registry, pinned by digest, and the git controller's
  `repositories` section naming the same repository. The observer reported its default branch; the orchestrator fetched the
  commit from github.com (`git.fetch-public`), archived it, pushed the archive, the empty config and the manifest to the registry
  in the cluster (seven `registry.source.push` requests: HEAD, POST, PUT for each blob, and the manifest), read the template, made
  the Job, polled it to its end (complete in 6 s), read its pod's log (no report in it) and said it succeeded, 10 s in all, every
  request judged and allowed. The pod's fetch pulled the archive by its digest over plain http and unpacked it ("the source is in
  the workspace"), and the pipeline printed the repository's README. Found for the watched build: a build pod lives seconds, so
  `kubectl logs -f` started before it, or without `--all-containers`, misses it; the fetch says one line and the orchestrator's
  log is a build's fuller record. O3 DONE.
- **Found 2026-11-08, planning the watched build, to fix before it** (the maintainer: "This must be fixed first"; "Deps first,
  then network"):
  - *A build's dependencies would come from outside the record.* Decision 1 brings the source by digest, its origin never
    reached by the pod; but `cargo build` in the pod would fetch every crate it locks from crates.io, foreign code choosing what to
    fetch, nothing judged or recorded. Decision 1 holds for dependencies too: the orchestrator fetches each through its handlers,
    checked against the digest the lock file pins, and the pod builds offline. Polar's own `Cargo.lock`: 863 packages, 773 from
    crates.io each pinned by sha256, 10 git dependencies from five repositories each pinned by a commit, the rest the workspace's;
    about 174 MB of crates.
  - *A build pod can reach anything.* No NetworkPolicy covers `polar-builds`, and u7c's network plugin enforces none
    (`cert-issuer-isolation.md`, "Does the dev cluster enforce NetworkPolicy? No"): a pod running foreign code reaches the
    internet, Cassini, Neo4j, cert-issuer and the registry, which takes pushes from any pod without a login. Polar's own pods pin
    their images by digest (`tag@sha256:`), so a pushed tag replaces none of them; what a push could do is fill the registry or
    mislead what reads a tag. To be closed as `cert-issuer-isolation.md`'s layer 4 is designed: a deny-all egress policy for the
    build namespace (the fetch's way to the registry its one exception), a canary that proves the cluster enforces it, and the
    build namespace requiring enforcement, so the orchestrator runs no build where it is not proved: for pods that run foreign
    code the fallback is no builds, not open ones. A policy engine on u7c is the maintainer's to approve. A policy is the pod's,
    so its pipeline would still reach the registry its fetch needs; the registry refusing anonymous pushes is
    `registry-gate.md`'s ground, and until then that is the residual risk, recorded.
  - *Planned 2026-11-08* (the maintainer, "Yes, record it and start D1"), after nixpkgs' `importCargoLock`, the fetching done by
    the orchestrator through its handlers: **D1** the lock read into what it pins, anything unpinned refused at the build's
    source; **D2** the dependency step after the source: each crate's blob in `build-dependencies` is the very sha256 the lock
    pins, so it is fetched from crates.io (a declared HTTP operation at a configured host, no credential), checked and pushed
    once across every build and repository; each git dependency fetched at its commit through the git handler, archived as
    O3b archives, pushed; an index of them and a manifest by commit naming every blob (the "blob plus a manifest" rule); a
    Dynamic bound on their total; **D3** the fetch pulls the index and each dependency by its digest, unpacks the crates into a
    vendor directory with nixpkgs' `.cargo-checksum.json` (`{"files":{},"package":"<sha256>"}`) and the git dependencies beside
    them, and writes Cargo's source replacement into the build's own Cargo home, never the repository's `.cargo/config.toml`;
    `departures` lets it be told the index's digest; **D4** the pipeline offline (`CARGO_NET_OFFLINE`, `--frozen`), taking
    `CI_COMMIT_SHA` (the orchestrator says `CI_COMMIT_SHORT_SHA` today, which holds the whole commit) and its workspace without
    `.git`, and a Polar crate built live. Then the network: deny-all, the canary, no build where it is not enforced. Decided by
    standing rules, for review: a blob per crate, not the dependencies vendored into the source archive (evidence storage keeps
    bodies content-addressed, each once); git dependencies public for now (a private one fails at the source, with the reason);
    the pipeline image carries Polar's toolchain, since nothing downloads one offline (the dev image has it).
  - *D1 DONE 2026-11-08* (`lock.rs`): a lock is foreign input, so it is read as Cargo writes it and nothing else, by Polar's
    own reader rather than a general TOML parser: a `version` line, then `[[package]]` tables of `name`, `version`, `source`,
    `checksum` and `dependencies`, each a plain string (no escape, no control character) or a list of them one to a line, at
    most 16 MiB and 20,000 packages; anything else is refused by its line. A crates.io crate (the git index's name or the sparse
    one's) must be pinned by a sha256, a git source by a commit at an https address of a host (the git controller's own check);
    another registry or source is refused; a name or version that could not be a directory's is refused; the workspace's own
    packages are no dependency. Git packages are grouped by their source (with its query, which Cargo's source replacement is
    keyed by) and commit. Decided by standing rules, for review: the lock is read in the orchestrator's process and not in the
    locked-down worker, since it comes from the repository the signed mapping names, while reports come from code that ran.
    Tested: Polar's own lock read whole, every crates.io checksum in it and every git package; a property that any lock as
    Cargo writes one reads back as exactly what it pins, in any order of its packages; a property that any one of twelve
    spoilings is refused, saying where and never what (an unknown key, another registry, a git source with no commit or a commit
    that is not one, plain http, a login in the address, a name that leaves its directory, an escape, a `[metadata]` table, a
    carriage return, a list item not quoted, a list not closed); a crate with no sha256 refused; a lock past its bound unread.
  - *D2 in two*: D2a the crates; D2b the git dependencies, which locks a build reads, and the step wired in after the source.
    *D2a DONE 2026-11-08* (`deps.rs`): a build's crates in the registry in the cluster by the digests their lock pins. Each is
    asked of `build-dependencies` first (HEAD, which now says how large what it holds is: `push::held`), and only one it does
    not hold is downloaded, by name and version (`/crates/<name>/<name>-<version>.crate`), through `crates.download`, a declared
    HTTP operation at `POLAR_ORCHESTRATOR_CRATES` (a Static setting, `https://static.crates.io` unless the catalog names a
    mirror), with no credential; checked against the lock's sha256 and pushed, eight at a time. Then the index (each crate by
    name, version and sha256, each git dependency by its source, commit, packages and archive's digest; canonical, the same
    dependencies the same bytes in any order) and a manifest by the commit naming the index, every crate and every git
    dependency by digest and size, so the registry keeps them. Past `POLAR_ORCHESTRATOR_MAX_DEPENDENCY_BYTES` (Dynamic, 1 GiB)
    in all, the build's dependencies are refused. The push serves any repository now (`push::blob`, `push::put_manifest`).
    Tested through the real HTTP handler against a stand-in crates host and the stand-in registry (which now serves any
    repository, its manifests kept by repository and tag, and says a blob's length to a HEAD, as distribution does): crates
    downloaded, checked and kept by their lock digests, with the index and the manifest; a crate the registry holds not
    downloaded again; a crate that is not what the lock pins refused, naming it, nothing kept; a crate the host lacks named; a
    bound passed refused with no manifest; and a property that the index and manifest are the same bytes in any order and
    name the index, every crate and the git dependency once each.
    *D2b DONE 2026-11-08*: a mapping names its `locks`, the paths of the Cargo locks in its repository whose dependencies its
    builds are given (each of plain segments, none `.` or `..`, the last `Cargo.lock`; at most 16; left out, none, and a build
    has nothing but its source). Decided by standing rules, for review: the signed mapping says which locks, since a repository
    can hold several workspaces (Polar's own is `src/agents/Cargo.lock`) and a guess would decide what the build depends on.
    The source step reads them from the same commit's tree in the same fetch (a lock the commit lacks is named, and the build
    fails at its source), and depends on their union (`lock::union`: each crate once, each git source's packages together).
    Each git dependency is fetched at the commit it pins through `git.fetch-public` into a clone of its own, archived as a
    source is and pushed to `build-dependencies`; then `deps::store` brings the crates in and keeps all of it under the index
    and a manifest by the commit. The build's archive carries the index (`SourceArchive::with_dependencies`), for its fetch in
    D3. The source step is asked all of this at once (`source::How`: the credential, the locks, the bounds). Tested: a mapping's
    locks read and paths that leave the tree refused, in the mappings property too; a property that the union of locks is the
    same in any order, holds every part and nothing else; and through the real handlers, a stand-in git server, a git
    dependency served over TLS, the stand-in crates host and registry: a source's lock read from its commit, its crate kept by
    the lock's sha256, its git dependency archived at its commit, the index naming both, and the build given the index; no
    locks, no dependencies; a lock the commit lacks named; a bound passed refused.
  - *D3 planned 2026-11-08* (the maintainer, "Yes, record it and start"), on experiments with Cargo (in the scratchpad, Cargo
    1.101 nightly): a project builds offline (`--offline --frozen`) with a read-only Cargo home holding only its config and a
    read-only vendor directory whose crates carry nixpkgs' minimal `.cargo-checksum.json` (`{"files":{},"package":"<sha256>"}`),
    and Cargo refuses a vendored crate whose checksum is not its lock's. A git dependency is the hard part: one is often a member
    of its own workspace, its `Cargo.toml` inheriting from the workspace's (`version.workspace = true`), so vendoring it as a
    directory means rewriting a foreign `Cargo.toml` (nixpkgs does, with a script). Instead the git source is replaced by
    another git source, a local repository: Cargo builds from it, resolving the inheritance itself, and from a shallow bare
    repository holding the pinned commit alone (its pack, a ref, `shallow`). So no `Cargo.toml` is read or rewritten. The cost:
    Cargo counts even a `file://` checkout as network, so a build is `--locked` and not `--offline`, and what keeps the pod off
    the network is the network step after D4; source replacement only leaves Cargo no reason to go out, and a build script that
    downloads is stopped by nothing else. In three: D3a the orchestrator pushes a git dependency as that shallow repository (a
    pack of the commit, its tree and blobs, built with libgit2's pack builder, its index with libgit2's indexer, a ref and the
    `shallow` marker); D3b the template gains a `dependencies` volume shared by the fetch and the pipeline, and the pipeline
    `CARGO_HOME=/dependencies/cargo`; the fetch, told the index's digest (the one more thing `departures` lets it be told),
    pulls the index and each dependency by digest, unpacks each crate into `/dependencies/vendor/<name>-<version>` (refusing an
    entry outside it) with the checksum file, each git repository into `/dependencies/git/`, and writes Cargo's source
    replacement (crates.io by the vendor directory, each git source, keyed as the lock names it, by its repository); D3c an
    end-to-end test: a crate and a git dependency laid out as the pod lays them out, and the test's own `cargo build --locked` of
    a project that uses both.
    *D3a DONE 2026-11-08* (`shallow.rs`): a git dependency goes to the registry as a shallow bare repository of the commit its
    lock pins, a gzipped tar of `HEAD` naming `refs/heads/polar`, that ref, `shallow`, a `config`, and one pack of the commit,
    its tree and their blobs (libgit2's pack builder, one thread, `insert_commit`, which takes no parent) with the pack's index
    (libgit2's indexer, in a directory of the clone's own, removed after). The indexer is not asked to check connectivity, since
    a shallow pack lacks the commit's parents as it should; each object is still checked against its id as it is indexed.
    Deterministic, every entry with the commit's time and owner 0. The dependency's media type is now
    `application/vnd.polar.git-repository.v1.tar+gzip`. Tested from a real repository of two commits: it opens as a bare,
    shallow repository whose ref and `HEAD` are the commit, which it holds with its whole tree, and the parent is not there;
    made twice it is the same bytes; past its bound, or for a commit the repository lacks, refused, the clone left as it was;
    and the source step's test now finds the dependency as that repository.
    *D3b DONE 2026-11-08*: the build workload's template gains a `dependencies` emptyDir (`build.nuon`, `dependencies:
    "/dependencies"`, through resolve to `pod-template.dhall`), mounted in the fetch, which is told it
    (`CYCLOPS_DEPENDENCY_ROOT`), and in the pipeline, whose `CARGO_HOME` is `/dependencies/cargo`, the one thing of Polar's
    the pipeline is told; Cargo checks a git dependency out there, so it is written by both. The orchestrator tells the fetch
    the index (`CYCLOPS_DEPENDENCIES`, emitted by `SourceArchive::fetch_env` when the source has dependencies), and
    `departures` lets the fetch be told it only pinned by a digest. The fetch (`build-fetch`, `dependencies::lay_out`) reads
    the index by its digest, and holds every value in it to what it may be before it becomes a path or a line of TOML: a crate's
    name and version as the lock reader holds them, a sha256 that is one, a git dependency pinned by its digest and to a commit,
    its source an https address with no login and a query of one `branch`, `tag` or `rev` at most, agreeing with its address.
    Each crate is fetched by its digest and unpacked under `vendor/<name>-<version>/` and nowhere else (`unpack_under`: every
    entry, and whatever a link in it names, inside that one directory, so a crate reaches no other beside it), with nixpkgs'
    `.cargo-checksum.json`; each git dependency into `git/<n>.git`; then `cargo/config.toml` replaces crates.io by the vendor
    directory and each git source, keyed as the lock names it, by its repository. With no index the configuration alone is
    written, crates.io replaced by an empty vendor directory: a build given no dependencies has none to reach. Tested: a
    crate and a git dependency laid out from a stand-in registry, the checksum file and the configuration as Cargo reads
    them; no index, no dependencies; a crate reaching past its own directory refused, nothing of it beside; nine things an
    index may not say refused; an index that is not its digest refused; the Job told the index, departing nowhere, in the
    departures property too; the template rendered with the volume, mounts and settings, and its test pinned to that shape.
    *D3c DONE 2026-11-08* (`tests/cargo.rs`): end to end, what the orchestrator makes of a build's dependencies (a crate by
    the digest its lock pins; a git dependency, a member of its own workspace whose `Cargo.toml` inherits its version and
    edition, as a shallow repository of its commit, `shallow.rs`; the index of both, `deps::index`), served by the stand-in
    registry by digest (which now gives a blob to a GET, as distribution does), laid out by the fetch's own `lay_out`, and the
    test's own Cargo building a project that depends on both, `--locked`, with the Cargo home the fetch wrote; the built program
    prints what the two dependencies give. The git source names a host under `.invalid`, so a build that reached for it would
    have failed: Cargo built from what was laid out and nothing else. D3 DONE.
  - *D4 planned 2026-11-08* (the maintainer chose the source, "Public ace-tops"). The pipeline image is Polar's CI image
    (`polar-ci`, `src/flake/ci-container.nix`: nightly Rust, nu, cargo-cyclonedx, cargo-deny), not the dev image. Found reading
    it: the image points `CARGO_TARGET_DIR` (`/var/cache/cargo-target`) and `HOME` (`/root`) at its root, which a build pod
    mounts read-only and runs as the template's user; `scripts/pipeline/core/cargo.nu` asks git where the workspace is, and an
    archive has no `.git`; the orchestrator says `CI_COMMIT_SHORT_SHA` (holding the whole commit) where `ci.nu` reads
    `CI_COMMIT_SHA`; `ci.nu` already builds `--locked` (D3: not `--offline`, which refuses a `file://` git source). Found, for
    later: cargo-deny downloads its advisory database, another input from outside the record; the watched build skips the scan
    (`--skip-audit`), and the database is to be fetched by the orchestrator by digest as the crates are. In two: **D4a** the
    orchestrator says `CI_COMMIT_SHA`; `workspace-root` finds the workspace from where the script itself sits, not from git (the
    script lives in the repository it builds); the template gives the pipeline `CARGO_TARGET_DIR` and `HOME` where it may write;
    `polar-ci` a row in `images.nuon`; rehearsed locally, the real `ci.nu` in `polar-ci` under podman with no network, a
    read-only root and a non-root user, before it runs live. **D4b** live on u7c: `polar-ci` in its registry, pinned by
    digest; main pushed to the public `cmu-sei/ace-tops` and the git controller's `repositories` section and the orchestrator's
    `mappings` naming it (`locks: ["src/agents/Cargo.lock"]`, the command `nu scripts/pipeline/ci.nu $(POLAR_BUILD_ID) --package
    logger --skip-analysis --skip-audit --skip-images --skip-upload`, Kubernetes filling in the build's id so its reports carry
    the orchestrator's own), signed by the maintainer; the build watched through tails of the orchestrator, the build pod,
    build-processor, Cassini and the registry. Decided by standing rules, for review: `logger` as the crate (the smallest agent);
    the target directory and home are the template's, beside `CARGO_HOME`, since where a build may write is the pod's fact.
    *D4a DONE 2026-11-08*: the orchestrator says `CI_COMMIT_SHA`; `workspace-root` finds the workspace three up from its own
    file (`path self`), and `source-commit` takes the orchestrator's commit and asks git only when none is named (nu's
    `default (…)` runs its argument even when the value is there, so `ci.nu` asked git anyway); the template gives the pipeline
    `CARGO_TARGET_DIR=/workspace/.build/target` and `HOME=/workspace/.build/home`; `polar-ci` has its row. Rehearsed: `ci.nu
    <id> --package logger --skip-analysis --skip-audit --skip-images --skip-upload` in `polar-ci` (1.4 GB compressed) under
    podman with no network, a read-only root, uid 1000, every capability dropped, 2 CPUs and 4 GiB, a 256 MiB `/tmp`, and Polar's
    dependencies vendored into a Cargo home of their own: an SBOM for each of the 80 workspace packages, `event-logger` built
    `--release --locked` in about two minutes from cold, 559 MB written to `.build`. Two faults found there and fixed, both older
    than the orchestrator: (1) `emit-binary-linked` declared its record with `binding_digest: null`, and nu keeps that type, so
    the digest put there later was refused and every binary's link was lost; the record is built whole now. (2) A report on
    stdout was spoiled by a log line on stderr landing inside it (1 of 162, an SBOM report of 131 KB; 57 of them pass 64 KiB):
    the runtime reads a container's two streams apart, in pieces, and its log splices them, a piece of one between pieces of
    the other, as Kubernetes' does (16 KiB records, each stream's in order). So the pipeline's log lines go to stdout with its
    reports (`core/logging.nu`, no longer `std/log`, which writes only to stderr): nu is the one writer of stdout, and each
    line arrives whole; five rehearsals since, every report read. Found, for later: a subprocess's stderr (Cargo's warnings) is
    still a second stream, so a line of it left partial as a report is read could spoil that report; the reader refuses and
    counts it. Reading stdout alone (Kubernetes' split log streams, alpha) would close it. Tested: nu tests for the workspace
    and commit found with no `.git` and no git, a binary's link with and without its digest, and every log level on stdout and
    none on stderr; the template test pins the pipeline's three variables.
  - *Revised 2026-11-08, the source*: the maintainer, "Why are you pushing there? We are working on the private gitea." The
    watched build fetches Polar from the private gitea (`SEI/ACE`), not the public ace-tops (nothing was pushed there: the
    push was refused). No way reaches the gitea today: it serves plain http on a port only a tunnel reaches, and over ssh
    (port 22, open) Polar's git handler goes nowhere. Chosen, "Git over ssh in Polar", and for the gitea's want of a name,
    "IP allowed, key pinned". **E1** the git handler takes `ssh://host[:port]/path` (no login in it; the user name is the
    binding's), and a credential of a new kind, `SshKey`: an Ed25519 private key escrowed to the agent as a token is, its
    binding naming the user and the server's host key by its SHA-256 fingerprint. libgit2's `certificate_check` compares the
    key the server shows against that pin, and nothing is offered to another; an ssh fetch without such a credential is
    refused (no trust on first use), and so is one the egress settings would send through a proxy, since libgit2's proxy is
    http only. An `SshKey` binding may name an IP address, since its pin is the server's identity; a token or a password
    still goes only to a host name, which a certificate vouches for. **E2** the git agents read an ssh URL when a credential
    is named (`git/common/src/remote.rs`), and the controller's `repositories` and the orchestrator's `mappings` say so; the
    git dependencies a lock names stay https. **E3** live: a read-only deploy key on `SEI/ACE` (the maintainer's to add),
    sealed and signed into the credentials sections, and the mapping and repositories naming
    `ssh://52.235.181.217/SEI/ACE.git`; then the watched build. Decided by standing rules, for review: the pin in the
    signed credential, not a render-time known-hosts setting; tested against an ssh server in the test (`russh`, a
    dev-dependency) running `git upload-pack`.
    *E1 and E2 DONE 2026-11-08*. `polar-crypto/src/registry.rs`: `SecretKind::SshKey` (`ssh-key`) and
    `SecretBinding.host_key`, kept in the escrowed record only when there is one (a token's record is the bytes it was);
    `check` requires an ssh key's pin in `ssh-keygen -l`'s one canonical spelling and refuses a pin on any other kind, and an
    address as a token's or a password's host; an ssh key bound to an address is given for that address however it is written,
    to git only (`UseRefusal::NotForHttp`), with the user `git` unless named. The credentials section takes `kind: ssh-key`
    and `host_key`, judged by the registry's own `check`. The git handler (`protocol/git.rs`): an ssh address is a host name
    or a plain IPv4 address, no login, no escape, no IPv6 in brackets; libgit2's `certificate_check` compares the server's
    key with the pin and stops the fetch before anything is offered; the key goes to libssh2 from memory; an ssh fetch with
    no credential, with a token, or where the egress settings would send it through a proxy, is refused before it connects,
    and an ssh key never goes over https. `git/common/src/remote.rs`: `ssh_host`, and `repository_host(url, credential)`
    taking ssh only with a credential, which the controller's `repositories` and the orchestrator's `mappings` read with;
    `canonical_repository` reads ssh too. Found doing it: the egress settings' `proxy_for` matches http and https only, so an
    ssh fetch would have gone around a configured proxy without a word; it is refused instead. Tested: the registry's rules
    as examples and a property over bindings and hosts; the section's; the handler against an ssh server in the test (a
    fetch with the pinned key, twice, the key in no file of the clone; a server showing another host key offered nothing;
    no credential or a token not even connected to; an ssh key not sent over https; a proxy refused); a property that what
    the controller takes over ssh the handler judges for the same host. `russh` (ring) is a dev-dependency of the builder only,
    with 594 lines of `Cargo.lock`. The gitea's key as libssh2 sees it, probed with libgit2 (the server offers three; libssh2
    takes its Ed25519 one): `SHA256:YFLdJcQIVfrVsL4igdbFhIjYNMuGwNDejlBfkfBM5Lw`.
    *Found live 2026-11-08, and the shape reworked* (the maintainer, "Fix the shape first"): in the cluster the gitea showed
    its ECDSA key, and the Ed25519 pin refused it, nothing offered. The probe had run with a `known_hosts` that lists the
    host, and libgit2 asks libssh2 to prefer a type that file names; with none, as in a pod, libssh2's own order gives ECDSA
    (probed both ways). Which key a server shows is negotiated, so a pin of one is a guess about the negotiation: a binding
    now pins the server's keys, each by its fingerprint, separated by commas (at most 8), any one of which may be shown, and
    the refusal names the type and fingerprint it was shown (a host key is public). Found too: the deploy key was deleted
    once sealed, before a fetch had used it, and a sealed copy is bound to its section's version, so the next version needed a
    new key (what is replaced stays in place until the transition is tested). And the observer polled the
    dropped `ace-tops` entry for ten minutes after the repositories changed: by design, the controller's sets are incomplete
    during its warm-up after a start (`POLAR_GIT_CONTROLLER_WARMUP_SECS`, 600 s), and an incomplete set stops no worker.
    *Found live next, older than E* (since O2e): the gitea fetched over ssh, and no build came. The controller names a
    repository to the observer by its URL normalised (`RepoId::normalize_repo_url`: no `.git`, no trailing slash), and the
    mapping keyed on its URL as written, so `…/SEI/ACE.git` was waited for under an id no update ever carries, and every
    update was taken as unmapped, without a word. Hello-World's URL had no `.git`, which hid it. One function now gives the
    id both use (`git_agent_common::remote::repo_id_of`); a test builds from an update carrying the id the controller gives,
    for a mapping parsed as signed, where the old tests made both sides with the same raw call and agreed with each other.
    *Found live next, older than E* (since D2a): the build began (the source fetched from the gitea over ssh and pushed, the
    lock's five git dependencies fetched and pushed), and every crate was refused, "the variable it goes to is not set".
    A protocol handler read a configured location's variable as set (`Config::var`) and never its declared default, and the
    catalog does not set `POLAR_ORCHESTRATOR_CRATES`, whose default is `https://static.crates.io`; D2a's tests named the
    variable, which hid it. `polar_env::Config::resolved` gives what a declared variable resolves to (an override, its value,
    its default), as every read of the setting does, and the handler goes to that. Tested: `resolved` for each source and
    for one undeclared; the configuration handle read as a handler reads it.
  - *D4 and E3 DONE 2026-11-09: the watched build, live on u7c.* The observer fetched `main` of `SEI/ACE` from the private
    gitea over ssh with the deploy key (credentials version 2, pinning the gitea's three host keys; the cluster is shown
    its ECDSA one) and reported it; the orchestrator, by mappings version 3, fetched the same commit over ssh, archived and
    pushed the source, read `src/agents/Cargo.lock`, fetched the five git dependencies it pins (public, from github) as
    shallow repositories and the crates from `static.crates.io`, each checked against the lock and pushed to
    `build-dependencies` (816 crate downloads, every request judged and recorded), and made the Job. The fetch laid out
    the dependencies ("crates=816 git=5") and the source; the pipeline, in `polar-ci` pinned by digest, offline but for the
    registry, read-only root, uid 1000, made an SBOM of each of the 80 workspace packages and built `event-logger`
    `--release --locked` (133 s); the orchestrator read the pod's log once it ended, relayed its 162 reports
    (`relayed=162`), and the build succeeded, 194 s from the ref to the end. build-processor took them (SBOMs, artifacts,
    the binary's link), saying of three crates with no dependencies (`gitlab-common`, `openapi-common`, `polar-scudo`)
    that their SBOMs link flat. Found on the way, each fixed and recorded above: the pin of one host key; a mapping's
    repository id; a configured location's default. Found, for later: every bring-up rebuilds all 32 agent images (32 of
    41 pushed new each time, the 9 unchanged being mirrored or external), even for a change to one agent: the nix build
    seems to take the whole workspace as each agent's input, not its own closure (not yet read in `workspace.nix`); and
    superseded images, ReplicaSets and the like accumulate, now the Reaper's (`pod-reaper.md`, "Every kind of stale
    object"). And `str downcase` (deprecated in nu 0.114) printed a warning at the head of every build's log; it is `str
    lowercase` now. Next: the network step.
  - *The network step, planned 2026-11-09* (the maintainer: Canal on u7c, "I want it to work unprivileged, using
    nftables, and no requirement for ipv6"). Today a build pod reaches anything; u7c's CNI (`ptp`, `host-local`, `tuning`,
    `portmap`, `nix-usernetes/flake.nix`) enforces no NetworkPolicy and the API server accepts one silently
    (`cert-issuer-isolation.md`, "Does the dev cluster enforce NetworkPolicy? No."). The shape is that document's layer 4:
    the policy rendered, enforcement proved by a canary, and no builds where it is not proved. In three:
    **N1** the policy, rendered from the catalog for the build namespace: no ingress, and egress only to the registry's
    pods on its port. No DNS (decided by the trust model, for review): CoreDNS forwards upstream, which would be a way out
    for foreign code; the registry's Service gets a fixed cluster IP in its manifest (a deployment fact from the catalog),
    and the build template maps the registry's name to it (`hostAliases`), so nothing in the pod resolves a name. Recorded
    residual: a policy is the pod's, so the pipeline reaches the registry too, which takes pushes from anyone
    (`registry-gate.md`); image pulls are the kubelet's and unaffected.
    **N2** the canary, run by the orchestrator in the build namespace under the builds' own policy, not by the installer
    (Polar's own checks are the guard): a short Job of the fetch's image in a probe mode that must reach the registry (the
    pod's network works) and must fail to reach the Kubernetes API's service address and an address outside the cluster.
    Run when the orchestrator starts and before admitting a build when the last proof is older than a Dynamic bound; where
    enforcement is not proved, a build is refused at admission with the reason, and the result is published.
    **N3** enforcement on u7c, then live: Canal (Flannel for the pod network, VXLAN; Calico for policy, its nftables
    dataplane, GA since Calico 3.31, `nftablesMode: Enabled`), in `nix-usernetes`, rootless, IPv4 only (Felix's IPv6
    support off), with kube-proxy in nftables mode as it is. Unproven and so a spike first: Flannel's own nftables mode is
    still experimental, and nothing published says either way whether Canal runs in a user namespace; the host must have
    the modules a user namespace cannot load (`vxlan`; `nf_tables` is loaded already, since kube-proxy's nftables mode
    works in the node containers). Polar keeps to standard NetworkPolicy, so the policy and the canary carry to any
    enforcing cluster (Calico, Cilium, EKS's VPC CNI, kube-router in k3s, RKE2's Canal by default); the engine only has to
    make the canary pass. *Deferred 2026-11-09* (the maintainer, to finish Vaughn's port first): not in the way while the
    only code a build runs is Polar's own. **Until N1 to N3 are done, no mapping names a repository Polar does not
    control, and no registry archive is built:** a build pod reaches every service in the cluster and the internet, and a
    build is offline only because Cargo has no reason to go out, not because anything stops it. Decided while N1 was
    being read: the orchestrator resolves the registry's name itself when it makes a Job and gives the pod the address in
    `hostAliases`, in place of a fixed cluster IP on the registry's Service (which cannot be changed on a Service that
    exists, so every cluster would need its Service recreated).
- **O4** the one read after the pod ends: the log as a registry blob, its digest in the execution event (a wire change), and the reports
  in it judged by the O2d reader and relayed.
  *O4 DONE 2026-11-09* (the reports were relayed since O2d; this keeps the log). While the orchestrator reads the pod's log
  for its reports, it keeps the bytes, at most `POLAR_ORCHESTRATOR_MAX_LOG_BYTES` (Dynamic, 64 MiB; past it what came first,
  said to be cut), and pushes them by the "blob plus a manifest" rule as the source is: a blob in `build-logs` and a manifest
  tagged by the build's id (`logs.rs`, `RegistryLogs`, through the same declared push), so the registry's garbage collection
  keeps it and it is found by the build. `ExecutionCompleted` and `ExecutionFailed` carry `log: Option<BuildLog>` (digest,
  bytes, truncated) and `refused_reports`; a build that ended before its pod ran has neither, and a log the registry will
  not keep leaves the build as it ended, its log said to be none. build-processor writes them on the build's node
  (`log_digest`, `log_bytes`, `log_truncated`, `refused_reports`). A wire change: the orchestrator and build-processor are
  deployed together, and nothing holds the old form (Cassini keeps no messages), so it needs no migration; graphs gain
  properties. Tested: the log kept whole by its digest and said with its end and its refused reports; cut at its bound,
  the reports still read whole; a registry that will not keep it; a failed build's log, and none for one that never ran;
  the real keeper through the HTTP handler against the stand-in registry, and a refusal leaving no manifest; the
  projection's properties, and none of a log when none was kept. Seen live on u7c, 2026-11-09: build `616253d6` (`logger`, 151 s)
  relayed its 162 reports and kept its log, 8,292,177 bytes, not cut, as `sha256:eb904111…` in `build-logs` with its manifest
  by the build's id, and its node in the graph holds `log_digest`, `log_bytes`, `log_truncated` and `refused_reports` (0).
- **O5** absorbed (revised 3): a `build_id` is the orchestrator's, stamped on every report it relays (O2d3, O2e).
- **O6** live on u7c: a test repository built end to end, its build in the graph.

Open, to raise when its bite comes: the registry write (an operation on the registry handler, its grant); which event carries the log's
digest; the build Jobs' lifecycle (`lifecycle.md`: they are many short instances of one workload); reading whether a build is still
running from its pod's activity (`remaining-work.md`, B21's direction).

Found in O2a3b, for O2b and later:

- *The pipeline's UID.* The custody daemon serves the UIDs it is told (`POLAR_CUSTODY_WORKLOAD_UIDS`, 1000 in every pod), so a pipeline
  that a signed mapping runs as root, or as another UID, could not sign through it. Answered by revised 3: a build pod holds no
  identity, so a mapping may run its pipeline as any user.
- *The Job's name.* `job_name_for_build` names a Job `build-<id>`; the attestation agent takes a Job as `build-runner`'s only when it is
  named `build-runner-<id>` (7b). Renamed in O2c: `job_name_for_build(template, build_id)`.
- *The fetch's registry.* `CYCLOPS_REGISTRY_INSECURE` is not set in the template: whether the fetch reads Polar's registry over plain
  http is the cluster's fact, set with O3, where the archive is first pushed there.
- *Polar's identity containers and `restricted`.* `polar-init` sets neither `allowPrivilegeEscalation: false` nor a seccomp profile,
  nor does the custody daemon, in any Polar pod (`schema/functions.dhall`, `makePolarInitContainerWith`; `agent-pod.dhall`), and the
  agents' own containers neither (`Constants.DropAllCapSecurityContext`). Found by the build namespace's `restricted` warnings in
  O2a3b; since O2b a build pod has no identity containers and meets `restricted` in full. Polar-wide for the agents, not this bite's.
