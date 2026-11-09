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

# Remaining work

The single source of truth for what is left. Update it as items finish; do not rely on conversation memory.
Organized by theme; the themes, and the items within each, run in the order they matter, what blocks or risks users
first. Since 3.0.0 a breaking change carries a migration. Items that may no longer be wanted are marked
`(see "possibly obsolete")` and listed in the last section. Done items are in the docs and in git history.
Last updated: 2026-11-03.

## The order of work (the maintainer, 2026-11-02)

Each step is taken in bites, each reported before the next.

1. **Runtime attestation, slice A: the agent answering from what it sees** (`docs/architecture/runtime-attestation.md`). In progress.
2. ~~**Handing a cluster's deployment off to Polar's own git server.**~~ Done 2026-11-02 (`docs/architecture/cluster-bootstrap.md`), on u7s and u7c. The signed record of slice A travels this path.
3. **Runtime attestation, the rest of slices A and B:** ~~the signed record~~ (done 2026-11-02), ~~the askers~~ (done 2026-11-03: refusing is on, and the agent proves itself first), ~~watching~~ (done 2026-11-03: it reports altered pods and crashes, and nothing acts). Attesting what was signed unattested is optional, not planned (`runtime-attestation.md`, "Optional features").
4. **The protocol handlers, every service at once (the maintainer, 2026-11-03).** Below, under the builder; `docs/architecture/protocol-handlers.md`. DONE, in six bites, 2026-11-04: the framework, HTTP, the registry scheme, git and the Kubernetes API, five agents on them, and the old routes closed. GitLab and OpenAPI move at step 7, where `domain_has_no_way_out.rs` starts holding them as they reach the builder. Still not checked live: a credential presented over HTTP, Jira's or a registry's.
   Before what follows, so that the Dynamic settings build on it and the OpenAPI and GitLab agents migrate onto it, not twice.
5. **The sequence diagrams.** Below, under docs.
6. ~~**Every builder agent's non-secret settings Dynamic.**~~ Done, and checked live on u7s, 2026-11-05: `docs/architecture/dynamic-settings.md`.
7. **The two OpenAPI and two GitLab agents onto the builder and into the catalog.** Below, under the builder. OpenAPI done as a first cut, 2026-11-05: the first of the HTTP observers, on shared libraries, one workload per kind, with its processor driven by a signed Dhall mapping (`docs/architecture/http-observers.md`). GitLab moves to the builder on its own, without waiting for that engine. The maintainer, 2026-11-05: the generic HTTP architecture is settled first, so the agents rewritten onto it do not move again, by the evidence plan in `docs/architecture/http-observers.md`, "Evidence", in seven bites. Bite 1, the scaffold as the contract, built 2026-11-05. Bite 2, pure cores and engine properties, built 2026-11-05; it found Dhall evaluation exponential in nesting (open there). Bite 3, the test kit every kind takes (`polar-http-testkit`), built 2026-11-05. Bite 4, `polar-sign projection test` with signed evidence records in a new `polar-evidence` repository on the git server, built 2026-11-06. Bite 5, `polar-sign check`, the first invariants over one instance's signed facts, report only, built 2026-11-06; asking the running agents what is in force (`check --ask`) built the same day and checked live on u7c. Bite 6, version ranges and migrations as signed facts the agent and the check both hold to, built the same day.
8. **Runtime attestation, slice C.** It puts a builder actor in every agent, so it waits for step 7.
9. ~~**Merge Vaughn's work from GitHub's main; then build-processor and the build orchestrator, last.**~~ DONE 2026-11-09, as the port's six
   areas (below, under the builder, "Upstream's work, by Vaughn's port"): build-processor and the orchestrator as area 2, the operator's
   ideas taken into lifecycle as area 4. Left from it: our fixes from area 5's review, starting with kube-observer's role derived from what it
   declares.
10. **Lifecycle, after slice C** (the maintainer, 2026-11-09, "After slice C, sure"): `docs/architecture/lifecycle.md`'s order, the lifecycle
    document and its reader (where the Rust `polar` CLI starts), the agents deriving from it, then the catalog's split (where a downstream
    project's workloads get their layer), then the GitOps controller around phases. Where the port's area 5 lands in it: the review on
    Vaughn's branch, `docs/requests/public-polar-port-deployment-review.md` (`bdf2f096`).
11. **The polar package** (the maintainer, 2026-11-09; the plan, nothing built): a package manager's feel for building an agent and
    installing it into a Polar cluster, what Vaughn's `polar` CLI reached for.
    - Commands: `polar new|init` (a skeleton crate on `AgentBuilder` and its Nix package), `polar add <git>#<rev>` (fetch and build
      pinned source, flake-like), `polar check` (what the package still lacks against this cluster), `polar install` (a lifecycle move
      to under test), `polar promote` (the owner's signed move to deployed). Rust libraries, with `polar` as the binary.
    - Builder agents only; adapters later. The builder is the abstraction point (a Python builder is possible); a language without
      rkyv talks through the Cassini client on the domain socket. The scaffold is the package's contract, versioned and kept stable.
    - A package carries no deployment decisions: source at a rev, its build, the scaffold the build prints, its ELIDE intent and
      evidence. Pool, phase, runtime sections and secrets are the cluster's intent, the downstream layer of the catalog's split.
    - Offline first, then live. Offline, `check` reads a cluster profile (the capability vocabulary, services, pools, kinds, the
      platform version, the CA) signed at publish beside `deployment-record.json` with the pipeline's certificate; live adds what
      exists only after bring-up (`cluster_uid`).
    - Evidence is polar-eden's (`.elide.dhall` intent, signed records in `polar-evidence`, computed debt), agreed with polar-cc:
      promotion counts only records whose signer's certificate carries a new evidence capability (`c:record-evidence`: granted to
      admins, computed from the scaffold for collector workloads), not anyone the cluster CA issued; the author's records, under a CA
      the package brings, are shown beside the debt as claims and never meet a binding. Records name the rev and the source digest,
      not the image: `promote` rebuilds from the rev and checks the image's digest, only the cluster's under-test records name the
      image, a record made with changes beside its commit (`changed_beside_it`) is refused, and `promote` signs the debt's figures
      with the digests of the records they came from. The capability is main's (`polar-signing`, the capability list), the trust
      check in `polar-eden records` is polar-cc's.
    - Migration: records signed by admin certificates without the capability stop counting when the check lands (about 15 on u7c),
      until admins hold it and the collectors re-run; a customer cluster after 3.0.0 needs that in its migration notes.
    - Order: the cluster profile, `new`/`init`, `check` (useful before lifecycle, and what Blitz needs), then `add`, then `install` and
      `promote` after step 10's lifecycle and catalog split. Not yet placed in this order of work.

## Runtime attestation

- [ ] **Slices A and B** (the maintainer, 2026-11-02: "I want it done sooner than most of the work I asked you for"; the musl
  move, Scudo, the Cassini benchmarks and the custodian were its foundation). The plan is in `docs/architecture/runtime-attestation.md`,
  its open questions now answered there. Every target has the signed image lock it checks against, since `local` and `local-minimal` went (below).
  A pod is checked against its Deployment at issuance; the Deployments against a signed record that the scheduler observer delivers from the deployment repository (2026-11-02).
- [ ] **The escrow path's instance check has never run live** (found 2026-11-03). `agent_escrow_issuance.rs` runs only at a workload's first escrow certificate, and u7s and u7c already had theirs, so the shadow run asked nothing there. Only its unit test covers it. A clean install of the askers runs it; read its verdicts then.
- [ ] **A debugged pod crash-loops once refusing is on** (found 2026-11-03). `kubectl debug` marks a pod for good, so with refusing on it is refused at its next renewal and restarts in place until someone replaces it. Say so in the operator docs, and decide whether the Reaper replaces it. `runtime-attestation.md`, "What refusing will do to a debugged pod".
- [ ] **What the crash report cannot see** (found 2026-11-03, `runtime-attestation.md`, "Slice B"). A crash while the attestation agent is down is lost, since a pod's restart overwrites it within seconds. A Rust panic is not a signal, and ractor catches it, so it needs its own route. A Scudo abort reads as `SIGSEGV` from PID 1, and none has been seen for certain.
- [ ] **Slice C**, after the four agents migrate: the node sensor, the runtime challenges, the builder's seccomp and Landlock lock.
- [ ] **Hardening the binaries** (the maintainer, 2026-11-03: every security feature Rust allows in what ships). Flags and state in `runtime-attestation.md`, "Hardening the binaries". Needs no builder work, so it need not wait for slice C; none has been tried on the musl target, and each is measured in release. The maintainer's caution: crane and Nix's Rust builds may need settings we don't know, or cost us some of what they give, so rebuilding the standard library for CFI and setting C flags for musl and Scudo are the likely fights.
- [ ] **A Polar security dashboard** (the maintainer, 2026-11-03: wanted for a long time; infrastructure first). What slice B records is its beginning: pods that lapsed, crashes by signal, refusals. Not started, and nothing is to be built for it yet.
- [ ] **The main user application** (the maintainer, 2026-11-05: where this is headed; infrastructure now, and the command-line tools always first, since what they do informs its design). A dashboard that reads an agent's configuration, presents a form to edit it, and signs an update. Two halves like every other agent service: the observer authenticates users, takes requests and shares results (axum and dioxus, with a Rust and wasm dioxus client, which the browser loads as a static asset, then presenting the user's browser-loaded certificate); the other half holds the privilege. Groups say who may do what: `config-readers`, `config-writers`, `health-readers` (seeded, `dynamic-settings.md`). **Open:** a browser does not let page code use the private key behind a certificate it presents for TLS, so wasm cannot sign an update with that key, and how a person's signature gets made needs deciding before the form is designed. What the library lacks for it: `dynamic-settings.md`, "What a later service needs". Not started.
- [ ] **Version ranges and migrations for signed sections** (the maintainer, 2026-11-05; designed, not built: `docs/architecture/http-observers.md`, "Versions and migrations"). A range in a signed document's `target`; a migration file in `polar-schedules` bound by digest, applied by an administrator, with a signed applied record the agent waits for; a pre-flight check in `up.nu`. Also the customer's migration path, for what fits it.
- [ ] **A broker backpressure test fails under `RUST_LOG=trace`** (found by the agentic-control-plane session, 2026-11-06; to look at later, the maintainer). `a_processor_holding_back_its_own_topic_is_not_cut_for_acknowledgements_the_broker_has_not_read` fails at `cassini/broker/tests/backpressure.rs:1152`, "its connection is not ended": the broker cuts the connection. Twice on a clean ec7dc525 with `RUST_LOG=trace`; with it unset all 20 backpressure tests pass, three runs in three. Whether trace logging slows the broker's path enough to change what it does, or the test is too tight, is not known.
- [x] **A record under `migrations/` was never delivered, and the scheduler's watcher could fail silently** (fixed 2026-11-06, 896b8b63). `is_schedule_file` took only `permanent/`, `adhoc/` and `ephemeral/`, so no `migration-applied` record reached its agent; and the filesystem watcher ran in a thread that unwrapped its errors. Now each pull is followed by a rescan that publishes what changed, once (`tests/rescan.rs`). **Corrected the same day:** an earlier entry here said the scheduler did not deliver pushed documents. That was my reading of the agents' logs filtered with `grep -v tcp_client`, which hid the very lines (the configuration actor logs inside the transport's span); the documents were delivered and refused as they should be (`http-observers.md`, bite 6, "Checked live on u7c"). Still open and untested, as the agentic-control-plane session's mutation review found: the replay through the observer's supervisor (`handle` 4 survivors, `pre_start` 10); it worked live.
- [ ] **A third backpressure test fails on timing** (found 2026-11-06, GitLab G3's workspace run, 4,005 of 4,006). `a_client_that_publishes_and_subscribes_under_an_exhausted_budget_recovers` timed out in `wait_for` (`cassini/broker/tests/support/mod.rs:1111`) in the workspace run, and the backpressure suite alone failed one run in three, on another of its tests. The broker has not changed since bite 6's runs passed. With the two below, the backpressure tests' waits look tighter than a loaded machine allows; whether a wait is too short, or the broker slower than it should be under load, is not known.
- [ ] **A broker backpressure test failed once in a full workspace run** (found 2026-11-06, bite 6's run). `a_client_that_publishes_and_never_acknowledges_is_spared_once_and_then_ended`: once the broker's stop had returned, a session's actor (`<id>:loop`) was still registered (`cassini/broker/tests/support/mod.rs:633`). It passed alone three times in three and with its suite (20 of 20). A teardown that does not wait for every session's actor, seen under the load of the whole workspace; with the trace finding above, the backpressure tests are sensitive to timing. Not looked into yet.
- [ ] **For the customer's migration: the deployment record is schema 2 (breaking, 2026-11-07).** Each workload says `under_test`
  (`configurations-under-test.md`, CT2). An attestation agent from before reads only schema 1, so it refuses the first record published after the upgrade
  ("refused a deployment record") and answers as with no record until its own image is replaced, which the same publish does. The upgrade needs the render and the
  agents to go out together, as they do through Flux; a cluster that pins an older attestation image would not hold pods to the record.
- [ ] **For the customer's migration: the running-configuration answer changed (breaking, 2026-11-06).** It carries the agent's build and each section's document id and body digest, for `polar-sign check --ask` (`http-observers.md`, "Evidence"). An answer is rkyv, so `polar-running-config` (now a binary of `polar-sign`) reads only agents of its own build: upgrade the tool with the agents, and an older tool says it cannot read the answer.
- [ ] **Asking for an agent's health as a person** (found 2026-11-05). `health-readers` is seeded and grants nothing: the question topic is per agent, and Cedar names a topic exactly. Decide the shape (a shared topic, as the configuration question has?) before a tool or a rule.
- [ ] **An administrator's restart and quarantine of an agent** (the maintainer asked, 2026-11-05: should there be one, perhaps by revoking its certificate? Recommended, not decided or built). Revoking is the forceful route and needs nothing from the agent: the connection closes, its custody daemon destroys its keys, and it restarts, but the renewal rule then admits it again after five minutes (`sequences/general/revocation.mmd`), so revoking alone is a hard restart and not a quarantine. Quarantine also needs issuance refused: a policy that cuts it off, which `authority-model.md` allows on purpose, and that has not been tried. A graceful restart suits a signed command to a healthy agent, by the shutdown pipeline, where revoking would throw away work. Only the broker and custody daemons act on the revoked set, so a revoked workload keeps what the git server, cert-issuer and Neo4j accept until the certificate ends.

## The agent builder: tests its agent-wide rules lack

Found by the agentic-control-plane session's review of what the builder promises every agent built on it, handed over
2026-11-08; the maintainer: record now, work after the build orchestrator (O6), unless one blocks it. Each is a test, or a
gap, in `polar-agent-builder` or the crate named; one landing closes its rule for every agent at once, so each commit goes
back to that session (polar-cc), which re-runs its review. Its rule files and the evidence drafts are pre-release, named
only.

- [ ] **Timeouts and ending.** (1) No test of the Kubernetes call's timeout (`protocol/kubernetes.rs`, `REQUEST_TIMEOUT`),
  nor of the crypto and state replies'; git's (`protocol/git.rs`) and HTTP's (`protocol/http.rs`) are tested. (2) An agent's
  ending: no test that the reason is logged before exit 1, that a natural rejuvenation never exits 137, or that the
  termination message is written. (3) The shutdown watchdog: no test that each infrastructure stop step is bounded, or that
  the reason is logged before the watchdog's exit. (4) Hard deadlines: untested that the clock runs from start or disconnect
  to the next connect, that a reconnect resets it, that the actor judges nothing after its verdict, and that the verdict names
  the deadline. (5) Rejuvenation before expiry: untested that it waits while a dependency's certificate is unhealthy, its
  random jitter, and that the slowest rejuvenation gives its verdict before the floor. (6) Untested that the health actor ends
  the agent as its shortest-lived certificate nears expiry. (7) Restarts: no test that any exit code restarts, that no pod is
  left Failed, or that the termination message carries the last logs (likely the render's and Kubernetes', not the builder's).
- [ ] **Health.** (8) Each contradiction of the health settings alone (a deadline under 1 s, rejuvenation not above expiry,
  too small a window, probe staleness not above two ticks): tested only together, by example. (9) A hold: untested that it is
  logged at error, and the version range or migration it names is not asserted in the report. (10) A held agent: untested
  that it still rejuvenates, and that its domain stops retrying. (11) Nothing shows that no agent runs a heartbeat of its own
  (health is asked for). (12) Unhealthy until the first snapshot: no test, and perhaps no code; the bootstrap exemption
  untested too.
- [ ] **Configuration and environment.** (13) No test that a configuration problem's message gives the variable's purpose,
  or that a mistyped variable name is an error. (14) No test asserts history version 0 for an update refused before its
  payload is trusted (`configuration.rs`, recorded there). (15) Override, then environment, then default: tested only in
  `polar-env` (`config.rs`); no builder test sets an override and an environment value on one variable. (16) The environment
  after start: untested that later changes go unseen and that an undeclared read is refused (likely `polar-env`'s).
  (17) Facts computed once: only the floor and the topics are tested; not causes, groups, operations, graph labels,
  configuration requirements, the startup check or the shutdown budget. The `ProcessEnv` lint is opt-in, with about 90
  direct reads not yet moved. (18) The default trace filter, `warn` (`lib/src/logging.rs`, `DEFAULT_TRACE_FILTER`), is
  untested.
- [ ] **Authority.** (19) The pinned publisher: key pinning, the incident on a different key, and keeping the policy in force
  when a new one fails to load live in `credentials_agent_common::authority_leaf`, with no builder test; only a wrong
  publisher changing nothing is tested. (20) Degraded authority is not built: `POLAR_AUTHORITY_MAX_AGE_SECS` is in no code
  (already noted under the authority distribution: the 90-minute bound, the health failure naming its cause, a cache never
  persisted, the credentials agent's exemption).
- [ ] **Mutants that survived** (the builder's own run over `signed.rs`, `configuration.rs` and `policy_authority.rs`):
  `ConfigurationState::submit`, `>` to `>=`; `ConfigurationState::migration_applied`, the `!` deleted;
  `ConfigurationHandle::followed_by` always `Ok(())`; `Opened::payload`; the `Display` of `ConfigurationError` and
  `FollowError`. A test that kills each.
- Updates being all or nothing needs no new test: `polar-env` (`config.rs`) meets it; naming it is that session's.

## The Cassini broker and client

- [ ] FOUND 2026-11-01 (the sixth set, `broker-baseline.md`, "The sixth set: pressure"): a publisher's messages are
  delivered out of order after the broker spares its connection. Run 3 (six producers at 64 KiB into a sink 10 ms a
  delivery) delivered 18,366 of 60,000 after a later one of the same producer, none lost, none repeated; it alone had
  spared connections (each producer's `selftest.harness-producer` subscription, 30 s without progress, 21 times). A
  spared connection's publishes are refused for now (`PublishRefusal::Unavailable`, `cassini/broker/src/listener.rs:372`)
  and its client sends the message again while later ones go on: a mechanism read, not reproduced. Test first: a
  publisher refused for now mid-stream, then its order at the subscriber. Also to settle: why a producer's own selftest
  subscription stalls at all while it publishes.
- [~] DELIVERY IS BEST ATTEMPT (the maintainer, 2026-10-31): Polar does not guarantee delivery, but the broker and its
  clients must handle messages and acknowledgements correctly, with no stray resends from a lost acknowledgement. Every
  publish carries `MessageId { epoch, seq }` and every delivery a `delivery_id` and its `origin`
  (`cassini/types/src/lib.rs:110`), used today only to match acknowledgements; deduplication on them (reliability step 4)
  is NOT pursued until an issue is shown. Known path to a duplicate: an accepted publish whose acknowledgement is lost with
  its connection is sent again from the outbox after the next registration.
  - ACCEPTED LIMITATIONS of the best-effort broker (decided 2026-10-09: option A, nothing the broker holds is persisted), to revisit with a DURABLE BROKER (option C: a write-ahead log per topic and subscriber on a volume, replayed at boot, acked to the publisher only after the write) if a workload ever needs it. What a broker restart loses, pinned by tests in `cassini/broker/tests/restart.rs`: (1) messages queued for a topic that has no subscriber (the topic actor holds them in memory, for about three minutes at most anyway); (2) what was held for a disconnected session (the per-subscriber dead letters, up to R = 10 minutes), so a new session of the same identity inherits nothing after a restart; (3) deliveries in flight at the moment of the restart (not testable deterministically). Session metadata (registration ids, subscriptions) is lost too but costs nothing: clients register fresh and subscribe again within seconds. How often: the broker restarts about every 12 hours by design, because its server certificate lives 12 h (`server_lifetime` 43200) and its health actor rejuvenates when 300 s remain; any pod restart also does it. Why accepted for now: the current workloads are retried (request/reply callers time out and retry, polar-init retries) or re-observed (jira polls every 30 minutes; the kube observer was believed to resync after a reconnect, which is NOT verified). Revisit when: a Cassini topic carries an event that nobody retries and nobody re-observes (none is known), or the acknowledged outbox (redesign steps 2 to 5) is built and the remaining window is "accepted by the broker, not yet delivered". Option B (persist session metadata only) was judged worth nothing, and C subsumes it; option D (publisher keeps each message until the consumer acks) fits request/reply and not pub/sub. Open decision 2 of `docs/architecture/cassini-client-reliability.md` is closed by this. To verify when convenient: that the kube observer re-sends its state after a reconnect. MITIGATION RECORDED for the state-carrying case: the scheduler re-sends every agent its desired state periodically (the "SCHEDULER AGENT, reconciliation" item, under configuration), so a lost configuration message is repaired at the next interval
  - Cassini client reliability redesign (2026-10-08; design in `docs/architecture/cassini-client-reliability.md`, five diagrams): split `TcpClientActor` into a stable facade with a sequenced outbox and a disposable transport; a message leaves the outbox only when the broker acknowledges that exact message, so the protocol needs a message identity in the publish and its ack (today `PublishRequestAck` carries only the topic); at the first sign of trouble the outbox is written to a file and everything goes to it until the connection is back, then rehydrated and retransmitted in order; duplicates are removed by a per-sender epoch and sequence carried end to end. Open decisions in section 6 of the note (where duplicates are removed, where the file lives given that rejuvenation replaces the pod, broker persistence, bounds, receipts). Steps in section 7. Makes the domain supervisors' `InfrastructureRespawned` handling, the supervisor's `respawn_tcp_client` and the crypto actor's `ClientReplaced` unnecessary
    - Build steps 1b to 5 as in the note: 1b is the broker's dead-connection detection and a retention window of R = 10 minutes for a disconnected session; the acknowledged outbox with `(epoch, seq)` and per-message acks; the offline file; dedupe at the broker and at subscribers; the broker's per-subscriber outbox keyed by identity. Update 2026-10-09: step 1b is DONE (dead-connection detection in about a minute at both ends, retention window R = 10 minutes, goodbye ends a session, resume replays what was missed, supersede by identity, all measured or exercised on the cluster); steps 2 to 5 remain: the acknowledged outbox with `(epoch, seq)` and per-message acks, the offline file, dedupe at the broker and subscribers, and the broker's per-subscriber outbox keyed by identity
  - GAP (Cassini broker): no migration of a session's messages to its successor. The broker queues per topic, not per session, and the topic queue drops messages older than a hard-coded about three minutes (`QUEUE_STALE_AFTER_SECS` in `topic.rs`); a delivery already in flight to a session that died is lost. The intended behaviour (2026-10-08): messages held for a disconnected session go to a new session from the same actor identity, and expire after `R`. Design: a per-subscriber delivery outbox keyed by identity and subscription, with acknowledgements (section 5a of the reliability note). Update 2026-10-08: the migration by identity is done (supersede rule, `tests/supersede.rs`); what remains of this item is the delivery in flight when a connection dies (acknowledged deliveries, build steps 2 to 5 of the reliability design) and the topic queue's three minute staleness
  - The file-backed queue is build step 3 of that design: since 2026-10-09 `Queue` goes to the facade's bounded in-memory
    buffer (1000, oldest dropped), `Fail` and `Drop` are honoured from its online flag (`490d419c`), and what the old path
    wrote to `CASSINI_QUEUE_PATH` is not used by agents any more.
- [~] MULTI-INSTANCE WORKLOADS (asked by Blitz 2026-10-31; built 2026-11-01, `docs/architecture/authority-model.md`,
  "Multi-instance workloads", "As built"; in 3.0.0). Seen on u7c (broker-baseline.md, "The sixth set"): every harness
  producer pod its own session, none superseded. Left: a clean end closing its session at once; concurrent first escrow
  issuances of a multi-instance workload with `encryption` (none has one yet); Blitz's `build-job` workload (a reply to
  Blitz was drafted for the maintainer); the decisions marked for review in authority-model.md. Rotation on a
  compromise is key-rotation.md's.
  - MULTI-INSTANCE: WHAT LETS ONE CONSUME (later; `authority-model.md`, "Multi-instance workloads", "Later"): shared
    subscriptions (a "load balancer") and commands to one instance; the encryption model already fits them.
  - **Pods of one workload share an identity**, and the broker keeps one live session per identity (a new one supersedes
    the rest and closes their connections). *Since 2026-11-01* a multi-instance workload's pods are each a session (who a
    connection is: the pod in the certificate, `authority-model.md`, "Multi-instance workloads"); who gets a message is
    still open (the "load balancer", below). So a workload cannot run several pods at once, and the harness cannot measure
    several connections. Horizontal scaling is wanted (David, 2026-10-22), and needs two things, not one
    (`docs/architecture/cassini-broker.md`, "One session per identity, and fan-out"):
    - *Who a connection is:* a replica runs beside the others, a replacement takes over; the broker cannot tell them apart
      from the certificate today. Options: an identity per pod (a workload per pod, or a pod-instance name in the
      certificate), or sessions keyed by pod instance as well as identity.
    - *Who gets a message:* topics fan out to every subscriber, so replicas with identities of their own would each
      process every message. Scaling a consumer or processor needs consumer groups: replicas share a subscription and each
      message goes to one of them; ungrouped subscribers keep fan-out. The workload is the natural group, the pod its
      member; the supersede rule would then apply per member. Observers that scale out must split their source instead.
    - Cedar decides per workload either way (the replicas hold the same authority), so stage 5b and its cache do not
      depend on this. Not needed yet; decide before any workload runs more than one replica.
- [ ] THE BROKER, TO MEASURE NEXT (from the fifth and sixth sets, broker-baseline.md; on a quiet machine, release builds):
  - The tunables again, now that several publishers exercise the controller (`infra/load-plans/pressure.nuon`: the
    budget reached its 512 MiB ceiling in four of eight runs).
  - Where the new broker's CPU goes: 8-20% more per message saturated, up to 45% at set rates; -13% at 64 KiB.
  - Why latency at low rates improved: 64 KiB at 100/s has p50 0.54 ms against about 10 ms on S4m, which S4m carried
    since 2026-10-21. The maintainer: "astonishing ... on a case that wouldn't seem to have been about back-pressure at
    all. We should study this to understand why."
  - That u7c's nested rootless cgroup enforces the broker's 1 GiB `memory.max`, not only reports it (the controller
    read its ceiling from it, `Ceiling(Limit)`, 512 MiB).
- [ ] The broker at 256 connections at once (found 2026-10-27, by the storm bench, `cassini/broker/tests/storm.rs`):
  with key files and with the daemon alike, a p99 handshake of 1.0 to 1.1 s, a TCP connection retried after its SYN
  went unanswered, some rounds at 250 a second, the host's `somaxconn` and SYN backlog at 4,096. At 64 at once the p99
  is 3 to 31 ms. Look at the listener's accept loop and its backlog first (`cassini/broker/src/listener.rs`).
- [ ] **`backpressure`'s "a processor holding back its own topic is not cut for acknowledgements the broker has not read"
  has its connection ended** (seen once 2026-10-31, counted the same day; not fixed). "its connection is not ended
  (162 accepted, 0 deferred, 162 given back)", `slow_disconnections: 1`, the budget not exhausted
  (`tests/backpressure.rs:840`). It failed in the loaded workspace run, and side by side on main and with the three
  fixes of that day: alone, main 0 of 3 and fixed 2 of 3; under load (five copies, twelve busy loops) 0 of 15 each. So it is
  on main, and not made by those fixes (they touch registration, the custody report and another test). Its topic's
  stall rule should refuse the processor's publishes for now rather than end it (second review, finding A). To do:
  capture its debug log and find whether the verdict ends it before the reader's waiting reaches the session. Rerun 2026-10-31 on a quiet machine (load average 1 to 3,
  after the arm64 build): 10 of 10 alone and the whole binary 3 of 3 (17 tests each). It fails only at a load average of
  15 to 40, where the processor itself is starved of CPU and really does not acknowledge within `T_stall`; whether ending
  it then is wrong (a starved client looks stalled) or right is the open question, not a race seen on a quiet machine. "the budget was exhausted" (`tests/backpressure.rs:680`): the processor did
  not exhaust the budget within its 10 s. It fails the same on main (`e3d0a29e`, 2 of 3 runs alone with the load
  average 10 to 20 from another build), so it is not the names race. Once, with the names fix in (3 runs alone; not
  seen in main's 3), "a processor holding back its own topic is not cut for acknowledgements the broker has not read"
  had its connection ended (`backpressure.rs:802`), mid-test, where the fix (which acts only on a stop) does not
  reach. To do: find whether the 10 s is a debug-build budget or the publisher is starved.
- [ ] **The transport around a lost connection.**
  - The Cassini client's read loop goes on after a failed `read_exact`, reading from the middle of a frame
    (`cassini/client/src/lib.rs`, the read loop); it should end the transport.
  - The facade does not read its mailbox while a new transport comes up: `bring_up` awaits the new transport's
    `pre_start`, which retries the connection for about 9 s, so it cannot answer a `Disconnect` meanwhile (noted
    2026-10-09; the facade and `ReconnectMode`: `cassini-client-reliability.md`, `tests/restart.rs`).
- [ ] **The `cassini-client` CLI's rough edges** (found running Cassini on its own, 2026-10-28,
  `src/agents/cassini/broker/readme.md`, checked step by step; a person meets these first):
  - **A refused publish waits out its timeout** (also seen 2026-10-22 probing the sandbox's broker). The broker's refusal
    reaches the client at once and is logged ("The broker refused a publish on demo.other ..."), but `publish` goes on
    waiting for an acknowledgement and fails 10 s later with "Timed out waiting for publish ack". The refusal should end
    the command at once, with the refusal's reason as its error.
  - **Its results are log lines.** `Published to topic=...` and the topic and session lists are `info!` events, shown
    only with `CASSINI_LOG=info` (its console filter defaults to `warn`, `cassini-tracing`), so by default a successful
    command prints nothing. Results belong on stdout.
  - **It reads its log variables unlike every agent.** `cassini-tracing` filters the console with `CASSINI_LOG` and the
    exported traces with `RUST_LOG`, and exports to `localhost:4318` when `JAEGER_OTLP_ENDPOINT` is unset; the agents use
    `RUST_LOG` for the console, `POLAR_TRACE_FILTER` for traces, and export nothing without an endpoint
    (`lib/src/logging.rs`). Run without a collector, the client logs an export error.
  - **It does not subscribe**, so there is no tool to watch a topic; the tests and the in-cluster harness are the only
    subscribers.
- [ ] **Superseded sessions: what the takeover leaves** (the supersede rule itself: `cassini/broker/tests/supersede.rs`,
  `cassini-client-reliability.md`):
  - Supersede (broker): a superseded session is held until its subscribers confirm they hold (`SessionHeld`); if the subscriber manager never answers, the `held` entry stays not ready for ever (the expiry only drops ready ones) and the questions parked behind it are never answered. The caller times out, so nothing hangs, but the entry leaks. Give a not-ready entry the same expiry
  - Supersede (broker): a new session's subscribe waits on `GetHeldSessions` while a takeover for its identity is in progress, but the topic manager's `CreateSubscriber` call has a 200 ms timeout. A takeover that takes longer than that (a slow subscriber, many topics) makes the subscribe fail, and nothing retries it. Normally milliseconds. Either lengthen that timeout, or have the holder answer from what is ready and finish the rest later
  - Supersede (broker): a session with no verified identity (`peer_identity` is `None`, a certificate with no DNS name) is never superseded and never inherits. By design, but nothing logs it, and nothing refuses such a client
  - Known gaps of 2026-10-08: (b) between claiming and the new subscriber attaching to the topic a message can reach both,
    or neither if other subscribers exist, a window of milliseconds that dedupe (step 4) closes; (c) no limit on what a
    holder queues, like any dead-letter queue here.
- [ ] **A broker test that panics before its `broker.stop()` leaves its broker running,** and the next start's
  `clear_names` can then wait out its 5 s ("never became free"; seen once, 2026-10-31, after the names fix `92a76736`, which
  no doc holds; `cassini/broker/tests/support/mod.rs`). To do: stop the broker when a test panics, and have `clear_names`
  say which names it waited for.
- [ ] **The broker's exit code does not say why it ended:** `main` exits 2 whatever ended the broker, so an unhealthy verdict
  is not distinguishable from rejuvenation by exit code (left by the orderly shutdown of 2026-10-08; `tests/shutdown.rs`,
  `CASSINI_SHUTDOWN_BUDGET_SECS`, `health-and-shutdown.md`).
- [ ] **Two warnings at every broker start**, harmless: the supervisor's "Received unexpected message!
  SetTopicManagerRef" (`subscriber.rs:197`) and the topic manager's "PublishRequest missing reply_to" for the broker's
  own authority snapshot request (`topic.rs:772`).
- [ ] `cassini/broker/src/subscriber.rs`: `SubscriberManager.topic_mgr` is documented as "used to forward UnsubscribeRequest
  when a subscription ends, whether via explicit unsubscribe or the subscriber dying", but nothing reads it. Find
  whether that forwarding happens another way, or is missing; the field carries `#[allow(dead_code)]` until then.
- [ ] **Not seen on a cluster when last checked** (dev cluster `u7s`, 2026-10-08): the self-test's deaf path (no way found to
  make a consumer deaf on purpose; its healthy path ran for several minutes without a false alarm), the 60 s dead-peer
  detection, retention expiry after 10 minutes, the shutdown watchdog firing, a resumed session replaying what it missed.
  Step 1b of the reliability design records some of these as measured or exercised since (2026-10-09); which is not said.
- [ ] (see "possibly obsolete") **Cassini follow-ups from the migration (2026-10-09), what is left.** The rest is done and on
  the cluster (`infra/cassini-shutdown.nu`, `just cassini-shutdown [user]`, `tokens_match`; the dev constant `HEYTHERE` stays
  only in the local harness, `example.env` and the flake shell). Still open: (6) giving the broker the crypto actor and
  policy actors, which come through the builder as it grows them: a service has no client, and the crypto actor works
  through the client, so `ServiceBuilder` refuses it today. Options are in the conversation of 2026-10-09 and want a
  decision. Also noted: the broker now exports every span at the debug level to Jaeger (RUST_LOG unset gives the exporter a
  debug filter); watch Jaeger's load, and consider a default filter and a sampler.
- [ ] (see "possibly obsolete") Broker: after the orderly shutdown completes the process waits about 5 s more before exiting, because shutting down the tracer provider times out (`Error shutting down tracer provider: Timeout(5s)`, seen on the cluster). It fits the 20 s budget, but it is dead time on every restart and the watchdog does not cover it (it is stopped when the broker finishes). Bound or skip the tracing flush
- [ ] THE BROKER AS A USER OF SOFT STATE (agreed with the maintainer 2026-10-30). The broker's runtime budget
  controller (cassini-backpressure.md, "Runtime budget") exposes a typed snapshot and accepts a warm-start value
  (built in backpressure round 4). Next, after the StateActor and pulled health exist: the snapshot goes into the graph
  through pulled health (introspection), and the learned values (the last stable budget, the smoothed drain rate)
  through the StateActor (self-state), so a restarted broker starts warm instead of from the floor. The broker is not a
  Cassini client, so it would publish in-process into its own topics, stamped with its own identity; how the broker
  stamps its own `published_by` needs its own decision. The learned value is optional and late: the state agent needs
  the broker, so the broker never waits for it. This also closes the gap that the broker's health cannot be asked over
  Cassini. The bounds are then observable through the state agent and CONFIGURABLE BY SIGNED CONFIGURATION (the
  maintainer, 2026-10-30): the controller's tunables and cap are declared variables, changed by a signed configuration
  document (`c:update-configuration`, polar-schedules, the broker's own ConfigurationActor, reached by the same
  in-process path on `agent.cassini.configuration`); a one-off action (resetting what the controller learned) would be a
  signed command. The state agent's warm-start value is an unsigned hint adopted only inside the signed bounds; it can
  never widen one.
- [ ] BACKPRESSURE AS A POLAR CRATE (the maintainer, 2026-10-31: "back-pressure management is something other agents are
  probably going to want ... This is likely getting pulled out as a polar crate"). What would come out is what knows
  nothing of Cassini: the budget (reference-counted charges, the alarm and its hysteresis), the runtime controller
  (the ceiling from MemAvailable, the cgroup limit and PSI; the Little's-law target; additive growth and halving cuts;
  the floor; the typed snapshot and the warm-start input), the pure stall verdict (`pressure::verdict`), and on the client
  side the outbox as credit and `publish_when_ready`. Likely users: the processors (Cassini in, Neo4j out, so the
  drain rate is the graph's write throughput, and the gap waits unbounded today in their mailboxes and the graph
  controller's queue), git-repo-observer's batches, the credentials agent's ledger under bursts. Shape: a builder
  facility like the StateActor, a `PressureManager` under the InfrastructureSupervisor, its snapshot to health
  (introspection), its learned values to the StateActor (self-state), its tunables declared variables changed by signed
  configuration. Extract when a second user comes, not before; until then keep broker types out of the controller's and
  the budget's signatures (checked when backpressure merges) so that the move stays mechanical.

## Credentials, custody and the authority model

- [ ] ERROR PATHS TO EXERCISE ON PURPOSE (merged 2026-11-02): each is built and tested, and no run has triggered it, so
  each is forced on u7c, in a few minutes, with what should be seen:
  - **No schema yet** (soft-state.md, "Revised"; `ask_until_available`): scale soft-state-observer to 0, restart
    jira-observer, scale it back. Expect `Unavailable` retried every `POLAR_STATE_UNAVAILABLE_RETRY_SECS` (10 s), and
    the first issue pull at once after the schema arrives, not after Jira's backoff.
  - **A broker restarted during issuance, again and again** (core-restarts.md, "3 in detail", "One answer to a
    request"): restart Cassini several times while a pod is in polar-init. Expect issuance after each, never "too soon"
    for the same request (`cert-issuer/server/tests/broker_restarts_test.rs` does twelve).
  - **A retry after a lost reply** (deployments.md, "A retry is not a second request"): make polar-init's `Issue` reply
    time out (a 504 through the observer) or a custodian's reply never come. Expect the retry, the same CSR, admitted
    again within the renewal bound.
  - **An abandoned escrow certificate** (key-custody.md, "An escrow certificate asked again, or abandoned"): end the
    first pod of a new workload that encrypts right after its custodian is issued the escrow certificate, before it
    stores the key. Expect `BeingIssued` for others inside the custodian's window, then the next pod issued over it, the
    old one `Superseded` in the ledger.
  - **A multi-instance token with no pod name** (authority-model.md, "Multi-instance workloads"; `NoPodName`): take
    `instance_name_claim` out of cert-issuer's issuer, start a harness producer pod. Expect it refused, saying why,
    before cert-issuer is asked.
  - **A setting that cannot work, at start** (soft-state.md, "As built: pulled health"; `held::stay_up` and its
    `TryAgain`): render jira-observer with the placeholder `JIRA_URL` and start it. Expect it held as `Configuration` and
    up, no restart loop, `(:AgentHealth)` `unhealthy`; then a signed settings update with a working address starts its
    observers and releases the hold. (The run-time half was seen 2026-11-01: jira.md, "Seen on a cluster".)
- [ ] Credentials agent key custody (UPDATE 2026-10-28: every other agent's escrow key is in its custody daemon, part A of `key-custody.md`; this item, the credentials agent's own root key, is part B, still to do. 2026-10-07: PLANNED 2026-10-27: both keys into the custody daemon, `docs/architecture/key-custody.md`, "The escrow keys into the daemon" (for review). an init step loads the key, the workload only gets a handle, fall back to holding it only when the kernel cannot): `polar-init` gets a mode that mounts the key volume, generates the key if absent (`EscrowKeypair::load_or_generate` today runs in the workload), persists it, loads it and writes the handle, so the workload mounts no key volume (split it from the ledger volume in `credentials-agent-pvc`); a `CryptoActorLite` (probably in `polar-crypto`, sharing the kernel/in-memory decrypt dispatch) answers `DecryptOwnMessage` and the public key from the handle, and the seven handler actors that hold `Arc<EscrowKeypair>` ask it instead; the same actor is the sealed-config decryptor for the ConfigActor
- [ ] KEY ROTATION (direction decided by the maintainer 2026-11-01; `docs/architecture/key-rotation.md`): revocation records
  why (compromise vs an ordinary end), and only a compromise starts a rotation; a compromise is declared by the attestation
  agent or an administrator's signed command; rotation is a builder `RotationActor` over an agent's own declared encrypted
  stores (a `BackupActor` its sibling), observable through pulled health; the credentials agent's store is its first user;
  document-carried secrets are re-delivered by the credentials agent after a workload's key rotates, never rewritten. The
  design is to be written and cleared before building.
  DESIGN CLEARED 2026-11-01 (all twelve questions as recommended): a daemon `Rewrap`, the stores as their own progress, a
  signed `Keys { retiring, retired }` authority kind, wrapped keys shreddable outside the hash chain. Build after custody
  part B; the credentials agent's signing half is designed separately before first real use.
- [ ] **Whether an escrow certificate is renewed, and on what lifetime** (the maintainer, 2026-10-26: escrow certificates
  are meant to last a long time, so for now they get a lifetime of their own, `CERT_ISSUER_SERVICE_LIFETIME_SECS`, a year
  in the catalog and the chart, in place of `server_lifetime`; whether one is renewed, and on what lifetime, is revisited
  when revocation is built, which it now is: `key-custody.md`, "Step 5"). Done the same day (`2aafa380`). What stands: the
  consumer refuses a second escrow certificate for an identity while any record of one exists
  (`has_agent_escrow_certificate`, `credentials-agent/consume/src/state.rs:748`, a bare `contains_key`, not a validity
  check), so one is issued once and never again; the escrow key outlives the pod by design; read from the code, not yet
  seen to expire on a cluster. An escrow certificate already issued keeps its old form and lifetime until a fresh ledger
  (the form: `credentials-agent-architecture.md`, "Each certificate makes its own layer's decision"; `verify_escrow_certificate`).
- [ ] **The token's subject is still a key in two tables after the authority model** (found 2026-10-22;
  `docs/architecture/authority-model.md`, "Decisions": one identity). cert-issuer's floor
  (`cert-issuer/server/src/floor.rs:115`) and the credentials agent's grants for workloads
  (`credentials-agent/consume/src/issuance.rs:219`, "Two names for one credential") are keyed by
  `system:serviceaccount:<namespace>:<serviceaccount>`, where everything else is keyed by Polar's one identity, which is
  in hand at both (cert-issuer's `normalized_identity`). Key both by the identity, and convert the token's subject only
  where a token is read. The issuance floor's replacement is keyed this way: since slice 8 issuance asks the authority
  model by the identity (2026-10-22).
- [ ] Authority aging and forced catch-up, decided 2026-10-13 (`docs/architecture/authority-distribution.md`, "Aging, and being told to catch up"): the cache is ephemeral per pod; it expires after a maximum age (default 90 minutes, one and a half republish periods before that an agent asks for a snapshot) without hearing from the authority, and an expired agent fails its health check naming the cause, so the pod restarts into init; a signed revision notice (a sequence and a deadline) forces every agent to catch up or fail the same way; the credentials agent is exempt; an agent that has never verified a snapshot is not healthy. Nothing built.
  (`authority-distribution.md`, "As built", read 2026-10-21: `POLAR_AUTHORITY_MAX_AGE_SECS` and the revision notice are not built. The distribution itself, decided 2026-10-12, is built: the same doc.)
- [ ] (see "possibly obsolete") **The authority model** (`docs/architecture/authority-model.md`, proposed 2026-10-22, to cover with David after stage
  5b's slices 6 and 7): one model of the deployment as data, rules over it, and acceptance of a policy or groups
  document as a comparison over the closed catalog. It replaces slice 5's hand-written probes. Until it is built, a
  `forbid` on an authority path can lock a deployment out. **Being built** ("Build order, tests first"): slices 1 to 8 done by
  2026-10-22. Since slice 7 the credentials agent judges every `policy` and `groups` document before accepting it,
  so such a `forbid` is refused with its reason (open point B); since slice 8 a certificate carries what the model
  gives its workload, and the issuance floor is gone. Slices 9 (Cedar on the thirteen request topics) and 10 (deploy
  and verify) remain.
- [ ] **Admin `reissue` action:** revoke old cert, return account to pending with the same `account_id`, holder reruns `claim`
  (provisioning an existing username is refused today: `AccountAlreadyExists`). What waits on it: capabilities are fixed
  at issue, so an account made before a capability was granted cannot gain it (`alice` holds none of
  `c:update-configuration`, `c:run-command`, `c:update-policy`, `c:update-runtime`, `c:update-groups`; an account provisioned
  before 2026-10-27 has no `c:revoke`, `key-custody.md`) and needs another provisioned instead. Related: a fresh
  credentials-agent consumer refuses an admin action that carries a capability it has not heard of (`MalformedPayload`), so a
  CLI built from newer source than the deployed agent fails that way: redeploy first.
- [~] **Names, not UUIDs, as the identity people see** (wanted 2026-10-14). The git server's administrator list is keyed on
  the account UUID today (`POLAR_GIT_SERVER_ADMINS`, `targets/local-minimal/config.nuon`; a user's identity is a per-cluster
  UUID, the first DNS SAN, and it changes when the ledger is reset, so the catalog cannot name users). A durable answer is to
  authorise by permission SAN or capability (for example `c:grant`) rather than by uid (first found 2026-10-11).
  - Partly done 2026-10-14: the seed refusal now says the identity belongs to this cluster, to drop the previous cluster's
    value, and that running again restarts the git server by itself, which the ConfigMap restart made true. Not done:
    writing the list from the claim (`up.nu` knows it the moment the claim finishes), which waits on keying it by name.
- [ ] (see "possibly obsolete") **Arrival-time validators for policy invariants** (wanted 2026-10-14; candidates: the bootstrap
  identities can always be issued their own names; reserved core names only for their identity).
- [ ] **`NameTaken` tells a storer that the name exists,** which a retrieve never does (found 2026-10-12;
  `LedgerMessage::StoreSecret`). The other open point of that day, letting policy permit a store by someone else, is the
  Cedar `store` action decided 2026-10-14 (`credentials-policy.md`).
- [~] **The logging gaps** (mostly done 2026-10-08: the builder's subscription lines, one line per request received, the
  polar-init and observer request lines, the 60 s summary in `activity.rs`; `request_reply` and `relay`). Never log payloads,
  tokens, key material or decrypted secrets, only identifiers and outcomes. Left:
  - The consumer logs a request when it arrives but not its outcome (ok, refused with the reason, failed) or duration, nor
    the reply published: fifteen handler actors each build their own reply, so this wants one shared reply-publishing step
    like `request_reply` and `relay`. The periodic summary counts requests received, not handled or refused; the 60 s
    interval is a constant. The new log lines are not asserted by any test.
  - The credentials agent's consumer logs "no handler for topic" for admin-action and account requests it has just
    handed to their actors (found 2026-10-28, custody step 8): those two dispatch branches fall through to the warning,
    as before this work. Misleading only.
  - Broker: a session ended by a goodbye, or by retention, or superseded, is not logged at info with its reason (only "client went away, keeping its session" and the supersede are). On the cluster a goodbye had to be inferred from the absence of a "went away" line. Log `session ended: goodbye/retention/superseded` with the registration id
  - A record page taken is silent at INFO on both sides (`cert-issuer/server/src/supervisor.rs`, `RecordRequested`;
    `credentials-agent/consume/src/record_asker.rs`): an INFO line when a page brings certificates the ledger did not hold.
- [ ] **The custodian property reads the clock twice** (found 2026-10-31, not fixed). `credentials-agent/consume`'s
  "a custodian is answered only by the rule" (`src/custodian.rs:542`) failed once under load with `age_secs = 300`,
  exactly `CUSTODIAN_WINDOW_SECS`: its `record` stamps `now_millis() - age` and `judge` is given a later
  `now_millis()`, so at the boundary any millisecond between them closes the window, and the property's "refused as
  window closed only past the window" fails. To do: give `record` and `judge` one `now`.
- [ ] polar-init and the workload may no longer need one UID (found 2026-10-28): `infra/resolve.nu`'s `CUSTODY` gives
  them one "since the escrow key's hand-off through the user keyring needs it", and that hand-off is gone since custody
  step 9. Whether anything else needs it (the custody socket's group, the shared volumes' files) is to read before the
  security context changes; the comment is left as it is until then.
- [ ] The judge's summary ("N identities lose N uses of a topic, N gain N") counts requests too; say "uses of a topic or
  request", or count them apart.
- [ ] **What the credentials agent's migration did not exercise** (2026-10-06, both halves on the builder since; the circularity
  rules are built as the catalog's `escrow-exempt`): a drain with a request in flight and the `BrokerHandle` swap on a real
  TCP-client respawn (both unit-level only); the consumer's handling of requests arriving during the drain; the first request
  after a consumer start takes about 4 s and the next ones 44 ms (warm-up in the consumer, probably its first call to
  cert-issuer; cause unexamined); a `resolve.nu check` rule rejecting `encryption` together with the exception was planned and
  is not in `infra/rules.nu`.
- [ ] Decision to revisit: how the credentials-agent observer serves HTTP. Today: axum, with handlers outside the actor tree, so the TCP client is re-pointed through `BrokerHandle` and the server task checks a `stopping` flag and calls `exit(1)` itself if it dies unasked. Options: (a) keep axum and add a gateway actor that owns the broker client and reply routers, handlers shrink to `ractor::call!` (respawn becomes a message; one mailbox hop; the gateway must not await replies inside `handle()` or it serializes requests); (b) drop axum for `hyper` with a listener actor and one supervised connection actor per connection (shutdown becomes `stop_children_and_wait`, nothing outside the tree), at the cost of owning body-size limits, slow-client timeouts, content-type checks and malformed-request behaviour on the Credentials Agent's public front door, each needing tests. Needs are small (four POST routes), so (b) is feasible, but it is security-sensitive code. Not done as part of the migration; decide once both halves run on the builder
- [ ] Handler-level admin-action relay test in the observer (needs the `SignedAdminAction` struct)
- [ ] Rename `polar-admin-grant`
- [ ] (see "possibly obsolete") Cedar override-policy layer and the gitops policy path (proof of authorship for repo policies still open)
- [ ] (see "possibly obsolete") OCSP-style revocation-status topics (custom Cassini request/reply, ledger-backed)

## Security hardening

- [ ] **`polar-git-server`'s failure handling** (handed over 2026-11-06 by the agentic-control-plane session, at the maintainer's asking, from two read-only reviews,
  one guided by polar-eden's failure-mode catalogue; its write-up is in that branch's `docs/architecture/polar-eden.md`, "Failure modes"; the server has not changed
  on main since the commit they read, `fe2195a7`). Nothing fixed. "Checked" means that session read the code and it is as stated:
  - Checked, the most serious: `store.rs` create (~92-121) judges a repository to exist by its `HEAD`, and sets `receive.denyNonFastForwards` and
    `receive.denyDeletes` in separate steps after init. A step that fails, or a pod or client that goes in between (`run_git` has no `kill_on_drop`), leaves a repository
    every later create calls existing, without them: a writer could force-push or delete `main`, and in a signed repository move it back to an older commit the
    pipeline signed whose certificate is still valid, which Flux would roll back to.
  - Checked: the TLS serve loop (`tls.rs` ~169-206) has no handshake timeout, no header-read or idle timer and no connection cap: idle connections that never finish a
    handshake exhaust file descriptors while health stays green, and each shutdown waits the full drain.
  - Checked: `ClientIdentities` (`tls.rs` ~94-121) keeps only the deployment CA file's first certificate and prefixes `deployment:` only for leaves it signed directly,
    while the verifier trusts every certificate in the file and chains through intermediates: a leaf from a second certificate (a rotation bundle) or through an
    intermediate gets a plain name, so the deployment PKI could speak as a Polar identity. Latent while that PKI issues from one certificate.
  - Checked: a push is logged by re-reading each ref after `receive-pack` (`http.rs` ~273-291, `store.rs` `resolve_ref` ~154-167), not from git's report-status, so a
    concurrent push to the same ref goes unlogged or is credited to the other pusher, and an upper-case object id (`pktline.rs` `is_oid` ~105) may never be logged.
  - Checked: the handshake signs through the custody daemon synchronously inside `accept` on a runtime thread, a blocking round trip per ClientHello; it may apply to
    every `server_config` with a custody key.
  - Not re-read by that session: bodies of up to 256 MiB read whole and copied before `is_admin`, with no limit on concurrent requests; and, lesser, a push-log line or
    event lost on a crash, a 500 after 120 s though refs moved, `access.rs` writing without fsync, quarantine directories leaking and reused across restarts, `run_git`
    without a timeout, and signing-check errors logged as refusals.
- [ ] **polar-scheduler-observer's git calls have no time bound** (handed over 2026-11-08 by the agentic-control-plane session, found by its
  first rule-review run; its rule `limits calls-out-time-bounded` carries it as a gap, `rules/limits.rules.dhall` at `568f6ba4` there). `git_ops.rs`
  ~64-75 `run()` calls `Command::output()`, unbounded, for clone, fetch, pull and push; its callers await it through `spawn_blocking(...).await`
  with no `tokio::time::timeout` (`deployment_copy.rs` ~114-116 `copy_main`, `deployment_record.rs` ~117 `file_at_main`, `supervisor.rs` ~190
  `ensure_repo`), and no `http.lowSpeedLimit`/`lowSpeedTime` is set: a git server that accepts and never answers holds three actors in `handle`
  for good, their mailboxes unserved. A fix bounds each run (a child killed past a deadline, or `tokio::process` under a timeout), tested with a
  server that accepts and never answers: the call ends in error inside the bound and the actor goes on. Not scheduled.
- [ ] **The Kubernetes agents' failure handling** (handed over 2026-11-07 by the agentic-control-plane session, from four blind reviews, two unguided and
  two judging against the approved ELIDE rules; the count is how many found each; write-up in that branch's `docs/architecture/elide-intent.md`, "Tested
  blind, on Kubernetes", local at `3d84b4ee`; lines are main's as of `fe2195a7`, paths under `src/agents/`). Not fixed unless said; for the maintainer to
  schedule.
  - HIGH K1 [4]: one message the consumer cannot handle ends the agent: `kubernetes/consume/src/supervisor.rs` ~587-593 `deserialize_and_dispatch(...)?`
    returns from the root's handle any error of serde_json (~235), `from_value::<T>` (~207), `rkyv::from_bytes` (~264), the `todo!("Nodes")` panic (~247,
    K12, gone 2026-11-09 with area 3's bite C: nodes are projected) and the `?` on `emit_provenance_event` and `graph.cast` in `lib.rs`; what was in the mailbox was acknowledged and is lost. Triggers: a newer Flux
    adding a value to a closed kopium enum (`common/src/flux/kustomization.rs` ~582-588 `KustomizationSourceRefKind`, `oci_repositories.rs` ~182
    provider) crashes it on every status update of that object; resolver/consumer rkyv skew on `ProvenanceEvent` does the same. Log and skip the one message.
  - HIGH K18 [2]: that failure logs no reason: the root has no parent (`consume/src/agent.rs` ~96-101), ractor 0.15.13 does not log a handler error, and
    start says only "the kube-consumer supervisor stopped" (~105-118).
  - HIGH K5 [4]: a deletion in any gap is never recorded and the resource stays live in the graph: `observe/src/watches.rs` ~360 ignores Listing/Listed for
    every kind but Namespace though `polar-agent-builder/src/protocol/kubernetes.rs` ~98-108 defines Listed as "an object said before and not since has
    gone"; the handler ends the stream on every watcher error (~235) and relists after 5 s; the consumer has no sweep (`RESYNC_ACTIUON` unused); the module
    doc (`watches.rs` ~27-28) accepts the loss and no design doc does.
  - HIGH K14 [3]: a deleted namespace's pod, ReplicaSet and Job streams are dropped (`stop_namespace`, `watches.rs` ~332-336) before their pending Deleted
    events are read.
  - HIGH K19 [2]: pod env literals, args and command are written to Neo4j (`consume/src/lib.rs` ~805-809, PodContainer properties): a third-party pod's
    password in an env `value:` is stored in the graph, against the rule that the graph holds only non-sensitive facts.
  - HIGH K13 [1]: USES_IMAGE written to the tag's digest, not the kubelet's `image_id`. FIXED 2026-11-07 in `1f809267` (found independently, area 1
    above); "EnsureEdge also keeps both edges" is the old edges not being taken back, recorded there as a migration step.
  - MEDIUM K6 [4]: state nodes overwritten in place: Deployment keys on the newest condition's lastTransitionTime (`lib.rs` ~1111-1121, ~1144-1147),
    ReplicaSet with conditions (~1231), Kustomization Ready time (~1537), a running container's started_at (~468-473); `UpdateState` is MERGE then SET
    (`lib/src/graph/controller.rs` ~874-891), so a rollout or a 3→5 scale overwrites the earlier state's counts, against states.md §4.1.
  - MEDIUM K7 [4]: a new state for every observation: Pod (~589-593), Job with no completionTime (~356-366), ReplicaSet with no conditions (~1231-1240) and a
    Waiting container (~446-451) key on the consumer's `now_ms`; `ProjectionCache` is never used (`supervisor.rs` ~199 `_cache`); every relist or
    redelivery adds a state per pod, unbounded.
  - MEDIUM K16 [4]: `valid_from` mixes the consumer's clock with server and kubelet times, and the observer drops resourceVersion (`watches.rs` ~131): a
    Deleted can sort before the last live state, and an Applied redelivered after a Deleted looks like a resurrection.
  - MEDIUM K2 [2]: a failed graph write is dropped, not retried (`controller.rs` ~1262-1278; B2 of build-processor's, the same code).
  - MEDIUM K3 [4]: rejuvenation throws away acknowledged work: `supervisor.rs` ~578-585 drops every message for the 5 s window though the graph is
    healthy; DrainElapsed's `stop_and_wait` (~517-522) stops the controller ahead of its queued ops, where `drain_and_wait` would run them.
  - MEDIUM K4 [4]: no backpressure: deliveries are acknowledged at hand-off, each event is 10-50 `graph.cast` ops into an unbounded controller mailbox, and
    a slow Neo4j during a relist grows it until OOM.
  - MEDIUM K9 [2]: the Volume node is keyed on (namespace, volume name) (`lib.rs` ~621-624, ~835-838), but a volume name is local to its pod, so two pods
    sharing one share a node and each other's BACKED_BY secrets and PVCs.
  - MEDIUM K10 [4]: RECONCILED and DEPLOYED (`lib.rs` ~1422-1437, ~1599-1611) match Flux anchors by name and namespace, not uid, so a recreated object's
    old node gains the new edges; a MATCH on an OCIArtifact not yet written does nothing and is never retried.
  - MEDIUM K8 [3]: image discovery is published with `OfflineBehavior::Drop` (`lib/src/lib.rs` ~194, from `consume/src/lib.rs` ~904): offline or with the
    outbox full it is dropped silently, and a stable pod never gets USES_IMAGE.
  - LOW K20 [2]: a configuration answer in the watcher's start (`watches.rs` ~421-424, `follow_group` with `call_within(.., None)`) kills the observer root
    silently (`supervisor.rs` ~210-220 `?`); the wait is unbounded and blocks PrepareShutdown; `FollowError::Unreadable` is documented as "followed all
    the same".
  - LOW K21 [2]: the consumer ignores `published_by` (`supervisor.rs` ~577), the gap the docs already name.
  - LOW K24 [2]: a domain child's failure exits the process directly, past the health actor's verdict: `observe/src/supervisor.rs` ~438-450 `exit(1)`,
    `consume/src/supervisor.rs` ~553-556.
  - LOW K11 [2]: a stale Err from a dropped stream ends its replacement for the same key (`watches.rs` ~384-395, ~458-461) after a namespace is recreated.
  - LOW K15 [2]: Denied, NotYet and Backoff are retried on the 5 s "lost" timer (`watches.rs` ~390-393), ignoring the handler's wait: 4N+3 watches re-ask
    every 5 s.
  - LOW K17 [3]: the observer reports healthy while watching nothing (a 403 on namespaces is retried every 300 s with a warn).
  - LOW K22 [1]: the observer can respawn its watches during shutdown: a Registered queued after PrepareShutdown (`observe/src/supervisor.rs` ~195, ~207-222).
  - Unstated in the design: each event is many transactions, so a failure leaves a partial projection (`GraphOp::Transaction` exists); SessionEnded is
    ignored, with no resync for a temporal consumer; the signed waits have no upper bound.
- [ ] **build-processor's failure handling** (handed over 2026-11-07 by the agentic-control-plane session, from four blind reviews, two unguided and two guided,
  each fault with how many found it; write-up in that branch's `docs/architecture/polar-eden.md`, "The changed protocol, blind", local at `d2d4c5bf`; code there is
  main's as of `fe2195a7`). Nothing fixed. **Before fixing any: re-check against the upstream restructure.** Vaughn's `312d5dec` on github/main (2026-10-17,
  "revive cyclops ... restructure the build processor") deletes `linker.rs` and `projection.rs` for `src/project/{execution,findings,outputs,registry,mod}.rs`,
  reworks `supervisor.rs` and adds `tests/projection_neo4j.rs`; it is still a Job and not on the builder. So the linker and projection findings below are to be
  re-read against it when that merge happens, and none fixed in the old linker before it; the supervisor and Job ones (failed writes dropped, exit 0, drains,
  backpressure, `published_by`, refusals unlogged, the dead controller reference) likely stand until build-processor moves to the builder. One cause runs
  through several: the crate drops events trusting a replay to bring them back (`supervisor.rs` ~85-87;
  README, "the broker log is the source of truth"), and Cassini has no durable log and acknowledges on hand-off (`cassini-client-reliability.md` ~139-143), so every
  drop is for good.
  - HIGH [4], confirmed on main 2026-11-07: one bad message kills the linker, nothing restarts it, and health stays green. `linker.rs` ~855
    `serde_json::from_slice(&manifest_data)?` (and every `send_op` `?`, ~56-65) returns Err from `handle`, which stops the actor; `supervisor.rs` ~325-340 only logs
    ActorFailed unless it is the health actor (despite ~89-94), and ~421-427 then drops every later artifact event until the next re-registration, while the
    controller's 30 s canary keeps health green. Trigger: one OCIArtifactResolved whose manifest_data is not an OciManifest.
  - HIGH [4]: a failed graph write is dropped for good (`lib/src/graph/controller.rs` ~1262-1278 logs, sends OpFailed, drops; projection.rs and linker.rs cast and
    forget): a 90 s Neo4j restart loses every event in it, and ops that keep failing while `RETURN 1` succeeds never trip the deadline. HIGH [4]: a supervisor
    Err exits 0 (`main.rs` ~43; supervisor.rs ~181, 195, 209 spawn `?`, ~226 subscribe), and the Job (restartPolicy Never, completions 1, `processor.dhall` ~65,
    100-106) is Completed and never restarted, against `health-and-shutdown.md` ~59, "No agent ever exits with code 0".
  - MEDIUM: every drain, rejuvenation's too, loses events (supervisor.rs ~317-322, 333-338 await `send_after`; queued messages dropped while draining, ~232-238;
    ForceExit's `stop_and_wait` takes the stop before the queued ops, ~271-289, where `drain_and_wait` would run them; the BuildActor's and linker's mailboxes are
    never drained) [4]. BuildJobState is keyed on processing time, and started_at/completed_at are processing time (`projection.rs` ~49-52, 63, 102-105, 186-189,
    234-236, 255-258, 270-273, 321-324, 364-367): a redelivered ExecutionStarted after ExecutionCompleted, or a backward clock step, reads as running [4]. The edge
    timestamp is inside the MERGE pattern (linker.rs ~705, 748, 779, 807, `MERGE ...-[:REPORTED { at: $observed_at }]->`), so each repeat delivery mints another
    REPORTED, AFFECTS or CONCERNS edge, against `pipeline-design-reference.md` §5.5 (and §7 says fixed) [4]. SBOM components with no purl merge into one
    `Package{purl:""}` (linker.rs ~207-216; `scripts/pipeline/core/sbom.nu` ~333-342) [2]; plausibly the dependency tree is keyed on a bom-ref as if a purl
    (linker.rs ~233, 297-301; sbom.nu ~354) [2]; `SET p.license = row.license` with a null erases one another SBOM recorded (~211-215) [2]. No backpressure:
    acked on hand-off, unbounded mailboxes to a serial controller (supervisor.rs ~404, 425) [4]. `published_by` is ignored (supervisor.rs ~232), so any publisher
    allowed on `polar.provenance.events` or `.linker` sends any variant for any build_id, against "a request is judged by the broker-stamped identity" [2].
    Multi-op events are separate transactions (`GraphOp::Transaction` unused; projection.rs ~144-147 checks `BackendJobIdentity::new(..)?` after three ops were
    cast, leaving a BuildJob without its IS edge) [4]. The Artifact type edges point the wrong way (`(Artifact)-[:IS]->(x)`, linker.rs ~141-147, 363-369, 408,
    488-494, 631-637, 890-896, 1019-1025, against `pipeline-design-reference.md` ~123-125; registries CONTAIN the type node, ~897-903, 1027-1033) [2]. Plausibly
    MERGE races with no uniqueness constraint: the resolver publishes the same OCIArtifactResolved to kube-consumer and build-processor (`resolver.rs` ~148-164),
    both MERGE `OCIArtifact{digest}`, and the GitCommit stub (projection.rs ~123-134) races git-processor [2].
  - LOW: a backend identity with empty identity_props compiles to `MERGE (b:Label)` and matches every node of the label (projection.rs ~141-153, controller.rs
    ~622-626) [3]. SubscribeRefused and RegistrationRefused fall into `_ => {}` (supervisor.rs ~253) [3]. `in_artifact` is never read, so the FOUND_IN fallback
    (`pipeline-design-reference.md` ~197) is never written (linker.rs ~686-758, 763-817) [2]. Plausibly, after a re-registration respawns a dead graph controller,
    the BuildActor and linker keep the dead reference (supervisor.rs ~175-197; build.rs ~88-90, 165-167) while the new one keeps health green [3]. Latent:
    OCIArtifactCreated and ImageRefResolved go to the linker, which drops them (supervisor.rs ~415-417, linker.rs ~1145; README ~73 says handled) [3].
    ContainerImageCreated is keyed on `OCIArtifact{digest}` with the digest "" before a push (linker.rs ~569-571, events.rs ~326-328; `smoke-test.nu` ~114-123
    emits none), so those images merge into one node [2]. Unstated in the design: a build whose terminal event never arrives stays started for good [2]. Minor:
    supervisor.rs ~405 logs "linker" for the build handler; lib.rs has "polar.bullds.orchestrator".
  - Found later (2026-11-07, agentic-control-plane `3c8e74e1`, `elide-intent.md`, "Tested on the drafts"; on the pre-merge code, re-check at the merge like
    the rest). MEDIUM, plausible, disputed: the TcpClientActor's death is only logged (linked to the supervisor, `lib/src/cassini.rs` ~141-151; its
    ActorFailed or Terminated reaches `supervisor.rs` ~306-340, which logs it), so health never hears CassiniDisconnected and the agent stays healthy
    consuming nothing; earlier reviews held a TransportError sends CassiniDisconnected first and the Cassini deadline ends the agent, so whether an actor
    death without a TransportError can happen is worth one look. LOW, plausible: the dependency certificate check's endpoints are hard-coded
    (`supervisor.rs` ~113-118, Cassini's and the graph's host, namespace and port), so on a target laid out otherwise rejuvenation waits on one it cannot check.
- [ ] **The HTTP observer and processor's failure handling** (`polar-http-observer`, `polar-http-processor`, the protocol handler; handed over 2026-11-07 by the
  agentic-control-plane session, from two blind reviews, U without questions and G with the survey's; write-up in that branch's `docs/architecture/polar-eden.md`,
  "Scored blind on the HTTP observer and processor", local at `8ea36cac`; code there is main's as of `fe2195a7`). Nothing fixed.
  - HIGH, G, checked and reproduced there, and confirmed on main 2026-11-07: a remote host's `Retry-After` poisons the protocol handler for the whole agent.
    `polar-agent-builder/src/protocol.rs` ~608-612 inserts `Instant::now() + *wait` under the `not_before` lock, and `retry_after` (`protocol/http.rs` ~177-181)
    takes any u64 of seconds: `Retry-After: 18446744073709551615` overflows and panics with the guard held, poisoning the mutex, and `wait_for` (~381,
    `lock().unwrap()`) then panics on every request ("handler ended") until a restart, and again at the first read after. Every agent with the handler, not only
    the observer. Direction: cap the wait (a hint never widens a signed bound) and `checked_add`.
  - HIGH, U, checked: a failed publish is only logged and the source still reported healthy (`polar-http-observer/src/observer.rs` ~413-422; succeeded is marked
    before the publish, `observing.rs` ~228-236; PublishRefused and PublishDropped fall into `_ => {}`, observer.rs ~283): BufferFull on later pages drops them while
    health stays clear and the processor writes a partial set. (G held the next read republishes everything.)
  - MEDIUM: the observer's and processor's standing problems share the configuration actor's one `HoldReason::Configuration` slot (`problems.rs` ~124-129,
    `processing.rs` ~150-155, against `polar-health/src/machine.rs` ~393-412 and `polar-agent-builder/src/configuration.rs` ~458-466, 513-516, 606-613, 655-665), so
    each releases the other's hold and Reported dedup never sends it again; an observer hold overwrites the handler's Credentials hold. A host's wait is honoured
    with no ceiling and never reported (`observing.rs` ~98, ~106 `interval.max(*wait)`), stretching the signed interval without bound. A rate limit part-way
    through a paged read drops the rest and restarts from page 0, unreported (~98, 209-215, 241-245). A credential that arrives late or is replaced after a refusal
    waits for the next interval, up to 7 days (observer.rs ~246-257 never subscribes to `credentials_applied()`, as the jira and git observers do). A failed read of
    the section in force is never tried again (observer.rs ~289-299; processor `lib.rs` ~287-295, `processing.rs` ~128, which keeps "no projection is signed
    yet" and drops every document). Two section reads can race and install the older version (no version compared: observer.rs ~285-301, observing.rs ~175-183;
    processor lib.rs ~284-299, processing.rs ~122-125). Plausible: an older observation can overwrite a newer one (no `observed_at` comparison; `polar-projection`
    stamps unconditionally, lib.rs ~573-576). Nothing bounds concurrent fetches (observer.rs ~373-381, up to 500 at once) or what each holds (bodies buffered to
    256 MiB before the ~64 MiB check). Plausible: no backpressure toward the graph (processor lib.rs ~189-207, ~385, an unbounded mailbox to a serial controller).
  - LOW: 401 and 403 are Malformed, never CredentialRefused (observer.rs ~171-174), so a revoked token is presented on every read. The next page resolves against
    the requested URL, not the final one after redirects (observer.rs ~79-81, 109-111, 152-168; `paging.rs` ~212-217): an http-to-https redirect fails every read
    after page 0. Plausible: a Link header that is not visible ASCII is taken as the last page (observer.rs ~161, against ~150-151 and `http-observers.md` ~514).
    Observations that keep failing to decode are only warned of, with no hold (processor lib.rs ~205). The processor says the graph connected when the broker
    registers (lib.rs ~274-277; readiness only). Plausible: the processor's publisher check ignores the namespace (lib.rs ~150-152 via
    `cert-issuer/common/src/identity.rs` ~167-172).
- [ ] **Runtime attestation's failure handling** (`attestation-agent`, `attestation-common`; handed over 2026-11-07 by the agentic-control-plane session, from a blind
  review and three repeats; write-up in that branch's `docs/architecture/polar-eden.md`, "Scored blind on runtime attestation" and "Re-evaluated", local at
  `44bc51c8` and `e19f8fb2`; code there is main's as of `fe2195a7`). Nothing fixed.
  - HIGH, checked, confirmed on main 2026-11-07, latent in sandbox-local (its record names no Job): the self-check fails whenever a recorded Job's pod is held.
    `common/src/proof.rs` ~130 alters the owner to `{name}-altered`, which `verdict.rs` ~216-222 (`names_its_workload`) accepts for a Job by its `<record>-` prefix,
    so the altered pod is Genuine and `prove` returns CannotSayNo ("another owner", proof.rs ~214-226): CannotSay to every question, every certificate issued
    unattested, while any recorded Job's pods exist (Succeeded and Failed too). Reachable wherever `layers/3-workloads/agents/gitlab/{consumer,observer}.dhall` or
    `build-processor/processor.dhall` (Jobs) are deployed and recorded. `tests/props.rs` builds only Deployments. Direction: an alteration no prefix matches
    (`altered-{name}`), and a Job in the generator.
  - MEDIUM: "ready" is listed once with no failure, not up to date (`agent/src/holdings.rs` ~136-138, supervisor.rs ~76-82): a half-open watch (kube's ~295 s read
    timeout) freezes the holdings while ready, and a panicked watch task is drained by `try_join_next()` (`polar-agent-builder/src/protocol.rs` ~849-851) and never
    restarted (plausible). One watch that keeps failing (a missing Role, a 403 or 404 retried every 5 s as temporary, supervisor.rs ~228-236) switches off every
    verdict and every crash report (report() returns when not ready, ~129-131), against the design's "a crash is reported even while the agent doubts itself"
    (one reviewer held it fail-open by design). A StatefulSet pod of the old revision is judged against the current template (holdings.rs ~240-241, ~267, ~296),
    so a rolling update, OnDelete or a partition makes old pods AnotherImage; direction: judge by the pod's ControllerRevision. Plausible: the record's owner kind
    and name apply the moment it arrives, with no grace (supervisor.rs ~437-443, verdict.rs ~199-204), though record and Flux may be ten minutes apart: a rename or
    kind change refuses the old or the new pods AnotherOwner, and on the record's own delivery path may stick until a restart.
  - LOW-MEDIUM: an unchanged record stops verifying when the pipeline certificate expires (`agent/src/record.rs` ~42 verifies at now; `deploy-repo.nu`
    `next_record` re-signs only when the facts change; the certificate lasts 365 days, ~233): an ERROR every 30 s, and a restarted agent holds no record, so
    CannotSay to everything.
  - Found later (2026-11-07, reviews judging the code against drafted intent, agentic-control-plane `3c8e74e1`, `docs/architecture/elide-intent.md`, "Tested on
    the drafts"). LOW, confirmed by two: an unreadable deployment CA makes the agent crash-loop instead of holding (`agent/src/supervisor.rs` ~268-277 reads
    and parses it before `AgentBuilder::build()`, ~287-293, so `pre_start` fails, no health actor runs, the process exits 1 in a loop, naming the path);
    the drafted rules disagree on hold against crash-loop, so it is a decision for the maintainer. LOW, unstated in the design, one reviewer: the asker
    assumes the attestation agent runs in the asker's own namespace and domain (`common/src/asker.rs` ~78-81); anywhere else every answer is refused with
    a WARN and all issuance goes unattested.
  - LOW: a pod in a namespace not watched is answered NoSuchPod, not CannotSay (supervisor.rs ~76-82, verdict.rs ~143; record.rs ~88-92 drops the namespace; the
    drift path accounts for it, ~140). Plausible: a pod whose owner's watch lags is NoOwner (verdict.rs ~149, holdings.rs ~158); answers do not wait two checks as
    reports do. The drift grace runs on the wall clock (supervisor.rs ~238-243, ~404; record.rs ~230). A crash report whose publish failed is lost if the pod is
    gone by the next check (supervisor.rs ~152-161; `Reporting::check`, report.rs ~176), and offline, Queue requeues every standing report each minute until
    BufferFull refuses the newest, a new crash. Records are accepted on their version alone (record.rs ~370-376, supervisor.rs ~377-378; no content compare, no
    target check, ~343-357, common record.rs ~68-78): a recreated deploy repository at version 1 is refused as Older until a restart, and a higher version for
    another target under the same CA is taken. Latent until slice C: a DaemonSet pod is always NoOwner (holdings.rs ~245; OwnerKind has none, record.rs refuses
    one), so the planned node sensor would be refused on every node. Load-harness `--image-tag` runs are refused NotPinned (verdict.rs ~175-177 against
    `load-harness.nu` ~305-319), and a large run with no record can push the proof to CondemnsMost. Unstated in the design: during the agent's own rollout both
    instances answer and the first reply wins (asker.rs ~142-146), so an unproved instance's CannotSay can beat the old one's NotGenuine.
- [ ] **Soft state's failure handling** (`soft-state-common`, `-observer`, `-processor`; handed over 2026-11-07 by the agentic-control-plane session, from two
  blind failure-handling reviews; its write-up is that branch's `docs/architecture/polar-eden.md`, "Scored blind on soft state", local at `05c74ef7`; soft state
  there is main's as of `fe2195a7`). Nothing fixed. "Checked" or "confirmed", traced in the code; "plausible", the trigger not seen. 1-6 both reviewers found.
  - Checked, MEDIUM and HIGH once the Reaper reads it, confirmed on main 2026-11-07: the writer blames every workload for its own outage. `process/src/supervisor.rs`
    ~251-263 asks each workload with `OfflineBehavior::Drop` and opens the round whatever happened; a Drop publish while offline returns `Ok(())`
    (`lib/src/cassini.rs` ~341) and a full outbox drops one silently (~391-395); at close (`supervisor.rs` ~273-318, `classify.rs` ~84-87) every reachable workload
    with no answer is written Unresponsive. A 90 s drop of the writer's own session makes two false transitions per workload in a 20-slot history, pushing out
    real history. Direction: the writer knows whether its questions went out (Fail, not Drop, or no round while offline).
  - Confirmed, MEDIUM: reads that time out still run. `observe/src/query.rs` uses ractor `rpc::call`, and the graph controller is serial
    (`lib/src/graph/controller.rs` ~1294-1297), running every queued Query after its caller gave up: slow Max scans (`JiraIssue` `updated_ms`, no index) pile up, and
    the 30 s health tick queues behind them.
  - Confirmed, LOW-MEDIUM: timeouts inverted. The observer's graph timeout is 10 s (`observe/src/settings.rs` ~28-34), the asker's reply timeout 8 s
    (`polar-agent-builder/src/state.rs` ~53-56): "did not answer in time" is never heard, the StateActor's Unavailable retry (bfede9ef) never runs, and each ask
    leaves three scans running.
  - Confirmed, LOW-MEDIUM: a forward clock step freezes transition times (`process/src/history.rs` ~72-75 stamps `max(at_ms, last.at_ms)`): after a step later
    corrected, every transition carries the future time, persisted and reloaded at start (~53-59), disagreeing with `observed_at_ms`.
  - Confirmed, LOW: `(:AgentHealth)` of a workload dropped from `agents` is never removed or aged (only expected workloads are written, `supervisor.rs` ~273-318;
    nothing deletes); and a workload added or re-identified by an `agents` change while a round is open is recorded unresponsive (asked from expected at open,
    ~247; classified by expected at close, ~280-286, ~492).
  - Plausible, one reviewer each: a hung graph connection leaves the reader saying `graph_connected: true` (`observe/src/supervisor.rs` ~282-287 with
    `controller.rs` ~1272-1297: a failed or hung Query sends no health signal and the Tick queues behind it; turns on neo4rs read and pool timeouts, unchecked);
    the policy lookup has no timeout (`polar-agent-builder/src/authority.rs` ~395-406 `rpc::call(.., None)`, and `observe/src/supervisor.rs` ~349 spawns a task per
    request without limit; `publish_reply` uses `OfflineBehavior::Queue`, ~148, so replies buffered offline go after every asker has given up); a failed read of
    the runtime section is only logged (`observe/src/supervisor.rs` ~314, `process/src/supervisor.rs` ~444), and a replayed document of the same version is not
    announced again (`polar-agent-builder/src/configuration.rs` ~545), so the section stays stale until a newer one or a restart.
- [ ] **Key custody's failure handling** (`polar-custody`, `polar-custody-daemon`; handed over 2026-11-07 by the agentic-control-plane session, from a blind
  failure-handling review; its write-up is that branch's `docs/architecture/polar-eden.md`, "Scored blind on key custody", local at `eefd779c`; the custody code there is
  main's as of `fe2195a7`). The deadlock is fixed; the rest are not. "Checked" means that session traced it in the code; "plausible", that the trigger was not seen
  to happen.
  - *Fixed 2026-11-07*, checked, the most serious, and confirmed on main: the custodian deadlocked on its own lock. `daemon/src/bootstrap.rs` ~220-227 matches on
    `write(custody).workload_csr(..)` (and `escrow_csr()`), so the write guard, a temporary in the scrutinee, lives through the arms, and the `Err` arm's `fail()` (~178)
    takes `write(custody)` again: std's `RwLock` is not reentrant, the thread hangs holding it, every socket request and `end_once_failed` block, no failure is recorded
    and the pod stays in Init. Triggers: a plan server name `csr_for_key` refuses (empty, a wildcard, not IA5; `Custody::bootstrap` checks only permissions), a failed
    random source, Revoked or Sealed. Fixed by making each CSR before matching on it; `bootstrap.rs`'s tests drive a refusal out of `workload_csr` (a name no
    certificate can carry, and a revoked custody) and `escrow_csr` (revoked), each under a deadline, and failed by timing out before the fix.
  - Checked: every broker refusal is ignored (`watch.rs` ~460 `WatcherMessage::Event(_) => {}`; the Subscribe casts ~424 are `let _ =`). A refused reply topic leaves
    `ready_to_ask` (~290) false, so the bootstrap never asks and never fails and polar-init gets NotReady until its deadline; a refused authority topic leaves the daemon
    signing without hearing its own revocation, unlogged.
  - Checked: StoreEscrow waits for a pinned key with no deadline (`bootstrap.rs` ~289-294): nothing was sent, so `REPLY_TIMEOUT` never applies, and a key never pinned
    (snapshot replies refused, or Uncertified by a bad clock) never fails the bootstrap.
  - Checked: nothing supervises the Watcher actor (`daemon/src/main.rs` ~201-204 drops its ActorRef and JoinHandle); a panic (the `expect`s at `watch.rs` ~148, ~329,
    `bootstrap.rs` ~463, ~469) leaves the daemon signing with no revocation watch and no bootstrap progress, against "every component is a supervised actor".
  - Checked: a `Failed` reply is asked again at once, with no backoff (`bootstrap.rs` ~398-402 retrieve, ~439-442 store; `not_before` is set only for BeingIssued):
    with the credentials agent's backend down, every custodian loops at broker round-trip speed for its five-minute window.
  - Checked, lesser: one `accept()` error ends the daemon and every key (`src/server.rs` ~106 `?`, `main.rs` ~217-219 exits 1; a transient EMFILE should be logged and
    skipped); a poisoned custody lock answers "poisoned" forever (`server.rs` ~85, ~92) while `end_once_failed` reads `custody.read().ok()` as no failure, so the daemon
    never exits; per-connection request tasks are unbounded (`server.rs` ~136-162; only an in-pod caller can drive it, in mlocked memory); once the key is pinned the
    snapshot ask is sent once and never again (`watch.rs` ~215-235, ~431-432), so a revocation published during an outage waits for the next update or the half-hourly
    republish; a signature that cannot be made is answered as an empty one (`src/key.rs` ~134-139 `unwrap_or_default`, `custody.rs` ~248), not a refusal.
  - Plausible: bootstrap replies are taken without checking the publisher (`watch.rs` ~401-415 drops `published_by`; `bootstrap.rs` matches the correlation id only),
    resting on the broker's floor alone where the authority path checks it; a certificate not yet valid by the daemon's clock is a final failure (`custody.rs` ~532-534,
    no tolerance, and cert-issuer does not backdate `not_before`).
  - Lesser still: ticks pile up while the broker is unreachable (`watch.rs` ~346, a 1 s interval against a connect of up to ~47 s); replies that do not decode are
    dropped unlogged (`bootstrap.rs` ~144-151), so a version skew re-asks every 20 s in silence.

- [ ] (see "possibly obsolete") **GAP, MUST BE ADDRESSED (2026-10-14): nothing checks that a certificate presented as an access credential carries the permission for what it is used to do.** *(2026-10-21: the reading this entry asks for is done; the model, the enforcement map and the numbered gaps are in `docs/architecture/policy-enforcement.md`, the broker in `cassini-broker.md`, the topics in `topics.md`.)* The design says what a certificate's holder may communicate with is embedded in its SAN names (`p:` permissions, `cert-issuer/common/src/permission.rs`), resolved by `PermissionsActor` from the presented certificate plus supplemental permissions, and decided by Cedar in the nominal state (`polar-permissions`, `polar-policy`); the certificate is the floor and Cedar is the runtime nominal state. What is built: the credentials agent issues certificates with `p:` names from grants, runs Cedar over a requester's principal for secrets, and the builder admits signed documents by publisher. What is not: (1) agent certificates carry no `p:` names, because a Kubernetes workload needs no grant and none exists; (2) Cassini passes the peer's identity along with each message but, as far as grep of the broker shows, never decides whether a client may publish or subscribe to a topic, and never reads a permission; (3) no service-to-service call checks the caller's permission for the path. So any holder of a Polar-signed certificate can talk to any Polar service, which defeats the point of mTLS and zero trust for service-to-service traffic. Neo4j is the same and is accepted as a gap for now (next item). Shape agreed in principle, details to shake out: (a) know the pathways: each catalog workload declares the services and topics it needs, as it declares capabilities now, and the catalog is the source; (b) the certificate is the floor: the credentials agent issues each workload exactly those `p:` names from grants derived from the catalog, and refuses a request for more; (c) check at the receiving end: Cassini, and every service that receives requests, checks the presented certificate for the permission for the path, and consults Cedar when it is available (Cassini and cert-issuer run on the degraded floor alone, like the other bootstrap exceptions). To read before designing: how Cassini sessions, topics and `peer_identity` work in the broker; what the topics are and who publishes and subscribes to each; how `PermissionsActor` would be reached from Cassini, which is not a builder agent; what a grant for a workload looks like and where the catalog's grants are signed. Separate from, and after, who may obtain a certificate (cert-issuer isolation, below), which is what phase 6 does.
- [ ] DESIGN (2026-10-14), the Neo4j case of the gap above: nothing authorizes a graph operation per identity, and there should be a wrapper or proxy in front of the graph. Read from the configuration that day: Neo4j's bolt and https listeners have `client_auth=REQUIRE` with the Polar CA trusted, so any Polar-signed certificate (any workload's mTLS certificate, any person's user certificate) is accepted, and every agent then logs in as the same `neo4j` user with one shared password (`GRAPH_USER` / `GRAPH_PASSWORD`, the `polar-graph-pw` Secret). The `p:u2s:...` permission names in a certificate are not evaluated by anything on the Neo4j side. So an agent with a Polar certificate and that password can read, write or delete anything. One shape that fits the architecture, not decided: a graph service holds the only Neo4j credentials, agents reach it through Cassini as they reach the credentials agent, and it applies policy (Cedar, as the credentials agent does) to the requester's identity and the operation; Neo4j then accepts only that service. Open: what an agent is allowed to ask for (named operations or Cypher with checks), how the builder's graph component (`lib/src/graph`) changes, and what the graph projection of the credentials ledger does meanwhile. Not blocked by, and not made worse by, giving an agent one client certificate for Cassini and Neo4j.
  - FIRST CUT, the direction (2026-10-14; not scheduled, higher priorities first): a **Cypher query pass-through** for services that are not builder agents, ACE first (a Python Dash app, no Cassini connection, no escrow identity). The builder agents already reach the graph through the graph controller (`lib/src/graph/controller.rs`: `GraphOp` compiled to parameterized queries with identifier validation), so the new piece is for the exception. The parts: (1) **the transport exists**: `cassini-client` has a standalone mode (a daemon listening on a Unix socket, `CASSINI_DAEMON_SOCK`, or one-shot subcommands reading the payload from stdin) meant as a gateway so third-party apps, Python included, can talk to Cassini; (2) **a graph-querying binary does not**: it takes a Cypher query from the app, validates it with the shared graph-controller rules, sends the request through the Cassini client as the app's own identity, waits for the rows and hands them back; (3) **a graph service on the other side** receives that over Cassini and is the only holder of the Neo4j credentials, which is where the identity's permission would be checked (the floor from the certificate, Cedar above). Read before designing: what exists today covers only *identifiers* (`validate_cypher_identifier`, `CYPHER_KEYWORD_BLACKLIST` guards a label, relationship type or property name that is interpolated), not a whole query from an untrusted caller. `GraphControllerMsg::Query` takes a ready `neo4rs::Query`, skips `compile_graph_op`'s validation (its comment says the caller is trusted and that schema-access enforcement, which labels an agent may touch, is deliberately deferred), and `RawQuery` is the one explicit exception. So a validator for an arbitrary Cypher string is new work: read-only first, parameters not text, and an allowlist of labels and relationships per identity. Open: where the graph service lives (a builder agent that owns the graph controller is the obvious fit), the query language it accepts (named operations or checked Cypher), how a Python app gets its certificate (the standalone Cassini client needs one, so ACE is issued through the credentials agent like any workload), and what happens to the graph projection of the credentials ledger meanwhile.
- [ ] **cert-issuer isolation, what is left** (analysis 2026-10-13, phase 6 done 2026-10-14 on `local-minimal`:
  `docs/architecture/cert-issuer-isolation.md`). Left: NetworkPolicy emission with the canary, as an expected, automated
  control with a documented fallback where a cluster does not enforce it (the dev cluster's CNI, `ptp`, `host-local`,
  `portmap`, does not enforce NetworkPolicy, so an applied policy would be accepted and ignored). Not authenticated: whether
  a pod can tell it is talking to the credentials agent (`POST /workload/session`, `POST /workload/issue`, `sessions.rs`,
  `workload_issuance.rs`, `ephemeral_exchange.rs`), "to be settled with phase 3". `/issue` checks: `cert-issuer/server/tests/issue_extras_test.rs`,
  `floor.rs`. The model: a capability floor (static, rendered from the catalog, for the bootstrap identities credentials-agent, its
  observer and cassini) with signed policy authoritative above it in the nominal state. Decisions (2026-10-13): several separate
  requests per pod (no bundle), the token protected by an ephemeral negotiation (`ephemeral_exchange.rs`, ending at the consumer)
  and not TLS on the observer, the crypto actor owns both certificate lifecycles; see `cert-issuer-isolation.md`.
- [ ] **Items to review** (2026-10-12; where the remaining risk in the authority design actually sits, which is mostly not in
  the primitives, since attackers go around cryptography: stolen keys, misconfiguration, a logic gap, a compromised dependency,
  a person):
   1. The recovery path for the credentials agent's identity (its escrow keypair, which now also signs authority updates). Its loss is catastrophic and the path is not built.
   2. Logic gaps, the clearest being `DecryptOnBehalfOf` trusting a caller-asserted `resource_id` that nothing binds to the ciphertext: a requester only has to attach a label policy permits. Close it when `DecryptOnBehalfOf` is next touched, by binding the label into the ciphertext as authenticated data or by resolving a name the agent holds (`credentials-policy.md`).
   3. Policy and permissions delivery: who can author them (`c:update-policy`, `c:update-groups`, `c:update-runtime`, held by the first admin today), and how fast a demotion reaches the leaves (the half-hour republish and the missed-update detection are the bound until delivery is acknowledged).
   Optional, at the bottom of the list: the credentials agent decrypts ciphertext sent by authenticated requesters (StoreSecret, RetrieveSecret, DecryptOnBehalfOf), and I recall RUSTSEC-2023-0071, timing side channels in the `rsa` crate. Cargo.lock has `rsa` 0.9.10 and the 0.10.0-rc.18 fork (daveman1010221/RSA, rev aa4bc50). Not confirmed affected; `cargo audit` could not run (it cannot parse the newest advisory format). Signing is blinded. Realistic exposure is small (mTLS-only requesters, identities that live an hour, a query count that would be loud in the broker and the ledger). Cheap mitigations if wanted: a per-identity rate limit on those handlers and one uniform reply for every decrypt failure.
- [ ] **Left by the release advisory fixes (2026-10-31; `src/deny.toml`).**
  - RUSTSEC-2026-0387 (crypto-bigint timing variability) is ignored in `src/deny.toml`, the one advisory not fixed. It
    is reached only through jsonwebtoken 10.x on its rust_crypto backend, which still pulls p256/p384 0.13 and with them
    elliptic-curve 0.13 and crypto-bigint 0.5.5 (no patched 0.5.x or elliptic-curve 0.13.x exists). In production
    jsonwebtoken only verifies tokens (`cert-issuer/server/src/oidc.rs`), on public values only. Polar's own P-256
    signing moved to p256 0.14 (48f81ecc). Remove the ignore when jsonwebtoken releases on elliptic-curve 0.14 (upstream
    issue Keats/jsonwebtoken#549, waiting on rsa 0.10), or switch jsonwebtoken to its aws_lc_rs backend, which also
    drops rsa 0.9 and the RUSTSEC-2023-0071 ignore. Either swap moves RSA verification to 2048 to 8192-bit keys, so
    first add the token tests that are missing. Done 2026-10-31 for the algorithms:
    `cert-issuer/server/tests/oidc_algorithms_test.rs` pins, for every name `parse_allowed_algorithms` maps (RS256/384/512,
    PS256/384/512, ES256, ES384, EdDSA), acceptance when allowed and `ForbiddenAlgorithm` before any fetch when not; the
    deployed list (RS256, ES256, EdDSA); `none` in any case and HS* refused whatever the configuration; an `alg`
    jsonwebtoken has no variant for (ES512, `hs256`) as `InvalidToken`; keys of the wrong family or curve; expiry with
    jsonwebtoken's 60-second leeway; audience; issuer; and the `kubernetes.io` claim paths. Still open: RSA key sizes at
    the bounds. The ignore cannot be scoped to crypto-bigint 0.5: cargo-deny 0.19 takes only `id` and
    `reason` (later releases add `allow`), so until then check `cargo tree -i crypto-bigint` when the lockfile moves.
  - Noted at stage 3d (2026-10-16): `src/deny.toml` ignores with reasons the `rsa` Marvin advisory (reached only through
    `jsonwebtoken`, public-key verification) and three unmaintained crates (`instant` via `cassini-backoff`, `rustls-pemfile`,
    `unsafe-libyaml`), which still want migrating.
- [ ] **What the Polar git servers do not enforce yet.** Refusing unsigned pushes: a per-repo option on the Polar git server
  (`signed-configuration.md`, "git server enforcement"), and on the deployment git server (`deploy-repo.nu`,
  `cluster-bootstrap.md`). On the Polar git server (`docs/architecture/git-server.md`, `src/agents/polar-git-server`), not
  done: the Cedar authorizer, signed-commit verification, a signed push log (`push-log.jsonl` is one line per accepted ref
  update, append-only but NOT signed or chained). Decisions (2026-10-10): crate `src/agents/polar-git-server`; mTLS only, no
  TLS termination, identity from the handshake (Cassini `listener.rs` pattern); port-forward only for now; scheduler observer
  is the only agent reader; static default ACL with a Cedar override hook; authorization per repo (no branch rules, folders
  separated by repos); repos declared in deployment config and also creatable at runtime by an admin; authorship proof travels
  in signed commits (`polar-sign`), the server push log is an extra layer; topics are constants in the agent's common crate,
  not catalog entries. The old dev `src/agents/git-server` is still present (its removal awaits your word).
- [ ] **A registry in the cluster has no authentication** (2026-10-19; `cluster.registry_in_cluster: { node_port }`,
  `infra/cluster-registry.nu`, NodePort 30500 on `local-minimal`): anyone who reaches a node at the NodePort can push.
- [ ] Expiry check on admin actions (the consumer appears not to check the author cert's validity period; verify)
- [ ] Decide on the strict Subject-DN rebuild in cert-issuer `ca.rs`
- [ ] Test that `/issue` refuses `c:` extras
- [ ] Single-use `jti`; one token per cert
- [ ] Bootstrap cert permission set: least privilege?

## The Jira, git, GitLab and Kubernetes agents

- [ ] Git observer state, decided 2026-10-12 (not built):
   - Checkpoints (`last_seen` per ref) are restored from the graph at worker start, so a replaced pod does not re-emit history. Today `last_seen` starts empty and the first tick re-walks up to `max_depth` commits per ref and emits `RefUpdated` with `old: None`. Decided: the observer has no graph access (by design); it asks the processor over Cassini (request and reply) and the processor reads the graph. The latest tip per ref is the newest `POINTS_TO` edge (`observed_at` is stored as a String, so compare as numbers).
   - Seen 2026-10-31 by a consumer: the observer also reported a ref on every pass when it had not moved (`old == new`); fixed 2026-10-31 (Vaughn's fix in `observe_refs`, and the same rule in the worker's `publish_ref_update`, where the batched path publishes since the backpressure work; `docs/requests/git-observer-reports-moved-refs-only.md`). The restart case above is what remains, and a consumer that builds on `RefUpdated` builds each ref once per observer restart (about hourly) until it is done. Since 2026-10-31 the natural home for the restore is the StateActor (soft-state.md): a ref's checkpoint is the observer's own self-state, read back at start, rather than a request to the processor.
   - Repository storage goes on a PVC so clones are not repeated. emptyDir for now. A PVC is one claim per pod, so it does not scale to many repos by itself.
   - Sharding repositories across several observer pods will probably be needed once the repo count is large; it needs a partitioning scheme (by repo id) decided before the PVC is.
   - The controller's side, as first designed: `git-controller.md`, "Status and checkpoints", has the observer ask the processor over Cassini. See "STATE FOR AGENTS THAT IS NOT AUTHORITATIVE".
- [~] **Path 2, proposals and approvals** (started 2026-10-15; `docs/architecture/proposals.md`, `git-controller.md`). DONE: the plan
  (decided: proposals are soft state, the graph is a projection, `anonymous` is a separate list of hosts, accepted proposals
  EXPIRE when their proposer stops announcing them); step 1, the admission decision as a pure function and the canonical form
  of a proposed URL (`git/controller/src/admission.rs`, `git-agent-common/src/remote.rs`; `c7265e54`; decisions made where the
  design was silent are in `proposals.md` to be confirmed); step 2 (`0b6cf725`, `ab0ed616`: one `RepositorySet` with a `complete`
  flag; `proposals.rs`; the typed `admission` section; `polar-proposal-observe-repo`, `polar.git.proposals.decisions`,
  `POLAR_GIT_CONTROLLER_PROPOSAL_TTL_SECS`, `POLAR_GIT_CONTROLLER_WARMUP_SECS`) and step 3 (the processor writes a
  `(:GitProposal)` per repository and proposer, linked `PROPOSES` when accepted; only decisions about proposals the controller
  holds, `held`), both seen on a cluster 2026-10-15. The old per-repository announcement is gone, so the observer, controller and
  processor images must match. Left in that cluster: the settings document (TTL 300, warm-up 0), the two admission versions, and
  the Hello-World nodes in the graph (nothing removes graph nodes).
  - NOT seen on a cluster: the network guard against a real private address (unit-tested only), a rejection by the rules
    (denied, organisation), the hourly flood limit, a proposer other than the harness (`git-discovery-harness`, a test proposer,
    in the observer image, run with `env TLS_CLIENT_CERT=/etc/tls/certs/cert.pem TLS_CLIENT_KEY=... TLS_CA_CERT=... BROKER_ADDR=...
    CASSINI_SERVER_NAME=... git-discovery-harness <url>`).
  - TO DO, in order: (4) an easy way to approve (a `polar-sign` template for `admission`, probably `approve <url>`); (5) the
    GitLab consumer proposes instead of publishing the unreceived discovery event; (6) the observer's connect-time network guard,
    and removal (the observer stopping a worker for a repository no longer announced), which expiry needs; the Jira proposer
    after, because detecting a repository in an issue is new work.
- [~] Per-repository status feedback (2026-10-15: first, then path 2). BUILT 2026-10-15, unit-tested, and SEEN ON A CLUSTER the same day (see below): the observer publishes an `ObservationStatus` after every attempt on `polar.git.observation.status` (`observing`, `pending-credential`, `failing` with the reason: credential unusable for the host, clone failed, fetch failed; consecutive failures, last success, tips); the git processor writes the latest onto the `GitRepository` node (`observation_state`, `observation_reason`, `observation_consecutive_failures`, `observation_checked_at`, `observation_last_success`); a failed FETCH no longer ends the worker (a `failing` status and a retry at the next attempt or when credentials change). Reasons are cleaned (`sanitize_reason`). Tests: 14 in `observe/src/status.rs`, 6 worker tests, 4 graph-operation tests, 3 processor subscription/decode tests, 3 wire tests; 21 deliberate breakages, all caught (15 in the observer, 6 in the processor; two surviving ones about the `waiting` flag led to a test). The tests were written after the wiring this time, and the breakages are what checked them. SEEN 2026-10-15 (images rebuilt with `just image git-observer git-processor`, the two pods restarted): `observing` with no reason and 0 failures after the restart; after a `credentials` document at version 2 with an empty list and an observer restart, `pending-credential`, the reason null and the old `observation_last_success` kept (the new pod sent none); at version 3 with `host_pattern` `gitlab.com`, `failing` with `the credential cannot be used: the credential `mini-swe-agent` is not bound to this repository's host` and 1 failure, at once, because the worker was waiting; at version 4 with `github.com`, `observing` again with the reason cleared. NOT seen on a cluster: a failed fetch (the `the fetch failed` reason and the worker surviving it are only unit-tested, with an origin that disappears and returns) and a failed clone. Seen on the way: a healthy worker re-asks for its credential only at its next fetch (up to `frequency`, 900 s), so withdrawing a credential from a repository that is being observed shows as `pending-credential` only then, or at once after the observer restarts; the observer learns of a repository when the controller next announces it (up to 60 s after a restart). The runbook's Cypher works as written. Still TO DO: NOT built: the controller reading the status (liveness, backoff: path 2), `starting` and `stopped` states, the checkpoint request and reply, a `polar-sign status` command (the graph query is the way to look for now).
- [~] GIT CREDENTIAL PATH 1 (a permanent schedule), decisions of 2026-10-14 and what remains. DECIDED: a secret travels as ciphertext in a signed document addressed to the one agent that needs it; the ciphertext is the hybrid `EscrowedSecret`; the CryptoActor decrypts and registers the secret with its binding, and an actor that needs it asks for a named operation with it, never the plaintext (a cache there is an optimization); the CryptoActor makes no network calls, and I/O is done by other actors; the authority to push a credential is Cedar-first per section (`update-runtime` on `Section::"<agent>/<section>"`) with `c:update-runtime` as the fallback, and there is no capability of its own for credentials; `StoreSecret` is governed by a Cedar `store` action; path 1 is built before proposals. All recorded in `signed-configuration.md`, "Secrets in a document", and `git-controller.md`. BUILT SO FAR: authenticated context on `EscrowedSecret` (`encrypt_bound`, `decrypt_bound`; `442299db`); and, in the CryptoActor, the registry with `RegisterSecret`, `LoadSecret` and `GitCredential`, host-pattern matching and the escrowed form (step 1 of the plan, 2026-10-14; the `DecryptOwnEscrowed` message of `57432071` is internal now, and the builder's `CryptoClient` has the three methods); and step 2, the credentials agent's side of storing: labels on `StoreSecretRequest` and in the ledger (immutable, `LabelsChanged`), `Facts` carrying `namespace` and labels to Cedar, the typed `PolicyLookup::decide`, `StoreSecret` asking Cedar first with the floor, the `CryptoActor` sending the `kind` label, and the secret harness's secret renamed under the owner's identity (its intruder is now refused by policy, not `NameTaken`). NOT YET SEEN ON A CLUSTER, and it changes the wire format of `StoreSecretRequest`, so every image that escrows a secret has to be rebuilt together with the credentials agent. To check there: that an agent's own identity string (from its certificate) is the one the broker names it, since the floor compares them; and that every agent still escrows its keypair on a fresh cluster before a policy is seeded. TO BUILD (scope confirmed 2026-10-14; the CryptoActor part is built): in the observer, the `credentials` runtime section (declare it, hand each entry to the CryptoActor) and the use of that operation when it clones; a minimal `git-repo-controller` on the builder (declares the `repositories` section, holds the latest version, publishes each repository on `git.repo.config.events` naming its credential; no proposals, admission, status or backoff) which REPLACES the git scheduler (decided 2026-10-14); the repository configuration naming a credential (replacing the inline `credentials`, the unused `git.yaml` and `GitAgentConfig`); the author's side (the credentials agent's public escrow key endpoint, `polar-sign encrypt`); then a signed credentials document through the schedules repository and a clone of a private repository. DECIDED 2026-10-14: the binding context is `agent|section|version|entry-name|field` (names restricted to lowercase letters, digits and hyphens) and the ciphertext is written as base64 of the `EscrowedSecret` wire bytes. Secrets are named `<identity>/<name>`; `StoreSecret` asks Cedar first (action `store`), with a built-in floor when policy does not speak or none is loaded: an identity may store under its own `<identity>/` namespace and as `agent-escrow-keypair:<identity>`, so a fresh cluster's agents can still escrow their keypairs before the seed (`credentials-policy.md`, decided 2026-10-14). The seeded policy needs no `store` rule. The CryptoActor messages are `RegisterSecret`, `LoadSecret` and `GitCredential` (`credentials-agent-architecture.md`, decided 2026-10-14); `DecryptOwnEscrowed` becomes internal to `RegisterSecret`, since a public message that returns plaintext contradicts the named-operations decision. DECIDED 2026-10-14, step 3 plan: a repository whose credential is not there yet stays pending and retries when the `credentials` section changes and on its frequency tick; a later version of the section that leaves an entry out withdraws it, by a new CryptoActor message `ReplaceSection { section, keep }` and `LoadSecret` only for names the section lists. STEP 3 BUILT 2026-10-14 (observer): the CryptoActor's `ReplaceSection` and a `section` on `RegisterSecret`/`LoadSecret` (`8d0a4d4e`); the observer's `credentials` section, judged without opening anything, handed to the CryptoActor with the bound context, with a version's omissions withdrawn (`cc56d77f`); `RepoObservationConfig.credential` (a name) in place of the inline `credentials`, the worker asking for the credential at every attempt and waiting when it is missing, bound to another host or unusable (`e9a32950`); and the removals: `GitAgentConfig`, `git.yaml`, `git.dhall`, `git-agent-conf.dhall`, `POLAR_GIT_AGENT_CONFIG`, the `git-config` Secret step of the `local` target. Decided while building (not asked; say if you disagree): the observer does not use `LoadSecret` (the replayed section re-registers the credentials at each start, and a fetch could resurrect an older or withdrawn copy); a credential is only used for an `https` URL with no login in it whose authority agrees with the host that was checked (libgit2 reads the URL for itself); a clone that fails is retried at the next attempt, where it used to fail the worker's start for good (a failure of the fetch itself still ends the worker, as before). NOT YET SEEN ON A CLUSTER. The wire format of `RepoObservationConfig` changed: rebuild the observer, processor and scheduler together. Left over: `src/deploy/local` (the old Dhall deployment) still names `git-agent-local.yaml` and `GIT_AGENT_CONFIG` for the observer, and did before. STEP 4 BUILT 2026-10-14 (not yet seen on a cluster): the minimal `git-repo-controller` (`git/controller`; Cassini only, no graph) declares the `repositories` section and announces the whole set on `git.repo.config.events` at start, on change and every `POLAR_GIT_CONTROLLER_REPUBLISH_SECS` (60) seconds; the observer restarts a worker whose configuration changed and reads `refs/heads/X` from `refs/remotes/origin/X`; the host and credential-name rules moved into `git-agent-common` (`remote.rs`) for both agents; the scheduler crate, `git-scheduler` image, catalog row, target entries and Justfile line are replaced by the controller's (`git-controller` image, `gitControllerImage`, `container-controller.nix`). Not built or tried: a nix build of the new image (the flake evaluates), the controller's own reading of the section on a cluster, removal of a repository (deferred), the GitLab discovery flow (dropped until path 2: `git-discovery-harness` and the GitLab consumer still publish discovery events that nothing receives). Defaults changed from the design sample: refs left out mean the repository's default branch, not `refs/heads/main`. Delete the old `git-repo-scheduler` Job and ServiceAccount from a running cluster. Step 5 (the author's side) is being built (decided 2026-10-15, in `signed-configuration.md`, "The author's flow": `polar-sign template`, `sign` with encryption, `--push` to `permanent/<agent>/<section>.dhall`; a certificate-verified, unauthenticated `POST /agent-escrow-key` on the credentials agent's gateway). Decided 2026-10-14 in `git-controller.md`: discovery events are dropped until path 2 (the scheduler was their only subscriber), the controller republishes the whole set at start, on change and every 60 s (`POLAR_GIT_CONTROLLER_REPUBLISH_SECS`), the observer restarts a worker whose configuration changed and defers removal, and the observer translates `refs/heads/X` to `refs/remotes/<remote>/X`.
  - (see "possibly obsolete") STEP 5 CHECKLIST (the author's flow: `polar-sign template`, `sign`, `--push`; design in `signed-configuration.md`, "The author's flow"; update this as each item is done and committed, one line each):
    - Open question for a cluster run (not for the code): that the credentials agent's gateway may publish on `credentials-agent-escrow-key-requests`. The only place the topic is named is `credentials-agent/common/src/lib.rs`; no Cassini topic rule was found in the repo, so check the broker's actual rules when the cluster is up.
  - NOTHING IS OPEN for path 1 now: steps 4 to 6 wait for the go-ahead. Path 2 (proposals and approvals through the
    controller) follows. LATER, not path 1: I/O actors (HTTP, GraphQL, ...) that run requests prepared by the CryptoActor, and
    derived tokens (a result that is itself a secret, registered with an expiry). The runbook is
    `docs/operations/git-private-repository.md`.
- [ ] **The git server does not watch its listener (found 2026-10-23).** Its supervisor runs `serve_tls` as a task and awaits it only at shutdown (`polar-git-server/server/src/supervisor.rs:188`, `:221`), so a listener that ends any other way (a panic) leaves a pod that looks healthy and serves nothing. Watch the task and begin the shutdown when it ends outside one, as cert-issuer's supervisor will (`docs/architecture/cert-issuer-isolation.md`, "1b in detail").
- [ ] **The git server as an optional capability, what is left** (`PolarAgent::OPTIONAL`, `Configured::cassini_enabled`, the
  README in `src/agents/polar-git-server`, 2026-10-16): a push through the cluster's server being published as `RepoChanged`
  (the pod had not been pushed to since), running the image outside a cluster, joining a cluster from outside, and making other
  capabilities optional.
- [ ] **Scheduler processor leftovers** (2026-10-10): `ProcessorMsg::Event` is left in place with nothing sending it, so ephemeral
  schedules do not trigger anything (the old `events.#` subscription never delivered, since Cassini has no wildcard topics); the
  notification on `agent.hello-agent.schedule` has no subscriber. Retiring `adhoc` and `ephemeral` is step 4 of "Scheduler kinds",
  under configuration. A startup order dependency of the scheduler observer on the git server is left to the Job's retry because
  the dependency-certificate check may not tolerate a server that requires client certificates.
- [ ] jira-processor handles one issue per message; batching them needs a wire-type change (`JiraData`), not yet worth it at 50 issues a page.
- [ ] **The Jira poll interval is still a constant** (noted 2026-10-09 with the Jira settings, `jira/observe/src/settings.rs`).
  Its first pull's cursor is under "STATE FOR AGENTS THAT IS NOT AUTHORITATIVE".
- [ ] **Kubernetes agents:** CronJob owners (of Jobs) are unmapped (the owner edges of 2026-10-14: `KubeNodeKey`, `cypher_match`; two
  mutants caught, "NOT deployed" when recorded). To verify when convenient: that the kube observer re-sends its state after a
  reconnect (see the accepted limitations, under the broker).
- [ ] Empty `GITLAB_TOKEN` fails validation in some paths; handle gracefully
- [ ] `gitlab/observe/src/lib.rs`: `GitlabObserverState.tcp_client` is given and never read (the observers send through the
  client registered as `BROKER_CLIENT_NAME`). Removing it changes the state's constructor and its callers.

## The graph and soft state, with health

- [ ] THE GRAPH WRITE PATH, AFTER 2026-11-01 (graph-write-path.md; built, tested and measured, not seen on a cluster):
  see on a cluster the constraints made at start (and the duplicates they report), the repair of the empty state-type
  nodes, and Apache's 674 projects written; the lost project pulls, which need the next run's logs and, for the
  Cassini client, an info line at the projects publish and dispatch and a first-come wait for outbox room (the
  maintainer's call); whether `HAS_STATE` should point at the current instance rather than the `:State` taxonomy node;
  owned labels and `GRAPH_KEYS` for the writers that declare none yet; drop the repair once every graph has run it.
- [~] (BUILT 2026-11-01, not yet on a cluster; `docs/architecture/soft-state.md`, "As built: pulled health", with the
  decisions made where the design was silent, to confirm: the writer a new workload `soft-state-processor` on the
  writers' pool; its `agents` section seeded from the catalog's `agent` kind; a standing problem `Unhealthy`; the gate's
  floor the writer of the agent's own namespace and domain. The API a domain reports a standing problem through:
  `HealthHandle::hold(HoldReason::Configuration | HoldReason::Credentials, message)` and `release`. To see on a
  cluster: the seeded `agents`, the rounds and `AgentHealth`, the gate against stamped identities, jira-observer held.)
  HEALTH IN THE GRAPH, PULLED (decided by the maintainer 2026-10-30, replacing the same day's push design;
  `docs/architecture/soft-state.md`, "Revised by the maintainer's review"). The state agent's writer half asks every
  workload named in its signed configuration on `agent.<name>.health` (implied for every agent; answered by the
  HealthCheckActor) and writes `(:AgentHealth)`, the latest report plus the last 20 transitions; a workload that does
  not answer is unresponsive, one outside the deployed family is unreachable (drift). The report: status
  `Starting | Healthy | Degraded | Unhealthy | Draining`, a reason enum split by whether a restart helps (`Broker`,
  `Graph`, `Dependency`, `Internal`: the verdict ends the agent as today) or not (`Configuration`, `Credentials`: the
  agent stays up, reports, and stops retrying), an optional sanitized one-line message, connections, counters,
  uptime. To start AFTER the backpressure merge. Why (u7c, 2026-10-30): jira-observer refused a placeholder JIRA_URL,
  exited, the in-place restart removed its log and polar-init waited 5 minutes on TooSoon before the next refusal.
- [~] STATE FOR AGENTS THAT IS NOT AUTHORITATIVE (REBUILD DECIDED 2026-10-30: the floor and the set of agents asked become signed runtime sections, health is pulled, `SoftState` is a computed capability; see soft-state.md "Revised". 2026-10-15; DESIGN WRITTEN AND CLEARED 2026-10-30 in `docs/architecture/soft-state.md`; the maintainer chose the state agent over the Jira pair answering itself). READER BUILT 2026-10-30 and REBUILT the same day on the review (`soft-state.md`, "As built"): agents declare the labels they own and read (`PolarAgent::GRAPH`, in the scaffold); the builder computes the `soft-state` capability from a read, implies its topics (rule `soft-state`) and starts a `StateActor` (`StateHandle::get`); the `graph-read` capability; `Action::"read-state"` on `Label`; the state agent `soft-state-observer`, its floor the signed runtime section `schema`, seeded from the scaffolds by `infra/seed.nu`, its replies a family over the served workloads, the graph down reported as not connected; a read of an unowned label, or an agent needing the state agent in a target without it, failing `resolve.nu check`; jira-processor writing `updated_ms` from the system field `updated`, and jira-observer starting its first issue pull from the graph's newest issue through its state actor (`QUERY_DATE` only for an empty graph). The rebuild is not yet run on a cluster; the decisions made where the review was silent are listed there to confirm. BUILT 2026-11-01, not yet on a cluster: the set of agents asked as a signed section (`agents`) and pulled health, by the writer half `soft-state-processor` ("HEALTH IN THE GRAPH, PULLED"). PENDING: self-state writes (`StateHandle::put`) and the git checkpoints. Decided: observer checkpoints (the last tip of each ref), pollers' cursors and the like are not sensitive and cost little if lost, so they MAY be kept in the graph and read back from it. The rule that stays: an observer never reads or writes the graph itself; the privileged half of an agent pair (controller, processor or consumer) does, and passes what an observer needs to it. Signed configuration and secrets are still never rebuilt from the graph. An idea, to be designed: a soft-state agent pair so that no pair has to do this for itself, its observer half answering other agents' requests for state (a graph READER only, cluster-internal) and its processor half making the graph writes. It would decide a request by the requesting agent's identity and permissions against the nodes and relationships that agent is responsible for, so agents must REPORT THEIR GRAPH SCHEMA (the node labels and relationship types each owns) in `--scaffold`, and it reaches the catalog. Where the ownership comes from (2026-10-15): the schema is part of the agent binary's `--scaffold` output, so it is not a runtime claim; it gains authority when an admin puts it in the catalog and it SEEDS the state agent's signed configuration (like the cluster's first policy). Conditions to keep: the seed is a reviewed artifact, never regenerated automatically on deploy (a swapped image would define its own ownership; export, diff against the signed seed, an admin approves, then it is signed, and a mismatch is reported as drift); ownership is bound to the agent's IDENTITY as the broker names it, not the image; "owns (writes)" and "may read" are separate; Cedar is a candidate way to express it. Open questions for the design: what a request and a reply look like (Cassini request and reply), and how much of this the git agents' checkpoints (`git-controller.md`, "Status and checkpoints", which has the observer ask the processor over Cassini) already are. Two concrete first users: observer checkpoints and the Jira and GitLab consumers' cursors. Path 2 does not wait for it. A data point (2026-10-30): a user pulling a real Jira site sets `QUERY_DATE` from a script of their own each time they need data, as a hand-made cursor. The observer keeps `full_pull_done` only in memory (`jira/observe/src/issues.rs:222-239`), so every restart (about every half hour, with rejuvenation) starts from the same fixed `QUERY_DATE`, or pulls everything; `QUERY_DATE` is static, so moving it means a re-render and a restart. The cursor the design gives the Jira pair is the last `updated` time actually written to the graph, handed to the observer at its start; it has to account for JQL reading an absolute date in the Jira user's time zone (the relative `-35m` form is evaluated on Jira's clock).
- [ ] The credentials agent's graph projection does not catch up after Neo4j was down: certificates reported by cert-issuer's
  record on the first page, while Neo4j was starting, are in the ledger and not in the graph
  (`docs/architecture/authority-model.md`, slice 10, "Found"). Decide whether the projection replays from its checkpoint.
- [ ] Audit the graph writes that are not MERGE-style (2026-10-08: almost all are). The Cassini reliability design makes consumer processing at-least-once, so a write that creates where it should merge would duplicate on a repeated delivery. Find them in the kube, jira and credentials projection consumers and make them safe to repeat
- [~] **The credentials-agent consumer can be up, healthy and deaf, with no sign of it in its logs** (2026-10-06, first
  fresh-cluster run). The first stall's cause is known (`up.nu` started clients before the new broker; the client attached to the
  old broker and re-registered without re-subscribing). Still unexplained: the first manual restart of the consumer (16:29:14,
  fourteen minutes after Cassini's last change, so no ordering race) stayed deaf for 25 minutes, and the second (16:54:26, same
  conditions) worked at once; the two startup logs were identical. Suspect a race or stale state in subscription setup or in the
  broker's topic actor (the broker logged `Dropped N stale message(s)` on the escrow-keypair request topic until 16:29:13 and
  nothing after). To do: reproduce it on a clean Cassini restart.
  - The self-test catches and replaces such a consumer (`AgentBuilder::with_self_test()`, `selftest.rs`, `selftest.<service>`, on
    every builder agent; 2026-10-08/09): what it proves and what it does not: the whole path out and back works through the
    session, client and router every topic shares; it does NOT prove each of the 15 request topics is subscribed (a subscription
    lost for one topic only is not seen).
  - Its numbers (probe every 30 s, deaf after 20 s, look every 5 s) are constants in `infrastructure.rs`, not environment
    variables, not in the catalog and not in the scaffold (`--describe` when written); agents not yet on the builder have none.
- [ ] **Rejuvenation not yet forced for jira-processor or kube-observer,** which use the same builder path with their own
  supervisor halves (verified on a real cluster for kube-consumer, 2026-10-06, by setting `POLAR_HEALTH_REJUVENATION_SECS` above the
  cert lifetime; `health-and-shutdown.md`).

## The agent builder and its migration

- [x] A PERSON'S IDENTITY IN A WORKLOAD'S FORM (found and FIXED 2026-11-09, `docs/architecture/remote-observers.md`, the last section).
  A Keycloak token with `identity_scope` `polar.serviceaccount.cluster.local` normalized to a workload's identity, and neither cert-issuer
  nor the credentials agent refused it (the realm's mapper is admin-set, so it took the realm's administrator). `normalize_identity` now
  refuses a suffixed identity that `workload_of` reads as a workload, tested by example and by property.
- [ ] UPSTREAM'S WORK, BY VAUGHN'S PORT, TAKEN APART AREA BY AREA (decided 2026-11-07, the maintainer, "Yes, oci fixes first"). What there is (read
  2026-11-07): cmu-sei/Polar `main` (`5074f15f`, 2026-10-17, 14 commits since `9aea62f6`) and `blitz-deploy` (`df69bce`, 2026-10-31, those and 43
  more: the operator, the `polar` CLI, the Dhall deployment library, the build orchestrator), neither moved since; on gitea, Vaughn's
  `port/public-polar-blitz-deploy` (`b59ea4d4`, 2026-11-05), all of `blitz-deploy` re-made on our v3.0.0 (13 port commits, each naming the upstream
  commits it carries) and his work after it (build-orchestrator hardening, oci-resolver reference fixes, images named `localhost/<name>`, a
  `polar-sign next` proposal, a merge of `release/3.0.x`), 29 ahead of main and 195 behind, his own note (`docs/requests/public-polar-port.md` on
  it) calling it "a worked version of that merge for the owner to take apart"; and `fix/git-observer-report-moved-refs-only`, already on main
  (`db133f93`). The branch is not merged or rebased: each area comes to main as its own bite, by our rules (tests first, one fix a commit, on the
  builder). In order: (1) his oci-resolver fixes, each with a test; the `localhost/<name>` naming checked against one artifact per target before it
  is taken; (2) build-processor and the build orchestrator together, his port the starting point, moved onto the builder and into the catalog, the
  failure findings re-read on that code (merging and migrating one step per area); (3) the kube agents' cluster-scoped identity and discovery, its
  own bite, `cluster_uid` on every key a breaking graph change needing a migration, one events topic or one per cluster the maintainer's to decide
  (PLANNED 2026-11-09, `docs/architecture/kubernetes/kubernetes.md`, "Cluster-scoped identity and discovery"; DECIDED 2026-11-09, the
  maintainer: one cluster for now, observers that run anywhere written up and deferred in `docs/architecture/remote-observers.md`; so area 3
  is bite C only, Namespace and Node states and a pod `RUNNING_ON` its node, and A, B and D wait with remote observers; C BUILT 2026-11-09,
  the observer stamping the cluster's uid, K12's panic gone, K6 and K7 not repeated in the new projections; seen live on u7c the same day);
  (4) the operator not merged: its phases and back-off are lifecycle's, taken into `docs/architecture/lifecycle.md`'s design (DONE 2026-11-09:
  written there, "From Vaughn's operator", what to take and not, and three questions for when the controller is designed); (5) the `polar` CLI
  and the Dhall deployment library wait for the catalog conversation, a second deployment system beside the catalog (REVIEWED 2026-11-09: not
  taken as a system; what is taken, what is not and why, the problems for Blitz to fix now, and the options, written on his branch as
  `docs/requests/public-polar-port-deployment-review.md`, `bdf2f096`; the parts taken land in step 10's lifecycle work, and these now, in bites:
  kube-observer's role derived from what it declares (it reads every Secret today, `infra/config/capabilities.nuon:165`), `up.nu` requiring the
  cluster named, a timed-out wait saying why, the plan naming secrets without values, the graph password's two forms checked to agree, the
  bootstrap CA constrained for new clusters, and tests that `polar-sign` and `polar-admin-grant` cannot print a secret); (6) `polar-sign next` read
  against lifecycle's decisions first. (6) DONE 2026-11-09 (the maintainer, "Take it, with the push fix"): `polar-sign next` built, with a sealed secret
  never carried (bound to its version) and `push`'s stale clone fixed (`docs/architecture/polar-sign-next.md`). (1) DONE 2026-11-07: taken from `2cce4722`/`5189c650`, Docker's rule for the registry host (a tag's dots
  are not a host: `neo4j:5.26.2` had been sent to a registry named "neo4j:5.26.2") and a `localhost` registry as the node's own store, never fetched,
  logged "not verified"; changed, hostless means Docker Hub only when a digest pins it, an unpinned hostless name is not verified (the maintainer,
  "Docker Hub only if pinned": a digest proves the image wherever it is fetched, a tag on Docker Hub may not be what a node loaded by that name);
  declined, `7621f9bb` (credentials from `DOCKER_CONFIG`, the file path main replaced with escrowed `credentials` sections in `775a1ecc`) and
  `9132832e` (images named `localhost/<name>`, not taken now). Found doing it, not his, and FIXED 2026-11-07 (the maintainer, "the digest
  fix"): nothing read the kubelet's `image_id`, though the kubernetes consumer says the resolver must trust it
  (`src/agents/kubernetes/consume/src/lib.rs`, "Image discovery: kubelet-attested only"); the resolver pulled the spec's tag as it was then and the
  consumer linked `USES_IMAGE` to that digest, so a tag repointed after the pull attested an image the pod was not running. Now a container is
  read by the kubelet's digest from where the spec names (`src/agents/resolver/src/resolver.rs`, `image_source`, `kubelet_digest`), else by the
  spec's own digest, else not verified; this also pins a hostless name the kubelet ran. Still open: a repoint is not flagged (the consumer's
  contract asked for it, detection first), which takes a second read, of the tag, on every observation; and a read that fails is made again
  on every observation. Every observation used to read the registry again, which on Docker Hub meets its pull limits now that hostless names the
  kubelet ran are read there; since 2026-11-07 an image read by its digest is kept (`ReadCache`, at most 1024 then all dropped, as the broker's
  decision cache), so it is read once. Checked live on u7c, 2026-11-07 (the GitLab configuration under test up, the
  resolver at `a29d1d36`): the two Docker Hub images were read once each in two minutes while each container was discovered about four times,
  and their edges are the kubelet's digests; coredns, whose kubelet gave a bare `sha256:` (an image the node had loaded), was logged "not
  verified" where the old resolver had linked registry.k8s.io's tag as it then was, a digest the kubelet did not run. THAT EDGE IS STILL THERE: an
  edge the old resolver made is never taken back, so a graph built before `1f809267` may hold `USES_IMAGE` edges to images a container did not
  run; removing them (each `PodContainer` whose kubelet digest is not its edge's) is a migration step for after 3.0.0, not written. Polar's own
  `localhost:30500` images still fail, as below ("The resolver cannot read images from the node's registry"). (2) READ 2026-11-07, not started (his branch
  forks from v3.0.0; main is ~200 ahead). BUILD-PROCESSOR, his `de642e6a` (upstream `312d5dec`): a pure projection (`src/project/*`, one dispatch,
  no wildcard) replacing the linker; it fixes the findings above B1 (a bad message no longer kills anything), B6 (timestamps out of MERGE
  patterns), B19, B20, and removes B18's actor; B2-B5, B7-B17, B21 and the two later candidates still stand in it; new: N1 `dispatch` returns at
  the first failed cast and drops the rest of that event's ops, N2 a controller dying between registrations is only logged (TODO
  `supervisor.rs` ~299), N3 stale docs, N4 `tests/projection_neo4j.rs` is `#[ignore]` and was never run. It is still on the bare transport (refusals
  to `_ => {}`), still a Job, still says "the broker log is the source of truth" (`supervisor.rs` ~47, ~84, ~280; README ~40), not in the
  catalog, its graph password from a render-time Secret env. Its lib additions (`PackageAnalysisStarted`, `AnalysisFindingReported`,
  `OCILayerDiffId`, `HAS_DIFF_ID`) have no producer on either branch. BUILD-ORCHESTRATOR (10 commits from `69cd7731`, ~9k lines, 37% tests; his
  own note: ported, tests carried not written red-first, never run on a cluster): already on the builder (`PolarAgent`, `Subscription`, signed
  `mappings` and escrowed `credentials` sections, pipeline images pinned by digest, a namespaced Role, build pods with no token, supervised actors,
  build state owned by a registry actor and changed by message), which fits; against Polar's model: a YAML config rendered into a ConfigMap with
  any field overridable by `BUILD_ORCHESTRATOR__*` env (namespace, clone image, job identity, broker address, store endpoint: render-time facts,
  not signed), the object store's keys from a Kubernetes Secret env and its traffic over its own aws-sdk client on plain http (not a protocol
  handler), `NEEDS` says `KubeApiRead` though it creates and deletes Jobs and Secrets and the Dhall declares its capabilities a second time,
  deployed only through `src/deploy`'s Dhall library (not the catalog; main means to retire `src/deploy`), `requested_by` taken from the payload
  and recorded as `triggered_by` with the broker-stamped `published_by` dropped, `std::process::exit(1)` on an essential child's failure
  ("the operator starts a new pod"; main's rule is the HealthCheckActor's verdict), the escrowed git credential written in plaintext into a
  per-build Secret, a clone image defaulting to an unbuilt `:latest`, a shared `client-tls` fallback, registry push not built (placeholder
  credentials), the retention sweep a bare `tokio::spawn`. Only the pipeline log reaches the store; nothing is pushed. Plan (the maintainer, 2026-11-07,
  "Build-processor first"): P1 his projection onto main's build-processor; P2 onto the builder and into the catalog as a Deployment (the transport,
  Job, exit 0, drains, refusals, render-time settings, graph password, N2, and the legacy `polar.provenance.linker` topic, which nothing has
  published to since G5a removed the old GitLab consumer; `topics.md` still names it); P3 the remaining projection findings, one a commit, tests
  first; then the orchestrator's design conversation before any of it is ported (HELD 2026-11-07: four decisions asked and answered, three by standing rules, and the plan in bites O1-O6, `docs/architecture/build-orchestrator.md`). P1 DONE 2026-11-07: taken from `de642e6a` and the
  `OCILayerDiffId`/`HAS_DIFF_ID` part of `04badb51`; not taken, his analysis events (`PackageAnalysisStarted`, `AnalysisFindingReported`, no
  producer on either branch) and `PackageRef::archive_sha256` (a wire change with no producer). His findings projection wrote `ON CREATE SET`,
  which the graph controller's raw-write guard refuses (`validate_raw_op_text`, MATCH/MERGE/SET/UNWIND only, there since v3.0.0), so every finding
  would have been refused and dropped; his Neo4j test, `#[ignore]` and never run, would have shown it. Kept first-write-wins with
  `SET x.at = coalesce(x.at, $observed_at)`, a test now holds every projection to what the controller accepts, and the Neo4j test runs with the
  suite. Migration step, not written: graphs the old linker wrote hold built images' layers as `OCILayer` keyed by uncompressed diff ID, which the
  projection now writes as `OCILayerDiffId`. P2 DONE 2026-11-07: a PolarAgent on the HTTP processor's shape, a catalog workload
  (`provenance.nuon`, writers pool) that sandbox-local enables, a Deployment; the hand chart, its render arm and the linker topic gone; closes B3,
  B4, B14 (a constraint for each of its sixteen labels), B16, B22, B23, N2, N3. Checked live on u7c: it ran 2/2 with no restart, made its
  constraints, and wrote the resolver's two Docker Hub images as `OCIArtifact`s `HOSTED_BY` docker.io, each an index with 12 `HAS_MANIFEST`
  platform manifests, which nothing wrote before. Migration step, not written: a cluster that ever applied the old chart keeps its
  `build-processor` Job and ServiceAccount, to delete. P3: B12 and N1 DONE 2026-11-07 (`2a304ef9`: one event's writes are one
  `GraphOp::Transaction`); B11 DONE 2026-11-07 (`37c57e14`, the maintainer, "Split topics by whose word"): the resolver's verified registry facts
  on `polar.provenance.resolutions`, which it alone declares, build reports on `polar.provenance.events`, each kind believed on one topic only
  (`project::whose_word`, `believed_on`); checked live on u7c, the resolver's facts written by the new build-processor five seconds after it
  started, nothing refused. Open from B11: which build publisher owns which `build_id` (any publisher the topic admits may still report for
  any build). Next, the projection findings, one a commit: B13 DONE 2026-11-07 (artifacts IS `Artifact`,
  as the type-marker idiom says, and a registry no longer CONTAINS the anchor; migration step, not written: graphs written before hold
  `(Artifact)-[:IS]->(x)` and `(OCIRegistry)-[:CONTAINS]->(Artifact)`, u7c's two resolved images among them, to reverse and remove), B21 DONE 2026-11-07 (the maintainer, "build-processor ages it", `lost_at` on the BuildJob, "Pick a bounded time and end it": a sweep every five minutes judges lost a build started and not heard of for `POLAR_BUILD_LOST_AFTER_SECS`, a day by default, Dynamic; any later event clears it; checked live on u7c, a seeded stale build judged lost by the first sweep five minutes after start, its read allowed, the build then removed; DIRECTION, the maintainer: whether a build stopped is mostly a monitoring event, no CPU, network or disk activity, to read from the build's pod when the orchestrator runs builds), B17 DONE 2026-11-07 (a finding no package resolved for is FOUND_IN its BuildArtifact when the scanner gives `in_artifact`; scanning.nu sends none yet, as its own comment says: no artifact hash is threaded through), B15 DONE 2026-11-07 (a backend job's identity names at least one property, `BackendJobIdentityError::NoProperty`), B5 DONE 2026-11-07 (the maintainer, "Reporter's time on the wire": execution and stage events carry `at`, required, and a build's states and times are keyed on it in UTC; the pipeline's emitters stamp it, `reported-now`; checked in Neo4j that a start seen again after the build finished lands on the start it had; breaking wire change, every agent of `ProvenanceEvent` built together; `scripts/pipeline/smoke-test.nu` was already stale before it, calling an `emit-stage-started` that does not exist and passing build ids the emitters no longer take, not fixed), B9 DONE 2026-11-07 (an SBOM that gives no license or source no longer erases one recorded), B7 DONE 2026-11-07 (a component or root with no purl is not written; graphs written before may hold one `Package { purl: "" }` that every such entry merged into, to remove), B8 DONE 2026-11-07 (the pipeline gives the tree between purls, translating
  bom-refs, and build-processor writes no package for a ref that is not a purl; `scripts/pipeline/tests/sbom.nu` is the pipeline scripts' first
  test; migration step, not written: graphs written before hold `Package` nodes keyed by bom-refs, with their DEPENDS_ON edges, to remove), (dependency tree keyed on bom-ref), B7 (empty purl),
  B9 (null license erases), B5 (processing time as the state key), B15, B17, B21, B2/B10 (shared with kube-consumer's K2/K4). **Status
  2026-11-09:** B5 (`95d3cc2d`), B7 (`3a7010e5`), B9 (`2dabb775`), B15 (`b9ccf3b5`), B17 (`bc4709eb`) and B21 (`3116680b`) are done; B2 and
  B10 are the shared graph controller's (`lib/src/graph/controller.rs`: a failed write dropped, no backpressure on its mailbox), not Vaughn's
  code, so they leave this area and stand as K2 and K4 for every graph writer (decided for review, to finish the port). The build orchestrator:
  O1 to O3, D1 to D4, E1 to E3 and O4 done, the watched build live on u7c (`docs/architecture/build-orchestrator.md`); O4 to be seen live with
  the next bring-up; the network step planned and deferred behind a standing rule (no mapping of a repository Polar does not control, no
  archive built, until it is done); images out of build pods a decision of its own. O4 seen live 2026-11-09 (build `616253d6`): area (2) is
  DONE. The history that
  follows, superseded:
  MERGE UPSTREAM (github.com/cmu-sei/Polar) AND MIGRATE THE BUILD PROCESSOR, IN AN ORDER NOT YET DECIDED. **Reopened 2026-11-07** (the maintainer, through
  the agentic-control-plane session): build-processor moves onto polar-agent-builder and into the catalog when the GitLab work is done, which takes Vaughn's
  upstream code, his restructure of it around cyclops (`312d5dec`) and the build orchestrator included; whether the merge comes before or after the migration
  is the maintainer's to decide then, not settled. An input to it: the build-processor failure findings above were read on the linker and projection that
  `312d5dec` deletes, so fixing them in the old code first is wasted either way. (Was: confirmed 2026-11-02: the OpenAPI and GitLab agents first, then the merge, then build-processor and the orchestrator; the maintainer, 2026-10-31:
  Vaughn may have been working there). Read 2026-10-31 (fetch only): the merge base is `9aea62f6` (2026-08-07); ours has
  1058 commits since, `origin/main` 14 (Vaughn, to 2026-10-17, 161 files, +22.7k/-5.9k): the build orchestrator (56
  files; Blitz's per-run identity request is about its builds), the build processor restructured around cyclops
  (`312d5dec`, also nufmt and nu-lint), the Kubernetes agents (nodes, namespaces, cluster-scoped identity and
  multi-observer discovery, a projection cache; ours moved them to the builder since, the hardest part), cert-issuer
  (liveness and readiness, an eager JWKS fetch), the resolver's configuration schema, `lib`'s graph controller sync
  operations, pipeline scripts. `origin/polar-operator` (`3c3a4b78`, 2026-10-18): a PolarAgent CRD and operator that
  keep agents alive with their lifecycle in the graph; it overlaps decisions made since (the health actor's verdict and
  restart in place, the Reaper owning housekeeping, pulled health in the graph) and needs a design conversation, not
  only a merge. A plan first: area by area, which side's design holds, tests first. Do not take Vaughn's state-type
  line in the controller (`f604cc43`, `MERGE (stype {stype})` in `UpdateState`): it worked around `KubeNodeKey::State`
  matching `(:State)` with no variable; since 2026-11-01 every key's pattern is derived from its identity and binds the
  variable it is given (`(stype:State)`), so ours, `MERGE ({stype})`, is right for every key, and his would write
  `MERGE (stype stype:State)`, which Neo4j refuses (docs/architecture/graph-write-path.md, "Every key binds its
  variable").
- [~] **Remaining agents onto `polar-agent-builder` (`PolarAgent`) and into the catalog: gitlab, openapi, build-processor**
  (THE MAINTAINER, 2026-10-31: "It's time we migrated these agents to the builder and the catalog", toward the end of the current
  list; a second registration collided on actor names in all three, made reachable by the broker ending a shed session, and is
  worked around in backpressure round 5 until they migrate; gitlab-consumer's is fixed (2026-10-31: the supervisor stops its
  consumers and graph controller, waits, and respawns them, since they subscribe in `pre_start`)). Done, on the builder and in the
  catalog: kube, jira, credentials agent, resolver (`e245b97b`, `f249491b`, the best template for a small agent with its own env),
  Cassini broker, git, polar-scheduler, git server, cert-issuer, soft-state; `ace` is a deployed service, not a crate in this
  workspace. Ground rules: `AGENTS.md`, tests first (red before green, stated in the commit message), one fix per commit, no
  behaviour change inside a refactor commit. Order (rationale: observers have no graph and the smallest blast radius; processors add
  the graph rule; the two with open decisions come last): openapi-observer; gitlab-observer (adds a health check that never existed);
  gitlab-consumer, openapi-processor (graph agents); build-processor (read in full first; merge upstream before it, above).
  - All still build their own `HealthCheckActor` and Cassini client by hand. Hand charts live under
    `infra/layers/3-workloads/agents/<group>/` (`gitlab`, `openapi`, `build-processor`). Line counts are of the file holding the
    supervisor (2026-10-14).

    | # | Agent | Source | Lines | Graph | Notes / known hazards |
    |---|---|---|---|---|---|
    | 1 | openapi-observer | `openapi/observe/src/actors.rs` | 311 | no | named spawn in `Registered`: second registration returns the error |
    | 2 | gitlab-observer | `gitlab/observe/src/supervisor.rs` | 244 | no | **has no `HealthCheckActor` at all today**; migration adds health/shutdown behaviour |
    | 3 | gitlab-consumer | `gitlab/consume/src/supervisor.rs` | 360 | yes | graph controller and consumers spawned in `Registered`; a repeat stops and respawns them (2026-10-31, `stop_children`); `TcpClient::spawn` |
    | 4 | openapi-processor | `openapi/process/src/actors.rs` | 403 | yes (1 ref) | named spawn in `Registered` |
    | 5 | build-processor | `build-processor/src/supervisor.rs` | 414 | yes | consumes the resolver's output; this file says it was not read to the end for the `Registered` hazard; unread |

    In scope with them (the maintainer, 2026-11-02): the builder owning the graph controller and the shutdown handshake, and the close-out below.

    Not part of this migration, so nobody wonders: `polar-init` (init container; has its own client by
    design), `cassini/test/*` and `cassini-c2` and the Cassini CLI client, `credentials-agent/admin` (CLI),
    `polar-scheduler/tests/mock-*`, `logger`, and the non-Rust services
    (ace, Neo4j, Postgres, Keycloak, Jaeger: charts under `infra/layers/2-services`).

    Facts to confirm per agent during triage (not yet established): exact `Registered` behaviour for
    build-processor, whether any needs `with_encryption`, the real drain worst case for
    the budget, and the image row names in `infra/images.nuon` / flake attrs.
  - **What "migrated" means** (`polar-agent-builder/src/agent.rs`, `examples/hello_agent.rs`; the old
    `AgentBuilder::new(..).with_health_check(..)` shape is gone, older commit messages describe it):
    - The agent is a type implementing `PolarAgent`: `NAME`, `PURPOSE`, `NEEDS` (capabilities beyond the
      Cassini client), `SHUTDOWN_BUDGET`, `SECTIONS` (its own `polar-env` variables), `HELP`,
      `SELF_TEST`, `CASSINI_CLIENT`, and `async fn start(Configured)`.
    - `main` is `polar_agent_builder::run::<A>()`. `run` answers `--help`, `--scaffold`, `--check --config
      FILE`, judges the configuration, and starts the agent; it never exits 0 for a started agent.
    - Capabilities (`.with_graph_write()`, `.with_encryption()`, `.requires(..)`) replace
      `with_health_check`; health args come from capabilities and `POLAR_HEALTH_*`. The agent reads its own
      variables through `polar-env` declarations, not `std::env` (a `disallowed_methods` lint and a
      `clippy.toml` per crate enforce it).
    - The infrastructure supervisor owns health, router, Cassini facade (reconnects with backoff and
      buffers offline publishes) and optionally crypto. `Respawned` / `InfrastructureRespawned` no
      longer exist. The domain supervisor keeps its half of `PrepareShutdown` -> drain ->
      `ProceedWithShutdown`, declares its own `SHUTDOWN_BUDGET`, and must treat the supervisor stopping as
      failure (exit non-zero so the Job restarts).
    - A `Registered` arm must do health and nothing else, or guard what it spawns (`is_none()`), because
      `Registered` now fires on every registration, including a resume after a transient drop
      (the FINDING below).
    - Tests: `polar_agent_tests!(MyAgent)` in the agent's `agent.rs`.
  - **The per-agent checklist:**
    1. Read the supervisor and entrypoint completely; list children, topics, shutdown path, `Registered` arm
    2. `agent.rs`: `impl PolarAgent`; `main.rs` becomes `run::<A>()`; `lib.rs` exports the module
    3. Own env vars -> `settings.rs` `polar-env` section (`SECTIONS`); remove `std::env` reads; add `clippy.toml` (copy identical) and the `deny(clippy::disallowed_methods)` attribute
    4. Domain supervisor on the builder's `Configured`/resources: topics as `Subscription`s, drop the hand-rolled `HealthCheckActor` / `TcpClient::spawn` / `TcpClientActor`, drop `HealthCheckArgs` and dead dep-endpoint literals
    5. Declare `SHUTDOWN_BUDGET` (the drain's real worst case) and handle `PrepareShutdown`; make a stopped supervisor an error
    6. Fix the `Registered` arm per the rule above
    7. Graph agents: graph via the builder's graph capability / `GraphSettings` from the snapshot (watch the health-versus-projection distinction recorded for the credentials consumer)
    8. Tests (red first); `cargo check`, `clippy` on the crate, `fmt`, package tests, then workspace tests
    9. Catalog: add `infra/config/workloads/<group>.nuon` entry (`name`, `kind`, `image`, `config: "document"`, plus `provides`/secrets where the deployment gives more); image row in `infra/images.nuon`; golden-diff the render against the old chart; delete the hand chart and its `render.nu` arm
    10. `resolve.nu check` clean (it runs the agent's own `--check` from its image under `up.nu`); deploy and verify on the cluster, record what was and was not observed
  - FINDING (no work until the agents are migrated, 2026-10-09): `Registered` handlers that run one-time work again on every registration. Checked 2026-10-09 by reading the handlers; nothing was changed. The mechanism: `ClientEvent::Registered` is now emitted on EVERY registration answer, including a resume that returns the same session, because `f16eb166` made the client report an answer that arrives while it is already registered (it was ignored before, which left consumers deaf and observers unhealthy). The client reconnects in place after any lost connection (confirmed in the harness: the transport actor is the same actor, id 9 before and after a broker restart), so every transient drop or broker restart reaches the handler, not only a new session. A second spawn of a named actor is refused by ractor (`Actor 'x' is already registered in the actor registry`, confirmed). Effects in the agents NOT yet on the builder, which the migration is to fix: git observer (`init` spawns the named repo supervisor, then `myself.stop` on the error, so a reconnect ends the agent), git process (graph controller spawn, `?`), gitlab consumer (graph controller, stops itself), openapi observer and processor (named spawn, returns the error); git scheduler (`init` only subscribes) and polar-scheduler observer (guarded by `watcher.is_none()`, with a comment about respawn on reconnect) are repeatable; build-processor and the resolver were not read to the end. The six agents ON the builder are all repeatable: credentials consumer and observer, kube-consumer and jira-processor only tell health, kube-observer and jira-observer guard each spawn with `is_none()`. The rule for the migration: a `Registered` arm does health and nothing else (the builder subscribes), or guards what it spawns. A correction to an earlier note of mine: this is not limited to a new session, as I first wrote
  - **Close-out, with the last of them:** remove the process-reading fallbacks that exist only for un-migrated agents
    (`TCPClientConfig::new()`, `TcpClient::spawn_with_router`, `get_neo_config()`, the health actor reading the process, the
    client's `Registered`-while-registered arm), the dead dep-endpoint literals and `HealthCheckArgs` from the remaining agents,
    and the dead hard-coded endpoint fallbacks in the Rust agents once the env is always set (confirm `HealthCheckArgs` hard-coding
    was a convenience).
  - **`--version`:** the binaries that do not answer it yet (2026-10-31; `infra/INFRA.md`, "The version a binary reports"):
    `cert-issuer-setup` and `discover_repo` (developer tools), and the binaries that are not on the builder and parse no arguments,
    which would start on `--version`: gitlab-observer, gitlab-consumer, build-processor, the
    logger, polar-healthcheck and polar-custody's daemon. Each is one line, `polar_version::exit_if_asked("<name>")`, or nothing
    once it moves onto the builder.
  - polar-scheduler-observer and polar-scheduler-processor: Running on the cluster, 0 restarts (2026-10-14), and the checks of the
    list above (survives a broker restart, drains on SIGTERM) are not recorded for them.
- [ ] **PROTOCOL HANDLERS: AGENTS' I/O IN INFRASTRUCTURE** (decided by the maintainer, 2026-11-02; `docs/architecture/protocol-handlers.md`).
  Handlers for HTTP (with the registry scheme), git and the Kubernetes API in the builder's infrastructure, for the domain side, on behalf of a domain actor
  that declares its credential and registers its operations at load. The handler gets the credential from the `CryptoActor` itself and calls the callback with
  what came back; nothing domain code can call answers with a credential. A request is judged and logged; an arbitrary one is a declared permission and carries no
  credential. Not the credentials agent or cert-issuer. Step 4 of the order of work. Built, 2026-11-04: the framework, HTTP and its registry scheme, git and the Kubernetes API, with jira-observer, the resolver, the git observer, the Kubernetes observer and the attestation agent on them, and the old routes to a credential closed. For the customer's migration: a `credentials` section for jira-observer must name its entry `jira`, as the seed does; one hand-signed under another name registers, and the agent holds `Credentials` and says so until it is signed again. And the resolver no longer reads a Docker config: each private registry's login becomes an entry of its signed `credentials` section (`polar-sign`), with a host pattern naming the registry and, if another, the auth host (`*.docker.io`, `registry.gitlab.com,gitlab.com`). Docker's `auths` keys cannot be carried over as they are, and a helper's identity token still has no form here. A credential for a registry in `OCI_INSECURE_REGISTRIES` is no longer sent at all: it goes over nothing that is not encrypted. The Secret `oci-registry-auth` is no longer made or read: delete it from a running cluster.
- [x] **A signed list cannot hold entries with different fields** (seen 2026-11-04; fixed 2026-11-06, bite 7: `polar-sign` writes a field one entry leaves out, or gives as null, as `None` and the rest as `Some`, and every reader takes it back as null, as the git controller's `repositories` and the `credentials` section already did). `polar-sign` renders to Dhall, whose lists hold one type, and refuses a `null`, so one `repositories` version cannot name a repository with a `credential` and one without, though `git-controller.md`'s
  example does. The same goes for a `token` and a `user-password` in one `credentials` version, since only the second has a `username`, unless the token names one too. For repositories there is no way round it today. The fix is in how `polar-sign` writes an optional field the scaffold declares, as `None`, and how the reader takes it. Not done: outside the handlers.
  **Completed 2026-11-07:** the 11-06 fix wrote the `None` but signed the body as given, so such a document did not verify ("the signature does not verify":
  the GitLab observer refused its `sources`, a source with no `paging` beside one with); `sign_to_dhall` now signs the payload as the Dhall it is written as
  evaluates, what every reader sees, with a test and a property that sign and verify.
- [ ] **`decrypt_on_behalf_of` reads the requester's certificate as RSA** (`credentials-agent/consume/src/decrypt_on_behalf_of.rs:109`, seen 2026-11-04), as `retrieve_secret` did until it was fixed. It reads the mTLS certificate, not the escrow one, so whether it should seal to that at all wants a look before it is changed. Nothing on the builder's side calls it yet.
- [ ] **Breaking, for the migration notes:** the git observer no longer follows a redirect to another host, and reaches only http and https (`protocol-handlers.md`). A repository that relied on either fails and says so; the address in its `repositories` entry is what to change.
- [ ] **The resolver cannot read images from the node's registry** (seen 2026-11-03; the same before and after it moved to the handler). On a cluster whose registry is in the cluster, images are named `localhost:30500/...`, which is right for a kubelet and means nothing in a pod: each read fails with `tcp open error: Address family not supported by protocol`, an error is logged per image, and Polar's own images never become `OCIArtifact`s, only those from public registries. `OCI_INSECURE_REGISTRIES` is given the same name, so the target thinks it is handled. It needs the registry's address from a pod, as a mapping from the name the image uses. Not done: it is its own change, and it is what provenance of Polar's own images on this kind of cluster depends on.
- [ ] EVERY AGENT'S NON-SECRET SETTINGS DYNAMIC (the maintainer, 2026-11-01: an agent whose own non-secret settings are
  Static "hasn't been properly migrated to the builder"). Control travels as signed configuration at run time, and only
  a Dynamic variable can be changed by a signed update (`polar-agent-builder/src/configuration.rs`), so a held agent
  (`held::stay_up`) or a running one cannot be mended without a restart while its settings are Static. Done for
  jira-observer (`e0901170`: `JIRA_URL`, `JIRA_ANONYMOUS`, `JIRA_DEPLOYMENT`, `QUERY_DATE`; egress stays Static, the
  cluster's setting). For each other agent: declare its own non-secret settings `.dynamic()`, and have it take a
  `ConfigChanged` naming one (read `current()` again, start what depends on it again); a secret travels as a signed
  runtime section, as the git observer's and jira-observer's credentials do. docs/architecture/soft-state.md, "A held
  agent tries again on a signed update".
  *Scope (the maintainer, 2026-11-02):* stays Static for now: paths, sockets and bind addresses (the deployment mounts or binds them); the
  channel, `BROKER_ADDR`, `CASSINI_SERVER_NAME`, `POLAR_SCHEDULER_REMOTE_URL` (a wrong value cuts off the path its correction arrives on);
  and the trust settings, `CERT_ISSUER_ISSUERS`, `CERT_ISSUER_INTERNAL_CALLERS`, `POLAR_GIT_SERVER_ADMINS`,
  `CREDENTIALS_AGENT_BOOTSTRAP_IDENTITY`. Designed and cleared 2026-11-04, `docs/architecture/dynamic-settings.md`: the actor that holds a value follows it (`ConfigurationHandle::follow`,
  `follow_group`), an update nothing follows says so in its outcome, `dynamic_settings_problems` is the shared check, and `PolarAgent::SETTINGS_JUDGE` refuses an update that would break working settings.
  Built and checked live 2026-11-05. Since 2026-11-05 an applied document replaces the one before it, and a running agent can be asked what is in force, with a file to edit written from the answer (that document, "Asking an agent what is in force"); a library since, with the groups `config-readers` and `config-writers` saying who may. **Left:** a refused version still replaces the good file in the repository, so a restart then comes back on the rendered values: it needs a check before signing or before the merge. **For the customer's migration:** sign a next version of the policy with the two new rules to be able to ask, and anyone signing documents that name only what they change now loses the rest at once rather than at the next restart. The broker has no way to hear an update (the subscription exists only for a Cassini client, `infrastructure.rs`), so its tunables stay Static until that is its own change. Its logging would not reload anyway: it starts `cassini_tracing`, not `polar::logging`.
  Seen on the way: `CASSINI_QUEUE_PATH` is read from the process, not the snapshot (`cassini/client/src/lib.rs:128`).
- [ ] Builder: graph controller as infrastructure via `.with_graph_write()` (builder owns the spawn, `GraphSignal` wiring and flush), builder-owned shutdown handshake boilerplate so a migrated agent cannot forget its half; then migrate kube-consumer, jira-processor and credentials-agent to it
  Since 2026-10-12 the graph start, stop and drain are shared in polar-agent-builder (`graph.rs`).
- [ ] **cert-issuer's `conf/` describes a file it no longer reads (found 2026-10-23).** `src/agents/cert-issuer/server/conf/dev.dhall` and `cert-issuer.dhall` render the JSON configuration file cert-issuer read before it moved onto the builder (and were already out of date: one `issuer`, where it reads a list). Its settings are declared variables now (`settings.rs`; `cert-issuer --help`). Remove them, or replace them with a development configuration document for `--config`, once the move onto the builder and into the catalog is complete and validated by testing (the maintainer, 2026-10-23).
- [ ] **Scaffolding a new agent** (ideas of 2026-10-07 and 2026-10-09; the first is the catalog-entry half of the second and should
  be built with it):
  - NEW-AGENT SCAFFOLDER (idea, 2026-10-09, on seeing `hello_agent --help` and `--scaffold`): a tool that creates a new agent crate: a cargo project with the `PolarAgent` implementation, `polar_agent_builder::run::<A>()` as its main, the `polar_agent_tests!` macro, a `settings.rs` for its own variables, the `disallowed_methods` lint and `clippy.toml`, the image row in `images.nuon` and the nix package entry, and a catalog entry (`config: "document"`) so that it renders and deploys from the first commit. The facts it would start from are all in the code now (`examples/hello_agent.rs` is the smallest working agent, `kube-observer` the smallest real one). Questions for when it is taken up: where it lives (a `cargo xtask`, a nu command next to `resolve.nu`, a `cargo generate` template), whether it asks for capabilities and sections or takes flags, and how it keeps itself in step with the agents as they change (a test that scaffolds into a temp directory and builds it would do). Not the same as the older `resolve.nu new-workload` scaffolder for catalog entries, below, which this would absorb
  - A scaffolder: `resolve.nu new-workload`, which asks what the agent needs (capabilities, image, kind), writes a draft `.nuon` entry with only the real overrides, runs the checker on its resolved environment, and reports what is still missing (the checker names each unset required variable and what it is for) until the check is clean. Secrets are asked for by name and key, never by value; defaults are shown and not written. The gap it fills is what the capabilities do not already provide. Needs `--describe` in machine-readable form, the capability-to-section mapping, and, for the agent-specific variables and the minimum drain budget, the agent's own `--check`; until then it would have to ask for those. Idea from a side conversation, 2026-10-07. UPDATE 2026-10-09: what it needed now exists (`--scaffold` as JSON, the capability mapping, the agent's own `--check`), and a catalog entry is now four lines (`name`, `kind`, `image`, `config: "document"`) plus `provides` and the like where the deployment gives more. It is the catalog-entry half of the NEW-AGENT SCAFFOLDER and should be built with it
- [ ] **SELF-DESCRIBING AGENTS, what is left** (decided 2026-10-09: the code is the source of truth, and the binary produces its own
  scaffold; rejected: committed per-agent contract files and a hand-kept SPEC; design `docs/architecture/configuration.md` section
  9, `docs/architecture/configuration-flow.md`). Built and on the cluster: `polar-env`'s `Document`, `FileEnv`, `Source::File`,
  `from_environment` (the document `POLAR_CONFIG` names), `ProbeConfig::from_environment`; the `PolarAgent` trait, `run::<A>()`,
  `--help`, `--scaffold [--config FILE]`, `--check --config FILE`, `polar_agent_tests!`, `examples/hello_agent.rs`; `infra/document.nu`,
  `POLAR_SCAFFOLD_DIR`; `polar-config-check` retired. Left: `resolve.nu`'s `config: "document"` is now only a guard and could go, and
  no test refuses a non-document workload (the resolver reads the real catalog; a test would need a fixture catalog);
  `InitMountEntry` has no `read_only` (polar-init's CA mount is no longer read-only: add one if that matters); the catalog-bypassing
  workloads are their own item, under configuration.

## Configuration, signed configuration and polar-env

- [ ] TYPED RUNTIME DOCUMENTS FROM THE DECLARATIONS (decided by the maintainer 2026-10-31). `polar-sign` renders a
  runtime section from the agent's declared body type (its scaffold), so a missing optional field in a list entry
  becomes `None T` and a present one `Some x`, and the scheduler reads them back as absent. Today (since `50baf2f6`)
  polar-sign refuses, at signing, a list whose records set different fields; Dhall already refused them at the
  scheduler. Affected: git `repositories` (`credential`, `refs`, `shallow_depth`, `max_depth`, `frequency_secs`) and
  git-observer `credentials` (`username`). It is the start of the typed Dhall templates generated from the declarations
  that runtime sections were meant to have (git-controller.md, "The `runtime` document type", not built).
- [ ] **A read of the configuration actor waits behind a judgement** (found 2026-10-31 fixing `submit`'s timeout, not fixed).
  The actor judges a runtime document inside its handler, so a read sent meanwhile (`runtime`, `current`, `history`)
  waits for the judgement and fails after `CALL_TIMEOUT` (5 s) if it is longer. In release builds a judgement is well
  under that today; it grows with the model (workloads, topics, persons). To do: judge off the actor's loop (keeping
  documents in order), or have the reader that matters (`pass_on_section`) retry instead of waiting for a republish.
- [~] **Signed configuration** (DESIGN WRITTEN 2026-10-11, `docs/architecture/signed-configuration.md`; original note 2026-10-07,
  `docs/architecture/configuration.md` section 6. Decision: both a signed document as the trust root, ONE Dhall file per item with
  `payload` and `signature` fields and no signature files, rendered to normal form and signed by `polar-sign`, and signed git
  commits for audit; typed templates generated from each agent's schema export; git server refusal of unsigned pushes to be a
  per-repo option; revocation planned with a seam; the email comes from the certificate's `mail`, which cert-issuer writes
  authoritatively; v1 authority is `c:update-policy`, Cedar later). Built: the library `src/agents/polar-signing` (canonical
  encoding, Ed25519 and ECDSA P-256, chain to a pinned CA); `ConfigurationHandle::submit(document)` as the only way in
  (`polar-agent-builder/src/signed.rs` and `configuration.rs`); delivery (the scheduler processor writes a
  `(:Schedule:Configuration {id})` node and publishes a `ConfigurationNotification` on `agent.<name>.configuration`); `polar-sign`.
  Open: imports in signed Dhall; revocation (a hook that says no today); git server enforcement (under security); addressing (a
  payload's `target.agent` is the receiver's service name for now; schedule ids and agent types are not mapped); which Dynamic
  variables need which authority. `credentials-agent-common`'s `admin_signing` does similar work for administrative actions with
  the same two key types; the two could share code later.
- [~] ConfigurationActor, SHELL BUILT 2026-10-11 (`polar-agent-builder/src/configuration.rs`, `AgentResources::configuration`; transactional, monotonic versions, history, change notifications, 8 unit tests and 1 through the infrastructure supervisor). NOT built: the subscriber that turns a `ScheduleNotification` on `agent.<id>.schedule` into an update, addressing, where `TimeSpec` fits, authentication of the publisher (signed configuration, below), and nothing declares a `Dynamic` variable yet. (idea and direction, 2026-10-07; design notes, not decisions): a per-agent actor under `InfrastructureSupervisor` that owns the agent's configuration, is how other actors get theirs, and later receives runtime overrides from the scheduler. It is the runtime shell around the pure layered `Config` that the next steps build in `polar-env`. The scheduler cut already in the repo (`polar-scheduler`): the git observer publishes `GitScheduleChange` to `scheduler.in`, the processor stores `ScheduleNode`s in Neo4j and publishes `ScheduleNotification` to `agent.<id>.schedule`, agents announce themselves on `scheduler.adhoc`; a node's `config` is an untyped `serde_json::Value`, and the mock agent's step to fetch the full schedule from the graph is commented out. Notes: (1) layers `default < environment < scheduled override`, each value reported with its source and the schedule version; (2) each declaration says whether it is `Static` (the default) or `Dynamic`; only Dynamic ones accept overrides and notify, so the code, not the repo, decides what may change at runtime (TLS paths, `BROKER_ADDR`, capabilities and the health safety invariants stay Static), and add the field when the layered `Config` is built since adding it later touches every declaration; (3) the environment layer is built before any actor (the Cassini client needs its own config) and cannot depend on Cassini; the remote layer attaches after the client registers, and the agent must run on the environment alone if the scheduler is down (the credentials agent serves identity and cannot depend on remote config to start); (4) updates are transactional: parse with the same declaration (a bad override is refused naming the variable), re-check the section relations on the candidate result, apply only if sound, keep the old value and report if not; (5) subscribers are told through an `OutputPort` message and re-read, not by closures run inside the actor; (6) secrets travel as references (name and key), never as values in git or on a topic [SUPERSEDED 2026-10-14: a secret travels as ciphertext in a signed document addressed to its agent, see `signed-configuration.md`, "Secrets in a document"]; (7) record applied and rejected changes as provenance events; (8) `--describe --json` is the schema export, so CI on the schedules repo can validate a schedule's `config` against its agent's declared Dynamic variables before merge; (9) keep the roles distinct: the scheduler agent publishes, the ConfigurationActor receives. Open: where the schedule's `TimeSpec` fits (probably a typed Dynamic value), and addressing (per agent id and per agent type)
  - Left of `polar-config-check --effective` (2026-10-07; `<agent> --scaffold [--config FILE]` replaced the binary): showing the
    effective view of a running agent, which needs the ConfigurationActor.
- [~] Scheduler kinds, PROGRESS 2026-10-11: all four decisions were confirmed (repository transport first). Built: `type` in every signed payload (a receiver accepts only its kind, checked first; the processor routes only `configuration` and writes the others as unroutable), the `c:run-command` capability (appended to the closed set), and the pure command verifier and time rules (`polar-agent-builder/src/command.rs`, 22 tests, five deliberate weakenings caught; it found an overflow in the window arithmetic). DECIDED (2026-10-11): configuration documents are gated on a new `c:update-configuration` (appended to the capability set), and `c:update-policy` stays for Cedar policy updates; a signer holding only update-policy is refused for configuration. NOTE: the first admin the `admin-provision` recipe made held neither `c:update-configuration` nor `c:run-command`, so could not sign either. FIXED 2026-10-12: the recipe now grants both (capabilities are fixed when the certificate is issued, so an account provisioned before this does not have them: provision another, or wait for the reissue action). AGENT SIDE OF COMMANDS BUILT 2026-10-11 (declaration in `PolarAgent::COMMANDS` and the schema export, `with_command`, the `CommandActor` with its checks, timeout, drain and interruption handling, built-in subscription and outcome publishing on `polar-command-outcome`; 40-odd tests, eleven weakenings caught; nothing run on a cluster, no agent declares a command yet). Next: the scheduler's command ledger and graph writes (dispatched mark, unanswered sweep, the outcome nodes), the repository transport for commands, then proposal decision procedure (pure function, attack list first), admission documents. Original note (2026-10-11; design `docs/architecture/scheduling-kinds.md`): three different things, not three directories. Configuration (signed desired state, the only kind the repository holds; delivery built), Proposal (an agent-to-agent event with admission rules at the receiver; the rules are themselves signed repository content, a distinct kind of scheduler repository specification, and agents subscribe to the proposal kinds they care about; credentials bound to host patterns; pending until a credential exists; removable by an admin; Cedar for "X may propose K to Y"), Command (an admin action with a unique id and an expiry, not a repository file; the agent remembers ids it has run and reports success or failure; the agent declares the commands it accepts in its schema export). Principle: EVERY scheduling event (repository update, proposal, command) writes an observable graph node on receipt and its outcome later. In order: (1) configuration delivery [done], (2) outcome events [done 2026-10-11: the ConfigurationActor announces every document it handles, the infrastructure publishes it on `polar-configuration-outcome`, the processor writes a `(:Schedule:ConfigurationOutcome)` node per event linked `HAD_OUTCOME` from the item, with `reported_by` kept apart; not run on a cluster; a tool for an author to read their refusals from the graph is not built], (3) a proposal design and a command design [WRITTEN 2026-10-11: `docs/architecture/proposals.md` and `commands.md`, each with a sequence diagram in `docs/architecture/sequences/general/`; each ends with decisions to confirm; nothing built], then their code, tests first, (4) retire the old `adhoc` and `ephemeral` handling and the samples (today `adhoc` is an agent type announcing a default schedule on `scheduler.adhoc`, and the `ephemeral` sample is an event-triggered rule that does not even have the `ScheduleNode` shape; nothing outside the scheduler publishes either)
  - Not verified (2026-10-12, after the `ScheduleKey` fix `f7c549fa`): the outcome nodes and `HAD_OUTCOME` edges in the graph.
- [ ] SCHEDULER AGENT, reconciliation as the answer to a lossy broker (direction, 2026-10-09; the scheduler agents have been on the builder since 2026-10-10, so this is now a note for the reconcile design). The scheduler's reconcile loop should not only react to changes (a privileged admin changing a repo or a schedule, which happens sporadically); it should also, periodically, send EVERY agent the state it should be operating in, as the scheduler understands it from the live configuration: desired state, re-asserted on an interval, so drift is corrected and anything the broker dropped is repaired. That closes the gap recorded under the accepted limitations of the best-effort broker for this class of message (an event that is sent once, when a change is made, and that nobody otherwise re-observes), and it is the pattern that makes the broker's best-effort delivery safe by construction: every state-carrying message is repeatable. Requirements this puts on the receivers: applying the same desired state twice is a no-op (idempotent apply), and a message carries the whole desired state for its recipient, not a delta, so a lost one costs at most one interval. The interval is a decision (how long may an agent run on stale configuration); it should be configurable and carried in the schedule configuration. Related: the signed-configuration and ConfigurationActor items in this section, which are where the desired state comes from
- [ ] Port the rest to `polar-env`: `lib` (proxy CA, Jaeger tracing), the Cassini client's CLI daemon variables, and each agent's own variables (`JIRA_*`, `OPENAPI_ENDPOINT`, credentials agent). Agent-specific ones become declarations the agent hands the builder, not code in the checker. UPDATE 2026-10-09: done since: the Jira variables, the credentials consumer's nine and the observer's port are declared. Left: `lib` (proxy CA, Jaeger tracing), the Cassini client's CLI daemon variables, `OPENAPI_ENDPOINT` and the agents not yet on the builder
  - `polar-env` facts left by the steps of 2026-10-07 (`docs/architecture/configuration.md`): un-migrated agents still start the
    health actor with no config, so it reads the process for them until they move; `kube-api-read` brings no section yet
    (`polar-agent-builder/src/environment.rs:108`); judging the init container's environment at render time is not done
    (`polar-init` could answer a `--check` flag with the same ERROR lines, run by `resolve.nu check` with the init container's env,
    which the Dhall template builds and the catalog does not hold yet); `cert-client`'s `HandshakeClient::ca_path_from_env` is still
    read by the credentials consumer; a developer shell that exports `GRAPH_*` hides a test that only asks for success, so tests of
    a source choice must look at the value used.
  - The direct-read lint (`clippy.toml`, `#![deny(clippy::disallowed_methods)]`): each crate that moves onto polar-env copies in
    `clippy.toml` (keep the files identical) and adds the attribute; about 90 direct reads in 36 files were left to port on
    2026-10-07; `polar-crypto`, `polar-init`, `lib` and the agents' own variables were the bulk.
  - Controlled process environment (wanted as a security and correctness property, 2026-10-07): the builder snapshot copies only declared variables, so an undeclared variable never enters the agent and later changes are not seen. Keep it true as steps land: nothing reads the process environment after the snapshot, enforced by the `disallowed-methods` lint, and `<agent> --scaffold --config FILE` shows exactly what the document gives
- [ ] Use the `--scaffold` JSON (the schema export) for scaffolding and validation beyond the workload scaffolder: scaffold a schedule from an agent's declared Dynamic variables, and validate a schedule against them in CI on the schedules repository before merge. The export exists (`<agent> --scaffold`); this is the uses that are not built
- [ ] Env precedence: a target `workloads.<name>.env` entry whose name the catalog also derives (seen with `POLAR_HEALTH_TICK_SECS`) is rendered twice and the later, derived value won silently (kubectl warns `hides previous definition`). Decide the precedence (the target should win) and make `resolve.nu check` fail on duplicate env names within a resolved workload
- [ ] WORKLOADS THAT BYPASS THE CATALOG (recorded 2026-10-09; UPDATE 2026-10-10: the credentials pair, the Cassini broker and the OCI resolver have since moved into the catalog, so the list below is out of date for them; not the focus now: first make the interaction right for the agents that use it). As first recorded, only `kube-observer`, `kube-consumer`, `jira-observer` and `jira-processor` were in `infra/config/workloads/` (2026-10-14: it holds sixteen workloads, the list of agents done is in the builder item). Hand-written charts under `infra/layers/`: the credentials agent consumer and observer (both on the builder, so they could move), the Cassini broker (not on `polar-env`; budget and grace margin written by hand in `deployment.dhall`), `polar-init` (an init container of every agent; its arguments are generated, its own environment is declared but it has no description mode), ace, cert-issuer, Neo4j, Postgres, Keycloak, Jaeger. The agents not on the builder were (gitlab, git, scheduler, openapi, build-processor, resolver); as of 2026-10-14 only gitlab, openapi and build-processor are in neither the catalog nor the builder, and their migration comes first. For each bypassing workload the cost is the same: its numbers and variables are tied to its code by convention or by the runtime check alone, so nothing at render time catches a mismatch
- [ ] **Configurable cluster domain:** `cluster.domain` in `infra/config/cluster.nuon` now drives catalog addresses; still hardcoded
  in the Dhall charts and not passed to polar-init. Pass `--cluster-domain` to polar-init from `cluster.domain`; derive polar-init env
  (now `Constants.commonClientEnv`) from the cassini capability. UPDATE 2026-10-09: the `init` facet (environment and mounts for
  polar-init, per capability) is the place for the second half; not done.
- [ ] Move other agents' RBAC (`ace-rbac`, etc.) into the `resources` facet; add further facets as needed (the resolver check enforces every capability answers every facet)
- [ ] Derive `apply_order` from the catalog (resources before the Job) instead of the hand-typed list in `target.nu`
  Done for `local-minimal` and `sandbox-local` (`apply_order` adds up their `apply_layers`); `local` is typed by hand.
- [ ] Replace the `render.nu` `match $chart_name` table (the remaining arms mostly pass the same four values) with data
- [ ] Gitignored local overlay for per-developer values; a second target's `config.nuon`
- [ ] `local` vs `local-minimal` drift: `polar_init_image`, `identity_lifetime_overrides`, and `local` lacks postgres/keycloak/ace; and
  `targets/local/config.nuon`'s `OCI_INSECURE_REGISTRIES` (the legacy `local` target) was left alone by the one registry setting
  (`infra/registry.nu`, 2026-10-19).
- [ ] Evaluate an existing policy or constraint language for the config rules (decided not to build one): Rego with `regorus` (a Rust interpreter, 0.12, MIT, passes the OPA conformance suite apart from some builtins; a pre-1.0 API; about 1.9 MB with default features off), CEL (what Kubernetes `ValidatingAdmissionPolicy` uses), or CUE. Trigger to do it: the rules grow beyond a handful, rules need authors who are not us or a regulator to audit them, or we want admission-time enforcement in the cluster. Prerequisites: the agent exports its declared requirements as data, and the defaults have one home. Also considered and set aside: embedding Nushell in the agents (pre-1.0 engine, version coupling with the devshell, heavy, a shell in every startup path) and an in-pod Nushell preflight using `polar-nu-init` (still runtime, still duplicates the Rust check, cannot see the code's declarations)
- [ ] (see "possibly obsolete") (Design note: `docs/architecture/configuration.md`.) Credentials agent as the main consumer of scheduled overrides, 2026-10-07 direction: secrets from the schedules repo encrypted to the credentials agent's public escrow key (the repo holds only ciphertext), policy from the repo applied to the decisions the credentials agent makes, and overrides authored by a privileged user. It starts on its environment alone and takes these when they arrive. Needs the ConfigurationActor and the scheduler integration first. Open design questions, to settle before building: how the receiver authenticates who published an override (a writable topic is not authorization; likely the publisher's identity checked against policy, which `polar-policy`/Cedar already wraps); monotonic versions so an old override cannot be replayed over a newer one; failing closed (refuse) until a policy has arrived; and for other agents, secrets as references and not ciphertext on a topic [SUPERSEDED 2026-10-14: ciphertext in a signed document addressed to the agent; see `signed-configuration.md`]

## Infra and up.nu, images and release

- [ ] **`infra/tests/resolve.nu`'s "every wait of a target's layers names a workload its render makes" fails on main** (found 2026-11-07, run against u7s's
  scaffolds with `POLAR_TEST_CLUSTER_KUBECONFIG`; 86 of 87 pass on `f1d60e13`, and the same one fails with the GitLab test material too). It says "These are not
  equal" for `sandbox-local`: one of the target's layer waits names something the render did not make, or a render step failed. Not looked into.

- [ ] **A SERVICE DEPENDENCY GRAPH INSTEAD OF LAYERS** (the maintainer, 2026-11-02: agents declare their dependencies and the infrastructure works out the order, "no need for shit like layers"; and it holds what each requires, out of the catalog,
  so that a controller can enforce the catalog's intent). The design, with its two kinds of edge, is in the GitOps controller proposal (`docs/architecture/gitops-controller.md`, on its branch until vetted). It can be proved on Flux first, by generating `apply_layers` and `dependsOn`. Where it falls in the order of work is open: suggested after the handoff.
- [x] **HANDING OFF TO POLAR'S GIT SERVER** (the maintainer, 2026-11-02: the bootstrap repository is for the bootstrap; Flux follows a copy on Polar's git server, and the bootstrap
  server is removed). Done 2026-11-02, on u7s and u7c, with both recoveries run on purpose: `docs/architecture/cluster-bootstrap.md`, "Handing off to Polar's git server". The push is now where a deployment commit's signature is checked. A customer's deployment moves by the migration plan below.
- [ ] **A migration plan for the customer's deployment** (the maintainer, 2026-11-02; no hurry, "quite a while to think about that one"). Brent does a clean install, so nothing is written for 3.0.0's test deployments. A customer's deployment needs a way across what has changed since: the handoff to Polar's git server, and a deployment PKI that moved from RSA to P-256, whose old commits the git server now refuses. To think about then: its signed history, which the provenance trail keeps, either by verifying the old commits again for that history alone or by a new root that names where the old one is kept. Also, since 2026-11-05 (`dynamic-settings.md`, "Asking an agent what is in force"): asking a running agent needs the next policy version with its rules and a first groups version naming who may read and write, since the seed only ever writes the first; and a signed settings document now replaces the ones before it at once, so one that names only what it changes loses the rest.
- [ ] **Why `cert-issuer` can still make RSA keys** (seen 2026-11-02, moving the deployment PKI to P-256; not read yet). `cert-issuer/common/src/keypair.rs:114` generates RSA 4096, and the workspace carries a fork of the `rsa` crate. If nothing needs it, both can go, with the RUSTSEC-2023-0071 ignore.
- [ ] **Switching this machine between clusters loses its admin state** (found 2026-11-02). `up.nu` moves `~/.config/polar-admin` aside when it holds another cluster's CA, and discards `cluster-inputs.nuon`, but coming back does not bring them back: the admin flow then fails with `BootstrapAlreadyDone`, and, before the handoff, the git server loses its administrator (a handed-off cluster's inputs now come back from its signed record, so that half is only for one not yet handed off). Restoring both by hand from the `polar-admin.old-*` that matches the CA worked. It could look for that itself. A person with one cluster never sees this.
- [ ] **`polar-schedules` has no copy off the cluster** (found 2026-11-02, deleting the git server's volume on purpose). `deployment` comes back from `mirror.git`; `polar-schedules` comes back as the seed's documents, and whatever people signed since is gone, with its history. It is the same kind of record: signed, and what the cluster's configuration is made from.
- [ ] **The configuration agent keeps a stale checkout after `polar-schedules` is rebuilt** (found 2026-11-02, same run). `pull_repo` refuses a history that diverged, which is right against a rewrite, and logs an ERROR on every pull: signed configuration stops reaching agents until the pod restarts, and nothing but that log says so. It should go to its health verdict, at least.
- [ ] **`mirror.git` and `images.dev.lock.nuon` belong to a machine and a target, not a cluster** (found 2026-11-02, u7s and u7c on one machine). A publish force-pushes the mirror, so it holds the last cluster published to; recovering another from it would give that cluster the wrong history. `images.nu sync` writes the dev lock, and the next render, for any cluster, pins it. Tied to the cluster's CA like `cluster-inputs.nuon`, perhaps; though a rebuilt cluster is given its mirror on purpose, so that needs a thought.
- [ ] **A publish can name a digest the cluster's registry does not hold** (found 2026-11-02, same run). `pin_images` reads the lock, nobody asks the registry, so the pods sit in `ImagePullBackOff` until `wait_pods` gives up; and if the git server is one of them, it stops the deployment's own path. `publish` should ask the registry first.
- [ ] **The deployment PKI's certificates last 365 days, and nothing renews them** (seen 2026-11-02). `ensure_pki` replaces one only when its names change, and after a handoff it no longer runs at all. `flux` and `pipeline` expiring stops Flux reading and new commits verifying.
- [ ] **`polar-init` keeps a certificate about to expire** (found 2026-11-02, u7s). `keeps_existing_bundle` kept one with 56 s left ("valid until 00:54:15" at 00:53:19), so the agent came up and restarted again about a minute later for a new one; `polar-scheduler-observer` had 9 restarts where its neighbours had 6 over the same time. It costs a restart and no harm was seen. It should ask for a new certificate when too little is left to be worth starting on.
- [ ] **Measure memory on one node again, settled, with the attestation agent.** The README's "about 9 GB" is from before it; 10.6 GB was read on u7s just after a rollout, which may not be its resting figure.
- [ ] **Carry the move off `local-minimal` in the next release's changelog** (retired 2026-11-02, `bfadf828`; the maintainer: "We'll recreate them
  later, if needed"; topology is now a setting on the target, `docs/architecture/placement.md`). The migration is `docs/operations/moving-to-sandbox-local.md`, tried
  in place on u7s. Brent stays on the `v3.0.0` tag until then, without `--import-tag`, which v3.0.0 breaks on Neo4j (fixed by `67b5a4fa`). GitLab, OpenAPI and
  build-processor have no target until each joins the catalog: to compare against what `local` deployed, `nu infra/render.nu local --charts-into <dir>` at `ad8712b5`.
- [ ] **Audit main for back-ports to `release/3.0.x`, later (the maintainer, 2026-11-04).** Only what Brent needs goes on that branch now. After more implementation and testing on `main`: every critical fix on `main` since v3.0.0 was tagged, and a list to consider, to stabilize the branch. Already in 3.0.1: `1a9485d3` (polar-init kept a certificate an agent would rejuvenate from at once), cherry-picked as `9d2fadb8`. Known candidate: `896b8b63`, only with `72169bdc` (its watcher rescanned without end, every scan's own reads asking for the next; found by the agentic-control-plane session) and `73a8e587` (a checkout folder starting with a dot was read as hidden) (the scheduler observer delivers a pushed file only through a filesystem watcher that dies in silence; hit by Brent on 3.0.1, 2026-11-06, where the seed's sealed Jira credential reached jira-observer only after `kubectl -n polar rollout restart deploy/polar-scheduler-observer`, and every later push will need the same).
- [ ] **Brent's clean install of 3.0.1 on a Mac, and what it found** (2026-11-06, minikube on Apple silicon, `local-minimal`, polar namespaces deleted rather than the cluster). It reads Brent's Jira with the token the seed sealed. On the way:
  - **The Mac's VPN holds the cluster VM's outbound connections:** the VM hands each connection to the host, TCP completes and TLS never answers. With it off the site was reached. `jira-check.nu` now says so (`c9f875df`, `f793cfd6`, both on `release/3.0.x`), and it read both `/proc/net/tcp` listings where the node has IPv6, which the machines it was tested on do not. The ace-tops `release/3.0.x` push waits on the maintainer's `sei-djshepard` login.
  - **v3.0.0's `polar-sign` refuses every agent's escrow certificate** (`af6e1afa`, in 3.0.1), and v3.0.0's credentials agent read the requester's escrow certificate as RSA too. Nothing could be sealed on a v3.0.0 cluster, so Brent moved to 3.0.1.
  - **macOS's `openssl verify` (LibreSSL) fails Polar's certificates** with error 53, "unsupported or invalid name syntax", with no name constraints in the CA: it checks the syntax of every name in a certificate, and ours carry names it does not parse. Harmless to the Keychain import; the pair can be checked by its key identifiers instead. Which name it trips on is not confirmed.
  - **Writing a token through fish's `read` into `polar-sign` damaged `creds.json`**, as Brent reported; `polar-sign` never writes its input, so how is not known. The token was then typed into the file and the file deleted after.
  - The README's once-per-pod setup for `polar-sign` (step 8: forwards, git config, scaffolds) was skipped on the first try; its errors said what to run.
- [ ] **v3.0.0 cannot seal a secret, and Brent's first run from the dev container found what else a release needs** (2026-11-04). The `release/3.0.x` branch on gitea is v3.0.0 with two commits and the same images: the seal (`868198e9`, `polar-sign` refused the escrow certificates the issuer gives, since 2026-10-27), and `bin/polar-dev` copying your gitignored `user.sops.yaml` into the pod. Brent is on it. To decide: a v3.0.1 from it, which publishes images, and not while Brent is testing `latest`. Until then the bring-up doc should point at the branch rather than the tag. Seen on the way, all small:
  - A pod made before 2026-10-30 keeps `feat/ace-integration` in `/workspace`, since `polar-dev` clones only into an empty one. `up` could say when the pod's checkout is not the commit this machine has: Brent checked out v3.0.0 on the Mac, and the pod carried on at 2026-10-28 with v3.0.0's images, which failed as `unknown need 'soft-state'`.
  - `up.nu`'s pause at the browser step speaks only of Librewolf and `bin/polar-dev cert`, and that command stops with an error when it finds no profile. The README's Keychain steps are right for a Mac with Chrome: the pause and the error should say so.
  - The `cert` step stops the run for what is only needed for a browser. Pressing Enter at it is fine, and that is not said.
- [~] **`up.nu` must notice a state it is about to crash on, and either stop and say the way out or resolve it itself** (2026-10-14,
  after a fresh-cluster bring-up on a second workstation took five resume loops, each a different stale state that a check said was
  fine). Tests first, in `infra/tests/`, each rule broken on purpose. Kept as the model: the stale `~/.config/polar-admin` check named
  the problem and gave the exact command. Done: forwards probed (`forwards.nu`), the browser and Neo4j check (`browser.nu`,
  `tests/browser.nu`), the initial password from `NEO4J_AUTH` (nix-neo4j `0a8ba5f`, `e1ad68a`). Left:
  - The admin flow failed on an unreachable observer with a raw `error sending request for url`; it should say what it is doing, as
    `forwards.nu` now checks the forward first.
  - The admin step refuses to continue while `~/.config/polar-admin` holds material from a previous cluster and tells you to `mv` it
    aside (first real run on a fresh cluster, 2026-10-06, steps 1-8 passed once the SOPS variables were right). That is correct but is a
    human step in an otherwise unattended run; consider detecting it in the plan up front, and say so in the plan.
  - `up.nu` provisions with `bootstrap-admin` by default, which a cluster's first provisioning spends, so an existing cluster needs the
    signer named by hand (`BootstrapCertificateSpent`, 2026-10-12).
  - `up.nu` does not restart a StatefulSet for a rebuilt image (still open 2026-10-14; Neo4j was restarted by hand).
  - (see "possibly obsolete") Where a warm `up.nu` resume still spends its 28.0 s (measured 2026-10-14, `infra/INFRA.md` "The render cache"; by subtraction): about 12.6 s rendering the eight custom charts, which are not cached; about 8.2 s resolving each catalog workload twice (about 0.25 s each: it pulls the image and runs `--scaffold`) and reading the cache; about 7.2 s for the applies, their comparisons with the cluster, the checks and the waits. The same recipe as the manifests would cache the charts (a key over the chart's directory, the overrides and the context); the resolving could be cached by the image's digest (the scaffold is a pure function of the image) or skipped for a workload whose inputs are unchanged. Measure each before building it: the cache of the catalog took a 55 s render to 8 s, and these three together are the remaining 21 s of 28 s.
- [ ] **The Flux target, what is still open** (`sandbox-local`, built and run 2026-10-19; `docs/architecture/cluster-bootstrap.md`,
  `infra/INFRA.md`; `infra/up.nu`, `infra/flux.nu`, `infra/agent-pods.nu`, `infra/tests/layers.nu`, `infra/tests/render-determinism.nu`):
  - SOPS-encrypted secrets in the repository: not built. The CA, the admin flow and the schedules seed stay imperative; `git revert`
    rolls back manifests only, not data, secrets or certificates.
  - `local` and `local-minimal` as gitops targets; `local` has no layers yet (stage 2; `infra/layers.nu`).
  - The agents' `ndots` (Polar-side hardening against search domains; see the cluster DNS item, under the dev environment).
  - Render time: an agent's scaffold is cached by image digest and the charts go through the same cache (`infra/dhall-render.nu`), so a
    warm render is about 12 s (a render with no cache at all is still over a minute). Not done: resolving all workloads in one process.
- [ ] **Images and registries, what the registry work left** (2026-10-19; `infra/registry.nu`, `infra/images.nu`, `infra/lock.nu`; the
  registry's authentication is under security): `--import-from` on a fresh cluster; pulling from a registry that needs credentials
  (Docker Hub answers no digest without a token); Neo4j in `images.nu import`.
- [ ] (see "possibly obsolete") **The pull policy and moving tags** (the hazard was `IfNotPresent` + `:latest`; mitigated by `images.nu`
  dropping each node's cached copy, every node of a nix-usernetes cluster since 2026-10-27; `Always` (`kinds.nuon`), `rules.nu` `pull_policy_problems` and
  `report_stale_images` since 2026-10-19). Not done: removing `evict_row` (wait until `Always` has run on a real cluster); a direct-load
  cluster (`just cluster-load` of an image that is not in the registry) now needs the image in the registry too; jaeger, keycloak and
  postgres keep `IfNotPresent` (upstream version tags). Optional later: render injects image tags from `images.nuon` into the Dhall (single
  source of truth); content-hash tags would end the hazard for good.
- [ ] The Neo4j image's label (found 2026-10-27): `infra/images.nuon` gives the external `neo4j` image the tag `5.26.2`,
  but the image it points at (`~/Documents/projects/nix-neo4j/result-neo4j-image`) is Neo4j 2025.08.0 built from source
  (`nix-neo4j/pkgs/neo4j-from-source.nix`). What is pinned and what is run should say the same.
- [ ] Publishing images for another architecture is emulated, and slow (found 2026-10-28, publishing for `arm64` from
  `x86_64`): `images.nu publish --arch arm64` builds `.#packages.aarch64-linux…`, whose `rustc` runs under the builder's
  binfmt emulation of aarch64, and each agent's image compiles the shared workspace crates again; image 1 took about
  half an hour and the rest some ten to fifteen minutes each. Cross-compiling (an `x86_64` compiler targeting aarch64,
  in the flake's image builds), and building the shared crates once for every image, would make it a fraction of that.
- [ ] **The browser certificate install supports Librewolf alone** (found 2026-10-28, writing the Mac steps; the maintainer: "the browser
  certificate installation script(s) probably need rewritten to support normies"): `infra/user-cert-install.sh` (run by `bin/polar-dev
  cert`, `just user-cert-install`, and `up.nu`'s browser step on the user's own machine) imports into a Librewolf profile's NSS store. Most
  people use Safari, Chrome or Edge, which read the operating system's store (the macOS Keychain; on Linux, Chrome's `~/.pki/nssdb`;
  Windows' own), or Firefox's profile. Until it is rewritten, the README gives the steps by hand (**On a Mac, with minikube**, step 5), and
  `up.nu`'s browser check (`infra/browser.nu`) still looks at Librewolf. A Chromium variant of `user-cert-install` (`~/.pki/nssdb`) was to
  be tested by someone else.
- [ ] **One `infra/tests/resolve.nu` test fails against a cluster whose images predate the code** (2026-10-30): "workloads
  still asking cert-issuer are listed as pending while the floor is off, and refused once it is enforced" fails at its
  floor-off `check` with "the agents could not judge their documents: Eval block failed with pipeline input"
  (`resolve.nu:761`, `agent_checks`, which runs each agent's `--check` as a pod in the images the cluster's registry has).
  It fails the same on `feat/ace-integration` before the egress change (1 of 65) and after (1 of 69), run against u7c,
  whose images are the day before's. The rest of the file passes there; with no cluster it cannot run at all (it asks
  the agents' images for their scaffolds, or takes `POLAR_SCAFFOLD_DIR`). To do: find which agent's check fails on that
  target (the test's own `cert-issuer` and `jira-observer` overrides are the suspects), and make the error say which.
- [ ] **`src/deploy/`: remove it once nothing renders it.** Dead, but `scripts/pipeline/render-manifests.nu` renders its tree for Flux, and
  `cyclops.yaml` (the removed build orchestrator, under `src/agents/build-orchestrator` in history) is its config; a colleague's branch may
  bring cyclops back. Remove it with `scripts/polar-init.nu` and `scripts/setup-neo4j.sh` once the Flux target replaces
  `render-manifests.nu`. `src/deploy/local` (the old Dhall deployment) still names `git-agent-local.yaml` and `GIT_AGENT_CONFIG` for the
  observer.
- [ ] **What a release leaves** (2026-10-16 and 2026-10-31; `infra/release.nu`, `infra/semver.nu`, `infra/changelog.nu`, `release-baseline.nuon`, v0.1.0 before the first conventional commit, af152e6):
  - Enforcing conventional commits on the server, since the local hook let 225 through; whether the dev-env commit should be overridden as
    not breaking the platform (`release-overrides.nuon`). A `.mailmap` was not made: it needs email addresses.
  - `[workspace.package] version` in `src/agents/Cargo.toml` (1.0.0) is not the platform version and a release does not
    change it; nothing reports `CARGO_PKG_VERSION` any more. Bumping it would change `Cargo.lock` and every crate at a
    release, which the release changes anyway; decide whether it follows VERSION or is left as it is.
  - (see "possibly obsolete") `service.version` from the digest (stage 3a, 2026-10-16).
- [ ] `up.nu`: `job_verdict` calls a changed Job template "could not compare it with the cluster" when `kubectl diff` exits 2, which is what an immutable pod template change does (seen on the cluster: the Cassini Job, "spec.template: Invalid value ... field is immutable"). The behaviour is right (restart) but the message is wrong; say "its pod template changed"
- [ ] Justfile: Neo4j password helper; cluster status/health recipe; check `cluster-ctx`/`cluster-reset` against what `up.nu` expects
- [ ] `images.nu`: confirm `result/` is gitignored; check nothing else reads the old `result-*` symlinks (docs, other recipes); old digest entries accumulate in the node's image store
- [ ] `maxLayers = 20` in package.nix files to speed up containerd image loading
- [ ] Slim `polar-init` (was blocked on nix-container-lib Shell selection)
- [ ] `clusterrolebinding/kube-observer-read` printed `configured` on both applies even though `kubectl diff` is empty afterwards; confirm a later apply says `unchanged`
- [ ] (see "possibly obsolete") `build-orchestrator` Dhall config wiring (`cyclops-k8s.dhall`, `cyclops-podman.dhall`)

## The dev environment

- [ ] **The dev host's storage.** About 750 GiB of the `nix` volume group is unallocated, `/` is a 199 GB f2fs on a 400 GB volume (never
  grown; f2fs grows only unmounted), and the nix-usernetes node's containerd and kubelet state share `/home` with everything else, so a
  large Cargo `target` directory tainted the node with disk pressure and evicted every pod (2026-10-21). A volume of its own for the node's
  state would stop builds evicting the cluster. **The node flapped in and out of disk pressure for hours (2026-10-26/27), evicting 252
  pods:** `/home` at 86% sat under the kubelet's 15% image-filesystem threshold; freed by pruning podman's unused images and volumes,
  `nix-store --gc` and `cargo clean` (Polar's `target`, 139 GiB). Nothing warns before the threshold is crossed; see "Host storage to fix"
  in the maintainer's notes. The unused anonymous podman volumes come back with every `cargo test` that starts a Neo4j container (2026-10-12).
- [ ] **A test runner for the Nushell tests, as `cargo test` is for the Rust ones (the maintainer, 2026-10-26).** It
  finds the tests itself and runs the whole batch or any part of it: one file, or the tests whose names match a filter,
  as `cargo test <filter>` does. Today there is no runner at all: `infra/tests/` holds 39 files, one per script
  (`infra/INFRA.md`, "tests/"), each run by hand as `nu infra/tests/<name>.nu` and each printing its own summary, and
  the files do not share one shape (most hold a `let tests = { "<name>": { ... } }` record their `main` walks; about a
  dozen, `admin.nu`, `agent-pods.nu`, `browser.nu`, `cache.nu`, `deploy-objects.nu`, `deploy-repo.nu`,
  `dhall-cache.nu`, `lock.nu`, `neo4j-certificate-size.nu`, `seed.nu` among them, do not). Some need what others do
  not: `resolve.nu` needs the cluster, its registry forward and every image in that registry; `rules.nu` and
  `charts.nu` need nothing (`INFRA.md`). So the runner should also know what a file needs and skip it, saying why,
  when that is not there, as a Rust test that needs a container does. Then a `just` recipe, and where it runs before a
  commit (the gate, `just static-analysis`, or its own). Found 2026-10-07 with five files; on 2026-10-26 step 1 of
  closing the floor had to run all 39 by hand, and found one (`resolve.nu`, the floor-pending test) failing since
  cert-issuer became a catalog workload, which a runner in the gate would have caught.
- [ ] (see "possibly obsolete") Workspace clippy cannot pass `-D warnings`, so the `AGENTS.md` rule (`cargo clippy --workspace -- -D warnings` before a commit) cannot be met as written. Found 2026-10-07; the choice was to leave it for now and handle it after the health work. About 19 findings in five crates, all from the toolchain in use (nightly 1.101). `cargo clippy -- -D warnings` applies to every workspace crate it compiles, so the first failing crate (`polar-router`) stops the run, which is why it looks like one problem. Also: `cassini-types` did not compile its test target under it (2026-10-16). Whether the rule is expected to pass, per-crate clippy otherwise, was a decision asked in the builder plan. The list:
  - `polar-router/src/lib.rs:110`: `clippy::map_entry`, `contains_key` then `insert` on `state.registrations` (use the `Entry` API; keep the duplicate-registration error)
  - `polar-init/src/main.rs` (the CSR retry in `issue_cert`, about line 460): `clippy::never_loop`, a `loop` whose body always returns or breaks on the first pass, which is a deny-by-default lint, so clippy fails for the whole binary. Found 2026-10-07 when the lint was turned on there; not changed, since it is its own pass
  - `polar-agent-builder` (6): five collapsible `if` (four of them the nested `if let` in `infrastructure.rs` `ClientEvent::Registered`, one more elsewhere), one redundant closure
  - `cassini-client` (6): two `&PathBuf` where `&Path` will do, two `std::io::Error::other`, one collapsible `if`, one function with too many arguments (8/7)
  - `polar-crypto` (3): functions with too many arguments (8/7 twice, 9/7), which needs a real refactor (an arguments struct), not a mechanical fix
  - `lib` (3): `clone` on `Option<WireTraceCtx>` which is `Copy`, a non-binding `let` on a future, a doc list item without indentation
  - Do it as its own pass and commit, apart from any behaviour change (rustfmt and clippy on whole files is fine). `polar-health` and `polar-healthcheck` already pass `-D warnings` on their own
- [ ] **The dev container** (`bin/polar-dev up`, `infra/dev-pod`, 2026-10-19; image `docker.io/daveman1010220/polar-dev:latest-amd64`,
  nix-container-lib 5d02bc7/c3a8618). Not yet: a full up.nu bring-up from inside it; `cert` and `forward` on a machine other than this one;
  SIGTERM handling in the headless start.nu (the pod is killed after its 10 s grace); the port-forwards from the dev container on a Mac,
  where host networking is the VM's. `podman` is not in the dev container, so `--dev` with the host registry runs from the host (a mounted
  host socket might do; untried; 2026-10-16). Docker itself is untried for `POLAR_CONTAINER_RUNTIME` (`infra/runtime.nu`); the u7s steps stay
  podman-only.
- [ ] (see "possibly obsolete") **Cluster DNS (lives in `~/Documents/projects/nix-usernetes`, not Polar; do not change product code for it). Diagnosed, not fixed, and not being pursued now.** Two separate problems:
  - Search domain: the kubelet config sets no `resolvConf`, so every pod inherits the node's `search wifi.local.cmu.edu`. With `ndots:5`, each cluster-name lookup first tries `<name>.wifi.local.cmu.edu` through CoreDNS and waits for a timeout, about 4 s of startup delay in every agent. Repo-only fix: `resolvConf` pointing at a file with only a `nameserver` line, built into the image next to `etc/kubelet/kubelet-config.yaml` in `flake.nix`
  - External names: CoreDNS (`dnsPolicy: Default`, Corefile built in `flake.nix`) forwards only to slirp4netns's relay `10.0.2.3`, which times out. The host resolves through the `systemd-resolved` stub, which listens only on `127.0.0.53` and `127.0.0.54` (not `127.0.0.1`), so the relay cannot reach it even though the container is started with `allow_host_loopback=true` (`Justfile:41`). The host also routes all of the user's traffic through a Mullvad tunnel (`wg0-mullvad`), whose firewall refuses DNS to anything but its own resolver, so the campus servers `128.2.1.10/.11` also time out
  - Live workaround in place (not persisted, lost when the container is recreated, works only while Mullvad is connected): the running `/etc/coredns/Corefile` has `forward . 100.64.0.63`
  - Persistent options, all needing a host decision: let resolved also listen on `127.0.0.1` (`DNSStubListenerExtra`) and forward to `10.0.2.2`; move the container to the `pasta` network backend; or a literal upstream in the Corefile (brittle across networks)
  - Left of the fix of 2026-10-14 (pods resolving names outside the cluster; nix-usernetes `53d6270`, `services.resolved.settings.Resolve.DNSStubListenerExtra`, `infra/egress.nu`): the node image rebuild from `nix-usernetes` and the same `resolved` setting on the other workstation are the maintainer's to do.
- [ ] **nix-container-lib images have no `/etc/protocols` or `/etc/services`,** which would expose any of them to the class of bug that broke
  kube-proxy's nftables sync on the vigild node (found 2026-10-26, fixed for the node in nix-usernetes `c7616cb`: `nft --json` listed
  protocols by number where kube-proxy keys them by name).
- [ ] `my.env`: `GRAPH_PASSWORD` / `NEO4J_AUTH` after the password change; dev shell `BIND_ADDR`/`BROKER_ADDR` on 8080 collides with the Keycloak port-forward; `CASSINI_SHUTDOWN_TOKEN` is a dev constant
- [ ] **Archive and restore what a deployment cannot lose** (the maintainer, 2026-11-02). The list and the plan are `docs/operations/critical-state.md`: the credentials agent's store, the root CA and `polar-schedules` have no copy anywhere and no way to restore. For later (the maintainer, 2026-11-02); the plan's open questions are to be cleared first. Delete `~/.config/polar-admin.old` once they are covered.
- [ ] Dependency updates (from the older backlog; the clippy half is the item above).
- [ ] ace <-> Neo4j connectivity (parked; ace is running)

## Docs

- [ ] **THE SEQUENCE DIAGRAMS** (the maintainer, 2026-11-02: "a serious documentation pass"; all four bites, broker and client first,
  no diagram yet of many new features). An audit against the code, 2026-11-02, over the 41 then in `docs/architecture/sequences`: 26
  stale, 9 wrong or placeholders, 6 with no mismatch on a shallow reading; none changed since 2026-10-28, and 14 linked from no document. Four
  early sketches were deleted as nothing the project is heading for. Designed steps stay shaded (`rect rgb(235, 219, 178)`).
  - *Bite 1, broker and client:* DONE 2026-11-04. Four new (session supersede and takeover, admission, the stall rule, shutdown and drain), six of
    `broker/` and the five client reliability diagrams redrawn from the code, with registration refusals, and what is not built shaded. Deleted as wrong or
    duplicates and linked from nowhere: `client_timeout` (no such path), `internal_publish`, `internal_subscription` (both claimed no topic is created on first use), `topic_creation`.
  - *Bite 2, certificates and identity:* DONE 2026-11-04. New: `workload_certificate_issuance` (`polar-init` with custody), `multi_instance_workload`, `revocation`, `core_restart_ticket`,
    and `key_rotation`, all shaded as design. `admin_bootstrap_identity` redrawn as the two-phase claim. `attestation_and_issuance` was marked as the original design and the three attestation diagrams were drawn with slices A and B, so
    they stand. Not traced in this pass: `user_cert_issuance_and_usage` and `identity_normalization_query`, against an IdP (for bite 4).
  - *Bite 3, configuration and health:* DONE 2026-11-04. New: `pod_restart_in_place`, `held_agent_and_dynamic_setting`, `configuration_replay`, `escrowed_credential_lifecycle`,
    `pulled_health`, `jira_cursor_soft_state`. Redrawn: `health_rejuvenation`, `shutdown_pipeline`, `configuration_startup`, `signed_configuration_delivery`, `signed_configuration_secrets`.
    Compared with the logs and graph on u7s: restart in place, replay, pulled health, the cursor. Not presented to a real site in this pass: a credential (u7s reads Jira anonymously).
  - *Bite 4, the rest:* DONE 2026-11-04. New: `authority_snapshot_catchup`, `credentials_agent_requests`, `git_repository_observation`, `git_server_push`, `bootstrap/image_publish_import_release`;
    shaded as design, `registry_gate`, `pod_reaper`. Redrawn: `policy_update_enforcement`, `proposal_flow`, `command_flow` (everything above the agent shaded), `user_cert_issuance_and_usage`, `identity_normalization_query`,
    `admin_permission_grant`, `graph_projection_catch_up`, `topic_floor_issuance`; the bootstrap overview and phases 1 to 3 corrected. `observe_process_sequence` removed: a three-box sketch linked from nowhere, which `git_repository_observation` draws for real. Every diagram is linked.
  - *After the merge:* anything of GitLab, OpenAPI, build-processor, the orchestrator; the graph write path.
  - *Read in the code, 2026-11-04:* `signed_configuration_delivery` had the scheduler observer refusing an import and verifying early. Neither was built. The refusal is now
    (`signed-configuration.md`); the early verification stays shaded, and the target verifies regardless. Still to bring into line: `infra/seed.nu` reads the repository's documents with `dhall-to-json`, imports on.
- [ ] **Found drawing the last diagrams, 2026-11-04, read and not run:**
  - *The credentials agent's projection re-reads its whole log on every graph tick* (`projection.rs`, `catch_up`; `controller.rs`: `Available` on each 30 s tick and after each operation that sent something), through the ledger's mailbox. It grows with the log.
  - *A grant may never be marked consumed in the graph:* `project_single_event` asks whether it existed after the fold has removed it (`projection.rs`, `ledger.rs`), and the operation keys on the identity. Not tested. The ledger is the record, and it is right.
  - *An accepted proposal leaves the set after a controller restart,* since proposals are not replayed and nothing re-announces yet. It matters once a real proposer exists (`proposals.md`).
  - *`git-controller.md`'s connect-time check by the observer is not built* (`git_repository_observation` shades it).
  - *No target renders `CREDENTIALS_AGENT_INTROSPECTION_*`,* so an IdP token is refused at introspection everywhere. `user-cert-fetcher` reads a token from a file; nothing in the code uses the `browser-cert-fetcher` client Keycloak is given.
  - *The release flow has no signature and no comparison:* a tag is annotated and unsigned, `images.nu publish` is not tied to the tag or the lock, and `images.nu import` records what it copied without comparing it with the committed lock.
  - *Stale comments and text:* `infra/targets/sandbox-local/target.nu:64`, `infra/up.nu:309-312` and `:847`, the retrieve comment in `credentials-agent/common/src/lib.rs`, `policy-enforcement.md:267`.
- [ ] **Stale text** (`docs/` and comments that no longer say what is true):
  - `docs/architecture/git/agents.md` is conceptually sound but stale (2026-10-10): its tree shows `GitObserverRoot` owning the client, it
    omits the `GIT_REPO_CONFIG_EVENTS` configuration path (the README describes `GIT_AGENT_CONFIG` JSON instead), topics, shutdown and
    `Registered` behaviour, and that the observer's cache is an emptyDir (`working-checkout`). Still stale 2026-10-14: the supervisor tree.
  - Stale RabbitMQ wording in the gitlab/jira/broker READMEs, `Polar.md` and `src/flake/gen-certs.nix` (2026-10-16; `src/agents/gitlab/README.md` still has it).
  - README Keycloak walkthrough: confirm the HTTPS curl works against the port-forward
  - The empty `infra/secrets/` directory tree (from the first pipeline design) is unused; secrets are per target (`secrets.sops.yaml`, `secrets.nu`). Remove it
  - The architecture diagrams' comments still name `10.0.2.2` (left alone by the one registry setting, 2026-10-19).
- [ ] Generate the environment documentation from each agent's `--scaffold` (every variable per capability, with type, default, doc and secrecy) instead of the hand-written lists in `INFRA.md` and `config-catalog-design.md`
- [ ] **A guide to running an agent on its own** (asked by the maintainer, 2026-10-28; not urgent), beside the broker's:
  for example the Kubernetes flow without a cluster, an agent pointed at a standalone broker and messages pushed through
  it with `cassini-client`. To be worked out when it is written: what each agent needs besides the broker (the
  consumer's Neo4j, the observer's Kubernetes API), the certificates and their topics, and the messages to push.

## For the maintainer: possibly obsolete

Each line names an item left under its theme, marked `(see "possibly obsolete")`, and why it may be superseded or no longer wanted. Nothing
here was deleted; say the word and it goes.

- **The Cassini follow-ups from the migration, item (6)** (broker): the policy half looks done, since the broker has hosted its policy and
  permissions actors from stage 5b (2026-10-22); the crypto half and the Jaeger filter may stand.
- **The broker's 5 s tracer flush** (broker): the follow-ups of 2026-10-09 found the cause, a trace endpoint at Jaeger's UI port 16686; sending to the OTLP port 4318 closed it for the broker.
- **THE AUTHORITY MODEL, slices 9 and 10** (credentials): `authority-model.md` records slice 9's mutants and slice 10's findings, so both look done.
- **Cedar override-policy layer and the gitops policy path** (credentials): the signed `policy` section through `polar-schedules` looks like that path.
- **OCSP-style revocation-status topics** (credentials): revocation reaches the broker and daemons through watcher sessions since custody step 5.
- **Arrival-time validators for policy invariants** (credentials): since slice 7 the credentials agent judges every `policy` and `groups` document.
- **GAP, MUST BE ADDRESSED (2026-10-14)** (security): stage 5b and slice 8 built points (1) and (2); point (3), service-to-service calls, is what may stand.
- **STEP 5 CHECKLIST and its open question** (git, under path 1): the author's flow is built and used; since stage 5b the broker's floor answers the question.
- **Credentials agent as the main consumer of scheduled overrides** (configuration): its open questions are answered by signed configuration, and it is marked SUPERSEDED in part.
- **The warm `up.nu` resume's 28 s** (infra): the charts and scaffolds have been cached since 2026-10-19, so the breakdown is old.
- **The pull policy and moving tags** (infra): `Always` and the image lock answer most of it; what is listed may be all that is left.
- **`service.version` from the digest** (infra): `INFRA.md`, "The version a binary reports", has traces carry the version as `service.version`.
- **`build-orchestrator` Dhall config wiring** (infra): the orchestrator was removed; it comes back only with the upstream merge.
- **Workspace clippy cannot pass `-D warnings`** (dev): the lint findings were cleared 2026-10-23 and clippy is in the workflow (`just` recipe); `polar-router`'s `contains_key` is gone. Not re-run for this list.
- **Cluster DNS (nix-usernetes)** (dev): the search domain went with `--dns-search=.` (2026-10-19) and external names with `53d6270` (2026-10-14); `ndots` is under the Flux item.
