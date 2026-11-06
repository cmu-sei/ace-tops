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

# HTTP observers

Status, 2026-11-05: a design from a conversation with the maintainer, with its first cut built on the OpenAPI pair: `polar-http-observer`, `polar-http-processor`, `polar-projection`, and thin
`openapi-observer` and `openapi-processor` crates on the builder and in the catalog. It replaces the plan to repair the OpenAPI agents as they stand. Paths relative to `src/agents/`.

## Why

Most real infrastructure speaks HTTP, so the list of observers that read something over HTTP will keep growing. The maintainer's idea: what to observe and how is
data, defined and signed into the git server and handed to the agent, and the observer is paired with a processor for the thing observed. The OpenAPI agents come
first. They began as an example for a todo application (`6bfa506a`, moved here in `f25edb6c`), and no design or reader of their data exists, so they cost little to
reshape, and an OpenAPI document is the simplest real case.

## Decided: a shared library, and one workload per kind (the maintainer, 2026-11-05)

Not one `http-observer` that watches everything. The provenance chain has to be able to say: this service, which is trivial to identify, was compromised, and here
is what it was able to touch in that state. One workload holding Jira's, GitLab's and everyone else's credentials under one identity could not say that, and Cedar
and revocation could act only on all of it at once. Not wanting to build and deploy more workloads is not a good enough reason to break the trust model.

So `own_name.rs` stands: an agent's name is a constant, one binary per workload. The engine is a library, `polar-http-observer`, and each kind is a small crate that
names itself and gives the engine what is particular to it. Another endpoint of a kind is data alone; a new kind is that small crate and a catalog entry.

## The shape

**What to observe is a signed runtime section** of the agent, at `permanent/<agent>/`, written and pushed with `polar-sign` as any other, so an endpoint is added
without a deployment. For OpenAPI, `sources`, each with a `name`, a `url` and an `interval_secs`, all required.

**Each request is judged as the handlers judge any other** (`protocol-handlers.md`). A URL from a signed section is `Arbitrary`, which never carries a credential, or
`Bound`, whose host must match its credential's signed binding. The framework needs no new location. OpenAPI's are `Arbitrary`.

**One fixed topic per kind**, declared in code and computed by the builder, which its processor subscribes to. That is the pairing, and the processor believes only its own observer, by the broker's stamp, since
a policy could permit another publisher. A signed section cannot name a topic, since a hint never widens a signed bound. Each message says which source it is from, when, and the body as it came.

**Every read is published, not only a changed one.** The graph's writes are idempotent, and a document published while the processor held no mapping, or was restarting, is written at the next read, with nothing kept anywhere to
remember what was sent. Its stamp then says when it was last seen. Intervals are signed, at least 60 s.

**The observer does not read the document.** It schedules, pages, backs off as a host asks, and publishes. Only the processor parses what a service sent. Observers never
touch the graph (`soft-state.md`). One source failing is reported and does not end the agent or stop the others.

**Size.** The handler bounds a reply at 256 MiB (`MAX_BODY`) and Cassini a frame at 64 MiB (`MAX_FRAME_BYTES`, `MAX_PAYLOAD_BYTES`), so the engine's bound is the
smaller, and a document over it is a reported failure for that source.

**Configuration stays small and closed:** a URL, an interval, a credential and a paging style (none, a `Link` header, a page parameter, a cursor path). What has state or
branches is a Rust walker plugged into the engine, with the engine's scheduling, backoff, health and publishing. Otherwise every quirk becomes an option, and the
configuration a poor programming language. Jira's observer is about 5,600 lines: a cursor read back through the state agent, JQL date windows, different Cloud and Data Center
paths, a group picker that ignores `startAt`. GitLab's is about 2,700 lines of typed GraphQL POSTs. Neither would become configuration, though Jira may become a walker.

## The generic processor: a projection

The maintainer asked what one would look like, then asked for a first cut on OpenAPI, 2026-11-05. A processor turns a message into graph operations, and `GraphOp` and the graph controller
are already generic, so what differs by kind is the mapping. That becomes data: `polar-projection`, with its Dhall type in `projection.dhall` and OpenAPI's mapping in `examples/openapi.dhall`.

**Structure comes from the signed mapping, values from the document.** Labels, key names and edge types are written in the mapping and nothing in a document can choose one, so a hostile
document can give only values, which reach Cypher as parameters. The language walks a finite document, filters on an entry's key and writes. It has no arithmetic, recursion or calls, so it ends.

**Two layers, the maintainer's correction (2026-11-05).** A signed update cannot define everything, because scaffolds are computed from what an agent is built to do:

| | Fixed when built, and given by the scaffold | Changed by a signed update |
|---|---|---|
| Observer | what it needs to run: its name, its topic, its operations, its variables | its data tasking: `sources` |
| Processor | its schema: labels, what identifies each, and edges, each a type between two of its labels (`polar_projection::Bounds`) | which data goes where inside that schema: the mapping |

So the agent judges a signed mapping against its `Bounds`, and a mapping can only choose data within them. That settles three things a mapping free to name labels left open: constraints are made at
the controller's first contact with the graph, from the built schema; the state agent's first schema still comes from scaffolds; and one workload cannot write another's labels. The cost: a new label needs
a new build of that small crate. So a new endpoint, or new data from one, needs no binary change, and a new kind of thing in the graph does.

**The scaffold is the contract (built 2026-11-05, the first bite of "Evidence" below).** A kind declares its schema once, with `polar_http_processor::schema!`: each label with its keys and
purpose, each edge with the labels at both ends. That one declaration makes the `Bounds` a mapping is judged by and the kind's `GRAPH` and `GRAPH_EDGES`, so they cannot drift. The scaffold
prints each owned label's keys (`graph[].keys`, the sets its constraints are made on, `graph_key_indexes`) and its edges (`graph_edges`), so `<processor> --scaffold` says exactly what the binary
may write. `polar-sign runtime --projection` reads the agent's scaffold (`--scaffold`, or `<dir>/scaffolds/<agent>.json`), refuses a section the scaffold does not take, and judges the mapping
by the agent's own rule (`Projection::judged`), so nothing is signed that the agent would refuse; without a scaffold it signs no projection. An edge is a triple: `HAS_ENDPOINT` is allowed from an
application to an endpoint and nowhere else. A property test holds the tool and the agent to the same verdict (`openapi/process/src/agent.rs`), and another holds the schema read back from the
printed scaffold to the one built in. Marked for review: requiring a scaffold to sign a projection, and edges as triples rather than types. Cypher's rule for a name moved into `polar-cypher`,
shared by the graph controller and `polar-projection`, so the tool judges names as the graph does without taking a graph. A projection signed with `--body-file` instead is still judged by the agent alone.

**The type is for the author, and the agent trusts none of it.** `polar-sign runtime --projection <file>` checks the Dhall against the type, then that it is well formed. Imports stay off, so a file cannot name
the type and the tool gives it. The agent judges the JSON again, against its own bounds, which `polar-sign` knows only from the scaffold. The type has no Optional, because a signed document cannot hold a null, and
it is flat, because a Dhall type cannot refer to itself: an empty `parent`, `edge` or `only` means none. `polar-projection` has no graph or runtime without its `graph` feature, so the tool that holds an
administrator's key takes neither.

**A document is a snapshot, and a guard says it is the right one.** A value a document no longer has is cleared from the node, since `SET n += row.p` removes a null. Otherwise a source that moved from a 3.0 document to a 2.0 one held both versions, as was seen live. That makes a wrong response dangerous: a service
answering `{"error": ...}` with a 200 would empty the node. So a mapping must have a `guard`, what a document has to say: paths that must have a value, each optionally starting with one of some prefixes, with alternatives. A document that fails it is refused whole, before anything is written or cleared, so the last good data stays.

**A mapping has two things to match, and each is enforced.** The agent's build, by `Bounds`, when the mapping arrives. The service it reads, by the guard, at each document. The maintainer asked whether a mapping must match the service's version exactly: no, since one mapping reads Swagger 2.0 and OpenAPI 3.0 and 3.1 alike. It has to match the shape, and an upgrade that changes the shape is now refused and said, not silently written. A mapping can record the service's own version as a property, as OpenAPI's does (`api_version`, `openapi`, `swagger`).

**Health says which source is in trouble.** A standing problem through the health actor, read by asking the agent or from the state agent's record, naming the source and why, and never what a document said. In the processor, a refused document or skipped entries, at once, since a document was read. In the observer, two failed reads in a row, so a blip is not reported, and a host asking for time is not a failure. It does not end the agent, and the other sources go on. A source taken out of the observer's list drops its problem there at once; the processor does not know the list, so there it stands until the next rejuvenation, about an hour.

**How far it reaches** (from op counts and file sizes): OpenAPI and flat lists yes; GitLab's consumer probably most, but it also publishes follow-on events; the Kubernetes consumer needs `UpdateState` as a rule; Jira's
issues no, since Jira's field names become labels; build-processor no, since `linker.rs` correlates across messages. **Tried against Jira,** in a test only: a mapping writes exactly what `build_ops_for_projects` writes,
for any projects. Groups and users would not yet: groups writes an empty text for a missing value where a projection clears it, and a user's identity is its key or else its name, which needs a "first present".

## Checked live on u7s, 2026-11-05 UTC

On images built from these commits, through `up.nu`, the broker, the scheduler and `polar-sign`, against a busybox server in the cluster serving test documents. Nothing went to an outside host.

- **With nothing signed:** the observer read nothing; the processor held and said why. Its constraints were made from the built schema, and both answered `polar-running-config`.
- **The certificate.** Both pods first failed in `polar-init`: a workload stays on cert-issuer until its target moves it, and the test for that needs a cluster. Moved, with a test that does not.
- **Sources before a mapping:** each read judged (`arbitrary=true`, no credential) and published, and the processor said at each read that it was not written. Signed afterwards, the documents were in the graph at the next read, with no restart.
- **The documents:** an OpenAPI 3.0 and a Swagger 2.0 document, through one mapping: two applications, five endpoints, including two with no `operationId`, and `parameters` not taken for an operation. A title of `x"}) DETACH DELETE n //` is stored as that text, and the graph's count of nodes did not fall.
- **One source failing:** a 404 and a document in YAML were each said and touched nothing else.
- **Refused:** a mapping writing `Pod`, and one with another edge type, were refused by the agent, the last one stayed in force, and neither spent its version. A type error and an import never reached signing. Sources with a password in the URL and an interval of 5 were refused, and the refusal did not repeat the password.
- **Changed:** a mapping keeping only `get` applied at once and was stamped on what it wrote. A list dropping two sources and moving one read only that one, at once.
- **Found:** a source moved from a 3.0 to a 2.0 document held both versions on one node. Fixed (above) and seen cleared.
- **Restart:** both pods deleted: each replayed what was in force and the hold cleared at once.

**The guard and health, checked the same way the same day, on images with the guard.**

- **An error answered with a 200:** a source moved to `{"error": "...password=hunter2"}`, served with a 200. Refused whole, naming `body.openapi or body.swagger`. The node's title, version and license all stayed, and so did its endpoints, with the last-seen time unchanged. The processor's health held, naming the source, and the password appeared nowhere in its log. Back on the good document, the next read wrote it and the hold cleared by itself.
- **A mapping with no guard:** `polar-sign --projection` refused it by its type. Signed past that with `--body-file`, the agent refused it (`missing field guard`), and the mapping in force stayed.
- **The observer:** one 404 was logged and no more. The second in a row held, naming the source and `it answered 404`, while the other source went on being read and published. Taking the source out of the list cleared it at once.

Health was read from the agents' logs. The answer through the state agent was not seen, since its seeded list of agents predates these two.

An endpoint a document dropped stays in the graph, but its `polar_observed_at` falls behind, so it can be told apart: that is the start of handling it.

**Not seen live, tests only:** a document from a publisher other than the observer, a document over the size bound, a host asking for time, and skipped entries as a standing problem. **Not run:** a fresh bring-up with these agents, and their health being asked by the state agent, whose first `agents` was seeded before they existed.

Removed afterwards: the documents, the server, and the test nodes. The two agents remain deployed, the observer reading nothing and the processor holding.

## Versions and migrations

Decided with the maintainer, 2026-11-05. Not built: the guard below comes first.

**A signed section says which versions of the agent it is for**: a range in its `target`, checked where every signed document is opened, so this is one mechanism for every agent. Open-ended by default, since every binary
shares one platform version and an exact pin would mean signing everything again at every release. Out of range, the agent holds and says why. Images and sections arrive from two repositories with no atomic switch, so an upgrade signs a range that covers both versions first.

**A migration lives in the repository with the signed configuration change it belongs to, and an administrator applies it.** The maintainer's design: `migrations/<agent>/<id>.cypher` in `polar-schedules`, where the scheduler does not read, and the signed section names it by id and digest. The agent never
runs it, so no signer gains power over the graph, and `repair.rs`'s rule stands: an agent takes no caller's Cypher. The digest is what binds them: `polar-schedules` takes unsigned commits, so being in the same commit proves nothing.

**Two recorded events:** intended, which the signed change and its `ConfigurationOutcome` say, and applied, a second document the administrator signs: who, when, which digest, and what it reported. Comparing them lists what was meant and never done. The applied record is a signed claim and not proof.

**The agent keeps its old mapping until the applied record arrives** (the maintainer), and health says what it waits on. So a forgotten migration blocks the new mapping visibly, where the alternative mixes old and new data silently. A migration that must run after the new mapping is live needs a flag saying so.

**Bite 6, planned 2026-11-06, the maintainer's choices:**

- **The range is two fields**, `target.versions: { from, below }`, each a platform version and each optional, absent meaning any, compared by `polar_version`'s own
  order (a release before its development line: 3.0.0 < 3.0.0+dev < 3.0.1). `polar-sign --from <v> --below <v>`.
- **Out of range, the agent refuses the document and holds** on Configuration, saying for which versions it was signed and which it is, until a document in range
  arrives; what it held stays in force.
- **The applied record is a signed `.dhall` the scheduler delivers**: `polar-sign migration applied` writes `migrations/<agent>/<id>.applied.dhall`, a document of its
  own type (`migration-applied`: the migration's id and digest, who, when, what was reported), routed as the scheduler routes the rest; the agent releases the section
  that named it.
- **Who may sign it: whoever may sign the section it releases**, by the section's own capability and Cedar first, so no new capability.

The steps: the range (`polar-version`, the agent's check where it opens a document, `polar-sign`); a section naming its migrations (`migrations: [{ id, sha256, after }]`,
beside the body) and the agent holding it until each is applied, unless `after`; the applied record and its tool; both as facts and invariants of `polar-sign check`.

**Bite 6, built 2026-11-06.** As planned above:

- **The range.** `polar_version::VersionRange` and the order of platform versions (a property holds both). Where an agent opens a runtime or settings document, one outside its
  range is refused (`Rejection::OutOfRange`), what it held stays, and the configuration actor holds health on Configuration ("a signed document (r-2) is signed for from 4.0.0
  of this agent, and this is 3.1.0") until a document is applied; it releases only a hold it made. `polar-sign runtime` and `configuration` take `--from` and `--below`.
- **Migrations.** A runtime document may name `migrations: [{ id, sha256, after }]`, written by `polar-sign runtime --migration ID=FILE` (or `--migration-after`), the digest
  being the file's. The agent holds a section that names one not `after` and not yet recorded (outcome `waiting`, health on Configuration saying which), with what it had in
  force; a signed `migration-applied` record of that id and digest puts it in force, and one that arrives first, as a replay may deliver it, is kept for it. `polar-sign
  migration applied --agent --section --id --file --report` signs the record (who, when, the digest, what was reported) and pushes it to `migrations/<agent>/<id>.applied.dhall`,
  which the scheduler now routes with the section (`polar_scheduler_common::routing`). Who may sign it is who may sign the section: the same authority, Cedar first.
- **As facts.** `polar-sign check` reads each section's range and migrations, every applied record and every `migrations/<agent>/<id>.cypher`. Two more invariants:
  `sections-in-range` (each section that names a range holds the agent's build: each pod's when asked, else its scaffold's) and `migrations-applied` (every migration a
  section in force names is in the repository as signed, by its digest, and a signed record says it was applied).

Checked by deliberate breakage (`mut12.py`, 15 of 15): the order and the range, the verifier's check for both kinds of document, the hold and its release, a migration
`after` holding nothing, a record of another digest releasing nothing, the pending section put in force, the scheduler's routing, and both invariants. The workspace: 3,940
passed and one broker test failed once under its load, passing alone and with its suite (`remaining-work.md`).

Marked for review: the hold for a range or a migration is on Configuration, the reason a domain's own configuration hold uses, so releasing it can clear the domain's own,
which the domain makes again at its next attempt; a reason of its own would need a change to the health wire.

**Checked live on u7c, 2026-11-06**, upgraded from its volumes, then again with the scheduler's fix (`896b8b63`):

- The mapping signed as version 3 for agents from 99.0.0: the processor refused it ("signed configuration refused rejection=signed for from 99.0.0 of this agent,
  and this is 3.0.0+dev"), kept what it held, and held health ("a signed document (openapi-projection-3) is signed for from 99.0.0 of this agent, and this is
  3.0.0+dev: sign it for this version"); `sections-in-range` and `sections-in-force` were violated. A restarted processor was replayed the same document and refused it the same way.
- Version 4 for this build, naming migration `m1` with its file committed beside it: verified, held ("runtime section waits on its migrations ... waiting=["m1"]"),
  and health said so ("projection version 4 waits on migration m1: apply it, then sign its record (polar-sign migration applied)"). `polar-sign migration applied --push`:
  within six seconds the record was verified, version 4 replaced the section, the hold was resolved and the mapping was in force. The check: 11 of 11, `migrations-applied`
  "applied, by djshepard", `sections-in-range` "version 4 (from 3.0.0): openapi-processor is 3.0.0+dev".

**A correction.** The first look at this run concluded that the scheduler did not deliver pushed documents. It did: the agents' configuration actor logs inside the
transport's span, and the processor's log had been read filtered with `grep -v tcp_client`, which hid the refusals that were there. What the first look did find was
real, and is fixed (`896b8b63`): a `migration-applied` record, under `migrations/`, was not a schedule file, so none would ever have been delivered; and the observer's
filesystem watcher ran in a thread that unwrapped its errors, so a watcher that failed would have said nothing. Each pull is now followed by a rescan that publishes what
changed, once (`polar-scheduler/observer/tests/rescan.rs`, six breakages of six caught). The replay through the observer's supervisor worked live and is still untested.

Compiled repairs stay for what a write bug left behind, on every cluster. Whether a migration deletes or supersedes is its author's call; superseding is the documented default, since the graph has to answer what was known at the time.

## Mapping the security controls

The maintainer's requirement: the same properties, and more, from dynamic configuration as from static deployments. A first map, read from the code. **Open** means not answered yet.

| Control | With a static agent | With a signed mapping | |
|---|---|---|---|
| Who a workload is | Name constant in the binary, checked against its certificate (`own_name.rs`) | The same in this cut: each kind is a small crate | Same. A kind with no binary of its own would have to reverse this. **Open** |
| Topics | Computed by the builder, in the certificate, decided at the broker | Fixed by the kind; a mapping cannot name one | Same |
| Where it may connect | Operations declared when built, each request judged and logged | `Arbitrary`, never a credential, each judged and logged. The signer chooses the host | Weaker: a list of hosts where there was one variable. Same trust as `JIRA_URL` |
| Who may change it | Build, deployment signature | `c:update-runtime`, Cedar on `Section::"<agent>/<section>"`, version, revocation, replay from git | Same machinery, and one signer |
| Review and tests | A commit, CI, tests and a signed deployment | The checks above, and no test against a real document | **Weaker.** A dry run in `polar-sign` against a sample would help, and `commands.md` already notes two signers as later |
| A bad update | Fails to build or deploy | Refused and the last one kept, until a restart: a refused file still replaces the good one (`dynamic-settings.md`) | **Weaker until that gap closes.** The agent would hold, not misbehave |
| A service that changes under it | Parsing code fails, or silently reads less | The guard refuses the document whole and health names the source | **Stronger**, for what the guard says |
| Labels it may write | Declared in `GRAPH`, not enforced on writes | Enforced by `Bounds` when the mapping is judged | **Stronger** |
| Cypher injection | Parameters, by each author's care | By construction, and names judged by Cypher's rule (`polar-cypher`) before signing, at the agent and by the graph controller | **Stronger** |
| Sensitive data in the graph | A reviewer sees what code copies | A signer can project any field of what was fetched. With a credential, that could be a route out | **Weaker, and matters at the first kind with a credential.** OpenAPI has none |
| What the graph knows of itself | Whatever the code writes | Every node and edge stamped: source, workload, mapping version, time | **Stronger** |
| What ran | The image digest, by attestation | The digest no longer says all of what it does: digest and signed section together do, and each signed version is in git | Different. Slice C should count this |
| A hostile document | Each parser's care | One engine, property-tested on any JSON; a bound on writes, refused whole | **Stronger** |

## Datalog

The maintainer asked whether the credentials agent's engine helps here. `ascent` is a macro: its rules are compiled, and only its facts arrive at run time (`credentials-agent/model/src/rules.rs`), so it cannot run a signed mapping, and
`authority-model.md` already says rules written by administrators would need a runtime engine. A mapping needs no recursion either, and a more powerful language would be harder to reason about.

It may help with the question this design exists for, though. "This service was compromised: what could it touch?" is reachability, which the authority model already computes over topics. Facts from the catalog and
from each signed version (a workload's sources, its credentials, the labels in its bounds) would answer it with a rule, and would have caught `polar.web.consumer` going nowhere. Not designed: a place to go when the provenance chain is built.

## Evidence: tests, invariants and facts (planned 2026-11-05)

The maintainer chose to settle this architecture before GitLab, so the agents rewritten onto it do not have to move again, and asked for the most use of tests, invariants and facts tied to a
version and an instance. Cleared the same day. Three layers, each true of something different:

| Layer | Proves | True of |
|---|---|---|
| Properties | The engine obeys its rules for any input | A build of the code |
| Examples | This mapping does the right thing with these documents | A mapping, a schema and samples |
| Facts and invariants | This deployment's declared state is sound, and which evidence still applies | One version of one instance |

An instance is the target and its CA fingerprint, and the pod (`Instance.uid`, stamped by the broker). A version is the image digest and platform version, the scaffold's digest, and each signed
section's id, version and digest. The sources are the catalog and scaffolds, the signed deployment record, the `polar-schedules` history, and `polar-running-config` for what is in force (which needs the
platform version added to its answer).

### How the evidence ties to the architecture (2026-11-06)

What a kind does is mostly signed configuration, not code: its `sources` say what the observer reads, its `projection` what the processor
writes. So most of what can go wrong with a pair is a fact of one deployment (which mapping is in force, what policy allows, who owns a
label, whether what was signed was tested), and the layers above answer different questions. Properties (bite 2) are true of the engine
for any mapping; examples (bites 3 and 4) of one mapping and its samples; facts and invariants (bite 5) of one version of one instance,
and they are what catches a deployment that is wrong while every test passes.

Each link of a pair is held by one invariant:

```
service ──HTTP──▶ observer ──topic──▶ processor ──mapping──▶ graph
          (sources)        (policy)            (projection)  (labels)
```

- **Observer to processor: every pair connected and allowed.** The first OpenAPI pair published `polar.web.consumer` and subscribed
  `polar.openapi.processor`, so nothing arrived ("What the OpenAPI pair fixes"); a Cedar `forbid` can cut the same link with the names
  right. The check runs the authority model's own flow rules, the ones the credentials agent judges a policy by, over the deployment's
  policy and groups, so the check and the enforcement cannot disagree. That is why the model is split from the agent builder first: the
  tool that checks links the same rules.
- **Processor to graph: one owner per label.** Why the labels are `OpenApiApplication` and not a generic `Application`: two writers of one
  label overwrite each other. The state agent's signed `schema` and the scaffolds must agree on one owner.
- **The mapping: inside its binary's schema, and tested at the version in force.** Bite 1 judges a mapping when it is signed; bite 5
  judges what `polar-schedules` holds, against the deployed image's scaffold. Bite 4 leaves a signed record of each test, with the
  body's digest and the reads no sample reached; bite 5 finds the record for the body in force, and a mapping signed without one is no
  longer covered: there was evidence, for another version.
- **The workloads: certified, and seen by health.** Each pair adds two identities, which the credentials agent must certify and the
  state agent's `agents` list must name; checked live on u7s, the state agent's seeded list predated the pair, so its health was not seen
  through it ("Checked live on u7s").
- **Outside: what each workload could touch.** An observer reaches hosts its sections name ("the signer chooses hosts"): reported per
  workload with its allowed topics and the labels it owns and reads.

Every new kind (GitLab next, Jira after) adds such a pair. The kit gives the kind its tests; the check gives each deployment of it the
assurance, without a cluster, that the pair is wired, allowed, owned, certified, seen and tested at the version that runs. The one
deferred, a credentialed fetch reaching the graph unreviewed, is the same idea for the first kind that fetches with a credential.

The bites, in order:

1. **The scaffold becomes the contract.** Built: above.
2. **Pure cores and engine properties.** The observer's and processor's decisions out of their actors, and a generator of valid mappings: for any valid mapping and any JSON, no panic, the same writes
   each time, only the labels and edges it names, every write stamped, nothing written on a failed guard, no null key, no document text in Cypher, a round trip through signing. The state machines
   against a simple model: the last good document under the last accepted mapping. Built: below.
3. **A test kit for every kind.** `polar_http_tests!(Kind)` and a pair harness: the real handler, a stand-in service, the real signing path and real Neo4j, with samples and expected writes beside
   each mapping. Built: below.
4. **`polar-sign projection test`.** The same checks for a deployment's own mapping, writing a signed evidence record (the digests of mapping, scaffold and samples, the tool's version and the
   result) into the evidence repository (planned for `polar-schedules`; moved by the maintainer's choice, 2026-11-06, to follow the evidence registry's decision). Built: below.
5. **A fact base and invariants.** The authority model's facts and rules split into a crate with no runtime, and `polar-sign check` giving each instance holds, no longer covered or violated, with
   a witness. Each invariant has a test that a bad fact base breaks it; report-only first. The first ones: every pair connected and allowed; one owner per label; each mapping inside its binary's
   schema; every path a mapping reads in a tested sample; signed sections as in force; every non-bootstrap workload certified by the credentials agent; every catalog workload in the state agent's
   list; no credentialed fetch reaching the graph unreviewed; what each workload could touch.
6. **Version ranges and migrations**, as designed above, both becoming facts.
7. **Harder shapes.** Paging, `Bound` credentials and the signed-list fix, with Jira's projects, groups and users through the kit in tests, and a fresh bring-up.

**Bite 2, built 2026-11-05.** The decisions are pure cores, as `Asking` is (`polar-running-config`): `Observing` (`polar-http-observer/src/observing.rs`) and `Processing`
(`polar-http-processor/src/processing.rs`) take an event and say the steps (read, publish, read again, write, tell health), and the actors carry the steps out. `polar-projection`'s `testing`
feature generates any valid mapping, with the schema it fits, and documents in its words whose every string carries a mark no mapping can hold (`src/testing.rs`). The properties:

- for any such mapping and any such document: the same writes each time, only the labels, keys, properties and edges its rules name, the four stamps exact on every write, no null key, and a
  guard that refuses exactly when a reading of the language, not the engine, says a check fails; and the same of the guard alone, from its own generator (`polar-projection/src/tests.rs`);
- under any such mapping, the graph controller takes the operation and none of the document's text is in its Cypher (`graph.rs`);
- any such mapping, signed with `polar-sign`, committed, verified and read back, is judged the same projection (`polar-sign/src/lib.rs`);
- the observer, over any sequence of lists, reads, stale generations and a shutdown, against a model: a source read only at its latest version's generation while listed, a read published and
  read again once, at its interval or the host's longer wait, nothing after shutdown, and health naming exactly the sources whose last two reads failed;
- the processor, over any sequence of mappings, refusals, rereads, restarts and documents, against a model graph that does what MERGE and SET do and documents described plainly: each source's
  last good document under the mapping in force when it came, with that version's stamps; anything else of the source from an earlier good document; a refused document, or one with no mapping
  held, changing nothing; and health saying there is no mapping exactly when none is held.

Each was checked to catch deliberate breakage of what it states, run against the new properties alone (`mut7.py`, 19 of 19). What the bite found:

- **A generator that only makes valid mappings can still test little.** The first one wrote an edge in none of 256 cases, and two breakages of edges went uncaught. Biased toward keys from
  `source`, a guard alternative every document passes, and steps over what was last bound, about six cases in ten pass the guard and one in fourteen writes an edge; but then the guard rarely
  decided, and two breakages of it went uncaught. So the guard has its own generator, `guarded`, with no way to pass that every document has, and its own property, whose documents are built
  against the guard's paths: each absent, null, text with a prefix first or later, or a number. A random document reached the decisive case, a null where a check looks, in four runs of five.

- **Dhall evaluation grows exponentially with nesting.** Measured with the Dhall crates optimised: about three times longer for each level of records within records, and about nine times for
  each level of records within lists; a list of records seven deep takes 81 seconds. A signed projection's file is five records and two lists of records deep and takes 0.1 to 0.8 seconds,
  about ten times its body's, because signing wraps the body two levels deeper. A body much deeper than a projection's, or a projection grown deeper, would hold up the configuration actor for
  seconds or minutes. Whether the parser or the type checker is the cause is not yet found; the fix is in the Dhall fork. Open, below.
- **Dhall is slow unoptimised.** The example's file took 2.7 seconds to read in a debug build, 0.23 optimised. Marked for review: the workspace's `Cargo.toml` optimises `dhall`, `serde_dhall`,
  `pest` and `pest_consume` in dev builds, as in a release, and nothing of Polar's own. With that the round trip still takes about two minutes for its 256 cases, which are kept.
- **No signed-list limit for a projection.** Every rule and step has the same fields, so the signing tool types each list; the limit stays for lists whose entries differ (bite 7).
- **A property a new mapping does not set stays**, as an entry a document dropped does: the model leaves it out. Open, with the dropped entries.
- Marked for review: `polar-projection` gains an optional `proptest` dependency, behind `testing`, so other crates' properties use the same generator; nothing that ships enables it.

**Bite 3, built 2026-11-05.** `polar-http-testkit`, a dev-dependency only. A kind's processor crate calls `polar_http_tests!` with its observer, its processor, its mapping and the directory
of samples beside the mapping (`openapi/process/src/agent.rs`), and has three tests:

- the mapping is judged by the processor's own scaffold and signed by `polar-sign`, written as the Dhall file that is committed, evaluated as the scheduler's observer does, submitted to a
  configuration actor holding the processor's own sections, and read back in force; the projection the processor takes from it is the one the author wrote;
- each sample is served by a stand-in service (wiremock) and read through the real protocol handler as the observer's one operation (`polar_http_observer::observer::read`, which the actor
  uses too), with the observer's and the processor's own cores deciding and the observation encoded and decoded as the broker carries it. What the pair writes is what the mapping makes of that
  observation, and that is what is written beside the sample, `<name>.expected.json`: the nodes and edges plainly, without the stamps, and how many entries were skipped, or why it was refused.
  `POLAR_BLESS=1` writes them, to be read before they are committed;
- the samples are written to real Neo4j (`polar-test-graph`) by `handle_op`, the graph controller's own write: each to a source of its own, then all to one source in turn and in reverse, as a
  service changing its document. After each step the graph is, line for line, what the model graph says (`polar_projection::testing::MemoryGraph`, now also the processor's property's), so the
  model bite 2 holds the processor to is a model of Neo4j and not only of itself.

OpenAPI's samples are written by hand, not taken from a service: Swagger 2.0, OpenAPI 3.0 and 3.1, an empty `paths`, and an error answered with a 200 (`polar-projection/examples/openapi/`).
Each expected file was read against its document. Checked to catch deliberate breakage (`mut8.py`, 6 of 6): the model graph not clearing on a null or not holding a node's keys, the engine
ignoring `only` or writing empty text for what is absent, the observer refusing a larger document, and the graph controller replacing a node's properties instead of adding to them, which only
Neo4j shows. What it does not reach: the actors themselves and the broker (the cores are what they run), the controller actor's retries and its constraints, and documents from real services,
which need their licences checked and the maintainer's leave to fetch. Seen in them: the mapping does not observe a 3.1 document's `webhooks`, as written.

Marked for review: the kit is on the builder and reaches `reqwest` (through `polar-sign` and `polar-test-graph`), which the guard that a domain crate has no way out of its own refused
(`polar-agent-builder/tests/domain_has_no_way_out.rs`). The guard now leaves alone a library that builds no binary and that no crate takes as a normal dependency, since nothing of it can reach
a workload; the day a crate takes it as one, it is walked from that crate as any helper is, and a test says so. In the workspace today that is the kit alone. It is not on the list of what is
not the domain, which holds the maintainer's decisions.

**Bite 4, built 2026-11-06.** `polar-sign projection test <mapping.dhall> --agent <agent> --section <section>` holds a deployment's own mapping to the checks a kind's is held to,
by the agent's scaffold as `polar-sign` already reads it, and signs a record of what it found (`polar-sign/src/evidence.rs`):

- the mapping is inside the schema the scaffold gives; signed as the section with the user's own key and read back as the agent reads its committed file, verified against their CA, it is
  the same projection; and each sample beside it, the folder named as the mapping is without `.dhall`, becomes what is written beside that. `--bless` writes those, and signs nothing;
- the record names what it is true of by digest: the mapping's file, the scaffold (with the agent version it carries), each sample and, canonically, what is written beside it; and this
  tool's version record, the time, and the result, in lines that name a sample and never say what it holds (what it became is said whole on the terminal only). It is written whether the
  mapping passes or not, and the tool fails if it does not;
- it is signed in a new domain, `polar-evidence-record-v1` (`Domain::EVIDENCE_RECORD`), so no evidence record is ever taken for a configuration document or the other way round, and
  `polar-sign verify --evidence` checks one;
- `--push` commits it to `polar-evidence` (`POLAR_EVIDENCE_URL`), at `projection-test/<agent>/<section>/<sha256 of the signed record>.json`, so a new record never replaces another. The
  git server now declares that repository, seeded once and written by its administrators, as `polar-schedules` is (`infra/config/workloads/git-server.nuon`, `infra/seeds/polar-evidence`).

The sample checks moved from the kit into `polar-projection` (`src/samples.rs`), with the processor's `Outcome` (`Projection::outcome`), so the kit and the tool run the same code, and
the kit has a fourth test: the tool's checks pass for the kind's own mapping by the processor's real scaffold. The order of what a sample becomes is now taken from what identifies each
node and edge, with names sorted, where before it was the text of each, which is in a different order when a build keeps JSON objects in insertion order (`serde_json`'s
`preserve_order`, which the workspace's other crates turn on): `polar-projection`'s own tests saw the other order. The expected files did not change.

Where the record goes was the maintainer's choice (2026-11-06): the plan said `polar-schedules`, and the evidence registry's decision (`agentic-control-plane.md`, on the
`agentic-control-plane` branch) says a repository of its own, each record signed by its collector in a domain of its own; the evidence repository was chosen. Marked for review:

- **No commit rule on it yet.** The git server's commit rule names one signer (`signed_by`, the pipeline for `deployment`), and evidence has as many signers as people who test. Each record
  carries its own signature, so a forged record does not verify; but a commit that removes or changes one is taken, as on every repository but `deployment`. Open, below.
- **Who may record evidence.** Anyone with a certificate from the CA: the record says who, and nothing takes a record as an order. No capability is asked for. The round trip signs the
  mapping with the same key and keeps nothing of it.
- **No Neo4j in the tool.** The kit holds the model graph to Neo4j for the engine; the tool checks what a mapping makes of its samples, which is what a deployment changes.

**Bite 5, planned 2026-11-06, cleared by the maintainer.** Facts from the signed repositories only, first: what is declared. Asking the running agents what they hold in force
(`polar-running-config`, with the platform version added to its answer) is its own step right after. "No credentialed fetch reaches the graph unreviewed" waits for bite 7, with Jira,
the first kind that fetches with a credential and so can break it; built now it would hold trivially.

1. **The model without a runtime.** What the authority model takes from the agent builder is pure: the topic types (`topics.rs`), the gate's `rule` and Cedar's `entity`. They move to
   a crate of their own, `polar-topics`, which the builder re-exports, so no path changes; the model takes it in place of the builder, and the credentials agent's common crate keeps
   its graph keys behind a default feature, so the model has neither Neo4j nor actors. The model's tests stay as they are and pass.
2. **A fact base for one instance.** `polar-sign check` reads checkouts of `deployment` (the rendered manifests with the authority model the render gives the credentials agent,
   `provenance.json`, the signed deployment record), `polar-schedules` (policy, groups, the state agent's `schema` and `agents`, each projection) and `polar-evidence`, at given commits,
   and the scaffolds; every signature is verified as it is read. The instance is the target and its CA's fingerprint; the version, each image's digest, each scaffold's digest, and each
   signed section's id, version and digest.
3. **Verdicts.** Each invariant holds, is violated, or is no longer covered (there was evidence, for another version), with a witness. Report only: the tool fails only when it cannot
   run. The verdicts are an evidence record of their own, signed and pushed as a projection test's is.
4. **The projection test's record grows** the digest of the mapping's body, since the schedules hold the body and not the author's file, and the paths the mapping reads that no sample
   reaches (the mapping's names, never what a document says).
5. **Tests.** Each invariant has a test that a bad fact base breaks it; properties that a verdict does not depend on the order of the facts and that a witness given for one that holds
   does hold.

The first invariants: every pair connected and allowed, under the policy and groups in the schedules; one owner per label, by the state agent's `schema` and the scaffolds; each projection
in the schedules inside its binary's schema, by the deployed image's scaffold; every path a mapping in force reads reached by a sample of a passing test of that body (no longer covered
when the body has none); every non-bootstrap workload certified by the credentials agent; every catalog workload that reads a document in the state agent's `agents`; and, as a report
rather than a verdict, what each workload could touch.

**Bite 5, built 2026-11-06.** `polar-sign check --deployment <checkout> --schedules <checkout> --evidence <checkout> --deploy-ca <ca.pem> --user <you>` reads one instance's
facts and judges them (`polar-sign/src/instance.rs`, reading in `instance/read.rs`):

- **Reading, every signature verified.** The deployment's checkout must have no change since its last commit, which is what is read and what is signed, and that commit must be the
  pipeline's under the deployment CA; its `deployment-record.json` must verify in the deployment
  record's domain, and the authority model is the one the render gave the credentials agent, in its ConfigMap. Every signed runtime document of `polar-schedules` is verified as an agent
  verifies it, and every record of `polar-evidence` in the evidence domain; one that does not verify is not in force anywhere, so it is left out and said, and the deployment not
  verifying stops the check. The scaffolds are read as `nu infra/resolve.nu scaffolds` writes them.
- **The invariants, each by a stable id**, which a claim binds by (the statement lives once, in the check): `pairs-connected` (every publisher of a topic reaches every hearer under the
  policy and groups in force, by the model's own flow rules, and the side that is refused is named), `authority-reaches-every-agent` (the model's own goals: the authority's updates,
  requests and correction), `one-owner-per-label` (by the deployed workloads' scaffolds and the state agent's `schema`), `projections-inside-schema` (each section a scaffold says holds a
  projection, `polar_projection::SECTION_TYPE`, judged by that scaffold; a signed section of an agent with no scaffold is violated), `projections-tested` (a passing projection test of that
  body by that scaffold's digest, reaching every read; another version's is no longer covered), `credentialed-reads-reviewed` (bite 7: below), `certified-by-the-credentials-agent`, and
  `seen-by-health` (every agent that reads a document in the state agent's `agents`, and nothing else). What each workload could touch is reported: the topics the pair lets it publish and hear, the labels it owns and reads, the
  hosts its sections name.
- **The record** is signed in the evidence domain and pushed beside the projection tests, at `instance-check/<target>/<sha256>.json`. Report only: the tool fails when it cannot judge,
  never for a verdict.

**The record envelope is common to every type of evidence record** (agreed with the agentic control plane's session, 2026-11-06, marked for review): `type`, `subject`, the digests
and versions it is true of, `tool` (the tool's version record), `result { passed, problems }` and a time `<verb>_at_unix_secs`, with what the type says beside them. A claim binds a
record by its type and subject, never a digest, so it survives a new version.

Each invariant was checked to catch deliberate breakage of what it states, and the reading to refuse what does not verify (`mut10.py`, 22 of 22). Four first survived: two
breakages that did not break (a `?` left in), and two tests missing, written then: a schema naming another owner, and a section whose `rules` are not a projection. Writing the test of a
changed deployment record found that the check verified the commit and read the working tree, so a checkout changed by hand would have been judged as signed; a checkout with changes is
now refused.

What changed for it: the authority model's facts carry each workload's `kind` and `config` as the catalog says them (`infra/rules.nu` `model_facts`), since who belongs in the state
agent's `agents` is the document agents of kind agent, and nothing else the deployment says tells a CA or a broker from an agent; a model rendered before reads, and the check asks for
it to be rendered again. The policy and groups sections are read into a pair by the credentials agent's own reading, moved to `credentials_agent_common`
(`AuthorityBody::of_section`) and `Pair::from_sections`; a person's username stays as written, so what the pair is judged for is the workloads. The model's fixture was regenerated
(`fixtures/regenerate.nu`): it predated six workloads (the OpenAPI pair, the state agent's two, attestation, the registry resolver) and every agent's present topics, and every test
over it passes. Checked over the sandbox's own deployment mirror (`~/.config/polar-deploy/sandbox-local/mirror.git`, rendered from 66affca5) with empty schedules: the pipeline's
signature, the record and the model are read, five invariants hold, and the two that should not do not: no schema signed, and a model rendered before it said kinds.

Marked for review:

- **The rule for who health asks lives in the check as well as the render** (`graph.nu` `health_agents`), over facts the catalog states. The alternative is a fact the render
  computes, which would make the check compare the render with itself.
- **A projection is tested only by the scaffold's text digest.** A scaffold written again by the same binary has the same text; one from another build is no longer covered, though it
  may judge the same.
- **Ractor comes into the model through `polar-policy`**, whose evaluator and actor are one crate. Nothing in the model runs it.
- **What it does not read yet:** the images' scaffolds by their digests (the render caches them so; the check is given a folder). What runs is the next step, below.

**What is in force, built 2026-11-06.** `polar-sign check --ask` also asks every agent that reads a signed document what it holds, over Cassini, as the person running it,
and hears every pod's answer for the wait (`polar_running_config::survey`, a pure core `Surveying` beside the one-question `Asking`). Two more invariants, judged only when asked:
`sections-in-force` (every agent asked answers, and each pod holds each section signed for it by document id, version and body digest, nothing unsigned, and its settings at the
version signed) and `running-as-scaffolded` (each pod runs the build its scaffold, which the check judged by, came from). The record keeps what each pod said it holds, by agent and
pod as the broker stamped them, and never a setting's value. The maintainer's choices, 2026-11-06:

- the answer grows each section's document id and body digest (SHA-256 of the canonical body) and the agent's build, as a breaking change of the rkyv answer, recorded for the
  customer's migration (`remaining-work.md`), rather than a second answer type;
- `polar-sign` asks itself, rather than reading answers saved by another tool. So that the two packages do not depend on each other, `polar_running_config` is the asking library and
  the `polar-running-config` tool is a binary of the `polar-sign` package; the identity both read is `polar_signing::identity`. Recorded as open: `polar-sign` does too many things.

Checked by deliberate breakage (`mut11.py`, 11 of 11; two tests written when their breakage first survived: a pod behind on a body signed again unchanged, and a
document's id kept when it is applied). Not tested against a broker in the workspace: the decisions are (`Surveying`, and each invariant over answers), and the path was checked live before for one question
(`dynamic-settings.md`, "Checked live on u7s").

**Checked live on u7c, 2026-11-06 UTC**, reset and brought up fresh from `f56788da` (`up.nu sandbox-local --dev --topology separated`), with the three
repositories cloned from Polar's git server and the scaffolds from `resolve.nu scaffolds`:

- As brought up: 9 of 9 hold. 18 agents asked, 18 answers; each holds the seeded sections by id, version and digest, at the build its scaffold is of.
- The OpenAPI mapping signed as version 1 and pushed: the processor applied it within seconds, and `projections-tested` was violated, never tested. `polar-sign projection
  test --push` to `polar-evidence`: 9 of 9 again, the test found by the body's digest and the scaffold's.
- The gap of "a refused file replaces the good one" (`dynamic-settings.md`), made on purpose: a changed mapping signed again as version 1 under a new document id. The processor
  refused it as not higher than what it held, and `sections-in-force` was violated ("holds projection version 1 (document openapi-projection-1), and version 1 (document
  openapi-projection-1b) is signed"); `projections-tested` was no longer covered, the body in the repository being one no test was of. The tested body signed as version 2: 9 of 9.

Seen there: an answer names its agent and no pod, since the broker stamps the instance its certificate names and issuance writes one only for a workload of many instances; every
agent of the target is of one. And `up.nu` runs the `polar-sign` found first on `PATH`, which in the dev shell was the `polar-tools` package of an older build: it did not know
`Action::"read-configuration"` and refused the seeded policy, so the seed step stopped until the tree's own build was put first (open, below).

What it closes, by the plan: no test against a real document (3, 4), a mapping outside its binary's schema (1, 5), an agent version mismatch (6), an issuer mistake and a stale state-agent list (5),
what a workload could touch at a past version (5), and which version and configuration ran as declared (5; what actually ran is slice C). Detected, not fixed: a refused file replacing the good one
(5; the fix is a server-side check at push), and a forgotten migration (5, 6). Narrowed: a service changing its shape (the guard; a field outside it can still clear), one signer and no review (4, 5),
a sensitive field reaching the graph (5 sees the flow, not which field is sensitive), the signer choosing hosts (reported, not bounded). Remaining: what a workload actually touched (the request
record is only in logs; the fix is a durable `Recorder`), evidence and applied records being signed claims rather than proof, facts against real behaviour (2 and 3 tie code to facts; "should" stays
"should"), and dropped endpoints with the processor's stale problem (small, needs a decision).

**Bite 7, planned 2026-11-06, the maintainer's choices.** Each page of a paged source is an observation of its own, of the same source, each within the frame's
bound, so nothing holds a whole source and the observer still does not read a document beyond the paging it follows. Jira's projects, groups and users go through the kit
as a test kind only, a Jira-shaped mapping with hand-written samples against a stand-in Jira, paged and with a `Bound` credential; the `jira-observer` stays as it is.
"No credentialed fetch reaches the graph unreviewed" is that every source read with a credential feeds a processor whose mapping in force passed a projection test of that
body, its samples reaching every read: someone has reviewed, in the expected files, what that data becomes.

The steps: the signed-list fix (`polar-sign` writes an optional field one entry leaves out as `None`, and what reads a section takes it as null), so one `sources` version
can hold a source with a credential and one without; a source's `credential`, read through a second operation, `Bound` with the credential the request names; a source's
`paging`, a `Link` header, a page parameter or a cursor path; the Jira-shaped kind through the kit; the invariant in `polar-sign check`; a fresh bring-up.

The credential, done (`polar-http-observer/src/sources.rs`, `observer.rs`). A kind declares `Kind::CREDENTIALED`, its `Bound` operation with `Credential::Chosen`, and
`observer::read` asks it for a source that names one and the `Arbitrary` operation for a source that names none; a kind without one refuses such a source when it is read.
Marked for review: which section a kind declares decides whether a source may name a credential, and it is refused when the section is signed, not only when read. A
kind with no credentialed operation declares `SOURCES`, which refuses `credential`; one with it declares `CREDENTIALED_SOURCES`, which takes it and holds a source that
names one to https, since the handler refuses a credential over plain http (`judge.rs`). Whether the named credential is one the agent holds is the handler's to say
when it reads (`Failure::NoCredential`), since a credential may arrive after the sources that name it.

Paging, done (`polar-http-observer/src/paging.rs`, `observing.rs`, `observer.rs`). A source's `paging` is one of three styles, in either section: `{style: link}`, the
`Link` header's `rel="next"` (GitLab, GitHub); `{style: cursor, next: <JSON pointer>}`, the next page's address in the page (Jira's `nextPage`); `{style: offset, param,
items: <JSON pointer>}`, a query parameter set to how many items were read so far, and a page with none is the last (Jira's `startAt`). `max_pages`, 1 to 1000, default
100, bounds one read. The read operation finds the next page's address from what came back, and the observer's core follows it at the same generation, so a new version
of the source, or a shutdown, stops a read between pages; the property test holds the core to that over any sequence. Marked for review:
- A next page is on the source's own scheme, host and port, whatever the page says: a host does not send the observer, or a source's credential, anywhere else.
  One that names another, or the page itself, fails the read.
- A next page that cannot be found (a cursor that is not an address, a page that is not the JSON the style reads) fails the read, so a paging that cannot work is said
  rather than taken for the last page. The pages before it stay published.
- A read that reaches `max_pages` with more named is published and counts as a problem for the source, as a failed read does: data left unread is worth saying, and
  raising `max_pages` is the way out.

A rule's own guard, `when` (the maintainer's choice, 2026-11-06; `polar-projection/src/lib.rs`, `projection.dhall`). Writing the Jira-shaped mapping showed that a
kind whose sources return different documents could not say which rule is for which: one mapping runs every rule on every page, and Jira's projects, groups and
members pages share one envelope (`{startAt, maxResults, total, isLast, values}`), so the only thing keeping them apart was a rule's key, and a page of projects
counted every project as skipped by the group and member rules. Now a rule may carry `when`, checks of the guard's kind, and writes only the entries every check
holds for; one it does not is another rule's, written by none of this rule and not counted as skipped, so `skipped` again means an entry this rule could not
identify. Marked for review: the checks are read for each entry, where the keys are, so they may test the entry (`item.groupId`) as well as the source's name
(`source`, with a prefix) or the page (`body`); a check on the source or the page decides the same for every entry. Each alternative is a read, `<rule> when
<path>`, so a projection test with full coverage needs a sample it holds for. The property `a_guard_moved_onto_the_rules_writes_what_it_wrote_or_nothing` holds it
to the guard's model. Breaking for authors only: `projection.dhall`'s type now has `when`, so a mapping's Dhall says it on every rule (`[] : List {...}` for every
entry); a body signed before reads it as left out, and no target deploys an HTTP pair, so nothing signed needs migrating.

The Jira-shaped kind, done (`polar-http-testkit/tests/jira_shaped.rs`, `tests/jira-shaped/`): a test kind only, an observer with a `Bound` credentialed operation
and `CREDENTIALED_SOURCES`, a processor writing `JiraTestProject`, `JiraTestGroup` and `JiraTestUser` with a project's lead as `LED_BY`, and a mapping whose rules
say by `when` which entries are theirs. It has the kit's tests, as every kind does, and two of its own through what the kit gained for them: `Pair::credentialed`
(the stand-in behind TLS on `localhost`, a token bound to it by the real binding rule) and `Pair::read_paged` (a source's pages served in its style). Projects are
read by cursor over two pages and members by offset to an empty page, every page with the token, each published and written as it is read; a member Jira does not
identify is skipped, and that is the only skip. Dropping the source's paging, or the credential the fetch presents, fails both.

The invariant, done (`polar-sign/src/instance.rs`, `credentialed_reads_reviewed`; the maintainer's choice, "a tested mapping"). `credentialed-reads-reviewed`: for each
source in force that names a credential, the topics its observer declares and publishes, by its scaffold (`from: declared`; what the builder implies is infrastructure's,
which never carries what a source said), are followed to every workload the model says hears them, and each must have a projection in force that `projections-tested`
would hold for, by the same judgment (`tested`). A hearer whose scaffold takes no projection is violated, since what it writes of the data no reviewed mapping says;
one with no projection in force holds, since it writes nothing; an observer whose scaffold cannot be read is violated, since which topic carries its reads is not
known. A source read with no credential is not this invariant's. Marked for review: where it overlaps `projections-tested`, it says the same thing of the same
projection, from the source's side, so a reader of one credential's claim finds it under that credential's name.

Bite 7 live, a fresh u7c from main at `df4b09de` (2026-11-06): `up.nu sandbox-local --dev --topology separated` ran its 17 steps; the scheduler observer sat idle
with the seeded schedules in its checkout (its CPU time unchanged over ten seconds) now that `72169bdc` stops its endless rescan. The OpenAPI mapping, every rule
saying `when`, signed as version 1: the processor verified it and held it in force within seconds. `polar-sign projection test` passed and was pushed, and `polar-sign
check --ask` asked 18 agents: 12 of 12 invariants hold. `credentialed-reads-reviewed` holds only as "no source names a credential": no deployed kind can carry one
yet, since the OpenAPI observer declares `SOURCES`, which refuses a credential when signed. The credentialed, paged path is shown by the Jira-shaped kind's tests,
and the invariant's holds and violations by its own tests; a deployed kind that declares `CREDENTIALED_SOURCES` (GitLab, next) is where it first holds of something.

## What the OpenAPI pair fixes

Seen reading the code, 2026-11-05. No target deploys them, so there is no data to migrate.

- The observer publishes `polar.web.consumer`, the processor subscribes `polar.openapi.processor`: nothing arrives.
- The processor formats what the document says into Cypher. `GraphOp`, with parameters, ends that.
- The observer reads once at start and then sits idle.
- `utoipa` accepts 3.1.x alone, so a 3.0 or Swagger 2.0 document counts as a failure and restarts the observer. The processor reads only what it needs with a small parser of its own,
  the same for all three, and `utoipa` goes.
- Identity. A node is merged on all its properties, so a new description makes a new node, and operations with no `operationId` collapse into one. Instead, a source's `name`
  keys its document, and the document with a method and path keys an endpoint. Marked for review: the labels `OpenApiApplication` and `OpenApiEndpoint`, prefixed as `JiraIssue` is, so a
  generic `Application` is not taken by the first thing to want it.

## GitLab (planned 2026-11-06)

What is there (read 2026-11-06): five crates (`gitlab/observe`, `consume`, `query`, `schema`, `common`) on the older pattern, a hand-written supervisor and Cassini
client, no `PolarAgent`, no health actor; outside the catalog, enabled by no target, so no deployment holds their data. The observer sends about 2,700 lines of typed
GraphQL (cynic) as POSTs with `GITLAB_TOKEN` from the environment, and never pages: every query starts with `after: None` and `pageInfo` is fetched and never read
(`gitlab/observe/src/users.rs:59`, `projects.rs:67`, `groups.rs:66`). The consumer writes 13 labels and their edges through `GraphOp`, keyed by a UUIDv5 of the base URL
(`lib/src/graph/nodes/gitlab.rs:96-196`), and publishes provenance events besides.

The maintainer's choices: GitLab comes onto this architecture as GraphQL, by extending the library ("GraphQL, extend the library"), not as REST v4 or a Rust walker;
a list nested in each item (a project's pipelines, jobs, packages) is read by a follow-up query per item ("A follow-up query per item"); and a node says which GitLab it
came from by its source's origin ("The source's origin").

Decided by the standing rules, marked for review:
- An observer only reads: a GraphQL source whose query is anything but one `query` operation is refused when signed, by parsing it (`cynic-parser`, already in the
  lock through cynic), not by matching text.
- A GraphQL answer with `errors` and no `data` fails the read, as an error status does; its messages are not repeated.
- The processor only writes the graph: the old consumer's provenance events do not come along (`remaining-work.md` already has the consumer proposing repositories
  instead, later).
- The labels keep their names, with new keys: `origin` and GitLab's own id. Nothing deployed holds the old keys.

The bites:
- **G1, GraphQL sources.** A source may be a GraphQL request (`query`, `variables`), POSTed as JSON to its signed URL; a `graphql` paging style reads
  `pageInfo.{endCursor, hasNextPage}` at a pointer and sets `after` in the variables. An observation carries its source's origin (scheme, host, port), which a mapping
  reads as `origin`; a sample is read at a fixed origin, so what it becomes does not depend on where it was served.
- **G2, a follow-up query per item.** A GraphQL source may name a second query run for each item of each page, its variables from that item, paged by its own cursor,
  each page of it an observation; signed bounds on items and pages. The follow-up asks for its parent's id, so the mapping can draw the edge.
- **G3, the GitLab pair on the library.** `gitlab-observer` (`CREDENTIALED_SOURCES`, a `Bound` operation) and `gitlab-processor` (the labels above), a mapping with
  `when`, hand-written GraphQL samples for each kind of data, and the kit's tests, paged and followed.
- **G4, the catalog and live.** Catalog entries for both; the token a sealed `credentials` section, as Jira's; a bring-up on u7c, where `credentialed-reads-reviewed`
  first holds of a real source. Which GitLab it reads is asked first, since that sends a credential to an outside host.
- **G5, the old pair goes.** The five crates, the hand-written chart, `gitlab-secret` and the GitLab variables, once G4 has shown the new pair working.

G1, done (`polar-http-observer/src/graphql.rs`, `paging.rs`, `observer.rs`; `polar-projection`'s `Stamp`). A source may carry `graphql: {query}`, POSTed as
`{query, variables: {after}}` to its URL with `Request::post_at`, the builder's POST of a whole address. The query is judged when signed by `cynic-parser`: one
operation, a `query`; a paged one declares `$after`. The `graphql` paging style reads `<connection>/pageInfo`: `hasNextPage` false is the last page, true asks the
same query after its `endCursor`, and a missing cursor, or the one just asked after, fails the read. A page's next is an address or a cursor (`paging::Next`), and the
fetch step carries the query and the cursor, so the property model holds both kinds of next to the same rule. An answer of `errors` with no `data` fails the read
without repeating its messages. An observation carries its source's origin; a mapping reads it as `origin`, every write is stamped `polar_origin`, and samples are
read at `https://samples.example`. Marked for review: a GraphQL source signs only its query, constants written in it, and its one variable is the cursor: arbitrary
variables in a signed list would make every source's Dhall type carry them, and G2's follow-up fills its variables from the item it follows. The kit's stand-in does
not serve GraphQL pages yet; G3 does, for GitLab's tests.

G2, done (`graphql.rs` `Each`, `observing.rs` `Reading`). A GraphQL source's `graphql` may carry `each: {items, query, variables: [{name, from}], paging, max_items}`:
for each item of each page, at `items`, the follow-up `query` is POSTed to the source's own address with the item's variables (each a JSON pointer into the item)
and, paged by GraphQL's paging, the cursor; `max_items` (1 to 10,000, default 1,000) bounds the items one read follows. The follow-up is judged as the source's query
is, and must declare each of its variables, and `$after` when it is paged. The read operation picks each page's items (`Page.items`) as it finds the next page, so the
core stays pure; the core holds where each read is (the source's page in hand, or the item and follow-up page in hand) and drops a read that comes back anywhere
else. A read goes page by page: a page is published, its items followed one at a time to their last page, then the source's next page, and its source is held to
the first problem it met when it ends. Marked for review: a follow-up that fails is a problem and the read goes on to the next item, so one project that always
answers 403 does not stop every project after it on every read; a source page that fails ends the read; a host asking for time, on any page, ends the read and says
nothing of health; an item lacking a variable is a problem, not skipped in silence; a follow-up page is an observation of the same source, so the mapping tells
pages apart by what they hold (`when`), and a follow-up asks for its parent's id so the mapping can draw the edge. The model test holds the core to all of it over
any sequence of events at 512 cases, with pages that hold several items so a follow-up failing with more left behind it is common; breaking that rule fails it.

## Open

- **What it did touch.** What a workload could reach is answerable: the catalog, and each signed version of its sections, in git history. What it did reach is one log line per
  request (`RequestRecord`: operation, host, credential's name, verdict), which goes only to the pod's log (`protocol.rs`, `log_request`). The maintainer's chain needs that to last, so it needs
  somewhere durable to go. The handlers' `Recorder` is the place to attach it. Not designed.
- **One workload per kind, or per site?** A kind with credentials may want one workload per site, so two Jira sites are not one identity. OpenAPI has none, so this waits for the second kind.
- **A signed list cannot hold entries with different fields** (`remaining-work.md`). OpenAPI's `sources` are all required, so it does not stop the first kind. Credentials and paging will need the fix.
- **An endpoint a document dropped** stays in the graph, with an older `polar_observed_at`. Not handled further yet. So does a property a new version of the mapping no longer sets (bite 2).
- **The evidence repository refuses deleted branches and rewritten history, and takes any other commit.** The evidence registry's decision (`agentic-control-plane.md`, on its
  branch, 2026-11-05) is a repository that requires signed commits and refuses deletions and rewrites; the second is built as on every repository, and a commit that removes or changes a
  record is the part not built. Decided by the maintainer, 2026-11-06: **add only**, each commit adding files, each a record that verifies in the evidence domain, and not a list of
  signers; a wrong record is superseded by a newer one, never changed or removed, so a failed record stays, which a coverage engine counts on (bites 4, 5). Not built yet.
- **`up.nu` uses whatever `polar-sign` is first on `PATH`.** The dev shell's `polar-tools` package can be older than the tree it deploys; on u7c it refused the seeded policy
  (bite 5, "Checked live on u7c"). Building the tree's tools, or checking the tool's version against the tree's, would end it. Not done.
- **`polar-sign` does too many things.** It signs documents, tests projections, checks an instance, and now asks running agents over Cassini (its binary
  `polar-running-config`). The maintainer, 2026-11-06: it is headed for a refactor anyway; for now it works. Not designed.
- **Dhall evaluation is exponential in nesting** (bite 2, above). A signed projection is within it today. Finding whether the parser or the type checker is the cause, and fixing it in the
  Dhall fork, comes before any section body nested much deeper than a projection's.
- **A mapping's first version.** A processor with no signed mapping holds and says so. It is not seeded: the mapping is in `polar-projection/examples/openapi.dhall`, to sign. A built-in default or a seed are the alternatives.
- **Who owns the graph controller.** The processor spawns its own, as the others do, so it moves again when the builder owns it (`remaining-work.md`).
- **A kind with no binary of its own** would have to reverse `own_name.rs`. This cut does not.
- **Linking a document to the service that runs it,** which is what would make this useful to anything else in the graph. Nothing connects them yet.
