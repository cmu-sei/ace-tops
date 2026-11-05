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
| Processor | its schema: labels, what identifies each, edge types (`polar_projection::Bounds`) | which data goes where inside that schema: the mapping |

So the agent judges a signed mapping against its `Bounds`, and a mapping can only choose data within them. That settles three things a mapping free to name labels left open: constraints are made at
the controller's first contact with the graph, from the built schema; the state agent's first schema still comes from scaffolds; and one workload cannot write another's labels. The cost: a new label needs
a new build of that small crate. So a new endpoint, or new data from one, needs no binary change, and a new kind of thing in the graph does.

**The type is for the author, and the agent trusts none of it.** `polar-sign runtime --projection <file>` checks the Dhall against the type, then that it is well formed. Imports stay off, so a file cannot name
the type and the tool gives it. The agent judges the JSON again, and against its own bounds, which `polar-sign` does not know. The type has no Optional, because a signed document cannot hold a null, and
it is flat, because a Dhall type cannot refer to itself: an empty `parent`, `edge` or `only` means none. `polar-projection` has no graph or runtime without its `graph` feature, so the tool that holds an
administrator's key takes neither.

**A document is a snapshot.** A value it no longer has is cleared from the node, since `SET n += row.p` removes a null. Otherwise a source that moved from a 3.0 document to a 2.0 one held both versions, as was seen live.

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

An endpoint a document dropped stays in the graph, but its `polar_observed_at` falls behind, so it can be told apart: that is the start of handling it.

**Not seen live, tests only:** a document from a publisher other than the observer, a document over the size bound, and a host asking for time. **Not run:** a fresh bring-up with these agents, and their health being asked by the state agent, whose first `agents` was seeded before they existed.

Removed afterwards: the documents, the server, and the test nodes. The two agents remain deployed, the observer reading nothing and the processor holding.

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
| Labels it may write | Declared in `GRAPH`, not enforced on writes | Enforced by `Bounds` when the mapping is judged | **Stronger** |
| Cypher injection | Parameters, by each author's care | By construction, and names judged again by `validate_cypher_identifier` | **Stronger** |
| Sensitive data in the graph | A reviewer sees what code copies | A signer can project any field of what was fetched. With a credential, that could be a route out | **Weaker, and matters at the first kind with a credential.** OpenAPI has none |
| What the graph knows of itself | Whatever the code writes | Every node and edge stamped: source, workload, mapping version, time | **Stronger** |
| What ran | The image digest, by attestation | The digest no longer says all of what it does: digest and signed section together do, and each signed version is in git | Different. Slice C should count this |
| A hostile document | Each parser's care | One engine, property-tested on any JSON; a bound on writes, refused whole | **Stronger** |

## Datalog

The maintainer asked whether the credentials agent's engine helps here. `ascent` is a macro: its rules are compiled, and only its facts arrive at run time (`credentials-agent/model/src/rules.rs`), so it cannot run a signed mapping, and
`authority-model.md` already says rules written by administrators would need a runtime engine. A mapping needs no recursion either, and a more powerful language would be harder to reason about.

It may help with the question this design exists for, though. "This service was compromised: what could it touch?" is reachability, which the authority model already computes over topics. Facts from the catalog and
from each signed version (a workload's sources, its credentials, the labels in its bounds) would answer it with a rule, and would have caught `polar.web.consumer` going nowhere. Not designed: a place to go when the provenance chain is built.

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

## Open

- **What it did touch.** What a workload could reach is answerable: the catalog, and each signed version of its sections, in git history. What it did reach is one log line per
  request (`RequestRecord`: operation, host, credential's name, verdict), which goes only to the pod's log (`protocol.rs`, `log_request`). The maintainer's chain needs that to last, so it needs
  somewhere durable to go. The handlers' `Recorder` is the place to attach it. Not designed.
- **One workload per kind, or per site?** A kind with credentials may want one workload per site, so two Jira sites are not one identity. OpenAPI has none, so this waits for the second kind.
- **A signed list cannot hold entries with different fields** (`remaining-work.md`). OpenAPI's `sources` are all required, so it does not stop the first kind. Credentials and paging will need the fix.
- **An endpoint a document dropped** stays in the graph, with an older `polar_observed_at`. Not handled further yet.
- **A mapping's first version.** A processor with no signed mapping holds and says so. It is not seeded: the mapping is in `polar-projection/examples/openapi.dhall`, to sign. A built-in default or a seed are the alternatives.
- **Who owns the graph controller.** The processor spawns its own, as the others do, so it moves again when the builder owns it (`remaining-work.md`).
- **A kind with no binary of its own** would have to reverse `own_name.rs`. This cut does not.
- **Linking a document to the service that runs it,** which is what would make this useful to anything else in the graph. Nothing connects them yet.
