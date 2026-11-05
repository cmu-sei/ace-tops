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

Status, 2026-11-05: a design from a conversation with the maintainer, not built, and the order of its bites not yet cleared. It replaces the plan to repair the
OpenAPI agents as they stand. Paths relative to `src/agents/`.

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

**One fixed topic per kind**, declared in code and computed by the builder, which its processor subscribes to. That is the pairing. A signed section cannot name a topic,
since a hint never widens a signed bound. Each message says which source it is from, when, the status, and the body as it came.

**The observer does not read the document.** It schedules, pages, backs off as a host asks, and publishes. Only the processor parses what a service sent. Observers never
touch the graph (`soft-state.md`). One source failing is reported and does not end the agent or stop the others.

**Size.** The handler bounds a reply at 256 MiB (`MAX_BODY`) and Cassini a frame at 64 MiB (`MAX_FRAME_BYTES`, `MAX_PAYLOAD_BYTES`), so the engine's bound is the
smaller, and a document over it is a reported failure for that source.

**Configuration stays small and closed:** a URL, an interval, a credential and a paging style (none, a `Link` header, a page parameter, a cursor path). What has state or
branches is a Rust walker plugged into the engine, with the engine's scheduling, backoff, health and publishing. Otherwise every quirk becomes an option, and the
configuration a poor programming language. Jira's observer is about 5,600 lines: a cursor read back through the state agent, JQL date windows, different Cloud and Data Center
paths, a group picker that ignores `startAt`. GitLab's is about 2,700 lines of typed GraphQL POSTs. Neither would become configuration, though Jira may become a walker.

**The processors stay by hand for now.** A signed mapping (for each item at this path, upsert this label keyed on this field) would cover OpenAPI and flat lists, and
not Jira's changelogs and custom fields; its labels and constraints would have to be declared and checked too (`GraphDecl`, `GRAPH_KEYS`). Worth looking at again after two or three
processors exist, to see what really repeats.

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
- **An endpoint a document dropped** stays in the graph. Not handled yet.
- **Linking a document to the service that runs it,** which is what would make this useful to anything else in the graph. Nothing connects them yet.
