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

# Protocol handlers: the domain's I/O in infrastructure

Status, 2026-11-04: the design, from the maintainer, vetted. Built, in bites: the framework, HTTP and its registry scheme, git and the Kubernetes API, with jira-observer, the resolver, the git observer, the Kubernetes observer and the attestation agent on them, and the old routes closed. GitLab and OpenAPI move when they reach the builder, and are held to it then ("When, and in what order";
`polar-agent-builder/src/protocol.rs`). Framework code that lets us reason about
each request a domain actor makes, whether to allow or deny it, and that protects the credentials it uses. The domain says what it
wants; a protocol handler in the builder's infrastructure gets the credential itself, uses it, and calls the domain's code with what
came back. No code a developer writes on the domain side can be given the credential.

## Why

A token reaches domain code today. `jira/observe/src/lib.rs:354-369` asks `CryptoClient::http_credential` for it and calls
`req.bearer_auth(token)`; the token is also read there to warn when it looks base64-encoded. The git observer is handed its own through
`git_credential` (`git/observe/src/credentials.rs:351`). The GitLab observer reads `GITLAB_TOKEN`, the resolver a Docker config file, and
OpenAPI's client is a bare `Client::new()`, with no egress at all. So every agent that speaks a protocol solves the same problems itself:
attaching the credential, the egress proxy and CA, rate limits, tracing without the secret, what a 401 or a 404 means for its health, and
picking up a new token. Nobody can say what requests an agent makes, or refuse one. Mechanisms accumulating around one need is the shape
being wrong (`AGENTS.md`).

The direction was set on 2026-10-14 (`credentials-agent-architecture.md`, "Named operations on registered secrets"): every use of a secret
passes through one place, the `CryptoActor` makes no network calls, and I/O actors carry out what needs I/O as pure decisions around a thin
effectful edge. They were never built, and on 2026-11-01 `HttpCredential` went the other way for lack of them, "DECIDED, to review", handing
the caller the header's material. This design builds them and closes that.

Where the handler came from: a side conversation of 2026-10-14 about a friend's design, a sidecar that injects secrets into a workload's
plaintext requests. The appeal is that the workload never holds the secret. The objection is that something rewrites a request
behind the code's back, so the code does not say what really happens, and a Kubernetes proxy is not how Polar works.

## What it does for the code (the maintainer, 2026-11-02)

"I can test and validate so much of the code that makes up an agent this way, and writing domain logic reduces to writing domain
logic." This is as much the reason for the design as the secret is.

- *The I/O is tested once.* Redirects, the egress proxy, rate limits, a refused credential and a dropped connection are the
  handler's, tested against real servers in one place, and every agent inherits them. Today each agent carries its own version and
  its own tests of it.
- *Domain logic becomes a function.* A callback takes what the handler gives it and returns a value, so it can be tested with no server,
  no actor system and no certificates, and it is a natural place for property tests: any response, any page, and the rule holds.
- *What is left to test per agent is small:* its callbacks, and one run through the handler showing that they are wired up.
- *A new agent is mostly its domain.* What the builder does for health, Cassini and shutdown it now does for the agent's I/O too, and
  `polar_agent_tests!` can grow to check what an agent declares it uses.

## Decisions (the maintainer)

2026-11-02:
- **Generalized I/O handlers, one for each protocol Polar speaks,** in the builder's infrastructure, working on behalf of the
  domain actor that needed something. Not a Kubernetes sidecar and not a proxy.
- **A callback never sees the secret; the handler attaches it.** An unusual authentication scheme, such as a signed request, is added to
  the handler rather than worked around in an agent.

2026-11-03:
- **Every service at once, not HTTP first.** The answers for all of them shape the framework, so the protocol handler only needs to know
  the specifics of the request.
- **The domain declares the credential.** The declaration maps it into the agent's catalog section. Applied, it is stored in the
  credentials agent. When it is needed the domain asks infrastructure for the work, using that credential by name.
- **The protocol handler gets the credential from the `CryptoActor`, itself.** The domain names the protocol and the request. The handler
  uses the credential to retrieve the data, then calls the callback to process it. "The developer shouldn't be able to just write a
  function that returns the credential."
- **A request's location** is either retrieved by the agent's configuration actor, or something the agent is allowed to do: a controlled,
  monitored request not known ahead of time, as part of how the domain needs to operate. "We allow it that privilege."
- **That privilege is a permission for an arbitrary request, probably not an arbitrary request with a credential.** The maintainer is open to
  it being needed; so far it is not (below). "Either way, it's getting logged and reviewed, eventually."
- **The domain side only.** The credentials agent and cert-issuer do not use this: it is meant for the domain side, "of which credentials
  agent is sort of special".

## The flow

1. **Declare.** `PolarAgent::CREDENTIALS`, with what `protocol::credentials::section::<MAX>(doc)` makes. As the agent's other facts are, it is
   a constant of the trait, since the scaffold is printed without running the agent. The builder computes the rest: the `credentials` runtime
   section appears in the scaffold and so in the catalog, as `polar::egress::SECTION` does (`egress.md`, "How it stays opt-in"), and the
   agent needs encryption without listing it. Jira and git each write that section by hand today (`*/observe/src/credentials.rs`); it is
   written once, in the builder, and they lose theirs as they move. The catalog carries that the credential exists, never its value.
2. **Apply.** As built. The value is signed as an `EscrowedSecret` for this agent. The `CryptoActor` opens it through the custody daemon, keeps it
   with its binding, and escrows both with the credentials agent (`StoreSecret`, `signed-configuration.md`). The builder does this
   for the section, so the domain no longer calls `register_secret` or `replace_section`.
3. **Register, at load.** `PolarAgent::OPERATIONS`, each a request type's declaration, so nobody declares it twice and it cannot differ from
   what runs. The list is a constant, and each `read` is compiled code called directly, so there is no table of pointers to change. This is the callback
   "registered at load", which is where IO effects really occur, and it pairs with the lock in `runtime-attestation.md`. What an agent can ask
   for is a fact the builder knows, so the scaffold prints it under `operations`.
4. **Ask.** The domain actor sends the request. It names no secret value, holds no client, and gets on with its mailbox.
5. **Judge.** One pure function decides, and the decision is logged (below).
6. **Fulfil.** The protocol handler asks the `CryptoActor` for the credential for that host. The `CryptoActor` checks the binding, where
   the secret lives. The handler attaches it, makes the request through the egress proxy and CA, and drops it.
7. **Process.** The handler calls the registered callback with what came back.
8. **Return.** The callback's value reaches the domain actor as an ordinary message.

```rust
impl PolarAgent for JiraObserver {
    const CREDENTIALS: Option<&'static RuntimeSection> = Some(&CREDENTIALS);  // the catalog learns of it
    const OPERATIONS: &'static [OperationDecl] = &[Projects::DECL];           // fixed at load
    // ...
}

impl Operation for Projects {
    type Protocol = Http;
    type Output = Vec<Project>;
    const DECL: OperationDecl = OperationDecl {
        name: "jira.projects",
        doc: "the projects the token can see",
        protocol: ProtocolKind::Http,
        location: Location::Configured { variable: "JIRA_URL", credential: Some(Credential::Named("jira")) },
    };
    fn request(&self) -> Request { /* the specifics */ }
    fn read(&self, reply: &Reply) -> Result<Self::Output, ReadFailure> { /* domain logic */ }
}

let projects = protocols.ask(Projects { start_at }).await?;   // waits, holding only this actor's mailbox
let watching = protocols.stream(Pods { namespace }, myself, Message::Seen)?;   // one message for each change, until `watching` is dropped
```

`Protocol` is the trait each handler implements, and it says only what differs: its request, how a credential attaches, and what a callback
reads. Everything else is written once: the operations, the judgment and its log, asking for the credential, egress, the budget, tracing,
and a refused credential becoming a held `Credentials` report (`polar-agent-builder/src/held.rs`), cleared by a new version.

### No way to the credential from domain code

A rule the developer has to remember is not the rule asked for. By possession, not by convention. Every route is closed, as built 2026-11-04:

| Route | Closed by |
|---|---|
| `CryptoClient::http_credential`, `git_credential` | removed from the trait; compile-fail doctests hold it (`polar-agent-builder/src/crypto.rs`) |
| `CryptoMessage::HttpCredential`, `GitCredential` | removed. What asks now is `UseCredential`, with the `CredentialPass` the builder made when it spawned the actor, compared by identity. The handlers hold the port, and nothing hands it on |
| `CryptoHandle::as_actor_ref`, which gave the domain every message there is | removed. A method for the builder's own use stays, `pub(crate)` |
| `CryptoClient::register_secret`, `replace_section`, `load_secret`. **Found closing the others:** an agent can read the ciphertext in its own section, so it could register that under a binding of its choosing and have the handler present the token there | moved to a `pub(crate)` trait, `SectionKeeper`, for what the builder does with a section. `load_secret` had no caller left, so it goes from the client; the message stays for key rotation's re-delivery, which is designed and not built (`key-rotation.md`, P20) |
| `CryptoClient::retrieve_secret`, which answers with plaintext, for the escrowed `<identity>/<name>` | refused, `IsACredential`, **by what the record is rather than by its name as first designed:** a name check would pass one not registered yet in this run, or withdrawn, and an agent can ask for both. A secret stored any other way still comes back |
| its own client, or a `CryptoActor` or custody client of its own | `polar-agent-builder/tests/domain_has_no_way_out.rs`, over `cargo metadata`: no domain crate on the builder has one of them, by itself or through a helper crate, in anything but its tests. A new agent is held to it without being listed |
| `git2` and `oci-client`, which two crates keep for what they read | `clippy.toml`, since a dependency cannot say which methods: the git observer may not fetch, connect, push or clone, and the resolver may not name `oci_client::Client`. Allowances are listed in the test with their reason, and one nothing needs any more fails it |

Left out of that test by decision, each listed there with why: the credentials agent and cert-issuer (the maintainer, above), the broker, the git server and the custody daemon, which serve. Not on the builder yet, so not held: GitLab, OpenAPI and build-processor, which still have `reqwest` until step 7 and step 9.

To go further would take the process apart, not more checks: a raw socket is not a dependency, and domain code could speak Cassini to the credentials agent itself, though it would then have nothing to open the answer with. What this closes is a developer's mistake and a logic bug, as it set out to.

What a callback reads has no route either: a `Reply` holds the response's status, headers and body, never the request that was sent. Domain code
that wants a fact about a credential asks for the fact (Jira's "this token looks base64-encoded"). A server that echoes its request headers
into a body is the one thing the handler cannot take away; a credential goes only to a bound host, so that is a host already trusted with it.

This stops a developer's mistake and a logic bug. It does not stop code injected into the process, which shares the address space (below).

The token stays in the `CryptoActor`'s registry in the agent's memory (`polar-crypto/src/lib.rs:371`), asked for on each request, so a new signed
version takes effect by itself. The custody daemon holds the escrow key and unwraps each secret's AES key; it does not hold tokens.
Moving them there would mean the daemon also makes the request, which is the seam below and not this work.

## Location, and the permission

| Location | Where it comes from | Credential | Example |
|---|---|---|---|
| `Configured` | a variable of the agent's, read as it is in force at each request | if the operation declares one and the host matches its binding | Jira and GitLab's site |
| `Bound` | the domain, at run time, and the host must match the credential's signed binding | always | the git observer's repositories that name a credential; a registry a credential is bound to |
| `Arbitrary` | the domain, at run time, with the permission declared on the operation | **never**: the declaration has no place to name one | OpenAPI following a document's URL; a public repository; a registry nothing is bound to |
| `Cluster` | Kubernetes, which tells every pod where its API is. The request can name no host | the pod's service account token, which no section holds: recorded as `service-account`, and only over TLS | the Kubernetes observer's and the attestation agent's watches |

- A path, a query and a page belong to the request; the host is what is judged. A location a response gives, such as GitLab's `Link` header, is
  judged like any other: another host is not the same request.
- A redirect is judged at each hop. A credentialed request is never followed to a host off its binding: it fails and is reported.
- The permission is declared on the operation when it is built, so the builder knows it and the catalog says it. Applying the catalog is the
  sign-off (`policy-enforcement.md`).

Proposed, to review: `Bound`. The **resolver** learns registries from the images it sees (`resolver/src/registry.rs`), and the git observer's repositories
come from the controller naming their credential. The host is the domain's, but the host pattern a credential may go to is signed, so a match is a
location someone signed off and not an arbitrary request. A credential the request names and the host does not match is `NotBound`, and nothing is sent.

Which credential, three ways (`judge::Credential`): `Named` by the declaration, `Chosen` by the request, and `ForHost`, by nobody. The resolver has no name
to give: a registry is whatever an image says. So the CryptoActor says which secret's binding names the host, the closest pattern first and among equals the
first name (`registry::bound_to`), and answers with a name. It decides once, where the request first goes, and stays that credential at every later hop, whose host
its binding must also name. If none is bound the verdict is `NoCredentialBound`, nothing is sent, and the domain may make the `Arbitrary` operation it declared.
So each read of a public image is two lines on the record, the refused `Bound` one and the allowed `Arbitrary` one. Decided while building, to review: the record says
exactly what happened, at the cost of a refusal that means nothing for every public image, which the dashboard will have to tell apart.

## The judgment

`judge(operation, location, binding, permission) -> Allow | Deny(why)`: pure, with no I/O, and a natural property test. Every request gets a line at
one place: the operation, the protocol, the host, whether a credential was attached (its name, never a value), and the verdict, with
`Arbitrary` marked. Hosts only: a path or a query can carry what should not be logged. Logged now, and reviewed eventually: the security dashboard
reads it when it exists (`remaining-work.md`, "A Polar security dashboard"). It is not a Cedar decision yet (Open).

## The protocols

| Protocol | Domain's users | Credential | Callback reads | Moves |
|---|---|---|---|---|
| HTTP | Jira, GitLab, OpenAPI | declared | a reply, whole and bounded | Jira now; GitLab and OpenAPI at step 7, when they reach the builder |
| OCI registry | resolver | declared | a manifest | built, 2026-11-03. A breaking change, with its migration note (`remaining-work.md`) |
| git | git observer | declared | the fetched `git2::Repository` | built, 2026-11-04 |
| Kubernetes API | Kubernetes observer, attestation agent | the pod's service account token, which `kube` already picks up: the capability declares it, not `with_credential` | one change at a time | built, 2026-11-04 |

- **OCI is HTTP with one more authentication scheme, not a handler of its own** (`Request::at_a_registry`, `protocol/http.rs`). A registry's token exchange is the
  unusual scheme the decisions provide for, and it is needed: `oci-client` sends Basic credentials to whatever host the registry's `WWW-Authenticate` realm names (read in
  0.18.0's `client.rs`, the `get(realm)` with `apply_authentication`; not tried), so a binding cannot be enforced around it. The request goes with nothing at first. On a
  401 a `token` credential goes to the registry as it is; a `user-password` goes to the registry for a Basic challenge, or for a Bearer one to the auth host it names, judged as a hop
  against the same credential's binding, and only what comes back goes to the registry, and no further than that host. So a binding for a registry names its auth host too:
  `*.docker.io`, or `registry.gitlab.com,gitlab.com` where one wildcard cannot say both, which is why a pattern may now list several. The registry's word alone is not enough for an auth host,
  since a token from a host we hold a login for, handed to any registry that asked, is a leak. So a credential is never found by the auth host, only by the registry.

  **A change from what was vetted, to review.** This said the handler would do the exchange and give `oci-client` the bearer token. Reading how it would run, that cannot work: `oci-client`
  caches the first auth of each registry for good (`store_auth_if_needed`) and reuses it, so a token scoped to one repository would be presented for the next and a new signed version never taken up;
  it follows redirects itself, with no way to judge them; and a Basic-only registry still needs Basic handed over, whereupon it would follow a Bearer challenge by itself. So the handler makes the request as
  well, and `oci-client` stays for its types alone (`Reference`, `OciManifest`). The checks that made its client worth having are in the resolver's `read`: the digest of the body against the header and against the
  digest the image names, and the schema version and media type. One client for the agent, whose egress is the handler's, in place of a second that needed its own proxy and CA.

  The anonymous path is the same exchange with nothing presented. A registry can make it fetch any address as its auth host: a GET, with no credential, of which nothing but a token is ever read, recorded
  as the permission it is. The old client did the same, without the record.
- **Git keeps libgit2** (`protocol/git.rs`). It does its own I/O and asks through a callback, and that callback is the handler's. It offers the credential once for each connection, and only when the host
  challenges: asked again means refused, which is held like any other (libgit2 would otherwise ask up to its limit of replays). A test shows that the token is in no file of the clone. The CA (`trust_ca_file`) and the timeouts are global to libgit2, so they are set
  once, by the handler. The two timeouts go together: the connect timeout leaves the socket non-blocking, and with no server timeout every read fails at once with `EAGAIN` (found by a mutation). Bounds: `CONNECT_TIMEOUT` 15 s, `SERVER_TIMEOUT` 120 s for each read or write,
  and `MAX_FETCH` 16 GiB, to review, since a fetch goes to disk and nothing bounded it before. Each request runs on a blocking thread, where the worker used to block a thread of the runtime.

  **A redirect to another host fails, with or without a credential, decided while building, to review.** "A redirect is judged at each hop" cannot hold here: libgit2 follows it inside the fetch and never asks, so the hop would be neither judged nor on the record, and a repository's contents would come from a host nobody signed off.
  The credential itself does not go along: with `RemoteRedirect::Initial`, the default the old code had, a redirect after the login reached the other host with nothing presented (tried, 2026-11-04), and were that host to challenge, the callback would refuse it as another host. So `RemoteRedirect::None`: within the host it still
  follows, and libgit2 itself refuses https to http. A public repository that moved to another host now fails, saying so, where it used to be followed. The address in the controller's section is what to change.

  **What `read` does (decided while building).** It finds what each ref would publish, from the checkpoints the operation carries: the plans, commit ids only. The events are then made a batch at a time as the client takes them, by the worker from the clone it opens itself: a `read`
  returns once, and holding a whole walk's events to return them is what `cassini-backpressure.md`, decision 17, ended. So the observer keeps `git2` for reading the clone on disk, which the "beyond the types it reads" of the table above allows, and it is a local read. Nothing yet stops
  it calling `Remote::fetch` itself: bite 6's test over `cargo metadata` cannot see that, so a lint must (`#![deny(clippy::disallowed_methods)]` is on the crate already).

  A clone's URL is the request's, read as the controller reads it: a test holds `git_agent_common::remote::https_host` and the handler to the same host for any text the first accepts. Only http and https go anywhere now; a path, `ssh://` and `git://` used to reach libgit2 for a public repository.
- **Kubernetes needs a stream, so one request and many results is part of the framework now** (`ProtocolHandle::stream`, `protocol/kubernetes.rs`). A watch never ends.
  `kube`'s own watcher stays, and the callback is called per change, each value a message. The token's file stays readable in the pod, which no handler changes: Kubernetes is the trust base.

  **`Location::Cluster`, decided while building, to review.** None of the three locations was true of it. The address is not a variable of the agent's and the token is not a section's, and it is hardly arbitrary. So a fourth: Kubernetes says where, the
  request can name no host at all, and it goes only over TLS. The capability says it has a token to go with: an agent with such an operation and neither `kube-api-read` nor `pod-read` does not pass `polar_agent_tests!`. What a watch is of is not on the record, which has hosts only, and the Role or ClusterRole is what bounds it.

  **A stream is paced, and ends once.** What is published can have to wait (`cassini-backpressure.md`), and a watch that piled up in a mailbox would undo that. So each message holds a `Delivery`, and the next change is not read until the actor has let go of it, which it does by finishing with the message. One stream's wait holds no other's. Decided while building, to review.
  A stream ends when its `Streaming` is dropped, or with one failure, which is its last message. A change `read` cannot make sense of ends it as well: a stream says each change once, so one that was lost leaves a gap, and the watch that replaces it starts from a list. There are no retries in a handler, so asking again is the domain's: each agent waits 5 s after a watch is lost, and the observer 5 minutes after the API refuses one (403) or does not serve the kind (404), as Flux's kinds may not be there.

  **One protocol for every kind, so what it hands on is JSON, decided while building.** `Protocol::Request` is one type, and `kube`'s `DynamicObject` watches any kind by name (`Resource`, `Resource::of::<Pod>()` for a type the API defines). So the attestation agent's `read` parses each object into its `k8s-openapi` type, and the observer publishes it as it came. Neither crate has `kube` any more, but for the observer's tests of Flux's names. An object of a list has its `apiVersion` and `kind` written back, which a list's items do not carry.
  The observer used to go through its own types, so a Flux object it had no field for lost that field, and one it could not parse stopped the watch. Now the consumer sees all of it, and is what has to read it.

  **What the observer's move changed.** The handler holds the loop, so most of the actor tree had no reason left: one actor per watch, a supervisor per namespace, and the macros to make them. Now `ClusterWatcher` holds every stream and publishes, and the supervisor, which it would otherwise hold up when a publish waits, still hears the client and shutdown. Four behaviours differ, each to review:
  - *A lost watch comes back.* Before, a watcher that lost the API stopped and nobody restarted it (`NamespaceWatcherSupervisor`'s `handle_supervisor_evt` only logged), so it was blind to that kind in that namespace until the pod's next restart, within the hour. The doc comment said that supervision would restart it.
  - *A relist is published.* The watcher's own list was ignored after a separate one at the start, so what changed while a watch was lost never went out. Deletions in that time still do not: the consumer has no way to hear them, as when the observer itself restarts.
  - *A namespace that went while its watch was lost* stops being watched, by not being in the next list.
  - *Shutdown no longer times out by design.* `stop_and_wait` on an actor in an endless `handle` could only time out, and the `?` on it would fail the supervisor, which reaches the exit by accident (read in the code; not seen in a log). `SHUTDOWN_BUDGET` is now 20 s rather than 40.

  Gone with the tree, unused: the watchers defined for nodes, CRDs, ClusterRoles, ClusterRoleBindings, Secrets and ConfigMaps, none of which were ever started.
- **Responses are bounded and whole for HTTP and git.** Paging stays in the domain, as one request per page.

*Stays as it is, with no credential to protect:* Cassini, which is infrastructure's already. Bolt: the domain sends the graph controller messages
and has never had `GRAPH_PASSWORD`. The trait is checked against it; moving it is the existing open item (`remaining-work.md`).

*Not this framework:*
- the credentials agent's introspection and cert-issuer's JWKS fetch (the maintainer, above). It stays known that the introspection client secret is a
  plain `String` from a setting (`credentials-agent/consume/src/introspection.rs:50`), and the credentials agent cannot ask itself for it;
- the configuration agent's `git` command, to Polar's git server with a client certificate (`polar-scheduler/observer/src/git_ops.rs`): no credential,
  and it is what delivers configuration. Proposed, to review;
- what runs before or outside the builder: `polar-init`'s handshake, the admin tools, `polar-sign`; and `polar-git-server`, which serves git.

### Callbacks and the actor rule (proposed, for review)

A callback runs domain code inside infrastructure, and actors exchange messages and never touch each other's state (`AGENTS.md`). So:
- `read(&self, reply)` has the request's own values, which the domain moved into it, and what came back. It returns a value, and that value reaches the
  domain actor as an ordinary message. Not a plain `fn` as first proposed: git's needs the commit it last saw and Jira's the page it is on. So what keeps actor
  state out is the review of what an operation holds, not the compiler;
- each call runs on its own blocking task with its own budget, so a slow callback stalls neither the handler nor anyone else's request. One past its
  budget is reported and its result dropped. A stuck `read` cannot be killed, so it costs a thread until it returns, and that is left to show;
- **no retries inside a handler.** The 2026-11-02 list had retries here, but Jira retries at the level of the pull, and retrying in both multiplies attempts
  and hides failures. One attempt, a failure kind returned, and no call to a host before its `Retry-After` has passed. Let it fail, and see why.

## What it closes and what it does not

| A secret leaking through | With handlers |
|---|---|
| a log line, an error message or a trace in domain code | closed: domain code does not have it |
| a redirect or a wrong host, by a mistake in the agent | closed in one place: the handler decides what is sent where |
| a logic bug in code parsing what a server sent | closed: that code runs with no access to the secret |
| a developer writing a function that returns the credential | closed: nothing it could call answers with one |
| code injected into the process, reading its memory | **not closed** |

It is one address space, so it does not change what remains in `runtime-attestation.md`, "Runtime attestation of the process".
The interface is the seam if a handler ever has to move out of the process: the request is already a plain, explicit message.
Private keys are already out of the process, in the custody daemon (`key-custody.md`); tokens are not.

## When, and in what order

The HTTP handler was placed after runtime attestation's slices A and B and before the sequence diagrams, the Dynamic settings and the GitLab and
OpenAPI migrations, so those agents move onto it once and not twice (the maintainer, 2026-11-02; `remaining-work.md`, "The order of work"). The
place stands, for all of it. In bites, each reported before the next:

1. **Built, 2026-11-03.** The framework: `Protocol`, operations, `judge` and its record, the port from the `CryptoActor` (`polar_crypto::CredentialPort`, whose
   `CredentialPass` the actor compares by identity), `PolarAgent::CREDENTIALS` and `OPERATIONS` and the facts they give the scaffold, the section handed to the
   `CryptoActor`, a refused credential held and cleared by a new version, and a host's `Retry-After` honoured. Against a test protocol, no real one.
2. **Built, 2026-11-03.** HTTP, against real TLS (`protocol/http.rs`): one attempt, each redirect judged, a bounded reply (`MAX_BODY`, 256 MiB, to review: nothing
   bounded it before), and the egress section brought by the operation. Jira moves: two operations, the credential named `jira`, and `ProtocolHandle::ask`, since its observers go through
   their pages in order and waiting holds only their own mailbox. `stream` is for a stream.
   Checked live on u7s, 2026-11-03, reading Apache's Jira anonymously: the agent starts, each request is on the record, and issues keep arriving in the graph (2,343 to 2,351, the
   cursor moving on, projects unchanged). Starting the client there found a lost `Registered`, fixed for every agent (`infrastructure::catch_up`). **Not checked live: the credential path.**
   The sandbox reads anonymously, so the real `CredentialPort`, an applied section and a presented token have run only in tests.
3. **Built, 2026-11-03.** The registry scheme, and the resolver moves (above), with its section, `Credential::ForHost` and host patterns that list several. Tested over real TLS against stand-ins, and against a
   real `registry:2` anonymously and with an htpasswd login behind TLS (right password, wrong password held, a binding for another host asked with nothing).
   Checked live on u7s, 2026-11-03, anonymously: each image goes through both operations on the record, and real exchanges work. Docker Hub (`index.docker.io`, a token from `auth.docker.io`), ghcr.io (its own host for both),
   quay.io (no challenge), and `registry.k8s.io`, which redirected to `us-east4-docker.pkg.dev`, a hop judged and recorded. Two throwaway pods of images new to the graph took `OCIArtifact` from 4 to 6 and joined their `PodContainer`s, each digest the kubelet's `imageID`.
   The real `CredentialPort` answered every `bound_to`. **Not checked live, still: a credential presented.** No registry the sandbox reads wants one; a real one, or one set up for it, is needed. The `localhost:30500` images fail as they did before
   (`remaining-work.md`).
4. **Built, 2026-11-04.** git, and the git observer moves (above). Tested over real TLS against a stand-in that speaks the smart protocol (`testing::GitOrigin`), through libgit2 itself.
   `ProtocolKind` became what a protocol starts through, rather than a list, so that a protocol is linked only into an agent that names one: `git_libgit2_init` is in `git-repo-observer` and in neither `jira-observer` nor `oci-resolver` (`nm`, debug builds). Decided while building, to review; Kubernetes will want it too.
   Checked live on u7s, 2026-11-04, **a credential presented for the first time**, against a throwaway git server in the cluster, TLS under a CA given by the target's `cluster.egress.ca_file`, with a login. A real signed `credentials` section went through `polar-sign`, the
   custody daemon and the real `CredentialPort`. With the wrong token: the server saw a request with nothing, then one with the credential, once, and refused it; the agent held `Credentials` and did not try again. A new signed version with the right token: the hold cleared, the handler asked at once, the server accepted, and both commits are in the graph. The withdrawal
   (`withdrawn=1`) and a public repository, `octocat/Hello-World` from `github.com`, recorded as arbitrary, work too. **Still not checked live: a credential presented over HTTP**, Jira's or a registry's. They share all of this but `CredentialPort::http` and the `Authorization` header.
   Signing that credential found that **nothing could be sealed to an agent at all, since 2026-10-27** (`polar_signing::verify_escrow_certificate`, fixed), and that a signed list cannot hold entries with different fields (`remaining-work.md`).
5. **Built, 2026-11-04.** Kubernetes and the stream, and the Kubernetes observer and the attestation agent move (above). Tested over real TLS against a stand-in API (`testing::KubeApi`), through `kube`'s watcher.
   `kube` is linked into those two agents and no other, by `nm` on debug builds: `problems()` first compared against `ProtocolKind::KUBERNETES`, whose function pointer would have linked it into every agent, so it asks the kind instead (`to_the_cluster`).
   Checked live on u7s, 2026-11-04. `kube-observer` makes 47 watches (3 across the cluster, 4 in each of 11 namespaces), and `attestation-agent` 15 (5 in each of 3), each on the record with the API's address and `service-account`. The attestation agent listed everything and proved itself, 23 judged and none condemned; pods, containers and replica sets kept arriving in the graph.
   A namespace coming and going: 4 more watches, its pod in the graph, and a Flux `OCIRepository`, the first on this cluster, in the graph as `FluxOCIRepository` by way of the raw object. Deleted, it asked for nothing more; made again, 4 new ones, so it had been let go.
   The API refusing, by taking away a binding and restarting the pod: the attestation agent's 5 watches in `polar-graph` said 403 and were asked for again every 5 s, and with the binding back it was ready and had proved itself within 5 s, with no restart. The observer's 3 cluster-wide watches said the same, and came back at their 5 minutes (47 watches and those 3 asked again), with no restart.
   A real shutdown of the observer: `PrepareShutdown` to the end of the infrastructure in under a millisecond, the pod gone in 1 s.
   **Not checked live:** a watch lost to something other than a refusal, an API server restarting say (only against the stand-in), and a broker falling behind slowing a watch (only with a stand-in for the client). No credential of the CryptoActor's goes this way, so bite 4's open item, a credential presented over HTTP, stays open.
6. **Built, 2026-11-04.** The routes close (the table above). The diagrams as built: `sequences/general/protocol_handler_request`, and `protocol_handler_stream` for a watch.
   Checked live on u7s, 2026-11-04, with every agent rebuilt on it: all 20 pods running with no restarts, Jira issues still arriving (2,712), both watching agents on the record as in bite 5, the git observer applying its section, and the real `CredentialPort` answering the resolver's `bound_to` with the pass (`no credential is bound`, 3 records). **Not repeated: a credential presented**, since no credential is in force on the cluster. The port's code did not change, and the actor with a real custody daemon is tested through it; bite 4's live check stands, and a credential presented over HTTP is still open.

## Open

- What a callback's budget is, by protocol.
- Whether a Dynamic setting's reaction shrinks when a URL or a host is the handler's to pick up. A little (`dynamic-settings.md`).
- Whether Cedar judges requests one day, as it does configuration and commands (`Operation::"<agent>/<name>"`), overriding the floor both ways.
- Whether an operation can ever need an arbitrary request with a credential (the maintainer: open to it). None found.
- Slice C's lock and the configuration agent's `git` command: it needs `exec`, which the lock would otherwise refuse (`runtime-attestation.md`).

## Tests first, when it is built

- A property: no sequence of requests gives a callback's reply a value containing the secret, short of a server echoing it.
- Properties of `judge`: an `Arbitrary` location never gets a credential; a credential never goes to a host off its binding; an undeclared
  operation or an undeclared permission is denied, for every input.
- A credential sent only to the host it is bound to, including across a redirect and a registry's realm, against a real TLS server
  (`lib/src/egress.rs`'s test server).
- A callback that blocks stalls no other request; one past its budget is refused and reported.
- A refused credential becomes a held report, and a new version clears it, with no agent code involved.
- Declaring credentials gives the scaffold its section; a domain crate that depends on `reqwest` fails the metadata test, and so does a helper crate one leans on.
- Each request is logged with its verdict, with no path and no value.
- A stream's next change waits for the domain; one that cannot be read ends it, and a failure is its last message; dropping it ends it.
- Mutations: the handler attaching a credential for another host; `judge` allowing an arbitrary request a credential; a callback's result delivered with no
  message.
