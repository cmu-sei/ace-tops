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

Status, 2026-11-03: the design, from the maintainer, vetted. The framework is built, against a test protocol, with no agent on it and no real
protocol yet (`polar-agent-builder/src/protocol.rs`, "When, and in what order"). Framework code that lets us reason about
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

protocols.request(Projects { start_at }, myself, Message::Projects)?;   // the value comes back as a message
```

`Protocol` is the trait each handler implements, and it says only what differs: its request, how a credential attaches, and what a callback
reads. Everything else is written once: the operations, the judgment and its log, asking for the credential, egress, the budget, tracing,
and a refused credential becoming a held `Credentials` report (`polar-agent-builder/src/held.rs`), cleared by a new version.

### No way to the credential from domain code

A rule the developer has to remember is not the rule asked for. By possession, not by convention. Every route open today closes:

| Route today | Closed by |
|---|---|
| `CryptoClient::http_credential`, `git_credential` | removed from the trait |
| `CryptoMessage::HttpCredential`, `GitCredential`, reachable through `resources.crypto` and `CryptoHandle::as_actor_ref` | removed from the public message. The actor gives the builder a port for them when it is spawned, the handlers hold it, and nothing hands it on. A domain crate that spawns its own `CryptoActor` gets an empty registry |
| `CryptoClient::retrieve_secret`, which answers with plaintext, for the escrowed `<identity>/<name>` | refused for a name a registered credential uses. `LoadSecret` is internal and does not need the message. Nothing in domain code calls it today, outside the harness |
| its own HTTP client, or `git2` | a test over `cargo metadata`: a domain crate on the builder has none of `reqwest`, `git2`, `oci-client` or `kube`, beyond the types it reads. Otherwise an agent walks round the judgment as well as the credential |

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
| `Bound` | the domain, at run time, and the host must match the credential's signed binding | always | the git observer's repositories that name a credential; a registry with a credential |
| `Arbitrary` | the domain, at run time, with the permission declared on the operation | **never**: the declaration has no place to name one | OpenAPI following a document's URL; a public repository; a registry nothing is bound to |

- A path, a query and a page belong to the request; the host is what is judged. A location a response gives, such as GitLab's `Link` header, is
  judged like any other: another host is not the same request.
- A redirect is judged at each hop. A credentialed request is never followed to a host off its binding: it fails and is reported.
- The permission is declared on the operation when it is built, so the builder knows it and the catalog says it. Applying the catalog is the
  sign-off (`policy-enforcement.md`).

Proposed, to review: `Bound`. The **resolver** learns registries from the images it sees (`resolver/src/resolver.rs:78`), and the git observer's repositories
come from the controller naming their credential. The host is the domain's, but the host pattern a credential may go to is signed, so a match is a
location someone signed off and not an arbitrary request. No match is `NotBound`, nothing is sent, and the domain may make the `Arbitrary`
operation it declared, with no credential.

## The judgment

`judge(operation, location, binding, permission) -> Allow | Deny(why)`: pure, with no I/O, and a natural property test. Every request gets a line at
one place: the operation, the protocol, the host, whether a credential was attached (its name, never a value), and the verdict, with
`Arbitrary` marked. Hosts only: a path or a query can carry what should not be logged. Logged now, and reviewed eventually: the security dashboard
reads it when it exists (`remaining-work.md`, "A Polar security dashboard"). It is not a Cedar decision yet (Open).

## The protocols

| Protocol | Domain's users | Credential | Callback reads | Moves |
|---|---|---|---|---|
| HTTP | Jira, GitLab, OpenAPI | declared | a reply, whole and bounded | Jira now; GitLab and OpenAPI at step 7, when they reach the builder |
| OCI registry | resolver | declared; today a Docker config file | a manifest | now. A breaking change: it needs a migration note (`remaining-work.md`) |
| git | git observer | declared | the fetched `git2::Repository` | now |
| Kubernetes API | Kubernetes observer, attestation agent | the pod's service account token, which `kube` already picks up: the capability declares it, not `with_credential` | one change at a time | now |

- **OCI is HTTP with one more authentication scheme, not a handler of its own.** A registry's token exchange is the unusual scheme the decisions
  provide for, and it is needed: `oci-client` sends Basic credentials to whatever host the registry's `WWW-Authenticate` realm names (read in
  0.18.0's `client.rs`, the `get(realm)` with `apply_authentication`; not tried), so a binding cannot be enforced around it today. The handler does the
  exchange, judges the realm against the binding, and gives `oci-client` only the bearer token. So a binding for a registry names its auth host too.
- **Git keeps libgit2.** It does its own I/O and asks through a callback, `git/observe/src/lib.rs:722`; that callback moves into the handler. A test
  shows that the token is not left in the repository's config. The process-wide CA (`trust_ca_file`) is set once, by the handler.
- **Kubernetes needs a stream, so one request and many results is part of the framework now.** A watch never ends (`attestation/agent/src/watch.rs`).
  The callback is called per change and each value is a message. `kube`'s own watcher stays. The token's file stays readable in the pod, which
  no handler changes: Kubernetes is the trust base.
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
2. HTTP, against a real TLS server. Jira moves. On a cluster: nothing changes in what lands in the graph.
3. The registry scheme. The resolver moves, with its migration note.
4. git. The git observer moves.
5. Kubernetes and the stream. The Kubernetes observer and the attestation agent move.
6. The routes close (the table above), once nothing uses them. Docs and the diagram as built.

## Open

- What a callback's budget is, by protocol.
- Whether a Dynamic setting's reaction (`remaining-work.md`, "EVERY AGENT'S NON-SECRET SETTINGS DYNAMIC") shrinks when a URL or a host is
  the handler's to pick up.
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
- `with_credential` gives the scaffold its section; a domain crate that depends on `reqwest` fails the metadata test.
- Each request is logged with its verdict, with no path and no value.
- Mutations: the handler attaching a credential for another host; `judge` allowing an arbitrary request a credential; a callback's result delivered with no
  message.
