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

# Protocol handlers: agents' I/O in infrastructure

Status, 2026-11-02: the shape, decided with the maintainer. Nothing here is built. An agent's domain code stops holding the
secrets it uses: a generalized handler for each protocol does the I/O in the builder's infrastructure, attaches the
credential itself, and calls back into the domain's code without showing it the credential.

## Why

A token reaches domain code today. `jira/observe/src/lib.rs:354-369` asks `CryptoClient::http_credential` for it and calls
`req.bearer_auth(token)`; the token is also read there to warn when it looks base64-encoded. The GitLab and OpenAPI observers use
`reqwest` each on their own. So every agent that speaks a protocol solves the same problems itself: attaching the credential,
the egress proxy and CA, retries, rate limits, tracing without the secret, what a 401 or a 404 means for its health, and picking
up a new token. Mechanisms accumulating around one need is the shape being wrong (`AGENTS.md`).

Where it came from: a side conversation of 2026-10-14 about a friend's design, a sidecar that injects secrets into a workload's
plaintext requests. The appeal is that the workload never holds the secret. The objection is that something rewrites a request
behind the code's back, so the code does not say what really happens, and a Kubernetes proxy is not how Polar works.

## What it does for the code (the maintainer, 2026-11-02)

"I can test and validate so much of the code that makes up an agent this way, and writing domain logic reduces to writing domain
logic." This is as much the reason for the design as the secret is.

- *The I/O is tested once.* Retries, redirects, the egress proxy, rate limits, a refused credential and a dropped connection are the
  handler's, tested against real servers in one place, and every agent inherits them. Today each agent carries its own version and
  its own tests of it.
- *Domain logic becomes a function.* A callback takes what the handler gives it and returns a value, so it can be tested with no server,
  no actor system and no certificates, and it is a natural place for property tests: any response, any page, and the rule holds.
- *What is left to test per agent is small:* its callbacks, and one run through the handler showing that they are wired up.
- *A new agent is mostly its domain.* What the builder does for health, Cassini and shutdown it now does for the agent's I/O too, and
  `polar_agent_tests!` can grow to check what an agent declares it uses.

## Decisions (the maintainer, 2026-11-02)

- **Generalized I/O handlers, one for each protocol Polar speaks,** in the builder's infrastructure, working on behalf of the
  domain actor that needed something. Not a Kubernetes sidecar and not a proxy.
- **The user of a secret registers a callback,** called from within the handler's working context.
- **A callback never sees the secret; the handler attaches it.** The callback gets an authenticated session, or the response.
  An unusual authentication scheme, such as a signed request, is added to the handler rather than worked around in an agent.

## The shape

It is the pattern Polar already has. Domain actors send messages to the Cassini client, and the infrastructure supervisor owns
the connection, its certificates and its reconnects. The open item for the builder to own the graph controller
(`remaining-work.md`) is the same move. HTTP and git are what is left.

| Protocol | Today | With a handler |
|---|---|---|
| Cassini | infrastructure's | no change |
| Bolt | the builder starts and stops the controller (`polar-agent-builder/src/graph.rs`); the agent wires it up | that open item |
| HTTP | each agent's `reqwest` client (Jira, GitLab, OpenAPI) | the first new handler |
| git | the git observer's libgit2 calls; its credential callback, `git/observe/src/lib.rs:722`, is already a registered callback | libgit2's credential callback moves into the handler; the domain's callback gets the fetched repository |

A request stays explicit, which is what the sidecar gives up: the domain names the operation and the credential, and nothing is
changed behind its back. The credential's host binding is checked as it is today (`polar-crypto/src/registry.rs`).

*Enforced by the types.* The callback's session has no way to read the credential. `CryptoClient::http_credential` and
`git_credential` stop being callable from domain code, so an agent cannot go round the handler. What domain code wants to know about a
credential is a fact the handler reports (Jira's "this token looks base64-encoded"), not the credential.

*What moves to one place:* the host binding, the egress proxy and CA (`lib/src/egress.rs`), retries, rate limits, tracing and
redaction, a refused credential becoming a held `Credentials` report (`polar-agent-builder/src/held.rs`), and a new version of a
credentials section taking effect.

### Callbacks and the actor rule (proposed by the agent that wrote this, for review)

A callback is needed because some work must happen in the handler's context: walking a fetched `git2::Repository`, or reading a
streamed response. But it runs domain code inside an infrastructure actor, and actors exchange messages and never touch each
other's state (`AGENTS.md`). So:
- a callback captures no actor state: it works on what the handler gives it and returns a value, and that value reaches the domain
  actor as an ordinary message;
- each call runs in its own task with its own budget, so that a slow callback stalls neither the handler nor anyone else's request.

## What it closes and what it does not

| A secret leaking through | With handlers |
|---|---|
| a log line, an error message or a trace in domain code | closed: domain code does not have it |
| a redirect or a wrong host, by a mistake in the agent | closed in one place: the handler decides what is sent where |
| a logic bug in code parsing what a server sent | closed: that code runs with no access to the secret |
| code injected into the process, reading its memory | **not closed** |

It is one address space, so it does not change what remains in `runtime-attestation.md`, "Runtime attestation of the process".
The interface is the seam if a handler ever has to move out of the process: the request is already a plain, explicit message.
Private keys are already out of the process, in the custody daemon (`key-custody.md`); tokens are not.

## Open

- Where this falls in the order of work (`remaining-work.md`). The GitLab and OpenAPI agents' migration either starts on handlers or
  moves onto them later.
- The handler's interface for paged and streamed responses, and what a callback's budget is.
- Whether the Kubernetes API (`Capability::KubeApiRead`, the workload's own service account token) and the OCI resolver's registries
  are handlers too.
- Whether a Dynamic setting's reaction (`remaining-work.md`, "EVERY AGENT'S NON-SECRET SETTINGS DYNAMIC") shrinks when a URL or a host is
  the handler's to pick up.
- Whether a handler holds a token between requests or asks for it each time, as Jira does today, to shorten how long it is in memory.

## Tests first, when it is built

- A property: no sequence of requests gives a callback's session a value containing the secret.
- A credential sent only to the host it is bound to, including across a redirect, against a real TLS server (`lib/src/egress.rs`'s
  test server).
- A callback that blocks stalls no other request; one past its budget is refused and reported.
- A refused credential becomes a held report, and a new version clears it, with no agent code involved.
- Mutations: the handler attaching a credential for another host; a callback's result delivered with no message.
