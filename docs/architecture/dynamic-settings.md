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

# Dynamic settings

Step 6 of the order of work (`remaining-work.md`, "EVERY AGENT'S NON-SECRET SETTINGS DYNAMIC"). The maintainer asked for one
reaction in the builder rather than Jira's by hand in every agent, and a shared test that fails a Dynamic setting nothing
reacts to. Designed and cleared 2026-11-04. **Built, and checked live on u7s the same day** ("Checked live", below).

## What holds it together

- Only a Dynamic variable can be changed by a signed update (`polar-env/src/config.rs:318`). Cedar is asked per variable,
  `Variable::"<agent>/<name>"`, with `c:update-configuration` as the fallback (`polar-agent-builder/src/signed.rs:460`).
- A domain supervisor is the **parent** of its infrastructure: `AgentBuilder::new(myself, ...)` in its `pre_start`. So the
  builder cannot stop an agent's work and start it again without losing the session, the health actor and the configuration
  itself. Restarting the work is the agent's to do, where it has to be done at all.

## The shape (the maintainer's, 2026-11-04)

**The actor that holds a value follows it.** It registers, the answer is the value in force, and each later value that
differs arrives as a message of its own, which it already knows what to do with: keep it for next use, replace a timer, or
restart a child. A supervisor follows only what it must restart a child for.

```rust
let batch = resources.configuration.follow(&PUBLISH_BATCH, &myself, Msg::BatchChanged).await?;
```

Built in `polar-agent-builder/src/configuration.rs`:

- **The callback only maps to a message.** What a new value means runs in the actor's own `handle`. The value is read and
  compared in a task of the follower's, not in the ConfigurationActor, so no closure of a domain's can slow it or panic it.
- **`follow` answers with the value in force.** The ConfigurationActor takes the registration in its turn, so no update falls
  between what the actor read and what it is sent. It also means a child started again later has the value signed since, not
  the one the render gave it, as long as it follows from `pre_start`.
- **Settings that mean something together register together.** `follow_group(names, read, actor, message)`: an update that
  changes several is one message holding one consistent value. An update that sets `JIRA_URL` to http and `JIRA_ANONYMOUS` to
  true must never be seen half done, with http and a credential. `read` is pure, and `names` says what it reads.
- **A value that does not read** gives `FollowError::Unreadable` at registration, and is followed all the same: the next value
  that reads arrives as a message. A later one that does not read is logged, and the last value stands.

**Declaring a variable Dynamic is the opt-in, and it means something follows it.**

- At run time, an update to a variable nothing follows still applies, and its outcome says so in `notes`: "nothing follows X
  now: what starts next reads it, at the latest at the agent's next restart". That is also the truth when the follower is down,
  or when none is running yet: a git worker started later reads the signed batch. A held supervisor
  counts as following everything while it runs, since any change asks the agent to try again.
- In tests, `ConfigurationHandle::dynamic_settings_problems(&[&SECTION])` is the shared check. Once an agent's actors have
  registered, it fails a Dynamic variable nothing follows, a variable whose follower's value does not depend on it, a Static
  variable someone follows, and a variable a test cannot change. It changes copies, so it applies nothing. The other value
  comes from the type (a number goes up by one, a flag flips, a list gains an entry) or from `.example("...")` on the
  declaration for text (`VarDesc::another_value`).

**What the shared check does not do.** Registrations exist only at run time, so it cannot live in `polar_agent_tests!`, and
nothing forces an agent to call it. Declaring them in a const would close that gap, and write each one down twice, which the
design principles rule out. The outcome's note is what catches a missed follower on a live cluster. It also stops at the
registration: an actor could take the message and ignore it, so each agent has a test of its own `handle`. And an agent's test
calls the same function its `pre_start` does (Jira's `follow_settings`), rather than starting the whole supervisor, whose
`pre_start` builds the infrastructure. **Marked for review:** the first design said the helper starts the real supervisor; the
builder has no rig an agent's crate can use for that, and the live check below is what covers `pre_start`.

**An update that would break working settings is refused.** `PolarAgent::SETTINGS_JUDGE` is an optional pure function for what
an agent's settings must satisfy as a whole, beyond what its sections check. The ConfigurationActor runs it on the settings in
force and on the candidate, and refuses only when the first works and the second does not (`breaks_what_works`): `Invalid`, with
the judge's reason, the values in force stay, and the version is not spent. While the settings do not work any update goes
through, or an agent held on them could not have its logging changed, nor be mended in two steps. Only jira-observer has one,
`prepare`, because `relations` already covers the checks between variables elsewhere. A section cannot do this job for it: a
section must accept the placeholder address, so the agent can stay up and say so. This replaces what jira-observer did before,
which was to stop its observers and hold `Configuration` on an update that could not work: a typo no longer stops a working agent.

Drawn as built: [`held_agent_and_dynamic_setting`](sequences/general/held_agent_and_dynamic_setting.mmd).

### Rejected: the builder restarts the work

The builder could own the work and restart all of it on a change, so that an agent could not forget. It needs every domain
supervisor turned inside out, with the infrastructure no longer its child, in every agent, and most values need no restart. It
belongs with the remaining-work item on the builder-owned shutdown handshake, if ever. `held::stay_up` stays as it is.

## Which variables

### Dynamic, as already declared

All following now. Logging, `RUST_LOG`, `POLAR_TRACE_FILTER` (the infrastructure supervisor). `JIRA_URL`, `JIRA_ANONYMOUS`,
`JIRA_DEPLOYMENT`, `QUERY_DATE` (one group, the observers' supervisor). `POLAR_GIT_CONTROLLER_REPUBLISH_SECS`,
`_PROPOSAL_TTL_SECS`, `_WARMUP_SECS` (one group, the controller's supervisor, where they had been read with `current()` at each
use with a fallback written out each time).

### Dynamic, new (built 2026-11-04)

Each follows in the actor that holds it, which also means each is read through `follow` at its start.

| Variable | Agent | Who follows it, and what a new value does |
|---|---|---|
| `POLAR_GIT_PUBLISH_BATCH` | git-repo-observer | each worker; its next batch is that size. The first design restarted the workers; with the actor following it they need no restart |
| `POLAR_STATE_GRAPH_TIMEOUT_SECS` | soft-state observer | the supervisor; the next read goes by it |
| `POLAR_HEALTH_ASK_INTERVAL_SECS`, `POLAR_HEALTH_ANSWER_TIMEOUT_SECS` | soft-state processor | the supervisor, as one group: the check that the wait stays below the interval holds only together. A new interval replaces the timer; a round in flight closes by the wait it began with |
| `POLAR_STATE_REPLY_TIMEOUT_SECS`, `_ATTEMPTS`, `_UNAVAILABLE_RETRY_SECS`, `_UNAVAILABLE_LIMIT_SECS` | every agent that reads state, the builder's own | the state actor, as one group; the next question goes by them, and one already waiting keeps what it started with |

### Constants that became variables (cleared and built 2026-11-04)

The list above is short. Most of what an operator would want to tune was not a variable. Their defaults are what the constants were.

| Variable | Default | Agent | Who follows it, and what a new value does |
|---|---|---|---|
| `JIRA_POLL_SECS` | 1800, at least 60 | jira-observer | the supervisor, in the group with the other settings; the observers start again with it |
| `JIRA_PAGE_SIZE` | 50, from 1 to 1000 | jira-observer | the same |
| `POLAR_SCHEDULER_DEPLOYMENT_COPY_SECS` | 10, a 0 taken as 1 | scheduler observer | the copy actor, which replaces its timer. Only while the copy runs: nothing follows it after the handoff, and an update says so |
| `POLAR_SCHEDULER_DEPLOYMENT_RECORD_SECS` | 30, a 0 taken as 1 | scheduler observer | the record actor, which replaces its timer |
| `POLAR_KUBE_WATCH_LOST_SECS` | 5, at least 1 | kube-observer | the watcher, once it has started (at the first registration); the next ended watch goes by it, and one already waiting keeps what it was told |
| `POLAR_KUBE_WATCH_REFUSED_SECS` | 300, at least 1 | kube-observer | the same |

Left as constants: the git controller's admission limits (`MAX_ENTRIES` and the like, bounds on what proposers can do), the
drain windows (the shutdown budget is computed from them), and `DRIFT_GRACE_SECS` (a detection window, for slice C to settle).

### Static, by the maintainer's scope of 2026-11-02

Paths, sockets and bind addresses. `BROKER_ADDR`, `CASSINI_SERVER_NAME`, `POLAR_SCHEDULER_REMOTE_URL`. `CERT_ISSUER_ISSUERS`,
`CERT_ISSUER_INTERNAL_CALLERS`, `POLAR_GIT_SERVER_ADMINS`, `CREDENTIALS_AGENT_BOOTSTRAP_IDENTITY`. Egress (jira.md, the cluster's
setting).

### Static, read from the same rules (cleared 2026-11-04)

| Variable | Why |
|---|---|
| `OCI_INSECURE_REGISTRIES` | allows plain http to a host: a trust setting |
| `CERT_ISSUER_*_LIFETIME_SECS`, `_IDENTITY_LIFETIME_OVERRIDES`, `_MAX_TOKEN_LIFETIME_SECS` | whoever may change them can lengthen every certificate's life, which is the bound the rest of the design leans on |
| `CERT_ISSUER_BOOTSTRAP`, `_CA_PROVISIONING`, `_SERVER_IDENTITY` | trust |
| `CREDENTIALS_AGENT_KUBERNETES_ISSUERS`, `_INTROSPECTION_ENDPOINT`, `_INTROSPECTION_CLIENT_ID`, `CREDENTIALS_AGENT_AUTHORITY_MODEL` | trust |
| `POLAR_GIT_SERVER_REPOS` | its access rules |
| `POLAR_AUTHORITY_PUBLISHER`, `POLAR_CAPABILITIES`, `POLAR_SERVED_WORKLOADS` | trust, or facts the render signs off |
| `POLAR_ATTESTATION_NAMESPACES` | the render grants a Role per namespace (`capabilities.nuon:182`), so a new one would have no access |
| `POLAR_SCHEDULER_DEPLOYMENT_*_URL` | channel |
| `POLAR_SCHEDULER_SYNC_INTERVAL` | channel, for a remote that is not Polar's git server: 0 means it never pulls again, so the correction never arrives |
| `GRAPH_DB`, `GRAPH_USER`, `GRAPH_ENDPOINT` | channel, beside a secret |
| The health section | `configuration.md` keeps the safety invariants Static; the threshold must match polar-init's (`1a9485d3`), and the tick must match the probe's staleness |
| The broker's `CASSINI_DECISION_CACHE_SECS`, `_STALL_SECS`, `_MEMORY_BUDGET_BYTES`, `_BUDGET_*` | **It has no way to hear an update.** The subscription exists only for a Cassini client (`infrastructure.rs:514`), and the broker is not one. It is its own change |

So these agents end with logging as their only Dynamic setting, because they have no other setting of this kind:
kube-consumer, the Jira, git and scheduler processors, the credentials pair, cert-issuer, polar-git-server, the attestation
agent and the resolver. The maintainer's test, that an agent whose non-secret settings are Static is not properly migrated,
then rests on the table above.

## What this leaves true

- **The rendered value runs first after every restart.** Agents read at start, and the replay comes after registration, so
  an agent runs on the render's value until the signed one arrives, and then reacts if the value differs. It is seconds, it is
  true of Jira as it always was, and it is a reason a trust setting cannot be Dynamic: this window would hold the old value.
- **A signed document removed from the repository stays in force until the agent restarts.** As before.
- **A running agent's overrides add up, and a restart has only the file.** Updates apply on top of each other, but
  `permanent/<agent>/configuration.dhall` holds one document, the latest, and that is all the replay can bring. So a document that
  names only what it changes loses, at the next restart, what the one before it set. And a refused version replaces the good file
  just the same: seen live, version 1 set `JIRA_POLL_SECS`, a refused version 2 replaced the file, and the restart came back on the
  rendered 1800. **Until this is settled, name everything you mean to keep in each document, and sign a corrected one over a refused
  one.** `polar-sign template --settings` gives a whole file; `polar-sign configuration --set` does not. Not changed here.
- **Every new Dynamic variable widens what `c:update-configuration` can do**, for a signer with no Cedar rule saying otherwise.
- **While a held agent's work runs, its held supervisor still counts as following everything**, so the note does not appear for
  a variable the work forgets. Jira, the one user, follows all of its own.

## The protocol handlers' open question

`protocol-handlers.md` asks whether a reaction shrinks when a URL is the handler's to pick up. A little: `Location::Configured`
reads the host in force at each request, so the judgment already follows. The domain still builds its URLs, and Jira still
restarts its observers. Nothing here depends on it.

## Seen on the way

`CASSINI_QUEUE_PATH` is declared, but read from the process's environment rather than the snapshot (`cassini/client/src/lib.rs:128`),
so a value given in the `POLAR_CONFIG` document is missed. Not part of this.

## Checked live

On u7s, 2026-11-05 UTC, with every image rebuilt from `304879d6` and the real path: `polar-sign`, a push to `polar-schedules`, the
scheduler, the agent's verifier. The outcomes were read from the graph (`:ConfigurationOutcome`).

- **Restart:** `JIRA_POLL_SECS=120` on jira-observer. The observers started again in the same second as the push, and pulled at
  00:24:19 and 00:26:21. `POLAR_STATE_ATTEMPTS` in the same document: one `applied` outcome naming both, with no note.
- **Timer:** `POLAR_HEALTH_ASK_INTERVAL_SECS=20` with `RUST_LOG` on soft-state-processor: the log filter changed at once, and the
  rounds went at :33, :53, :13.
- **Refused:** `JIRA_URL` at the placeholder, by the judge, and `JIRA_PAGE_SIZE=0`, by the section: `invalid`, each with its reason,
  no restart of the observers, and the corrected version took the same number.
- **The note:** `POLAR_SCHEDULER_DEPLOYMENT_COPY_SECS` after the handoff said nothing follows it, and `_RECORD_SECS` in the same
  document had no note. `POLAR_GIT_PUBLISH_BATCH` with no repository configured said so too; with one worker running (a public
  repository, read with no credential), it did not.
- **Replay:** jira-observer's pod deleted. It came up on the rendered 1800, the document was applied in the same millisecond, and
  it was on 120 about 1.4 s later, having started a pull on each.
- **Held:** `JIRA_URL` set to the placeholder in its ConfigMap, by hand, and the pod deleted. It held `Configuration`, and the replayed
  version 3, which left the problem in place, applied with no note and kept the hold. Version 4 with the real address: "a signed
  update mended what held it", the hold released, the observers at 120. Version 5 with the placeholder: refused, and they ran on.

**Registered, and the effect not seen:** `POLAR_GIT_PUBLISH_BATCH`, `POLAR_STATE_GRAPH_TIMEOUT_SECS`, the four `POLAR_STATE_*`,
`POLAR_KUBE_WATCH_*`, `POLAR_GIT_CONTROLLER_REPUBLISH_SECS` and `_RECORD_SECS`: each outcome had no note, which says an actor follows
it, and the tests say what the actor does with it. `JIRA_PAGE_SIZE` above its default and `POLAR_SCHEDULER_DEPLOYMENT_COPY_SECS` with
the copy running were not tried. All removed afterwards: the documents deleted, the agents restarted, the ConfigMap put back.

## The order

1. **The builder and its first users. Built 2026-11-04.** `follow`, `follow_group`, the outcome's note, `SETTINGS_JUDGE`,
   the shared check. Jira and the git controller moved onto them, and the infrastructure supervisor's logging. Jira's
   stop-and-hold went, and so did its filter of what changed (`touches_the_observers`), which held a branch that could never
   fire (egress is Static).
2. **The new variables and the constants above. Built 2026-11-04**, each with a test of its `handle` and the shared check.
3. **Live on u7s. Done 2026-11-05** (above).

No migration is needed: a variable going from Static to Dynamic changes nothing for a deployment that does not sign an update.
