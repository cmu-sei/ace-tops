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
- **A signed document replaces the one before it** ("Asking an agent what is in force", below). A running agent and one that has
  restarted and heard only the latest document now agree. What this does not settle: **a refused version still replaces the good file
  in the repository**, so the next restart comes back on the rendered values until a corrected version is signed. The answer shows it,
  since the version in force stays below the file's. Stopping it needs a check before signing or before the merge, which is its own change.
- **A variable-by-variable Cedar rule now reaches further.** A document is judged for every variable it names and every override it would
  take away, and the file is replayed whole at a restart. So one signer has to be permitted everything in the file: a signer kept to one
  variable cannot sign while another's override is held. No seeded policy does this.
- **Every new Dynamic variable widens what `c:update-configuration` can do**, for a signer with no Cedar rule saying otherwise.
- **While a held agent's work runs, its held supervisor still counts as following everything**, so the note does not appear for
  a variable the work forgets. Jira, the one user, follows all of its own.

## Asking an agent what is in force

Asked for by the maintainer, 2026-11-04, on hearing that overrides add up in a running agent and a restart has only the latest
file: ask a running agent for its running configuration, and from the answer generate a document that someone can edit, and that says
where they are now. Cleared the same day. Drawn as built: [`running_configuration`](sequences/general/running_configuration.mmd).

```
just port-forwards-up broker                                  # once, from your own machine
polar-running-config jira-observer --user alice               # the answer, as JSON
polar-running-config jira-observer --user alice --template > file     # a file to edit and sign
polar-sign sign file --user alice --push
```

**An applied document replaces every override before it.** `Config::replace_overrides`, from `ConfigurationState::apply`: what a
document does not name goes back to the rendered value, now as it would at a restart. Commenting a line out of the file therefore means
what it looks like. A refused document changes nothing. `apply_overrides` stays for the shared check, which changes copies one variable
at a time. An empty `settings` is still refused by `polar-sign`, as more likely a mistake; to return everything to the render, name one
setting with an empty value.

**Leaving a variable out is a change to it, so it needs the same permission** (`Opened::request_replacing`). Otherwise a signer Cedar
keeps off a variable could still take away its value by not naming it.

**The file holds what a signed document set as live lines, and the rest commented out with their value and source**
(`polar_sign::template::running_settings_template`). Signing it unchanged keeps what is running, which a test holds across the
agent's answer, the template and a fresh `Config`. If every value were live, signing would turn each rendered value into an override,
and a later change to the catalog would silently not reach the agent. The version is one above the last applied. A secret or withheld
value is never a live line. An override the scaffold does not offer is refused rather than lost, since signing would take it away.

**The answer** (`polar_scheduler_common::running::RunningConfiguration`, built in `polar-agent-builder/src/running.rs`): every declared
variable, Static ones included, with its value, source and whether it is Dynamic; the last version applied; each runtime section's
version, never its body; since 2026-11-06 each section's document id and body digest, and the agent's build, for `polar-sign check --ask`
(a breaking change of the wire: the tool reads agents of its own build). A declared secret's value does not leave the agent, nor does any value that repeats one. Other values go as
they are, Jira's address for one, so the answer goes back to whoever may ask and not to the graph.

**A question is a signed document, under its own signing domain** (`Domain::RUNNING_CONFIGURATION_QUESTION`). The broker stamps an
identity and nothing more, so the agent alone cannot learn what the asker's certificate carries. Signing gives it the certificate
and proof of the key, by the path every other signed document takes, and a signature made for this can do nothing else, in either
direction. The signer must be who the broker says sent it. A window of at most five minutes (`MAX_QUESTION_VALIDITY_SECS`) bounds a
replay, which would only make the agent answer again.

**Who may ask: the groups `config-readers` and `config-writers` (the maintainer, 2026-11-05).** The first policy permits `config-readers`
the two topics and `read-configuration`, and `config-writers` `update-configuration`; the first groups document puts `config-writers` in
`config-readers` and the first administrator in `config-writers`. Anyone else is added by a later groups version, by username, signed by a
holder of `c:update-groups`. A reader need hold no capability, and is refused if they sign an update. Under that, the decision stays as it
was: Cedar first, `Action::"read-configuration"` on `Agent::"<agent>"`; where it is silent, the certificate's `c:update-configuration`, and
a `forbid` can keep someone off one agent. **Marked for review:** the policy gives a person the topics through the group alone, so a holder
of `c:update-configuration` who is in no group can still sign updates but is refused at the broker when they ask. A workload needs no group
for the topics, which its catalog entry can declare.

**One topic for all questions, one for all answers** (`QUESTIONS_TOPIC`, `ANSWERS_TOPIC`, implied by the `agent` rule), rather than one per
agent as health has. A person's certificate names no topics, so a Cedar rule is what lets one use the broker at all, and a rule names a
topic exactly: a topic per agent would need a rule per agent. `infra/seeds/signed/policy.cedar` holds the two rules, for
`Group::"config-readers"`. Every agent hears every question and reads no further than whom it is for. Everyone who may ask
hears every answer, and the tool takes only its own: its id, that agent, and stamped with that workload.

**A refused question gets no answer**, as with health, and a warning in the agent's log naming the asker. The tool's wait ends and it says
where to look. A refusal at the broker is said at once.

**Asking is a library, and `polar-running-config` a thin tool over it (the maintainer, 2026-11-05).** The first build joined two tools with a
nushell script, so the whole flow existed only as a script, which an agent or a dashboard cannot call. `polar_running_config` now has three layers:
`question` makes the signed question; `Asking` says what to do on each thing the broker says, for a caller with a Cassini client of its own;
`ask` connects, asks and waits, and says why with `AskError`. The tool writes the file itself with `polar_sign::template`, and
`polar-sign template --settings --running <file>` stays for an answer saved earlier. Since 2026-11-06 the tool is a binary of the `polar-sign`
package, and `polar_running_config` a library only, so that `polar-sign check --ask` asks the running agents with the same code (the maintainer's
choice; `http-observers.md`, "Evidence"): `polar-sign` now links a Cassini client. The person's certificate and key are read by
`polar_signing::identity`, which both use.

**The broker is 8080 in the cluster, mTLS and not HTTP, and 18081 on your own machine** (`just port-forwards-up broker`, since keycloak
owns local 8080). The tool looks there by default, as `polar-sign` looks for the observer's forward; `--broker` and `POLAR_BROKER_ADDR` say
otherwise, and `--server-name` and `POLAR_BROKER_NAME` for a cluster on another domain. A wrong name says only that no answer came, as does a
missing forward.

**What a later service needs that the library does not give it yet.** Signing takes the key as PEM text (`polar_sign::Identity`), so a key
held by the CryptoActor would need a signer of another shape. `polar_sign::push` runs the `git` command, which an agent's image may not have.
`Scaffold::load` reads a person's folder, so a service needs its own source of scaffolds. Depending on `polar_sign` brings its blocking HTTP
client. None is built for now: the command-line tools come first, and what they do informs the application (`remaining-work.md`).

**What this does not cover.** The broker is not a Cassini client, so it cannot be asked, the same gap as its not hearing updates. An agent
must be up and connected. A Dynamic secret, which no real agent has, could not be kept by a file (`polar-sign` refuses to set one), and
the file says signing takes it away.

**The group `health-readers` grants nothing yet.** The maintainer asked for it beside the other two, and the first administrator is seeded
into it, but a person has no way to ask for health: each agent's question topic is its own (`agent.<name>.health`), and Cedar names a topic
exactly, so it is the one rule per agent the configuration question avoided by sharing a topic. Giving it effect needs that shape settled first.

**For an existing deployment (recorded for the customer's migration, `remaining-work.md`).** Asking needs the rules: the seed is only
ever the first policy, so sign the next version with them, and a first groups version naming who may read and write. Anyone signing documents that name only what they change, relying on a running
agent keeping the rest, now loses the rest at once, where before it was at the next restart.

**Checked live on u7s, 2026-11-05 UTC**, with every image rebuilt from `a246975d` and the real path: `polar-running-config` over the port-forward,
`polar-sign`, a push to `polar-schedules`, the scheduler, the agent's verifier.

- **Before the rules:** on the policy of the first bring-up, asking was refused at the broker at once, and the tool said which rules were missing.
- **Signing them:** policy version 2, the seed's text. The first try after the push was refused while it travelled; the next was answered.
- **The flow, on jira-observer:** nothing signed, so the file had no live lines and said version 1. Two lines edited (`JIRA_POLL_SECS=120`,
  `JIRA_PAGE_SIZE=75`) and signed: asked again, both `override`, version 1. Written again and signed unchanged: the same two, version 2. Pod
  deleted: on the same two after the replay. One line taken out: `JIRA_PAGE_SIZE` back on 50, `default`, at once, the other kept.
- **Refused:** `JIRA_PAGE_SIZE=0` as version 4. The answer stayed on version 3 with the values in force, and the next file offered version 4 again.
  Pod deleted with that file in place: back on the rendered 1800, version 0. That is the gap above, and the answer shows it plainly.
- **Who may ask:** a certificate without `c:update-configuration` (`bootstrap-admin`) was refused at the broker. A policy with
  `forbid` on `read-configuration` for `Agent::"jira-observer"`: no answer, a warning in its log naming the asker and the reason, and
  kube-observer still answered.
- **Every agent:** all 17 running builder agents answered, cert-issuer among them. Every `GRAPH_PASSWORD` and the introspection client
  secret came back withheld, and no withheld setting carried a value. `cassini` did not, as expected, nor the two harness workloads, which do not run on this target.

**Not seen:** the refusal when the stamp and the signer differ, a replay, a revoked certificate, and a value that repeats a secret, which only the
tests cover. All removed afterwards: the document deleted and Jira restarted.

**Checked live on u7s again, 2026-11-05 UTC, for the groups and the tool in Rust**, with the agents' images unchanged (the change is the tool and the
seed) and the tool built from the tree, in debug, not from a shipped image. The bodies came from `seed.nu`'s own functions and were signed as the seed step signs them;
`up.nu`'s seed step itself was not run, and neither was a fresh bring-up.

- **No forward:** no answer in the wait, and the tool said how to start it. **With it,** on the older policy: `djshepard` answered and `bootstrap-admin` was refused at
  the broker.
- **The seed's text:** policy version 5 and groups version 1 applied. `djshepard` answered through the group, the capability rules being gone.
- **A person with no config capability** (`cfgcheck`, provisioned for this, certificate since revoked, key deleted): in no group, refused at the broker; in `config-readers`,
  answered, and an update they signed refused by the agent, `does not hold c:update-configuration`; in `config-writers`, the same update applied, and still answered, through the nesting.
- **The whole flow:** `--template` offered version 2 with that value live; one more line edited and signed; both `override`. `just running-config` printed the answer. `polar-sign template --running` read a saved one.
- **The credentials agent's refusals on the way:** a groups document naming an account ID, or a name with no account, is refused, `would apply to no one`. So a group's members are named by username.

Removed afterwards: the document deleted and Jira restarted, back on 1800 and 50. In force now: policy version 5 and groups version 4, the seed's text for `djshepard`.

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
