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

# Polar git server

Status, 2026-11-04: built, and running on clusters. Built: transport and identity, the read and write paths, push
authorization, the `RepoChanged` topic, seeding, runtime repository creation, the push log, and every commit of a
repository that names a signer verified on push (`server/src/signed.rs`, the deployment repository). `polar-sign` signs
the documents; `polar-schedules` has no signer of its own. `polar-evidence` holds evidence records, each signed by the
collector that made it (`polar-sign projection test` first; `http-observers.md`, "Evidence"), and has no signer of its own
either, since its records have many. Not built: the Cedar authorizer, and a rule refusing a commit that removes or changes
an evidence record.
Crates: `src/agents/polar-git-server/{common,server}`. Drawn as built: [`git_server_push`](sequences/general/git_server_push.mmd).

## Purpose

`polar-git-server` hosts the git repositories that carry Polar's configuration: the schedules
repo, the per-agent configuration repos, and whatever else the deployment declares. It replaces
the development-only nginx + fcgiwrap container in `src/agents/git-server`.

It is a `PolarAgent` on the builder (ractor actors under the InfrastructureSupervisor) and a
catalog workload. It is core infrastructure, deployed by the `infra/` stack. It is optional: a
deployment may point the scheduler at any other git remote, at the cost of the managed features
listed under "Degraded mode".

## Transport and identity

- Git smart HTTP over mTLS. The user's `git` CLI is configured with `http.sslCert`,
  `http.sslKey` and `http.sslCAInfo` (their Polar user certificate and the Polar CA). No
  credential helper, no passwords, no tokens.
- The server never terminates TLS on behalf of something else. Client certificates are required on
  every connection (no `allow_unauthenticated`). Peer identity is taken from the verified
  handshake, never from a header. The pattern is Cassini's `listener.rs`
  (`extract_peer_identity`, `WebPkiClientVerifier`), which cert-issuer's `tls.rs` mirrors.
- Workload certificates (the scheduler observer, later the git agent) authenticate the same way,
  so reading the schedules repo needs no stored credential.
- Development: `kubectl port-forward` to the service, plus the matching `git config` lines.

## Git execution

Rust has no server-side `receive-pack` (gitoxide is client-side), so each request spawns
`git upload-pack --stateless-rpc` or `git receive-pack --stateless-rpc` against a bare repository,
under a supervised request actor with a timeout and a body size limit.

Push authorization happens before git runs. A push body begins with pkt-line ref-update commands,
ahead of the pack. The server parses those, authorizes each ref update for the peer identity, and
only then spawns `receive-pack`. No hook scripts, so nothing in git has to call back into actors.

## Authorization

- Default policy is static and lives in the server's configuration: per repo, the identities allowed to read
  and to write. *As built (2026-10-21): an identity is the certificate's first DNS SAN, matched exactly against
  `readers`, `writers` and `admins` (`server/src/access.rs:43-90`, `StaticAcl`/`RuntimeAcl`); `p:` and `c:` SANs are not
  read, and the Cedar authorizer below is not wired (`access.rs:24` mentions it only in a comment).* By default the scheduler observer is the
  only agent that may read, and admins write. Who the admins are is a fact about the deployment, so `POLAR_GIT_SERVER_ADMINS` names them apart from the repository declaration (and in addition to the `admins` in it); in development `up.nu` records the first admin's identity (the DNS name in the certificate `just admin-claim` made, their ledger identity, which changes when the cluster is reset) as a gitignored cluster input (`infra/targets/<target>/cluster-inputs.nuon`), renders it into this setting, and publishes it in the signed record (`docs/architecture/cluster-bootstrap.md`).
- The decision goes through one function behind a trait, so a Cedar evaluator (`polar-policy`)
  can replace or override it. Cedar-defined groups (for example "config policy authors") then
  extend who may push, with no change to the server.
- The policy repo is not hosted on the server it governs (bootstrap circle). Static first.
- Granularity is the repository. Things that need different authors are different repositories.
  Path-level rules would require quarantining a push and diffing trees; deferred, not designed.
  Branch rules are not used; each repo has `main`.

## Repositories

Two sources, one store.

1. **Declared at deploy time.** The git server's catalog entry lists bootstrap repositories
   (name, access list, optional seed tree taken from `infra/`). Render also derives a
   configuration repository for any agent entry that takes `config: "document"` once that
   convention is decided. Why the catalog: it is the one thing the check/render/apply pipeline
   reads, so a repository declared there is provisioned by the same apply that deploys the agent.
2. **Created at runtime.** `PUT /admin/repos/<name>` with an optional JSON body
   `{"readers": [..], "writers": [..]}`, allowed only to an administrator (identified by its client
   certificate like every caller). Idempotent: 201 when created, 200 when it already existed, and
   the access list is set to the body's either way. The deployment's declaration always wins: a
   repository the catalog declares answers 409 and keeps its list. The access lists of runtime
   repositories are kept in `runtime-acl.json` beside the repositories. The server's list of repos
   is its own state (a PVC of bare repositories); the catalog is the desired subset, not the whole
   list.

Seeding happens once, only when the repository is empty, so redeploying never overwrites later
edits. A declared repository's `seed` names a directory under the seed root; the trees are in
`infra/seeds/<repo>` and the Nix build puts them in the image (the server binary carries their
store path as its default seed root, which is also what makes the image include them).

## Notifications

After a push is accepted, the server publishes a `RepoChanged { repo, ref, old, new, pusher }`
message on a Cassini topic. Topics are not declared in the catalog; each agent keeps its topic
names as constants in its common crate (as credentials-agent-common does), and so will this one
(`polar-git-server-common`). The scheduler observer subscribes, so with the managed server it
need not poll; against another remote it keeps polling.

## Running on its own

The same binary runs inside a Polar cluster and on its own. Cassini is an optional capability of
the server (`OPTIONAL = [Cassini]` in its `PolarAgent` declaration, `CASSINI_CLIENT = false`): it is
a Cassini client exactly when the deployment lists `cassini` in `POLAR_CAPABILITIES`. The catalog's
`agent` kind provides it, so in a cluster nothing changes. A deployment that says nothing (the
variable unset) provides nothing optional, so a server started by hand, in a container or under
systemd, with only its five `POLAR_GIT_SERVER_*` settings, has no broker connection, no router
and no Cassini variables to set. It then keeps the health check and the shutdown handshake of
`ServiceBuilder`, serves, authenticates by certificate against whatever CA it is given, and logs each accepted push to `push-log.jsonl`;
it publishes no `RepoChanged`. When `cassini` is provided, the client's settings become required
as for any agent, and a half-configured server refuses to start. How to run it: the crate's `README.md`.

## Inside the boundary (the maintainer, 2026-11-09)

**Decided:** where an agent and a service Polar built are both inside Polar's boundary, the agent reaches the service
through Cassini, never by a direct connection; and the degraded paths (another git remote, a key file to reach the
service) are not valid for Polar's own use. A deployment has a Polar git server. Why: what traverses Cassini is
observable, judged by the broker-stamped identity, and needs no key outside the custody daemon; a direct connection is
none of these, and the server announces only the pushes it accepts, not what it serves.

*Its scope, as read by the agent that recorded it, for review:* it governs Polar's services inside the boundary, which
today means this server. It does not govern Polar's edges, which are what direct connections are for: Neo4j, the
Kubernetes API, and an observer's outside sources; nor bootstrap, where `polar-init` has no certificate to join Cassini
with yet. Running the server on its own ("Running on its own", above) is unchanged: that is the server outside a
cluster, not an agent inside one.

*What it changes, tracked:*
- **The scheduler observer's reads** of `polar-schedules` and the deployment repository, until then `git` over mTLS on a
  key file (`key-custody.md`: the one pod on key files), come through Cassini from this server ("Reads over Cassini",
  below). Its polling of another remote goes with it. *Built 2026-11-10 (O2):* it names the repositories
  (`POLAR_SCHEDULER_SCHEDULES_REPO`, `POLAR_SCHEDULER_DEPLOYMENT_REPO`) where it named URLs, and runs `git` only for the
  deployment copy's push until `up.nu` makes the copy (O3). *Built (O3):* `up.nu` copies the deployment as an
  administrator, and the observer runs no git.
- **Evidence records** reach `polar-evidence` over Cassini: a collector that is a workload (the attestation agent first)
  sends its signed records, and this server verifies each in the evidence domain, takes them only from identities
  allowed to add evidence, commits them to its own repository under the add-only rule, and announces the commit as it
  does every push (`record-store.md`, "Attestation verdicts as records").
- People still push with `git` and their own certificates, as `polar-sign` does: they are outside the boundary, and each
  push is announced.

### Evidence records over Cassini, built (2026-11-09, bite A)

- **The topics** (`polar-git-server-common`): a collector publishes `Envelope<AddRecord>`, the signed record as its
  signer wrote it, on `polar-git-evidence-requests`; the answer goes to the sender's own topic,
  `polar-git-evidence-replies.<workload>`, named per sender as the attestation agent's askers are, so the server's
  certificate carries no family (the attestation agent's). The answer is `Committed { path, commit }`,
  `AlreadyThere { path }`, `Refused { why }` (never as it is: the sender may not add evidence, or it is no verifying
  record) or `NotNow { why }` (the repository could not be written: the sender keeps it and sends it again).
- **Who may add** is who may write `polar-evidence`, by the server's own access list, judged on the identity the broker
  stamped; a reader is refused, and a request with no stamped identity, or one that names no workload, has nobody to
  answer and is dropped with a warning. The record must also be the sender's own, of a type its signing certificate
  may record (below).
- **What is added** (`src/evidence.rs`, `place`): a record that verifies in the evidence domain under the CA the server's
  clients chain to, at `<type>/<the subject's values, sorted by key>/<sha256 of its bytes>.json`, as polar-sign
  places its own. The keys are sorted in the code: whether serde_json keeps an object's written order depends
  on the build's features, and here it does (a test caught it). A segment that is empty, starts with `.`, or holds `/`,
  a backslash or a control character is refused.
- **How it is committed** (`RepoStore::add_file`): one commit by `polar-git-server` on `main`, built in an index of its
  own beside the bare repository (no working tree), never over a file that is there; `main` is moved only from the
  commit read (`git update-ref` with the old value), so a push in between is never lost, and the addition is made again
  on top of it, five times at most. A test races five additions at once and loses none; with the old value left out, it
  fails. The commit is announced as `RepoChanged` with the sender as pusher, and written to `push-log.jsonl`, as a push
  is.
- **The actor** (`IntakeActor`): one at a time, so additions never race each other; its answers carry the server's
  identity, for the sender to check who answered. Only with Cassini; on its own the server takes none.
- **Tests:** the messages over the wire; `place` for each refusal; the intake committing, answering with the
  correlation id and announcing once, the same record again already there, a reader and a stranger refused, a record
  under another CA refused, nobody to answer, and a repository that cannot be written answered not now; the store's
  addition, its refusals of paths, and the race; the declared topics.
- **The sender's own** (built 2026-11-10, `key-custody.md`, "Workload signing keys", item 8): a record is taken only
  when its signer is the sender, under a signing certificate (never the pod's mTLS one) whose `c:record-evidence`
  allows its type (`place_senders`, `polar_signing::workload_certificate_refusal`, then policy, the certificate where
  policy is silent).
- **Into the evidence log** (`record-store.md`, "Bite 3"): each record the intake takes is appended to the store's
  evidence log before it is committed, and a push to `polar-evidence` feeds the log before any ref moves; at start the
  log catches up with what the repository holds.
- **Pushed commits about now** (built 2026-11-10, item 7): a push to `polar-evidence` is refused when a commit it brings
  is dated more than ten minutes from the server's clock, or not at all, since readers verify a record as of the commit
  that added it (`check_pushed_times`, in the push's quarantine, over the commits signed repositories check).
- **Not yet:** the rest of the add-only rule for what people push with `git` (no file changed or removed).

### Reads over Cassini, built (2026-11-10, slice C, C2, O1)

- **The topics** (`polar-git-server-common`): an agent publishes `Envelope<ReadMain>` on `polar-git-read-requests`: a
  repository, the paths it wants (each a file, or a directory and all under it, segment by segment; none, every file), and
  the commit it has, if any. The answer goes to the sender's own topic, `polar-git-read-replies.<workload>`, named per
  reader as the evidence intake names its senders (the scheduler observer's first): `Files { commit, files }` (each with
  its path, whether it is plain, executable or a link, and its bytes, by path), `Unchanged { commit }` when `main` is
  still the commit it has, `NoMain`, `Refused { why }` (it may not read the repository, there is none, or the answer is more
  than one message carries: ask for less) or `NotNow { why }` (the repository could not be read: ask again).
- **Who may read** is the repository's readers, judged on the identity the broker stamped, as a fetch over HTTP is on its
  certificate's. A refusal comes before whether the repository exists, so a sender learns nothing of one it may not read;
  a request with no stamped identity, or one that names no workload, has nobody to answer and is dropped with a warning.
- **What is read** (`RepoStore::read_main`): `main`'s tree, entered only where it leads to a path asked for, each blob
  read in process; a submodule's commit is passed over. Reading stops once the files and their paths pass the bound, and
  the whole answer is held to it again before it is sent: Cassini's payload bound (64 MiB less the envelope's allowance,
  `cassini_types::MAX_PAYLOAD_BYTES`).
- **The actor** (`ReadActor`, `server/src/read.rs`): one read at a time, beside the evidence intake, so a read never waits
  on an addition. Only with Cassini.
- **Tests:** the wire types' round trip for every request and answer (a property), garbage refused; the store's read
  (the whole tree, a directory, files, a prefix of a name that is not a path, unchanged, no `main`, file kinds, too large),
  and a property that a read enters every directory above a wanted file and takes only wanted files; the reader answering
  on the sender's topic, a stranger refused before anything is said of the repository, a reader told a declared repository
  is not there, too large refused, nobody to answer; the declared topics.

## Authorship, and degraded mode

The server's own record of pushes says who pushed what and when: `push-log.jsonl` beside the
repositories, one JSON line per accepted ref update (time, repo, ref, old, new, pusher), appended and
synced. It is append-only by construction but not signed or chained, so it is a record, not proof;
a signed log in the style of the credentials ledger is the later step. It is not the only proof,
because it does not exist when the repo is hosted elsewhere.

Authorship travels in the data: commits are signed with the author's Polar certificate key
(`gpg.format=x509` with a signing program that Polar ships, `polar-sign`), and the consumer
verifies the signature against the Polar CA chain and the certificate's permissions, whichever
remote the commits came from. Degraded mode (own remote) therefore keeps verified configuration,
loses push-time authorization, the push log and `RepoChanged` notifications, and needs `polar-sign`
on the author's machine but no other client.

## Build order and tests

1. This document and the work-file decision record.
2. Crate on the builder: TLS listener, identity extraction, request actor.
3. Repo store and one-time seeding.
4. Read path (`upload-pack`).
5. Write path (`receive-pack`, ref-command parsing, authorization).
6. `RepoChanged` topic.
7. Push log.

Tests run real `git` against the server (clone with a valid cert; unknown or unauthorized cert
rejected with no anonymous fallback; authorized push; rejected push to a repo the identity cannot
write; seed once and not again; idempotent `CreateRepo`; `RepoChanged` only after success).
