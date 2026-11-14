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

# The record store: Polar's signed logs, presented as git

Status, 2026-11-10: designed with the maintainer, and **cleared as written** by the maintainer the same day, the
choices marked *(for review)* included. Built first on the agentic-control-plane branch, and coming to main in bites
(the maintainer, 2026-11-13: "Bring the store to main"; `docs/plans/record-store/to-main.md`).

**On main (2026-11-13):** bite 1 of that plan: the store's logs in the git server, served to people as tiles; the
evidence intake over Cassini, each record appended to the evidence log, a push to `polar-evidence` too, and the log
caught up with the repository at start; and the attestation agent's records (below, "Attestation verdicts as
records"). The checkpoint key is the crypto actor's (`docs/plans/crypto-actor.md`): it makes it once beside the logs,
signs every checkpoint and has the credentials agent certify it, so the store holds no key of its own. **On main
(2026-11-14):** bite 2, the witness (bite 5 below): the attestation agent co-signs each checkpoint through its crypto
actor, the store keeps each co-signed checkpoint beside its log and serves only those, and up.nu's seed pins each key
in the other's settings (`runtime-attestation.md`, "The witness of the store's logs", which says how main differs).
**On main (2026-11-14):** bite 3, schedules on the log (bite 6 below): each push to polar-schedules is appended to the
schedules log before any ref moves, the log is caught up with polar-schedules' `main` at the store's start, and the
scheduler observer reads the log over Cassini, held to its two pins, which up.nu's seed signs in its settings. As on
the other branch, but for one thing: until the witness has co-signed a log, the store answers a reader with its own
checkpoint, and on `main` the crypto actor signs it when it is asked, since the store holds no key. **On main
(2026-11-14):** bite 4, people's tools over Cassini (below, "People's tools over Cassini"): a person's floor, Cedar told
whom a topic is addressed to, the store answering a person and taking their signed sections, and `polar-sign`'s pushes
through `polar-records-client` when no git repository is named, its TLS from a crypto actor over the person's files.
`polar-eden`'s use of the client is the other branch's. **On main (2026-11-14):** bite 5, `polar-git` and its git
client, `git-remote-polar` (`polar-git.md`, which says how main differs). Every bite of the plan is on `main`. What this page says of those, and of `polar-eden` (a tool of the agentic-control-plane
branch), describes that branch until its bite lands. Decisions the maintainer made are dated
and attributed; the rest are this session's, by the design principles (`AGENTS.md`), and marked *(for review)*. Owner:
the agentic-control-plane session (the maintainer, 2026-11-10). The research on formats and Merkle logs is polar-89's,
in main's `docs/architecture/ledger-evolution.md`, and is cited here, not redone.

## Why

Polar keeps several logs of signed facts that are only ever added to: evidence records, the agents' signed configuration
(polar-schedules), the deployment and its signed record, the git server's push log, and the credentials agent's ledger.
They live in git repositories, or in a JSON file, and every property Polar has needed of them this past week was built on
top of git rather than given by it:

- a record's time is the commit's, which is the pusher's word, so the server holds pushes to a window of its clock;
- when a record arrived is worked out by reading `git log`, and a reader that cannot run git must refuse to read;
- what is added is meant to stay (add only, decided 2026-11-06), but a push may delete or change a file, and a reader of
  the tree no longer sees it, so a deleted revocation brings its certificate's records back;
- nothing outside the server can check that it did not rewrite or reorder what it holds;
- the credentials ledger's entries carry no type or version, so a newer writer stops an older reader (`ledger-evolution.md`).

Meanwhile what git is good at is barely used: agents write and read over Cassini, the server is gitoxide in process, and
nobody branches or merges evidence. The maintainer (2026-11-10): "we're basically only supporting git in-name… Maybe the
storage tech underlying it isn't actually git. Maybe we can do better… and get some of the properties we care about with
polar, while also improving our assurance goals."

## Decided (the maintainer, 2026-11-10)

1. **A store of signed logs replaces git as the system of record**, and **can present as git**: in a *degraded mode*,
   where the deployment is kept in a site's own git server, and at *deployment time*, where git is mostly needed. In
   self-hosted Polar, git access can be turned off.
2. **The store always runs; git is one more face.** Polar's agents use the store only through Cassini (the 2026-11-09
   rule, `git-server.md`, "Inside the boundary"). Degraded mode means only that the deployment lives in the site's own
   git, which the store exports to.
3. **What it holds:** evidence (attestation records and revocations among them), polar-schedules, the deployment and its
   record, and the store's own push log. **The credentials ledger stays the agent's own file**, in the same format,
   since the agent starts before the store; its signed checkpoints go into the store, so its history leaves the agent.
4. **Entries are deterministic CBOR** (RFC 8949, 4.2). Today's signed JSON documents ride inside an entry as opaque
   bytes, unchanged.
5. **Checkpoints are signed with a stable P-256 key of the store's own**, certified by the internal CA for that purpose
   alone; witnesses pin it. The credentials agent certifies it (decided 2026-11-11): at nominal cert-issuer is isolated
   beyond the credentials agent, and nothing else asks it for a certificate; the isolation becomes formal with the
   cluster's network policy.
6. **Witnesses:** the attestation agent co-signs each checkpoint, live; polar-eden keeps the last checkpoint it verified,
   on the reader's machine, and checks consistency at every read. Decided 2026-11-11 (through polar-89): **readers
   require the witness's co-signature**; the store serves the latest co-signed checkpoint, readers pin both keys, and
   while the witness is down they see the log as of its last co-signature. **The co-signature is P-256**, outside C2SP
   tlog-cosignature (Ed25519 or ML-DSA-44 only), so only Polar code checks it. **Cadence:** a checkpoint at the store's
   start and at most once a second while entries arrive, each submitted to the witness. The plan: "Bite 5", below.
7. **People write two ways:** `polar-sign` appends through the store's own mTLS interface, and a git push is turned into
   appends, under the same admission; a push that deletes, changes or renames a file is refused. Both go when git does.
8. **polar-git-server becomes the store**, and the crate moves to this session's ownership (polar-89 agreed, nothing of
   its in flight there).
9. **The shared log format is the store's** (the envelope, the Merkle tree, checkpoints, witnesses), in one crate the
   credentials ledger also uses; the ledger's own parts stay polar-89's (`ledger-evolution.md`).
10. **A deployment entry is the pipeline-signed commit, with the objects it adds, as a git pack.** The log's order is the
    history, so a walk from the commit applied is "the entries since", and a rewind cannot be appended. The git face
    serves those commits byte for byte, and any transport carries the same verifiable bytes
    (`polar_signing::commit::verify_commit`).
11. **The deployer** (Polar's GitOps controller, `gitops-controller.md`, unvetted) **reads the store over Cassini at
    nominal, its seed ConfigMap at bootstrap, and, in degraded mode only, the site's own git**: an exception to the
    2026-11-09 rule, granted by the maintainer for the deployment alone (chosen in so many words, 2026-11-10).

### Revised (the maintainer, 2026-11-11): source code goes to `polar-git`, and records take no direct connections

Asked to make the git server usable as an ordinary git server, the maintainer found the record rules had spread to every
repository: no force-push or branch deletion anywhere, no tags, creation by an administrator only. Decided, in
conversation, and then "please just go ahead and implement":

- **Two services, each kind of data in one home.** `polar-git` hosts source code; the store (this document, the
  workload `polar-git-server`, keeping its name so its logs' origins and the witness's pins stand) holds the records.
  Nothing is copied between them: a record names a commit by its digest.
- **`polar-git` is the one service inside the boundary that takes direct connections**, since git is a protocol Cassini
  cannot carry without breaking every git client. Its edge does what the broker does: Polar certificates say who,
  Cedar decides each operation (reading, pushing, forcing, deleting, tagging, creating), and everything it does,
  refusals included, is reported over Cassini, so a source repository is as observable as any agent. A person with
  the right Cedar permissions (a `repo-developer` group) does ordinary git: any branch, tags, force-push and deletion
  where policy allows. People reach it through the Polar git client, a git remote helper (`git-remote-polar`), so
  plain `git` commands work.
- **The store takes no direct connections at nominal.** Agents and the deployer reach it over Cassini, as they do;
  people's own tools (`polar-sign`, `polar-eden`, `fetch-log`) are moved onto Cassini as clients with the person's
  certificate ("We can adjust our own tools"). Flux keeps its read of the deployment until the deployer replaces it
  ("We are replacing flux, it will work much differently").
- **What it changes here:** decision 1's git face is for degraded mode and deployment time only, no longer how people
  write; decision 7 becomes: people write through their tools over Cassini, under the same admission, and git pushes
  of records go with Flux; decision 9 (git pushes as appends) is no longer a bite. Bite 7, the deployment log, waits for
  its reader, the deployer; decision 10's packs are revisited then (the maintainer had no preference between packs and
  the signed commits alone, 2026-11-11).

### People's tools over Cassini: the plan (2026-11-11, this session's, by precedent, for review)

The maintainer: "We can adjust our own tools", and "go ahead and implement, no need to ask me". Built in this order:

- **A person's floor.** A person's certificate names no workload, and today implies no topic (`polar-agent-builder`,
  `floor.rs`), so only policy lets one use Cassini (the seeded `config-readers` rules, `polar-running-config`). As a
  custodian's floor is its identity's and the same for every custodian, a person's becomes: publishing the store's
  request topics (`polar-git-evidence-requests`, `polar-log-read-requests`, `polar-schedules-requests`), and hearing the
  answers on topics named with their own identity (`polar-git-evidence-replies.<identity>`,
  `polar-log-read-replies.<identity>`, `polar-schedules-replies.<identity>`), so nobody hears another's answers. Cedar
  overrides it both ways, as every floor.
- **The store** answers a person on their own topic, as it answers a workload on its; who may read or write a log or a
  repository is judged as now, on the identity the broker stamped (the repository's readers and writers, the evidence
  admission).
- **The tools.** `polar-eden collect --push` sends its signed run to the evidence intake, as the attestation agent sends
  its verdicts. `polar-sign`'s pushes of signed sections go as a schedules request, appended to the schedules log and
  committed to polar-schedules by the store, as the intake does evidence. `polar-eden fetch-log` reads a log's leaves
  over Cassini and builds its mirror from them, held to the same keys.
- **Not moved:** up.nu's seed, which runs at deployment time, where git is the face (decision 1).
- **Decided (the maintainer, 2026-11-11): Cedar decides who hears a person's answers.** The broker, and every agent's
  own gate, tell Cedar the person a topic is addressed to (`context.addressed`), when its name ends with a person's
  identity, an account's UUID (`polar_git_server_common::is_person`, so no certificate can name itself to hear a
  workload's answers). The first policy lets that person hear it, nobody else, and the store (by its `workload`
  attribute, so the rule holds on any cluster domain) publish it.
- **Built (2026-11-11):**
  - a person's floor: the store's request topics, and the answer topics named for them;
  - the store answering a person by their identity (`polar_git_server::reply`);
  - the evidence intake taking a person's own record, signed with the certificate they connected with;
  - a section intake: a signed section from a person who may write polar-schedules is logged first, then committed at
    its place (put over its earlier version), then announced;
  - `polar-records-client`, the asking side every tool shares;
  - the tools: `polar-sign`'s pushes and `polar-eden collect --push` go over Cassini when no git repository is named
    (`--repo`, `POLAR_SCHEDULES_URL`, `POLAR_EVIDENCE_URL` keep git, for degraded mode and a site's own server), and
    `polar-eden fetch-log` without `--from` reads the log over Cassini and builds its mirror from the leaves, held to the
    same keys.
- **Live on u7c (2026-11-11, agentic-control-plane b1e7f270)**, as djshepard, with no git repository named and no direct
  connection to the store:
  - policy version 4 (the two rules) went in with git, since the store may answer a person only once it is in force;
  - `polar-sign sign --push` sent kube-observer's settings version 2 over Cassini: the store logged and committed it, and
    kube-observer applied it seconds later;
  - `polar-eden fetch-log --log schedules` and `--log evidence` built their mirrors from leaves read over Cassini (25 and
    27), held to both keys, and `records` verified the 27 evidence records by the policy from the schedules log;
  - `polar-eden collect --package polar-version --sign --push` sent its signed run over Cassini, and the store holds it.

Already decided, and kept: add only, a wrong record superseded and never changed or removed (2026-11-06,
`polar-eden.md`, "Signed evidence"); large bodies as content-addressed blobs in the registry, Nix-store style, with
the logs as their roots (2026-11-05).

## What it must give

| Requirement | From |
|---|---|
| Named logs, append only; a wrong entry superseded, never changed or removed | decisions 1 and 3; 2026-11-06 |
| Each entry signed by its author, verified in its own domain | polar-signing's domains |
| One admission, whatever the way in: signature, the policy then, a known type | the evidence intake; git pushes bypass it today |
| The log's own sequence and time for every entry, in what is hashed | replaces the commit-time window |
| Inclusion and consistency proofs; signed checkpoints; witnesses | `ledger-evolution.md`; decisions 5, 6 |
| "As of" and "since" reads; "newest" is the entry added last | forbid forward, revocations; confirmed 2026-11-10 |
| Typed, versioned entries with a critical flag; the envelope readable before the event; the writer's Polar version; a replay that gives back "unknown type or version" with the flag and lets the caller decide; an entry saying a log continues an older one (its last hash and count) | `ledger-evolution.md`; polar-89's six needs |
| Blobs by digest in the registry | 2026-11-05 |
| Presentable as git, served byte for byte where entries are git's own; git off when self-hosted | decisions 1, 7, 10 |
| Reached through Cassini inside the boundary | 2026-11-09 |

## The shape *(for review)*

**An entry** is deterministic CBOR, an envelope map: `0` its type, `1` its version, `2` critical, `3` the writer's
platform version as polar-version's record gives it (a semver and the target, never a commit, so a refusal compares
versions), `4` the event as a byte string, its encoding fixed for each type and version by the log's owner (a signed JSON
document, a git pack, a ledger event in deterministic CBOR), so a reader passes over an event it does not know without
decoding it. **A leaf** of the log is the CBOR of `{0: entry bytes, 1: admitted at
(Unix milliseconds), 2: the submitter's identity as the broker or TLS stamped it}`: the log's time and who brought the
entry are in what is hashed, and the signed event inside still says who made it.

**Replay** gives back, for each entry, one of four things, and the caller decides what to do with all but the first:
*decoded*; *unknown* (a type or version this reader does not know: its type, version, critical flag, writer and sequence,
so the caller holds on a critical one or skips and counts the rest); *malformed* (a type and version it knows whose bytes
do not decode: corruption or a writer's fault, never skipped as an unknown non-critical one may be); and *torn* (the last
entry cut short by a write that did not finish). *(The four outcomes, polar-89's review, 2026-11-10.)*

**A log continues an older one** with a first entry naming it: `{old_kind, alg, digest, count}`, the digest tagged with
its algorithm (a git repository's last commit is a SHA-1 id; the JSON ledger's would be a SHA-256).

**A log** is an RFC 9162 Merkle tree over its leaves, kept on the store's volume as C2SP tlog-tiles (tiles and entry
bundles), so a reader can fetch and verify any part without the rest. The same crate keeps a log in the same layout on an agent's
own volume, for the credentials ledger: appended and synced before it is answered, replayed at start. Its recovery rule:
a torn final entry is cut back to the last whole one, and said; damage before the end refuses the log. Indexes (by type and subject, by time) are
derived from the log and rebuilt from it, never a second truth. A **checkpoint** is a C2SP checkpoint in a signed note,
signed with the store's key (decision 5), made at the store's start and at most once a second while entries arrive;
co-signatures are added beside it. Hashing and proofs from `tlog_tiles` (Cloudflare's port of Go's `sumdb/tlog`), or a
few hundred lines of our own held to it and to Go's test vectors by properties (`ledger-evolution.md`, "The Rust
crates").

**The credentials ledger's checkpoints** are signed by the credentials agent, with a key of its own for that purpose
(one key, one purpose: neither its authority key nor its escrow key), and published into the store as entries of their
own, where the store's checkpoints and witnesses cover them. *Decided (the maintainer, 2026-11-11):* the key is one of
its own, P-256, certified for that purpose alone as the store's is (decision 5): through the credentials agent, the one
workload that asks the cert issuer. The ledger's events are marked
critical as `ledger-evolution.md` proposes ("A proposed classification"): an older agent refuses to serve on a critical
type or version it does not know and passes over the rest, counting them; every type is critical unless declared
otherwise, and the build fails on a type with no mark.

**Admission**, the same whether an entry arrives over Cassini, from `polar-sign`, or from a git push, before anything is
appended:

| Log | Admitted when |
|---|---|
| evidence | the record verifies in the evidence domain; over Cassini its signer is its sender, under a document-signing certificate; policy admits its type for its signer, then the certificate (`admit_evidence`) |
| schedules | the document verifies in the configuration domain, chains to the CA, and its signer may make that change (policy, then the capability) |
| deployment | the commit verifies under the deployment CA as `pipeline`, and descends from the log's last entry; its message carries a `Provenance-Sha256` trailer (`gitops-controller.md`, section 6) that matches the pack's `provenance.json`, so what the pipeline signed reaches the tree in SHA-256, not only SHA-1. The log proves the store kept what it got; the trailer proves what the pipeline meant |
| push log | the store's own entries only |

**Reads over Cassini**: an entry range; "since" a sequence; "as of" a time (the sequence then); the newest entry of a
type and subject; inclusion and consistency proofs; the latest checkpoint and its co-signatures. An answer fits one
message, and a reader pages. The deployer's read of the deployment log is a range of packs from the commit it applied.

**The git face**: a log presented as a repository, made from its entries. Evidence and schedules: a commit for each entry,
adding its file at its place, committed at the time it was admitted, so a reader of the git face (polar-eden today, a
mirror, a person) sees the log's times. The deployment: the entries' own commits. A push is read in the push's
quarantine and turned into appends: each added file one entry, refused whole if it deletes, changes or renames. The
face can be turned off.

**Moving in**: each repository is copied, not converted in place: its commits in order become entries that carry their
original commit and time, after a first entry naming the repository's last commit and how many it held, and the old
repository is kept read-only beside it. The credentials ledger moves to the format by the same copy, in the agent
(polar-89).

**Readers**: polar-eden reads a log with its proofs and keeps its last checkpoint (decision 6), and judges a record as
of the time the log admitted it, which replaces `added_at`'s `git log`; on a git face or a mirror it falls back to the
commit times, and says so.

## Bites, in order *(for review)*

1. *The format crate*: the envelope and leaf in deterministic CBOR (a re-encoding property), the Merkle tree and its
   proofs (held to Go's vectors), checkpoints in signed notes (signed and verified with P-256), a replay that gives back
   decoded or "unknown" with the flag; tests first, properties throughout.
2. *One log in the store*: on its volume as tiles, appended and read, its checkpoint signed with the store's key, the
   certificate for it from the credentials agent (decision 5).
3. *Evidence on it*: the intake appends instead of committing; reads and proofs over Cassini; the git face for evidence.
4. *polar-eden reads the log*, proofs and the remembered checkpoint, the log's time in place of `git log`.
5. *The attestation agent witnesses* (planned 2026-11-11, below; reads of a log over Cassini move to the first
   monitor, a bite of their own).
6. *Schedules*, the scheduler observer reading the log (planned 2026-11-11, below).
7. *The deployment log*: packs, the walk, the `Provenance-Sha256` trailer in `publish`; Flux, and later the deployer,
   reading the git face, tested as Flux is configured: a depth-1 clone (gix-serve needed shallow fetches for it).
   *Waits for the deployer, its reader (revised 2026-11-11, above).*
8. *Moving u7c's repositories in*, and the push log.
9. *Git pushes as appends*, and turning the face off.
10. *The credentials ledger's checkpoints* published into the store, with polar-89's ledger work.

## Bite 5, the witness: the plan (2026-11-11, cleared by the maintainer the same day)

The maintainer's order: polar-89 writes the witness's side into `runtime-attestation.md` and this session the store's
here, both for review; the maintainer clears them; then this session builds the store's side and the co-signature code
in polar-log, and polar-89 builds the witness and runs it live on u7c. Read: C2SP tlog-witness and tlog-cosignature
(polar-89, the editor's copies, 2026-11-11) and signed-note's type registry.

**A witness reads no entries.** The log brings it each new checkpoint, as tlog-witness's `add-checkpoint`: the size the
log believes the witness last co-signed, a consistency proof from that size, and the new signed checkpoint. The witness
checks the proof against the size it holds for that origin, keeps the new one before it answers, and answers with its
co-signature line; on a size that is not its own it answers with its size (409), on a proof that does not hold it
refuses (422). Reading a log's entries over Cassini is a monitor's job, so the earlier line "the first workload reader is
the witness" no longer holds: Cassini reads wait for the first monitor.

**The co-signature (polar-log, shared, so the witness signs with it and readers check with it):**
- *Its type is `0xff` followed by `polar.dev/cosignature/p256/v1`*: signed-note keeps `0xff` for types it does not
  assign, followed by an identifier unlikely to collide (0x01 to 0x06 are assigned, 0x03 and 0xfa to 0xfe reserved). A
  type of its own, not the checkpoint's `0x02`, because `open` checks every trusted key's line over the note's text and
  refuses the note when one fails, and a co-signature is over another message: under `0x02` a reader trusting both
  keys would refuse every co-signed checkpoint. *The identifier's text (for review).*
- *Its key ID*, as C2SP derives co-signers': the first four bytes of SHA-256 of the key's name, `0x0A`, the type
  (`0xff` and the identifier) and the DER SPKI, so a witness key never shares an ID with a checkpoint key. *Its
  verifier key*: `<name>+<id>+base64(type || DER SPKI)`; a verifier knows the one identifier, so where the SPKI begins
  is never in doubt.
- *What is signed*: `cosignature/v1\n`, `time <T>\n`, then the checkpoint's body (C2SP's message), with ECDSA P-256
  over SHA-256, DER. *The line* carries the key ID, then T as a big-endian u64, then the DER signature; the header and
  time lines are only in the signed message, never in the note, and a reader rebuilds them from T.
- *`open` checks each trusted key over its own message*: the checkpoint's key over the text, a co-signer over the
  co-signature message, and says which verified. A co-signature dated in the future of the reader's clock by more than
  a minute is refused *(for review: C2SP leaves T's checking to the reader)*.

**The store's side:**
- *Cadence*: a checkpoint at the store's start and at most once a second while entries arrive, replacing bite 2's
  checkpoint at each request. Each is submitted to the witness over Cassini, inside the boundary (2026-11-09), as a
  request with a reply topic named for the store; its message carries add-checkpoint's three parts, and its answers the
  co-signature line, the witness's size, or the refusal. *The wire form is the witness's* (`runtime-attestation.md`,
  "The witness of the store's logs: the plan"; the types in `attestation-common`, rkyv in the shared envelope): the
  store asks on `attestation-witness-requests` with `AddCheckpoint { old, proof, checkpoint }` and is answered on
  `attestation-witness-replies.polar-git-server`, each answer naming the checkpoint's origin and size; an answer that
  names neither a checkpoint the store asked about nor its latest is dropped.
- *Each answer*: `Cosigned(line)` is checked and kept; `Conflict(size)` (409) is submitted once more from that size,
  said at info; `Refused` is said by its reason. `UnknownOrigin` (404) and `Untrusted` (403) mean the keys are not yet
  pinned in each other, or not alike: an outage, said once. `Malformed` (400) after a 409's retry, and `Inconsistent`
  (422), mean the store's own signed checkpoints cannot follow what the witness co-signed: an error each time, never
  retried as they were, since the witness reports them as misbehaviour.
- *What the store keeps*: the latest co-signed checkpoint of each log, written beside the log (to a new file, synced,
  then renamed over) before it is served. The size it last saw co-signed is the size it submits from; on a 409 it
  submits again from the witness's size, with the proof from there.
- *What it serves*: `/logs/<log>/checkpoint` is the latest co-signed checkpoint, never a newer one alone. The tiles
  past it are served as before; a reader verifies only as far as the checkpoint it holds.
- *The store checks what it gets back* against the witness's key before keeping it, so it never serves a line that does
  not verify. It learns that key, and the witness's name, from a signed runtime section via polar-schedules (the design
  principle: what an agent must know about others is signed configuration at run time), until the credentials agent
  certifies witness keys as it will the store's own (decision 5). The witness's key is named `<identity>/witness`. The
  witness learns the store's key the same way, so a first deployment has one step for a person: both log their verifier
  keys, and an administrator signs the update that pins each in the other. *Decided (the maintainer, 2026-11-11):*
  up.nu does it on any target, as the `--user` who runs it, waiting for both keys to be logged and signing the update.
- *While the witness is down*, or answers with a refusal: the store keeps appending and keeps serving the last
  co-signed checkpoint, says so in its log once per outage, and submits again at the next checkpoint. Before the first
  co-signature a log has no checkpoint to serve, and a reader is told "not yet witnessed". A refusal on proof (422) is
  the one answer that should never happen between two honest parties, so it is said as an error each time.
- *Every log is witnessed*, each origin on its own, since readers require the co-signature of every log they read.

**Readers (polar-eden)**: `fetch-log` and `records --evidence-log` pin the witness's key beside the store's
(`--witness-key`, or `POLAR_EDEN_WITNESS_KEY`, beside `--log-key`), and refuse a checkpoint without both signatures.
The remembered checkpoint stays per store key.

**Tests first**: the co-signature's round trip and its refusals (another message, another time, another key, a line
under the checkpoint's type); `open` with both keys trusted; the store's cadence, its 409 path, an outage served as the
last co-signed checkpoint, and the restart that finds the kept one; a reader that refuses a checkpoint missing either
signature. Properties: a co-signature verifies only over the exact message signed, and the store never serves a
checkpoint whose co-signature does not verify.

## Bite 6, schedules on the log: the plan (2026-11-11, cleared by the maintainer the same day, as written)

polar-schedules gets a `schedules` log beside it, as polar-evidence has `evidence`. The scheduler observer reads that log
over Cassini, held to the witnessed checkpoint, instead of asking what `main` holds. polar-eden's `--schedules` reads the
policy's history from it. Everything after the observer's checkout stays as it is: the watcher, the processor, and each
agent's own verification.

**What polar-schedules is (read 2026-11-11).** It is a tree of files, not a pile of records:
- `polar-sign push` writes each new version of a section over the one before, at its place
  (`permanent/<agent>/<section>.dhall`, `push::place`).
- `migrations/<agent>/<id>.cypher` and the records that a migration was applied sit beside the sections.
- up.nu's seed removes the sections of a configuration no longer under test (`under-test.nu`, `left_behind`).

The observer's checkout holds the tree `main` holds, and a file gone from it is a `GitScheduleChange::Delete`. So the
log carries changes to the tree, and the tree is derived from the log.

**The entries.** There are two types, each at version 1 and critical, since a reader that skips either derives the wrong
tree:
- `schedules-file`: `{0: path, 1: bytes}`, the file's whole bytes as pushed;
- `schedules-removal`: `{0: path}`.

The tree as of a sequence holds, for each path, its last file entry, unless a removal of that path follows it. The
derivation, and the difference between two trees, live in `polar-git-server-common` (the observer already depends on
it). Properties hold them:
- applying the difference from tree a to tree b, to a, gives b;
- the tree does not depend on how its entries were split across pushes;
- a removal followed by the same file again holds the file.

**Each change is appended once, judged against the tree rather than the entry's digest.** The evidence log answers an
entry it already holds with that entry's first sequence. Here the same bytes can come back after a removal, and they must
be a new entry. The store keeps the log's tree in memory and appends only what differs from it, so a push sent again
after a lost answer appends nothing.

**What the store appends:**
- *For a push to polar-schedules*, once nothing else refuses it: the difference between the log's tree and the new tip
  of `main`, appended as the pusher's before any ref moves, as `evidence::pushed_records` does. A change the log does not
  take refuses the push. Only `main` counts, since the observer reads nothing else.
- *At the store's start*: the difference between the log's tree and `main`'s, appended as the store's own. On the first
  start this fills the log, after a continuation entry naming `main`'s commit (SHA-1) and how many commits it held. On a
  start after an older store took pushes (a rollback), it catches the log up. One mechanism covers the first fill, a
  push and a catch-up.
- *Pushes are taken as the repository takes them* (bite 3's rule): who may push stays as it is today. The admission rules
  for the configuration domain (the table in "The shape") come with bite 9.
- *A link, or a file over the leaf bound, is never an entry.* A push that brings one is refused; the checkout never
  makes a link, and nothing reads one. One the repository already holds at the start is left out, and the store says so.

**Reads of a log over Cassini.** The observer is the first workload to read a log; the monitor will use the same reads.
A reader sends `ReadLog { log, from }` on `polar-log-read-requests` and is answered on its own
`polar-log-read-replies.<workload>` with one of four answers, `LogRead::`:
- `Entries { checkpoint, leaves }`: the latest co-signed checkpoint, and the leaves from `from` up to its size, as many
  as one message carries; the reader asks again from where the answer stopped;
- `NotWitnessed`;
- `Refused { why }`;
- `NotNow { why }`.

Who may read a log is the readers of its governing repository, judged on the identity the broker stamped, as `read_main`
judges them. A reader sees the log as of its last co-signature (decision 6), and never a leaf past it.

**When a log's co-signature grows**, the store says so on `polar-log-witnessed` (`{log, size}`, caused by the
witness's answer), and the observer reads at once. The announcement of a push alone would find nothing witnessed yet.
The interval read stays.

**The observer holds the log to its keys.** Two Dynamic settings, `POLAR_SCHEDULER_STORE_KEY` and
`POLAR_SCHEDULER_WITNESS_KEY`, are signed by up.nu's seed, as the store's and the witness's pins are, in one document
that is version 1 of the observer's settings. The observer keeps every leaf it has read, since the log is small. It takes
an answer only when its leaves make the root of a checkpoint that `open_witnessed` opens with both keys. Then it derives
the tree and writes the checkout as it does now (`checkout::apply`).
- A critical entry of a type it does not know stops it at that entry, and it says so.
- A malformed entry refuses the answer.
- A log that is not the one it held, where its leaves do not make the root, stops it with an error. It delivers nothing
  more until it is restarted.

**Its own keys come from the log it reads.** The observer's settings arrive through the observer itself, so it has no
keys when it starts. It reads the log as it is answered and takes its own settings document from the tree
(`permanent/polar-scheduler-observer/configuration.dhall`). It submits that document to its own `ConfigurationHandle`,
which verifies it as every agent does: the CA, the signature, the signer's authority and the version. Only once the keys
are applied does it hold what it read to them. Nothing reaches the checkout before then. The store cannot put keys of
its own in the document, since an administrator signs it. The most it can do is withhold the document, and then the
observer delivers nothing and says why. *(For review: the alternative is for the observer to believe the store's answer
as it believes `read_main` today. That leaves readers trusting the store, the opposite of decision 6.)*

**polar-eden's `--schedules`** reads the policy's history from the schedules log, as `--evidence-log` reads evidence.
Each version is in force from the time the log admitted it, not from the pusher's commit time. `--schedules <checkout>`
stays for the git face and for a mirror, and says which it read. *(For review: this adds a second reader to the same
bite.)*

**up.nu.** The seed's pins carry the observer's two keys in one document. The rest of the seed is unchanged and pushes
as it does now.

**Not in this bite:**
- the read of the deployment record (bite 7);
- the git face: polar-schedules is still written, and `polar-sign check` reads a checkout;
- a signed withdrawal in place of a removal (bite 9, below).

**Open, for bite 9 (found while planning this one).** Decision 7 refuses a push that deletes, changes or renames a file.
But for schedules, a new version *changes* its file at its place, and the seed removes the sections no longer under
test. One of two things has to give:
- for schedules, a file changed at its place counts as an append, and a removal becomes a signed withdrawal; or
- `polar-sign` places each version at a path of its own, and the newest version is the one in force.

Bite 6 takes both kinds of change as the repository does.

**Tests, written first:**
- properties of the tree, as above;
- the store:
  - a push appends its difference, and nothing when sent again;
  - a removal, then the same file again;
  - the catch-up at the start, and the first fill with its continuation entry;
  - a link refused;
  - reads only up to the co-signed size, and paged;
  - refusals by identity;
- the observer:
  - nothing written before its keys are applied;
  - a log held to its keys;
  - a root its leaves do not make stops it;
  - an unknown critical entry stops it;
- end to end, through the store's real push path;
- mutants on each.

**Live on u7c:**
- a fresh seed;
- a signed settings change for one agent, delivered through the log;
- the observer restarted;
- a configuration under test removed.

## The credentials ledger on the log: the plan (2026-11-11, cleared as written by the maintainer the same day)

The ledger work from `ledger-evolution.md` (main) and bite 10. *Decided (the maintainer, 2026-11-11):* the
checkpoints' key and the events' criticality (above, "The credentials ledger's checkpoints"), and the events are CBOR
now, through minicbor 2's derives. Read for it: `lib/src/event_log.rs`, `credentials-agent/consume/src/ledger.rs`,
`projection.rs`, `supervisor.rs`, `authority_certificate.rs`, `common/src/events.rs`, `polar-log` (`entry.rs`, `file.rs`,
`checkpoint.rs`), the store's move of its repositories (`logs.rs`, the continuation) and `polar-agent-builder/src/health.rs`.
Three bites. The first is planned in full; the other two are outlined and planned once it is built.

**L1, the ledger on the log.**
1. *Each event kind has frozen wire types.* `credentials-agent/common` gains a `ledger` module. Each variant of
   `CredentialsEvent` is a kind (`credentials.grant`, `credentials.revoke`, and so on) at version 1. Each version is a
   struct of its own, derived with minicbor as an index-keyed map, and is frozen once written. The domain enum
   converts to and from them, so the enum can change while what is on disk stays as written. The types nested in an
   event (cert-issuer's `Permission`, `Capability`, `CertType` and `IssuePath`; `EscrowedSecret`;
   `SignedAdminAction`; and the rest) get index annotations where they are defined. The recorded samples (5) catch a
   change to any of them.
2. *Strict and deterministic.* An event's bytes are deterministic CBOR (RFC 8949, 4.2.1). Maps keyed by text, such as
   a secret's labels, are written with their keys in that rule's order. That is the order of the encoded keys'
   bytes, not `BTreeMap`'s. A decoded event is encoded again, and the bytes must match, so a non-canonical event is
   *malformed* and is never read as some other value. Each entry's length is capped by `polar-log`'s frame. The
   events are not recursive, so their nesting is bounded by their types.
3. *Criticality is a match, not a list.* A function maps every variant to its kind, version and critical mark, with
   the marks as decided. A new variant that is not given its arm fails the build.
4. *Replay gives four outcomes* (above, "Replay"):
   - *decoded*: the event is folded into state;
   - *unknown and not critical*: the entry is passed over, counted and reported;
   - *unknown and critical*, or *malformed*: the agent refuses to serve. Its supervisor starts nothing else and loads
     no key. It stays up, held unhealthy with one line: "the ledger holds `<kind>` v`<n>`, written by `<writer>`,
     which this agent (`<own version>`) cannot read; it serves nothing until a version that can is deployed";
   - *torn*: the last entry is cut back, and the run says so, as `polar-log` does.

   The hold needs a new `HoldReason`, `Version`. That changes the health report's wire type, which C3 avoided for the
   lock state. Here the agent's own health is the only place the refusal can be seen. *For review.*
5. *Compatibility is checked transitively.* `common/tests/ledger-samples/<kind>.v<n>.cbor` holds a recorded sample of
   every version of every kind. A test decodes each sample with the current code. A second test checks that the
   current writer's encoding of the example each kind declares equals the recorded sample of its current version. So
   a change of shape without a new version and its upcaster fails the build. There are properties too: encoding then
   decoding gives back any event, and every decoded byte string is the one encoding of its value.
6. *The ledger is a `polar-log` file log.* It goes in `CREDENTIALS_LEDGER_PATH`, a new path setting, `WriteFile`,
   default `/var/lib/credentials-agent/ledger.log`, beside the old file. Each leaf is admitted at the time of its
   append and submitted by the agent's identity. Its writer is the platform version, as the store names its own
   (`logs::writer`). `FileLog::open` gains `EventLog`'s exclusive lock and its `Held` refusal, so `open_log`'s wait
   for a draining predecessor carries over. The store's logs gain the same guard.
7. *The JSON ledger is copied, once.* At open, when there is no `ledger.log` and `CREDENTIALS_EVENT_LOG_PATH` names an
   `events.jsonl`, the agent replays it with today's `EventLog`, so its chain is checked as it is read.
   - It writes a continuation into `ledger.log.copying`: `{jsonl, sha256, the old last hash, its count}`.
   - After it comes every old event, as version 1 of its kind, admitted at the old entry's timestamp.
   - It syncs the file and renames it to `ledger.log`. The old file stays where it is, read-only (mode 0400).
   - A `.copying` file left by a crash is removed, and the copy is made again. The run says what it copied.

   An agent that finds both files reads only `ledger.log`.
8. *Positions are sequence numbers.* The projection's checkpoint becomes the leaf's sequence number, where it was
   the entry's hash. A checkpoint not found in the history used to stop the projection silently, since
   `ops_for_catch_up` never got past it. It now projects from the start, and the run says so. The ops are `MERGE`s,
   so a second pass gives the same graph. That covers a graph whose checkpoint is an old hash after the copy.
   *For review.*
9. *A reader for people.* `polar-ledger`, a CLI in the credentials agent's crate, prints a ledger's entries as CBOR's
   diagnostic notation, with their kinds, versions, critical marks and writers. It verifies the frames and the tree,
   and with `--against <events.jsonl>` it checks the copy: every old event decodes to the same value. It is the
   operator's and the auditor's way to read the ledger now that it is binary.

*Tests:* the samples and the properties (1 to 5); replay with an unknown critical kind, an unknown non-critical kind,
a malformed event and a torn end; the hold, with no key loaded; the copy from a JSON ledger with every kind in it, and
again after a crash mid-copy; the lock; the projection from an unknown checkpoint. *Live, on u7c:* the agent copies
u7c's ledger (about 13,000 entries), with the time it took, and keeps serving. An image built with one event's critical
version raised past what the deployed agent knows makes the deployed agent hold. The way back is the newer image.
*Revised (the maintainer, 2026-11-11):* the hold is checked on a copy of u7c's ledger, not on u7c. Once an entry the
deployed build cannot read is in a ledger, only a build that can read it serves that ledger again, so the planned test
could be undone only by putting back a saved ledger, rewriting its history. Instead the deployed image's own binary is
started here against a copy holding one unknown critical entry, and must say the refusal and load no key.

*L1 built* (`credentials-agent/common/src/ledger.rs` and `tests/ledger.rs` with `tests/ledger-samples`;
`consume/src/ledger.rs`, `ledger_reader.rs` and the `polar-ledger` binary; `polar-log`'s `FileLog`). *Decided while
building, for review:*
- *Kinds* are named `credentials.<the variant in kebab case>`, at version 1. The v1 structs carry today's field names
  in today's order, indexed from 0.
- *An entry whose critical mark is not its kind's is malformed.* The mark goes with the kind and version. A writer
  that sets another has not followed this code's rule.
- *Every refusal holds under `HoldReason::Version`*: an unknown critical entry, a malformed one, a continuation that
  is not first, and a ledger damaged before its end. `Version`'s doc says what these share: what the agent keeps is not
  what this version can read. A restart helps none of them.
- *The refusal is decided before anything is spawned.* `PolarAgent::start` opens the ledger, copying the JSON ledger
  if need be, and on a refusal goes to `held::stay_up` with `held::never()`, the builder's agent that stays up to say
  why. So no key is loaded and nothing subscribes. The ledger actor opens the ledger again, so it is replayed twice at
  start; that keeps the actor's arguments as they were.
- *`FileLog::append_all`* appends many leaves and syncs once, so the copy is not one `fsync` per entry. A write that
  stops part way leaves a prefix, as for any append.
- *The copy* admits its first entry at the time of the copy, and every copied entry at the JSON ledger's time for it.
  Before anything is renamed, it checks that every event reads back as it was. Then the JSON ledger is made read-only:
  an older agent given the volume again cannot open it to append, so it cannot fork the history. It fails loudly
  instead, since released agents know none of this.
- *The projection's checkpoint* is `last_seq`. A graph holding only `last_hash` (the JSON ledger's) is projected once
  more from the start.
- *Tests that read the log as text* now read its events (`ledger::tests::events_in`). One of them,
  `instance_check`'s "only the attestation agent … is believed", checked that the file did *not* contain an event's
  name. It would have passed vacuously against a binary file, and now reads the events too.
- *`polar-ledger`* reads copies of both files, so it neither locks nor changes them. Its copy of a read-only JSON
  ledger is made writable for opening, as `EventLog` opens. CBOR's diagnostic notation needs minicbor's `half` feature.

*Live on u7c (2026-11-11, agentic-control-plane ae2c42fc):*
- *The copy.* The new credentials agent copied u7c's JSON ledger at its first start: 20,135 entries, 26.5 MB. The
  container started at 02:57:13 and the copy was done by 02:57:13.93, so the copy and the check that every event
  reads back took under a second. It then replayed 20,135 events and served. `events.jsonl` is mode 0400, and
  `ledger.log` was 21.2 MB. After the run all 27 pods were running, the credentials agent with no restart.
- *Checked against its source.* `polar-ledger ledger.log --against events.jsonl`, on copies taken from the pod: 20,330
  entries by then, with the tree root printed. It found "the copy holds the JSON ledger's 20135 entries, as they were
  and when they were", and nothing that did not hold, in 1.5 seconds.
- *The projection.* Neo4j was still starting for the agent's first 16 seconds. Once it answered, the graph's
  checkpoint read `last_seq` 20,329, the last event, beside the old `last_hash`. So the graph was projected over the
  new ledger without being told.
- *The hold, on a copy.* The deployed image's own binary (`credentials-agent-consumer`, from its digest) was started
  here against a copy of u7c's ledger with one entry added: `credentials.something-new` v1, critical, written by
  "9.0.0". It said: "credentials-agent cannot start its work, and stays up to say so (a restart would not help): the
  ledger holds credentials.something-new v1 (entry 20330), written by 9.0.0 x86_64-unknown-linux-musl, which this
  agent (3.0.0+dev x86_64-unknown-linux-musl) cannot read: it serves nothing until a version that can is deployed".
  It ran only its infrastructure (`credentials-agent.held`), its health file said unhealthy, and no key file was
  written. It stayed up until it was stopped after 25 seconds. The copies were deleted afterwards.
- *Found:* `polar-ledger` prints a certificate's PEM with its line breaks, so an entry holding one spans several lines.
  It is cosmetic, and left as it is.

**L2, checkpoints: the plan (2026-11-12, cleared by the maintainer the same day, as written).** Read for it: `authority_certificate.rs`,
`authority_key.rs`, `polar-signing/src/verify.rs` (`verify_authority_certificate`, `believed_leaf`,
`for_signing_documents`), cert-issuer's `CertType`, `ca.rs` (the usages by type) and `handler.rs` (steps 1.2 and 1.5),
`polar-log`'s `checkpoint.rs`, and the store's `logs.rs` (its key and its kept checkpoint).

*Found in reading:* the authority key's certificate is a `Signing` one, and `verify_authority_certificate` asks only
for `id-kp-documentSigning`, no TLS purpose, and the agent's name. A ledger key certified the same way would pass it,
so it could sign snapshots a leaf believes. One key, one purpose needs a certificate that says the purpose.
*Decided (the maintainer, 2026-11-12):* a certificate type of its own.

1. *A checkpoint certificate.* cert-issuer gains `CertType::Checkpoint`. Its key usage is `digitalSignature`, and its
   one extended key usage is `id-polar-kp-logCheckpoint`, `2.25.214751505132549872223803780954079323746.1`. That is an
   X.667 UUID OID (`a18fa2ab-c873-451d-bff8-a0d22b3b6662`), which needs no registration. Polar allocates under it, so a
   witness's co-signing key can later be `.2`. The type is signed only on `/internal/issue`, and only for the caller's
   own identity, as steps 1.2 and 1.5 do for `Signing`. Later, the store's key takes the same type, for a pod, on its
   custodian's behalf. The name in the certificate says whose log it is.
2. *Its check.* `polar_signing::verify_checkpoint_certificate(chain, trust, now, identity)` is `believed_leaf`
   with this purpose: `digitalSignature`, and the checkpoint usage, with no TLS purpose and no document signing. It
   gives back the P-256 key. The checks that already exist require document signing, so they refuse a checkpoint
   certificate, and this one refuses theirs. A test checks both directions for every type.
3. *The certificates-reported event goes to v2.* `ReportedCertificate` carries a `CertType`, which gains a value. v1
   stays as written and is read as before. The writer writes v2, so an L1 agent meets an unknown critical version and
   holds with its plain line, instead of finding the entry malformed. v2's sample is recorded, and the samples test
   covers both versions.
4. *The key.* P-256, at `CREDENTIALS_LEDGER_KEY_PATH` (`WriteFile`, default
   `/var/lib/credentials-agent/ledger-key.pem`), mode 0600. It is made at first start and never replaced, as the
   authority key is (`authority_key::load_or_generate`). It is loaded after the ledger has opened without a refusal,
   so a held agent still loads no key. It is named `<identity>/checkpoint`, as the store names its own key. The
   checkpoint's origin is `<identity>/ledger`.
5. *Certified as the other keys are.* The certifier that renews the authority and escrow keys certifies it at half
   its life, and tries again while cert-issuer cannot answer. It gives the certificate to the ledger actor, not to the
   publisher. The latest certificate is kept beside the key in `ledger-key.crt` (written to a new file, synced, and
   renamed over). A checkpoint needs no certificate to be signed; the certificate is for whoever checks it.
6. *Checkpoints.* The ledger actor signs one when it opens the ledger, and at most once a second while entries are
   appended (a tick after an append, as the store does). It keeps only the latest, in `ledger.checkpoint` beside the
   ledger: written to a new file, synced, renamed over, then the directory synced. The copy from the JSON ledger is
   followed by the first one. An L1 ledger with no checkpoint gets one at start, and the run says so.
7. *A rolled-back ledger is refused.* At open, the kept checkpoint must verify under the ledger key, and its tree must
   be the ledger's own tree at its size, by a consistency proof. A ledger shorter than its checkpoint is refused, and
   so is one whose tree at that size differs. That catches a restored older copy, which would forget revocations made
   since. The refusal holds under `HoldReason::Version`, as L1's damaged ledger does: what the agent keeps is not what
   it signed. A kept checkpoint that the key does not verify is refused too. Its way back is a person removing the
   file, deliberately. *For review.*
8. *`polar-ledger` checks them.* Given `--ca`, it prints the kept checkpoint and verifies four things:
   - its signature, under the key in `ledger-key.crt`;
   - that certificate, as a checkpoint certificate of the credentials agent, chaining to the CA, as of now (or
     `--at <unix seconds>` for an old copy; the certificates last an hour);
   - the ledger's tree at the checkpoint's size;
   - with `--since <older checkpoint>`, the consistency proof from it.

   *For review:* the certificate is checked as of a time the reader chooses, since a checkpoint carries none.

*Tests:*
- cert-issuer signs a checkpoint certificate only on `/internal/issue`, and only for the caller's own identity.
- Each check refuses each other type's certificate, as a property over the types.
- The v2 sample, with v1 still read.
- The key is made once and kept across a restart. A held agent makes no key.
- Many appends in a second make one checkpoint, and an open makes one.
- The kept checkpoint survives a restart.
- The hold is checked three ways: a shorter ledger, another tree at the same size, and a checkpoint under another key.
- `polar-ledger` verifies a good checkpoint, and refuses a changed root, another key, and a certificate of another type.

*Live, on u7c:*
- After the deploy, cert-issuer signs the ledger key's checkpoint certificate.
- `ledger.checkpoint` follows the appends.
- After the pod is replaced, the key is the same.
- `polar-ledger` verifies copies taken from the pod against the CA.
- The rollback hold is checked as L1's was: the deployed binary, started here against an older copy of u7c's ledger
  beside its newer checkpoint.

*L2 built* (cert-issuer's `CertType::Checkpoint`; `polar_signing::verify_checkpoint_certificate`; the ledger's
`certificates-reported` v2; `consume/src/ledger_checkpoint.rs`, the ledger actor and `polar-ledger`). *Decided while
building, for review:*
- *The OID is written by hand.* Its arc is 128 bits wide, and rcgen writes OID arcs as `u64`, so cert-issuer writes the
  extended key usage extension whole (`cert_issuer_common::log_checkpoint_extended_key_usage`), and the check compares
  the OID's bytes. *Found:* Go's `crypto/x509` refuses to parse any certificate whose extended key usage has an arc
  over 31 bits (`cryptobyte`'s `readBase128Int`, read in Go 1.26's source), so no Go tool can read a checkpoint
  certificate. Polar's code, rustls and OpenSSL can. The certificates last hours, so moving to another arc (a
  registered enterprise number) costs one constant and a renewal.
- *cert-issuer signs a checkpoint certificate* only on `/internal/issue`, only for the caller's own identity, with no
  instance binding and no other name (a name beside its own is `InvalidCsr`), for the server lifetime, as the
  authority key's is. It is refused on `/issue` whatever the floor says.
- *Version 1 of `certificates-reported` holding a checkpoint certificate is malformed*: version 1 never had that value.
  The copy from a JSON ledger now writes each event at its kind's current version, so a reported certificate is
  copied at version 2; the copy's check that every event reads back as it was is unchanged.
- *The rollback check computes the tree at the checkpoint's size from the ledger itself*, rather than taking a
  consistency proof: the agent holds every leaf, so this checks the same and more.
- *A checkpoint kept whose key is gone* is refused, and no key is made in its place. A version hold still reads no
  key; a rollback hold reads the ledger key, to check the checkpoint, and signs nothing.
- *The agent's start reads its own certificate* before it opens the ledger, since the checkpoint's origin names it. An
  unreadable certificate is an error at start, as it was in the supervisor, not a hold.
- *The certifier is told whom to give each certificate* (`authority_certificate::Certified`): the publisher, for the
  authority and escrow keys; the ledger, for its key. `ledger-key.crt` holds the certificate alone; the CA is the one
  every pod pins.
- *A checkpoint that cannot be kept* is said as an error and tried again a second later; the ledger itself is whole.
- *`polar-ledger` takes the identity from the checkpoint*: its origin is `<identity>/ledger`, and the certificate must
  be that identity's checkpoint certificate.
- *Found, L1's:* `polar-ledger` was built without declaring Scudo as its allocator, which `polar-scudo`'s
  `every_binary` test refuses. L1's test runs did not catch it; L2's whole-workspace run did. It declares Scudo now.
  Cargo stops at the first failing test binary unless told not to, so the workspace is run with `--no-fail-fast`.

*Live on u7c (2026-11-12, agentic-control-plane 09532662, the deployment Flux applied as `fba7c24`):*
- *The key and its certificate.* At its first start the new agent made the ledger key (mode 0600) and signed the
  ledger's first checkpoint, at 21,525 entries ("the ledger had no checkpoint kept; signed its first"). The certifier
  then had it certified as `cert_type=Checkpoint`, renewed in 6 hours, and the ledger kept the certificate in
  `ledger-key.crt`. OpenSSL reads it: digital signature, the one extended key usage
  `2.25.214751505132549872223803780954079323746.1`, the agent's DNS name, 12 hours.
- *Checkpoints follow the appends.* Two minutes later the kept checkpoint was at 21,682 entries, the ledger's size.
  `polar-ledger --ca`, on copies taken from the pod with the CA the pods pin, found it signed by
  `credentials-agent.polar.serviceaccount.cluster.local/checkpoint`, certified for that identity's checkpoints alone,
  over the ledger's own tree, in half a second. Entries of `credentials.certificates-reported` are now written at v2.
- *After the pod was replaced*, the certified key was the same (its public key's digest unchanged), and the kept
  checkpoint already matched the ledger, so nothing was signed at the start. It then followed the ledger to 21,687,
  and `polar-ledger --since` the first copy's checkpoint found the two consistent. Checked as of a time after the
  certificate's end (`--at`), the certificate is refused.
- *The hold, on copies.* The deployed image's own binary (`credentials-agent-consumer`, from its digest) was started
  here against the older copy of u7c's ledger (21,682 entries) beside a checkpoint of the newer copy (21,687). That
  checkpoint was signed with a throwaway key written beside it, so u7c's own ledger key never left the pod. It said:
  "credentials-agent cannot start its work, and stays up to say so (a restart would not help): the ledger holds 21682
  entries, and its last checkpoint was signed at 21687: it is not the ledger this agent signed (an older copy put
  back?), and it serves nothing until the ledger it signed is put back, or a person removes …/ledger.checkpoint to
  accept the ledger as it is". It ran its held infrastructure only, its health file said unhealthy under `version`,
  and the checkpoint was left as it was. With the newer copy put back, the same binary replayed 21,686 events and
  started its work. The copies were deleted afterwards. After the run all 27 pods were running, none restarted.
- *Found:* a certificate refused as out of date is named by its subject's common name, and these certificates have
  none, so the line reads "the certificate for `` is not valid at the time of checking". It is cosmetic, and left as
  it is.

**L3, checkpoints into the store: the plan (2026-11-12, for the maintainer to clear).** Read for it: the store's
`logs.rs` (logs made at their first append, `AppendOnce`, `governing_repo`), `evidence.rs` (the intake: a sender the
broker stamped, answered on a topic named for it), `witness.rs` and bite 5's plan above (the store submitting its
checkpoints), `log_read.rs` and `http.rs` (who reads a log), `polar_git_server_common` (the wire types and topics), and
the credentials agent's `revocation_evidence.rs`, which already sends the store records over Cassini.

*The shape:* the ledger submits its checkpoints to the store as the store submits its own to the witness. The store
holds, for each ledger, the last checkpoint it admitted, and takes a new one only when it follows on from it. So the
store refuses a rewritten ledger, and its own checkpoints and the witness cover what it admitted.

1. *A `ledger` log in the store*, made at its first entry, as every log is. Its entries are of the kind
   `ledger-checkpoint`, version 1, critical. The event is a fixed CBOR map, written by hand as the envelope is:
   `0` the signed note, `1` the ledger key's certificate (PEM). It is witnessed as every log is. It is served, as
   tiles and over Cassini, to whoever may read `polar-evidence` (`governing_repo`): a checkpoint says nothing secret,
   and it is evidence about the credentials agent. *For review.*
2. *The request.* On `polar-ledger-checkpoint-requests`, the agent sends
   `AddLedgerCheckpoint { old, proof, checkpoint, certificate }`: the size it believes the store last admitted, the
   consistency proof from there, its signed checkpoint, and its key's certificate. It is answered on
   `polar-ledger-checkpoint-replies.<workload>`, with the request's correlation ID. The types live in
   `polar_git_server_common`, in rkyv, in the shared envelope, as the evidence intake's do.
3. *Admission*, in order, refusing at the first that fails:
   - the sender is one the broker stamped;
   - the certificate is a checkpoint certificate of that sender's identity, under the CA the store trusts, now
     (`verify_checkpoint_certificate`);
   - the note opens under the key it certifies;
   - its origin is `<the sender's identity>/ledger`;
   - it follows on from the last checkpoint the store admitted of that origin: `old` is that checkpoint's size, and
     the proof holds from its root to the new one. The first of an origin is taken whole, and the store pins it.

   An admitted checkpoint is appended as an entry, and the sender is its submitter. The last admitted checkpoint of
   each origin is read from the log when the store starts; there is no second record of it.
4. *The answers:* `Admitted { size }`; `Conflict { size }`, when `old` is not the size the store admitted last, and
   the agent sends again from that size; `Refused { why }`; and `NotNow { why }`, when the log does not take it.
   A checkpoint the store holds already is `Admitted`, so an answer that was lost costs nothing.
5. *What the agent does.* A `LedgerSubmitter` actor sends the ledger's latest checkpoint once the agent has
   started, and then at most once a minute while it grows. It asks the ledger actor for the checkpoint and the proof,
   as the store's witness client asks its logs. It starts from `old = 0`, so the store's first answer to a new agent is
   a `Conflict` naming the size it holds. A minute bounds what a rewrite could take away before the store saw it; a
   second, the ledger's own cadence, would put up to 86,400 entries a day in the store. *For review.*
   - On `Admitted`, it is said at debug.
   - On `Conflict`, it sends again at once, from the store's size.
   - On `NotNow`, or no answer, it is said once per outage and tried again at the next minute.
   - A refusal because the ledger does not follow on from what the store admitted is said as an error every time. The
     agent keeps serving. This is as the store does when the witness refuses its proof (bite 5), and stopping would let
     a store that misbehaves shut down the credentials agent. *For review.*
   - The agent's catalog entry gains the request topic to publish and its replies topic to subscribe, and the store's
     gains the reverse.
6. *A reader for an auditor.* `polar-eden fetch-log` mirrors the `ledger` log as it mirrors the others, held to both
   keys. `polar-ledger --against-store <mirror> --log-key <the store's key> --witness-key <the witness's>` reads the
   mirror (`polar_log::tiles`), takes the last checkpoint the store admitted of the ledger's origin, and checks that
   the ledger on the volume follows on from it.

*Open, decided to come later (the maintainer, 2026-11-12):* a person who accepts an older ledger (L2's way back,
removing `ledger.checkpoint`) is then refused by the store at every submission, since the store's log keeps the
history it admitted. Accepting it there takes an administrator's signed "new start" for that origin, appended to the
`ledger` log, after which the next checkpoint is taken whole. That is a bite of its own. Until it is built, such a
ledger is refused and said.

*Tests first:*
- Admission refuses another sender's checkpoint, a certificate of another type or identity, a note the certified key
  did not sign, another origin, and a proof that does not hold. It takes the first whole, and the same one twice.
- `Conflict` and the resend from the store's size.
- After a restart, the store's last admitted checkpoint is read from the log.
- The submitter's cadence, and its outage said once.
- `polar-ledger --against-store` takes a ledger that follows on, and refuses one rewritten behind what was admitted.
- Properties: the store admits a checkpoint exactly when it follows on from the last one admitted of its origin; for
  any sequence of submissions, the admitted checkpoints of an origin are each consistent with the one before.

*Live, on u7c:*
- The store's first admitted checkpoint, and a minute later the next.
- The `ledger` log co-signed by the witness.
- `polar-eden fetch-log` of it, and `polar-ledger --against-store` on copies.
- The refusal, on copies. Only the credentials agent can send as itself, so a test client sending to u7c's store
  would be refused for who it is, before its checkpoint is looked at. Instead, the deployed commit's admission is run
  here against a copy of the store's `ledger` log and an older copy of u7c's ledger, signed with a throwaway key
  certified as in the tests. It must say the checkpoint does not follow on, and append nothing.

## Built

**Bite 1, the format crate (`src/agents/polar-log`, 2026-11-10).** Choices made in building, by the design principles,
*for review*:
- *CBOR by hand, strictly* (`cbor.rs`): the envelope, the leaf and the continuation are a few fixed maps, so a small
  encoder and a decoder that takes only the deterministic form (shortest heads, definite lengths, keys 0 to n-1 in
  order, nothing left over, no length beyond the bytes there) replace a general crate, which would also read the
  non-canonical forms of the same value. The writers of events (the credentials ledger) choose their own encoder.
- *The Merkle tree of our own* (`merkle.rs`), RFC 9162's definitions and its verification algorithms step for step,
  held to the shared RFC 6962 test vectors (the roots of the eight-leaf tree) and by properties to a second
  construction and to every proof of every leaf of every size below 70, rather than the `tlog_tiles` crate.
- *Signed notes with type 0x02* (`checkpoint.rs`), as transparency-dev's `formats/note` makes them (read 2026-11-10;
  the C2SP page leaves the ECDSA details to it): DER over SHA-256 of the note text, the key ID the first four bytes
  of SHA-256 of the DER SPKI. Checkpoints with extension lines are neither written nor read.
- *The file log in frames, not tiles* (`file.rs`): length, a check of the length, the leaf, its leaf hash. The check
  is what keeps a damaged length from passing for a write that stopped (found by writing the property that a byte
  changed anywhere refuses the log); a frame cut short at the end is cut back and said. A leaf up to 64 MiB.
- Its properties: one encoding for each value and every decoded byte string is that encoding; proofs hold for their
  tree and fail for any changed leaf, index, path, older tree or root; a cut anywhere leaves a prefix and appending
  goes on; a byte changed anywhere in a whole frame refuses the log and cuts nothing.

**Bite 2, logs in the store (`polar-git-server/server/src/logs.rs`, 2026-11-10).** *For review:*
- *Frames, not tiles, on the store's volume too*: one file per log (`<name>.log` under `POLAR_GIT_SERVER_LOG_ROOT`,
  `/var/lib/<workload>/logs` on the persistent claim, `/repos/logs` for the bootstrap server), replayed at start. A
  reader fetches entries and proofs from the store over Cassini (bite 3's reads), not tiles over HTTP, so tiles wait
  for a reader that needs them (a mirror, a witness off the cluster); the frame layout converts to them without loss.
- *A log with a malformed leaf is refused when it opens*, and the store does not start: a leaf the store wrote that no
  longer decodes is damage, never passed over.
- *The checkpoint key is the store's own, made once* (`checkpoint-key.pem` beside the logs, 0600, never replaced),
  named `<origin>/checkpoint`, the origin being the server's identity from its certificate. **Not yet certified**:
  the credentials agent is to certify it (decision 5); until it does, a witness pins the key's verifier line by hand
  (`VerifierKey`).
- *Each entry once*: the store keeps a digest of every entry it holds, and an entry sent again is answered with its
  first sequence; a sender whose answer was lost resends without making a second leaf.
- *A checkpoint at each request*, not at most once a second: there is one writer and no reader yet asks often; the
  cadence comes with the witness (bite 5, planned above: at most once a second).

**Bite 3, evidence on the log (begun, 2026-11-10).** The intake appends each admitted record to the `evidence` log, as
an `evidence-record` entry (version 1, critical; the signed document as its sender sent it), **before** it commits it
to `polar-evidence`; a record the log does not take is answered "not now", and nothing is committed. *For review:*
- *Both, not instead*: the design's bite says the intake appends instead of committing. Until polar-eden reads the log
  (bite 4) and the git face exists, every reader reads the repository, so the repository is still written, after the
  log, and the log is what a reader will move to. When the git face serves `polar-evidence`, the commit goes.
- *A crash between the two* leaves the record in the log and not the repository; the sender, unanswered, resends, the
  log finds it held, and the commit is made. The repository can lag the log, never lead it.
- *The log's time never goes back*: a leaf is admitted at the later of the clock and the last leaf's time, so a clock
  stepped back cannot put an entry "before" one already there, and "as of" a time is always a prefix of the log.

**The log's face for people (bite 3, 2026-11-10).** People read a log through the store's mTLS interface (decision 7's
path for people, as `polar-sign` will write through it), and polar-eden is a person's tool, so the first read face is
that one, not Cassini: the log as **C2SP tlog-tiles** (`polar_log::tiles`, the spec read 2026-11-10) at
`/logs/<log>/checkpoint` and `/logs/<log>/tile/...`. A reader fetches the checkpoint, opens it with the store's pinned
verifier key, fetches the entry bundles, and `read_log` gives back the leaves only when they make the checkpoint's root:
what was fetched is the log the store signed, wherever it came from, so a mirror is a directory of these files.
Reads over Cassini come with the first workload that reads a log's entries, with reply topics named for it, as every
reader's are: a monitor, not the witness, which is brought checkpoints and reads no entries (bite 5's plan). *For review:*
- *Who reads a log*: the readers of the repository it replaces (`evidence` → `polar-evidence`;
  `polar_git_server::logs::governing_repo`); no other log is served yet. A log holds what its repository held, so the
  same people read it.
- *A leaf is at most 65,535 bytes in the store*: a bundle carries an entry after a two-byte length, and every log is
  served as tiles, so the store refuses a longer leaf when it is appended, never one it holds and cannot serve. An
  evidence record is a few kilobytes. A deployment's pack can be larger, so bite 7 puts the pack's bytes in the store as
  a content-addressed blob and the entry names it (as large evidence bodies are kept: `agentic-control-plane.md`,
  "Evidence registry"), rather than widening the format. The file log's own bound (64 MiB) is for an agent's ledger,
  which is not served as tiles.
- *Tiles are computed from the leaf hashes held in memory*, not kept as files: the frame file stays the one copy. A tile
  above level 0 costs the hashing of everything under it, which is nothing at today's sizes; tiles are cached when a
  log grows past where that shows.
- *The checkpoint's origin is the store's identity and the log's name* (`<identity>/<log>`), not its URL prefix as the
  spec suggests (a SHOULD): the store is reached by several names (the Service, a forward), and its identity is the one
  that does not change.
- *A full tile is sent as immutable, and private*: what a tile holds never changes, but reading it was authorized, so
  no shared cache keeps it.

**Pushes to the log (2026-11-11, ahead of bite 9).** Reading the log in place of the checkout would have missed every
record a person pushes with git (polar-eden's own signed runs among them), so a push to `polar-evidence` now feeds the
log too: once nothing else refuses the push (its commits' times, here), each `*.json` file outside a hidden folder that
a ref's new tip holds and its old tip did not hold with those bytes is appended to the `evidence` log as the pusher's,
before any ref moves (`evidence::pushed_records`, in the push's judge); a record the log does not take refuses the
push. So the log holds every record the repository holds, and leads it if anything. *For review:*
- *The log takes what the repository takes, no more checked*: the evidence admission rules (verify in the evidence
  domain, then policy) are applied to a push's records in bite 9, when pushes become appends and the repository a face.
  Until then reading the log is never weaker than reading the checkout, which took the same records, and polar-eden
  judges each as it did.
- *A record is its bytes*: the same bytes pushed at two paths are one entry, as the intake's records are named by their
  digest. A checkout read now agrees (2026-11-11, polar-eden.md, "A record added again counts once"): the same record
  at two paths counts once, as of its first addition.

**Bite 4, polar-eden reads the log (2026-11-10).** `polar-eden records --evidence-log` (polar-eden.md, "The store's
log"). *For review:*
- *A mirror directory, not a connection*: polar-eden reads the files the store serves, from wherever they were put, and
  believes them only as far as the checkpoint and the remembered one carry. `polar-eden fetch-log --from
  https://<store>/logs/evidence --out <mirror> --user <you>` fills it (`polar_log::tiles::mirror`): the checkpoint opened
  with the pinned key, the bundles it lacks fetched (a full one it holds is never fetched again), nothing written unless
  they make the signed root, the checkpoint written last. It presents the person's certificate as polar-sign and
  polar-git-push do (`<user>.crt`, `<user>.key` and the store's `ca.pem` in `~/.config/polar-admin`), following them.
- *The remembered checkpoint is per store key*, so two stores' logs are never held to each other's, and is written only
  after the whole log was read and found to be the one before, grown.
- *A log that is not the one read before stops the read*, with nothing judged: a rewritten log is the store's failure
  (or another log), not a record's, and a reader that judged the rest would be judging the rewriter's choice of rest.
- *Seconds, not milliseconds*: a record is verified as of its admission time floored to the second, as certificates'
  times are kept.

**Live on u7c (2026-11-11, agentic-control-plane 49f9221a).** The git server opened its logs at
`/var/lib/polar-git-server/logs` on its claim, its key named `polar-git-server.polar.serviceaccount.cluster.local/checkpoint`
from its certificate. The attestation agent's verdict, sent over Cassini, was admitted to the evidence log (and
committed to `polar-evidence`). `polar-eden fetch-log` as djshepard, through the local forward by the Service's name
(`--resolve polar-git-server.polar.svc.cluster.local:8443:127.0.0.1`, curl's form, as `seed.nu` and `browser.nu` reach
it), fetched it as tiles, and `records --evidence-log` verified it as of its admission, at
`polar-git-server.polar.serviceaccount.cluster.local/evidence#000000000000`. After the pod was deleted and replaced, the
key was the same, the log the same, and the read held to the checkpoint remembered before it.

**A person's push, live (2026-11-11, agentic-control-plane 21d8c34a, every agent under the builder's seccomp lock).**
`polar-eden collect --package polar-version --sign --push` as djshepard pushed a signed `polar-eden-run` to
`polar-evidence` through the forward; it was the log's fourth leaf, after three of the attestation agent's verdicts.
The store's key was the same across the redeploy, and the read held to the checkpoint remembered from the day before.
`records --evidence-log --schedules` verified all four; without `--schedules`, the run is refused ("djshepard may not
sign evidence of `polar-eden-run` … or the certificate"), as it and every earlier run of theirs is when the checkout is
read the same way: their certificate does not name the type, and the policy does. The log and the checkout agree.

**Bite 5, the co-signature in polar-log (2026-11-11).** `polar_log::checkpoint::Cosigner` signs a checkpoint's text at a
time as the plan says (`cosignature/v1`, `time <T>`, the text; the line the key ID, T and the DER signature; the type
`COSIGNATURE_TYPE`, `0xff` and `polar.dev/cosignature/p256/v1`; the key ID `cosigner_key_id`). A verifier key of that type
reads as a co-signer's, and `open_signed` checks each trusted key over its own message and gives each co-signer's T;
`open` is as it was. Requiring both keys, and the reader's minute, are the readers'. Its tests hold the message to
C2SP's by checking the signature over it directly; a property holds a co-signature to its checkpoint and time.

**Bite 5, the store's side and the readers (2026-11-11).** As planned above. `Logs` keeps each log's latest co-signed
checkpoint in `<log>.cosigned` beside it (a new file, synced, renamed over, the directory synced) and serves only that at
`/logs/<log>/checkpoint`, "the log is not yet witnessed" (503) before the first; `Logs::open` refuses a kept checkpoint
that is not the store's of the log beside it, as a malformed leaf is refused. `witness::WitnessActor` follows
`POLAR_GIT_SERVER_WITNESS_KEY` (Dynamic), ticks at once and then each second, submits each log that grew on
`attestation-witness-requests`, and takes the answers on `attestation-witness-replies.polar-git-server` only from the
identity the key names (`<identity>/witness`). The readers are polar-eden's (polar-eden.md, "The witness's co-signature,
required"), through `polar_log::tiles::mirror`, which now takes both keys. *For review:*
- *A pinned key that is not a co-signer's is refused*, by the client and by `keep_cosigned`, so a key of the
  checkpoint's type can never stand in for the witness.
- *An answer must name the checkpoint submitted* (origin and size) as well as its correlation ID; one about anything
  else is dropped, said at debug.
- *Which log line is said*, once per outage or each time, is not held by tests: the mutants that change only that
  (the once-said flags, the rollback line after a retry) are left, the state they keep (`Witnessing::away`) is tested.
- *Until both keys are pinned in each other* (up.nu, decided above, polar-89's to write with this session), a store
  deployed with this serves no checkpoint: `fetch-log` answers "not yet witnessed".

**Bite 5, live on u7c (2026-11-11, agentic-control-plane 4af66add; polar-89's run, its notes in
`runtime-attestation.md`).** The seed signed both pins and each agent took its own. The store submitted the evidence log
(13 leaves) from 0 and kept the witness's co-signature; `polar-eden fetch-log` with both keys fetched the checkpoint
carrying both signatures and held it to the one remembered from the day before. After the attestation agent's pod was
replaced, the witness had the same key and still held 13, and co-signed 14, which `fetch-log` read. The store's witness
client said one warning, before the pins (no witness key yet), and nothing after.

**Bite 6, schedules on the log (2026-11-11).** As planned above:
- `polar_git_server_common::schedules` holds the entries, the tree and the replay.
- The store appends at a push and at its start (`schedules.rs`), and answers reads over Cassini (`log_read.rs`).
- The scheduler observer's sync actor reads the log, held to its keys, into the checkout as before.
- `polar-eden records --schedules-log` reads the policy's history from a mirror of the log.
- up.nu's seed pins both keys in the observer.

*Found in building, for review:*
- *On a fresh cluster the store's witness pin reaches it only through the observer*, and the log can be witnessed only
  once the store has that pin. If readers saw only the witnessed log, nothing would ever be delivered. So until the
  witness has ever co-signed a log, the store answers a read of it with its own checkpoint, marked so
  (`LogRead::Entries { witnessed: false }`). An observer with no keys writes that as the store's word, as `main` was
  before the log. An observer with keys takes nothing unwitnessed. Once a log has been co-signed, the kept checkpoint
  outlives the store's restarts (bite 5), and this path is not taken again.
- *What is left:* an observer that has just started holds no keys until its settings arrive. A store that hides that
  it was ever witnessed (by losing its `.cosigned` file) is believed by such an observer until the keys arrive, as
  `main` was believed before. The witness, which holds its own size, would refuse that store's next checkpoint.
- *The observer's own settings are handed on from every answer*, whether or not it verified. An administrator signs
  them and the configuration actor verifies them, so the store cannot put keys of its own there. This is also what lets
  a pin that changes (a witness's new key) reach an observer whose old keys no longer verify the log.
- *Only `main`* is the log's: a push to another branch of polar-schedules appends nothing, since nothing reads one.
- *A push that fails after the log took it* (the refs not written) leaves the log ahead of `main` until the store
  restarts; the start then appends what makes it `main` again.
- The pushed tree is compared with the log's tree, so a push sent again appends nothing.
- *The evidence log's remembered checkpoint keeps its file*; the schedules log's is beside it, its name ending in
  `.schedules`.
- *The deployment record* is still read from `main` (bite 7).

**Bite 6, live on u7c (2026-11-11, agentic-control-plane 7501f3d8).**
- *At the store's start*, the schedules log was brought to polar-schedules' `main` (commit `7244654`): 19 leaves, the
  continuation and 18 files, appended as the store's own.
- *Before the pins*, the observer had no keys and the log had never been witnessed. It wrote the 19 leaves as the
  store's word, as planned, and the credentials agent applied and published its policy from them.
- *The seed's push*: the seed left the store's and the witness's pins as they were and pinned the observer (leaf 20).
  The witness then co-signed the log, the first time it had co-signed this one.
- *The observer's own settings*: it took them from the witnessed log and handed them on, and its configuration actor
  applied both keys. It then checked the 20 leaves against the checkpoint and wrote them.
- *A person's signed change*: a settings version for kube-observer, pushed with git as djshepard, reached the agent
  through the log in under a second:
  - pushed at 17:17:23.17;
  - co-signed at size 21 (`polar-log-witnessed`) at 23.95;
  - written by the observer, checked against both keys, at 23.99;
  - applied by kube-observer at 24.00.
- *After the observer's pod was replaced*, it held its keys and had written 21 checked leaves within 50 ms of its first
  read.
- *polar-eden*: `fetch-log` fetched both logs with both keys (schedules 20 leaves, evidence 18). `records
  --evidence-log --schedules-log` judged the 18 records by the policy from the log: all verified.
- *The witness* logged no warning, refusal, 404 or 422. Its ready line counts the origins it held at start (1, the
  evidence log), and nothing is logged when it takes up a new one.
- *A warning that misled*: right after the observer handed on its own settings, it warned that it held no keys, while
  the keys were already on their way. It now says, at info, that it will read again once they are in force.

*Mutants, after the tests they found:* all caught in the schedules tree and in polar-eden's history from the log. Those
left change only what is logged (the observer's once-said and handed-on lines, the witness client's "co-signs again"
line) or are older code that moved: the observer's first-read backoff, the tile fetch's NotFound guard in
`verified_leaves`, and `files_of`'s size bound.

## Attestation verdicts as records

*Decided (the maintainer, 2026-11-09; built 2026-11-10 on the agentic-control-plane branch, on main 2026-11-13).* The
attestation agent's verdicts lived only in its logs and in other agents' state: a refusal and an unattested issuance in
the credentials agent's ledger, a finding as an `AttestationReported` there, a lasting drift as an ERROR line. None was
evidence a claim could bind. So:

1. **The attestation agent signs its own records,** in the evidence domain, with a key of its own per pod, never
   escrowed, under a signing certificate carrying `c:record-evidence:attestation-report,attestation`
   (`key-custody.md`, "Workload signing keys"). On main it signs through its crypto actor (`SignRecord`).
2. **Two kinds of record.** `attestation-report`, one for each finding as it is published on `attestation-reports` (an
   alteration, a crash by a signal, a panic: a container that exits 101), with `under_test`. And `attestation`, the
   cluster's standing, subject `target=<the deployment record's target>`, three verdicts by id with their witnesses:
   `agent-proved-itself`, `pods-genuine`, `deployments-match-record`. Written whenever a verdict changes, and once a day
   regardless, so a reader sees it is fresh (`attestation/agent/src/evidence.rs`).
3. **They reach `polar-evidence` through the git server, over Cassini** (`git-server.md`, "Inside the boundary"): no
   agent pushes with `git`. The builder's recorder (`polar-agent-builder/src/recorder.rs`) sends them one at a time and
   in order, keeps one the server cannot take now and sends it again, at most 1000 kept; one refused for good, or past
   the bound, is said at ERROR, never lost silently. A finding before a deployment record is held waits for the
   record's target, within the bound.

A crash still shown in a pod's status is found again after the agent restarts, and recorded again (a signature differs
each time, so the file does too); a reader tells them apart by the pod's UID, the container and when it ended.

## What a rollback needs

Moving a repository in is forward only. Code from before the store, finding the old repository kept beside the log, would
serve it as it stood at the move and miss everything appended since (a revocation among it); and an old polar-git-server
makes a repository its configuration names when it is missing. So the old repository is kept under a name no old code
opens, and a rollback past the move is a copy back, out of the log, not a downgrade of the image. The credentials ledger
has the same hazard with its old `events.jsonl`, and polar-89's ledger work makes old code refuse plainly.

## Open

- The retention of anything: none is proposed; every entry is kept, and a blob no entry names may be collected.
- The deployer itself is unvetted; decision 11 is what the store promises it.
- How a site's git is kept in step with the store in degraded mode (the store pushes, or the site pulls).
- Reads of a log over Cassini: built with bite 6, the scheduler observer the first workload to read one; a monitor
  will use the same reads, and none is planned yet.
