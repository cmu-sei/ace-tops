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

# to-main — Claude's side

PAIR: `to-main.md` (people). Same plan, two forms; change together.
SPLIT: people side has no dates, attributions, quotes, codenames or branch/process status; those live here.
PARENT: `../record-store.claude.md`. Branch store-to-main, rebased on ace-remote/main 7e43bb92 (2026-11-13); taken by
polar-89 (current session name polar-f1) after review against main, then to the maintainer to clear.
STATUS: DONE 2026-11-14. Cleared by the maintainer 2026-11-13 ("Cleared; build it"); B1–B5 on main ffabeec5, live on u7c
(polar-f1 2026-11-14: 25 pods Running, no agent refuses its configuration). Was: PROPOSAL 2026-11-13, reviewed ready by polar-f1.
FLOW per bite: polar-cc prepares, polar-f1 (polar-89's current session) takes. On a branch from main (≥ 7e43bb92; tests pass there, capped: systemd-run
MemoryMax=24G) → polar-89 takes onto main → deploys u7c (up.nu sandbox-local --dev, no --under-test gitlab) → next.

## DECIDED (maintainer, 2026-11-13, via the coordinator)
- D1 polar-git (source-code server) + git-remote-polar MOVE to main: bite B5, after B4.
- D2 .elide.dhall intents and polar-eden STAY on acp.
- D3 checkpoint key: "a file now, custody later". Port as is (key file on the store's volume, certified by the
  credentials agent); move to a named, escrowed custody key when main's trusted-remotes step 3 lands.
- D4 polar-89's three conditions, all met below: (1) every bite based on main ≥ 7e43bb92 (K3b changed git-server
  tls.rs/settings.rs/supervisor.rs; server keys TLS_SERVER_CERT_CHAIN/TLS_SERVER_KEY declared by `keys`);
  (2) every key use through the agent's CryptoActor (docs/plans/crypto-actor.md); no polar_custody outside
  polar-crypto, polar-init, polar-health, the daemon (K4 dep test); new CryptoMessages named per bite, added by polar-89
  on main ahead of it; (3) per bite: signed/persisted state changed + what a running u7c needs.

## NEW CRYPTOMESSAGES (polar-f1 adds on main ahead of the bite; names proposed). Review: polar-f1 2026-11-13, 7 points, settled here.
Main today: CryptoMessage {Connect, ClientTls, ServerTls, SignRecord, StoreSecret, EncryptForRecipient, RegisterSecret,
LoadSecret, ReplaceSection, UseCredential, RetrieveSecret, RoutedReply}; KeyFiles = TLS client/server pairs only.
- B1 `SignCheckpoint { text: String, reply } -> sig line`. Checks: `polar_log::checkpoint::Checkpoint::parse(text)` ok
  (exactly 3 lines: origin, decimal size, base64 root, trailing \n, no extensions; polar-log/src/checkpoint.rs
  :83-131) AND origin == `<own_identity>/<log>`. ORIGIN SOURCE (point 2): the actor's own identity from its
  certificate (own_identity). acp does the same today: supervisor.rs:266-269 `extract_own_identity(cert pem)`, with
  fallback SERVICE_NAME (drop the fallback in the actor: no identity → refuse). Not a git-server setting. Note name
  `<own_identity>/checkpoint` (logs.rs:50 KEY_NAME, :153). Signs via NoteSigner (type 0x02, ECDSA P-256 over SHA-256 of text).
- B2 `Cosign { text: String, reply } -> (line, T)` (point 3). T = the actor's own clock (no caller T: backdating).
  Checks: Checkpoint::parse ok AND origin's identity prefix == pinned store (POLAR_ATTESTATION_WITNESSED_STORE). Builds
  `cosignature/v1\ntime <T>\n<text>` (checkpoint.rs:164); `Cosigner::cosign_line` (COSIGNATURE_TYPE :54,
  cosigner_key_id :152). Consistency vs last co-signed stays in the witness actor (domain), before asking.
- Records: `SignRecord` on main (K1 9a2cc593); B1 attestation evidence.rs uses it.
KEY FILES (point 1; main: `_KEY` = a private-key PATH; acp's pins are public keys under _KEY names, unchanged):
`POLAR_STORE_CHECKPOINT_KEY` and `POLAR_WITNESS_COSIGNING_KEY`, declared ONCE in polar-crypto's `keys` section,
Optional, NO default there; the render sets each for its one workload in capabilities.nuon at today's path:
polar-git-server → /var/lib/polar-git-server/logs/checkpoint-key.pem (acp LOG_ROOT settings.rs:44-50 + logs.rs:48
KEY_FILE); attestation-agent → <POLAR_ATTESTATION_WITNESS_ROOT>/witness-key.pem (attestation settings.rs:43-46 +
witness.rs:251). u7c keys + pins survive.
MAKE-ONCE + CERTIFICATION (point 4).
- acp TODAY: LogsActor::open (logs.rs:146-153) makes the key once beside the logs, owner-only, never replaced (test
  `the_checkpoint_key_is_made_once_kept_private_and_pinned` :1318); NOT certified (logs.rs:27-28: "Its certificate
  from the internal CA is not yet asked for: no issuance path exists for a workload's own stable key"). Witness:
  witness.rs:284-320 `open(dir)` makes its key + holding, Damage if one without the other; pinned only.
- PROPOSED: the CryptoActor makes each key if its file is absent (0600, never replaced), not the domain. For the
  checkpoint key, the CryptoActor (not the domain) asks the credentials agent to certify it, for checkpoints alone
  (cert type: cert-issuer's checkpoint certificate, main 402e7958, used today for the ledger's own key), over NEW
  topics fitted to main's convention (polar-f1 2026-11-13): `credentials-key-certification-requests` and
  `credentials-key-certification-replies` (constants CREDENTIALS_KEY_CERTIFICATION_{REQUESTS,REPLIES}_TOPIC in
  credentials-agent/common/src/lib.rs); ONE reply topic, no per-identity suffix: each answer names its requester
  inside and is answered only to the identity that asked. Message `CertifyKey { csr_pem, purpose: Checkpoint }` →
  `Certified { chain_pem }` | refusal; asks again before expiry. (a) The credentials agent certifies a checkpoint key
  only for a requester whose workload the catalog gives that capability (the git server), judged by the
  broker-stamped identity. (b) The git server's floor gains exactly those two topics, computed from its build (the
  builder's implied topics), never hand-declared. Credentials agent side + topic
  policy added on main with B1 (polar-f1). This is NEW (acp never certified), and the maintainer's D3 "certified by
  the credentials agent" is met by it. Witness key: stays pinned by verifier key (decision 5 names only the store key).

## PREREQUISITES
- K2b (crypto-actor.md): person CLIs get TLS from a CryptoActor over their key files; the cassini-client CLI moves to
  its own package. Before B4 and B5 (point 5).
- B4 adds NO new direct key-PEM signing (point 6). polar-sign / polar-running-config signing with identity.key_pem is
  a pre-existing gap, recorded by polar-f1 in crypto-actor.md.

## ACP CODE (since merge base a4c1c984)
polar-git-server +6967/−92 (new: logs, log_read, reply, evidence, schedules, witness .rs); attestation +2788/−41
(witness.rs 1211, evidence.rs 536, common witness.rs 235, report/record/proof); polar-scheduler +2145/−263
(observer sync_actor/reads/settings; common running.rs; 3 .elide.dhall STAY); polar-records-client +533;
git-remote-polar +642; polar-git (src: events, http, lib, main, settings, supervisor; tests e2e 426); seed.nu +54
(witness_pins :355-382); up.nu +49/−2. polar-log: no diff. Catch-up 7f02484c acp-only. ≈15k + polar-git.

## BITES — state and what u7c needs
B1 logs + reads + evidence intake + catch-up + attestation evidence.rs + record-store.md current on main.
   STATE: polar-git-server-data PVC (UID 50bb1772 as of 11-12): logs dir with evidence + schedules logs and
   checkpoint-key.pem, written by acp, KEPT (never re-init); evidence log appends missing (44 caught up live 11-12).
   schedules repo: none. NEEDS: SignCheckpoint on main; up.nu --dev; no wipe, no re-seal.
B2 witness (attestation witness.rs/common, git-server witness.rs, seed pins for git-server + attestation).
   STATE: attestation-agent-data PVC (9e644997): witness dir (witness-key.pem, holding) KEPT. Schedules:
   permanent/{polar-git-server,attestation-agent}/configuration.dhall v1 already carry the pins (acp seed);
   witness_pins writes only when an agent has no settings → writes nothing on u7c; main now declares
   POLAR_GIT_SERVER_WITNESS_KEY + POLAR_ATTESTATION_WITNESSED_STORE → those two v1 updates accepted.
   NEEDS: Cosign on main; up.nu --dev.
B3 schedules on log (git-server schedules.rs; scheduler observer reads log, both pins; seed observer pins).
   STATE: schedules log already on PVC; observer v1 (POLAR_SCHEDULER_STORE_KEY + _WITNESS_KEY) accepted → no agent
   refuses its configuration. NEEDS: up.nu --dev.
B4 people's tools (builder person floor floor.rs; polar-records-client; polar-sign over Cassini, no --repo).
   STATE: Cedar person-answer rules = policy v4 already in force on u7c (main accepted v4); context.addressed on main
   (2cc50d72). No persisted change. Floor in every agent → all rebuilt. polar-records-client is a person CLI: K2b.
   NEEDS: up.nu --dev; tools rebuilt on people's machines. polar-eden fetch-log/collect --push stay on acp (D2).
B5 polar-git + git-remote-polar.
   STATE: new workload + its own PVC (repos); TLS via TlsHandle with TLS_SERVER_CERT_CHAIN/TLS_SERVER_KEY (K3b names;
   acp's POLAR_* key names + settings.rs:74-77 ServerKey/one_key + supervisor TlsAcceptor replaced: K3 "ACP'S OWN
   PATHS"); Cedar git-* actions + Repository entity on main (2cc50d72); groups doc (repo-developer) in schedules.
   NEEDS: catalog entry + PVC via render; up.nu --dev; git-remote-polar on people's machines (K2b CLI CryptoActor).

## DECIDED WHILE PORTING (polar-cc's worker, by the plan and standing rules; for review)
B2 (store-bite-2, 2026-11-14):
- Holding records its key: witnessed.json = {key, origins}; a holding under another key than CosignHandle::key() is
  Damage::AnotherKey. acp's old form (origins map alone) is taken once every line verifies under the actor's key, then
  rewritten with the key (u7c's file converts on first start). Replaces acp's "key file without holding" check, which
  the domain can no longer make (the actor makes the key).
- GAP: a holding lost while the key survives starts empty under the same key; undetectable in the domain. Closing it
  needs the actor to make key + holding together.
- A co-sign T that goes back on the held T for that origin is neither kept nor sent (logged error).
- attestation-agent does not depend on polar-crypto (domain_has_no_way_out): polar_agent_builder::crypto re-exports
  WITNESSED_STORE and EXAMPLE_STORE (precedent: CryptoError, EvidenceRecord, host_matches re-exports).
B3 (store-bite-3, 2026-11-14), from acp 535fd6d8, fee9065c, a3c999fc (polar-eden test + live-notes docs dropped),
c43cafe2:
- Logs::read_from(name, from, limit, own: Option<String>): before a log is ever co-signed, acp answered with the
  store's own checkpoint signed in-domain. On main the LogsActor's ReadFrom arm asks the CheckpointHandle to sign
  checkpoint_text and passes the note in; signing fails → NotNow. No new CryptoMessage (SignCheckpoint suffices).
- acp's Cause::OwnConfiguration (60a68b51, a polar-topics/scheduler-common refactor) is NOT ported: the observer
  declares OWN_CONFIGURATION_TOPIC = "agent.polar-scheduler-observer.configuration", tied to
  configuration_topic(SERVICE_NAME) by a test, as SCHEDULER_OBSERVER_READ_REPLIES_TOPIC already is. When acp's
  refactor reaches main, replace it.
- polar-scheduler-common running.rs: acp's diff is test-only (answer round trip), unrelated to B3; not ported.
- Store start: evidence catch-up, then schedules catch-up (both before serving). On u7c the schedules log (acp-written)
  opens as found; pushes made while main ran B1/B2 (no schedules hook) are appended at the first B3 start as the store's.
B3 rebased onto main 7a6363de (2026-11-14; WITNESS_ROOT made Required::path WriteDir after u7c's render refused a
  path declared as text). Bites 3+4 checked for the same class: their only new text variables are
  POLAR_SCHEDULER_{STORE,WITNESS}_KEY (verifier keys); no catalog values added. RENDER CHECK WITHOUT A CLUSTER: build
  the agent bins (debug, capped), ask each `<bin> --scaffold` with POLAR_SERVED_WORKLOADS = served(workloads), save
  `<workload>.json` (bins: credentials-agent→credentials-agent-consumer, cassini→cassini-server,
  oci-registry-resolver→oci-resolver, else the workload's name), then POLAR_SCAFFOLD_DIR=<dir> nu infra/render.nu
  sandbox-local. All checks through Landlock/cert-issuer/CA pass; it stops at image pinning (no image lock in a
  worktree). A local polar-git-server build has SEED_ROOT=/nonexistent/... (option_env POLAR_GIT_SERVER_BUILT_SEED_ROOT
  unset), which the lock check flags; build with that set to a /nix/store path, as the image is.
B4 (store-bite-4, 2026-11-14), from acp 3c6938fa + b1e7f270:
- Ported: person floor (floor.rs), Facts.addressed + topic_gate::addressed_to (the broker asks through topic_gate::ask,
  so it computes it too), the store's reply.rs / person evidence / section intake (SCHEDULES_REQUESTS_TOPIC) /
  put_file, polar-records-client, polar-sign pushes over Cassini.
- polar-records-client re-exports main's polar_running_config::client_config, which returns (crypto, config) from
  polar_crypto::cassini::standalone; polar-sign stops the crypto actor after each answer (as its running-config
  survey already does). No polar_custody use; no new key-PEM signing.
- Seed policy.cedar gains only the two People-on-Cassini rules; acp's polar-git rules (repo-developers, owner) are B5.
  u7c runs acp's policy v4 already; the seed writes nothing there.
- NOT ported: polar-eden (D2), acp's source-git capability name in capability.rs's test list (B5), the
  owned-repository store test (create_owned, B5), Cargo members polar-git / git-remote-polar / polar-git-push (B5).
- Finding: cassini-broker's a_client_that_publishes_and_never_acknowledges_is_spared_once_and_then_ended failed once
  under the full workspace run ("the stopped broker still holds 1 names") and passed 3/3 alone; timing under load,
  not B4's code (B4 touches only topic_gate::ask's facts). Reported, not changed.
RACE (polar-f1's bite-4 review, 2026-11-14), fixed on store-bite-4 (covers B3's push hook, on main, and B4's intake):
- Two writers of polar-schedules + its log, unserialized: SectionIntake::add (read main T0, append T0+section,
  put_file) and receive_pack's hook (append tree(P) in the judge, then gix-serve moves the ref). (1) push between the
  intake's read and append → log reverts P while git keeps P+section; (2) section before a push from an older clone →
  the hook logged P' (dropping the section) and the ref CAS then failed, log ahead; (3) any ref update failing after
  the hook's append (non-ff race, ref lock) → log ahead of git.
- Fix: RepoStore::writing(name) (per-repo tokio Mutex, FIFO, shared by every clone of the one store; writers_waiting
  for tests/diagnostics). Held by receive_pack (every repo) from before the judge until refs moved or the log is put
  back, and by SectionIntake::add from reading main through put_file. Under it the intake's `to` is the main it commits
  on. The hook re-checks `main` == the client's old before appending (http.rs main_is), so a stale push is refused
  before anything is logged. If the hook appended and the push then did not move main (Err or no commands made), or
  put_file fails after the intake's append, schedules::catch_up puts the log back to git main (appends the reverting
  changes, as the writer's): a log cannot drop a leaf, so this is the only way back; it never stays ahead.
- Tests (e2e.rs): push in flight then section; section then a push from before it (refused, section kept); push with
  main.lock present (log put back); 6 concurrent rounds. First three fail on the old writers; the rounds test did not
  reproduce the race on the old code (timing), kept as a regression guard.
- Evidence repo: receive_pack now holds the same lock for it; the evidence intake's add_file does not take it. A record
  logged by a push whose ref then fails stays in the log only (log ⊇ repo is that log's stated invariant; catch_up
  covers the other direction). Left as is.
- acp has the same race (its schedules.rs/http.rs are the source of this port); acp's merge of main resolves it by
  taking main's version of these files.
B5 (store-bite-5, 2026-11-14, on store-bite-4 f06c4022), from acp f79af58d + 2cfc9fa2 + 7822a2bd:
- polar-git: settings drop POLAR_GIT_CERT/POLAR_GIT_KEY, polar_custody ServerKey/one_key and read_key; the catalog's
  source-git sets TLS_SERVER_CERT_CHAIN/TLS_SERVER_KEY (key_of: server), declared by `keys`. Its section's relation
  requires TLS_SERVER_CERT_CHAIN (polar_crypto::environment::SERVER_CERT_FILE), since it serves nothing without one; the
  key-or-socket choice is the crypto actor's at start, as for every server (no one_key, per the coordinator). Listener:
  polar_git_server::tls::server_config(&resources.tls, ca, None). Dep polar-custody → polar-crypto (polar-git is
  NOT_THE_DOMAIN in domain_has_no_way_out, as acp listed it). Tests build the server config with
  polar_crypto::tls::server_config(KeySource::Files), as polar-git-server's e2e does.
- git-remote-polar: NOT through polar_crypto::cassini::standalone. It never uses Cassini and never opens a key: it
  hands git `http.sslCert/sslKey/sslCAInfo` paths and git's curl does TLS. acp's polar-git-push dep (a polar-eden
  crate, D2) replaced by its 3-line git_config, inlined.
- Path-valued variables: POLAR_GIT_REPO_ROOT path WriteDir, POLAR_GIT_CA_CERT path ReadFile; no text path. Render
  check without a cluster (25 scaffolds, polar-git included): all checks pass through Landlock, cert-issuer, CA; stops
  at image pinning only.
- capability.rs DEPLOYMENT_ONLY gains "source-git" (removed in B4, B5's). Seed policy gains the polar-git rules after
  the People-on-Cassini rules; groups.json's repo-developers from acp. polar-git.nuon's header named git-server.nuon
  too (acp copy slip): fixed.
- STATE: new workload polar-git, its own persistent-data PVC (repos), certificates from the credentials agent
  (sandbox-local issuer). u7c (read 2026-11-14): acp's polar-git deployment was pruned when main took the cluster, and
  its claim polar-git-data (pvc-e8e267d3, 2d11h) is still Bound; main's render names the same claim
  (persistent-data, `<workload>-data`), so its repositories open as found. Policy v3+/groups v2 with repo-developers
  are already in force on u7c, so the seed writes nothing.

## MET (2026-11-14, main ffabeec5, u7c live per polar-f1)
- B1 871739eb ca14b6d4 d77874e1 a85157e4 (+0ab01c5f resolve.nu test): logs opened as found, key kept + certified, catch-up
  current, attestation records through the intake.
- B2 1381df26 (S2, polar-f1) bc9880f3 7e900ea8 bfffd2c9 8a6b8eff (+7a6363de WITNESS_ROOT Required::path WriteDir, found at
  u7c render step 4): witness-key.pem kept, witnessed.json converted to {key, origins}, both pins taken.
- B3 de708eb8 c1592391 4f9ea4ef 908f4710: schedules log opened as found + caught up; observer reads the log, both pins.
- B4 aee96e78 799513d7 23f90586 a3cdf719: person floor, addressed, section intake, polar-sign over Cassini.
- RACE f06c4022 (polar-f1's B4 review): RepoStore::writing; stale push refused before logging; log put back on a failed
  ref update.
- B5 e63282ca a3fd337b ffabeec5: polar-git + git-remote-polar; polar-f1 checked push, clone, owner force-push, and
  bootstrap-admin refused 403 "may not git-read". Test repo f1-bite5-check LEFT on polar-git-data on u7c.
LEFT (none blocking): checkpoint key → named custody key when trusted-remotes step 3 lands (D3); witness holding lost
with key kept starts empty (B2 GAP); large records as blobs (> MAX_ENTRY 65,535; polar-eden run record 237 KB); evidence
intake's add_file takes no writer lock, by design (evidence log ⊇ repo).
NEXT: acp merges main (ffabeec5+), taking main's version of everything ported.

## RISKS
size; record-store.md on main stale (acp +76); u7c PVC state must survive (B1 opens as found); acp tests touching
polar-eden must be split out; the make-once key rule must move into the CryptoActor intact.

## REVIEW
polar-f1 (polar-89) read the plan against main 2026-11-13 (7 points, then topic names) and found it READY for the
maintainer.
