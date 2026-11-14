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
polar-89 after review against main, then to the maintainer to clear.
STATUS: PROPOSAL 2026-11-13, not cleared. Behind it: maintainer "Bring the store to main" (2026-11-13).
FLOW per bite: polar-cc prepares on a branch from main (≥ 7e43bb92; tests pass there, capped: systemd-run
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

## NEW CRYPTOMESSAGES (polar-89 adds on main ahead of the bite; names proposed)
Main today: CryptoMessage {Connect, ClientTls, ServerTls, SignRecord, StoreSecret, EncryptForRecipient, RegisterSecret,
LoadSecret, ReplaceSection, UseCredential, RetrieveSecret, RoutedReply}; KeyFiles = TLS client/server pairs only.
- B1 `SignCheckpoint { text: String, reply }` (store). Checks: `polar_log::checkpoint::Checkpoint::parse(text)` ok
  (exactly 3 lines: origin, decimal size, base64 root, trailing \n, no extension lines; polar-log/src/checkpoint.rs
  :83-131) AND origin == `<store origin>/<log>` for this store (acp logs.rs:144-146 `Logs::open(root, origin)`,
  checkpoints name `origin/<log>`). Signs via `NoteSigner` (signed-note type 0x02, ECDSA P-256, DER over SHA-256 of
  the text). Returns the signature line.
- B2 `Cosign { text: String, time: u64, reply }` (attestation agent). Checks: Checkpoint::parse ok AND origin's store
  prefix == the pinned store (POLAR_ATTESTATION_WITNESSED_STORE). Builds `cosignature/v1\ntime <T>\n<text>` itself
  (checkpoint.rs:164) and signs as `Cosigner::cosign_line` (type COSIGNATURE_TYPE = b"\xffpolar.dev/cosignature/p256/v1"
  :54; key id cosigner_key_id :152). Consistency with the last co-signed checkpoint stays in the witness actor
  (domain), before it asks.
- Records: `SignRecord` already on main (K1 9a2cc593); B1's attestation evidence.rs uses it.
KEY FILES (new KeyFiles entries in polar_crypto::environment; names proposed, defaults = today's paths so u7c keys
and pins survive): `POLAR_STORE_CHECKPOINT_KEY` default `/var/lib/polar-git-server/logs/checkpoint-key.pem` (acp:
LOG_ROOT settings.rs:44-50 + logs.rs:48 KEY_FILE); `POLAR_WITNESS_KEY` default `<POLAR_ATTESTATION_WITNESS_ROOT>/
witness-key.pem` (acp: attestation settings.rs:43-46 WITNESS_ROOT + witness.rs:251 KEY_FILE). Today the store makes
its key once if absent (logs.rs test `the_checkpoint_key_is_made_once_kept_private_and_pinned`); the CryptoActor must
keep that: make-once 0600 if absent, never replace (a new key breaks the pins).

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

## RISKS
size; record-store.md on main stale (acp +76); u7c PVC state must survive (B1 opens as found); acp tests touching
polar-eden must be split out; the make-once key rule must move into the CryptoActor intact.

## OPEN
key-file variable names (proposed above; polar-89 to confirm against main's naming).
