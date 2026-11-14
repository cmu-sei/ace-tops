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

# crypto-actor — Claude's side

PAIR: `crypto-actor.md` (people). Same plan, two forms; change together.
PARENT: none (capability). AS-OF main 84179d44 (2026-11-13). STATUS: approved ("it's high time we cleaned this up"),
building.

## ORIGIN (2026-11-13, the maintainer)
- "The custodian is supposed to [be] just that: a simple, secure place that store keys, allow for them to be used safely.
  It's not supposed to keep increasing in scope. I build the cryptoactor to be the place the crypto work happens and you
  seem to not want to use it for that."
- Asked who talks to the custodian, then "Why is everyone circumventing cryptoactor?", "Why isn't git server a builder
  agent?" (it is; it lacks `Encryption`, so no CryptoActor), "Why are we using rustls if it doesn't properly support
  async?", "We should also ensure that the number of actors affected by the dependency cycle is minimized. We should fix
  the builder's signer both here and on polar-cc."
- Then: "Make your checks but it's high time we cleaned this up because I'm really tired of explaining how all of the
  crypto infrastructure is supposed to work, only to realize later that we somehow built yet-another circumvention of
  the design."
- polar-cc's key-custody.md 84179d44: custody's scope is the keyring's; test "would the kernel keyring do this?".

## FACTS (main 84179d44)
Custody client users (production): cassini/client/src/lib.rs:1721 client_config; cassini/broker/src/listener.rs:633
server_config + settings.rs:175 read_server_key (file|socket); polar-git-server/server/src/tls.rs:76 server_config +
settings.rs:125 read_key; lib/src/graph/controller.rs:1333 client_config; cert-issuer/client/src/handshake.rs:225
with_root_ca_and_custody (caller: credentials-agent/consume/src/supervisor.rs:1033 for_trust_mode_with_identity);
polar-agent-builder/src/signer.rs + infrastructure.rs:693 (SignerActor, bite S); polar-crypto Unwrap; polar-init
(installer); polar-health/src/custody.rs:50 (probe: Certificate). Tests elsewhere use custody in test modules only.
CryptoActor: spawned only `if setup.wants_crypto` (Encryption), AFTER the tcp_client (infrastructure.rs:651), given
`tcp_client` + router (it requests via Cassini: retrieve/store/escrow). Broker and git server are PolarAgents
without Encryption.
rustls 0.23 `Signer::sign(&self,&[u8]) -> Result<Vec<u8>>` sync (crypto/signer.rs:84); async-capable TLS = C (BoringSSL
PrivateKeyMethod/tokio-boring, OpenSSL ASYNC, s2n-tls). Speed gate: custody adds 0-22 µs p99 (ring build;
key-custody.md:186-198).
Key files: render drops `key_of` vars when the pod runs custody (resolve.nu:552); custody on for kind `agent` and
`service` (kinds.nuon:88), cluster `custody.enabled: true` (cluster.nuon:70). Files remain: `ca` kind (cert-issuer, by
design, makes and self-signs its key), `template` (no identity), clusters with custody off (degraded), neo4j (3rd party).
Direct crypto deps elsewhere: polar-signing in broker (Trust), git server (commit verify), credentials agent (authority/
escrow/checkpoint cert verify), builder config/authority actors (signed sections), attestation-agent; polar-escrow in
builder (credentials.rs binding_context, a context string helper) and credentials agent.

## STANDALONE CASSINI CLIENTS (the maintainer, mid-turn: "the cassini client as a standalone daemon. In order to be
consistent, that guy would need to be built with a cryptoactor and a custodian, somehow.")
Found: cassini-client bin `--daemon` (cli.rs; TCPClientConfig::from_env, own TLS via lib.rs:1721); cassini-c2
(main.rs:65 TCPClientConfig::new); polar-running-config (lib.rs:114, a person's keys); polar-init (own client +
CryptoActor, escrow bootstrap); custody daemon custodian (watch.rs:248, signs own handshake in process: the one
exception, custody is the keyring); `polar::cassini` (lib/src/cassini.rs:139) = a SECOND client inside builder agents:
attestation/agent/src/supervisor.rs, build-orchestrator/agent/src/publish.rs, cert-issuer/server/src/supervisor.rs,
cassini/test/producer. Decided (standing rules, maintainer's direction): the CryptoActor is startable by any process
(polar-crypto), TCPClientConfig takes TLS only from a CryptoActor (no env key reading in cassini-client), key source is
the CryptoActor's (custody socket in a pod; files for a person or cert-issuer); deployed CLI daemon / c2 rendered with
the custody sidecar; `polar::cassini` helper removed, its users take the builder's client.

## ACP'S OWN PATHS (polar-cc, 2026-11-13, since merge base a4c1c984; test files left out)
1. polar-git (acp-only source-code git server): src/settings.rs:74-77 ServerKey (File|Custody via one_key),
   src/supervisor.rs its own tokio_rustls TlsAcceptor → K3, as the git server.
2. polar-records-client (acp-only): src/lib.rs its own TcpClientActor + TCPClientConfig, a person's tool over Cassini
   (used by polar-eden, polar-sign evidence/schedules) → K2b, beside polar-running-config.
3. polar-eden src/main.rs (acp-only): reqwest Identity::from_pem + add_root_certificate with a person's cert/key files,
   for the git face of polar-evidence. DECIDED (the rule): included, a person's CLI is a process that uses a key → a
   CryptoActor over file keys, as polar-sign's git push would be.
4. attestation agent src/supervisor.rs:545-552 (acp) reads its own TLS_CLIENT_CERT file for its identity → the
   CryptoActor answers its identity (it already derives own_identity from that certificate).
5. builder signer.rs: superseded by K1.
OWNER: these crates exist only on acp; moving 1-4 onto the CryptoActor is polar-cc's, after it merges K3/K2b (polar-cc,
2026-11-13). Main's side: K3's API stays general, not shaped around the git server: a server TLS config for the pod's
own identity with ALPN as the caller asks, and a client config from a person's own key files.

## STEPS (each tested, committed, pushed; u7c bring-up before the TLS step is called done)
K1 DONE 2026-11-13. Signer into the CryptoActor: CryptoMessage/port op SignRecord-equivalent in polar-crypto (input build + type check
   from signer.rs), SignerHandle → CryptoActor; SignerActor and its spawn removed; signing agents get a CryptoActor.
   acp: its only custody call is signer.rs (polar-cc, 2026-11-13); fixed by its next merge of main. Tell polar-cc.
K2 DONE 2026-11-13 (builder agents; standalone processes are K2b). polar-crypto: CryptoActorArgs::unconnected(),
   CryptoMessage::Connect{tcp_client, router} (reply topics registered then; NotConnected before), own identity and
   pinned CA optional (CryptoSettings::from_env_for(env, escrow): a non-escrow actor reads neither, only the custody
   socket); CryptoError::NotConnected, NoIdentity. Builder: spawn_crypto in pre_start before the authority/client
   parts, for every agent (escrow = wants_crypto; CredentialPort only then), Connect cast once the tcp_client exists;
   the supervisor's state holds it (child identified there); the domain gets its handle only when it escrows. FOUND for
   K3: Config holds only declared variables, so a non-Cassini agent's crypto actor sees no POLAR_CUSTODY_SOCKET (it is
   declared by cassini-client's section): K3 moves that declaration to the crypto actor's own section, every agent.
   Was: CryptoActor in every agent, first: spawned before tcp_client with custody client (or key files when degraded); late
   `Connected(tcp_client)`; `Encryption` keeps meaning escrow key (wants_crypto → escrow ops only).
K3a DONE 2026-11-13 (polar-crypto + builder handle; call sites are K3b). polar-crypto/src/tls.rs: KeySource
   {Custody{client,slot} | Files{certificate,key}}; SlotSigner (rustls SigningKey/Signer over a custody slot, ECDSA
   P-256, refuses anything but a TLS 1.3 CertificateVerify input before asking the daemon); client_config(verifier,
   source), server_config(verifier, alpn, source) (custody → TLS 1.3 only, cert chain from the slot; files → rustls
   defaults). CryptoMessage::ClientTls{verifier} / ServerTls{verifier, alpn} (spawn_blocking; key_source: custody slot
   if the pod has the daemon, else the key files). environment::KEYS section (POLAR_CUSTODY_SOCKET, TLS_CLIENT_CERT,
   TLS_CLIENT_KEY, TLS_SERVER_CERT_CHAIN, TLS_SERVER_KEY, all Optional; the same names cassini-client's and the
   broker's sections declare today); KeyFiles in
   CryptoSettings. KEYS is NOT yet registered: the agents' soundness test requires each variable declared once, and the
   Cassini client's and the broker's sections declare these names; each stops declaring them in K3b as it takes its TLS
   from the crypto actor, and K3b registers KEYS in the builder's base sections then (tried in K3a: 52 soundness
   failures, and the broker's settings tests read the names as undeclared). Builder: crypto::TlsHandle (client_config, server_config; nothing else) in AgentResources.tls and
   ServiceResources.tls (polar-cc's general API: a server config for the pod's identity, ALPN by the caller). Tests:
   in-memory mutual handshakes (daemon keys, ALPN agreed; key files), the signer's refusal, the actor's TLS ops and a
   keyless actor's refusal. Custody's own TLS-shape check stays until K3b moves every caller (removing it first would
   leave the old signers unchecked).
K3 TLS from the CryptoActor: polar-crypto offers client/server rustls configs (or a sync `TlsKeys` handle) built from
   the agent's cert, custody signer, trust; the TLS-1.3-shape check moves from custody's daemon (custody.rs Sign arm,
   is_tls13_certificate_verify) into the signer polar-crypto makes. Five call sites switch. u7c bring-up.
K3b DONE 2026-11-13 (main): every agent's Cassini client, its graph client, the credentials agent's cert-issuer client,
   the broker's listener and the git server's listener take their TLS from the CryptoActor (TlsHandle). KEYS registered in
   the builder's base sections; cassini-client declares TLS_CLIENT_CERT only, the broker and the git server none of the
   key names (each keeps a rule that it has a server key: one_key on TLS_SERVER_KEY or the socket). The git server's
   POLAR_GIT_SERVER_CERT/KEY are TLS_SERVER_CERT_CHAIN/TLS_SERVER_KEY (capabilities.nuon, deploy-repo.nu). With custody,
   a server's certificate is the slot's, so TLS_SERVER_CERT_CHAIN is required only beside a key file (`keys`). NOT done
   in K3b: custody's daemon-side TLS-shape check. The Cassini client still builds its own TLS over custody's signer when
   not handed one (cassini/client/src/lib.rs, the standalone processes), so the check goes at the end of K2b.
K2b Standalone processes: CLI daemon, c2, polar-running-config, cert-issuer, polar-init each start a CryptoActor;
   TCPClientConfig loses its own key reading; `polar::cassini` removed. Then custody's daemon drops
   is_tls13_certificate_verify from its Sign arm (and Refusal::NotTls13Handshake), and polar_custody::client's own
   rustls signers/configs go; own.rs (the daemon's own session, in process) stays.
K4 Dependency test: cargo metadata; only polar-crypto, polar-init, polar-health, polar-custody-daemon (and polar-custody
   itself) may depend on polar-custody. Builder loses its direct dependency.
K5 Degraded key files held by the CryptoActor (same shape).
K6 Then trusted-remotes C3: custody named Ed25519 keys; CryptoActor ssh signer + Nix signer.
V  Verification into the CryptoActor: separate plan.
OPEN: whether K3 hands rustls a config or a key handle (decide by what the five sites need; no question to the
maintainer).
