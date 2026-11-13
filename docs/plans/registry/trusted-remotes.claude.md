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

# trusted-remotes — Claude's side

PAIR: `trusted-remotes.md` (people). Same plan, two forms; change together.
SPLIT: people side has no dates, attributions, quotes, codenames or branch/process status; those live here.
PARENT: `../registry.claude.md`. AS-OF main 621375b8 (2026-11-13). STATUS: proposed; one decision for review (KEY).

## ORIGIN (2026-11-13)
- Maintainer: "Have we built the part that allows us to configure trusted remotes via the configuration agent and to
  escrow trusted remote certificates yet?" → no.
- I said a Nix cache's signing key isn't a secret; maintainer: "I disagree. We will eventually have a non-public nix
  cache." I separated: cache's secret signing key (secret), access credential (secret, escrow), verifying public key
  (my claim: not secret). Maintainer: "The remote itself can indeed be a secret." → whole entry sealable.
- Pending my question: may the domain hold a sealed remote's public key? Recommendation below, marked for review.

## FACTS (main as is)
- Registry upstream: settings.rs Static POLAR_REGISTRY_NIX_UPSTREAM (default https://cache.nixos.org) +
  POLAR_REGISTRY_NIX_UPSTREAM_KEY; one operation `nix.upstream` Location::Configured (upstream.rs).
- credentials section (polar-agent-builder/src/protocol/credentials.rs BODY): name, host_pattern, kind (token |
  user-password | ssh-key), username, host_key (ssh pins), secret = base64 EscrowedSecret bound to
  `<agent>|credentials|<version>|<name>|secret`, made by polar-sign. ONLY `secret` is ciphertext: host_pattern,
  username, host_key are clear in the signed doc. CryptoActor opens via custody, keeps with binding.
- Locations (judge.rs:122): Configured {variable}, Bound {credential} (host learned at run time, must match the
  credential's binding), Arbitrary (any host, never a credential, marked), Cluster. No "host from a signed list".
- RequestRecord (protocol.rs:286) logs `host` per request; faults.jsonl records Upstream.url per try.
- HTTP handler: one reqwest client per agent (Http::client(egress,...)), roots = system + egress CA; no per-remote trust.
- polar_escrow EscrowedSecret holds arbitrary bytes bound to a context string → can hold a whole JSON entry.

## DESIGN (mine, for review)
- `remotes` RuntimeSection (SectionAuthority::Runtime), per agent; entries {name, order, plain{url, key (Nix public
  key for nix kinds), tls: system|ca(pem)|pin(sha256 of cert/SPKI), credential: name in `credentials`, uses}} |
  {name, order, sealed: base64 EscrowedSecret bound `<agent>|remotes|<version>|<name>|entry` of the plain fields incl.
  its credential's secret inline}. Replaced whole → withdrawn by omission.
- Builder: new Location `Remote { section: "remotes" }` (name TBD). Request carries remote name + path; handler resolves
  via section (plain) or CryptoActor (sealed: returns a connection spec, address never to domain); per-remote reqwest
  client (roots/pin), credential attached in handler; judge refuses a name not in force. Record host = "remote:<name>"
  for sealed; plain may record host (TBD: always name? simpler: always name + plain host).
- KEY (for review): domain may hold a sealed remote's verifying public key in memory, never logged/recorded; CryptoActor
  answers "the key for remote X". Alt: verify in escrow (narinfo fingerprint + sig → bool) — more crossings, key only
  verifies. I recommend domain holds it.
- Registry: Upstream list from `remotes`, follow changes (runtime_changes), Upstream.via = the new operation; faults
  records `upstream: <name>`.
- Steps: R1 section plain + registry reads it; R2 handler Remote location (plain); R3 sealed (polar-sign seal,
  CryptoActor open, resolve without exposing); R4 host store remote.
- Compatibility: additive builder API; acp shares polar-agent-builder (main-and-acp-stay-compatible) — new Location
  variant: match exhaustiveness in acp code? judge matches are inside builder; check acp for `match location` before R2.

## QUARANTINE (maintainer 2026-11-13: "A dropped remote should place the files in the registry that came from that
remote under quarantine.")
Design (mine; release rule for review): per-path provenance `from: <remote name>` in the path record (NixCache narinfo
store; extend the record beyond NarInfo text, e.g. a sidecar or a record type), backfilled from upstream Sig key names
(cache.nixos.org-1 → the remote whose key it is). On a `remotes` version that drops X: mark every path from X
quarantined {by section version, at}; lookup treats quarantined as not held → fault from remaining remotes (a fresh,
verified entry under a trusted key releases it) else refuse + record outcome "quarantined"; NAR endpoint serves a blob
only if some unquarantined path names it (blob → paths index). Release: trusted remote vouches again, or a person's
signed release (where signed: TBD). Re-adding X alone does NOT release (for review). Delete: only by a person (claims
precedent, deploy-objects.nu protect_claims, maintainer 2026-11-02). Generalize to every face (crates, images) via the
same provenance field in the CAS's records.

## DECIDED (maintainer, 2026-11-13, asked all at once: "Ask all of your questions.")
1. Sealed remote's key: "1., and it should be held by the infrastructure side actors, maybe crypto actor or config
   actor." → the domain holds NO remote key (plain or sealed); infra side holds keys and verifies on request by remote
   name. Mine, for review: the CryptoActor (it already opens escrowed entries and keeps credentials with bindings);
   plain remotes' keys too, so one API: verify(remote, fingerprint, sig) → bool.
2. Quarantine release: trusted remote vouching again, or a person's signed release; re-adding alone does not.
3. Release/delete: signed commands (commands.md), a capability of their own; recorded.
4. Remotes list: per agent.
5. Records: plain remote by name + host; sealed by name only.
6. Uses: kinds of content now (nix, crates, oci, git); finer scoping later.
7. Server identity: "System roots are not to be trusted for this, the trust must be declared within polar and managed
   within polar." → entry declares CA (PEM) or pin (SPKI SHA-256); no webpki/system roots for remote clients; even
   cache.nixos.org gets an explicit anchor in its signed entry. Handler: per-remote client built with only the declared
   trust (reqwest ClientBuilder tls_built_in_root_certs(false) + add_root_certificate, or a pinning verifier).
8. Polar's own Nix signing key: custody signs Ed25519 BEFORE the registry is deployed to any cluster (NC5 blocked on it).
Decided by standing rules (for review): order = list order; a fault in flight when its remote is dropped finishes,
then its path is quarantined with the rest; quarantine records name the remotes version that dropped it.

## CREDENTIALS FIRST (maintainer, 2026-11-13)
Asked "So the configuration actor delivers updates to both the protocol actor and the cryptoactor, right?" → no: config
→ ProtocolActor (SectionChanged, protocol.rs:917) → apply_section reads version (937) → credentials::apply →
SectionKeeper::register_secret on CryptoActor (970; ciphertext + binding, nothing kept). Then: "the protocol actor
should not directly hold a username and password, right?"; then "A credential is a combo of a username and a password,
not just a password. The idea was supposed to be that credentials were handled with kids gloves and the protocol actor
itself provides or perhaps the domain side, registers a callback that assists with usage of that credential but they
never actually see it." Found: domain has no route (protocol-handlers.md "No way to the credential", table, built
2026-11-04), BUT handler gets plaintext per request via UseCredential + CredentialPass (perform attaches; doc: "Moving
them there would mean the daemon also makes the request, which is the seam below and not this work"), AND username is
clear in the signed `credentials` section (binding). Maintainer: "sigh..." — the earlier work recorded the seam and the
public username without asking. Then: "I want to be clear on what you mean by 'The holder uses it'" → explained keys
(signing oracle: custody, like the git server's TLS server slot / ssh-agent) vs shared secrets (must go on the wire:
holder makes the request; CryptoActor in-process vs custody out-of-process). Maintainer: "Ok, let's go with that."
DECIDED: keys → custody signs; shared secrets → CryptoActor sends the credentialed request (handler gives judged
request + credential name, gets response only); custody-sent requests recorded as the stronger option for the
foothold work. Whole credential sealed (username inside); migration for existing sections (post-3.0.0 rule).
Steps: C1 seal whole + migrate (polar-sign re-seal; breaking: main first, tell polar-cc — acp's sections/agents use
credentials: git observer, jira, gitlab, orchestrator); C2 CryptoActor sends HTTP; git over HTTPS needs a path
(candidate: in-process proxy the CryptoActor owns that injects Authorization and makes the upstream TLS connection,
libgit2 pointed at it; or gitoxide-based fetch with a request hook); C3 custody signing: ssh (libgit2 ssh-agent
credential via a custody agent socket? git2-rs Cred::ssh_key_from_agent; or gitoxide ssh), client certs (custody client
slot, today only a server slot), Ed25519 for Nix (prereq for NC5). Then R1.. as before.

## DECIDED (maintainer, 2026-11-13, "Ask your questions and then I have to run off for a meeting")
- Migration: "Re-seal everything at once" (not my recommendation of both formats for a release): new format only;
  every credential re-entered with polar-sign before agents of the new version start.
- Git over HTTPS: "Move git fetches to gitoxide" (not my local-proxy recommendation): fetch via daveman1010221/gitoxide
  with a transport hook the CryptoActor fills; git observer and orchestrator source fetch leave libgit2 for fetching.
- SSH: "An ssh-agent from custody": custody speaks ssh-agent protocol on a socket only the handler reaches.
- Rollout: every agent at once; one credential path.
FOUND (to settle in C2/C3): gix's ssh transport shells out to the `ssh` program; agents' seccomp lock refuses new
programs (runtime-attestation "Each agent locks itself") → need an in-process ssh client in the fork (russh, already a
dev-dep of the builder for tests) talking to custody's agent socket. Check git-server's gix-serve fork work for reuse.
NOT STARTED: C1 is breaking for acp (credentials sections of git observer, jira, gitlab, orchestrator) → told polar-cc
before starting; user away at a meeting, C1 waits for the go-ahead.

## REVISED (maintainer, 2026-11-13): "I'd prefer you keep as much of the ssh stuff out of custody daemon as possible.
Please limit the footprint of that work that must go into the custodian."
Supersedes "An ssh-agent from custody". Custody gains ONE generic capability: sign(key name, bytes) → signature, and
public(key name) → public key; Ed25519 (Nix, ssh-ed25519) and the types custody already has (P-256 for TLS). No ssh-agent
protocol, socket, ssh parsing, or Nix/TLS knowledge in custody. SSH: in-process client in the gitoxide fork takes a
Signer trait; the builder implements it (builds nothing ssh-specific beyond passing the exact bytes the client hands it)
by calling custody sign. Same capability serves the registry's Nix key (NC5 prereq) and client certificates (TLS layer in
the builder signs the handshake via custody, as the git server's server slot does).

## PURPOSE-BOUND (polar-cc, 2026-11-13; PROPOSED to the maintainer as the trade with "limit the footprint")
acp has polar-custody Slot::Signer + Request::SignRecord{record}: daemon builds the input in the evidence domain
(polar_signing::signing_input_in), signs only types its cert names (c:record-evidence), refuses NotItsRecordType /
BadRequest; Sign{slot,message} never allowed on the signer slot (key-custody.md "Workload signing keys": one key, one
purpose, custody enforces). A generic sign(named bytes) breaks that (keys forge for each other). Shape: each custody key
has one purpose at creation; per purpose minimal input rule: record → custody builds; nix → input parses as a narinfo
fingerprint `1;/nix/store/<hash>-<name>;sha256:<nix32>;<n>;<refs>`; ssh → userauth blob (string session_id, byte 50
SSH_MSG_USERAUTH_REQUEST, ...); tls → TLS 1.3 CertificateVerify (64×0x20 + context string + 0x00 + hash). No raw sign.
Agreed with polar-cc: bring acp's Slot::Signer + SignRecord to main as the first purpose when step C3 starts (port
together); before that nothing collides.
Settled with polar-cc (2026-11-13): a key's purpose comes from its CERTIFICATE (c:record-evidence:<type> on acp; a
capability naming nix/ssh/tls purpose likewise), not a per-key setting at creation — AGENTS.md "certificates carry
them". acp "bite S" to port at C3: 094e51ae (custody signer slot + SignRecord), 3e704430 (custodian fetches the pod's
signing key), c45ec253 (builder's signer + domain handle); main reads the Signing certificate since 0388d70f.

## C1 DONE 2026-11-13 (maintainer: "Please continue without me.")
Smallest change that holds: the credentials schema marks `username` `{"type":"ciphertext","secret":true}` → polar-sign
(generic: seals every field the schema marks secret, polar-sign/src/seal.rs) seals it with NO polar-sign code change,
bound `<agent>|credentials|<version>|<name>|username` (own field, same entry: cannot be paired with another entry's
secret). Section check (credentials.rs `entry`): a username must be an escrowed secret by its bytes (`secret_problem`),
else "`username` … a user name is sealed, as the secret is, and polar-sign seals it". `apply` hands it on as
`polar_crypto::SealedPart {ciphertext, context}`; the binding carries no username. CryptoActor `RegisterSecret` gains
`username: Option<SealedPart>`; `register_secret` refuses a binding naming a username ("a user name comes sealed, never in
the binding"), opens the sealed one in custody, holds it to `registry::is_username` (1..=MAX_USERNAME 128, no control),
puts it in its own binding, then `binding.check()`. Escrow record (escrow_form) unchanged: it already holds username
inside. Not "sealed whole" as one blob: two sealed fields bound to the same entry — the same property (neither clear,
not separable). Reach: an existing section fails only where an entry names a username (Jira Cloud email+token: seed.nu
writes `username: $email`, sealed by polar-sign from the new scaffold with no seed change); tokens and ssh keys without
one stay valid. Tests: crypto (sealed username → Basic; clear-in-binding refused; sealed under another field's context →
DecryptFailed; empty / control → BadBinding; helpers seal any test binding's username), builder (clear username refused,
schema marks it secret, apply hands it on under `…|username`, polar-sign's own seal_body with this schema seals both).
Suites: builder 692, polar-crypto 102, polar-sign 159; workspace check all-targets clean. Mutants: crypto
register_secret/is_username 8/8 caught; builder entry/apply/context 13 caught + 2 unviable (3 older gaps in the binding
field-naming closed with a test). Docs: jira.md, git-controller.md. NOT DEPLOYED: u7c agents rebuild at the next
bring-up; then a Jira user-password credential must be re-sealed by the user.

## C2 DESIGN (2026-11-13, written while the maintainer was away; APPROVED the same day)
Maintainer: "Is cryptoa actor using the protocol actor for this or something else?" → explained: protocol actor keeps
judging, recording, building the request without credential; hands the CryptoActor the request + ITS OWN client + the
credential's name; CryptoActor checks binding, attaches, sends with that client, returns response + facts. Maintainer:
"That's the part I was looking for, sends the request with the protocol actor's client. It doesn't actually put a bunch
of HTTP code in the crypto actor. Then yes, I'm good with that." Caveat told: for a registry the CryptoActor also reads
the auth host's token reply (small JSON), since the token it keeps is the secret.
Found reading http.rs: today `run` → admit → `CredentialSource::http(name, host)` → CryptoActor `UseCredential` returns
plaintext `HttpCredential` (Bearer | Basic{username, password}) → `perform(.., credential, ..)` → `attach()` puts it on
the reqwest RequestBuilder and computes `Presented` + `looks_base64` from it. Registry path (`at_a_registry`):
`answer_challenge` sends the login (Basic) to the auth host named by the WWW-Authenticate challenge (judged hop), parses
`{token|access_token}` (≤ MAX_TOKEN_REPLY), and presents that DERIVED bearer token to the registry; the handler holds it.
Redirect hops re-admit (binding checked per host). git.rs: `CredentialSource::git` → plaintext `GitCredential` → libgit2
callbacks (`Cred::userpass_plaintext`, `ssh_key_from_memory`).
Proposed (each for review):
- polar-crypto gains reqwest (already linked into every agent via the builder; one-artifact unchanged) and a message
  `SendWithCredential { pass, name, host, request: reqwest::Request, client: reqwest::Client }`: the handler builds the
  request WITHOUT auth, with its own client (egress proxy + roots), the CryptoActor checks the binding names the
  request's host, attaches Bearer/Basic, executes, and replies with the reqwest::Response (body streams to the handler,
  which reads it as now) plus the facts (`Presented`, `looks_base64`) it computed. Each redirect hop is a new
  SendWithCredential, so the binding is checked per hop in the holder.
- Registry auth: `SendToRegistry { pass, name, scope, request, client }`: the CryptoActor runs the challenge exchange
  itself (realm judged by the handler first: the handler passes the judged realm URL, so judging stays in the judge), and
  KEEPS the derived token (per credential + realm + scope, until its `expires_in` or a 401) — the handler never holds it.
  Moves bearer_challenge parsing + TokenReply into polar-crypto (or a small shared crate both use).
- Protocol trait: `type Credential` for Http becomes a reference (name + the CredentialPort), never plaintext;
  `CredentialSource::http` returning plaintext is removed; the `domain_has_no_way_out` test extended: no plaintext
  credential type reachable from the builder's protocol code except inside polar-crypto.
- C2c git: fetch on gitoxide (daveman1010221/gitoxide, pinned rev) with an HTTP transport whose requests go through
  SendWithCredential; ssh fetch waits for C3's signer.
- Bites: C2a plain HTTP (Bearer/Basic, hops); C2b registry exchange; C2c git over HTTPS on gitoxide. "Every agent at
  once": none deployed until C2a–C2c are all in; the old path removed in the same series.
Open for the maintainer: polar-crypto owning an HTTP client and the OCI token exchange (alternative: a separate
"credentialed-sender" actor in the builder that receives the plaintext from the CryptoActor — rejected by me: it is
the handler again under another name).

## OPEN
- `uses` vocabulary (nix|crates|oci|git; per-build scoping) — settle with other faces.
- Certificate-as-credential kind (mTLS client auth to a remote) — new SecretKind.
- Does the configuration agent (scheduler observer) need anything new? Runtime sections already flow; sealed entries
  need polar-sign support only (like credentials).
