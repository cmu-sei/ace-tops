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

## OPEN
- `uses` vocabulary (nix|crates|oci|git; per-build scoping) — settle with other faces.
- Certificate-as-credential kind (mTLS client auth to a remote) — new SecretKind.
- Does the configuration agent (scheduler observer) need anything new? Runtime sections already flow; sealed entries
  need polar-sign support only (like credentials).
