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

## OPEN
- `uses` vocabulary (nix|crates|oci|git; per-build scoping) — settle with other faces.
- Certificate-as-credential kind (mTLS client auth to a remote) — new SecretKind.
- Does the configuration agent (scheduler observer) need anything new? Runtime sections already flow; sealed entries
  need polar-sign support only (like credentials).
