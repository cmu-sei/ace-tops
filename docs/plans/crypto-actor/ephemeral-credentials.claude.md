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

# ephemeral-credentials — Claude's side

PAIR: `ephemeral-credentials.md` (people). Same plan, two forms; change together.
SPLIT: people side has no dates, attributions, quotes, codenames or branch/process status; those live here.
PARENT: `../crypto-actor.claude.md` (step E). AS-OF main 246317eb (R1), 2026-11-14. Re-verify `file:line`.
STATUS: PROPOSAL, nothing built. Written by polar-cc at the maintainer's request; for polar-f1's read against main, then
the maintainer clears it.

## ORIGIN (the maintainer, 2026-11-14)
- Idea: "crypto actor could access stored credentials ephemerally, encrypting them with a key from the custodian when
  they're not actively being used". Asked after polar-cc confirmed the CryptoActor holds registered credentials in the
  clear.
- Cost: "we already did benchmarking on key operations on the custodian when we built it and it benchmarks at about 320k
  key operations per second on my hardware, so a decrypt, use, and wipe for a credential is far under a millisecond, for
  an operation that should be low-rate." (key-custody.md "Step 6, the speed gate": daemon ~320,000 signatures/s at 32
  and 128 callers; 1 caller adds 0-21 µs. Those are SIGNATURES; an Unwrap (ECDH + AES-GCM open) is not measured yet:
  measure it in the release bench, expect the same order.)
- Hardening: "We should definitely take the same measures to protect crypto actor that we currently take to protect the
  custodian, if possible."
- CORRECTION (the maintainer, 2026-11-14, relayed by the coordinator): "no core dumps" cuts against attestation's work to
  close the assurance loop. An agent's crash is counter-evidence; its diagnosis (missed, tampering, hardware,
  unexplained) may need the dump. Agents stay DUMPABLE; never propose PR_SET_DUMPABLE 0 for agents or call it "as the
  custodian does". Keep secrets out of the dump while the dump stays whole: MADV_DONTDUMP / memfd_secret, locked pages,
  not mlockall. (attestation-threat-model: crash events are gold.)
- User name: "I consider the username part of the stored credential and we should treat it the same as a stored
  password."
- Framing: "We're making the case that we are trying to do zero trust correctly and this is how we get there".
- Earlier the same day the maintainer: honest about hardware (TPM/HSM/enclaves accepted, not trusted); this is the
  software-side step instead.

## FACTS@main 246317eb
- RegisteredSecret polar-crypto/src/lib.rs:808: `secret: Zeroizing<Vec<u8>>` (wiped on drop only); inserted at :1868
  and :1972 after one open at registration.
- User name: opened at :1861 into `binding.username = Some(opened.to_string())`: plain String, NOT zeroized
  (registry.rs SecretBinding.username :162).
- Registry tokens: `type Tokens` :805, `HashMap<u64, Zeroizing<Vec<u8>>>`, plaintext until the handle is released;
  send_with_token :419.
- Opening: handle_decrypt_own_escrowed :2089 -> open_escrowed :1717 -> custody `Request::Unwrap { wrapped }`
  (polar-custody/src/protocol.rs:77) -> 32-byte AES key back to the CryptoActor, which opens the AES-GCM body. So
  "custody opens" today = custody unwraps the data key; the CryptoActor holds the data key and plaintext transiently.
  Without a daemon nothing is asked (degraded: cannot open).
- Custody hardening: polar-custody/daemon/src/lib.rs:75 mlockall(MCL_CURRENT|MCL_FUTURE|MCL_ONFAULT); main.rs:141
  PR_SET_DUMPABLE 0 (custody keeps both). Agent processes: only the builder's worker CHILD sets dumpable 0
  (polar-agent-builder/src/worker.rs:195); the agent process stays dumpable (intended, see CORRECTION).
- ptrace: the builder's seccomp lock REFUSED list (polar-agent-builder/src/lock.rs:59-70) refuses ptrace,
  process_vm_readv, process_vm_writev (and memfd_create) whatever their arguments, in every agent. memfd_secret
  (SYS 447) is not on the list. Agents share no PID namespace with their pod's other containers (key-custody.md).
- ssh keys: CredentialSource::git gives an ssh key to the git transport (lib.rs :270, :437-438, :1476): the one stated
  exception to "sent, never given" (step 2c).

## DESIGN
E1 Sealed at rest: RegisteredSecret keeps the escrowed form (ciphertext + context as received), not the plaintext.
   Registration: open once (shape + binding check via registry::escrow_form), wipe. Each credentialed send: Unwrap ->
   open -> put on the request -> send -> wipe (data key and plaintext Zeroizing, dropped before the response is read
   back where possible).
E2 User name sealed with it: keep the sealed user name (SealedPart) as received; open per use with the secret; Zeroizing
   String. The binding at rest carries no user name.
E3 Registry tokens: on arrival, seal to the pod's own escrow public key (the CryptoActor already seals to a
   recipient's escrow key for escrow: reuse that path, recipient = self); keep only the sealed form; open per send.
E4 Custody records each Unwrap: who (SO_PEERCRED), when, which wrapped (digest, never content). Open count/rate per
   credential as a detection signal (attestation threat model: detection first). How it's read: custody log line first;
   a counter the health actor exposes later, decided when built.
E5 Secrets out of the dump, dump whole (NOT PR_SET_DUMPABLE 0 for agents):
   - A small arena for opened data keys and plaintexts (and the CryptoActor's held keys: the record key, the checkpoint
     key, the witness key): its pages mlock'd + MADV_DONTDUMP; from memfd_secret(2) where present (never dumped,
     removed from the kernel's direct map; Linux >= 5.14, some distros need `secretmem.enable`; not refused by the
     seccomp lock). The agent stays dumpable, so a crash's core file is whole for diagnosis and holds no secret.
   - NOT whole-process mlockall (an agent is large; MCL_FUTURE past RLIMIT_MEMLOCK makes allocations fail).
   - CHECK: RLIMIT_MEMLOCK in u7c pods (containerd default), nix-usernetes node kernels for memfd_secret, and whether the
     render sets a memlock limit for agents (from what the machine has).
E6 Tests first: properties (no plaintext credential in the registry at rest; each credentialed send opens exactly once
   and wipes; recorded opens == sends); a release-build bench of a credentialed request with and without E1.

## ALTERNATIVES (rejected)
keep as is | separate wrap key in custody (escrow key already seals, same purpose) | lock/hide the secrets' pages only
(no help vs disclosure bugs, checkpoints, snapshots) | PR_SET_DUMPABLE 0 for agents (blinds crash diagnosis; crashes are
the case's strongest counter-evidence; custody keeps it, being small and keys only) | whole-agent mlockall (size,
RLIMIT_MEMLOCK).

## LEFT EVEN THEN (honest)
- hyper header values and rustls records hold the credential during the request; not wiped. Shorter exposure, not zero.
- Code execution in the agent can ask custody to Unwrap as the CryptoActor does; E4's record is the answer, not a block.
- ssh key to the git transport (2c exception): whether gix can take a per-connection opened key; follows trusted-remotes
  C3 (custody signs for ssh), which removes it.

## OPEN (for the maintainer only if two answers stay open; else decide by precedent)
- E4's surface: log line vs counter (decide when built).
- E5 memory: the arena's size and the memlock limit the render sets (from what the machine has; a hint never widens).
