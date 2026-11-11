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

# The credentials ledger's evolution

Status, 2026-11-10: research (the evolution of events, then the file format), and a plan proposed from it, not yet
cleared. Owner: the runtime attestation session, at the
maintainer's word. The item it answers is in `remaining-work.md`, "A ledger written by newer code stops an older
credentials agent".

## The problem

The credentials agent keeps its state as an append-only, hash-chained log of events (`lib/src/event_log.rs`; the
events are `credentials-agent/common/src/events.rs`, `CredentialsEvent`), replayed whole at every start
(`credentials-agent/consume/src/ledger.rs`, `open_log`). An entry is `{timestamp, prev_hash, event, hash}`; the event is
serde's JSON of the enum, its variant's name as the only mark of what it is. Nothing says which version of an event an
entry holds, or which code wrote it.

So a log is readable only by code that knows every word in it. On u7c, the agentic-control-plane branch wrote words main
does not know: a certificate type `signing` (inside `IssuanceCompleted`), a `RevocationRecorded` event (K3), secrets
sealed again to a P-256 key (K2, `SecretStored`), and beside the log a P-256 escrow key file that main's code reads as
RSA. Main's agent replaying it stops at the first unknown word with serde's error ("unknown variant `signing`", line
13406), its start fails, the pod restarts, and it fails the same way. Stopping is right, since a reader that skips what
it does not understand could skip a revocation; stopping without saying why, again and again, is not.

The reverse is as open. Nothing says how new code reads old events whose shape has changed: renaming a field would
break the replay of every ledger written before.

## What others who build event-sourced logs do

**The five tactics** (`overeem2021empirical`: 19 event-sourced systems, 25 engineers, grounded theory). Practitioners
evolve a log by *versioned events* (a new event type beside the old), *weak schema* (events described minimally, read by
a tolerant reader, `fowler2011tolerant`), *upcasting* (an old event turned into the current shape as it is read; the
log untouched), *in-place transformation* (the stored events rewritten) and *copy-and-transform* (a new log written from
the old, the old left as it was). The paper's order of preference: the first two while they suffice, then upcasting,
copy-and-transform when performance or upkeep demand it, and in-place transformation only where neither immutability
nor an audit trail is required. Most systems combine several. Young's book (`young2017versioning`) is the source of much
of this vocabulary (weak schema, copy and replace, upcasting).

**The type and its version travel with each event.** Axon stores each event's type name and revision (`@Revision`),
and upcasters take revision *x* to *x+1*, in order (`axoniq2025versioning`). Akka stores a manifest with each event, and
event adapters promote old events to the current shape during recovery, so domain code sees one version
(`akka2025schema`). Rekor, a transparency log, gives each entry a `kind` and an `apiVersion`, serves several versions
of a kind at once, and refuses to insert one it does not support (`sigstore2025pluggable`). CloudEvents carries the
event's `type` and its `dataschema`, and an incompatible change to the data SHOULD change the schema's URI
(`cloudevents2022spec`).

**Readers older than the writer.** The answers differ by what is at stake. Protocol buffers keep unknown fields and
unknown enum values and write them back out (`google2025proto3`); CloudEvents' receivers may ignore extension attributes
they do not know; the tolerant reader ignores what it does not need. Where ignoring is unsafe, X.509 marks each extension
critical or not: a certificate-using system MUST reject a certificate with a critical extension it does not recognize,
and MAY ignore a non-critical one it does not recognize (`cooper2008rfc5280`, section 4.2). Akka's example serializers
fail on a manifest they do not handle, so recovery stops.

**Compatibility as a checked rule.** A schema registry checks each new schema against the old ones before it is used:
*backward* (a consumer on the new schema reads data written with the old; consumers are upgraded first), *forward* (a
consumer on the old schema reads data written with the new; producers first), *full* (both), and each *transitive*
over every earlier version, not only the last (`confluent2025evolution`). Protocol buffers make the same rules into
practice: never reuse a field number, reserve deleted ones, and only add.

## What it means for this ledger

The ledger is not a typical event store. Its history is evidence (the hash chain makes it tamper-evident), its writer and
its reader are one process, a stopped reader stops every issuance in the cluster, and a reader older than the writer is
real: a rollback of the images, or main's agent deployed over a branch's ledger as on u7c. From the above:

1. **Every entry says its event's type, version and criticality, inside what is hashed.** An entry written from now on
   carries them in an envelope before the event (its encoding: "The file format", below); an entry without one is version
   1 of the type its variant names. The chain's rule is unchanged: the bytes on disk are what is hashed.
2. **New readers upcast; nobody rewrites.** In-place transformation would break the chain, which is the point of the
   log, so it is out. Each change of an event's shape adds a version and an upcaster from the one before, applied as the
   log is replayed, so the state is folded from the current shape alone.
3. **Old readers follow X.509's rule.** Each event type is declared *critical* (its state must be understood: a grant, a
   revocation, an issuance, a secret, the authority's sequence) or not (a record of a refusal, a report already made).
   Every type is critical unless it is declared otherwise, and the writer sets the mark in each entry, as X.509 puts it in
   the certificate, so a reader decides about a type it has never heard of. A reader that meets a critical type or version it does not
   know refuses to serve: it stays up, held unhealthy with one line saying which version wrote the log and which this
   is (`polar-agent-builder/src/health.rs`, `HealthHandle::hold`), and never crash-loops; it does not replay, so it loads
   no key. One that meets a non-critical type it does not know passes over it, counts it and says so. A new variant of an
   enum inside an event (`signing`) is a new version of that event.
4. **Compatibility is checked, transitively.** Each version of each event is recorded as a sample, and a test holds
   every sample of every version readable by the current code (backward, transitive), and the current writer to the
   samples of the version it declares. A change of shape without a new version and its upcaster fails the build, as does
   a type without a declared criticality.
5. **What cannot be read going back is copied going forward.** A rollback past a critical change is not something an
   older reader can be made to do; it needs copy-and-transform: a new log whose first entry names the old log's last hash,
   written in the older shape by the newer code, the old log kept as it is. Nothing builds that now; what a rollback
   needs is recorded with each critical change (`key-custody.md`, "What a migration needs"), and recovery meanwhile is
   to deploy the newer version.
6. **The escrow key file is read after the ledger.** The agent opens the ledger before it loads its keys
   (`consume/src/supervisor.rs`), so the refusal in 3 comes first, and the key file needs no version of its own; its
   own refusal (an RSA reader given P-256) is a plain message too.

What no change can do: agents already released (3.0.x, and main as it is today) know none of this, and stop on a newer
ledger as before. The fix holds for every version from the one that carries it.

## A proposed classification, for review

| Event | Critical | Why |
|---|---|---|
| `Grant`, `Revoke`, `IssuanceCompleted`, `SecretStored`, `AgentEscrowIssuanceCompleted`, `AccountProvisioned`, `AccountCertificateIssued`, `AdminActionRecorded` | yes | the state they fold is who may do what, what is issued and revoked, and what is escrowed |
| `AuthorityPublished` | yes | its sequence must go on rising across restarts; a reader that passes over it could publish a number again |
| `CertificatesReported` | yes | it moves the cursor into cert-issuer's record and the supersessions it implies |
| `AuthorityRefused`, `InstanceRefused`, `IssuedUnattested` | no | they fold nothing: a record of what was refused or let through |
| `AttestationReported`, `RevocationRecorded` | no | they fold only "already done": a reader that passes over one may report or record it again, a duplicate (a second evidence record of the same revocation), not a wrong state |

## The file format

JSON was taken because serde made it easy, not chosen against anything. The maintainer prefers formats with properties
like rkyv's, which Cassini's wire already uses: zero-copy access to typed data, validation of untrusted bytes before
access, Rust types as the schema, and speed. A ledger also needs what the sections above found: events that evolve, a
reader that knows what it does not understand, and, for hashing or signing a value rather than its bytes, a
deterministic form. Read 2026-11-10.

**Two layers.** Transparency logs keep the container and the entries apart: C2SP's tiled logs hold entries as
length-prefixed bytes, opaque to the log, under an RFC 6962 Merkle tree with signed checkpoints (`c2sp2025tlogtiles`);
SCITT's transparency service treats each signed statement's content as opaque and returns a receipt proving its
inclusion (`ietf2025scitt`). So the choice is two choices: how an entry is encoded, and how entries are chained.

**The encodings weighed.**

| | rkyv | Cap'n Proto | FlatBuffers | musli-zerocopy | CBOR (deterministic) |
|---|---|---|---|---|---|
| Zero-copy, typed | yes | yes | yes | yes | no (decoded) |
| Untrusted bytes | validated up front (bytecheck) | validated as read, traversal and nesting limits | verifier | validated as read | decoded |
| Evolution in the format | none | add fields by ordinal | add fields at the end, deprecate | none | by convention |
| Canonical form | none defined | defined (for hashing and signing) | none | none | RFC 8949, 4.2 |
| Schema | Rust derives | IDL with stable ids, code generated | IDL, code generated | Rust derives | CDDL |
| Rust | 0.8; Cassini uses it | `capnp` 0.27, with `canonicalize` | three RustSec advisories, one critical in generated code | 0.1 | serde crates |

- *rkyv* (`rkyv2026docs`, `rkyv2026comparison`): its own comparison lists no schema evolution, and archived data is
  readable only while the schema is unchanged, the data was written by a semver-compatible rkyv, and its format features
  are the same. Evolution therefore lives outside it: each version of each event is a Rust type frozen once written,
  and an entry says which it is.
- *Cap'n Proto* (`capnproto2025encoding`, `capnproto2025language`, `capnprust2026`): evolution is in the layout (a
  field's place depends only on its definition and those numbered before it; a reader sees an unknown new field as
  nothing, and an absent one as its default), there is a canonical form for hashing and signing, and readers of
  untrusted messages MUST bound traversal and nesting. The cost is a schema language and generated code beside the Rust
  types, and a reader that silently does not see new fields, so criticality is still the envelope's to carry.
- *FlatBuffers* (`flatbuffers2025evolution`, `flatbuffers2025rust`): evolution and a verifier, but its Rust crate has
  three soundness advisories, the last (RUSTSEC-2021-0122, critical) in generated code that reads and writes out of
  bounds in safe code (`rustsec2021flatbuffers`). Not for this ledger.
- *musli-zerocopy* (`musli2025zerocopy`): safe and validated as it is read, but at 0.1 and with no evolution.
- *CBOR* (`bormann2020rfc8949`): a standard deterministic encoding (shortest forms, definite lengths, sorted map keys),
  CDDL for a schema, and COSE and SCITT built on it, but decoded rather than read in place: not what is preferred.

**What follows.**
1. *The envelope carries what a reader needs before it knows the type*: the type, its version, and whether it is
   critical, set by the writer, as X.509 puts the critical bit in the certificate, so a reader that has never heard of a
   type still knows whether it may pass over it. Then the event's bytes.
2. *The event's bytes are rkyv's, in a version frozen per type* (recommended): versioned events and upcasting, the
   tactics the evolution study ranks first, need no evolution from the encoding itself; a new field is a new version and
   an upcaster. Every reader validates before it reads. rkyv's own format is pinned (its major version and format
   features); moving it is a copy-and-transform into a new log, as any breaking change is. Its schema is the frozen Rust
   types, recorded as archived samples for the compatibility test. *Or Cap'n Proto*, if an IDL apart from the code,
   checked by its own compiler and readable by other languages, and a canonical form for signing values, weigh more than
   one stack and no code generation.
3. *The container frames each entry as length-prefixed bytes*, opaque to the chain, whichever encoding is chosen. The
   chain can stay linear (what is hashed: the previous hash, the time and the entry's bytes), or become a Merkle tree
   with signed checkpoints as transparency logs are, which lets someone other than the agent check that an entry is in
   the ledger and that the ledger only grew, without reading all of it. Not needed by the agent itself; it is what an
   audit of the ledger by others would want.
4. *A binary ledger needs a reader for people*: a command that prints a ledger's entries, their versions and their chain,
   so an operator or an auditor reads it as easily as the JSON now.

## References

The works are in [`docs/reference/citations.md`](../reference/citations.md), "Event-sourced logs and their evolution":
`overeem2021empirical`, `young2017versioning`, `fowler2011tolerant`, `axoniq2025versioning`, `akka2025schema`,
`sigstore2025pluggable`, `cloudevents2022spec`, `google2025proto3`, `cooper2008rfc5280`, `confluent2025evolution`; and for
the file format, `rkyv2026docs`, `rkyv2026comparison`, `capnproto2025encoding`, `capnproto2025language`, `capnprust2026`,
`flatbuffers2025evolution`, `flatbuffers2025rust`, `rustsec2021flatbuffers`, `musli2025zerocopy`, `bormann2020rfc8949`,
`c2sp2025tlogtiles`, `ietf2025scitt`.
