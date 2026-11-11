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

Status, 2026-11-10: research, and a plan proposed from it, not yet cleared. Owner: the runtime attestation session, at the
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

1. **Every entry says its event's type and version, inside what is hashed.** An entry written from now on carries
   `{"type": "Revoke", "version": 2, "data": ...}` as its event; an entry without one is version 1 of the type its variant
   names. The chain's rule is unchanged: the bytes on disk are what is hashed.
2. **New readers upcast; nobody rewrites.** In-place transformation would break the chain, which is the point of the
   log, so it is out. Each change of an event's shape adds a version and an upcaster from the one before, applied as the
   log is replayed, so the state is folded from the current shape alone.
3. **Old readers follow X.509's rule.** Each event type is declared *critical* (its state must be understood: a grant, a
   revocation, an issuance, a secret, the authority's sequence) or not (a record of a refusal, a report already made).
   Every type is critical unless it is declared otherwise. A reader that meets a critical type or version it does not
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

## References

The works are in [`docs/reference/citations.md`](../reference/citations.md), "Event-sourced logs and their evolution":
`overeem2021empirical`, `young2017versioning`, `fowler2011tolerant`, `axoniq2025versioning`, `akka2025schema`,
`sigstore2025pluggable`, `cloudevents2022spec`, `google2025proto3`, `cooper2008rfc5280`, `confluent2025evolution`.
