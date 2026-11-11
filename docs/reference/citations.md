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

# Citations

The works Polar's design relies on, by key. How to add one is in [`README.md`](README.md); the same entries are in
[`references.bib`](references.bib). Checked 2026-10-22.

## Datalog and its engine

### `sahebolamri2022ascent`

Arash Sahebolamri, Thomas Gilray and Kristopher Micinski. "Seamless Deductive Inference via Macros." In *Proceedings of
the 31st ACM SIGPLAN International Conference on Compiler Construction (CC '22)*, Seoul, 2022. 12 pages.
https://doi.org/10.1145/3497776.3517779

- Read it: the authors' copy, https://s-arash.github.io/ascent/cc22main-p95-seamless-deductive-inference-via-macros.pdf.
  Link only: published under the ACM's usual terms, which allow copies for personal or classroom use and not
  redistribution.
- What it is: Ascent, Datalog embedded in Rust by procedural macros, with lattices and user-defined types; the Rust
  borrow checker reimplemented in it, benchmarked against Datafrog, Flix and Soufflé.
- Why it matters to Polar: it is the engine of the authority model's rules, chosen after the research recorded there.
- Cited by: `docs/architecture/authority-model.md` ("The engine", "Ascent, researched").

### `sahebolamri2023byods`

Arash Sahebolamri, Langston Barrett, Scott Moore and Kristopher Micinski. "Bring Your Own Data Structures to Datalog."
*Proceedings of the ACM on Programming Languages* 7 (OOPSLA2), Article 264, October 2023. 26 pages.
https://doi.org/10.1145/3622840

- Read it: [`sahebolamri2023byods.pdf`](sahebolamri2023byods.pdf), from https://dl.acm.org/doi/pdf/10.1145/3622840.
  Licensed CC BY 4.0, "copyright held by the owner/author(s)".
- What it is: the formal semantics of Ascent's data-structure parameterization (BYODS), including what semi-naïve
  evaluation requires of a relation's representation; applications include an optimized Polonius and lattice-based
  PageRank.
- Why it matters to Polar: the semantics behind the engine's relations and lattices, which the authority model's witness
  lattice relies on.
- Cited by: `docs/architecture/authority-model.md` ("Ascent, researched").

### `ceri1989datalog`

Stefano Ceri, Georg Gottlob and Letizia Tanca. "What You Always Wanted to Know About Datalog (And Never Dared to Ask)."
*IEEE Transactions on Knowledge and Data Engineering* 1 (1): 146–166, 1989.

- Read it: the publisher's, through IEEE Xplore; the University of Oxford's record,
  https://ora.ox.ac.uk/objects/uuid:e12b804d-d586-4065-aa6f-bcde52d78a21. Its DOI was not confirmed when this entry was
  written.
- What it is: the classic survey of Datalog's syntax, semantics, evaluation (bottom-up, semi-naïve) and extensions,
  written for readers new to logic programming.
- Why it matters to Polar: the background for the authority model's rules: recursion, stratified negation, and why a
  bottom-up evaluation always ends.
- Cited by: `docs/architecture/authority-model.md` ("Rules over the model").

## Authorization

### `cutler2024cedar`

Joseph W. Cutler, Craig Disselkoen, Aaron Eline, et al. "Cedar: A New Language for Expressive, Fast, Safe, and
Analyzable Authorization." *Proceedings of the ACM on Programming Languages* (OOPSLA 2024).
https://doi.org/10.1145/3649835. Extended version: https://arxiv.org/abs/2403.04651

- What it is: the design of Cedar, the policy language Polar uses: its non-recursive, analyzable semantics, its schema
  and validation, and its SMT-based analysis.
- Why it matters to Polar: every policy decision in Polar is Cedar's (`polar-policy`); its deliberate lack of recursion
  is why the authority model adds Datalog beside it, never in place of it.
- Cited by: `docs/architecture/authority-model.md` ("Rules over the model", "Acceptance as a comparison").

### `oasis2013xacml`

OASIS. *eXtensible Access Control Markup Language (XACML) Version 3.0*. OASIS Standard, 22 January 2013. Edited by Erik
Rissanen. https://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html

- What it is: the access-control standard whose glossary names the policy administration point (PAP), decision point
  (PDP) and enforcement point (PEP).
- Why it matters to Polar: the authority model uses those names: the credentials agent is the administration point; the
  broker and every agent decide and enforce.
- Cited by: `docs/architecture/authority-model.md` ("The proposal").

### `pang2019zanzibar`

Ruoming Pang et al. "Zanzibar: Google's Consistent, Global Authorization System." In *2019 USENIX Annual Technical
Conference (USENIX ATC '19)*, Renton, WA, 2019, pages 33–46.
https://www.usenix.org/conference/atc19/presentation/pang

- What it is: a global store and evaluator of access-control relations, deciding by relationships between objects and
  subjects rather than by attributes.
- Why it matters to Polar: the main alternative to the attribute-and-policy approach Polar takes with Cedar; worth
  knowing when groups and relations grow.
- Cited by: none yet.

## Software

### `ascent`

The `ascent` crate: logic programming in Rust. MIT licence. https://github.com/s-arash/ascent, https://crates.io/crates/ascent,
documentation at https://s-arash.github.io/ascent/. Version 0.8.1 (2026-08-29) when it was chosen. Cited by:
`docs/architecture/authority-model.md`.

### `polonius`

Polonius, the Rust borrow checker formulated in Datalog, evaluated with Datafrog. https://github.com/rust-lang/polonius.
The work both Ascent papers reimplement as a benchmark. Cited by: none yet.

## Event-sourced logs and their evolution

Read 2026-11-10, for the credentials ledger's evolution (`docs/architecture/ledger-evolution.md`).

### `overeem2021empirical`

Michiel Overeem, Marten Spoor, Slinger Jansen and Sjaak Brinkkemper. "An Empirical Characterization of Event Sourced
Systems and Their Schema Evolution — Lessons from Industry." *Journal of Systems and Software* 178 (2021), 110970.
https://doi.org/10.1016/j.jss.2021.110970. Preprint: https://arxiv.org/abs/2104.01146

- Read it: [`overeem2021empirical.pdf`](overeem2021empirical.pdf), the arXiv preprint (v1), under CC BY-NC-ND 4.0,
  which allows an unchanged copy to be shared for non-commercial use.
- What it is: a grounded-theory study of 19 event-sourced systems and 25 engineers: the five tactics by which they evolve
  their events (versioned events, weak schema, upcasting, in-place transformation, copy-and-transform), with their
  trade-offs and an order of preference, and what immutability means in practice.
- Why it matters to Polar: the credentials ledger is an event-sourced, hash-chained log; the tactics, and which of them
  keep a log immutable, are what its evolution is chosen from.
- Cited by: `docs/architecture/ledger-evolution.md`.

### `young2017versioning`

Greg Young. *Versioning in an Event Sourced System*. Leanpub, 2017. https://leanpub.com/esversioning, free to read at
https://leanpub.com/esversioning/read

- Read it: online, free; link only (no licence for copies). For this work only its contents were read, for its
  vocabulary: type-based versioning, weak schema, negotiation, copy and replace, copy-transform, upcasting state.
- What it is: the practitioner's book on changing events in an event-sourced system without rewriting them.
- Why it matters to Polar: the names the tactics go by, and the case for never updating a stored event.
- Cited by: `docs/architecture/ledger-evolution.md`.

### `fowler2011tolerant`

Martin Fowler. "Tolerant Reader." Bliki, 9 May 2011. https://martinfowler.com/bliki/TolerantReader.html

- What it is: a consumer that reads only what it needs and ignores the rest, so a provider can add without breaking it.
- Why it matters to Polar: the reading that weak schema relies on, and what the ledger must not do with a critical event.
- Cited by: `docs/architecture/ledger-evolution.md`.

### `axoniq2025versioning`

AxonIQ. "Event Versioning." *Axon Framework Reference Guide* 4.12.
https://docs.axoniq.io/axon-framework-reference/4.12/events/event-versioning

- What it is: Axon's versioning: each stored event carries its type name and revision (`@Revision`), and ordered
  upcasters take revision *x* to *x+1*, one event to one or many.
- Why it matters to Polar: the model for the ledger's per-type versions and its chain of upcasters.
- Cited by: `docs/architecture/ledger-evolution.md`.

### `akka2025schema`

Akka. "Schema Evolution for Event Sourced Actors." *Akka core documentation* 2.10.
https://doc.akka.io/libraries/akka-core/current/persistence-schema-evolution.html

- What it is: manifests stored with each event, and event adapters that promote old events to the current shape during
  recovery, so domain code handles one version; a manifest the serializer does not handle fails.
- Why it matters to Polar: promotion at replay, and stopping on what cannot be read, as the ledger does.
- Cited by: `docs/architecture/ledger-evolution.md`.

### `sigstore2025pluggable`

Sigstore. "Pluggable Types." *Rekor documentation*. https://docs.sigstore.dev/logging/pluggable-types/

- What it is: a transparency log whose entries carry a `kind` and an `apiVersion`, several versions of a kind served at
  once, and an insert of an unsupported version refused.
- Why it matters to Polar: a tamper-evident log with typed, versioned entries, as the ledger is to become.
- Cited by: `docs/architecture/ledger-evolution.md`.

### `cloudevents2022spec`

CNCF CloudEvents. *CloudEvents — Version 1.0.2*. https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/spec.md
(read at the repository's head, 1.0.3-wip)

- What it is: a common envelope for events: `specversion`, `type`, `source`, `dataschema`, and extension attributes a
  receiver may ignore; an incompatible change to the data SHOULD change the schema's URI.
- Why it matters to Polar: type and schema version carried with each event, outside its data.
- Cited by: `docs/architecture/ledger-evolution.md`.

### `google2025proto3`

Google. "Language Guide (proto 3)." *Protocol Buffers documentation*. https://protobuf.dev/programming-guides/proto3/

- What it is: how protocol buffers evolve: unknown fields and enum values kept and written back, field numbers never
  reused, deleted ones reserved.
- Why it matters to Polar: the rules for changing an event's shape compatibly, and an example of tolerance where it is
  safe.
- Cited by: `docs/architecture/ledger-evolution.md`.

### `cooper2008rfc5280`

D. Cooper, S. Santesson, S. Farrell, S. Boeyen, R. Housley and W. Polk. *Internet X.509 Public Key Infrastructure
Certificate and Certificate Revocation List (CRL) Profile*. RFC 5280, May 2008. https://doi.org/10.17487/RFC5280

- What it is: the X.509 profile; its section 4.2 is the rule that a system MUST reject a certificate with a critical
  extension it does not recognize, and MAY ignore a non-critical one.
- Why it matters to Polar: the rule the ledger's readers follow for event types they do not know.
- Cited by: `docs/architecture/ledger-evolution.md`.

### `confluent2025evolution`

Confluent. "Schema Evolution and Compatibility for Schema Registry on Confluent Platform."
https://docs.confluent.io/platform/current/schema-registry/fundamentals/schema-evolution.html

- What it is: compatibility types checked before a schema is used: backward, forward and full, each also transitive
  over every earlier version, and the order in which consumers and producers must be upgraded for each.
- Why it matters to Polar: compatibility as a rule a test checks, transitively, rather than a hope.
- Cited by: `docs/architecture/ledger-evolution.md`.
