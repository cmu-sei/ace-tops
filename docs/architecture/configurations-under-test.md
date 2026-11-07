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

# Configurations under test (designing, 2026-11-07)

**Why.** Polar's deployment is tight: the catalog is the sign-off, the render is signed and published, the floor admits only
what the catalog and the target name, the attestation agent watches only Polar's namespaces and holds pods to the signed record.
That is right for a deployment, and it left no place for infrastructure that is there only while something is tested. The
GitLab pair's live run (`http-observers.md`, "GitLab", G4) showed it: its test GitLab needed a per-workload trust of the cluster
CA, a namespace attested (`attest_also`), a floor entry (`server_also`), and kubectl to apply it, each landing in `sandbox-local`
as if the target were permanently made of it. The maintainer (2026-11-07): "we need test configurations ... it's simply
infrastructure under test, not something we're permanently declaring as part of polar", "possibly with its own trust levels within
the polar boundary", which "would address things like A/B testing needs in the future too". Their choice: design it first; G4
waits for it and is its first user.

**What it is.** A configuration under test is a named, versioned addition to a target, declared in the repository beside the
targets, layered onto one cluster's deployment for as long as a test needs it, and removed whole. It adds:
- infrastructure: objects the render makes into a layer of its own (the test GitLab, its runner, a seeded dataset's job);
- settings: what the target would otherwise have to say for it (namespaces attested, servers on the floor, workloads enabled, a
  workload's settings, as the GitLab observer's trust of the cluster CA);
- expectations: what the test should then find (a seed's nodes and edges), for the evidence it produces.

**What the existing mechanisms already give it** (read 2026-11-07):
- *The signed render and record.* A layer the render makes is published, signed and recorded in `provenance.json`
  (`deploy-repo.nu:560-569`) and, for its workloads, in the deployment record (`deploy-objects.nu:223-247`), which the attestation
  agent holds pods to (`attestation/agent/src/record.rs:30-67`). Infrastructure applied outside the render is issued certificates
  unattested (`CannotSay`, `attestation/common/src/verdict.rs:116-118`) and shows as drift (`NotInRecord`, `record.rs:107-125`): so
  infrastructure under test is rendered, not applied by hand.
- *Per-cluster inputs.* `cluster-inputs.nuon` (`cluster-inputs.nu:26-36`) is per cluster, gitignored, tied to the cluster CA and
  recorded in `provenance.json` (`deploy-repo.nu:470-481`): a cluster can carry a configuration under test without the committed
  target saying so.
- *A mark a certificate carries.* A `g:` group is a Cedar parent of the identity (`polar-policy/src/lib.rs:594-641`), so an
  `under-test` group on every certificate a configuration under test is issued lets policy keep it from what production holds;
  the signed groups document can also place an identity (`authority-model.md:45, 142-148`).
- *Precedents.* The secret harness is "added to a target when it is what is being tested" (`policy-enforcement.md:81-83`,
  `config.nuon:124-125`); the load harness's Jobs are made per run (`load-harness.nu`). Both are configurations under test in all
  but name.

**Constraints** (`AGENTS.md`, "Design Principles"): applying the catalog is the sign-off; control travels signed at run time;
Kubernetes is the trust base; a trust setting is Static, never Dynamic (`dynamic-settings.md:134-165`); special cases around one
mechanism mean its shape is wrong. And the provenance trail is not negotiable: what a deployment carried while tested stays in
its signed record.

**Decided** (the maintainer, 2026-11-07):
1. *Where it lives*: a layer of the signed deployment ("A layer of the signed deployment"). The render makes a configuration under
   test into a layer of its own, published and signed with the rest; `provenance.json` and the deployment record name it, Flux
   applies and prunes it, and the attestation agent holds its pods to the record.
2. *How a cluster takes it*: per cluster, at bring-up ("Per cluster, at bring-up"). `up.nu <target> --under-test <name>` records
   it in the cluster's own inputs (`cluster-inputs.nuon`), which the signed provenance already carries; the committed target never
   says it, and running `up.nu` without it re-renders and Flux prunes the layer.
3. *Its trust level*: a group on its certificates, and the record ("A group on its certificates, and the record"). Every
   certificate issued to a configuration under test carries `g:under-test`, from the render's facts as other groups are, so Cedar
   policy can keep it from what production holds; and the deployment record marks its workloads (a new schema), so the attestation
   agent reports on them apart.
4. *A/B*: decided when the first variant is wanted ("When the first is wanted"): a variant is a second workload of an agent's
   kind, its own identity, in a configuration under test, marked by its group; what it may write is decided with it.
5. *The harnesses*: later ("Later"): the test GitLab is the first user; once the mechanism holds, the secret harness and the load
   harness move into it, each a step of its own.

**The bites.**
- **CT1, the declaration and the layering.** A configuration under test is a directory `infra/under-test/<name>/`: `under-test.nuon`
  (the settings it adds to a target: namespaces attested, servers on the floor, workloads enabled and their settings) and a chart
  the render makes into the layer `under-test-<name>`. `up.nu --under-test <name>` records it in `cluster-inputs.nuon`; the
  resolver merges its settings over the target's, judged as the target's are; the target's layers gain it; `provenance.json`
  names it. Tests first, for the merge (what it may add, and that it adds and never removes) and the layering.
  *Done (2026-11-07).* `infra/under-test.nu`: `declared` and `name_problems` (a DNS label the repository declares), `declaration`
  (`under-test.nuon`'s `adds` and `layer`, and `main.nu` as its chart), `adds_problems` (only `cluster.attest_also` and
  `cluster.issuance.server_also`, extended as lists; `workloads.<name>.enabled: true`; a workload's env entries that neither the
  target nor the catalog sets; anything else is refused by name), `with_adds` (a deep merge that appends lists), `with_layers` and
  `layered` (the layer `under-test-<name>`, after the target's last, its chart after the target's, and `under_test` in the record).
  `cluster-inputs.nu` records `under_test` (`with_under_test`, which leaves inputs untied when there is nothing to record, so a
  first run against a handed-off cluster still restores from the record; `inputs_from_record` gives it back); `deploy-repo.nu`'s
  `cluster_inputs_fact` puts it in `provenance.json`. The resolver's `target_config` (`resolve.nu`) merges what the cluster carries
  and stops on any refusal, so every reader of the target's config sees one merged config, judged as the target's (`attested.nu`:
  `attest_also`, `server_also`, their floor entries, the attested namespaces given to the attestation agent and made by the
  namespaces chart). `targets/sandbox-local/target.nu` ends with `layered`, so the eight readers of a target's record see the same
  layers. `up.nu --under-test a,b` checks the names, records them in preflight (after the discard and the restore from the record)
  and reads the target again. Tests: `tests/under-test.nu` (merge, refusals, layering, inputs), `tests/resolve.nu` ("a cluster's
  configurations under test add to its target as the resolver reads it, and only add").
- **CT2, the mark.** The render gives `g:under-test` to every workload of a configuration under test, in its certificate facts and
  any floor entry; the deployment record says which workloads are under test (schema 2), and the attestation agent reads both
  schemas and reports on them apart. Properties: a workload is marked exactly when a configuration under test makes it.
  *Decided* (the maintainer, 2026-11-07): "Only what it makes": what its layer makes and the catalog workloads it enables that the
  target leaves out, and nothing else, so a configuration under test configures only what it enables; and "A field on what it says":
  the record and the published report carry `under_test`, on the same topics.
  *Done (2026-11-07).* `under-test.nu`: `adds_problems` refuses a workload the target runs, and one named without `enabled: true`;
  `marked` gives what is under test (the workloads enabled, the servers added); `layer_problems` holds each enabled workload's
  `<name>.yaml` to its configuration's layer, checked as a cluster's are read, so the record marks it as its certificate is. The
  resolver adds `under-test` to those workloads' groups in the authority model and the floor (`marks_of`), and to the floor entries of
  the servers a configuration under test adds (`main server-also`; the target's own get none). The record and the agents: as
  `runtime-attestation.md`, "What is under test, said apart", and `authority-model.md`, "Two kinds of groups", say. Properties
  (`attestation/common/tests/props.rs`): a record's marks change nothing found but the mark, and a finding is under test exactly when
  the record claims its pod for a marked workload; drift is unchanged by random marks. Tests: `tests/under-test.nu` (7),
  `tests/deploy-repo.nu`, `tests/resolve.nu`, `record.rs`, `report.rs`, the ledger's replay of an entry from before.
- **CT3, the test GitLab as the first.** `infra/under-test/gitlab/`: what `infra/gitlab-test.nu` applies, rendered as a chart; its
  outside images pinned as the others are; its settings (`attest_also`, `server_also`, the GitLab observer's trust of the cluster
  CA) moved out of `sandbox-local`; what needs the running GitLab (its root token, the runner's registration) a step `up.nu` runs
  after the layer is ready. Then G4 resumes on it: the seed tool, the pair packaged, the live run.

**What G4 leaves for it.** `infra/attested.nu` and its use in `resolve.nu`, `render.nu` and the namespaces chart went in with CT1;
`sandbox-local` carries none of it. Uncommitted on main, as CT3's material: `infra/gitlab-test.nu` (the test GitLab, with tests,
one of which reads the `server_also` that `sandbox-local` no longer has).

**Open for CT3.**
- *Settled (the maintainer, 2026-11-07, "The CT may add it").* The GitLab observer's trust of the cluster CA is the test GitLab's
  configuration under test's to add: `POLAR_EGRESS_CLUSTER_CA` may come from a catalog entry or a configuration under test, never the
  target's own config or the cluster's inputs, and only as `/etc/polar-ca/ca.pem` (`egress.nu`, `env_problems`; `egress.md`).
- `render.nu` gives a chart its context by its directory's name; a configuration under test named `gitlab` would be given the old
  GitLab chart's (`layers/.../gitlab`, removed in G5). Harmless, but CT3 should not rely on it.
