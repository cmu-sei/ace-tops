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

# One switch per workload: whether a cluster runs it

> **This document has a twin.** [`one-switch-per-workload.claude.md`](one-switch-per-workload.claude.md) says the same
> thing, written for Claude. This one is written for people. They are two sides of one plan, and they are changed
> together.
>
> A **feature-level plan** for the lifecycle work ([`../../architecture/lifecycle.md`](../../architecture/lifecycle.md)),
> whose capability plan is not written yet. It is to be built with that work, not before it. It describes Polar's
> `main` as it is.

**Status: proposed, to be built with the lifecycle work.**

## 1. The need

Turning a workload off in a deployment target should be one change in one place. Today it is not, and how many changes
it takes depends on what kind of workload it is:

- **An agent of the catalog** has a switch, `enabled` under its name in the target's configuration, but its manifest
  files are also listed by hand in the target's layers, so turning it off or on takes two edits that must agree.
- **A service Polar runs but did not write** (Neo4j, Keycloak and its Postgres, Jaeger, ACE) has no switch at all: its
  files are listed in a layer and its chart in the target's list, and both are edited.
- **What a workload adds to another goes nowhere when it leaves:** Keycloak's token issuer is written into cert-issuer's
  settings, and Keycloak's secrets into the target's secrets, so turning Keycloak off takes edits in other places too,
  and missing one leaves trust or secrets behind for something that is gone.
- **A configuration under test,** such as the test GitLab, has a switch of its own: whether a cluster's bring-up names
  it. That one is already a single change.

## 2. How the need was found

- **Turning Keycloak and the test GitLab off on the development cluster** to free memory. Keycloak took its layer's
  files, the target's chart list and cert-issuer's trusted issuers, each edited by hand, and its secrets are still made
  at bring-up.
- **The lifecycle design** already names it: a workload's files are typed a second time into the target's layers, and
  being "in a target" is implied by several things at once.

## 3. The plan

**One switch, `enabled` under the workload's name, for every kind of workload, and one answer computed from it.**

1. **One function answers which workloads a cluster runs.** Every consumer reads it: the layers, the render's derived
   facts (the authority model, cert-issuer's floor, the attested namespaces, the signed record), the bring-up's waits
   and its port-forwards, the secrets it makes. When the lifecycle document exists, that function reads which
   workloads are deployed or under test from it, and nothing else changes.
2. **Layers name workloads, not files.** The render knows each workload's files, so a disabled workload's files drop
   out of its layer, and a layer left empty is dropped. When the catalog derives a dependency graph in place of
   hand-kept layers, the workload names are what it starts from.
3. **The services are named workloads too,** each by its directory under `layers/2-services`, with the same switch.
   Keycloak's Postgres is part of Keycloak's workload, since nothing else uses it. Where the services' declarations
   finally live is the catalog split's to decide, so they are not made catalog entries now.
4. **What a workload adds to another is declared with it, and added only while it runs.** Keycloak declares the token
   issuer it adds to cert-issuer's trust, and its secrets, beside its chart; the render adds them only while Keycloak is
   enabled. Later, cert-issuer derives its trusted issuers itself from the cluster's lifecycle.
5. **Configurations under test keep their own switch.** They put workloads under test together with what their test
   needs, which the lifecycle design gives a place of its own.

## 4. Alternatives considered

- **Making the services catalog entries now.** It would fix where their declarations live before the catalog split
  decides it.
- **Folding configurations under test into the target's switch.** Rejected: test infrastructure has its own trust level
  and is not target settings.
- **Building the dependency graph now** in place of layers. It is the catalog split's, proved on Flux first; naming
  workloads in layers is the part it needs and nothing more.
- **Building this before the lifecycle work.** It would be a second place that infers what a cluster runs, which the
  lifecycle document then has to replace.

## 5. Why this plan

- One change turns a workload off, whatever its kind, and nothing it added is left behind.
- The lifecycle document replaces one function's source, not every place that infers the set.
- The catalog split starts from workloads named in layers, which is what its dependency graph needs.

## 6. How much of the need is met now

- Agents of the catalog have a switch, and their files are listed by hand as well.
- Services have no switch. Keycloak and its Postgres are left out of the development target by hand, and cert-issuer
  no longer trusts Keycloak's tokens there; Keycloak's two secrets are still made at bring-up.
- Configurations under test have their switch.

## 7. What is left before this is met

- The lifecycle document and its reader, which this is built with.
- The function, the layers by workload name, the services as named workloads, and what a workload adds to others
  declared with it.
- What is left behind when a workload leaves (its volumes, its secrets, its certificates) is the lifecycle work's
  retirement, not this plan's.
