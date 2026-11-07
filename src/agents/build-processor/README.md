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

# Build Processor

The build processor writes Polar's software supply-chain facts into the
knowledge graph: builds, what they produced, findings about packages, and what
registries actually serve. Every agent that reports such a fact publishes a
canonical [`ProvenanceEvent`] to `polar.provenance.events`. This agent is the
one that records it.

## Design

- **The single writer.** No other agent writes these node types. Agents report
  facts; this one projects them.
- **Projection is pure.** `project::project(event, observed_at)` returns the
  `Vec<GraphOp>` that records the event. Nothing in `project/` touches the
  graph or the broker. That makes every projection unit-testable and runnable
  against a real Neo4j as-is.
- **Every write is an idempotent MERGE.** Projecting an event twice leaves the
  graph as it was. Events about the same nodes may arrive in any order.
  Timestamped edges are MERGEd on their endpoints alone, with `at` kept from the
  first write (`coalesce`: the graph controller takes no `ON CREATE`), so an
  event seen again never duplicates them. The broker keeps no log to replay: an
  event lost before it is written is lost.
- **One dispatch, no wildcard.** `project()` matches every `ProvenanceEvent`
  variant explicitly. A new variant doesn't compile until it's routed, and
  variants with no projection yet warn instead of disappearing.
- **One mailbox.** The supervisor decodes each event, projects it, and sends the
  operations in order to the `GraphControllerActor`, which serializes all
  writes. There are no per-domain actors: projection holds no state, so they
  would add a hop and split ordering without buying isolation.

## Modules

The projections are grouped by what the graph is *about*, which also tracks
whose word each fact is.

| Module | Subject | Reported by | Events |
|---|---|---|---|
| `project/execution.rs` | `BuildJob`: what ran, where, how it ended | orchestrator, CI | `ExecutionStarted`, `StageStarted`, `StageCompleted`, `ExecutionCompleted`, `ExecutionFailed`, `ExecutionCancelled` |
| `project/outputs.rs` | what a build produced | the producing build | `ArtifactProduced`, `SbomAnalyzed`, `BinaryLinked`, `ContainerImageCreated` |
| `project/findings.rs` | facts about packages | scanners | `SecurityAdvisoryFound`, `PackageStatusFound` |
| `project/registry.rs` | what a registry actually serves | the resolver | `OCIArtifactResolved`, `OCIRegistryDiscovered` |

Not projected:
- `OCIArtifactDiscovered` and `ArtifactDiscovered` are requests for the resolver. Only the resolved result is recorded.
- `OCIArtifactCreated` and `ImageRefResolved` have no producer yet. They warn when seen.

## Graph

```text
execution  (GitCommit)-[:BUILT_BY]->(BuildJob)                     git sources only
           (BuildJob)-[:EXECUTED_IN]->(KubernetesJob | PodmanPod)
           (BuildJob)-[:IS]->(BuildExecution)
           (BuildJob)-[:HAS_STAGE]->(BuildStage)
           (BuildJob)-[:TRANSITIONED_TO]->(BuildJobState {phase})-[:OF_TYPE]->(State)

outputs    (BuildJob)-[:PRODUCED]->(BuildArtifact)
           (BuildArtifact)-[:ANALYZED_AS]->(Sbom)-[:DESCRIBES]->(Package)
           (Package)-[:DEPENDS_ON]->(Package)
           (Binary)-[:BUILT_FROM]->(Package),  (Sbom)-[:ATTESTS]->(Binary)
           (BuildArtifact)-[:INSTANCE_OF]->(OCIArtifact)            pushed images
           (OCIArtifact)-[:HAS_DIFF_ID {order}]->(OCILayerDiffId)

findings   (BuildJob)-[:REPORTED]->(SecurityAdvisory | PackageStatus)-[:IS]->(Finding)
           (SecurityAdvisory)-[:AFFECTS]->(Package),  (PackageStatus)-[:CONCERNS]->(Package)

registry   (OCIArtifact)-[:HOSTED_BY]->(OCIRegistry)
           (OCIArtifact)-[:HAS_LAYER {order}]->(OCILayer)
           (OCIArtifact)-[:HAS_MANIFEST {platform_*}]->(OCIArtifact)    indexes
```

Points that are easy to get wrong:

- **`BuildJob.completed_at` means finished, not succeeded.** Success is the
  latest `BuildJobState {phase: 'succeeded'}`.
- **An image has two layer identities.** `OCILayer` is a registry blob, keyed
  by compressed digest. `OCILayerDiffId` is the image config's uncompressed
  diff ID, which SBOM tools reference. Both hang off the same
  `OCIArtifact {digest}`, and matching `order` pairs them.
- **Images meet on `OCIArtifact {digest}`.** A pushed build image, the
  resolver's manifest for it, and k8s's `PodContainer-[:USES_IMAGE]` (written
  by the kube consumer) all land on this node. Whether those claims agree is a
  graph query.

Not owned here and only referenced through edges: `GitCommit` (git
processor), backend job nodes (their observers), `PodContainer` (kube
consumer).

## Topics

| Topic | Purpose |
|---|---|
| `polar.provenance.events` | All provenance events: rkyv from Rust agents, JSON from nushell stages |

## Deployment

A catalog workload (`infra/config/workloads/provenance.nuon`) on `polar-agent-builder`: `build-processor --scaffold`
prints what it declares (the topic above, the graph-write capability, the labels it owns, its shutdown budget), and
the catalog renders the rest. The graph-write capability gives it the graph (`GRAPH_*`, the pod's client
certificate). It runs as a Deployment, and an agent that ends exits non-zero; health is its HealthCheckActor's.

## Tests

```sh
cargo test -p build-processor

# Includes the projections against a real Neo4j 5.26.2 (tests/projection_neo4j.rs),
# which needs a container runtime; with Podman, DOCKER_HOST at its socket.
```
