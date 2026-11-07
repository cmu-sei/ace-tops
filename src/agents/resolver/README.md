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

# OCI Resolver

## Overview

The OCI resolver is an event-driven agent in the Polar observability framework responsible for validating OCI artifact references discovered by other agents. When the Kubernetes observer, GitLab processor, or any other agent encounters a container image reference, it emits a discovery event. The resolver receives that event, pulls the image manifest from the appropriate registry, and emits a resolved event carrying the verified digest and manifest data for downstream processing by the build processor.

The resolver enforces a deliberate trust boundary: observer agents report what they see, which may be unverified references of unknown origin. The resolver's job is to follow those references to their source and retrieve the manifest — an irreversible, mechanically verifiable action — so that the build processor's provenance linker can record a ground-truth artifact node in the knowledge graph rather than an unverified claim.

## Architecture

```text
[Observer / Processor]
  emits OCIArtifactDiscovered / ImageRefDiscovered
          │
          ▼
    [OCI Resolver]
  pulls manifest from registry
  verifies digest
  emits OCIArtifactResolved / ImageRefResolved
          │
          ▼
  [Build Processor → Provenance Linker]
  upserts OCIRegistry, OCIArtifact, and
  ContainerImageRef nodes and edges
  in the knowledge graph
```

The resolver has no startup scrape and maintains no internal list of registries to watch. It is purely reactive — it does nothing until a discovery event arrives, at which point it resolves exactly that reference and forwards the result.

## Authentication

Registry credentials are the signed `credentials` runtime section (`src/credentials.rs`; `docs/architecture/protocol-handlers.md`, "The protocols"), each entry encrypted for this agent and bound to the hosts it names. `polar-sign` makes one. The resolver's code never has a credential: it asks the builder's HTTP protocol handler for a manifest, and the handler finds the entry whose host pattern names the registry's host most closely, answers the registry's challenge, and hands back what came.

- A `user-password` goes where the registry's challenge sends it: to the registry, for Basic, or to the auth host it names, which the entry must name too (`registry.gitlab.com,gitlab.com`; `*.docker.io`). An auth host the entry does not name is sent nothing, and the read fails. The registry itself sees only the token that came back.
- A `token` goes to the registry as it is, as `Bearer`.
- A registry no entry names is asked with no credential, as is a registry named in `OCI_INSECURE_REGISTRIES`: a credential goes over nothing that is not encrypted.
- A credential the registry refuses is presented to nobody until a new version of the section arrives, and the agent holds `Credentials` and says so. It does not become an anonymous read.

For a private registry with an internal CA, or a proxy that inspects TLS, the target sets `cluster.egress` (docs/architecture/egress.md): `POLAR_EGRESS_CA_CERT` names the PEM CA certificates the OCI client trusts beside the system's, every one of them, and `POLAR_EGRESS_PROXY` and `POLAR_EGRESS_NO_PROXY` the proxy it reaches a registry through and the hosts it reaches directly.

## Known Limitations

**Images no registry vouches for** — The resolver reads a reference by Docker's rule (`oci_client::Reference`, a port of Docker's `normalize.go`): the first component is a registry host when a path follows it and it holds a dot or a colon, or is `localhost`, so a tag's dots are not a host (`neo4j:5.26.2`). `localhost:5000/…` is a registry like any other and is resolved.

Only a digest proves which image a reference means, wherever it is fetched from, and a body with another digest is refused. A pod's container is the image its kubelet ran: the resolver reads it by the digest in the kubelet's `image_id` (`repo@sha256:…`, or the same after `docker-pullable://`), from the registry and repository the spec names, and never by the tag, which may have been moved since the pull. With no such digest it uses the spec's own digest, if it has one. A name with no registry host is Docker Hub's, so a pinned one is read there. A repoint is not flagged, since that would take a second read, of the tag. An image read by its digest is kept and not read again, since every observation of a pod discovers its images again and a registry counts the reads (Docker Hub limits them); at most 1024 are kept, then all are dropped and read again. An image read by a tag, and a read that failed, are not kept.

Never fetched and never vouched for:

- An image nothing pins: a container whose kubelet reported no digest a registry serves (a bare `sha256:…` is the image's own ID, as for a locally loaded image) and whose spec names none, or a repository's name with no registry host and no digest. Docker reads a hostless name as Docker Hub's, but a tag there may not be the image a node loaded by that name.
- A name whose registry is `localhost` (`localhost/blitz-portal:latest`), pinned or not: it is in a node's own image store, as podman names what it builds, and the resolver cannot see a node's store (it may run on another node).

Each logs `not verified: …` and publishes no event, so the container gets no `USES_IMAGE` edge. Calling an image local or unpinned can only take a verification away, never give one. The gap is a query, not a node:

```cypher
MATCH (c:PodContainer)
WHERE NOT (c)-[:USES_IMAGE]->(:OCIArtifact)
RETURN c.image, count(*)
```

In production, every image should come from a registry and be pinned by digest.

## Environment Variables

| Variable | Purpose |
|---|---|
| `POLAR_EGRESS_CA_CERT` | PEM CA certificates trusted beside the system's (the egress section, `polar::egress`) |
| `POLAR_EGRESS_PROXY`, `POLAR_EGRESS_NO_PROXY` | The proxy a registry is reached through, and the hosts reached directly |
| `OCI_INSECURE_REGISTRIES` | Registries, as host:port, spoken to over plain http with no credential: a development registry |

Standard Cassini broker connection variables apply as with all Polar agents.

## Container Image

```bash
nix build .#polarPkgs.resolver.image -o resolver-image
docker load < resolver-image
docker run --rm polar-oci-resolver:latest --scaffold
```
