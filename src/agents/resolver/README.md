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

**Unqualified image references** — When a pod spec contains an image reference without a registry prefix (e.g. `myimage:latest`), the Kubernetes API reports exactly that string. The resolver cannot determine the registry of origin from an unqualified reference and will skip resolution rather than guess. This is recorded in the graph as a provenance gap: the container was running an image whose origin cannot be verified. This most commonly occurs with locally loaded images in development environments. In production, all image references should be fully qualified.

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
