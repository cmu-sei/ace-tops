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

# OpenAPI agents

The first of the HTTP observers (`docs/architecture/http-observers.md`). They record which applications expose which API
operations, from their OpenAPI or Swagger documents.

- **openapi-observer** reads each document its signed `sources` section names, on that source's interval, with no credential,
  and publishes it as it came on `polar.openapi.observations`. It parses nothing and never touches the graph.
- **openapi-processor** takes those documents, from that observer alone, and writes them to the graph by its signed
  `projection` section, as `OpenApiApplication` and `OpenApiEndpoint` nodes. A projection chooses which data goes where inside
  the schema in `process/src/agent.rs`, and cannot name another label, key or edge. Until one is signed it holds and says so.

Both are thin: the work is in `polar-http-observer`, `polar-http-processor` and `polar-projection`.

## Pointing them at something

```
polar-sign template openapi-observer sources > sources.json     # fill it in
polar-sign sign sources.json --user alice --push

polar-sign runtime --agent openapi-processor --section projection --version 1 \
  --projection src/agents/polar-projection/examples/openapi.dhall --user alice --out projection.dhall
```

Documents must be JSON, in any of Swagger 2.0, OpenAPI 3.0 or 3.1, whose `paths` have the same shape.

## Not handled yet

An endpoint a document dropped stays in the graph, a document in YAML is refused, and nothing links an application to the
service that runs it.
