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

# one-switch-per-workload — Claude's side

PAIR: `one-switch-per-workload.md` (people). Same plan, two forms; change together.
SPLIT: people side has no dates, attributions, quotes, codenames or branch/process status; those live here.
PARENT: no lifecycle capability plan yet; design `docs/architecture/lifecycle.md`; order
`docs/requests/blitz-on-polar-coordination.md` steps C (lifecycle) → D (catalog split) → E (controller).
AS-OF main a488c9db (2026-11-13). STATUS: proposed; maintainer: "write it up as a plan to be implemented with that
work" (with lifecycle/catalog), "For now, let's just turn some shit off".

## ORIGIN (2026-11-13)
the maintainer's machine at ~21 GB idle. Found: 3 leaked testcontainers neo4j:5 (started 2026-11-12 06:31-07:24, ~1.2 GB RSS + ~1.6 GB
swap; removed with 5 stopped ones; one netavark nft cleanup error "Device or resource busy"), u7c: GitLab ~3.4 GB,
Neo4j ~3 GB, Keycloak 1.9 GB + Postgres 0.6 GB, k8s control plane, clamd 1.7 GB (host). Maintainer: remove Keycloak
(+Postgres) and GitLab from the target. Then: "We need a simple and efficient way to enable/disable a workload from a
given deployment target. This should be a simple matter." I proposed one switch; maintainer: "pay attention to how these
changes might be best implemented, given the upcoming lifecycle and catalog refactor"; then this plan, deferred.

## FACTS (main as is)
- catalog switch: resolve.nu:126-140 `disabled_in` / `all_workloads` (workloads.<name>.enabled == false); files typed
  again in targets/sandbox-local/target.nu layers (config.nuon comment: "set enabled: true on both and add their four
  manifests back to the agents layer"); lifecycle.md "What there is today" says the same.
- services: layers/2-services/{ace,jaeger,neo4j,keycloak,postgres,cert-issuer(legacy dhall, not in charts)}; charts list
  target.nu ~190; data layer files.
- Keycloak spill: config.nuon cert-issuer CERT_ISSUER_ISSUERS entry (live); overrides.dhall certIssuer issuer entry
  (inert: cert-issuer is a catalog `ca` workload now, the dhall cert-issuer chart is not in charts); secrets.nu:49-55
  keycloak-admin-secret, keycloak-db-secret (optional); Justfile port-forwards-up keycloak 8080, keycloak-bootstrap;
  attested.nu FIRST namespaces include auth; cluster.nuon namespaces.auth polar-auth.
- admin-claim uses credentials-agent observer (polar-admin-grant claim), not Keycloak.
- cert-issuer fetches an issuer's JWKS lazily (oidc.rs refresh on validation), so a missing Keycloak never blocked it.
- GitLab: configuration under test (infra/under-test/gitlab), cluster input `under_test` in git-ignored
  cluster-inputs.nuon; up.nu choose_under_test removes what is no longer named ("no longer under test, so removed").

## DONE NOW (a488c9db)
target.nu: data layer without postgres-*/keycloak-* files, charts without postgres/keycloak; config.nuon: Keycloak issuer
removed with a comment. Infra tests pass: charts 16, deploy-objects 11, facts 3, layers 11, plan 14, rules 44, forwards 7,
images 15, cluster-inputs 11; render-determinism skips (needs a cluster). `render.nu --charts-into` renders without them.
NOT APPLIED to u7c yet: needs a bring-up (u7c's last turn was polar-cc's), without `--under-test gitlab`.

## DESIGN (for the lifecycle work)
1 `cluster_workloads(target)` the only answer (later: lifecycle doc deployed|under-test). 2 layers by workload name; files
from the workload (catalog: <name>-resources.yaml, <name>.yaml; services: their main.nu's outputs). 3 services named by
their layers/2-services dir; Postgres inside Keycloak's. 4 contributions (Keycloak's cert-issuer issuer, its secrets)
declared beside its chart, added while enabled; later cert-issuer derives (lifecycle decision 4). 5 under-test switch
unchanged (configurations-under-test decision: own trust level, not target settings).
NOT: services as catalog entries (step D), the dependency graph (step D, Flux first), retirement cleanup (step C).
