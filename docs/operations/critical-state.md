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

# What a deployment cannot lose

Status, 2026-11-02: the list and the plan, to be built later (the maintainer). Polar archives nothing yet, and the one restore that has been run is marked. Why each is on the list comes from reading the code and, where it says so, from breaking it on purpose on u7s. How an operator keeps their own machine's files is their own; "operator's machine" below means Polar makes no copy.

A cluster's state is in three places: the operator's machine, the cluster's volumes, and the cluster's etcd. Everything a run of `up.nu` can make again is at the end, so that it is not mistaken for a gap.

## Cannot be made again

| What | Where | If it is lost | Copy today | Restore |
|---|---|---|---|---|
| The credentials agent's store: `events.jsonl`, the hash-chained ledger of accounts, certificates, secrets and policy, and `escrow-key.pem`, its root key | volume `polar/credentials-agent-data`, `/var/lib/credentials-agent` | Every account, every secret sealed to it, and the record of who was granted what. A rebuild of the cluster's identity | none | none, and none designed: `key-rotation.md`, "The `BackupActor`", is scope only |
| Polar's root CA | Secret `polar/cert-issuer-ca`, in etcd and nowhere else (`polar-admin-grant bootstrap-ca`) | No certificate can be issued under it. A rebuild | none | none. `bootstrap-ca` refuses to run while the Secret exists |
| What people signed into `polar-schedules` | volume `polar/polar-git-server-data` | The seed puts back the first version of what it seeds; later documents and all history are gone (seen on u7s, volume deleted on purpose) | none | the seed, in part |
| The deployment CA's key | `~/.config/polar-deploy/<target>/ca.key` | `ensure_pki` makes a new CA with no warning when the certificate is missing: the new commits no longer chain to what the cluster's git server trusts, and the signed history no longer chains to what signs next | operator's machine | by hand |
| The pipeline's key and its signing state | `pipeline.key`, `pipeline.pem`, `signing.pass`, `gnupg/`, same directory | Can be reissued from the CA's key, and the record then names a second signer | operator's machine | by hand |
| The bootstrap administrator's and people's keys | `~/.config/polar-admin/`, one directory per cluster; parked ones as `polar-admin.old-*` | "Losing the bootstrap material means a rebuild" (`identity-and-bootstrap-update.md`). `up.nu` fails with `BootstrapAlreadyDone`, and after a handoff nobody can publish | operator's machine | by hand, by matching `ca.pem` to the cluster's `polar-ca` |
| The keys that open the sops files | `~/.ssh`, by the recipients in `secrets.sops.yaml` | `up.nu` cannot read the target's secrets. Other recipients may still | operator's machine | by hand |
| This target's gitignored sops settings | `infra/targets/<target>/.sops.yaml`, `user.sops.yaml` | Who can be added as a recipient, and what a person's own secrets were | operator's machine | by hand |

## Losing it costs something, and it can be rebuilt

| What | Where | If it is lost | Copy today | Restore |
|---|---|---|---|---|
| The signed deployment history | volume `polar/polar-git-server-data`; `mirror.git` beside the PKI | With one copy left, nothing. With both gone, the record of what was deployed | **each other** | **Run on u7s:** a plain `up.nu` gives an empty server the mirror's history. One mirror per target, so two clusters overwrite it (`remaining-work.md`) |
| The issuance record | volume `polar/cert-issuer-data`, `issued.jsonl` | The record of what was issued, and what `core-restarts.md` restores from at start. New issuance goes on | none | none |
| The graph | volume `polar-graph/polar-db-data` | What was observed and linked, including what the systems observed no longer show. Observers can see the present again; never signed configuration or secrets, which are not rebuilt from it | none | `just neo4j-load-dump` loads a dump, and nothing makes one |
| Keycloak's database | volume `polar-auth/polar-postgres-data` | Its realm and users. I found no realm import under `infra/`, so what it holds was made by hand | none | none |

## Made again by a run

- `cluster-inputs.nuon`: on a handed-off cluster it comes back from the signed record (run on u7s and u7c). Before the handoff, the seed adds the administrator back.
- `secrets.sops.yaml` is in git, encrypted. Secrets from it are applied by the secrets step. `cassini-shutdown-token` is generated when missing.
- The rendered `manifests/`, `images.dev.lock.nuon`, the `flux`, `server` and `configuration-agent` certificates (from the deployment CA), and `deployment-auth`.
- The registry's volume, from the nix builds or the published images: the 20 GiB is a cache of those.
- Neo4j's `polar-db-certs` and `polar-db-logs`, and every pod's certificates.

## What leaves them exposed

- A volume's reclaim policy is `Delete`: deleting a claim deletes its data, as was done on purpose on u7s.
- Etcd and the volumes are on the cluster's own storage, so a lost cluster takes the root CA and every store with it.

## What an archive has to get right

- The credentials agent's root key is in its volume in the clear until custody part B, and the sops keys and CA's are as sensitive. An archive holds the keys to the whole deployment, so it is encrypted to a key that is kept somewhere else.
- The root CA, the credentials store and the issuance record belong to one moment: the ledger's identities chain to the CA. They are taken together and restored together.
- `events.jsonl` is hash-chained and being appended to, so a copy of a live file can end in a torn line.
- Agents' images have no shell. A copy goes through a pod that mounts the claim, as `infra/neo4j-load.nu` does, or through the agent itself.
- A backup never brings a retired key back: restoring one made before a rotation gives entries that answer `Retired` (`key-rotation.md`).
- An archive that has not been restored is not known to work. Restoring onto a scratch cluster (u7c) is part of building it.

## The plan

To be cleared before it is built, and built after what `remaining-work.md` puts ahead of it.

1. **`nu infra/archive.nu create <target>`**, run by an operator against the cluster `KUBECONFIG` names. It makes one encrypted bundle: the first table's cluster and machine rows, the deployment history, the issuance record, and `polar-schedules` by a `git bundle`. A manifest in it names the cluster's CA, the time, and each file's digest.
2. **One moment.** Scale the credentials agent and cert-issuer down, copy through a pod that mounts each claim, and bring them back, as `infra/neo4j-load.nu` does for the graph (suspending what Flux would undo). Issuance waits for that long, which `core-restarts.md` already allows for. The graph and Keycloak's database are taken apart from these, by their own dump tools: they are large, and need not be the same moment. The graph's dump is the piece `neo4j-load-dump` is missing.
3. **`nu infra/archive.nu restore <bundle>`**, onto a new cluster or an emptied one. In order: the root CA before anything issues, then the credentials store and the issuance record, then the git server's repositories, then a run of `up.nu`, which finds the rest there. It refuses a bundle whose manifest does not verify. Restoring over a cluster with a different CA is an explicit choice, never a default.
4. **The proof:** archive u7c, delete its namespaces and volumes, restore, and check that an administrator can sign in and publish, agents get certificates, and a document signed before the archive still applies. Then the same with a bundle from before a rotation, once rotation exists.
5. **Then the agents' own.** The `BackupActor` of `key-rotation.md` takes over the stores it covers once custody part B is in: a domain's state is its own. This plan's commands remain for what no agent owns (etcd's Secret, the git repositories, the operator's keys).

**To settle when it is picked up:** which key the bundle is encrypted to, and where it is kept (never in the bundle, and not only on the cluster); where bundles go, and how often; whether `polar-schedules` should have a mirror off the cluster, as the deployment does, instead of waiting for an archive; and who may restore: a person with the kubeconfig, or something signed as well. The mirror's per-target shape (`remaining-work.md`) should be fixed first, since a bundle should not hold another cluster's history.
