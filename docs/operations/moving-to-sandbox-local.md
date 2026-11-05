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

# Moving a cluster from `local-minimal` to `sandbox-local`

After 3.0.0, `sandbox-local` is the only target (`docs/architecture/placement.md`). A cluster running `local-minimal` moves in place,
with no rebuild. Tried on 2026-11-02, on a single-node cluster brought up from the v3.0.0 tag and its published images: the CA and
every volume stayed, all six Flux layers became ready, and no pod restarted after it came up.

It is a move in one direction: the layers are then applied by Flux, and a later `local-minimal` is not a way back.

## Before you pull

The `local-minimal` directory goes away with the pull. Git leaves its ignored files in place, but a file you changed in it conflicts.

1. If you replaced the target's secrets file with your own (**Secrets setup** in the README, `git update-index --skip-worktree`),
   copy it somewhere safe and undo that:

   ```bash
   cp infra/targets/local-minimal/secrets.sops.yaml ~/polar-secrets.sops.yaml
   git update-index --no-skip-worktree infra/targets/local-minimal/secrets.sops.yaml
   git checkout infra/targets/local-minimal/secrets.sops.yaml
   ```

2. Commit or set aside anything else you changed in that directory, such as `config.nuon`. Its settings do not move by themselves.

## The move

Run this from the dev container (it has `gpgsm`, which signing the deployment needs), with the same `--user` and `--email`:

```bash
git pull
nu infra/up.nu sandbox-local --import-from docker.io/<account> --import-tag <the release> --user <name> --email <email>
```

Add `--allow-dirty` if your checkout has uncommitted changes; the signed record says so.

`up.nu` publishes the layers to a new deployment git server in the cluster, with a volume of its own, and installs Flux, which takes over the
running workloads. Their pods are replaced once. It then checks the seed and finds its documents already in the schedules repository.

## Afterwards

- Copy your own settings across, into `infra/targets/sandbox-local/`: the secrets file you saved, your `.sops.yaml` and `user.sops.yaml`
  (Git leaves those in the old directory), and anything from `config.nuon`. Re-run `up.nu` if you changed the target's settings.
- Delete what is left of `infra/targets/local-minimal/`. `up.nu` records this cluster's administrators again for the new target.
- The load harness's accounts and the OCI resolver now run too. To leave one out, set `enabled: false` in the target's `config.nuon`.

The default topology is `single`. A cluster that has been deployed keeps its layout; to place workloads on node pools, choose `--topology
separated` on a fresh cluster, since a deployed one's volumes are bound to their nodes.

## GitLab and build-processor

These ran only on the `local` target, which is gone with no replacement yet. They return as each joins the catalog (`remaining-work.md`). To run
them until then, stay on the v3.0.0 tag.
