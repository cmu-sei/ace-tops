#!/usr/bin/env nu

# ACE Tool
#
# Copyright 2026 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS
# FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
# EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
# PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE
# MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
# TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu
# for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited
# distribution.  Please see Copyright notice for non-US Government use and distribution.
#
# This Software includes and/or makes use of Third-Party Software each subject to its own license.
#
# DM26-0670

# infra/cluster-inputs.nu
#
# What belongs to one cluster: its topology (`up.nu --topology`, which of the target's layouts this cluster is deployed in), and
# the git server's administrators (the identity of the first admin account is made by the admin flow on the live cluster). They are inputs to the render like any other, so they
# are written down where the render reads them and recorded in the provenance of what is published; they are not committed,
# because a cluster's identities are not the repository's.
#
#   infra/targets/<target>/cluster-inputs.nuon        gitignored
#   { cluster: "<sha256 of the cluster CA>", topology: "<name>", under_test: ["<name>"], workloads: { <name>: { env: [{ name, value }] } } }
#
# `workloads.<name>.env` has the shape of the same key in the target's config.nuon, and replaces an entry of that name there.
# `cluster` ties the file to the cluster it was made for: a file from another cluster is discarded, not extended. A topology is
# chosen before a new cluster has a CA, so `cluster` is null until there is one: the file is then this machine's next cluster's.

export const ADMINS_WORKLOAD = "polar-git-server"
export const ADMINS_VAR = "POLAR_GIT_SERVER_ADMINS"

export def path_of [infra_root: string, target: string] {
    $infra_root | path join "targets" $target "cluster-inputs.nuon"
}

export def empty [] { { cluster: null, workloads: {} } }

# Whether a run may go on against the cluster KUBECONFIG reaches (`reached`, the uid of its kube-system namespace), given the one it
# was told it is for (`named`, `up.nu --cluster`): null when they are the one cluster, else why not. A run is never pointed at a
# cluster by the kubeconfig's current context alone, and a context's name would not do: a kubeadm cluster's is always
# kubernetes-admin@kubernetes (the port's review, step A).
export def named_cluster_problem [named: string, reached: string] {
    if ($named | is-empty) {
        return $"name the cluster this run is for: --cluster ($reached) is the one KUBECONFIG reaches \(the uid of its kube-system namespace\). up.nu never takes the kubeconfig's current context on trust"
    }
    if $named != $reached {
        return $"KUBECONFIG reaches the cluster ($reached), not ($named), the one named: point KUBECONFIG at that cluster, or name this one"
    }
    null
}

# The file's record, or an empty one when there is none.
export def read_inputs [path: string] {
    if ($path | path exists) { open $path } else { empty }
}

# The env entries these inputs give a workload.
export def env_for [inputs: record, workload: string] {
    $inputs | get -o workloads | default {} | get -o $workload | default {} | get -o env | default []
}

# Whether these inputs were made for another cluster than `cluster` (null: one with no CA yet). Inputs not yet tied to one were not.
export def another_clusters [inputs: record, cluster: any] {
    let tied = ($inputs | get -o cluster)
    $tied != null and $tied != $cluster
}

# The inputs as they stand for `cluster`: tied to it if they were tied to none, the same if they were tied to it, and empty when
# they were made for another.
export def reconcile [inputs: record, cluster: any] {
    if (another_clusters $inputs $cluster) { empty } else { $inputs | upsert cluster $cluster }
}

# The topology this cluster chose, or null when it deploys in the target's default.
export def topology_of [inputs: record] { $inputs | get -o topology }

# The inputs with `topology` chosen, for `cluster`, which may have no CA yet. `changed` is false when it already was.
export def with_topology [inputs: record, topology: string, cluster: any] {
    let current = (reconcile $inputs $cluster)
    let chosen = ($current | upsert topology $topology)
    { inputs: $chosen, changed: ($chosen != $inputs) }
}

export def admins_of [inputs: record] {
    let found = (env_for $inputs $ADMINS_WORKLOAD | where name == $ADMINS_VAR)
    if ($found | is-empty) { [] } else { $found | first | get value | split row "," | each {|i| $i | str trim } | where {|i| $i != "" } }
}

# Whether this cluster's deployment is handed off to Polar's git server. Where Flux reads says so; this is that fact where the render can read it (infra/up.nu).
export def handed_off_of [inputs: record] { $inputs | get -o handed_off | default false }

# This cluster's inputs from its signed record, `provenance.json`'s `cluster_inputs` (`cluster_inputs_fact`, infra/deploy-repo.nu), for a machine that holds none: rendering without them would take its administrators away. Null when the record is not this cluster's.
export def inputs_from_record [fact: any, cluster: string] {
    if $fact == null or ($fact | get -o cluster_ca_sha256) != $cluster { return null }
    {
        cluster: $cluster, workloads: ($fact | get -o values | default {}), topology: ($fact | get -o topology), handed_off: true
        under_test: ($fact | get -o under_test | default [])
    }
}

# The configurations under test this cluster carries (`up.nu --under-test`, infra/under-test.nu).
export def under_test_of [inputs: record] { $inputs | get -o under_test | default [] }

# The inputs carrying exactly `names`, for `cluster`. `changed` is false when they already did; carrying none where none was carried
# leaves the inputs as they are, untied, so a machine's first run against a cluster can still take its inputs from the record.
export def with_under_test [inputs: record, names: list<string>, cluster: any] {
    if ($names | is-empty) and (under_test_of $inputs | is-empty) { return { inputs: $inputs, changed: false } }
    let current = (reconcile $inputs $cluster)
    let chosen = ($current | upsert under_test $names)
    { inputs: $chosen, changed: ($chosen != $inputs) }
}

# The inputs with that recorded, for `cluster`. `changed` is false when nothing would change.
export def with_handed_off [inputs: record, handed_off: bool, cluster: any] {
    let current = (reconcile $inputs $cluster)
    if (handed_off_of $current) == $handed_off and (handed_off_of $inputs) == $handed_off {
        return { inputs: $current, changed: false }
    }
    { inputs: ($current | upsert handed_off $handed_off), changed: true }
}

# The inputs with `identity` among the git server's administrators, for `cluster`. `changed` is false when it already was.
export def with_admin [inputs: record, identity: string, cluster: string] {
    let current = (reconcile $inputs $cluster)
    let held = (admins_of $current)
    if $identity in $held { return { inputs: $current, changed: ($current != $inputs) } }
    let others = (env_for $current $ADMINS_WORKLOAD | where name != $ADMINS_VAR)
    let entries = ($others | append { name: $ADMINS_VAR, value: ($held | append $identity | str join ",") })
    {
        inputs: ($current | upsert cluster $cluster | upsert workloads ($current.workloads | upsert $ADMINS_WORKLOAD { env: $entries }))
        changed: true
    }
}

# A workload's env entries from the target's config (`ov`) without the names the cluster supplies, then the cluster's.
export def env_merged [config_env: list, supplied: list] {
    let names = ($supplied | get name)
    ($config_env | where {|e| $e.name not-in $names }) ++ $supplied
}
