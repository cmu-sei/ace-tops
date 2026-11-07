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

# infra/under-test.nu
#
# Configurations under test (docs/architecture/configurations-under-test.md): infrastructure and settings a cluster carries for as
# long as something is tested, and not part of its target. Each is declared in the repository,
#
#   infra/under-test/<name>/under-test.nuon   { adds: { cluster: {...}, workloads: {...} }, layer: { files: [...], wait_for: [...] } }
#   infra/under-test/<name>/main.nu           the chart the render makes its layer's files with, called as any other
#
# and a cluster carries those its inputs name (`up.nu --under-test`, infra/cluster-inputs.nu). Its `adds` are merged over the
# target's config.nuon (infra/resolve.nu) and only add: namespaces attested, servers on the floor, workloads enabled, a workload's
# settings the target does not give. Its layer, `under-test-<name>`, comes after the target's own (`layered`, which every
# target.nu ends with), so it is rendered, signed, published and recorded with the rest, and pruned when the cluster stops carrying it.

use cluster-inputs.nu [path_of, read_inputs, under_test_of]

export const DIR = "under-test"
export const LAYER_PREFIX = "under-test-"

# What `adds` may say under `cluster`: lists the target's own are extended by.
const CLUSTER_LISTS = ["attest_also" "issuance.server_also"]

# The configurations under test the repository declares.
export def declared [infra_root: string] {
    let dir = ($infra_root | path join $DIR)
    if not ($dir | path exists) { return [] }
    ls $dir | where type == dir | get name | where {|d| ($d | path join "under-test.nuon" | path exists) } | each {|d| $d | path basename } | sort
}

# Why `name` cannot be a configuration under test: it names its layer and its directory, so it is a DNS label, and one `known` declares.
export def name_problems [name: string, known: list<string>] {
    if not ($name =~ '^[a-z0-9]([-a-z0-9]{0,40}[a-z0-9])?$') {
        return [$"'($name)' is not a configuration under test's name: lowercase letters, digits and '-', as a namespace's"]
    }
    if $name not-in $known {
        return [$"no configuration under test named '($name)' \(infra/($DIR)/($name)/under-test.nuon\). Declared: ($known | str join ', ')"]
    }
    []
}

# A declaration: its name, its chart, its layer and what it adds.
export def declaration [infra_root: string, name: string] {
    let problems = (name_problems $name (declared $infra_root))
    if ($problems | is-not-empty) { error make --unspanned { msg: ($problems | str join "; ") } }
    let dir = ($infra_root | path join $DIR $name)
    let d = (open ($dir | path join "under-test.nuon"))
    {
        name: $name
        chart: ($dir | path join "main.nu")
        layer: ($d | get -o layer | default { files: [], wait_for: [] })
        adds: ($d | get -o adds | default {})
    }
}

# The declarations of what this cluster carries (its inputs for `target`).
export def of_cluster [infra_root: string, target: string] {
    under_test_of (read_inputs (path_of $infra_root $target)) | each {|n| declaration $infra_root $n }
}

# The paths under `cluster` that `adds` sets.
def leaves [r: record, prefix: string] {
    $r | transpose key value | each {|kv|
        let path = if ($prefix | is-empty) { $kv.key } else { $"($prefix).($kv.key)" }
        if ($kv.value | describe | str starts-with "record") and $path not-in $CLUSTER_LISTS { leaves $kv.value $path } else { [$path] }
    } | flatten
}

# Why `adds` is not only an addition to `config` (a target's config.nuon). `catalog_env` gives, for a workload the catalog defines,
# the names of its own env entries; when given, a workload it does not define is refused too.
export def adds_problems [adds: record, config: record, catalog_env: any = null] {
    let elsewhere = ($adds | columns | where {|k| $k not-in ["cluster" "workloads"] } | each {|k| $"`($k)`: a configuration under test adds only under cluster and workloads" })
    let cluster = (leaves ($adds.cluster? | default {}) "" | each {|p|
        if $p not-in $CLUSTER_LISTS {
            $"cluster.($p): a configuration under test adds only to ($CLUSTER_LISTS | each {|l| $'cluster.($l)' } | str join ', '), and never changes what the target says"
        } else if not ($adds.cluster | get ($p | split row "." | into cell-path) | describe | str replace --regex "<.*" "" | $in in ["list" "table"]) {
            $"cluster.($p): a list, which the target's own is extended by"
        }
    } | compact)
    let workloads = ($adds.workloads? | default {} | transpose name w | each {|it|
        let own = ($config.workloads? | default {} | get -o $it.name | default {})
        let known = if $catalog_env == null { true } else { $it.name in ($catalog_env | columns) }
        let held = (($own.env? | default []) ++ (if $catalog_env == null { [] } else { $catalog_env | get -o $it.name | default [] | each {|n| { name: $n } } }) | get -o name | default [])
        [
            (if not $known { $"workloads.($it.name): no workload of that name in the catalog" })
            ...($it.w | columns | where {|k| $k not-in ["enabled" "env"] } | each {|k| $"workloads.($it.name).($k): a configuration under test enables a workload and adds to its env, nothing else" })
            (if ($it.w.enabled? | default true) != true { $"workloads.($it.name).enabled: a configuration under test enables, and never leaves out what the target runs" })
            ...($it.w.env? | default [] | where {|e| $e.name in $held } | each {|e| $"workloads.($it.name).env ($e.name): the target or the catalog already sets it, and a configuration under test only adds" })
        ] | compact
    } | flatten)
    $elsewhere ++ $cluster ++ $workloads
}

# `config` with each of `adds_list` merged over it: lists extended, the rest added. Judged first (`adds_problems`).
export def with_adds [config: record, adds_list: list] {
    $adds_list | reduce --fold $config {|adds, acc| $acc | merge deep --strategy=append $adds }
}

# A target's record (what its target.nu prints) with a layer and chart for each of `declared`, after the target's own layers.
export def with_layers [record: record, declared: list] {
    if ($declared | is-empty) { return $record }
    let after = ($record.apply_layers | last | get name)
    let layers = ($declared | each {|d| {
        name: $"($LAYER_PREFIX)($d.name)"
        depends_on: [$after]
        wait_for: ($d.layer.wait_for? | default [])
        files: ($d.layer.files? | default [])
    } })
    let apply_layers = ($record.apply_layers ++ $layers)
    $record
    | upsert apply_layers $apply_layers
    | upsert apply_order ($apply_layers | each {|l| $l.files } | flatten)
    | upsert charts ($record.charts ++ ($declared | get chart))
    | upsert under_test ($declared | get name)
}

# What a target.nu ends with: its record with the configurations under test this cluster carries.
export def layered [] {
    let record = $in
    with_layers $record (of_cluster $record.infra_root $record.name)
}
