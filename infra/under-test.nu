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

# What `under-test.nuon` may say.
const KEYS = ["adds" "layer" "secrets" "ready" "images" "documents" "credentials"]

# Why a document or credential a declaration names cannot be signed: each is a section of polar-schedules (`permanent/`, where the
# scheduler's watcher reads), at a version from 1; a document's body is a projection (Dhall, which `polar-sign runtime --projection`
# checks against the agent's schema) or what a script prints (`make`), either a file found from the declaration's directory; a
# credential is a token the cluster holds in a Secret (`secret: { namespace, name, key }`), sealed to the agent's escrow key.
def document_problems [d: record, dir: string] {
    let where = ($d.path? | default "")
    let found = {|f| ($f | is-not-empty) and ($dir | path join $f | path exists) }
    let made = ([($d.projection? | default "") ($d.make? | default "")] | where {|f| $f | is-not-empty })
    [
        (if not ($where | str starts-with "permanent/") { $"($where): a document is a section of polar-schedules under permanent/" })
        (if ($d.agent? | default "" | is-empty) or ($d.section? | default "" | is-empty) { $"($where): an agent and a section" })
        (if (($d.version? | describe) != "int") or ($d.version? | default 0) < 1 { $"($where): a version, a whole number from 1" })
        (if ($made | length) != 1 { $"($where): its body from one file, a projection or make" })
        ...($made | where {|f| not (do $found $f) } | each {|f| $"($where): no ($f) from infra/($DIR)" })
    ] | compact
}

def credential_problems [c: record] {
    let where = ($c.path? | default "")
    [
        (if not ($where | str starts-with "permanent/") { $"($where): a credential is a section of polar-schedules under permanent/" })
        (if ($c.agent? | default "" | is-empty) or ($c.name? | default "" | is-empty) { $"($where): an agent and a name" })
        (if ($c.host_pattern? | default "" | is-empty) { $"($where): a host_pattern, the host the credential is bound to" })
        (if (($c.version? | describe) != "int") or ($c.version? | default 0) < 1 { $"($where): a version, a whole number from 1" })
        (if ([namespace name key] | any {|k| ($c.secret? | default {} | get -o $k | default "" | is-empty) }) { $"($where): a secret, { namespace, name, key }, that holds it" })
    ] | compact
}

# A declaration: its name, its chart, its layer, what it adds; the scripts up.nu runs for it, each a file beside its chart or null
# (`secrets`, with the target's secrets; `ready`, once Flux has its layer ready); and the images it names outside an `image:` line,
# as `<image>:<tag>` rows of infra/images.nuon, which the images step mirrors and the render pins.
export def declaration [infra_root: string, name: string] {
    let problems = (name_problems $name (declared $infra_root))
    if ($problems | is-not-empty) { error make --unspanned { msg: ($problems | str join "; ") } }
    let dir = ($infra_root | path join $DIR $name)
    let d = (open ($dir | path join "under-test.nuon"))
    let script = {|key|
        let given = ($d | get -o $key)
        if $given == null { return null }
        let p = ($dir | path join $given)
        if ($given | path dirname | is-not-empty) or not ($p | path exists) { null } else { $p }
    }
    let images = ($d | get -o images | default [])
    let wrong = [
        ...($d | columns | where {|k| $k not-in $KEYS } | each {|k| $"`($k)`: a declaration says only ($KEYS | str join ', ')" })
        ...(["secrets" "ready"] | where {|k| ($d | get -o $k) != null and (do $script $k) == null } | each {|k|
            $"`($k)`: ($d | get $k) is to be a file beside its chart, in infra/($DIR)/($name)/"
        })
        ...($images | where {|i| not ($i =~ '^[a-z0-9][a-z0-9._-]*:[A-Za-z0-9._-]+$') } | each {|i|
            $"`images`: ($i) is to be an image of infra/images.nuon and its tag, as <image>:<tag>"
        })
        ...($d | get -o documents | default [] | each {|doc| document_problems $doc $dir } | flatten)
        ...($d | get -o credentials | default [] | each {|c| credential_problems $c } | flatten)
        ...(($d | get -o documents | default []) ++ ($d | get -o credentials | default []) | get -o path | default [] | uniq --repeated
            | each {|p| $"($p): named twice" })
    ]
    if ($wrong | is-not-empty) { error make --unspanned { msg: $"under test ($name): ($wrong | str join '; ')" } }
    {
        name: $name
        chart: ($dir | path join "main.nu")
        layer: ($d | get -o layer | default { files: [], wait_for: [] })
        adds: ($d | get -o adds | default {})
        secrets: (do $script "secrets")
        ready: (do $script "ready")
        images: $images
        documents: ($d | get -o documents | default [] | each {|doc|
            let at = {|key| if ($doc | get -o $key | default "" | is-empty) { null } else { $dir | path join ($doc | get $key) | path expand } }
            $doc | upsert projection (do $at "projection") | upsert make (do $at "make")
        })
        credentials: ($d | get -o credentials | default [])
    }
}

# The documents of the configurations `carried` declares that polar-schedules (`existing`, its paths) does not hold yet.
export def documents_missing [carried: list, existing: list<string>] {
    $carried | each {|d| $d.documents } | flatten | where {|doc| $doc.path not-in $existing }
}

# Their credentials polar-schedules does not hold yet.
export def credentials_missing [carried: list, existing: list<string>] {
    $carried | each {|d| $d.credentials } | flatten | where {|c| $c.path not-in $existing }
}

# What a configuration under test the repository declares (`all`) and the cluster no longer carries (`carried`, names) left in
# polar-schedules: its documents and credentials, which go with it.
export def left_behind [all: list, carried: list<string>, existing: list<string>] {
    $all | where {|d| $d.name not-in $carried } | each {|d| ($d.documents ++ $d.credentials) | get path } | flatten
    | where {|p| $p in $existing } | uniq
}

# What `polar-sign sign` takes to seal credential `c`: its one entry, a token whose secret is read from standard input (`-`).
export def credential_input [c: record] {
    {
        agent: $c.agent, section: "credentials", version: $c.version
        body: { credentials: [{ name: $c.name, host_pattern: $c.host_pattern, kind: "token", secret: "-" }] }
    } | to json
}

# The declarations of what this cluster carries (its inputs for `target`).
export def of_cluster [infra_root: string, target: string] {
    let declared = (under_test_of (read_inputs (path_of $infra_root $target)) | each {|n| declaration $infra_root $n })
    let problems = (layer_problems $declared)
    if ($problems | is-not-empty) { error make --unspanned { msg: ($problems | str join "; ") } }
    $declared
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
        let left_out = (($own | describe | str starts-with "record") and ($own.enabled? | default true) == false)
        [
            (if not $known { $"workloads.($it.name): no workload of that name in the catalog" })
            # What the target runs is not under test (CT2): a configuration under test enables what the target leaves out, and configures only that.
            (if $known and not $left_out { $"workloads.($it.name): the target runs it, so a configuration under test neither enables nor configures it" })
            ...($it.w | columns | where {|k| $k not-in ["enabled" "env"] } | each {|k| $"workloads.($it.name).($k): a configuration under test enables a workload and adds to its env, nothing else" })
            (if ($it.w.enabled? | default null) != true { $"workloads.($it.name).enabled: a configuration under test says `enabled: true` of each workload it names, and never leaves out what the target runs" })
            ...($it.w.env? | default [] | where {|e| $e.name in $held } | each {|e| $"workloads.($it.name).env ($e.name): the target or the catalog already sets it, and a configuration under test only adds" })
        ] | compact
    } | flatten)
    $elsewhere ++ $cluster ++ $workloads
}

# What `declared` make, and so what is under test (docs/architecture/configurations-under-test.md, CT2): the catalog workloads they
# enable, by name, and the servers they put on the floor. Their certificates carry `g:under-test`.
export def marked [declared: list] {
    {
        workloads: ($declared | each {|d| $d.adds.workloads? | default {} | columns } | flatten | uniq | sort)
        servers: ($declared | each {|d| $d.adds.cluster?.issuance?.server_also? | default [] } | flatten)
    }
}

# Why a declaration's layer does not hold what it makes: each workload it enables is rendered into `<name>.yaml`, which is to be in
# its layer, so the deployment record marks it under test as its certificate is.
export def layer_problems [declared: list] {
    $declared | each {|d|
        $d.adds.workloads? | default {} | columns | where {|w| $"($w).yaml" not-in ($d.layer.files? | default []) } | each {|w|
            $"under test ($d.name): it enables ($w), so its layer holds ($w).yaml"
        }
    } | flatten
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
