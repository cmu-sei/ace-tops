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

# infra/attested.nu
#
# Which namespaces' pods Polar attests: its own, and those a target names besides (`cluster.attest_also` in its config.nuon), as
# sandbox-local names the test GitLab's (docs/architecture/http-observers.md, "GitLab"). The attestation agent watches each and
# has its read-only Role in each, and the render makes each namespace as it makes Polar's: a pod whose certificate Polar's CA
# issues is one the attestation agent can find, or the credentials agent refuses it as not found.

# Polar's own namespaces, then the target's others, in the order given.
export def attested_namespaces [cluster: record] {
    ($cluster.namespaces | values) ++ ($cluster.attest_also? | default [])
}

# What is wrong with a target's `attest_also`, each said: a list of distinct namespace names (RFC 1123 labels), none of them
# Polar's own, Kubernetes' (`kube-*`) or `default`.
export def attest_also_problems [also: any, own: list] {
    if not (($also | describe) =~ '^(list|table)') {
        return ["cluster.attest_also is a list of namespaces"]
    }
    mut problems = []
    for name in $also {
        if ($name | describe) != "string" or not ($name =~ '^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$') {
            $problems = ($problems | append $"cluster.attest_also: '($name)' is not a namespace's name")
        } else if $name in $own {
            $problems = ($problems | append $"cluster.attest_also: ($name) is Polar's own, attested already")
        } else if ($name | str starts-with "kube-") or $name == "default" {
            $problems = ($problems | append $"cluster.attest_also: ($name) is Kubernetes', not one Polar attests")
        }
    }
    let names = ($also | where {|n| ($n | describe) == "string" })
    if ($names | uniq | length) != ($names | length) {
        $problems = ($problems | append "cluster.attest_also names a namespace twice")
    }
    $problems
}

# What is wrong with a target's `cluster.issuance.server_also`, each said: servers the credentials agent vouches for beside
# Neo4j, each `{namespace, service_account, names}`, in a namespace Polar attests, with at least one name, each a DNS name.
export def server_also_problems [also: any, attested: list] {
    if not (($also | describe) =~ '^(list|table)') {
        return ["cluster.issuance.server_also is a list of {namespace, service_account, names}"]
    }
    $also | each {|s|
        let at = $"cluster.issuance.server_also ($s.namespace? | default '?')/($s.service_account? | default '?')"
        let names = ($s.names? | default [])
        [
            (if not (($s.namespace? | default "") in $attested) { $"($at): its namespace is not one Polar attests, so its pod could not be found" })
            (if ($s.service_account? | default "" | is-empty) { $"($at): it names no service account" })
            (if ($names | is-empty) { $"($at): it names nothing for the certificate" })
            ...($names | where {|n| not ($n =~ '^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$') } | each {|n| $"($at): '($n)' is not a DNS name" })
        ] | compact
    } | flatten
}

# A target's other servers as the floor's entries, as Neo4j's is (render.nu, neo4j_floor_entries): vouched for by the
# credentials agent, never signed on a token alone, with `groups` in their certificates (`under-test` for a configuration under test's).
export def floor_entries_also [also: list, groups: list<string> = []] {
    $also | each {|s|
        {
            workload: $"system:serviceaccount:($s.namespace):($s.service_account)"
            cert_type: "SERVER"
            names: $s.names
            vouched_only: true
            publish: []
            subscribe: []
            groups: $groups
        }
    }
}

# The namespaces a capability's Role goes in: the one it names, by its key among the cluster's namespaces, alone; or, when it
# names none, every namespace Polar attests. A key the cluster does not have is refused.
export def role_namespaces [role: record, cluster: record, capability: string] {
    match ($role.namespace? | default null) {
        null => (attested_namespaces $cluster)
        $key => {
            let found = ($cluster.namespaces | get -o $key)
            if $found == null {
                error make { msg: $"capability ($capability): its Role names the namespace `($key)`, which the cluster's namespaces do not have \(($cluster.namespaces | columns | str join ', ')\)" }
            }
            [$found]
        }
    }
}

# Why a capability's role may not be placed where the catalog says, or null. The agent's code holds a capability to the
# namespace its scaffold names (`role_namespaces`, by its key), or to none; the catalog's Role names the same key, and a
# capability held to none has a Role in each attested namespace, or a ClusterRole, and names none. `catalog` and
# `scaffold` are the two keys, null for none.
export def role_namespace_problem [catalog: any, scaffold: any, capability: string] {
    if $catalog == $scaffold {
        null
    } else if $catalog == null {
        $"capability ($capability): the agent's code holds it to the namespace `($scaffold)`, and the catalog places its role in none"
    } else if $scaffold == null {
        $"capability ($capability): the catalog's Role names the namespace `($catalog)`, and the agent's code holds it to none \(or its image was built before roles said their namespace: rebuild it\)"
    } else {
        $"capability ($capability): the catalog's Role names the namespace `($catalog)`, and the agent's code holds it to `($scaffold)`"
    }
}

# Polar's first namespaces, which the namespaces chart writes itself (namespaces.dhall), by their keys.
const FIRST = ["polar" "graph"]
const LEVELS = ["privileged" "baseline" "restricted"]
const MODES = ["enforce" "warn" "audit"]

# The namespaces Polar makes beyond its first, each with its labels: the cluster's other namespaces (the build namespace), with
# the Pod Security the cluster gives each by its key (`pod_security`), then those the target attests besides, with none. A
# Pod Security entry for a key the cluster does not have, or a level that is not one, is refused.
export def added_namespaces [cluster: record] {
    let security = ($cluster.pod_security? | default {})
    for key in ($security | columns) {
        if $key not-in ($cluster.namespaces | columns) {
            error make { msg: $"pod_security names `($key)`, which the cluster's namespaces do not have" }
        }
        for mode in ($security | get $key | columns) {
            let level = ($security | get $key | get $mode)
            if $mode not-in $MODES or $level not-in $LEVELS {
                error make { msg: $"pod_security.($key): `($mode): ($level)` is not a Pod Security mode \(($MODES | str join ', ')\) and level \(($LEVELS | str join ', ')\)" }
            }
        }
    }
    let own = ($cluster.namespaces | transpose key name | where {|n| $n.key not-in $FIRST } | each {|n|
        let modes = ($security | get -o $n.key | default {})
        { name: $n.name, labels: ($modes | transpose mode level | reduce --fold {} {|m, acc| $acc | insert $"pod-security.kubernetes.io/($m.mode)" $m.level }) }
    })
    $own ++ ($cluster.attest_also? | default [] | each {|name| { name: $name, labels: {} } })
}
