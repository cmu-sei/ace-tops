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
