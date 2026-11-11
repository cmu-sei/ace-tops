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

# infra/tests/role-namespaces.nu
#
# Tests that the resolver places a capability's role where the agent's code holds it, and nowhere else: job-run's Role in
# the namespace the scaffold's `role_namespaces` names (polar-agent-builder, capability::role_namespaces_of), refused when the
# scaffold names another, or none. Each test brings its own scaffold, in a directory of its own, so no cluster and no
# collected scaffolds are needed.
#
#   nu infra/tests/role-namespaces.nu

use std/assert

const RESOLVER = (path self | path dirname | path dirname | path join "resolve.nu")

# The build orchestrator's scaffold, as little of it as the resolver reads, with `role_namespaces` as given (null: none).
def orchestrator_scaffold [role_namespaces: any] {
    let scaffold = {
        agent: { name: "build-orchestrator", role: "controller" }
        requires: ["cassini" "encryption" "job-run"]
        shutdown_budget_minimum_secs: 1
        topics: []
        groups: []
        graph: []
        sections: []
        roles: { job-run: [{ api_groups: ["batch"], resources: ["jobs"], verbs: ["create"] }] }
    }
    if $role_namespaces == null { $scaffold } else { $scaffold | insert role_namespaces $role_namespaces }
}

# What `resolve.nu resources build-orchestrator` gives with that scaffold, for the committed sandbox-local target.
def resources_with [scaffold: record] {
    let dir = (mktemp --directory)
    $scaffold | to json | save ($dir | path join "build-orchestrator.json")
    let r = (with-env { POLAR_SCAFFOLD_DIR: $dir } { do { ^nu $RESOLVER resources build-orchestrator --target sandbox-local } | complete })
    rm -rf $dir
    $r
}

# What the resolver said, as one line: its error box wraps a long message and marks each line it wraps.
def said [stderr: string] {
    $stderr | str replace --all --regex '[\s|│]+' ' '
}

def main [] {
    let tests = [
        {
            name: "job-run's Role goes in the namespace the agent's code holds it to"
            body: {
                let r = (resources_with (orchestrator_scaffold { job-run: "builds" }))
                assert equal $r.exit_code 0 $r.stderr
                let resources = ($r.stdout | from json)
                assert equal ($resources.namespaced_roles | get namespace) ["polar-builds"]
                assert equal $resources.cluster_roles []
            }
        }
        {
            name: "a scaffold that says no namespace for job-run (or an image built before roles said one) is refused"
            body: {
                let r = (resources_with (orchestrator_scaffold null))
                assert ($r.exit_code != 0) $r.stdout
                assert (said $r.stderr | str contains "capability job-run: the catalog's Role names the namespace `builds`, and the agent's code holds it to none") $r.stderr
            }
        }
        {
            name: "a scaffold that holds job-run to another namespace is refused"
            body: {
                let r = (resources_with (orchestrator_scaffold { job-run: "core" }))
                assert ($r.exit_code != 0) $r.stdout
                assert (said $r.stderr | str contains "the agent's code holds it to `core`") $r.stderr
            }
        }
    ]

    let results = ($tests | each {|t|
        try { do $t.body; { name: $t.name, error: null } } catch {|e| { name: $t.name, error: $e.msg } }
    })
    for r in $results {
        if $r.error == null { print $"  ok    ($r.name)" } else { print -e $"  FAIL  ($r.name): ($r.error)" }
    }
    let failed = ($results | where error != null | length)
    if $failed > 0 { print -e $"($failed) of ($results | length) failed"; exit 1 }
    print $"all ($results | length) passed"
}
