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

use std/assert
use ../under-test.nu *
use ../cluster-inputs.nu [empty with_under_test under_test_of inputs_from_record]

# A target's config.nuon, as much of it as a configuration under test meets.
def target [] {
    {
        cluster: { issuance: { floor_enforced: true }, registry_in_cluster: { node_port: 30500 } }
        workloads: {
            secret-harness: { enabled: false }
            gitlab-observer: { env: [{ name: "POLAR_LOG", value: "info" }] }
        }
    }
}

# What the test GitLab adds (infra/under-test/gitlab/under-test.nuon, CT3), as a declaration's `adds`.
def gitlab_adds [] {
    {
        cluster: {
            attest_also: ["gitlab-test"]
            issuance: { server_also: [{ namespace: "gitlab-test", service_account: "gitlab", names: ["gitlab.gitlab-test.svc.cluster.local"] }] }
        }
        workloads: {
            gitlab-observer: { enabled: true, env: [{ name: "POLAR_SOURCE_LIMIT", value: "5" }] }
        }
    }
}

# The record a target.nu prints, as much of it as layering meets.
def target_record [] {
    let layers = [
        { name: "platform", depends_on: [], wait_for: [], files: ["namespaces.yaml"] }
        { name: "agents", depends_on: ["platform"], wait_for: [], files: ["agents.yaml"] }
    ]
    { charts: ["/r/infra/layers/1-platform/infra/namespaces/main.nu"], apply_layers: $layers, apply_order: ($layers | each {|l| $l.files } | flatten) }
}

def main [] {
    let tests = {
        "with no configuration under test the target's config is as it is": {
            assert equal (with_adds (target) []) (target)
        }

        "a configuration under test adds what it says, and the target keeps all it had": {
            let merged = (with_adds (target) [(gitlab_adds)])
            assert equal $merged.cluster.attest_also ["gitlab-test"]
            assert equal ($merged.cluster.issuance.server_also | get namespace) ["gitlab-test"]
            assert equal $merged.cluster.issuance.floor_enforced true
            assert equal $merged.cluster.registry_in_cluster.node_port 30500
            assert equal $merged.workloads.gitlab-observer.enabled true
            assert equal ($merged.workloads.gitlab-observer.env | get name) ["POLAR_LOG" "POLAR_SOURCE_LIMIT"]
            assert equal $merged.workloads.secret-harness.enabled false
            # Two add up: each list keeps both.
            let other = { cluster: { attest_also: ["ab-test"] } }
            assert equal (with_adds (target) [(gitlab_adds) $other] | get cluster.attest_also) ["gitlab-test" "ab-test"]
        }

        "a configuration under test only adds: what it would change or take away is refused, naming it": {
            for case in [
                [{ cluster: { issuance: { floor_enforced: false } } } "floor_enforced"]
                [{ cluster: { registry_in_cluster: { node_port: 1 } } } "registry_in_cluster"]
                [{ workloads: { secret-harness: { enabled: false } } } "enabled"]
                [{ workloads: { gitlab-observer: { env: [{ name: "POLAR_LOG", value: "debug" }] } } } "POLAR_LOG"]
                [{ workloads: { gitlab-observer: { needs: ["graph-write"] } } } "needs"]
                [{ elsewhere: {} } "elsewhere"]
            ] {
                let problems = (adds_problems $case.0 (target))
                assert ($problems | any {|p| $p | str contains $case.1 }) $"($case.0 | to nuon): ($problems | to nuon)"
            }
            assert equal (adds_problems (gitlab_adds) (target)) []
        }

        "a configuration under test's layer comes after the target's own, with its chart, and none leaves the record as it is": {
            assert equal (with_layers (target_record) []) (target_record)
            let declared = [{ name: "gitlab", chart: "/r/infra/under-test/gitlab/main.nu", layer: { files: ["gitlab-test.yaml"], wait_for: [] } }]
            let layered = (with_layers (target_record) $declared)
            assert equal ($layered.apply_layers | get name) ["platform" "agents" "under-test-gitlab"]
            assert equal ($layered.apply_layers | last | get depends_on) ["agents"]
            assert equal $layered.apply_order ["namespaces.yaml" "agents.yaml" "gitlab-test.yaml"]
            assert equal ($layered.charts | last) "/r/infra/under-test/gitlab/main.nu"
        }

        "a cluster's inputs say which configurations under test it carries, and its signed record gives them back": {
            assert equal (under_test_of (empty)) []
            let one = (with_under_test (empty) ["gitlab"] "ca1")
            assert equal (under_test_of $one.inputs) ["gitlab"]
            assert $one.changed
            assert (not (with_under_test $one.inputs ["gitlab"] "ca1").changed) "the same again changes nothing"
            # Running without it takes it away.
            assert equal (under_test_of (with_under_test $one.inputs [] "ca1").inputs) []
            let fact = { cluster_ca_sha256: "ca1", topology: null, values: {}, under_test: ["gitlab"] }
            assert equal (under_test_of (inputs_from_record $fact "ca1")) ["gitlab"]
        }

        "a configuration under test is named as a namespace is, and is one the repository declares": {
            assert equal (name_problems "gitlab" ["gitlab"]) []
            for bad in ["GitLab" "" "a b" "../x"] {
                assert ((name_problems $bad ["gitlab"]) | is-not-empty) $bad
            }
            assert ((name_problems "nowhere" ["gitlab"]) | is-not-empty) "not declared"
        }
    }

    let results = ($tests | transpose name body | each {|t|
        try {
            do $t.body
            { name: $t.name, error: null }
        } catch {|e|
            { name: $t.name, error: $e.msg }
        }
    })
    for r in $results {
        if $r.error == null { print $"  ok    ($r.name)" } else { print -e $"  FAIL  ($r.name): ($r.error)" }
    }
    let failed = ($results | where error != null | length)
    if $failed > 0 {
        print -e $"($failed) of ($results | length) failed"
        exit 1
    }
    print $"all ($results | length) passed"
}
