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

# The inputs that belong to one cluster: how they are added, when they are discarded, and how they meet the target's own env.

use std/assert
use ../cluster-inputs.nu [ADMINS_VAR, named_cluster_problem, handed_off_of, inputs_from_record, with_handed_off, admins_of, another_clusters, empty, env_for, env_merged, path_of, reconcile, topology_of, with_admin, with_topology]

def main [] {
    let tests = [
        {
            # The port's review, step A: up.nu is told which cluster a run is for, by the uid of its kube-system namespace,
            # and refuses one KUBECONFIG reaches that is another. A kubeadm cluster's context is always
            # kubernetes-admin@kubernetes, so a context's name would not tell two apart.
            name: "a run names its cluster, and one that reaches another is refused"
            body: {
                assert equal (named_cluster_problem "uid-a" "uid-a") null
                let unnamed = (named_cluster_problem "" "uid-a")
                assert ($unnamed | str contains "--cluster uid-a") $unnamed
                let other = (named_cluster_problem "uid-b" "uid-a")
                assert ($other | str contains "uid-a") $other
                assert ($other | str contains "uid-b") $other
                assert ($other | str contains "KUBECONFIG") $other
            }
        }
        {
            name: "the file sits beside the target's config"
            body: { assert equal (path_of "/r/infra" "sandbox-local") "/r/infra/targets/sandbox-local/cluster-inputs.nuon" }
        }
        {
            name: "a topology is chosen before the cluster has a CA, ties to the cluster once it has one, and goes with it"
            body: {
                let chosen = (with_topology (empty) "separated" null)
                assert $chosen.changed
                assert equal (topology_of $chosen.inputs) "separated"
                assert equal $chosen.inputs.cluster null
                assert (not (another_clusters $chosen.inputs null))
                assert (not (another_clusters $chosen.inputs "ca-A"))
                let tied = (reconcile $chosen.inputs "ca-A")
                assert equal $tied.cluster "ca-A"
                assert equal (topology_of $tied) "separated"
                assert (another_clusters $tied "ca-B")
                assert (another_clusters $tied null)
                assert equal (topology_of (reconcile $tied "ca-B")) null
                assert equal (topology_of (empty)) null
            }
        }
        {
            name: "a machine without a cluster's inputs takes them from that cluster's signed record, and another cluster's record gives it nothing"
            body: {
                let values = { polar-git-server: { env: [[name, value]; [$ADMINS_VAR, "alice"]] } }
                let fact = { file: "f", sha256: "s", cluster_ca_sha256: "ca-1", topology: "separated", values: $values }
                let got = (inputs_from_record $fact "ca-1")
                assert equal $got.cluster "ca-1"
                assert equal $got.workloads $values
                assert equal (topology_of $got) "separated"
                assert equal (admins_of $got) ["alice"] "the person who publishes stays an administrator"
                assert (handed_off_of $got) "only a handed-off cluster's record is read"
                assert equal (inputs_from_record $fact "ca-2") null
                assert equal (inputs_from_record null "ca-1") null
                assert equal (inputs_from_record ($fact | reject values) "ca-1").workloads {}
            }
        }
        {
            name: "whether the deployment is handed off is recorded for the render, keeps the rest, and is false until it is"
            body: {
                assert (not (handed_off_of (empty)))
                let on = (with_handed_off ((with_topology (empty) "separated" "ca-A").inputs) true "ca-A")
                assert $on.changed
                assert (handed_off_of $on.inputs)
                assert equal (topology_of $on.inputs) "separated"
                assert (not (with_handed_off $on.inputs true "ca-A").changed)
                assert (not (handed_off_of (with_handed_off $on.inputs false "ca-A").inputs))
                assert (not (with_handed_off (empty) false null).changed) "nothing is written to say what is already so"
            }
        }
        {
            name: "choosing the same topology again changes nothing, and another replaces it"
            body: {
                let a = (with_topology (empty) "separated" "ca-A")
                assert (not (with_topology $a.inputs "separated" "ca-A").changed)
                let b = (with_topology $a.inputs "single" "ca-A")
                assert $b.changed
                assert equal (topology_of $b.inputs) "single"
            }
        }
        {
            name: "recording an administrator keeps the topology, and ties a file that was not yet tied"
            body: {
                let a = (with_admin (with_topology (empty) "separated" null).inputs "id-1" "ca-A")
                assert equal (topology_of $a.inputs) "separated"
                assert equal $a.inputs.cluster "ca-A"
                assert equal (admins_of $a.inputs) ["id-1"]
            }
        }
        {
            name: "an administrator is added to a cluster's inputs once, and a second one beside it"
            body: {
                let a = (with_admin (empty) "id-1" "ca-A")
                assert $a.changed
                assert equal (admins_of $a.inputs) ["id-1"]
                assert equal $a.inputs.cluster "ca-A"
                let again = (with_admin $a.inputs "id-1" "ca-A")
                assert (not $again.changed)
                assert equal $again.inputs $a.inputs
                let b = (with_admin $a.inputs "id-2" "ca-A")
                assert equal (admins_of $b.inputs) ["id-1" "id-2"]
            }
        }
        {
            name: "inputs made for another cluster are discarded, not extended"
            body: {
                let old = (with_admin (empty) "old-id" "ca-A").inputs
                let fresh = (with_admin $old "new-id" "ca-B")
                assert $fresh.changed
                assert equal (admins_of $fresh.inputs) ["new-id"]
                assert equal $fresh.inputs.cluster "ca-B"
                assert equal (reconcile $old "ca-B") (empty)
                assert equal (reconcile $old "ca-A") $old
                # no cluster yet: whatever was left over belongs to none
                assert equal (reconcile $old null) (empty)
            }
        }
        {
            name: "the env a workload is given comes from the inputs, and nothing is given to another workload"
            body: {
                let i = (with_admin (empty) "id-1" "ca-A").inputs
                assert equal (env_for $i "polar-git-server" | first | get value) "id-1"
                assert equal (env_for $i "cassini") []
                assert equal (env_for (empty) "polar-git-server") []
            }
        }
        {
            name: "a value the cluster supplies replaces the target's own of that name, and the rest stay"
            body: {
                let config = [{ name: "POLAR_GIT_SERVER_ADMINS", value: "stale-id" } { name: "OTHER", value: "x" }]
                let merged = (env_merged $config [{ name: "POLAR_GIT_SERVER_ADMINS", value: "id-1" }])
                assert equal ($merged | where name == "POLAR_GIT_SERVER_ADMINS" | length) 1
                assert equal ($merged | where name == "POLAR_GIT_SERVER_ADMINS" | first | get value) "id-1"
                assert equal ($merged | where name == "OTHER" | first | get value) "x"
                assert equal (env_merged $config []) $config
            }
        }
    ]

    let results = ($tests | each {|t|
        let r = (try { do $t.body; null } catch {|e| $e.msg })
        { name: $t.name, error: $r }
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
