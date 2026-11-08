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

# infra/tests/facts.nu
#
# Tests of `resolve.nu facts`: what each workload is, in every target, for tools that judge a crate by how it is
# deployed. It reads no scaffold, so these need no cluster.
#
#   nu infra/tests/facts.nu

use std/assert

const RESOLVER = (path self | path dirname | path dirname | path join "resolve.nu")

def facts [] { ^nu $RESOLVER facts | from json }

def main [] {
    let all = (facts)
    let tests = {
        "every workload a target runs is listed once for it, and none it leaves out": {
            let targets = ($all | get target | uniq)
            assert ("sandbox-local" in $targets) $"($targets)"
            for t in $targets {
                let listed = ($all | where target == $t | get workload)
                assert equal ($listed | sort) ($listed | uniq | sort) $"($t) lists a workload twice"
                let runs = (^nu $RESOLVER names --target $t | from json)
                assert equal ($listed | sort) ($runs | sort) $t
            }
        }

        "a workload's crate is its scaffold package, or its image's name when it has none": {
            let local = ($all | where target == "sandbox-local")
            assert equal ($local | where workload == "cassini" | get package) ["cassini-broker"]
            assert equal ($local | where workload == "kube-consumer" | get package) ["kube-consumer"]
        }

        # The values in effect, not the entries': custody the entry turns off, the CA's pod with neither polar-init nor the
        # daemon, and many instances only where the credentials agent issues them.
        "each fact is the one in effect": {
            let local = ($all | where target == "sandbox-local")
            let one = {|w| $local | where workload == $w | first }
            assert equal (do $one "polar-scheduler-observer").custody false
            assert equal (do $one "kube-observer").custody true
            let ca = (do $one "cert-issuer")
            assert equal [$ca.kind $ca.polar_init $ca.custody] ["ca" false false]
            assert equal (do $one "harness-producer").instances "many"
            assert ($local | where workload != "harness-producer" | all {|w| $w.instances == "one" })
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
        if $r.error == null {
            print $"  ok    ($r.name)"
        } else {
            print -e $"  FAIL  ($r.name): ($r.error)"
        }
    }

    let failed = ($results | where error != null | length)
    if $failed > 0 {
        print -e $"($failed) of ($results | length) failed"
        exit 1
    }
    print $"all ($results | length) passed"
}
