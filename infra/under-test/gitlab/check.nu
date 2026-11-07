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

# infra/under-test/gitlab/check.nu
#
# Holds the GitLab pair's graph to what the seed made (docs/architecture/http-observers.md, G4d): `gitlab-seed check` against the
# expectation the ready script keeps in configmap/gitlab-seed-expected, asking Neo4j's HTTP endpoint through a forward of its own,
# as the administrator `user` (the client certificate Neo4j asks for, from ~/.config/polar-admin), the password from Neo4j's Secret
# on standard input. Prints the report; fails when anything expected is missing.
#
#   nu infra/under-test/gitlab/check.nu <user>

use ../../tools.nu
use main.nu [NAMESPACE]
use ready.nu [EXPECTED_CONFIGMAP]

const GRAPH = "polar-graph"
const NEO4J = "polar-db-svc"
const HOST = "polar-db-svc.polar-graph.svc.cluster.local"

def main [user: string] {
    let admin = ($env.HOME | path join ".config/polar-admin")
    let work = (mktemp --directory)
    let expected = ($work | path join "expected.json")
    ^kubectl -n $NAMESPACE get configmap $EXPECTED_CONFIGMAP -o jsonpath='{.data.expected\.json}' | save --force $expected
    let password = (^kubectl -n $GRAPH get secret neo4j-secret -o jsonpath='{.data.secret}' | decode base64 | decode | split row "/" | skip 1 | str join "/")
    let log = ($work | path join "forward.log")
    let pid = (^bash -c $"kubectl -n ($GRAPH) port-forward svc/($NEO4J) :7473 > ($log) 2>&1 & echo $!" | str trim | into int)
    let stop = {|| if $pid > 1 { ^kill $pid | complete | ignore }; rm -rf $work }
    let r = (try {
        mut port: any = null
        for _ in 1..60 {
            let at = (open --raw $log | parse --regex 'Forwarding from 127\.0\.0\.1:(?<port>\d+)' | get -o 0.port)
            if $at != null { $port = $at; break }
            sleep 500ms
        }
        if $port == null { error make --unspanned { msg: $"no forward to Neo4j: (open --raw $log | str trim)" } }
        let local = $port
        let tool = (tools command "gitlab-seed")
        $password | do {
            (^($tool | first) ...($tool | skip 1) check --expected $expected --url $"https://($HOST):7473" --connect $"127.0.0.1:($local)"
                --ca ($admin | path join "ca.pem") --cert ($admin | path join $"($user).crt") --key ($admin | path join $"($user).key"))
        } | complete
    } catch {|e| do $stop; error make --unspanned { msg: $e.msg } })
    do $stop
    print $r.stdout
    print -e ($r.stderr | lines | where {|l| not ($l | str starts-with "warning") } | last 2 | str join "\n")
    if $r.exit_code != 0 { exit 1 }
}
