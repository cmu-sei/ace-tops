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

# infra/under-test/gitlab/schema.nu
#
# GitLab's schema refreshed from the test GitLab (docs/architecture/http-observers.md, G4d): `gitlab-seed schema` through a forward of
# its own, with the observer's read_api token on standard input, into the file the GitLab pair's queries and samples are held to.
#
#   nu infra/under-test/gitlab/schema.nu

use ../../tools.nu
use main.nu [NAMESPACE, NAME, names]
use ready.nu [OBSERVER_TOKEN_SECRET]

const OUT = (path self | path dirname | path join "../../../src/agents/gitlab/schema/gitlab.graphql")

def main [] {
    let work = (mktemp --directory)
    let ca = ($work | path join "ca.pem")
    ^kubectl -n $NAMESPACE get configmap polar-ca -o jsonpath='{.data.ca\.pem}' | save --force $ca
    let token = (^kubectl -n $NAMESPACE get secret $OBSERVER_TOKEN_SECRET -o jsonpath='{.data.token}' | decode base64 | decode)
    let log = ($work | path join "forward.log")
    let pid = (^bash -c $"kubectl -n ($NAMESPACE) port-forward svc/($NAME) :443 > ($log) 2>&1 & echo $!" | str trim | into int)
    let stop = {|| if $pid > 1 { ^kill $pid | complete | ignore }; rm -rf $work }
    let r = (try {
        mut port: any = null
        for _ in 1..60 {
            let at = (open --raw $log | parse --regex 'Forwarding from 127\.0\.0\.1:(?<port>\d+)' | get -o 0.port)
            if $at != null { $port = $at; break }
            sleep 500ms
        }
        if $port == null { error make --unspanned { msg: $"no forward to GitLab: (open --raw $log | str trim)" } }
        let local = $port
        let tool = (tools command "gitlab-seed")
        $token | do { ^($tool | first) ...($tool | skip 1) schema --url $"https://(names | first)" --connect $"127.0.0.1:($local)" --ca $ca --out ($OUT | path expand) } | complete
    } catch {|e| do $stop; error make --unspanned { msg: $e.msg } })
    do $stop
    print -e ($r.stderr | lines | where {|l| $l | str starts-with "GitLab " } | str join "\n")
    if $r.exit_code != 0 { error make --unspanned { msg: $"the schema was not refreshed: ($r.stderr | lines | last 3 | str join '; ')" } }
}
