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

# What infra/running-config.nu gives the two tools. Reaching a broker is checked on a cluster.

use std/assert
use ../running-config.nu *

def main [] {
    let tests = [
        {
            name: "asking names the agent, the certificate's owner and the forward's local end"
            body: {
                let args = (ask_args "jira-observer" "alice" "/d" 18081 "cassini.example")
                assert equal $args ["jira-observer" "--user" "alice" "--dir" "/d" "--broker" "127.0.0.1:18081" "--server-name" "cassini.example"]
            }
        }
        {
            name: "the template reads the answer from standard input, and a scaffold only if one is given"
            body: {
                assert equal (template_args "jira-observer" "/d" "") ["template" "jira-observer" "--settings" "--running" "-" "--dir" "/d"]
                assert equal (template_args "jira-observer" "/d" "/s.json" | last 2) ["--scaffold" "/s.json"]
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
