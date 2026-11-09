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

# scripts/pipeline/tests/logging.nu
#
# Where the pipeline's log lines go: stdout, with its reports. A build's pod log is its two streams spliced together as the
# runtime reads them, a piece of one between pieces of the other, so a log line on stderr could land inside a long report on
# stdout (found 2026-11-08 rehearsing the watched build, docs/architecture/build-orchestrator.md, D4a). On one stream, the
# pipeline its one writer, each line is whole. Run: nu scripts/pipeline/tests/logging.nu

use std/assert

const LOGGING = path self ../core/logging.nu

def logged [commands: string, --level: string = ""]: nothing -> record {
    with-env { NU_LOG_LEVEL: $level } {
        ^$nu.current-exe --no-config-file --commands $"use '($LOGGING)' *; ($commands)" | complete
    }
}

def main [] {
    let tests = [
        {
            name: "every level a line is logged at goes to stdout, one line each, and none to stderr"
            body: {
                let got = (logged "log-info 'i' --component c; log-warn 'w'; log-error 'e'; log-debug 'd'" --level "debug")
                assert equal $got.exit_code 0 $got.stderr
                assert equal $got.stderr ""
                let lines = ($got.stdout | lines | ansi strip)
                assert equal ($lines | length) 4 $got.stdout
                for pair in ($lines | zip ["[INF] c — i" "[WRN] w" "[ERR] e" "[DBG] d"]) {
                    assert ($pair.0 =~ '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} ') $pair.0
                    assert ($pair.0 | str ends-with $pair.1) $"($pair.0) ends with ($pair.1)"
                }
            }
        }
        {
            name: "debug is logged only when asked for"
            body: {
                let got = (logged "log-debug 'd'; log-info 'i'")
                assert equal ($got.stdout | lines | length) 1 $got.stdout
                assert ($got.stdout | ansi strip | str ends-with "[INF] i\n") $got.stdout
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
