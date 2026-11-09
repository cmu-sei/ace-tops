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

# scripts/pipeline/tests/events.nu
#
# What the pipeline's provenance events carry (core/events.nu). Run: nu scripts/pipeline/tests/events.nu

use std/assert
use ../core/events.nu [reported-now, report-line, REPORT_PREFIX]

const EVENTS = path self ../core/events.nu

def main [] {
    let tests = [
        {
            name: "an event's time is RFC 3339 with its offset, as build-processor takes it, and is now"
            body: {
                let at = (reported-now)
                assert ($at =~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([+-]\d{2}:\d{2}|Z)$') $at
                let age = ((date now) - ($at | into datetime))
                assert ($age >= 0sec and $age < 5sec) $"($at) is ($age) from now"
            }
        }
        {
            # docs/architecture/build-orchestrator.md, revised 3: a build reports by printing; the orchestrator reads its log after
            # the pod ends, judges each report line and relays what passes.
            name: "a report is one line: the prefix, then the event as compact JSON, whatever its strings hold"
            body: {
                let event = { type: "artifact_produced", name: "a\nb", note: "polar-report {\"x\":1}", size: 3 }
                let line = (report-line $event)
                assert equal $REPORT_PREFIX "polar-report "
                assert ($line | str starts-with $REPORT_PREFIX) $line
                assert equal ($line | lines | length) 1 "a newline in a string stays escaped"
                assert equal ($line | str substring ($REPORT_PREFIX | str length).. | from json) $event "it reads back as the event"
            }
        }
        {
            # A record declared with a `null` field keeps that type: a later string there is refused, which lost every binary's
            # link (found 2026-11-08 rehearsing the watched build, docs/architecture/build-orchestrator.md, D4a).
            name: "a binary's link carries its binding digest when it has one, and null when it has none"
            body: {
                let reported = {|...args: string|
                    ^$nu.current-exe --no-config-file --commands $"use '($EVENTS)' emit-binary-linked; emit-binary-linked ($args | str join ' ')"
                    | complete
                }
                let with = (do $reported "sha256:b" "event-logger" "pkg:cargo/logger@1.0.0" "sha256:s" "--binding_digest" "sha256:d")
                assert equal $with.exit_code 0 $with.stderr
                let event = ($with.stdout | str trim | str substring ($REPORT_PREFIX | str length).. | from json)
                assert equal $event { type: "binary_linked", binary_content_hash: "sha256:b", binary_name: "event-logger", root_purl: "pkg:cargo/logger@1.0.0", sbom_content_hash: "sha256:s", binding_digest: "sha256:d" }
                let without = (do $reported "sha256:b" "event-logger" "pkg:cargo/logger@1.0.0" "sha256:s")
                assert equal $without.exit_code 0 $without.stderr
                assert equal ($without.stdout | str trim | str substring ($REPORT_PREFIX | str length).. | from json | get binding_digest) null
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
