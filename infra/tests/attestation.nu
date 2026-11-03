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

# What a bring-up reports of the attestation agent, from what it logs (docs/architecture/attestation-when-it-cannot-answer.md, "The agent proves itself").

use std/assert
use ../attestation.nu [attestation_report]

def main [] {
    let proved = "2026-11-03T08:36:30Z  INFO attestation_agent::supervisor: it has proved itself: its verdicts stand judged=20 condemned=0"
    let doubts = "2026-11-03T08:40:00Z ERROR attestation_agent::supervisor: it doubts itself, and answers that it cannot say until this has gone: CondemnsMost { condemned: 5, judged: 6 }"
    let waiting = "2026-11-03T08:36:00Z  INFO attestation_agent::supervisor: it cannot say yet: NoRecord"
    let tests = [
        {
            name: "an agent that has proved itself is said to have"
            body: { assert equal (attestation_report ["other" $waiting $proved "other"]).verdict "proved" }
        }
        {
            name: "the last thing it said is what stands, either way"
            body: {
                assert equal (attestation_report [$proved $doubts]).verdict "doubts"
                assert equal (attestation_report [$doubts $proved]).verdict "proved"
            }
        }
        {
            name: "a doubt says what it is, and what follows from it"
            body: {
                let r = (attestation_report [$doubts])
                assert ($r.line | str contains "CondemnsMost { condemned: 5, judged: 6 }") $r.line
                assert ($r.line | str contains "unattested") $r.line
            }
        }
        {
            name: "waiting for what it needs is told from doubting itself"
            body: {
                let r = (attestation_report [$waiting])
                assert equal $r.verdict "waiting"
                assert ($r.line | str contains "NoRecord") $r.line
            }
        }
        {
            name: "proved with no record is still waiting for one, and says so"
            body: {
                let partly = "2026-11-03T08:36:00Z  INFO attestation_agent::supervisor: it has proved itself as far as it can with no record: it holds pods to their owners judged=20 condemned=0"
                let r = (attestation_report [$partly])
                assert equal $r.verdict "waiting"
                assert ($r.line | str contains "no signed record") $r.line
                assert equal (attestation_report [$partly $proved]).verdict "proved"
            }
        }
        {
            name: "colours in a log line do not hide what it says"
            body: { assert equal (attestation_report [$"(ansi green)($proved)(ansi reset)"]).verdict "proved" }
        }
        {
            name: "a log that says nothing of itself is unknown, and says where to look"
            body: {
                for lines in [[] ["other" "lines"]] {
                    let r = (attestation_report $lines)
                    assert equal $r.verdict "unknown"
                    assert ($r.line | str contains "kubectl logs") $r.line
                }
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
