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

# scripts/pipeline/tests/nix.nu
# How a derivation's outputs came to be in the store this run (core/nix.nu, `realisation`): built here, fetched from a
# cache, or present before the run, read from what `nix build --dry-run` says it will do. Run: nu scripts/pipeline/tests/nix.nu

use std/assert
use ../core/nix.nu [realisation]

const DRV = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-cassini-server-1.0.0.drv"
const OUT = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-cassini-server-1.0.0"
const LOG = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-cassini-server-1.0.0-cargolog"

def main [] {
    let outputs = [$OUT $LOG]
    let tests = [
        {
            name: "a derivation the dry run will build was built here"
            body: {
                let said = $"these 2 derivations will be built:\n  /nix/store/cccccccccccccccccccccccccccccccc-dep.drv\n  ($DRV)\nthese 3 paths will be fetched \(1.20 MiB download, 5.01 MiB unpacked\):\n  /nix/store/dddddddddddddddddddddddddddddddd-x\n"
                assert equal (realisation $said $DRV $outputs) built
                assert equal (
                    realisation $"this derivation will be built:\n  ($DRV)\n" $DRV $outputs
                ) built
            }
        }
        {
            name: "an output the dry run will fetch was fetched"
            body: {
                let said = $"this path will be fetched \(0.01 MiB download, 0.05 MiB unpacked\):\n  ($LOG)\n"
                assert equal (realisation $said $DRV $outputs) fetched
                let both = $"these 2 paths will be fetched \(4.10 MiB download, 9.00 MiB unpacked\):\n  ($OUT)\n  ($LOG)\n"
                assert equal (realisation $both $DRV $outputs) fetched
            }
        }
        {
            name: "outputs the dry run will neither build nor fetch were present before the run"
            body: {
                assert equal (realisation "" $DRV $outputs) present
                let others = "this derivation will be built:\n  /nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-other.drv\n"
                assert equal (realisation $others $DRV $outputs) present
            }
        }
        {
            name: "only a list's own lines are its paths: a path named in other text is not"
            body: {
                let said = $"warning: Git tree is dirty\nnote: ($DRV) is mentioned here\n"
                assert equal (realisation $said $DRV $outputs) present
            }
        }
    ]

    let results = ($tests | each {|t|
        try { do $t.body; { name: $t.name, error: null } } catch {|e| { name: $t.name, error: $e.msg } }
    })
    for r in $results {
        if $r.error == null { print $"  ok    ($r.name)" } else { print -e $"  FAIL  ($r.name): ($r.error)" }
    }
    let failed = $results | where error != null | length
    if $failed > 0 {
        print -e $"($failed) of ($results | length) failed"
        exit 1
    }
    print $"all ($results | length) passed"
}
