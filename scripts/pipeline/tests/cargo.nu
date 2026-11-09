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

# scripts/pipeline/tests/cargo.nu
#
# Where the pipeline finds the Cargo workspace it builds: from where its own scripts sit, so a build's source, an archive with
# no `.git` (docs/architecture/build-orchestrator.md, D4), is found as a checkout is. Run: nu scripts/pipeline/tests/cargo.nu

use std/assert

const PIPELINE = path self ..

# A copy of the pipeline's scripts in a tree of its own, with no `.git` anywhere above it, and the workspace's manifest if
# `with_manifest`; the tree's root.
def a_tree [with_manifest: bool]: nothing -> string {
    let root = (mktemp --directory --tmpdir)
    mkdir ($root | path join "scripts")
    cp --recursive $PIPELINE ($root | path join "scripts" "pipeline")
    if $with_manifest {
        mkdir ($root | path join "src" "agents")
        "[workspace]\n" | save ($root | path join "src" "agents" "Cargo.toml")
    }
    $root
}

# What `workspace-root` says, asked from `cwd` in a fresh nu, with the tree's own copy of the module; a refusal, its message.
def asked [root: string, cwd: string, ...args: string]: nothing -> record {
    let module = ($root | path join "scripts" "pipeline" "core" "cargo.nu")
    do {
        cd $cwd
        ^$nu.current-exe --no-config-file --commands $"use '($module)' workspace-root; try { workspace-root ($args | str join ' ') } catch {|e| print -e $e.msg; exit 1 }" | complete
    }
}

def main [] {
    let tests = [
        {
            name: "a tree with no .git is found from where the scripts sit, whatever the directory it is asked from"
            body: {
                let root = (a_tree true)
                let elsewhere = (mktemp --directory --tmpdir)
                assert (not ($root | path join ".git" | path exists))
                let got = (asked $root $elsewhere)
                rm --recursive --force $root $elsewhere
                assert equal $got.exit_code 0 $got.stderr
                assert equal ($got.stdout | str trim) ($root | path join "src" "agents")
            }
        }
        {
            name: "a tree with no workspace is refused, naming where it looked"
            body: {
                let root = (a_tree false)
                let got = (asked $root $root)
                rm --recursive --force $root
                assert ($got.exit_code != 0)
                assert str contains $got.stderr ($root | path join "src" "agents" "Cargo.toml")
            }
        }
        {
            name: "the commit the orchestrator names is the build's, and git is not asked for it"
            body: {
                let root = (a_tree true)
                let module = ($root | path join "scripts" "pipeline" "core" "cargo.nu")
                let got = do {
                    cd $root
                    with-env { CI_COMMIT_SHA: ("a" | fill --character "a" --width 40), PATH: "/nonexistent" } {
                        ^$nu.current-exe --no-config-file --commands $"use '($module)' source-commit; try { source-commit } catch {|e| print -e $e.msg; exit 1 }" | complete
                    }
                }
                rm --recursive --force $root
                assert equal $got.exit_code 0 $got.stderr
                assert equal ($got.stdout | str trim) ("a" | fill --character "a" --width 40)
            }
        }
        {
            name: "a manifest given is the workspace, wherever it is"
            body: {
                let root = (a_tree false)
                let got = (asked $root $root "--manifest-path" "/elsewhere/Cargo.toml")
                rm --recursive --force $root
                assert equal ($got.stdout | str trim) "/elsewhere"
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
