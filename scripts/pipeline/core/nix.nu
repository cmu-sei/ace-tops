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

# scripts/pipeline/core/nix.nu
#
# What a Nix build did, read from what the store says of its outputs (build-inspect-ship, S2). Pure but for
# `store-records`, which asks nix.

# How one output of a derivation came to be in the store, observed of the store itself, never planned: `outputs` are
# all the derivation's, `output` the one judged (a binary's is `out`: what is said of a binary is of the output that
# holds it, never of another, such as its cargo log); `before` is what `nix-store --check-validity --print-invalid
# <outputs>` gave before the build (the outputs not valid, one a line), and `after` what `nix path-info` gave after it in
# JSON of `output` (`store-records`), each `{exit_code, stdout}` as `complete` gives them.
#
# - `present`: `output` was valid before the build, whatever became of the others;
# - `built`: it was not, and the store records it as built on this machine (`ultimate`); `at`, the time the store
#   registered it, when it records one;
# - `fetched`: it was not, and the store records it as not built here, and signed: substituted from a cache, or copied
#   from another store;
# - `unknown`: anything else (a command that failed or said what is not read here, `output` not valid after), with no
#   time.
#
# `path-info --json` is read in both shapes Nix writes: an object keyed by path (2.19 and after), or a list, each with
# its `path`, `ultimate` left out when false (before).
export def observed-realisation [
    outputs: list<string>
    output: string
    before: record
    after: record
]: nothing -> record {
    let unknown = {realised: "unknown", at: null}
    if $before.exit_code != 0 or $output not-in $outputs { return $unknown }
    let invalid = $before.stdout | lines | str trim | where {|l| $l | is-not-empty }
    if ($invalid | any {|p| $p not-in $outputs }) { return $unknown }
    if $output not-in $invalid { return {realised: "present", at: null} }
    if $after.exit_code != 0 { return $unknown }
    let parsed = try {
        $after.stdout | from json
    } catch {
        null
    }
    let shape = $parsed | describe
    let infos = if ($shape | str starts-with "record") {
        $parsed | transpose path info
    } else if $shape =~ '^(list|table)' {
        $parsed
        | where {|i| ($i | describe | str starts-with "record") }
        | each {|i| {path: ($i.path? | default ""), info: $i} }
    } else {
        return $unknown
    }
    let info = $infos | where path == $output | get -o 0.info
    if not ($info | describe | str starts-with "record") {
        $unknown
    } else if ($info.ultimate? | default false) == true {
        let registered = $info.registrationTime? | default null
        {
            realised: "built"
            at: (
                if ($registered | describe) == "int" {
                    $registered * 1_000_000_000 | into datetime | format date "%Y-%m-%dT%H:%M:%S%:z"
                }
            )
        }
    } else if ($info.signatures? | default [] | is-not-empty) {
        {realised: "fetched", at: null}
    } else {
        $unknown
    }
}

# What the store records of `outputs`, as `nix path-info` gives it in JSON (`{exit_code, stdout, stderr}`, as `complete`
# gives them), for `observed-realisation`. JSON format 1 is asked for (`--json-format 1`), as Nix 2.34 wants: bare `--json`
# is deprecated there, and to become an error. A Nix that has no `--json-format` (2.18.2, the CI image's, from ACE's
# nixpkgs) refuses the flag, and is asked again with bare `--json`. Whichever shape either gives, `observed-realisation`
# reads it. Tried, not told by a version: any failure of the first asks the second, which fails as well when the cause
# was not the flag.
export def store-records [outputs: list<string>]: nothing -> record {
    let versioned = (^nix path-info --json --json-format 1 ...$outputs | complete)
    if $versioned.exit_code == 0 { return $versioned }
    ^nix path-info --json ...$outputs | complete
}
