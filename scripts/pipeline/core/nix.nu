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
# What a Nix build did, read from what it said (build-inspect-ship, S2). Pure: nothing is run here.

# How a derivation's outputs came to be in the store this run, from what `nix build --dry-run` said it would do (its
# standard error): `built` when its `.drv` is in a "will be built" list, `fetched` when one of `outputs` is in a "will be
# fetched" list, `present` when neither, as they were in the store before the run. A list is its header's indented store
# paths, and ends at the first line that is not one. When a binary was built is a fact only if it was built here.
export def realisation [dry_run: string, drv: string, outputs: list<string>]: nothing -> string {
    mut list = ""
    mut built = []
    mut fetched = []
    for line in ($dry_run | lines) {
        if $line =~ '^(this|these \d+) derivations? will be built:' {
            $list = "built"
            continue
        }
        if $line =~ '^(this|these \d+) paths? will be fetched' {
            $list = "fetched"
            continue
        }
        if ($list != "") and ($line =~ '^\s+/nix/store/\S+$') {
            let path = $line | str trim
            if $list == "built" { $built = ($built | append $path) } else { $fetched = ($fetched | append $path) }
            continue
        }
        $list = ""
    }
    let fetched = $fetched
    if $drv in $built {
        "built"
    } else if ($outputs | any {|o| $o in $fetched }) {
        "fetched"
    } else {
        "present"
    }
}

# How a derivation's outputs came to be in the store, observed of the store itself, before and after the build. Stub
# (H2): nothing yet.
export def observed-realisation [outputs: list<string>, before: record, after: record]: nothing -> record {
    {realised: "", at: null}
}
