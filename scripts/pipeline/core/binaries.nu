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

# scripts/pipeline/core/binaries.nu
#
# What a binary's build says of it (build-inspect-ship, S2). A binary is built by Nix, from its crane derivation, which
# keeps cargo's JSON log of the build as its `cargolog` output. This module reads that log: which binaries the build
# linked, and the package each belongs to, by its id; which packages it compiled for a binary's target, and which of
# those an SBOM names it did not. Pure: no file is read and nothing is run.

# The package a cargo package id names: `{name, version}`. Cargo writes an id as its source, `#`, and `name@version`, or
# only the version when the name is the last segment of the source's path (`path+file:///build/source/logger#1.0.0`);
# before cargo 1.77, as `name version (source)`.
export def package-of-id [id: string]: nothing -> record {
    let old = $id | parse --regex '^(?<name>\S+) (?<version>\S+) \(.*\)$'
    if ($old | is-not-empty) {
        return {name: $old.0.name, version: $old.0.version}
    }
    let source = $id | split row "#" | first
    let spec = $id | split row "#" | last
    if ($spec | str contains "@") {
        let parts = $spec | split row "@"
        {
            name: ($parts | first)
            version: ($parts | skip 1 | str join "@")
        }
    } else {
        {
            name: (
                $source
                | split row "?"
                | first
                | path basename
            )
            version: $spec
        }
    }
}

# The binaries a build linked, from its cargo log's lines (`--message-format json`, one message a line): each
# `compiler-artifact` of a `bin` target with an executable, as `{name, package, version}`, the name its executable's file
# name. A binary is known by its package (its id), never by a path: the log's paths are the build sandbox's. A line that
# is not a JSON object is not a message, and is passed over.
export def linked-binaries [log: list<string>]: nothing -> list<record> {
    $log
    | each {|line| try { $line | from json } catch { null } }
    | where {|m| ($m | describe | str starts-with "record") }
    | where {|m| ($m.reason? | default "") == "compiler-artifact" }
    | where {|m| "bin" in ($m.target?.kind? | default []) }
    | where {|m| ($m.executable? | default null) != null }
    | each {|m|
        let package = package-of-id $m.package_id
        {name: ($m.executable | path basename), package: $package.name, version: $package.version}
    }
}

# The packages compiled for the target a binary runs on, from its build's cargo log's lines: `{name, version}`, each
# once, by name and version. A unit is the target's when every file it wrote lies under the directory of the binary's
# executable: cargo writes a build for a target (`CARGO_BUILD_TARGET`, crane's musl triple) under `target/<triple>/`,
# and what runs on the build machine under `target/<profile>/`. A proc-macro or a build script (kinds `proc-macro` and
# `custom-build`) is the build machine's wherever it lies. With no target set, the two share a directory, and a library
# only the build machine's units need is counted too: what was compiled is then overstated, never understated.
#
# A derivation that links more than one binary compiles them as one build: each binary's units are all of its target's.
# A binary the log did not link is an error.
export def compiled-for-target [log: list<string>, binary: string]: nothing -> list<record> {
    let artifacts = (
        $log
        | each {|line| try { $line | from json } catch { null } }
        | where {|m| ($m | describe | str starts-with "record") }
        | where {|m| ($m.reason? | default "") == "compiler-artifact" }
    )
    let linked = (
        $artifacts
        | where {|m| "bin" in ($m.target?.kind? | default []) }
        | where {|m| ($m.executable? | default null) != null }
        | where {|m| ($m.executable | path basename) == $binary }
    )
    if ($linked | is-empty) {
        error make {msg: $"($binary): its build's cargo log does not say it linked it"}
    }
    let dir = (
        $linked
        | first
        | get executable
        | path dirname
    ) + "/"
    $artifacts
    | where {|m| ($m.target?.kind? | default [] | all {|k| $k not-in [proc-macro custom-build] }) }
    | where {|m|
        let files = $m.filenames? | default []
        ($files | is-not-empty) and ($files | all {|f| $f | str starts-with $dir })
    }
    | each {|m| package-of-id $m.package_id }
    | uniq
    | sort-by name version
}

# The packages an SBOM names that a build did not compile for its target: each of `components` (`{name, version,
# purl}`, as the SBOM gives them) whose name and version are not among `compiled` (`compiled-for-target`), once each,
# in the SBOM's order.
export def not-compiled [components: list<record>, compiled: list<record>]: nothing -> list<record> {
    let have = $compiled | each {|p| $"($p.name)@($p.version)" }
    $components
    | where {|c| $"($c.name)@($c.version)" not-in $have }
    | uniq
}
