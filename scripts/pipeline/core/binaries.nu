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
# linked, and the package each belongs to, by its id. Pure: no file is read and nothing is run.

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
