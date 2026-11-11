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

# Every import in infra/schema that names a file of the schema beside it carries that file's semantic hash, so a cold Dhall
# cache can check it and a warm one cannot serve an older file under the pin. A pin left behind when the file changes is
# refused here, not by the first render on a new machine.

use std/assert
use ../dhall-cache.nu [cache_dir]

const SCHEMA = path self ../schema

# The hash-pinned imports in Dhall text, each a { target, sha }: the import is the word before `sha256:`, on its line or the
# one before, however the expression is laid out. `local` keeps those that name a file of the schema (`./`, `../`).
def pins [text: string, --local] {
    let words = ($text | split row --regex '\s+' | where {|w| $w | is-not-empty })
    let found = ($words | enumerate | where {|e| ($e.item | str starts-with "sha256:") and $e.index > 0 } | each {|e|
        { target: ($words | get ($e.index - 1)), sha: ($e.item | str replace "sha256:" "") }
    })
    if $local { $found | where {|p| ($p.target | str starts-with "./") or ($p.target | str starts-with "../") } } else { $found }
}

def main [] {
    let tests = [
        {
            name: "a pin is read as the import before it, on its line or the one before, and local keeps only the schema's own files"
            body: {
                let text = "let A =\n      ./agents.dhall\n        sha256:aaaa\n\nlet K =\n      https://example.org/package.dhall\n        sha256:bbbb\n"
                assert equal (pins $text) [{ target: "./agents.dhall", sha: "aaaa" }, { target: "https://example.org/package.dhall", sha: "bbbb" }]
                assert equal (pins $text --local) [{ target: "./agents.dhall", sha: "aaaa" }]
                assert equal (pins "let A = ./a.dhall sha256:cccc\nlet B = ../b.dhall\n  sha256:dddd" --local) [{ target: "./a.dhall", sha: "cccc" }, { target: "../b.dhall", sha: "dddd" }]
            }
        }
        {
            name: "every local pin in infra/schema is the semantic hash of the file it names"
            body: {
                let files = (ls ($SCHEMA | path join "*.dhall" | into glob) | get name)
                let all = ($files | each {|f| pins (open --raw $f) | insert from $f } | flatten)
                let local = ($all | where {|p| ($p.target | str starts-with "./") or ($p.target | str starts-with "../") })
                # The schema pins its own files today; finding none means the reading is wrong, not that all is well.
                if ($local | is-empty) { error make { msg: "no local pin found in infra/schema" } }
                # Hashing a schema file resolves what it imports. Without dhall, or with a remote import the cache lacks, this
                # machine cannot judge the pins, and says so rather than fetch.
                if (which dhall | is-empty) { return "skip: dhall is not on PATH" }
                let uncached = ($all | where {|p| $p not-in $local } | where {|p|
                    not (($p.sha | is-not-empty) and ((cache_dir) | path join $"1220($p.sha)" | path exists))
                } | get target | uniq)
                if ($uncached | is-not-empty) { return $"skip: not in the Dhall cache: ($uncached | str join ', ')" }
                let wrong = ($local | each {|p|
                    let file = ($SCHEMA | path join $p.target | path expand)
                    let actual = (^dhall hash --file $file | str trim | str replace "sha256:" "")
                    if $actual == $p.sha { null } else {
                        $"($p.from | path basename) pins ($p.target) at ($p.sha), but the file hashes to ($actual)"
                    }
                } | compact)
                if ($wrong | is-not-empty) { error make { msg: ($wrong | str join '; ') } }
            }
        }
    ]
    let results = ($tests | each {|t|
        let r = (try { { result: (do $t.body), error: null } } catch {|e| { result: null, error: $e.msg } })
        { name: $t.name, error: $r.error, skip: (if ($r.result | describe) == "string" and ($r.result | str starts-with "skip:") { $r.result } else { null }) }
    })
    for r in $results {
        if $r.error != null { print -e $"  FAIL  ($r.name): ($r.error)" } else if $r.skip != null { print $"  ($r.skip)  ($r.name)" } else { print $"  ok    ($r.name)" }
    }
    let failed = ($results | where error != null | length)
    if $failed > 0 {
        print -e $"($failed) of ($results | length) failed"
        exit 1
    }
    print $"all ($results | length) passed"
}
