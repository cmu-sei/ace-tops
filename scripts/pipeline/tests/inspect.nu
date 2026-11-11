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

# scripts/pipeline/tests/inspect.nu
# What an image holds (core/inspect.nu): an OCI archive's layers checked against their digests and diff_ids, every
# executable hashed where it lies, and each binary found by its hash, or said to be missing. The archive is built here,
# small, by the test itself. Run: nu scripts/pipeline/tests/inspect.nu

use std/assert
use ../core/inspect.nu [inspect-archive placements]
use support/oci-archive.nu [archive text-digest]

# Two layers as Nix lays out an agent's image: the agent's store path, and the healthcheck's with a /bin link to it.
def agent_layers []: nothing -> list<record> {
    [
        {
            files: [
                {
                    path: "/nix/store/aaaa-cassini-server-1.0.0/bin/cassini-server"
                    text: "cassini"
                    executable: true
                }
                {
                    path: "/nix/store/aaaa-cassini-server-1.0.0/share/doc.txt"
                    text: "not a program"
                    executable: false
                }
            ]
            links: []
        }
        {
            files: [
                {
                    path: "/nix/store/bbbb-polar-healthcheck-1.0.0/bin/polar-healthcheck"
                    text: "healthcheck"
                    executable: true
                }
                {
                    path: "/nix/store/cccc-copy/bin/cassini-server"
                    text: "cassini"
                    executable: true
                }
            ]
            links: [
                {
                    path: "/bin/polar-healthcheck"
                    to: "/nix/store/bbbb-polar-healthcheck-1.0.0/bin/polar-healthcheck"
                }
            ]
        }
    ]
}

def main [] {
    let tests = [
        {
            name: "every executable is hashed in the layer it lies in, by its path in the image; a link and a plain file are not"
            body: {
                let root = mktemp --directory --tmpdir inspect-test.XXXXXX
                let made = archive $root (agent_layers)
                let scratch = $root | path join "scratch"
                let image = inspect-archive $made.archive $scratch
                assert equal $image.digest $made.digest "the image is its manifest's digest"
                assert equal ($image.layers | get diff_id) $made.diff_ids
                assert equal ($image.executables | sort-by path) ([
                    {diff_id: $made.diff_ids.0, path: "/nix/store/aaaa-cassini-server-1.0.0/bin/cassini-server", hash: (text-digest "cassini")}
                    {diff_id: $made.diff_ids.1, path: "/nix/store/bbbb-polar-healthcheck-1.0.0/bin/polar-healthcheck", hash: (text-digest "healthcheck")}
                    {diff_id: $made.diff_ids.1, path: "/nix/store/cccc-copy/bin/cassini-server", hash: (text-digest "cassini")}
                ] | sort-by path)
                assert (not ($scratch | path exists)) "the scratch is removed"
                rm --recursive --force $root
            }
        }
        {
            name: "executable entries are counted in every layer, a file replaced or deleted above included; a whiteout is none"
            body: {
                # Layer 1 replaces /bin/a and deletes /bin/b (its whiteout, given an execute bit here to show a marker is
                # never an entry). The image's filesystem holds one executable; its layers hold three entries.
                let root = mktemp --directory --tmpdir inspect-test.XXXXXX
                let made = archive $root [
                    {
                        files: [
                            {path: "/bin/a", text: "a, first", executable: true}
                            {path: "/bin/b", text: "b", executable: true}
                        ]
                        links: []
                    }
                    {
                        files: [
                            {
                                path: "/bin/a"
                                text: "a, replaced"
                                executable: true
                            }
                            {path: "/bin/.wh.b", text: "", executable: true}
                        ]
                        links: []
                    }
                ]
                let image = inspect-archive $made.archive ($root | path join "scratch")
                assert equal ($image.executables | sort-by diff_id path) ([
                    {diff_id: $made.diff_ids.0, path: "/bin/a", hash: (text-digest "a, first")}
                    {diff_id: $made.diff_ids.0, path: "/bin/b", hash: (text-digest "b")}
                    {diff_id: $made.diff_ids.1, path: "/bin/a", hash: (text-digest "a, replaced")}
                ] | sort-by diff_id path)
                rm --recursive --force $root
            }
        }
        {
            name: "a binary is found by its hash at each place it lies; one the image does not hold is missing, not refused"
            body: {
                let executables = [
                    {
                        diff_id: "sha256:l0"
                        path: "/nix/store/aaaa/bin/cassini-server"
                        hash: "sha256:c"
                    }
                    {
                        diff_id: "sha256:l1"
                        path: "/nix/store/cccc/bin/cassini-server"
                        hash: "sha256:c"
                    }
                    {
                        diff_id: "sha256:l1"
                        path: "/nix/store/bbbb/bin/polar-healthcheck"
                        hash: "sha256:h"
                    }
                ]
                let binaries = [
                    {name: "cassini-server", hash: "sha256:c"}
                    {name: "logger", hash: "sha256:x"}
                ]
                assert equal (placements $binaries $executables) {
                    found: [
                        {name: "cassini-server", hash: "sha256:c", diff_id: "sha256:l0", path: "/nix/store/aaaa/bin/cassini-server"}
                        {name: "cassini-server", hash: "sha256:c", diff_id: "sha256:l1", path: "/nix/store/cccc/bin/cassini-server"}
                    ]
                    missing: [{name: "logger", hash: "sha256:x"}]
                }
                assert equal (placements $binaries []) {found: [], missing: $binaries}
                assert equal (placements [] $executables) {found: [], missing: []}
            }
        }
        {
            name: "a layer whose content is not its diff_id stops the inspection, and leaves no scratch"
            body: {
                let root = mktemp --directory --tmpdir inspect-test.XXXXXX
                let made = archive $root (agent_layers) --spoil diff_id
                let scratch = $root | path join "scratch"
                let refused = try {
                    inspect-archive $made.archive $scratch
                    null
                } catch {|e|
                    $e.msg
                }
                assert ($refused != null) "a wrong diff_id was taken"
                assert ($refused =~ "diff_id") $refused
                assert (not ($scratch | path exists)) "the scratch is left"
                rm --recursive --force $root
            }
        }
        {
            name: "a layer whose blob is not its digest stops the inspection"
            body: {
                let root = mktemp --directory --tmpdir inspect-test.XXXXXX
                let made = archive $root (agent_layers) --spoil blob
                let refused = try {
                    inspect-archive $made.archive ($root | path join "scratch")
                    null
                } catch {|e|
                    $e.msg
                }
                assert ($refused != null) "a wrong blob was taken"
                assert ($refused =~ "digest") $refused
                rm --recursive --force $root
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
