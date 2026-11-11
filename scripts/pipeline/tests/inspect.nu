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

def digest-of [file: path]: nothing -> string {
    $"sha256:(open --raw $file | hash sha256)"
}

def text-digest [text: string]: nothing -> string {
    $"sha256:($text | hash sha256)"
}

# Writes `files` ({path, text, executable}) and `links` ({path, to}) under `dir`, as a layer's tree.
def tree [dir: path, files: list<record>, links: list<record>] {
    for f in $files {
        let at = $dir | path join ($f.path | str trim --left --char "/")
        mkdir ($at | path dirname)
        $f.text | save --raw $at
        if $f.executable { ^chmod +x $at }
    }
    for l in $links {
        let at = $dir | path join ($l.path | str trim --left --char "/")
        mkdir ($at | path dirname)
        ^ln -s $l.to $at
    }
}

# An OCI archive of `layers` (each {files, links}), gzip-compressed as the pipeline pushes them, in `root`; with
# `spoil` naming what to make wrong: "" (nothing), "diff_id" (layer 0's diff_id in the config) or "blob" (layer 0's
# blob, its content changed after its digest was taken). Returns {archive, digest, diff_ids}.
def archive [root: path, layers: list<record>, --spoil: string = ""]: nothing -> record {
    let layout = $root | path join "layout"
    let blobs = $layout | path join "blobs" "sha256"
    mkdir $blobs
    let made = $layers | enumerate | each {|l|
        let dir = $root | path join $"src-($l.index)"
        mkdir $dir
        tree $dir $l.item.files $l.item.links
        let tar = $root | path join $"layer-($l.index).tar"
        ^tar --sort=name --owner=0 --group=0 --numeric-owner -C $dir -cf $tar .
        let diff_id = digest-of $tar
        let gz = $root | path join $"layer-($l.index).tar.gz"
        ^gzip -n -c $tar | save --raw $gz
        let digest = digest-of $gz
        cp $gz ($blobs | path join ($digest | str replace "sha256:" ""))
        {digest: $digest, diff_id: $diff_id, size: (ls $gz | get 0.size | into int)}
    }
    if $spoil == "blob" {
        let blob = $blobs | path join ($made.0.digest | str replace "sha256:" "")
        ^chmod u+w $blob
        "not the layer" | save --force --raw $blob
    }
    let diff_ids = $made | get diff_id
    let config = {
        architecture: "amd64"
        os: "linux"
        rootfs: {type: "layers", diff_ids: (if $spoil == "diff_id" { $diff_ids | update 0 (text-digest "another layer") } else { $diff_ids })}
    } | to json --raw
    let config_digest = text-digest $config
    $config | save --raw ($blobs | path join ($config_digest | str replace "sha256:" ""))
    let manifest = {
        schemaVersion: 2
        mediaType: "application/vnd.oci.image.manifest.v1+json"
        config: {mediaType: "application/vnd.oci.image.config.v1+json", digest: $config_digest, size: ($config | str length)}
        layers: ($made | each {|m| {mediaType: "application/vnd.oci.image.layer.v1.tar+gzip", digest: $m.digest, size: $m.size} })
    } | to json --raw
    let digest = text-digest $manifest
    $manifest | save --raw ($blobs | path join ($digest | str replace "sha256:" ""))
    {schemaVersion: 2, manifests: [{mediaType: "application/vnd.oci.image.manifest.v1+json", digest: $digest, size: ($manifest | str length)}]}
    | to json --raw | save --raw ($layout | path join "index.json")
    '{"imageLayoutVersion":"1.0.0"}' | save --raw ($layout | path join "oci-layout")
    let file = $root | path join "image.oci.tar"
    ^tar -C $layout -cf $file .
    {archive: $file, digest: $digest, diff_ids: $diff_ids}
}

# Two layers as Nix lays out an agent's image: the agent's store path, and the healthcheck's with a /bin link to it.
def agent_layers []: nothing -> list<record> {
    [
        {
            files: [
                {path: "/nix/store/aaaa-cassini-server-1.0.0/bin/cassini-server", text: "cassini", executable: true}
                {path: "/nix/store/aaaa-cassini-server-1.0.0/share/doc.txt", text: "not a program", executable: false}
            ]
            links: []
        }
        {
            files: [
                {path: "/nix/store/bbbb-polar-healthcheck-1.0.0/bin/polar-healthcheck", text: "healthcheck", executable: true}
                {path: "/nix/store/cccc-copy/bin/cassini-server", text: "cassini", executable: true}
            ]
            links: [{path: "/bin/polar-healthcheck", to: "/nix/store/bbbb-polar-healthcheck-1.0.0/bin/polar-healthcheck"}]
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
            name: "a binary is found by its hash at each place it lies; one the image does not hold is missing, not refused"
            body: {
                let executables = [
                    {diff_id: "sha256:l0", path: "/nix/store/aaaa/bin/cassini-server", hash: "sha256:c"}
                    {diff_id: "sha256:l1", path: "/nix/store/cccc/bin/cassini-server", hash: "sha256:c"}
                    {diff_id: "sha256:l1", path: "/nix/store/bbbb/bin/polar-healthcheck", hash: "sha256:h"}
                ]
                let binaries = [{name: "cassini-server", hash: "sha256:c"} {name: "logger", hash: "sha256:x"}]
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
                let refused = try { inspect-archive $made.archive $scratch; null } catch {|e| $e.msg }
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
                let refused = try { inspect-archive $made.archive ($root | path join "scratch"); null } catch {|e| $e.msg }
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
    let failed = ($results | where error != null | length)
    if $failed > 0 { print -e $"($failed) of ($results | length) failed"; exit 1 }
    print $"all ($results | length) passed"
}
