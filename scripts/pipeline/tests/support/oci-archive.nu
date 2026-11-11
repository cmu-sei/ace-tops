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

# scripts/pipeline/tests/support/oci-archive.nu
# A small OCI archive, built by a test to stand in for the one the pipeline makes from a Nix image (`skopeo copy …
# oci-archive:`): its layers gzip-compressed, as the pipeline pushes them. Shared by tests/inspect.nu and tests/ship.nu.

export def digest-of [file: path]: nothing -> string {
    $"sha256:(open --raw $file | hash sha256)"
}

export def text-digest [text: string]: nothing -> string {
    $"sha256:($text | hash sha256)"
}
# Writes `files` ({path, text, executable}) and `links` ({path, to}) under `dir`, as a layer's tree.
export def tree [dir: path, files: list<record>, links: list<record>] {
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
export def archive [root: path, layers: list<record>, --spoil: string = ""]: nothing -> record {
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
        rootfs: {
            type: "layers"
            diff_ids: (
                if $spoil == "diff_id" {
                    $diff_ids | update 0 (text-digest "another layer")
                } else {
                    $diff_ids
                }
            )
        }
    } | to json --raw
    let config_digest = text-digest $config
    $config | save --raw ($blobs | path join ($config_digest | str replace "sha256:" ""))
    let manifest = {
        schemaVersion: 2
        mediaType: "application/vnd.oci.image.manifest.v1+json"
        config: {
            mediaType: "application/vnd.oci.image.config.v1+json"
            digest: $config_digest
            size: ($config | str length)
        }
        layers: (
            $made
            | each {|m| {mediaType: "application/vnd.oci.image.layer.v1.tar+gzip", digest: $m.digest, size: $m.size} }
        )
    } | to json --raw
    let digest = text-digest $manifest
    $manifest | save --raw ($blobs | path join ($digest | str replace "sha256:" ""))
    {
        schemaVersion: 2
        manifests: [
            {
                mediaType: "application/vnd.oci.image.manifest.v1+json"
                digest: $digest
                size: ($manifest | str length)
            }
        ]
    }
    | to json --raw
    | save --raw ($layout | path join "index.json")
    '{"imageLayoutVersion":"1.0.0"}' | save --raw ($layout | path join "oci-layout")
    let file = $root | path join "image.oci.tar"
    ^tar -C $layout -cf $file .
    {archive: $file, digest: $digest, diff_ids: $diff_ids}
}
