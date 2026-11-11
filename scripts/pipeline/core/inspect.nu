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

# scripts/pipeline/core/inspect.nu
#
# What an image holds, read from the OCI archive that is pushed (build-inspect-ship, S3): its manifest's digest, each
# layer checked against its digest and its diff_id, and every executable in each layer, by content. Then where each
# binary the build linked lies in it, by its hash. Observes: a binary found nowhere is said, never refused.

# The sha256 of a file, as `sha256:` and hex, read by sha256sum as it streams: a layer may be larger than memory.
def file-digest [file: path]: nothing -> string {
    $"sha256:(^sha256sum $file | split row ' ' | first)"
}

# The sha256 of a layer's content, decompressed when its media type says it is gzip-compressed: its diff_id.
def content-digest [blob: path, media_type: string]: nothing -> string {
    if ($media_type | str ends-with "gzip") {
        $"sha256:(^sh -c 'gzip -dc "$1" | sha256sum' _ $blob | split row ' ' | first)"
    } else if ($media_type | str ends-with ".tar") or ($media_type | str ends-with "tar") {
        file-digest $blob
    } else {
        error make {
            msg: $"a layer of media type ($media_type) is not one the inspection reads"
        }
    }
}

# The image in an OCI archive (`skopeo copy … oci-archive:`), as `{digest, config_digest, layers, executables}`: its
# manifest's digest, which a registry that is given the archive as it is gives it too; each layer, `{order, digest,
# diff_id}`, its blob checked against its digest and its content against the config's diff_id; and every executable in
# every layer, `{diff_id, path, hash}`, a regular file with an execute bit, by its path in the image. A symlink is not
# one: its target is, where it lies. Unpacked into `scratch`, one layer at a time, and removed whatever happens. A layer
# that is not what its digest or its diff_id says stops the inspection: the archive is not the image it names.
export def inspect-archive [archive: path, scratch: path]: nothing -> record {
    mkdir $scratch
    let result = try {
        let layout = $scratch | path join "layout"
        mkdir $layout
        ^tar -xf $archive -C $layout
        let blob = {|digest: string|
            $layout | path join "blobs" ($digest | split row ":" | first) ($digest | split row ":" | last)
        }
        let index = open --raw ($layout | path join "index.json") | from json
        let described = $index.manifests | first
        if (file-digest (do $blob $described.digest)) != $described.digest {
            error make {msg: "the manifest's blob is not its digest"}
        }
        let manifest = open --raw (do $blob $described.digest) | from json
        if (file-digest (do $blob $manifest.config.digest)) != $manifest.config.digest {
            error make {msg: "the config's blob is not its digest"}
        }
        let diff_ids = open --raw (do $blob $manifest.config.digest) | from json | get rootfs.diff_ids
        if ($diff_ids | length) != ($manifest.layers | length) {
            error make {
                msg: $"the manifest has ($manifest.layers | length) layers and the config ($diff_ids | length) diff_ids"
            }
        }
        # A loop, not a closure: an error made in a closure reaches the caller wrapped, without its message.
        mut layers = []
        for l in ($manifest.layers | enumerate) {
            let file = do $blob $l.item.digest
            if (file-digest $file) != $l.item.digest {
                error make {
                    msg: $"layer ($l.index): its blob is not its digest, ($l.item.digest)"
                }
            }
            let diff_id = $diff_ids | get $l.index
            if (content-digest $file $l.item.mediaType) != $diff_id {
                error make {
                    msg: $"layer ($l.index): its content is not its diff_id, ($diff_id)"
                }
            }
            $layers = (
                $layers
                | append {order: $l.index, digest: $l.item.digest, diff_id: $diff_id}
            )
        }
        let layers = $layers
        let executables = $layers | each {|l|
            let dir = $scratch | path join $"layer-($l.order)"
            mkdir $dir
            ^tar -xf (do $blob $l.digest) -C $dir --no-same-owner --no-same-permissions
            let found = ^find $dir -type f -perm /111 -exec sha256sum "{}" +
                | lines
                | parse "{hash}  {path}"
                | each {|e| {diff_id: $l.diff_id, path: ($e.path | str replace $dir ""), hash: $"sha256:($e.hash)"} }
            ^chmod -R u+w $dir
            rm --recursive --force $dir
            $found
        } | flatten
        {
            digest: $described.digest
            config_digest: $manifest.config.digest
            layers: $layers
            executables: $executables
        }
    } catch {|e|
        ^chmod -R u+w $scratch
        rm --recursive --force $scratch
        error make {msg: $e.msg}
    }
    ^chmod -R u+w $scratch
    rm --recursive --force $scratch
    $result
}

# Where each binary (`{name, hash}`, as phase 2 hashed it) lies among an image's executables, by hash: `found`, one
# `{name, hash, diff_id, path}` for each place it lies, and `missing`, those it holds nowhere. Observes: a binary missing
# is said, and stops nothing.
export def placements [binaries: list<record>, executables: list<record>]: nothing -> record {
    let hashes = $executables | each {|e| $e.hash }
    {
        found: ($binaries | each {|b|
            $executables | where hash == $b.hash | each {|e| {name: $b.name, hash: $b.hash, diff_id: $e.diff_id, path: $e.path} }
        } | flatten)
        missing: (
            $binaries
            | where {|b| $b.hash not-in $hashes }
            | each {|b| {name: $b.name, hash: $b.hash} }
        )
    }
}
