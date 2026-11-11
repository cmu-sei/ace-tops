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

# scripts/pipeline/tests/ship.nu
# What the pipeline's process says (build-inspect-ship): it runs ci.nu itself, as a build does, and asserts its exit and
# what it reported. Phase 3 over one image: an image not shipped as inspected, or not signed with a key, fails it.
# Phase 2 over the image's derivations: what a Binary is said to be, from its derivation's `out` alone. Each run is in a
# copy of the pipeline in a scratch repository (its workspace, one package), with stand-ins on PATH for the tools that
# would build, push and sign: cargo (metadata and an SBOM), nix (the image, a docker archive made here; a derivation's
# outputs and what the store records of them, as a store file made here says), nix-store (which outputs were valid
# before), skopeo (the OCI archive, made here by tests/support/oci-archive.nu; a push; the digest the registry serves)
# and cosign (its exit). Nothing is built, pushed or signed, and no key is used. Run: nu scripts/pipeline/tests/ship.nu

use std/assert
use support/oci-archive.nu [archive]

const PIPELINE = path self ..
const REPOSITORY = path self ../../..

# The tools the run calls, as scripts in `bin`, each doing only what the run needs of it.
def stand-ins [bin: path] {
    mkdir $bin
    let scripts = {
        cargo: '#!/usr/bin/env bash
# cargo: `metadata` and `cyclonedx` over the scratch workspace whose manifest is given.
manifest=""; prev=""
for a in "$@"; do [ "$prev" = "--manifest-path" ] && manifest="$a"; prev="$a"; done
ws=$(dirname "$manifest")
case "$1" in
  metadata)
    id="path+file://$ws/cassini#cassini-broker@1.0.0"
    printf "{\"packages\":[{\"name\":\"cassini-broker\",\"id\":\"%s\",\"manifest_path\":\"%s/cassini/Cargo.toml\",\"version\":\"1.0.0\"}],\"workspace_members\":[\"%s\"]}\n" "$id" "$ws" "$id" ;;
  cyclonedx)
    printf "%s\n" "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"metadata\":{\"component\":{\"type\":\"application\",\"name\":\"cassini-broker\",\"version\":\"1.0.0\",\"purl\":\"pkg:cargo/cassini-broker@1.0.0\",\"bom-ref\":\"r\"}},\"components\":[{\"type\":\"library\",\"name\":\"itoa\",\"version\":\"1.0.18\",\"purl\":\"pkg:cargo/itoa@1.0.18\",\"bom-ref\":\"i\"}],\"dependencies\":[{\"ref\":\"r\",\"dependsOn\":[\"i\"]}]}" > "$ws/cassini/cassini-broker.cdx.json" ;;
  *) echo "stand-in cargo: $*" >&2; exit 2 ;;
esac
'
        nix: '#!/usr/bin/env nu
# nix: `build … -o <link>` gives the image, the docker archive the test made ($SHIP_IMAGE); `eval`, `build --json` and
# `path-info` answer from the store the test describes ($NIX_STORE_STANDIN: each ref`s outputs, each path`s record).
def lookup [table: record, key: string] {
    $table | transpose k v | where k == $key | get -o 0.v
}

def --wrapped main [...args: string] {
    if ($args | first) == "build" and ("-o" in $args) {
        let at = ($args | enumerate | where item == "-o" | first | get index) + 1
        ^ln -sfn $env.SHIP_IMAGE ($args | get $at)
        return
    }
    let store = open --raw $env.NIX_STORE_STANDIN | from json
    match ($args | first) {
        "eval" => { print (lookup $store.refs ($args | get 2) | values | to json --raw) }
        "build" => {
            let ref = $args | where {|a| $a | str ends-with "^*" } | first | str replace "^*" ""
            print ([{drvPath: "/nix/store/stand-in.drv", outputs: (lookup $store.refs $ref)}] | to json --raw)
        }
        "path-info" => {
            let paths = $args | skip 1 | where {|a| $a | str starts-with "/" }
            print ($paths | reduce --fold {} {|p, acc| $acc | merge {($p): (lookup $store.info $p)} } | to json --raw)
        }
        _ => {
            print --stderr $"stand-in nix: ($args | str join (char space))"
            exit 2
        }
    }
}
'
        nix-store: '#!/usr/bin/env nu
# nix-store: `--check-validity --print-invalid <paths>` prints those the described store holds as not valid.
def --wrapped main [...args: string] {
    let store = open --raw $env.NIX_STORE_STANDIN | from json
    for p in ($args | where {|a| $a in $store.invalid }) { print $p }
}
'
        skopeo: '#!/usr/bin/env bash
# skopeo: a copy to a registry (docker://) is a push, and succeeds; a copy to an oci-archive: is the archive the test
# made ($SHIP_OCI); `inspect` gives the digest the registry serves ($SHIP_SERVES), and fails when there is none.
case "$1" in
  copy)
    for a in "$@"; do case "$a" in docker://*) exit 0 ;; esac; done
    for a in "$@"; do case "$a" in oci-archive:*) f="${a#oci-archive:}"; cp "$SHIP_OCI" "${f%:*}"; exit 0 ;; esac; done
    echo "stand-in skopeo: $*" >&2; exit 2 ;;
  inspect)
    [ -n "$SHIP_SERVES" ] || { echo "manifest unknown" >&2; exit 1; }
    printf "{\"Digest\":\"%s\"}\n" "$SHIP_SERVES" ;;
  *) echo "stand-in skopeo: $*" >&2; exit 2 ;;
esac
'
        cosign: '#!/usr/bin/env bash
# cosign: signs nothing, and exits as $SHIP_COSIGN says.
exit "${SHIP_COSIGN:-0}"
'
    }
    for s in ($scripts | transpose name text) {
        let file = $bin | path join $s.name
        $s.text | save --raw $file
        ^chmod +x $file
    }
}

# The image as Nix builds it: a docker archive, with the manifest and config the pipeline reads metadata from.
def docker-archive [root: path]: nothing -> string {
    let dir = $root | path join "docker"
    mkdir $dir
    {
        architecture: "amd64"
        os: "linux"
        rootfs: {
            type: "layers"
            diff_ids: ["sha256:00"]
        }
    }
    | to json --raw
    | save --raw ($dir | path join "config.json")
    [
        {
            Config: "config.json"
            RepoTags: ["cassini:t1"]
            Layers: ["layer.tar"]
        }
    ]
    | to json --raw
    | save --raw ($dir | path join "manifest.json")
    let file = $root | path join "image.docker.tar"
    ^tar -C $dir -cf $file manifest.json config.json
    $file
}

# A repository the pipeline can run in: a copy of it, the source-check script it uses, a workspace of one package, and
# the VERSION it reports its facts with.
def scratch-repo [root: path]: nothing -> string {
    let repo = $root | path join "repo"
    mkdir ($repo | path join "scripts") ($repo | path join "infra") ($repo | path join "src" "agents" "cassini")
    cp --recursive $PIPELINE ($repo | path join "scripts" "pipeline")
    cp ($REPOSITORY | path join "infra" "check-sources.nu") ($repo | path join "infra")
    "[workspace]\nmembers = [\"cassini\"]\n" | save --raw ($repo | path join "src" "agents" "Cargo.toml")
    "[package]\nname = \"cassini-broker\"\nversion = \"1.0.0\"\n"
    | save --raw ($repo | path join "src" "agents" "cassini" "Cargo.toml")
    "# a lock, for the binding digest\n" | save --raw ($repo | path join "src" "agents" "Cargo.lock")
    "1.0.0\n" | save --raw ($repo | path join "VERSION")
    $repo
}

# One run of ci.nu's phase 2 over the cassini image's two derivations, built by the stand-in nix from a store described
# here: cassini's derivation, with `out` (bin/cassini-server) and `cargolog` (the log saying it linked it), as `store`
# says (`out_valid` and `log_valid`, whether each was valid before the build; `out_at` and `log_at`, when the store
# registered each, as built here); the healthcheck's, valid long since, linking nothing. Gives the process's result, and
# the `polar.nix/*` facts it reported of the cassini-server Binary, `{name, value}`.
def link [store: record]: nothing -> record {
    let root = mktemp --directory --tmpdir link-test.XXXXXX
    let repo = scratch-repo $root
    let bin = $root | path join "bin"
    stand-ins $bin
    let paths = $root | path join "store"
    let out = $paths | path join "aaaa-cassini-server-1.0.0"
    let log = $paths | path join "aaaa-cassini-server-1.0.0-cargolog"
    let hc_out = $paths | path join "bbbb-polar-healthcheck-1.0.0"
    let hc_log = $paths | path join "bbbb-polar-healthcheck-1.0.0-cargolog"
    mkdir ($out | path join "bin") $log ($hc_out | path join "bin") $hc_log
    "cassini" | save --raw ($out | path join "bin" "cassini-server")
    ^chmod +x ($out | path join "bin" "cassini-server")
    let target = "/build/source/target/x86_64-unknown-linux-musl/release"
    [
        {
            reason: "compiler-artifact"
            package_id: "registry+https://github.com/rust-lang/crates.io-index#itoa@1.0.18"
            target: {
                kind: ["lib"]
            }
            filenames: [$"($target)/deps/libitoa.rlib"]
            executable: null
        }
        {
            reason: "compiler-artifact"
            package_id: "path+file:///build/source/cassini#cassini-broker@1.0.0"
            target: {
                kind: ["bin"]
            }
            filenames: [$"($target)/cassini-server"]
            executable: $"($target)/cassini-server"
        }
    ]
    | each { to json --raw }
    | str join "\n"
    | save --raw ($log | path join "cargo-build.json")
    "" | save --raw ($hc_log | path join "cargo-build.json")
    let built = {|at: int| {
        ultimate: true
        registrationTime: $at
        signatures: []
    } }
    let described = {
        refs: {
            ".#polarPkgs.cassini.cassini": {out: $out, cargolog: $log}
            ".#polarPkgs.healthcheck": {out: $hc_out, cargolog: $hc_log}
        }
        invalid: (
            [
                [$out $store.out_valid]
                [$log $store.log_valid]
            ]
            | where {|p| not $p.1 }
            | each {|p| $p.0 }
        )
        info: {
            ($out): (do $built $store.out_at)
            ($log): (do $built $store.log_at)
            ($hc_out): (do $built 1000)
            ($hc_log): (do $built 1000)
        }
    }
    let described_file = $root | path join "store.json"
    $described | to json --raw | save --raw $described_file
    let env_run = {
        PATH: ($env.PATH | prepend $bin)
        NIX_STORE_STANDIN: $described_file
        CI_REGISTRY: ""
        CI_COMMIT_SHA: "0123456789abcdef0123456789abcdef01234567"
    }
    let ci = $repo | path join "scripts" "pipeline" "ci.nu"
    let result = with-env $env_run {
        cd $root
        (^$nu.current-exe $ci link-test --skip-analysis --skip-audit --skip-images --filter cassini --tag t1
            --artifact-dir ($root | path join "out") | complete)
    }
    ^chmod -R u+w $root
    rm --recursive --force $root
    let binary = "sha256:" + ("cassini" | hash sha256)
    let facts = $result.stdout
    | lines
    | where {|l| $l | str starts-with "polar-report " }
    | each {|l| $l | str substring 13.. | from json }
    | where {|e| ($e.type? | default "") == "fact_reported" and $e.subject.key == $binary }
    | where {|e| $e.name | str starts-with "polar.nix/" }
    | each {|e| {name: $e.name, value: $e.value} }
    {result: $result, facts: $facts, out: $out}
}

# One run of ci.nu over the cassini image, as `run` says: `spoil` (the archive, as tests/support/oci-archive.nu takes
# it), `registry` ("honest", the inspected digest; "lying", another; "failing", none), `key` (COSIGN_KEY, "" for none)
# and `cosign` (its exit). Gives the process's `{exit_code, stdout, stderr}`.
def ship [run: record]: nothing -> record {
    let root = mktemp --directory --tmpdir ship-test.XXXXXX
    let repo = scratch-repo $root
    let bin = $root | path join "bin"
    stand-ins $bin
    let made = archive ($root | path join "oci") [
        {
            files: [
                {
                    path: "/nix/store/aaaa-cassini-server-1.0.0/bin/cassini-server"
                    text: "cassini"
                    executable: true
                }
            ]
            links: []
        }
    ] --spoil $run.spoil
    let another = "sha256:" + ("another image" | hash sha256)
    let serves = match $run.registry {
        honest => $made.digest
        lying => $another
        _ => ""
    }
    let env_run = {
        PATH: ($env.PATH | prepend $bin)
        SHIP_IMAGE: (docker-archive $root)
        SHIP_OCI: $made.archive
        SHIP_SERVES: $serves
        SHIP_COSIGN: ($run.cosign | into string)
        COSIGN_KEY: $run.key
        CI_REGISTRY: "127.0.0.1:5055"
        CI_REGISTRY_USER: ""
        POLAR_REGISTRY_INSECURE: ""
        CI_COMMIT_SHA: "0123456789abcdef0123456789abcdef01234567"
    }
    let ci = $repo | path join "scripts" "pipeline" "ci.nu"
    let out = $root | path join "out"
    let result = with-env $env_run {
        cd $root
        (^$nu.current-exe $ci ship-test --skip-analysis --skip-audit --skip-build --filter cassini --tag t1
            --artifact-dir $out | complete)
    }
    ^chmod -R u+w $root
    rm --recursive --force $root
    $result
}

def said [result: record]: nothing -> string {
    $result.stdout + $result.stderr
}

# What a failed assertion shows of a run: its exit, and its warnings, errors and last word.
def brief [result: record]: nothing -> string {
    let notable = (said $result) | lines | where {|l| $l =~ '\[(ERR|WRN)\]|pipeline complete|^Error' }
    $"exit ($result.exit_code): ($notable | last 6 | str join ' | ')"
}

def created [result: record]: nothing -> bool {
    $result.stdout | str contains '"type":"container_image_created"'
}

def main [] {
    let tests = [
        {
            name: "an image shipped as inspected, with no key, ends the pipeline well: signing is skipped"
            body: {
                let r = ship {
                    spoil: ""
                    registry: "honest"
                    key: ""
                    cosign: 0
                }
                assert equal $r.exit_code 0 (brief $r)
                assert (created $r) "the image is said to be created"
                # The count is of entries in its layers, not of the image's executables (Test's M1), and is named so.
                assert (
                    $r.stdout
                    | str contains '"name":"polar.image/executable-entries"'
                ) "the count is not named entries"
                assert (
                    not ($r.stdout | str contains '"name":"polar.image/executables"')
                ) "the count is named executables"
                assert ((said $r) | str contains "skipping signature") "signing is said to be skipped"
            }
        }
        {
            name: "an archive whose layer is not its digest fails the pipeline"
            body: {
                let r = ship {
                    spoil: "blob"
                    registry: "honest"
                    key: ""
                    cosign: 0
                }
                assert not equal $r.exit_code 0 (brief $r)
                assert (not (created $r)) "no image is said to be created"
                assert (not ((said $r) | str contains "pipeline complete")) "the pipeline is said to be complete"
            }
        }
        {
            name: "a registry serving another digest than the inspected one fails the pipeline"
            body: {
                let r = ship {
                    spoil: ""
                    registry: "lying"
                    key: ""
                    cosign: 0
                }
                assert not equal $r.exit_code 0 (brief $r)
                assert (not (created $r)) "an image the registry does not serve as inspected is said to be created"
            }
        }
        {
            name: "a registry that gives no digest fails the pipeline"
            body: {
                let r = ship {
                    spoil: ""
                    registry: "failing"
                    key: ""
                    cosign: 0
                }
                assert not equal $r.exit_code 0 (brief $r)
                assert (not (created $r)) "an image with no digest is said to be created"
            }
        }
        {
            name: "with a key, an image cosign does not sign fails the pipeline"
            body: {
                let r = ship {
                    spoil: ""
                    registry: "honest"
                    key: "stand-in.key"
                    cosign: 1
                }
                assert not equal $r.exit_code 0 (brief $r)
            }
        }
        {
            name: "with a key, an image cosign signs ends the pipeline well"
            body: {
                let r = ship {
                    spoil: ""
                    registry: "honest"
                    key: "stand-in.key"
                    cosign: 0
                }
                assert equal $r.exit_code 0 (brief $r)
                assert (created $r) "the image is said to be created"
            }
        }
        {
            name: "a binary whose out was present is present, with no built-at, though its cargo log was built now"
            body: {
                let r = link {
                    out_valid: true
                    out_at: 1000
                    log_valid: false
                    log_at: 1762890005
                }
                assert equal $r.result.exit_code 0 (brief $r.result)
                assert equal ($r.facts | sort-by name) [
                    {name: "polar.nix/realised", value: "present"}
                    {name: "polar.nix/store-path", value: $r.out}
                ]
            }
        }
        {
            name: "a binary built now is built at the time its out was registered, not its cargo log's"
            body: {
                let r = link {
                    out_valid: false
                    out_at: 1762890000
                    log_valid: false
                    log_at: 1762890005
                }
                assert equal $r.result.exit_code 0 (brief $r.result)
                assert equal ($r.facts | sort-by name) [
                    {
                        name: "polar.nix/built-at"
                        value: "2025-11-11T19:40:00+00:00"
                    }
                    {name: "polar.nix/realised", value: "built"}
                    {name: "polar.nix/store-path", value: $r.out}
                ]
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
