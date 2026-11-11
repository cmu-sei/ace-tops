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

# scripts/pipeline/tests/binaries.nu
# What a binary's build says of it (core/binaries.nu): the package a cargo package id names, and the binaries a crane
# build's cargo log says it linked, the packages it compiled for its target, and those an SBOM names that it did not,
# split into those never compiled and those compiled only for the build machine.
# Run: nu scripts/pipeline/tests/binaries.nu

use std/assert
use ../core/binaries.nu [package-of-id linked-binaries compiled-for-target not-compiled sbom-gap]

# A cargo log as crane keeps it (`--message-format json-render-diagnostics`): one JSON message a line, the paths the
# build sandbox's, not the checkout's.
def cargo_log []: nothing -> list<string> {
    let artifact = {|id: string, kind: list<string>, name: string, executable: any|
        {
            reason: "compiler-artifact"
            package_id: $id
            manifest_path: "/build/source/cassini/broker/Cargo.toml"
            target: {
                kind: $kind
                crate_types: $kind
                name: $name
                src_path: "/build/source/src/main.rs"
            }
            profile: {opt_level: "3", debuginfo: 0, test: false}
            features: []
            filenames: [
                (
                    $executable
                    | default "/build/source/target/release/deps/libx.rlib"
                )
            ]
            executable: $executable
            fresh: false
        } | to json --raw
    }
    [
        (
            (do
                $artifact
                "registry+https://github.com/rust-lang/crates.io-index#itoa@1.0.18"
                ["lib"]
                "itoa"
                null
            )
        )
        (do $artifact "path+file:///build/source/cassini/broker#cassini-broker@1.0.0" ["custom-build"] "build-script-build"
            "/build/source/target/release/build/cassini-broker-0a1b/build-script-build")
        (
            {
                reason: "build-script-executed"
                package_id: "path+file:///build/source/cassini/broker#cassini-broker@1.0.0"
            }
            | to json --raw
        )
        (
            {
                reason: "compiler-message"
                package_id: "path+file:///build/source/cassini/broker#cassini-broker@1.0.0"
                message: {rendered: "warning: unused"}
            }
            | to json --raw
        )
        (
            (do
                $artifact
                "path+file:///build/source/cassini/broker#cassini-broker@1.0.0"
                ["lib"]
                "cassini_broker"
                null
            )
        )
        (do $artifact "path+file:///build/source/cassini/broker#cassini-broker@1.0.0" ["bin"] "cassini-server"
            "/build/source/target/x86_64-unknown-linux-musl/release/cassini-server")
        (do $artifact "path+file:///build/source/git/observe#git-repo-observer@1.0.0" ["bin"] "git-repo-observer"
            "/build/source/target/x86_64-unknown-linux-musl/release/git-repo-observer")
        (do $artifact "path+file:///build/source/git/observe#git-repo-observer@1.0.0" ["bin"] "git-discovery-harness"
            "/build/source/target/x86_64-unknown-linux-musl/release/git-discovery-harness")
        ""
        "not json"
        ({reason: "build-finished", success: true} | to json --raw)
    ]
}

# A cargo log of a build for a target (`CARGO_BUILD_TARGET`, as crane's is given the musl triple), as `dir` lays it out
# under `/build/source/target`: a unit for the target lies under `<dir>`, one for the build machine (a proc-macro, a build
# script, what they need) under `release`. With `dir` "release", no target was set and the two share it.
def cross_log [dir: string]: nothing -> list<string> {
    let target = $"/build/source/target/($dir)"
    let unit = {|id: string, kind: list<string>, file: string, executable: any|
        {
            reason: "compiler-artifact"
            package_id: $id
            target: {
                kind: $kind
                crate_types: $kind
                name: "x"
                src_path: "/build/source/src/lib.rs"
            }
            filenames: [$file]
            executable: $executable
            fresh: true
        } | to json --raw
    }
    let itoa = "registry+https://github.com/rust-lang/crates.io-index#itoa@1.0.18"
    let memchr = "registry+https://github.com/rust-lang/crates.io-index#memchr@2.7.4"
    let syn = "registry+https://github.com/rust-lang/crates.io-index#syn@2.0.87"
    let derive = "registry+https://github.com/rust-lang/crates.io-index#serde_derive@1.0.210"
    let broker = "path+file:///build/source/cassini/broker#cassini-broker@1.0.0"
    [
        (
            (do
                $unit
                $syn
                ["lib"]
                "/build/source/target/release/deps/libsyn-1.rlib"
                null
            )
        )
        (
            (do
                $unit
                $memchr
                ["lib"]
                "/build/source/target/release/deps/libmemchr-1.rlib"
                null
            )
        )
        (
            (do
                $unit
                $derive
                ["proc-macro"]
                "/build/source/target/release/deps/libserde_derive-1.so"
                null
            )
        )
        (
            (do
                $unit
                $broker
                ["custom-build"]
                "/build/source/target/release/build/cassini-broker-0a1b/build-script-build"
                null
            )
        )
        ({reason: "build-script-executed", package_id: $broker} | to json --raw)
        (do $unit $itoa ["lib"] $"($target)/deps/libitoa-1.rlib" null)
        (do $unit $memchr ["lib"] $"($target)/deps/libmemchr-2.rlib" null)
        ((do
            $unit
            $broker
            ["lib"]
            $"($target)/deps/libcassini_broker-1.rlib"
            null
        ))
        (
            (do
                $unit
                $broker
                ["bin"]
                $"($target)/cassini-server"
                $"($target)/cassini-server"
            )
        )
        "not json"
        ({reason: "build-finished", success: true} | to json --raw)
    ]
}

# An SBOM's component, as the pipeline reads one: its name, version and purl.
def component [name: string, version: string]: nothing -> record {
    {
        name: $name
        version: $version
        purl: $"pkg:cargo/($name)@($version)"
    }
}

def main [] {
    let tests = [
        {
            name: "a package is named by its id, in each form cargo writes one"
            body: {
                for case in [
                    [
                        "path+file:///build/source/cassini/broker#cassini-broker@1.0.0"
                        cassini-broker
                        1.0.0
                    ]
                    ["path+file:///build/source/logger#1.0.0" logger 1.0.0]
                    [
                        "registry+https://github.com/rust-lang/crates.io-index#itoa@1.0.18"
                        itoa
                        1.0.18
                    ]
                    [
                        "git+https://github.com/daveman1010221/neo4rs?rev=4117f5a#neo4rs@0.9.0-rc.10"
                        neo4rs
                        0.9.0-rc.10
                    ]
                    [
                        "cassini-broker 1.0.0 (path+file:///build/source/cassini/broker)"
                        cassini-broker
                        1.0.0
                    ]
                ] {
                    assert equal (package-of-id $case.0) { name: $case.1, version: $case.2 } $case.0
                }
            }
        }
        {
            name: "the binaries a build linked are its bin artifacts with an executable, each by its package, not by its path"
            body: {
                assert equal (linked-binaries (cargo_log)) [
                    {
                        name: cassini-server
                        package: cassini-broker
                        version: 1.0.0
                    }
                    {
                        name: git-repo-observer
                        package: git-repo-observer
                        version: 1.0.0
                    }
                    {
                        name: git-discovery-harness
                        package: git-repo-observer
                        version: 1.0.0
                    }
                ]
            }
        }
        {
            name: "a log with no binary in it links none"
            body: {
                assert equal (linked-binaries (cargo_log | where {|l| not ($l =~ '"bin"') })) []
                assert equal (linked-binaries []) []
            }
        }
        {
            name: "a binary's target units are those beside it: never the build machine's, a proc-macro or a build script"
            body: {
                assert equal (
                    compiled-for-target (cross_log "x86_64-unknown-linux-musl/release") cassini-server
                ) [
                    {name: cassini-broker, version: 1.0.0}
                    {name: itoa, version: 1.0.18}
                    {name: memchr, version: 2.7.4}
                ]
            }
        }
        {
            name: "with no target set, the build machine's libraries are counted too, but never a proc-macro or a build script"
            body: {
                assert equal (compiled-for-target (cross_log "release") cassini-server) [
                    {name: cassini-broker, version: 1.0.0}
                    {name: itoa, version: 1.0.18}
                    {name: memchr, version: 2.7.4}
                    {name: syn, version: 2.0.87}
                ]
            }
        }
        {
            name: "a binary its log did not link has no target units to read"
            body: {
                let refused = try {
                    compiled-for-target (cross_log "x86_64-unknown-linux-musl/release") git-repo-observer
                    false
                } catch {
                    true
                }
                assert $refused "a binary not in the log is refused"
            }
        }
        {
            name: "the SBOM's packages not compiled are named once each, in its order, by name and version"
            body: {
                let compiled = [
                    {name: cassini-broker, version: 1.0.0}
                    {name: itoa, version: 1.0.18}
                ]
                let sbom = [
                    (component itoa 1.0.18)
                    (component syn 2.0.87)
                    (component itoa 1.0.17)
                    (component serde_derive 1.0.210)
                    (component syn 2.0.87)
                ]
                assert equal (not-compiled $sbom $compiled) [
                    (component syn 2.0.87)
                    (component itoa 1.0.17)
                    (component serde_derive 1.0.210)
                ]
                assert equal (not-compiled ($sbom | first 1) $compiled) []
                assert equal (not-compiled [] $compiled) []
            }
        }
        {
            name: "what the SBOM names that is not in the binary is split: never compiled, or compiled only for the build machine"
            body: {
                # syn is a library only the build machine's units need, serde_derive a proc-macro: compiled, but not for
                # the target. ryu was compiled for no machine. itoa and memchr were compiled for the target.
                let sbom = [
                    (component itoa 1.0.18)
                    (component syn 2.0.87)
                    (component ryu 1.0.23)
                    (component serde_derive 1.0.210)
                    (component memchr 2.7.4)
                    (component syn 2.0.87)
                ]
                assert equal (
                    sbom-gap $sbom (cross_log "x86_64-unknown-linux-musl/release") cassini-server
                ) {
                    not_compiled: [(component ryu 1.0.23)]
                    build_machine_only: [(component syn 2.0.87) (component serde_derive 1.0.210)]
                }
                assert equal (
                    sbom-gap ($sbom | first 1) (cross_log "x86_64-unknown-linux-musl/release") cassini-server
                ) {
                    not_compiled: []
                    build_machine_only: []
                }
            }
        }
        {
            name: "with no target set, a library the build machine needs reads as the target's, and a proc-macro still does not"
            body: {
                let sbom = [
                    (component syn 2.0.87)
                    (component ryu 1.0.23)
                    (component serde_derive 1.0.210)
                ]
                assert equal (sbom-gap $sbom (cross_log "release") cassini-server) {
                    not_compiled: [(component ryu 1.0.23)]
                    build_machine_only: [(component serde_derive 1.0.210)]
                }
            }
        }
        {
            name: "a binary its log did not link has no gap to read"
            body: {
                let refused = try {
                    sbom-gap [
                        (component ryu 1.0.23)
                    ] (cross_log "x86_64-unknown-linux-musl/release") git-repo-observer
                    false
                } catch {
                    true
                }
                assert $refused "a binary not in the log is refused"
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
