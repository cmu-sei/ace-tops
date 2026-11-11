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
# build's cargo log says it linked. Run: nu scripts/pipeline/tests/binaries.nu

use std/assert
use ../core/binaries.nu [package-of-id linked-binaries]

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
