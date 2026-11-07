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

# scripts/pipeline/tests/sbom.nu
#
# What a build's SBOM becomes as a graph fragment (core/sbom.nu, `extract-graph-fragment`): the packages, keyed by
# purl, and the dependency tree between them. Run: nu scripts/pipeline/tests/sbom.nu

use std/assert
use ../core/sbom.nu [extract-graph-fragment]

# A cargo-cyclonedx SBOM's shape: the tree is written between bom-refs, which are not purls.
def cargo_doc [] {
    {
        bomFormat: "CycloneDX"
        metadata: { component: { "bom-ref": "path+file:///work/probe#0.1.0", type: "application", name: "probe", version: "0.1.0", purl: "pkg:cargo/probe@0.1.0?download_url=file://." } }
        components: [
            { "bom-ref": "registry+https://github.com/rust-lang/crates.io-index#itoa@1.0.18", type: "library", name: "itoa", version: "1.0.18", purl: "pkg:cargo/itoa@1.0.18" }
            { "bom-ref": "registry+https://github.com/rust-lang/crates.io-index#ryu@1.0.20", type: "library", name: "ryu", version: "1.0.20", purl: "pkg:cargo/ryu@1.0.20" }
        ]
        dependencies: [
            { ref: "path+file:///work/probe#0.1.0", dependsOn: ["registry+https://github.com/rust-lang/crates.io-index#itoa@1.0.18"] }
            { ref: "registry+https://github.com/rust-lang/crates.io-index#itoa@1.0.18", dependsOn: ["registry+https://github.com/rust-lang/crates.io-index#ryu@1.0.20"] }
            { ref: "registry+https://github.com/rust-lang/crates.io-index#ryu@1.0.20", dependsOn: [] }
        ]
    }
}

def main [] {
    let tests = [
        {
            name: "the dependency tree is given between purls, the packages' key, not the SBOM's bom-refs"
            body: {
                let fragment = (extract-graph-fragment (cargo_doc) "sha256:sbom")
                assert equal $fragment.edges [
                    { from_ref: "pkg:cargo/probe@0.1.0?download_url=file://.", to_refs: ["pkg:cargo/itoa@1.0.18"] }
                    { from_ref: "pkg:cargo/itoa@1.0.18", to_refs: ["pkg:cargo/ryu@1.0.20"] }
                ]
                # The root's own entry is found by its purl, as build-processor looks for it.
                assert equal ($fragment.edges | where from_ref == $fragment.root.purl | length) 1
            }
        }
        {
            name: "a ref no component gives a purl for is left out, and an entry left with nothing is too"
            body: {
                let doc = (cargo_doc | update dependencies {|d| $d.dependencies | append [
                    { ref: "path+file:///work/probe#0.1.0", dependsOn: ["unknown#ref"] }
                    { ref: "unknown#ref", dependsOn: ["registry+https://github.com/rust-lang/crates.io-index#itoa@1.0.18"] }
                ] })
                let fragment = (extract-graph-fragment $doc "sha256:sbom")
                assert ($fragment.edges | all {|e| ($e.from_ref | str starts-with "pkg:") and ($e.to_refs | all {|t| $t | str starts-with "pkg:" }) })
                assert equal ($fragment.edges | length) 2
            }
        }
        {
            name: "a generator whose bom-refs are purls already gives the same tree"
            body: {
                let doc = {
                    bomFormat: "CycloneDX"
                    metadata: { component: { "bom-ref": "pkg:cargo/probe@0.1.0", name: "probe", purl: "pkg:cargo/probe@0.1.0" } }
                    components: [{ "bom-ref": "pkg:cargo/itoa@1.0.18", name: "itoa", purl: "pkg:cargo/itoa@1.0.18" }]
                    dependencies: [{ ref: "pkg:cargo/probe@0.1.0", dependsOn: ["pkg:cargo/itoa@1.0.18"] }]
                }
                assert equal (extract-graph-fragment $doc "sha256:sbom").edges [{ from_ref: "pkg:cargo/probe@0.1.0", to_refs: ["pkg:cargo/itoa@1.0.18"] }]
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
