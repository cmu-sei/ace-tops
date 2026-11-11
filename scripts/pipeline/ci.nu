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

#!/usr/bin/env nu
# ci.nu — unified Polar build pipeline
#
# Runs the full build sequence under a single Cassini daemon:
#
#   Phase 0 — Static analysis (no Cassini, no artifacts)
#     Parallel: cargo deny, clippy, udeps, semver-checks, geiger, hack,
#     check-sources (every locked git source fetchable anonymously)
#     Sequential: noseyparker (manages its own datastore), cargo mutants
#     (spawns its own workers). Failures are reported; --strict-analysis
#     aborts the pipeline on any non-zero exit.
#
#   Phase 1 — Cargo SBOMs
#     cargo-cyclonedx generates a CycloneDX SBOM per workspace member,
#     each is parsed into a graph fragment and emitted as sbom_analyzed.
#
#   Phase 1.5 — Vulnerability scanning
#     cargo-deny (via `check advisories --audit-compatible-output`) runs
#     against the workspace. Findings resolve
#     against the purls Phase 1 just recorded in sbom_packages — never
#     reconstructed by hand — and emit as SecurityAdvisory or PackageStatus
#     events depending on kind (see scanning.nu).
#
#   Phase 2 — Binaries, built by Nix
#     Each binary an image in scope ships is built by Nix from its crane
#     derivation (image-manifest, `binaries`), the store path its image is made
#     from: there is no cargo build here, and a pipeline without Nix reports no
#     binary. Its cargo log (the derivation's `cargolog` output) says what it
#     linked; it is hashed as installed, reported with how Nix realised it
#     (built, fetched or present), and linked to its Phase 1 SBOM via a
#     cryptographic binding digest, and to its own SBOM when it was built with
#     cargo-auditable (auditable2cdx).
#
#   Phase 3 — OCI images
#     nix build → skopeo upload → cosign sign, one pass per image in the
#     manifest. Source-level SBOM hashes from Phase 1 are threaded into
#     binary_linked events, closing the full provenance chain:
#       (Binary)-[:BUILT_FROM]->(Package)<-[:DESCRIBES]-(SourceSbom)
#
# All phases share one artifact directory. Phases 1-3 share one Cassini daemon.
# Adding a new image = one row in image-manifest, naming its binaries' derivations. Nothing else changes.

use ./core/state.nu [
    init-pipeline-state get-build-id
    record-sbom record-sbom-package get-sbom-info check-manifest-purl
    lookup-package-purl get-all-sbom-packages
    record-tarball-hash get-tarball-hash assert-sbom-state-populated
]
# The colour helpers (core/mod.nu): phase 0's logging names them, and `use ./core/<file>.nu` brings in none of them.
use ./core *
use ./core/oci.nu *
use ./core/logging.nu *
use ./core/events.nu *
use ./core/cargo.nu [workspace-root source-commit]
use ./core/hashing.nu *
use ./core/sbom.nu *
use ./core/scanning.nu [run-vulnerability-scan]
use ./core/binaries.nu [linked-binaries]
use ./core/nix.nu [realisation]
use ../../infra/check-sources.nu [summary_lines]
const COMPONENT = "ci"
const CHECK_SOURCES = (path self | path dirname | path join ../../infra/check-sources.nu | path expand)
const ELF_BINARY_ARTIFACT = "elf-binary"


# ===========================================================================
# Phase 0: Static analysis
# ===========================================================================

def check-tools [tools: list<string>] {
    let missing = $tools | where {|t| (which $t | is-empty) }
    if ($missing | is-not-empty) {
        log-error $"missing required tools: ($missing | str join ', ')" --component $COMPONENT
        error make {msg: "preflight tool check failed"}
    }
}

def run-tool [name: string, outfile: string, cmd: list<string>]: nothing -> record {
    let start = (date now)
    log-info (yellow $"  → ($name)...") --component $COMPONENT

    let bin = $cmd.0
    let args = $cmd | skip 1

    let exit_code = (do --ignore-errors {
        ^$bin ...$args out+err> $outfile
        0
    } | if ($in | is-empty) { 1 } else { $in | into int })

    let duration = ((date now) - $start) / 1sec | math round

    {
        name: $name
        outfile: $outfile
        exit_code: $exit_code
        duration_sec: $duration
    }
}

def static-tool-definitions [manifest: string, output_dir: string]: nothing -> list<record> {
    [
        {
            name: "cargo deny"
            outfile: $"($output_dir)/cargo_deny.txt"
            cmd: [cargo deny --manifest-path $manifest check]
        }
        {
            name: "cargo clippy"
            outfile: $"($output_dir)/cargo_clippy.txt"
            cmd: [
                cargo
                clippy
                --manifest-path
                $manifest
                --all-targets
                --all-features
                --
                -D
                warnings
            ]
        }
        {
            name: "cargo udeps"
            outfile: $"($output_dir)/cargo_udeps.txt"
            cmd: [cargo udeps --manifest-path $manifest --all-targets]
        }
        {
            name: "cargo semver-checks"
            outfile: $"($output_dir)/cargo_semver.txt"
            cmd: [cargo semver-checks --manifest-path $manifest]
        }
        {
            name: "cargo geiger"
            outfile: $"($output_dir)/cargo_geiger.txt"
            cmd: [cargo geiger --manifest-path $manifest]
        }
        {
            name: "cargo hack (feature powerset)"
            outfile: $"($output_dir)/cargo_hack.txt"
            cmd: [
                cargo
                hack
                check
                --manifest-path
                $manifest
                --feature-powerset
            ]
        }
        {
            name: "check-sources"
            outfile: $"($output_dir)/check_sources.txt"
            cmd: [nu $CHECK_SOURCES]
        }
    ]
}

def count-pattern [file: string, pattern: string]: nothing -> int {
    if not ($file | path exists) { return 0 }
    open $file | lines | where {|l| $l =~ $pattern } | length
}

def generate-static-summary [results: table, output_dir: string] {
    let summary_file = $"($output_dir)/static-analysis-summary.txt"
    mut sections = [
        (bold "Polar Static Analysis Summary")
        ""
    ]
    $sections = (
        $sections
        | append [
            (bold "=== Tool Results ===")
            ($results | select name exit_code duration_sec | to text)
            ""
        ]
    )
    let clippy_warnings = (count-pattern $"($output_dir)/cargo_clippy.txt" 'warning\[')
    let clippy_errors = (count-pattern $"($output_dir)/cargo_clippy.txt" 'error\[')
    $sections = (
        $sections
        | append [
            (bold "=== cargo clippy ===")
            $"Warnings: ($clippy_warnings)  Errors: ($clippy_errors)"
            ""
        ]
    )
    let deny_errors = (count-pattern $"($output_dir)/cargo_deny.txt" '^error')
    $sections = (
        $sections
        | append [
            (bold "=== cargo deny ===")
            $"Issues: ($deny_errors)"
            ""
        ]
    )
    let udeps_file = $"($output_dir)/cargo_udeps.txt"
    let udeps_lines = if ($udeps_file | path exists) {
        open $udeps_file | lines | where {|l| $l =~ 'unused|crate' } | first 10
    } else { [] }
    let udeps_body = if ($udeps_lines | is-not-empty) {
        $udeps_lines | str join "\n"
    } else { "No unused dependencies found." }
    $sections = ($sections | append [
        (bold "=== cargo udeps ===")
        $udeps_body
        ""
    ])
    let semver_file = $"($output_dir)/cargo_semver.txt"
    let semver_body = if ($semver_file | path exists) {
        open $semver_file | lines | where {|l| $l =~ 'Parsed|Checked|Summary|semver' } | str join "\n"
    } else { "" }
    $sections = ($sections | append [
        (bold "=== cargo semver-checks ===")
        $semver_body
        ""
    ])
    let geiger_file = $"($output_dir)/cargo_geiger.txt"
    let geiger_body = if ($geiger_file | path exists) {
        open $geiger_file | lines | last 15 | str join "\n"
    } else { "" }
    $sections = ($sections | append [
        (bold "=== cargo geiger ===")
        $geiger_body
        ""
    ])
    let sources_file = $"($output_dir)/check_sources.txt"
    let sources_body = if ($sources_file | path exists) {
        summary_lines (open $sources_file | lines) | str join "\n"
    } else { "" }
    $sections = ($sections | append [
        (bold "=== check-sources ===")
        $sources_body
        ""
    ])
    let np_report = $"($output_dir)/noseyparker_report.txt"
    let np_body = if ($np_report | path exists) {
        open $np_report | lines | first 30 | str join "\n"
    } else { "" }
    $sections = ($sections | append [
        (bold "=== noseyparker ===")
        $np_body
        ""
    ])
    let mutants_file = $"($output_dir)/cargo_mutants.txt"
    let mutants_body = if ($mutants_file | path exists) {
        open $mutants_file | lines | where {|l| $l =~ 'caught|missed|unviable|timeout|ok' } | last 10 | str join "\n"
    } else { "" }
    $sections = ($sections | append [
        (bold "=== cargo mutants ===")
        $mutants_body
        ""
    ])
    let failed = $results | where exit_code != 0
    if ($failed | is-not-empty) {
        let callout = (
            $failed
            | each {|r| $"  ($r.name) — exit ($r.exit_code) — ($r.outfile)" }
            | str join "\n"
        )
        $sections = (
            $sections
            | append [
                (bold "=== Tools with non-zero exit ===")
                $callout
                ""
            ]
        )
    }
    $sections | flatten | str join "\n" | save --force $summary_file
    log-info (green $"summary written to ($summary_file)") --component $COMPONENT
}

def run-static-analysis [ws_manifest: path, artifact_dir: path]: nothing -> table {
    check-tools [
        cargo
        cargo-deny
        cargo-udeps
        cargo-semver-checks
        cargo-geiger
        cargo-hack
        cargo-mutants
        git
        curl
        timeout
    ]
    log-info (bold "phase 0 — static analysis") --component $COMPONENT
    let parallel_results = (
        static-tool-definitions ($ws_manifest | path expand | into string) ($artifact_dir | into string)
        | par-each {|tool| run-tool $tool.name $tool.outfile $tool.cmd }
    )
    log-info "  → cargo mutants (slow)..." --component $COMPONENT
    let mutants_out = $"($artifact_dir)/cargo_mutants.txt"
    let mutants_out_dir = $"($artifact_dir)/mutants.out"
    let mutants = (run-tool "cargo mutants" $mutants_out [
        cargo mutants --manifest-path ($ws_manifest | into string) --output $mutants_out_dir
    ])
    let all_results = $parallel_results | append $mutants
    log-info ($all_results | select name exit_code duration_sec | table) --component $COMPONENT
    generate-static-summary $all_results ($artifact_dir | into string)
    $all_results
}

# ===========================================================================
# Image manifest — single source of truth for OCI images in this project.
# ===========================================================================

def image-manifest []: nothing -> list<record> {
    [
        {
            name: "polar-nu-init"
            binaries: [".#polarPkgs.certIssuer.client"]
            flake: ".#nuInitImage"
            image: "polar-nu-init"
            root_purl: ""
        }
        {
            name: "cert-issuer"
            binaries: [".#polarPkgs.certIssuer.server" ".#polarPkgs.healthcheck"]
            flake: ".#certIssuerImage"
            image: "cert-issuer"
            root_purl: "pkg:cargo/cert-issuer@0.1.0"
        }
        {
            name: "cassini"
            binaries: [".#polarPkgs.cassini.cassini" ".#polarPkgs.healthcheck"]
            flake: ".#cassiniImage"
            image: "cassini"
            root_purl: "pkg:cargo/cassini@0.1.0"
        }
        {
            name: "kube-observer"
            binaries: [".#polarPkgs.kubeAgent.observer" ".#polarPkgs.healthcheck"]
            flake: ".#kubeObserverImage"
            image: "kube-observer"
            root_purl: "pkg:cargo/kube-observer@0.1.0"
        }
        {
            name: "kube-consumer"
            binaries: [".#polarPkgs.kubeAgent.consumer" ".#polarPkgs.healthcheck"]
            flake: ".#kubeConsumerImage"
            image: "kube-consumer"
            root_purl: "pkg:cargo/kube-consumer@0.1.0"
        }
        {
            name: "git-observer"
            binaries: [".#polarPkgs.gitAgent.observer" ".#polarPkgs.healthcheck"]
            flake: ".#gitObserverImage"
            image: "git-observer"
            root_purl: "pkg:cargo/git-repo-observer@0.1.0"
        }
        {
            name: "git-processor"
            binaries: [".#polarPkgs.gitAgent.consumer" ".#polarPkgs.healthcheck"]
            flake: ".#gitProcessorImage"
            image: "git-processor"
            root_purl: ""
        }
        {
            name: "build-processor"
            binaries: [".#polarPkgs.buildProcessor.buildProcessor" ".#polarPkgs.healthcheck"]
            flake: ".#buildProcessorImage"
            image: "build-processor"
            root_purl: "pkg:cargo/build-processor@0.1.0"
        }
        {
            name: "oci-resolver"
            binaries: [".#polarPkgs.ociResolver.resolverBin" ".#polarPkgs.healthcheck"]
            flake: ".#ociResolverImage"
            image: "oci-resolver"
            root_purl: "pkg:cargo/oci-resolver@0.1.0"
        }
    ]
}

# ===========================================================================
# Cargo: package resolution
# ===========================================================================

def resolve-packages [--package(-p): string = ""]: nothing -> list<record> {
    let ws_root = (workspace-root)
    let manifest = $ws_root | path join "Cargo.toml"
    let meta = (
        cargo metadata --manifest-path $manifest --format-version 1 --no-deps
        | from json
    )

    let packages = if ($package | is-empty) {
        let members = $meta.workspace_members | default []
        $meta.packages | where {|pkg| $members | any {|id| $id == $pkg.id } }
    } else {
        $meta.packages | where name == $package
    }

    if ($packages | is-empty) {
        error make {msg: $"no Cargo package matched '($package)'"}
    }

    $packages | each {|pkg| {
        name:          $pkg.name
        manifest_path: ($pkg.manifest_path | path expand)
        version:       ($pkg.version? | default "0.0.0")
        purl:          $"pkg:cargo/($pkg.name)@($pkg.version? | default '0.0.0')"
    }}
}

# ===========================================================================
# Phase 1: SBOM generation and graph projection
# ===========================================================================

def generate-workspace-sboms [
    packages: list<record>
    ws_manifest: path
    artifact_dir: path
    --target(-t): string = ""
]: nothing -> list<record> {
    let ws_root = $ws_manifest | path dirname
    log-info $"generating SBOMs for ($packages | length) package\(s\)" --component $COMPONENT
    mut args = [--manifest-path $ws_manifest -f json]
    if ($target | is-not-empty) { $args = ($args | append [--target $target]) }
    log-info $"running: cargo cyclonedx ($args | str join ' ')" --component $COMPONENT
    let result = (^cargo cyclonedx ...$args | complete)
    if $result.exit_code != 0 {
        let msg = $result.stderr | default $result.stdout | str trim
        log-warn $"cargo-cyclonedx failed: ($msg)" --component $COMPONENT
        return []
    }
    # cargo-cyclonedx writes each SBOM beside its package's Cargo.toml: a .cdx.json anywhere else (a test's fixture, say)
    # is not one this run made.
    let found = (
        glob $"($ws_root)/**/*.cdx.json" --exclude ["**/target/**"]
        | where { ($in | path type) == "file" }
        | where { ($in | path dirname | path join "Cargo.toml" | path exists) }
    )
    log-debug $"found ($found | length) SBOM file\(s\) under ($ws_root)" --component $COMPONENT
    if ($found | is-empty) {
        log-warn "cargo-cyclonedx reported success but produced no *.cdx.json files" --component $COMPONENT
        return []
    }
    for src in $found {
        let dest = $artifact_dir | path join ($src | path basename)
        if ($src | path expand) == ($dest | path expand) { continue }
        mv --force $src $dest
    }
    let collected = (
        ls $artifact_dir
        | where type == file
        | where { ($in.name | path basename | str ends-with ".cdx.json") }
    )
    $collected
}


def process-cargo-sboms [sbom_files: list<record>, packages: list<record>]: nothing -> nothing {

    for f in $sbom_files {
        let doc = try { open $f.name } catch {|e|
            log-warn $"could not parse ($f.name): ($e.msg)" --component $COMPONENT
            continue
        }
        if ($doc.bomFormat? | default "") != "CycloneDX" { continue }

        let filename = $f.name | path basename
        let stem = $filename | str replace ".cdx.json" ""
        let content_hash = (content-hash-file $f.name)

        emit-artifact-produced $content_hash "sbom" --name $filename --content_type "application/vnd.cyclonedx+json"

        let fragment = (extract-graph-fragment $doc $content_hash)

        if $fragment.root != null {
            emit-sbom-analyzed $fragment $filename
            log-info $"($stem): ($fragment.components | length) components, ($fragment.edges | length) edges" --component $COMPONENT
        } else {
            log-warn $"($filename) has no metadata.component — graph fragment not emitted" --component $COMPONENT
        }

        let matched = (
            $packages
            | where name == $stem
            | first
            | default null
        )
        let root_purl = if $fragment.root != null {
            $fragment.root.purl
        } else if $matched != null {
            ($matched.purl? | default "")
        } else {
            ""
        }

        # Root-level lookup: Phase 2 binary linking + Phase 3 purl cross-check.
        record-sbom $stem $content_hash $root_purl ($fragment.components | length) ($fragment.edges | length)

        # Full component closure: vulnerability -> package attribution (#217).
        for c in ($fragment.components | uniq) {
            record-sbom-package ($c.name | default "") ($c.version | default "") ($c.purl | default "") $content_hash
        }
    }
}

# ===========================================================================
# Phase 2: Binary build and provenance linking
# ===========================================================================

# What the pipeline reports its own facts as (`fact_reported`): the tool, and its version, the repository's.
const FACT_TOOL = "polar-pipeline/ci.nu"

# The binaries the images in scope ship, each built by Nix from its crane derivation (`refs`, flake references to the
# derivations, as image-manifest names them; build-inspect-ship, S2). Nothing is built with cargo here: the binary
# reported is the one the image is made from, out of the same store path.
#
# For each derivation: how it came to be in the store this run (`nix build --dry-run`: built, fetched or present before
# the run, core/nix.nu), then its outputs, `out` and `cargolog`. Its cargo log says which binaries it linked and the
# package of each (core/binaries.nu). Each binary is hashed as it is installed in `$out/bin`, after Nix has stripped
# it, and reported: ArtifactProduced, the facts of its realisation, and BinaryLinked to its package's SBOM from phase 1.
# A binary built with cargo-auditable carries a record of the crates it was built from, which auditable2cdx writes out
# as CycloneDX. That record is reported (an SBOM of its own, linked to the binary by a second BinaryLinked) only when it
# is asked for (`--auditable_sbom`, ci.nu's `--auditable-sbom`), and is off by default because it was measured false:
# on cassini-server (build-processor/tests/binary_trees.rs, on the host 2026-11-11) cargo-auditable 0.6.2's record names
# 492 packages where the build compiled 466, the same 26 more the workspace SBOM names, and 13 proc-macros as runtime
# dependencies. It is the workspace's resolution, not the binary's. It goes on by default only when a cargo-auditable
# version passes that test.
#
# Run from the repository's root, as phase 3's `nix build` is.
def build-and-link-binaries [
    refs: list<string>
    packages: list<record>
    ws_manifest: path
    artifact_dir: path
    --filter_package: string = ""
    --auditable_sbom # report the binary's cargo-auditable record as its own SBOM (off: see above)
]: nothing -> list<record> {
    let ws_root = $ws_manifest | path dirname
    let version = open --raw ($ws_root | path join ".." ".." "VERSION") | str trim
    let cargo_lock_hash = (content-hash-file $"($ws_root)/Cargo.lock")
    let source_tree_hash = (tree-hash $ws_root)

    $refs | uniq | each {|ref|
        let derivation = (realise-derivation $ref)
        let log = open --raw ($derivation.outputs.cargolog | path join "cargo-build.json") | lines
        let linked = linked-binaries $log
        if ($linked | is-empty) {
            log-warn $"($ref): its cargo log names no binary it linked" --component $COMPONENT
        }
        $linked
        | where {|b| ($filter_package | is-empty) or $b.package == $filter_package }
        | each {|bin|
            let exe = $derivation.outputs.out | path join "bin" $bin.name
            if not ($exe | path exists) {
                log-warn $"($bin.name): linked by ($ref) but not in its out/bin" --component $COMPONENT
                return null
            }
            let pkg = $packages | where name == $bin.package | first | default null
            if $pkg == null {
                log-warn $"($bin.name): its package ($bin.package) is not among this run's packages" --component $COMPONENT
                return null
            }
            let binary_hash = (content-hash-file $exe)
            emit-artifact-produced $binary_hash $ELF_BINARY_ARTIFACT --name $bin.name

            let subject = {label: "Binary", key: $binary_hash}
            emit-fact $subject "polar.nix/realised" $FACT_TOOL $version --value $derivation.realised
            emit-fact $subject "polar.nix/store-path" $FACT_TOOL $version --value $derivation.outputs.out
            if $derivation.realised == "built" {
                emit-fact $subject "polar.nix/built-at" $FACT_TOOL $version --value $derivation.at
            }

            let cargo_toml_hash = (content-hash-file $pkg.manifest_path)
            let binding = (
                [$binary_hash $cargo_toml_hash $cargo_lock_hash $source_tree_hash]
                | str join ":"
                | hash sha256
                | $"sha256:($in)"
            )
            let sbom_info = (get-sbom-info $pkg.name)
            if $sbom_info != null {
                emit-binary-linked $binary_hash $bin.name $sbom_info.root_purl $sbom_info.content_hash --binding_digest $binding
                log-info $"($bin.name) -> ($sbom_info.root_purl)" --component $COMPONENT
            } else {
                log-warn $"($bin.name): no SBOM for package ($pkg.name) — binary_linked not emitted" --component $COMPONENT
            }
            let own = if $auditable_sbom { binary-sbom $exe $bin.name $artifact_dir } else { null }
            if $own != null {
                let root_purl = $sbom_info.root_purl? | default $own.root_purl
                emit-binary-linked $binary_hash $bin.name $root_purl $own.content_hash --binding_digest $binding
            }

            {
                name: $bin.name
                path: $exe
                binary_hash: $binary_hash
                package_name: $pkg.name
                realised: $derivation.realised
                root_purl: ($sbom_info.root_purl? | default "")
                sbom_content_hash: ($sbom_info.content_hash? | default "")
                own_sbom_content_hash: ($own.content_hash? | default "")
            }
        }
        | compact
    } | flatten
}

# One derivation, realised: how its outputs came to be in the store (`realised`, from the dry run), when it was built
# if it was built here (`at`), and its outputs' paths. A derivation Nix cannot plan or build stops the pipeline, as a
# failed cargo build did.
def realise-derivation [ref: string]: nothing -> record {
    let installable = $"($ref)^*"
    let drv = (^nix eval --raw $"($ref).drvPath" | complete)
    let outs = (
        ^nix eval --json $"($ref)" --apply "d: map (o: d.${o}.outPath) d.outputs"
        | complete
    )
    if $drv.exit_code != 0 or $outs.exit_code != 0 {
        error make {
            msg: $"nix could not evaluate ($ref): ($drv.stderr)($outs.stderr | str trim | lines | last 3 | str join ' ')"
        }
    }
    let dry = (^nix build --dry-run --no-link $installable | complete)
    if $dry.exit_code != 0 {
        error make {
            msg: $"nix could not plan ($ref): ($dry.stderr | str trim | lines | last 3 | str join ' ')"
        }
    }
    let realised = ((realisation
        $dry.stderr
        ($drv.stdout | str trim)
        ($outs.stdout | from json)
    ))
    log-info $"($ref): ($realised)" --component $COMPONENT
    let built = (^nix build --json --no-link $installable | complete)
    if $built.exit_code != 0 {
        error make {
            msg: $"nix build failed for ($ref): ($built.stderr | str trim | lines | last 5 | str join ' ')"
        }
    }
    {
        realised: $realised
        at: (reported-now)
        outputs: (
            $built.stdout
            | from json
            | first
            | get outputs
        )
    }
}

# A binary's own SBOM, out of the record cargo-auditable embedded in it, written out by auditable2cdx and reported as an
# SBOM: its file, its content hash and its root's purl, or null when the binary carries no record (one not built with
# cargo-auditable) or the tool is not here. Not a failure either way: the binary is still reported.
def binary-sbom [exe: path, name: string, artifact_dir: path]: nothing -> any {
    if (which auditable2cdx | is-empty) {
        log-warn $"($name): auditable2cdx is not on PATH, so no SBOM is taken out of the binary" --component $COMPONENT
        return null
    }
    let read = (^auditable2cdx $exe | complete)
    if $read.exit_code != 0 or ($read.stdout | is-empty) {
        log-info $"($name): no cargo-auditable record in it" --component $COMPONENT
        return null
    }
    let file = $artifact_dir | path join $"($name).auditable.cdx.json"
    $read.stdout | save --force --raw $file
    let content_hash = (content-hash-file $file)
    let filename = $file | path basename
    emit-artifact-produced $content_hash "sbom" --name $filename --content_type "application/vnd.cyclonedx+json"
    let fragment = extract-graph-fragment ($read.stdout | from json) $content_hash
    if $fragment.root == null {
        log-warn $"($name): its auditable record names no root" --component $COMPONENT
        return null
    }
    emit-sbom-analyzed $fragment $filename
    log-info $"($name): its own SBOM, ($fragment.components | length) components" --component $COMPONENT
    {file: $file, content_hash: $content_hash, root_purl: $fragment.root.purl}
}

# ===========================================================================
# Phase 3: OCI image build and upload
# ===========================================================================

def registry-refs [image_name: string]: nothing -> list<string> {
    mut refs = []
    let ci_reg = $env.CI_REGISTRY? | default ""
    if ($ci_reg | is-not-empty) { $refs = ($refs | append $"docker://($ci_reg)/polar/($image_name):{tag}") }
    $refs
}

# A helper that would let us login to multiple registires, should we wish to push to other places
def login-to-registries []: nothing -> nothing {
    let ci_reg  = $env.CI_REGISTRY? | default ""
    let ci_user = $env.CI_REGISTRY_USER? | default ""
    let ci_pass = $env.CI_REGISTRY_PASSWORD? | default ""

    if ($ci_reg | is-empty) or ($ci_user | is-empty) {
        log-debug "No OCI registry credentials configured, skipping login." --component $COMPONENT
        return
    }

    let insecure = ($env.POLAR_REGISTRY_INSECURE? | default "" | is-not-empty)
    let creds = [{registry: $ci_reg, username: $ci_user, password: $ci_pass, insecure: $insecure}]

    registry-login $creds
}

def process-image [entry: record, image_tag: string, --skip-upload]: nothing -> record {
    # Cross-validate the manifest's hardcoded root_purl against what Phase 1
    # actually analyzed. Static image-manifest purls drift silently on the
    # first crate version bump; this makes that loud.
    let chk = (check-manifest-purl $entry.root_purl)
    if $chk.status == "version_drift" {
        log-warn $"($entry.name): manifest pins ($chk.manifest_purl) but this run analyzed ($chk.analyzed_purl) — image-manifest is stale" --component $COMPONENT
    } else if $chk.status == "absent" {
        log-warn $"($entry.name): manifest root_purl ($chk.manifest_purl) was never analyzed this run" --component $COMPONENT
    }

    let build = (nix-build-image $entry.flake $entry.name)
    if not $build.success {
        return {
            success: false
            image_name: $entry.name
            uploads: []
        }
    }

    # Decouple the tarball hash from the return-record contract. Ideally this
    # write lives inside nix-build-image next to content-hash-file; recorded
    # here it still trusts $build once, but the guard in build-and-push-image
    # turns any miss into a loud failure instead of a silent null.
    record-tarball-hash $entry.name $build.tarball_hash

    if $skip_upload {
        return {
            success: true
            image_name: $entry.name
            uploads: []
        }
    }
    build-and-push-image $entry.name $image_tag (registry-refs $entry.image) $build --root_purl $entry.root_purl
}


def build-and-push-image [
    link_name: string
    tag: string
    registries: list<string>
    build: record
    --root_purl: string = ""
]: nothing -> record {
    let oci_metadata = $build.oci_metadata

    # Load-bearing: emit-container-image-created needs the tarball hash. Pull it
    # from stor (recorded in process-image) rather than $build, and fail loudly
    # if absent — the regression guard #231 asks for.
    let tarball_hash = (get-tarball-hash $link_name)
    if ($tarball_hash | is-empty) {
        error make {msg: $"no tarball hash recorded for ($link_name) — record-tarball-hash did not run"}
    }
    if ($registries | length) == 0 {
        log-warn $"No registries configured for ($link_name) — image will not be uploaded anywhere" --component $COMPONENT
    }

    let insecure = ($env.POLAR_REGISTRY_INSECURE? | default "" | is-not-empty)
    let uploads = ($registries | each {|template|
        let remote_ref = ($template | str replace "{tag}" $tag)
        if $insecure {
            upload-image $build.tarball $remote_ref --name $link_name --insecure
        } else {
            upload-image $build.tarball $remote_ref --name $link_name
        }
    })

    for upload in $uploads {
        if ($upload.digest | is-empty) {
            log-warn $"no digest for ($upload.remote_ref) — skipping sign" --component $COMPONENT
            continue
        }

        # emit an event saying we created a new build artifact
        emit-artifact-produced $upload.digest "oci-image" --name $link_name
        # then, emit a second message detailing that this artifact was a container image.

        # TODO: well, turns out this is pretty stupid. It's fine to treat all images effectively as build artifacts.
        # So perhaps these payloads could be merged. ContainerImageCreated messages should send build metadata now

        (
        emit-container-image-created
            $link_name
            $tarball_hash
            $oci_metadata.config_digest
            $oci_metadata.layers
            --os $oci_metadata.os
            --arch $oci_metadata.arch
            --created $oci_metadata.created
            --entrypoint $oci_metadata.entrypoint
            --cmd $oci_metadata.cmd
            --digest $upload.digest
            --uri $upload.remote_ref
        )

        # ── Cosign signature ───────────────────────────────────────────────────
        # cosign requires a digest ref: registry.io/org/app@sha256:abc...
        let base_ref = (
            $upload.remote_ref
            | str replace "docker://" ""
            | parse "{repo}:{tag}"
            | get -o 0
            | default {repo: ""}
            | get repo
        )
        let digest_ref = $"($base_ref)@($upload.digest)"
        sign-image $digest_ref --name $upload.name
    }

    {
        success: true
        image_name: $link_name
        tarball: $build.tarball
        oci_metadata: $oci_metadata
        uploads: $uploads
    }
}

# ===========================================================================
# Main
# ===========================================================================

def main [
    build_id: string            # Stable unique ID for this pipeline run.
                                # In GitLab CI: $CI_PIPELINE_ID or a UUIDv5 derived from it.
                                # Locally: pass any stable string, e.g. (random uuid) once per session.
    --package(-p): string = ""
    --target(-t): string = ""
    --tag: string = ""
    --filter: string = ""
    --skip-upload
    --artifact-dir: path = "pipeline-out"
    --skip-analysis
    --strict-analysis
    --skip-build
    # Report each binary's cargo-auditable record as its own SBOM. Off: cargo-auditable 0.6.2's record was measured to be
    # the workspace's, not the binary's (build-processor/tests/binary_trees.rs); on only for a version that passes it.
    --auditable-sbom
    --skip-images
    --skip-audit
    --audit-offline
] {
    let ws_root = (workspace-root)
    let ws_manifest = $ws_root | path join "Cargo.toml"
    let commit_sha = (source-commit)

    # Initialize pipeline-scoped singleton state. All emit-* functions that
    # need build_id (artifact domain events) read it from here rather than
    # from an env var. This guarantees every event in this pipeline run carries
    # the same build_id regardless of call depth or module boundaries.
    init-pipeline-state $build_id

    let result = try {
        let start_time = (date now)

        # That the build started, completed or failed is the orchestrator's to say, on its own topic, from what it saw
        # (docs/architecture/build-orchestrator.md, "Settled with it", two topics): the pipeline reports only what it made
        # and found, and a line it prints of an execution is refused.

        rm --force --recursive $artifact_dir
        mkdir -v $artifact_dir

        if not $skip_analysis {
            let analysis_results = (run-static-analysis $ws_manifest $artifact_dir)
            let failed = $analysis_results | where exit_code != 0
            if ($failed | is-not-empty) {
                let names = $failed | get name | str join ", "
                if $strict_analysis {
                    error make {msg: $"static analysis failed (strict mode): ($names)"}
                } else {
                    log-warn $"static analysis non-zero exits: ($names) — continuing \(pass --strict-analysis to abort\)" --component $COMPONENT
                }
            }
        }

        # Use full SHA for image tag when available — short SHA or "latest" as fallback.
        let image_tag = if ($tag | is-not-empty) {
            $tag
        } else {
            $env.CI_COMMIT_SHORT_SHA? | default ($commit_sha | str substring 0..8) | default "latest"
        }

        let packages = (resolve-packages --package $package)
        log-info $"($packages | length) package\(s\) in scope, image tag: ($image_tag)" --component $COMPONENT

        # Phase 1 — Cargo SBOMs
        let sbom_files = (generate-workspace-sboms $packages $ws_manifest $artifact_dir --target $target)
        process-cargo-sboms $sbom_files $packages
        log-info $"($sbom_files | length) SBOM\(s\) generated and analyzed" --component $COMPONENT

        # Phase 1.5 — Vulnerability scanning
        # Depends on sbom_packages populated above — resolves findings against
        # the purls Phase 1 just recorded, never reconstructs one by hand.
        # cargo-deny operates via --manifest-path, so $ws_manifest is passed
        # directly — no need to construct a separate Cargo.lock path the way
        # cargo-audit's --file flag once required.
        if not $skip_audit {
            let findings = (
                run-vulnerability-scan $ws_manifest
            )
            let unresolved = ($findings | where {|f| ($f.affected_package | default "" | is-empty) } | length)
            log-info $"($findings | length) finding\(s\) from vulnerability scan \(($unresolved) unresolved against SBOM\)" --component $COMPONENT
        }

        # Phase 2 — the binaries the images in scope ship, built by Nix from their crane derivations
        if not $skip_build {
            let rows = if ($filter | is-not-empty) {
                image-manifest | where { $in.name | str contains $filter }
            } else {
                image-manifest
            }
            let refs = $rows | get binaries | flatten | uniq
            let binaries = (
                build-and-link-binaries $refs $packages $ws_manifest $artifact_dir
                    --filter_package $package
                    --auditable_sbom=$auditable_sbom
            )
            log-info $"($binaries | length) binary\(ies\) built and linked" --component $COMPONENT
        }

        # Phase 3 — OCI images
        if not $skip_images {
            let manifest = if ($filter | is-not-empty) {
                image-manifest | where { $in.name | str contains $filter }
            } else {
                image-manifest
            }

            if ($manifest | is-empty) {
                log-warn $"no images match filter '($filter)' — skipping Phase 3" --component $COMPONENT
            } else {
                # Refuse image work if Phase 1 produced no SBOM state — turns a
                # downstream null into an immediate, diagnosable stop.
                assert-sbom-state-populated

                if not $skip_upload { login-to-registries }
                log-info $"building ($manifest | length) image\(s\)" --component $COMPONENT

                let results = ($manifest | each {|entry|
                    log-info $"--- ($entry.name) ---" --component $COMPONENT
                    process-image $entry $image_tag --skip-upload=$skip_upload
                })

                let succeeded = $results | where success == true | length
                let failed    = $results | where success == false | length
                log-info $"($succeeded) image\(s\) succeeded, ($failed) failed" --component $COMPONENT

                if $failed > 0 {
                    let failures = ($results | where success == false | get image_name | str join ", ")
                    log-warn $"failed images: ($failures)" --component $COMPONENT
                }
            }
        }

        let elapsed = (date now) - $start_time
        log-info $"pipeline complete \(duration: ($elapsed | format duration 'ms')\)" --component $COMPONENT


        null
    } catch {|e|
        let msg = $e.msg
        log-error $msg --component $COMPONENT
        $msg
    }

    if $result != null {
        error make {msg: $result}
    }
}
