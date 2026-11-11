# The fixtures for build-processor's falsifiability test (tests/sbom_trees.rs; Blitz's risk-gradients.md,
# "Verification"): for adjacent ACE commits with a Cargo.lock change, the tree each SBOM asserts must be what cargo
# resolves, at both commits, and the change between them must agree with the lock file's.
#
# Run on the host, in ACE's dev shell (cargo and cargo-cyclonedx), from anywhere in the repository:
#
#   nu src/agents/build-processor/tests/fixtures/sbom-trees/make.nu
#
# It builds nothing: `cargo cyclonedx` and `cargo tree` read the metadata only. For each pair below, at both commits,
# in a temporary worktree of `src/agents`, it writes beside this script, in `<pair>/`:
#
# - `manifest.json`: the commits, the tool versions, the packages the lock file gained and lost, and the roots kept;
# - `base/<root>.fragment.json` and `head/<root>.fragment.json`: the SBOM cargo-cyclonedx writes for the root, as
#   the pipeline generates it (`generate-workspace-sboms`) and reduces it (`extract-graph-fragment`);
# - `base/<root>.cargo-tree.json` and `head/<root>.cargo-tree.json`: the root's tree as `cargo tree` resolves it
#   (normal and build dependencies, the host's target), each package as `name@version`, apart from the SBOM.
#
# The roots kept are those whose `cargo tree` differs between the commits (at most MAX_TOUCHED, by name) and the first
# whose tree does not, which must assert the same tree at both. Pass `--target` as the pipeline was given one.

use ../../../../../../scripts/pipeline/core/sbom.nu [extract-graph-fragment]

const PAIRS = [
    {
        name: "ssh-keys"
        base: "a2165eeb^"
        head: "a2165eeb"
        says: "packages added (an ssh client and its crypto) and versions changed"
    }
    {
        name: "polar-version"
        base: "409a7a49^"
        head: "409a7a49"
        says: "edges only: polar-version added under five crates, no package new to the lock"
    }
]

const MAX_TOUCHED = 6

def main [--target: string = ""] {
    let repo = (^git rev-parse --show-toplevel | str trim)
    let out = $env.FILE_PWD
    let scratch = (mktemp --directory --tmpdir sbom-trees.XXXXXX)
    for pair in $PAIRS {
        let base = (^git -C $repo rev-parse $"($pair.base)^{commit}" | str trim)
        let head = (^git -C $repo rev-parse $"($pair.head)^{commit}" | str trim)
        print $"($pair.name): ($base) .. ($head)"
        let before = ((side
            $repo
            $base
            ($scratch | path join $"($pair.name)-base")
            $target
        ))
        let after = ((side
            $repo
            $head
            ($scratch | path join $"($pair.name)-head")
            $target
        ))

        let common = (
            $before.roots
            | columns
            | where {|r| $r in ($after.roots | columns) }
            | sort
        )
        let touched = (
            $common
            | where {|r| ($before.roots | get $r | get tree) != ($after.roots | get $r | get tree) }
        )
        let untouched = $common | where {|r| $r not-in $touched } | first 1
        if ($touched | is-empty) {
            error make {
                msg: $"($pair.name): no root's cargo tree differs between ($base) and ($head)"
            }
        }
        let kept = ($touched | first $MAX_TOUCHED | each {|r| {name: $r, touched: true} }
            | append ($untouched | each {|r| {name: $r, touched: false} }))

        let dir = $out | path join $pair.name
        rm --recursive --force $dir
        for which in [base head] {
            let at = if $which == "base" { $before } else { $after }
            mkdir ($dir | path join $which)
            for root in $kept {
                let kept_root = $at.roots | get $root.name
                $kept_root.fragment | to json | save --force ($dir | path join $which $"($root.name).fragment.json")
                $kept_root.tree | to json | save --force ($dir | path join $which $"($root.name).cargo-tree.json")
            }
        }
        {
            base: $base
            head: $head
            says: $pair.says
            target: $target
            cargo: $before.cargo
            cyclonedx: $before.cyclonedx
            lock: {
                added: ($after.lock | where {|p| $p not-in $before.lock } | sort)
                removed: ($before.lock | where {|p| $p not-in $after.lock } | sort)
            }
            roots: $kept
        } | to json | save --force ($dir | path join "manifest.json")
        print $"  kept ($kept | length) roots, ($touched | length) of ($common | length) touched"
    }
    rm --recursive --force $scratch
    ^git -C $repo worktree prune
}

# One commit: its SBOMs reduced to fragments, each root's cargo tree, and the packages in its lock file.
def side [
    repo: string
    commit: string
    dir: string
    target: string
]: nothing -> record {
    ^git -C $repo worktree add --detach $dir $commit
    let ws = $dir | path join "src" "agents"
    let manifest = $ws | path join "Cargo.toml"

    # As generate-workspace-sboms runs it (scripts/pipeline/ci.nu).
    mut args = [cyclonedx --manifest-path $manifest -f json]
    if ($target | is-not-empty) { $args = ($args | append [--target $target]) }
    ^cargo ...$args

    let roots = (glob $"($ws)/**/*.cdx.json" --exclude ["**/target/**"] | each {|file|
        let doc = open --raw $file | from json
        let hash = $"sha256:(open --raw $file | hash sha256)"
        let fragment = extract-graph-fragment $doc $hash | insert filename ($file | path basename)
        let name = $doc.metadata.component.name
        let version = $doc.metadata.component.version
        {name: $name, fragment: $fragment, tree: (cargo-tree $manifest $name $version $target)}
    } | reduce --fold {} {|root, acc| $acc | insert $root.name {fragment: $root.fragment, tree: $root.tree} })

    let lock = (open --raw ($ws | path join "Cargo.lock") | from toml | get package
        | each {|p| $"($p.name)@($p.version)" } | uniq)
    let versions = {
        cargo: (^cargo --version | str trim)
        cyclonedx: (^cargo cyclonedx --version | str trim)
    }
    ^git -C $repo worktree remove --force $dir
    {
        roots: $roots
        lock: $lock
        cargo: $versions.cargo
        cyclonedx: $versions.cyclonedx
    }
}

# A root's tree as cargo resolves it: its packages but the root, and each (from, to) dependency, as `name@version`.
# `--prefix depth` gives each line's depth; a package already shown is marked `(*)` and not expanded again, so each
# edge is listed once, under the one expansion of its `from`. Lines such as `[build-dependencies]` head a group.
def cargo-tree [
    manifest: string
    name: string
    version: string
    target: string
]: nothing -> record {
    mut args = [
        tree
        --manifest-path
        $manifest
        -p
        $"($name)@($version)"
        -e
        normal
        build
        --prefix
        depth
        --format
        "{p}"
    ]
    if ($target | is-not-empty) { $args = ($args | append [--target $target]) }
    let lines = (^cargo ...$args | lines | where {|l| $l | is-not-empty })
    mut path = []
    mut pairs = []
    for line in $lines {
        let parsed = $line | parse --regex '^(?<depth>\d*)(?<rest>.*)$' | first
        let rest = $parsed.rest | str trim
        if ($rest | str starts-with "[") { continue }
        let tokens = $rest | split row " "
        let package = $"($tokens.0)@($tokens.1 | str replace --regex '^v' '')"
        let depth = $parsed.depth | into int
        $path = ($path | first $depth | append $package)
        if $depth > 0 {
            $pairs = ($pairs | append [
                [
                    ($path | get ($depth - 1))
                    $package
                ]
            ])
        }
    }
    let root = $"($name)@($version)"
    let pairs = $pairs | uniq | sort
    let packages = (
        $pairs
        | flatten
        | where {|p| $p != $root }
        | uniq
        | sort
    )
    {root: $root, packages: $packages, pairs: $pairs}
}
