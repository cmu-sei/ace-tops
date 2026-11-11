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
# - `base/<root>.cdx.json` and `head/<root>.cdx.json`: the SBOM cargo-cyclonedx writes for the root, as the pipeline
#   generates it (`generate-workspace-sboms`), byte for byte;
# - `base/<root>.fragment.json` and `head/<root>.fragment.json`: that SBOM as the pipeline reduces it
#   (`extract-graph-fragment`);
# - `base/<root>.cargo-tree.json` and `head/<root>.cargo-tree.json`: the root's tree as `cargo tree` resolves it
#   (normal and build dependencies, the host's target), each package as `name@version`, apart from the SBOM.
#
# The roots kept are those whose `cargo tree` differs between the commits (at most MAX_TOUCHED, by name) and the first
# whose tree does not, which must assert the same tree at both. Pass `--target` as the pipeline was given one.

# The fixtures for build-processor's test of what a binary's own record says it holds (tests/binary_trees.rs;
# build-inspect-ship, S2): for a binary built with cargo-auditable, three package sets, compared there.
#
# - `<binary>.cargo-build.json`: the cargo log of the binary's Nix build (its derivation's `cargolog` output), which says
#   which crates were compiled for it: the ground truth;
# - `<binary>.auditable.cdx.json`: the record cargo-auditable embedded in the binary, written out by auditable2cdx,
#   byte for byte;
# - `<package>.cdx.json`: the workspace SBOM of the binary's package, as the pipeline generates it (cargo-cyclonedx,
#   `generate-workspace-sboms`), byte for byte;
# - `manifest.json`: the commit, the binary and its package, the store paths, and the tools' versions.
#
# Run on the host, in ACE's dev shell (nix, cargo and cargo-cyclonedx), from anywhere in the repository:
#
#   nu src/agents/build-processor/tests/fixtures/binary-trees/make.nu
#
# It builds the binary's derivation and auditable2cdx with Nix (from this checkout, as the pipeline does), and runs
# cargo-cyclonedx in a temporary worktree of the same commit, outside the repository. Any command that fails stops it.

use ../../../../../../scripts/pipeline/core/binaries.nu [linked-binaries]

# The binary, and the derivation it is built by (cassini-server: the first built with cargo-auditable).
const BINARY = "cassini-server"
const DERIVATION = ".#polarPkgs.cassini.cassini"

# Runs an external command and gives its output, or stops the script with what it said.
def --wrapped exec-or-stop [command: string, ...args: string]: nothing -> string {
    let result = ^$command ...$args | complete
    if $result.exit_code != 0 {
        error make {
            msg: $"($command) ($args | str join ' ') exited ($result.exit_code): ($result.stderr | str trim)"
        }
    }
    $result.stdout
}

def main [] {
    let repo = exec-or-stop git rev-parse --show-toplevel | str trim
    cd $repo
    let commit = exec-or-stop git rev-parse HEAD | str trim
    let dirty = exec-or-stop git status --porcelain | str trim | is-not-empty
    let out = $env.FILE_PWD | path join $BINARY

    print $"building ($DERIVATION) and auditable2cdx at ($commit)"
    let built = exec-or-stop nix build --json --no-link $"($DERIVATION)^*" | from json | first
    let tool = (exec-or-stop
        nix
        build
        --no-link
        --print-out-paths
        ".#polarPkgs.auditable2cdx"
    ) | str trim
    let exe = $built.outputs.out | path join "bin" $BINARY
    let log = open --raw ($built.outputs.cargolog | path join "cargo-build.json")
    let package = linked-binaries ($log | lines) | where name == $BINARY | first | get package

    rm --recursive --force $out
    mkdir $out
    $log | save --raw ($out | path join $"($BINARY).cargo-build.json")
    exec-or-stop ($tool | path join "bin" "auditable2cdx") $exe | save --raw ($out | path join $"($BINARY).auditable.cdx.json")

    # The workspace SBOM, as generate-workspace-sboms makes it, in a worktree of the same commit outside the repository.
    let scratch = mktemp --directory --tmpdir binary-trees.XXXXXX
    let worktree = $scratch | path join "tree"
    exec-or-stop git worktree add --detach $worktree $commit | ignore
    let manifest = $worktree | path join "src" "agents" "Cargo.toml"
    exec-or-stop cargo cyclonedx --manifest-path $manifest -f json | ignore
    let sbom = (
        glob $"($worktree)/src/agents/**/*.cdx.json" --exclude ["**/target/**"]
        # Beside a package's Cargo.toml, where cargo-cyclonedx writes them: not a test's fixtures.
        | where {|f| $f | path dirname | path join "Cargo.toml" | path exists }
        | where {|f| (open --raw $f | from json | get metadata.component.name) == $package }
    )
    if ($sbom | length) != 1 {
        error make {msg: $"($package): ($sbom | length) workspace SBOMs name it, not one"}
    }
    open --raw ($sbom | first) | save --raw ($out | path join $"($package).cdx.json")

    {
        commit: $commit
        dirty: $dirty
        binary: $BINARY
        package: $package
        derivation: $DERIVATION
        drv: $built.drvPath
        out: $built.outputs.out
        cargolog: $built.outputs.cargolog
        auditable2cdx: $tool
        nix: (exec-or-stop nix --version | str trim)
        cargo: (exec-or-stop cargo --version | str trim)
        cyclonedx: (exec-or-stop cargo cyclonedx --version | str trim)
    } | to json | save --force ($out | path join "manifest.json")

    exec-or-stop git worktree remove --force $worktree | ignore
    rm --recursive --force $scratch
    print $"wrote ($out)"
}
