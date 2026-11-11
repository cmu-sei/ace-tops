# The fixtures for build-processor's test of what a binary's build compiled against the workspace SBOM of its package
# (tests/binary_trees.rs; build-inspect-ship, S2): two package sets, compared there.
#
# - `<binary>.cargo-build.json`: the cargo log of the binary's Nix build (its derivation's `cargolog` output), which says
#   which crates were compiled for it: the record of that build;
# - `<package>.cdx.json`: the workspace SBOM of the binary's package, as the pipeline generates it (cargo-cyclonedx,
#   `generate-workspace-sboms`), byte for byte: a claim about the source tree at the commit;
# - `manifest.json`: the commit, the binary and its package, the store paths, and the tools' versions.
#
# Run on the host, in ACE's dev shell (nix, cargo and cargo-cyclonedx), from anywhere in the repository:
#
#   nu src/agents/build-processor/tests/fixtures/binary-trees/make.nu
#
# It builds the binary's derivation with Nix (from this checkout, as the pipeline does), and runs cargo-cyclonedx in a
# temporary worktree of the same commit, outside the repository. Any command that fails stops it.

use ../../../../../../scripts/pipeline/core/binaries.nu [linked-binaries]

# The binary, and the derivation it is built by.
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

    print $"building ($DERIVATION) at ($commit)"
    let built = exec-or-stop nix build --json --no-link $"($DERIVATION)^*" | from json | first
    let log = open --raw ($built.outputs.cargolog | path join "cargo-build.json")
    let package = linked-binaries ($log | lines) | where name == $BINARY | first | get package

    rm --recursive --force $out
    mkdir $out
    $log | save --raw ($out | path join $"($BINARY).cargo-build.json")

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
        nix: (exec-or-stop nix --version | str trim)
        cargo: (exec-or-stop cargo --version | str trim)
        cyclonedx: (exec-or-stop cargo cyclonedx --version | str trim)
    } | to json | save --force ($out | path join "manifest.json")

    exec-or-stop git worktree remove --force $worktree | ignore
    rm --recursive --force $scratch
    print $"wrote ($out)"
}
