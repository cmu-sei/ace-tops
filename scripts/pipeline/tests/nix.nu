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

# scripts/pipeline/tests/nix.nu
# How a derivation's outputs came to be in the store (core/nix.nu, `observed-realisation`): present, built here or
# fetched, or unknown, observed of the store before and after the build, never planned.
# Run: nu scripts/pipeline/tests/nix.nu

use std/assert
use ../core/nix.nu [observed-realisation store-records]

const OUT = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-cassini-server-1.0.0"
const LOG = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-cassini-server-1.0.0-cargolog"

# What `nix-store --check-validity --print-invalid` gives: the paths not valid, one a line.
def invalid [...paths: string]: nothing -> record {
    {
        exit_code: 0
        stdout: ($paths | each {|p| $p + "\n" } | str join)
    }
}

# What `nix path-info --json` gives, in the shape Nix 2.19 and after write: each path's info by its path.
def path-info [infos: record]: nothing -> record {
    {
        exit_code: 0
        stdout: ($infos | to json --raw)
    }
}

# A path's info as the store records one built here (`ultimate`, unsigned), and one substituted (signed).
def built-info [registered: int]: nothing -> record {
    {
        ultimate: true
        registrationTime: $registered
        signatures: []
        narHash: "sha256-x"
    }
}

def fetched-info [registered: int]: nothing -> record {
    {
        ultimate: false
        registrationTime: $registered
        signatures: ["cache.nixos.org-1:abc"]
        narHash: "sha256-x"
    }
}

# A stand-in `nix` in `bin`, answering `path-info` as $STANDIN_NIX says: "new" knows `--json-format` (and warns at bare
# `--json`, as Nix 2.34 does), "old" does not (as Nix 2.18, the CI image's, does not), "broken" fails. Each call's
# arguments are appended to $NIX_CALLS. Each output is recorded as built here.
def stand-in-nix [bin: path] {
    mkdir $bin
    let file = $bin | path join "nix"
    "#!/usr/bin/env bash\n" + r#'
echo "$*" >> "$NIX_CALLS"
[ "$1" = path-info ] || { echo "stand-in nix: $*" >&2; exit 2; }
shift
fmt=""; paths=()
while [ $# -gt 0 ]; do
  case "$1" in --json) ;; --json-format) fmt="$2"; shift ;; *) paths+=("$1") ;; esac
  shift
done
case "$STANDIN_NIX" in
  broken) echo "error: something else" >&2; exit 1 ;;
  old)
    [ -n "$fmt" ] && { echo "error: unrecognised flag '--json-format'" >&2; exit 1; }
    sep=""; printf "["
    for p in "${paths[@]}"; do printf '%s{"path":"%s","ultimate":true,"registrationTime":1762890005,"signatures":[]}' "$sep" "$p"; sep=","; done
    printf "]\n" ;;
  new)
    [ -z "$fmt" ] && echo "warning: '--json' without '--json-format' is deprecated" >&2
    sep=""; printf "{"
    for p in "${paths[@]}"; do printf '%s"%s":{"ultimate":true,"registrationTime":1762890005,"signatures":[]}' "$sep" "$p"; sep=","; done
    printf "}\n" ;;
esac
'# | save --raw $file
    ^chmod +x $file
}

# `store-records` of the outputs, with the stand-in `nix` as `mode` says first on PATH: its result, and the calls made.
def records-with [mode: string]: nothing -> record {
    let root = mktemp --directory --tmpdir nix-test.XXXXXX
    let bin = $root | path join "bin"
    stand-in-nix $bin
    let calls = $root | path join "calls"
    "" | save --raw $calls
    let result = with-env {PATH: ($env.PATH | prepend $bin), STANDIN_NIX: $mode, NIX_CALLS: $calls} {
        store-records [$OUT $LOG]
    }
    let made = open --raw $calls | lines
    rm --recursive --force $root
    {result: $result, calls: $made}
}

def main [] {
    let outputs = [$OUT $LOG]
    let tests = [
        {
            name: "outputs valid in the store before the build were present, whatever a dry run planned"
            body: {
                # A dry run that said `built` would have been wrong here: another process realised them first.
                let after = path-info {
                    ($OUT): (built-info 1762890000)
                    ($LOG): (built-info 1762890005)
                }
                assert equal (observed-realisation $outputs (invalid) $after) {realised: present, at: null}
                assert equal (
                    observed-realisation $outputs (invalid) {exit_code: 1, stdout: ""}
                ) {
                    realised: present
                    at: null
                }
            }
        }
        {
            name: "outputs the store says were built here were built, at the time it registered them"
            body: {
                # A substitution that failed and fell back to a build: the plan said fetched; the store says built.
                let after = path-info {
                    ($OUT): (built-info 1762890000)
                    ($LOG): (built-info 1762890005)
                }
                assert equal (observed-realisation $outputs (invalid $OUT $LOG) $after) {
                    realised: built
                    at: "2025-11-11T19:40:05+00:00"
                }
                # Only what was not valid before is read: here the log alone was built.
                let old = path-info {
                    ($OUT): (built-info 1)
                    ($LOG): (built-info 1762890005)
                }
                assert equal (observed-realisation $outputs (invalid $LOG) $old) {
                    realised: built
                    at: "2025-11-11T19:40:05+00:00"
                }
                # Built, with no registration time to say when: no time.
                let untimed = path-info {
                    ($OUT): {ultimate: true}
                    ($LOG): {ultimate: true}
                }
                assert equal (observed-realisation $outputs (invalid $OUT $LOG) $untimed) {realised: built, at: null}
            }
        }
        {
            name: "outputs the store says came signed from elsewhere were fetched, in either shape Nix writes path-info"
            body: {
                let keyed = path-info {
                    ($OUT): (fetched-info 1762890000)
                    ($LOG): (fetched-info 1762890005)
                }
                assert equal (observed-realisation $outputs (invalid $OUT $LOG) $keyed) {realised: fetched, at: null}
                # Before Nix 2.19: a list, each with its path, and `ultimate` left out when false.
                let listed = {
                    exit_code: 0
                    stdout: (
                        [
                            {path: $OUT, registrationTime: 1762890000, signatures: ["cache.nixos.org-1:abc"]}
                            {path: $LOG, registrationTime: 1762890005, signatures: ["cache.nixos.org-1:def"]}
                        ]
                        | to json --raw
                    )
                }
                assert equal (observed-realisation $outputs (invalid $OUT $LOG) $listed) {realised: fetched, at: null}
            }
        }
        {
            name: "what the store says that does not settle it is unknown, with no time"
            body: {
                let built = path-info {
                    ($OUT): (built-info 1762890000)
                    ($LOG): (built-info 1762890005)
                }
                for case in [
                    [
                        "validity not read"
                        {exit_code: 1, stdout: ""}
                        $built
                    ]
                    [
                        "validity said of another path"
                        (invalid "/nix/store/zzzz-other")
                        $built
                    ]
                    [
                        "validity said in words"
                        {exit_code: 0, stdout: "error: something\n"}
                        $built
                    ]
                    [
                        "path-info failed"
                        (invalid $OUT $LOG)
                        {exit_code: 1, stdout: ""}
                    ]
                    [
                        "path-info not JSON"
                        (invalid $OUT $LOG)
                        {exit_code: 0, stdout: "not json"}
                    ]
                    [
                        "path-info without the log"
                        (invalid $OUT $LOG)
                        (path-info {
                            ($OUT): (built-info 1)
                        })
                    ]
                    [
                        "the log not valid after"
                        (invalid $OUT $LOG)
                        (path-info {
                            ($OUT): (built-info 1)
                            ($LOG): null
                        })
                    ]
                    [
                        "neither built here nor signed"
                        (invalid $OUT $LOG)
                        (
                            path-info {
                                ($OUT): {registrationTime: 1}
                                ($LOG): {registrationTime: 1}
                            }
                        )
                    ]
                    [
                        "one built, one fetched"
                        (invalid $OUT $LOG)
                        (
                            path-info {
                                ($OUT): (built-info 1)
                                ($LOG): (fetched-info 1)
                            }
                        )
                    ]
                ] {
                    assert equal (observed-realisation $outputs $case.1 $case.2) {realised: unknown, at: null} $case.0
                }
            }
        }
        {
            name: "a Nix that knows --json-format is asked for format 1, once, and has nothing to warn of"
            body: {
                let r = records-with new
                assert equal $r.calls [$"path-info --json --json-format 1 ($OUT) ($LOG)"]
                assert (not ($r.result.stderr | str contains "deprecated")) $r.result.stderr
                assert equal (observed-realisation $outputs (invalid $OUT $LOG) $r.result) {
                    realised: built
                    at: "2025-11-11T19:40:05+00:00"
                }
            }
        }
        {
            name: "a Nix that does not know it, as 2.18 does not, is asked again with bare --json, and read"
            body: {
                let r = records-with old
                assert equal $r.calls [
                    $"path-info --json --json-format 1 ($OUT) ($LOG)"
                    $"path-info --json ($OUT) ($LOG)"
                ]
                assert equal (observed-realisation $outputs (invalid $OUT $LOG) $r.result) {
                    realised: built
                    at: "2025-11-11T19:40:05+00:00"
                }
            }
        }
        {
            name: "a Nix that fails both ways leaves the realisation unknown"
            body: {
                let r = records-with broken
                assert not equal $r.result.exit_code 0
                assert equal (observed-realisation $outputs (invalid $OUT $LOG) $r.result) {realised: unknown, at: null}
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
