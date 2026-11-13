#!/usr/bin/env nu

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

# infra/flux.nu
#
# Flux, for a target that deploys with it. The controllers are rendered into the repository like everything
# else, so they are reviewed, signed and rolled back the same way:
#
#   nu infra/flux.nu export    regenerate the controllers' YAML from the pinned fluxcd
#   nu infra/flux.nu install <target> [--port N]
#                              put Flux on the cluster and point it at the target's deployment repository, which runs in the
#                              cluster (infra/deploy-repo.nu ensure): Flux reaches it by its Service
#   nu infra/flux.nu wait <target> [--port N] [--timeout 20min]
#                              wait until every layer is Ready at the commit that was published
#
# The version is whatever `fluxcd` the repository's pinned nixpkgs provides: bump nixpkgs and run `export`,
# then mirror the new controller images (infra/images.nuon) and read the diff. Only the two controllers a
# git-sourced deployment needs are installed: source-controller and kustomize-controller. The file is
# generated and committed; `render` copies it, pointing the images at the registry the nodes pull from.

use deploy-repo.nu [DEFAULT_PORT, READER, ensure_signing, pki_dir, repo_name, tls_config]
use deploy-objects.nu [AUTH_SECRET, FLUX_NS, POLAR_AUTH_SECRET, SOURCE_NAME, is_handed_off, polar_git_repository]
use seed.nu [GIT_HOST, GIT_PORT]
use retry.nu [with_retries]

const CHART = (path self | path dirname | path join "layers" "1-platform" "services" "flux")
const SELF = (path self)
const OUT = (path self | path dirname | path join "layers" "1-platform" "services" "flux" "flux-controllers.yaml")

# The license banner this script itself carries, so the generated file has it too and cannot lose it.
def banner [] {
    let lines = (open --raw $SELF | lines)
    let start = ($lines | enumerate | where {|r| $r.item | str starts-with "# ACE Tool" } | first | get index)
    let end = ($lines | enumerate | where {|r| $r.item | str contains "DM26-0670" } | first | get index)
    $lines | skip $start | first ($end - $start + 1) | str join "\n"
}

# The controllers' manifests, as `flux install --export` prints them, under the banner and a header that says what they are.
# How often a layer asks again whether the one it depends on is ready. Flux's default, 30 s, was most of a rollout: on u7c, 2026-11-02, a commit
# that changed no pod took 183 s, 150 of them this, and 77 s at 5 s (docs/architecture/cluster-bootstrap.md, "A rollout is mostly waiting").
export const REQUEUE_DEPENDENCY = "5s"

# The controllers' YAML with the kustomize-controller told to ask again that often. An export that has lost the flag's place stops here, since it would otherwise go
# unnoticed as a slow cluster.
export def with_requeue [text: string] {
    let docs = ($text | split row "\n---\n")
    let flag = "        - --log-encoding=json\n"
    mut done = false
    mut out = []
    for doc in $docs {
        if ($doc =~ '(?m)^kind: Deployment$') and ($doc =~ '(?m)^  name: kustomize-controller$') and ($doc | str contains $flag) {
            $out = ($out | append ($doc | str replace $flag $"($flag)        - --requeue-dependency=($REQUEUE_DEPENDENCY)\n"))
            $done = true
        } else {
            $out = ($out | append $doc)
        }
    }
    if not $done { error make --unspanned { msg: "the export has no kustomize-controller Deployment with --log-encoding to put the requeue flag after" } }
    $out | str join "\n---\n"
}

# The arguments to kubectl that ask the source to read the repository now, rather than at its next poll. The annotation must change for Flux to act on it.
export def reconcile_request [namespace: string, source: string, at: string] {
    ["-n" $namespace "annotate" "--overwrite" "gitrepository" $source $"reconcile.fluxcd.io/requestedAt=($at)"]
}

export def controllers_yaml [] {
    let repo = (^git rev-parse --show-toplevel | str trim)
    let version = (^nix eval --raw --inputs-from $repo nixpkgs#fluxcd.version | str trim)
    let exported = (do {
        ^nix run --inputs-from $repo nixpkgs#fluxcd -- install --export --components=source-controller,kustomize-controller --namespace=flux-system
    } | complete)
    if $exported.exit_code != 0 {
        error make --unspanned { msg: $"flux install --export failed: ($exported.stderr | lines | last 5 | str join ' | ')" }
    }
    with_requeue ($"(banner)\n\n# Generated by `nu infra/flux.nu export` from fluxcd ($version): do not edit. Flux's source-controller and\n# kustomize-controller, with the CRDs they need. The images are pointed at the node registry when rendered.\n($exported.stdout)")
}

def "main export" [] {
    let text = (controllers_yaml)
    $text | save --force $OUT
    let images = ($text | lines | where {|l| $l =~ '^\s+image:' } | each {|l| $l | str trim } | uniq)
    print $"wrote ($OUT | path basename): ($text | lines | length) lines"
    for i in $images { print $"  ($i)" }
}

# ---- install and wait --------------------------------------------------------------------------------------------

# "main@sha1:abc..." -> "abc..."
export def commit_of_revision [revision: string] {
    $revision | split row ":" | last
}

# Where each Kustomization stands, given what `kubectl get kustomizations -o json` listed and the commit that was published.
export def layer_states [items: list, commit: string] {
    $items | each {|k|
        let ready = ($k.status?.conditions? | default [] | where type == "Ready" | default [{}] | first)
        let applied = ($k.status?.lastAppliedRevision? | default "")
        {
            name: $k.metadata.name
            ready: (($ready | get -o status | default "") == "True")
            reason: ($ready | get -o reason | default "")
            message: ($ready | get -o message | default "")
            applied: $applied
            current: (($applied | is-not-empty) and ($applied | str ends-with $commit))
        }
    }
}

# The Kustomizations of Polar's layers in the cluster (`present`, their names) that what was just published (`published`) no longer
# names: a layer taken out of the target, or a configuration under test the cluster no longer carries. Left in place, one fails
# ("kustomization path not found") and holds the wait for ever, and prunes nothing; deleted, Flux prunes what it applied, as
# for any object no longer rendered, and a claim keeps its data (deploy-objects.nu, protect_claims).
export def dropped_layers [present: list<string>, published: list<string>] {
    $present | where {|n| ($n | str starts-with "polar-") and $n not-in $published } | sort
}

# The names of the Kustomizations in a published `flux/kustomizations.yaml`, as deploy-objects.nu's `yaml_docs` writes it.
export def published_layers [text: string] {
    $text | split row "\n---\n" | each {|d| $d | from yaml } | compact | where {|d| ($d.kind? | default "") == "Kustomization" } | each {|d| $d.metadata.name }
}

# Every layer is Ready and applied from the published commit (and there is at least one).
export def settled [states: list] {
    ($states | is-not-empty) and ($states | all {|s| $s.ready and $s.current })
}

export def describe_state [s: record] {
    let state = if $s.ready and $s.current { "ready" } else if $s.ready { $"ready, but at ($s.applied)" } else { $s.reason }
    let note = ($s.message | lines | first | default "" | str substring 0..160)
    if ($note | is-empty) { $"($s.name): ($state)" } else { $"($s.name): ($state) -- ($note)" }
}

# How long a reconcile may sit in a health-check wait begun under a spec or revision that has since been replaced before `wait` restarts the
# controller. A hand-over between two reconciles takes seconds; this is long enough not to mistake one for the other.
export const STALE_AFTER = 15sec
export const MAX_RESTARTS = 3

# "Running health checks for revision main@sha1:abc with a timeout of 10m0s" -> "main@sha1:abc", or null.
export def revision_waited_on [message: string] {
    let found = ($message | parse --regex 'for revision (?<rev>\S+)')
    if ($found | is-empty) { null } else { $found | first | get rev }
}

# The Kustomizations whose reconcile is waiting on a health check that was begun under an older spec (the condition records the generation it
# started under) or an older revision than the current ones. Flux finishes a reconcile under the spec it began with, so the wait runs out its
# whole timeout (ten minutes) before the new spec or revision is read; a restart of the controller ends it.
export def stale_waits [items: list, commit: string] {
    $items | where {|k|
        let reconciling = ($k.status?.conditions? | default [] | where type == "Reconciling" and status == "True")
        if ($reconciling | is-empty) { return false }
        let c = ($reconciling | first)
        let message = ($c | get -o message | default "")
        if not ($message | str contains "Running health checks") { return false }
        let spec_moved = (($c | get -o observedGeneration | default 0) < ($k.metadata.generation? | default 0))
        let rev = (revision_waited_on $message)
        let revision_moved = ($rev != null and not ($rev | str ends-with $commit))
        $spec_moved or $revision_moved
    } | each {|k| $k.metadata.name }
}

# When each currently stale Kustomization was first seen stale: kept from `since` for the ones that still are, `now` for new ones.
export def track_stale [since: record, stale: list<string>, now: datetime] {
    $stale | reduce --fold {} {|n, acc| $acc | insert $n ($since | get -o $n | default $now) }
}

# The ones that have been stale for `after` or longer.
export def due_stale [since: record, now: datetime, after: duration] {
    $since | transpose name at | where {|r| ($now - $r.at) >= $after } | get name
}

def run_ok [what: string, cmd: closure] {
    let r = (do $cmd | complete)
    if $r.exit_code != 0 { error make --unspanned { msg: $"($what) failed: ($r.stderr | str trim)" } }
    $r.stdout
}

def load_config [target: string] {
    let file = ($env.PWD | path join $"infra/targets/($target)/target.nu")
    if not ($file | path exists) { error make --unspanned { msg: $"no such target: ($target)" } }
    ^$nu.current-exe $file | from nuon
}

def server_url [target: string, port: int, handed_off: bool = false] {
    if $handed_off { $"https://($GIT_HOST):($GIT_PORT)/deployment.git" } else { $"https://localhost:($port)/(repo_name $target).git" }
}

# Polar's CA as the cluster holds it, in a file beside the PKI, which is what to trust Polar's git server with.
def polar_ca_file [pki: string] {
    let file = ($pki | path join "polar-ca.pem")
    ^kubectl -n polar get configmap polar-ca -o 'jsonpath={.data.ca\.pem}' | save --force $file
    $file
}

def git_as_reader [pki: string, args: list<string>, handed_off: bool = false] {
    let tls = if $handed_off {
        [
            "-c" $"http.sslCAInfo=(polar_ca_file $pki)"
            "-c" $"http.sslCert=($pki | path join $'($READER).pem')"
            "-c" $"http.sslKey=($pki | path join $'($READER).key')"
            "-c" $"http.curloptResolve=($GIT_HOST):($GIT_PORT):127.0.0.1"
        ]
    } else {
        tls_config $pki $READER
    }
    ^env -u GIT_SSL_CAINFO -u SSL_CERT_FILE git ...$tls ...$args
}

# Whether this cluster's Flux reads Polar's git server, from the cluster itself: this machine's record of it can be another cluster's, or gone.
export def cluster_handed_off [] {
    let r = (do { ^kubectl -n $FLUX_NS get gitrepository $SOURCE_NAME -o 'jsonpath={.spec.url}' } | complete)
    $r.exit_code == 0 and (is_handed_off ($r.stdout | str trim))
}

# Flux's credentials for Polar's git server: its certificate of the deployment PKI, and Polar's CA.
def apply_polar_auth [pki: string] {
    let secret = (run_ok "building the credentials Secret" {
        ^kubectl -n $FLUX_NS create secret generic $POLAR_AUTH_SECRET $"--from-file=tls.crt=($pki | path join $'($READER).pem')" $"--from-file=tls.key=($pki | path join $'($READER).key')" $"--from-file=ca.crt=(polar_ca_file $pki)" --dry-run=client -o yaml
    })
    let applied = ($secret | do { ^kubectl apply -f - } | complete)
    if $applied.exit_code != 0 { error make --unspanned { msg: "applying the credentials Secret failed" } }
}

# What the head of the deployment on Polar's git server, verified, records of the cluster's inputs, as JSON on the last line.
def "main recorded-inputs" [target: string, --port: int = 9443] {
    let pki = (pki_dir $env.HOME $target)
    let work = (mktemp -d)
    let copy = ($work | path join "repo")
    let fact = (try { fetch_verified $pki $target $port $copy true; open ($copy | path join "provenance.json") | get -o cluster_inputs } catch {|e| rm -rf $work; error make --unspanned { msg: $e.msg } })
    rm -rf $work
    print ($fact | to json --raw)
}

# Waits until the copy on Polar's git server holds what the bootstrap repository does (up.nu has just pushed it, `deploy-repo.nu copy`). Only this machine publishes, so what it waits for holds still.
def "main copied" [target: string, --port: int = 9443] {
    let pki = (pki_dir $env.HOME $target)
    let head = (published_commit $pki $target $port)
    if $head == null { error make --unspanned { msg: $"nothing is published to deploy-($target)" } }
    let caught_up = (with_retries 60 5sec {|n|
        let copy = (try { published_commit $pki $target $port true } catch {|e| $e.msg })
        { ok: ($copy == $head), final: false, detail: $"it answered ($copy | default 'with no commit')" }
    })
    if not $caught_up.ok { error make --unspanned { msg: $"the copy on Polar's git server did not reach ($head | str substring 0..11) after ($caught_up.tries) tries: ($caught_up.detail). Copy it again: nu infra/deploy-repo.nu copy ($target) --as <administrator>" } }
    print $"  ok: Polar's git server holds ($head | str substring 0..11), as the bootstrap repository does"
}

# Moves Flux to the copy on Polar's git server, which must hold what it reads now. Ready alone says nothing until the controller has seen this spec: the condition is still the old URL's.
def "main switch" [target: string] {
    let pki = (pki_dir $env.HOME $target)
    apply_polar_auth $pki
    let applied = (polar_git_repository $GIT_HOST ($GIT_PORT | into int) | to json | do { ^kubectl apply -f - } | complete)
    if $applied.exit_code != 0 { error make --unspanned { msg: $"applying the source failed: ($applied.stderr | str trim)" } }
    do { ^kubectl ...(reconcile_request $FLUX_NS $SOURCE_NAME (date now | format date "%+")) } | complete | ignore
    let reading = (with_retries 36 5sec {|n|
        let got = (do { ^kubectl -n $FLUX_NS get gitrepository $SOURCE_NAME -o json } | complete)
        let source = (try { $got.stdout | from json } catch { {} })
        let ready = ($source.status?.conditions? | default [] | where type == "Ready" | get -o 0)
        { ok: (($source.status?.observedGeneration? | default 0) == ($source.metadata?.generation? | default (-1)) and $ready.status? == "True"), final: false, detail: ($ready.message? | default "no condition yet") }
    })
    if not $reading.ok { error make --unspanned { msg: $"Flux did not read Polar's git server after ($reading.tries) tries: ($reading.detail)" } }
    print "  ok: Flux reads the deployment from Polar's git server"
}

# The commit the deployment repository's main branch is at, or null when nothing is published.
def published_commit [pki: string, target: string, port: int, handed_off: bool = false] {
    # Polar's git server is one of the things a rollout replaces, and it is reached through a forward.
    let read = (with_retries (if $handed_off { 6 } else { 1 }) 5sec {|n|
        let r = (do { git_as_reader $pki [ls-remote (server_url $target $port $handed_off) refs/heads/main] $handed_off } | complete)
        { ok: ($r.exit_code == 0), final: false, detail: (if $r.exit_code == 0 { $r.stdout } else { $r.stderr }) }
    })
    if not $read.ok { error make --unspanned { msg: $"cannot read the deployment repository (is it running? nu infra/deploy-repo.nu ensure ($target)): ($read.detail | str trim)" } }
    let line = ($read.detail | lines | where {|l| $l | str contains "refs/heads/main" })
    if ($line | is-empty) { null } else { $line | first | split row "\t" | first | str trim }
}

# Clones the deployment repository as the reader and checks that its head is signed by the pipeline's certificate, which
# chains to the deployment CA. Nothing is applied from a tree that does not pass.
def fetch_verified [pki: string, target: string, port: int, into: string, handed_off: bool = false] {
    let commit = (published_commit $pki $target $port $handed_off)
    if $commit == null { error make --unspanned { msg: $"nothing is published to deploy-($target): run nu infra/deploy-repo.nu publish ($target)" } }
    let signing = (ensure_signing $pki)
    run_ok "cloning the deployment repository" { git_as_reader $pki [clone -q (server_url $target $port $handed_off) $into] $handed_off }
    let verified = (with-env { GNUPGHOME: $signing.home } {
        let r = (do { ^git -C $into -c gpg.format=x509 -c gpg.x509.program=gpgsm verify-commit HEAD } | complete)
        do { ^gpgconf --kill gpg-agent } | complete | ignore
        $r
    })
    if $verified.exit_code != 0 {
        error make --unspanned { msg: $"the head of deploy-($target) is not signed by the pipeline's certificate, so nothing from it is applied: ($verified.stderr | str trim | if ($in | is-empty) { 'the commit carries no signature' } else { $in })" }
    }
    $commit
}

def "main install" [
    target: string
    --port: int = 9443          # this machine's end of the forward to the deployment git server
    --handed-off                # the deployment is on Polar's git server
] {
    let config = (load_config $target)
    let pki = (pki_dir $env.HOME $target)
    if not ($pki | path join "ca.pem" | path exists) { error make --unspanned { msg: $"no deployment PKI at ($pki): run: nu infra/deploy-repo.nu ensure ($target)" } }
    let controllers = ($config.output_dir | path join "flux-controllers.yaml")
    if not ($controllers | path exists) { error make --unspanned { msg: $"no rendered ($controllers): run: nu infra/render.nu ($target)" } }

    # Before anything touches the cluster: the published tree is the one the pipeline signed.
    let work = (mktemp -d)
    let copy = ($work | path join "repo")
    let commit = (try { fetch_verified $pki $target $port $copy $handed_off } catch {|e| rm -rf $work; error make --unspanned { msg: $e.msg } })
    print $"  ok: deploy-($target) at ($commit | str substring 0..11) is signed by the pipeline's certificate"
    let objects = ["gitrepository.yaml" "kustomizations.yaml"] | each {|f| $copy | path join "flux" $f }
    for f in $objects { if not ($f | path exists) { rm -rf $work; error make --unspanned { msg: $"the published tree has no ($f | path relative-to $copy)" } } }

    print "  applying Flux's controllers..."
    run_ok "applying the controllers" { ^kubectl apply -f $controllers } | print
    run_ok "waiting for Flux's CRDs" { ^kubectl wait --for=condition=Established --timeout=120s crd/gitrepositories.source.toolkit.fluxcd.io crd/kustomizations.kustomize.toolkit.fluxcd.io } | ignore
    run_ok "waiting for Flux's controllers" { ^kubectl -n $FLUX_NS rollout status deploy/source-controller deploy/kustomize-controller --timeout=300s } | ignore
    print "  ok: source-controller and kustomize-controller are running"

    # The `flux` identity's certificate and key, and the CA of the server it reads, are what Flux presents and trusts. They go
    # from the files into the Secret without being printed or written anywhere else.
    if $handed_off {
        apply_polar_auth $pki
        print $"  ok: secret/($POLAR_AUTH_SECRET) holds the ($READER) identity"
    } else {
        let secret = (run_ok "building the credentials Secret" {
            ^kubectl -n $FLUX_NS create secret generic $AUTH_SECRET $"--from-file=tls.crt=($pki | path join $'($READER).pem')" $"--from-file=tls.key=($pki | path join $'($READER).key')" $"--from-file=ca.crt=($pki | path join 'ca.pem')" --dry-run=client -o yaml
        })
        let applied = ($secret | do { ^kubectl apply -f - } | complete)
        if $applied.exit_code != 0 { rm -rf $work; error make --unspanned { msg: "applying the credentials Secret failed" } }
        print $"  ok: secret/($AUTH_SECRET) holds the ($READER) identity"
    }

    # The source first, and wait until Flux has fetched the repository: Kustomizations applied before that report
    # "Source artifact not found" and retry after 30 seconds.
    let source = ($objects | first)
    run_ok $"applying ($source | path basename)" { ^kubectl apply -f $source } | print
    run_ok "waiting for Flux to fetch the deployment repository" { ^kubectl -n $FLUX_NS wait --for=condition=Ready --timeout=180s $"gitrepository/($SOURCE_NAME)" } | ignore
    print "  ok: Flux has fetched the deployment repository"
    for f in ($objects | skip 1) { run_ok $"applying ($f | path basename)" { ^kubectl apply -f $f } | print }
    let published = (published_layers (open --raw ($objects | last)))
    let present = (run_ok "listing the Kustomizations" { ^kubectl -n $FLUX_NS get kustomizations.kustomize.toolkit.fluxcd.io -o jsonpath='{.items[*].metadata.name}' } | split row " " | where {|n| $n | is-not-empty })
    for gone in (dropped_layers $present $published) {
        run_ok $"deleting ($gone), a layer no longer published" { ^kubectl -n $FLUX_NS delete kustomization $gone --timeout=300s } | print
    }
    rm -rf $work
    print $"  ok: Flux reconciles the layers of deploy-($target) from ($commit | str substring 0..11); next: nu infra/flux.nu wait ($target)"
}

def "main wait" [
    target: string
    --port: int = 9443
    --timeout: duration = 20min
    --handed-off                # the deployment is on Polar's git server
] {
    let pki = (pki_dir $env.HOME $target)
    let commit = (published_commit $pki $target $port $handed_off)
    if $commit == null { error make --unspanned { msg: $"nothing is published to deploy-($target)" } }
    print $"  waiting for every layer to be Ready at ($commit | str substring 0..11)..."
    # What was just published need not wait for the source's next poll. If this fails, it only means waiting for that poll.
    let asked = (do { ^kubectl ...(reconcile_request $FLUX_NS $SOURCE_NAME (date now | format date "%+")) } | complete)
    if $asked.exit_code != 0 { print "  -- could not ask the source to look now: it will at its next poll" }
    let deadline = ((date now) + $timeout)
    mut seen = ""
    mut states = []
    mut stale_since = {}
    mut restarts = 0
    loop {
        let got = (do { ^kubectl -n $FLUX_NS get kustomizations.kustomize.toolkit.fluxcd.io -o json } | complete)
        if $got.exit_code == 0 {
            let items = ($got.stdout | from json | get items)
            $states = (layer_states $items $commit)
            let lines = ($states | each {|s| describe_state $s })
            let shown = ($lines | str join "\n")
            if $shown != $seen {
                for l in $lines { print $"    ($l)" }
                print ""
                $seen = $shown
            }
            if (settled $states) { break }

            $stale_since = (track_stale $stale_since (stale_waits $items $commit) (date now))
            let due = (due_stale $stale_since (date now) $STALE_AFTER)
            if ($due | is-not-empty) and $restarts < $MAX_RESTARTS {
                print $"  -- ($due | str join ', ') has been waiting on a health check begun under an older spec or revision; restarting kustomize-controller so it reads the current one"
                run_ok "restarting kustomize-controller" { ^kubectl -n $FLUX_NS rollout restart deploy/kustomize-controller } | ignore
                run_ok "waiting for kustomize-controller" { ^kubectl -n $FLUX_NS rollout status deploy/kustomize-controller --timeout=120s } | ignore
                $restarts = $restarts + 1
                $stale_since = {}
            }
        }
        if (date now) > $deadline {
            let stuck = ($states | where {|s| not ($s.ready and $s.current) } | each {|s| describe_state $s })
            error make --unspanned { msg: $"not every layer was Ready at ($commit | str substring 0..11) after ($timeout): ($stuck | str join '; '). See: kubectl -n ($FLUX_NS) get kustomizations" }
        }
        sleep 5sec
    }
    print $"  ok: all ($states | length) layers are Ready at ($commit | str substring 0..11)"
}

def main [] {
    print "usage: nu infra/flux.nu export | install <target> [--port N] | wait <target> [--port N] [--timeout 20min]"
}
