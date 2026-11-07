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

# infra/under-test/gitlab/ready.nu
#
# What needs the test GitLab answering (docs/architecture/configurations-under-test.md, CT3), run by up.nu once Flux has its layer
# ready: root's personal access token, for the seed tool and, escrowed, the GitLab observer; the runner, created as root and
# its authentication token given to the runner's Deployment; and the seed's dataset (gitlab-seed). Each is made once, kept in a Secret in the cluster, and never
# printed: the token is made here and goes into the pod on stdin, the runner's comes out on stdout into a Secret on stdin.

use ../../secrets-lib.nu [random_token, secret_exists]
use ../../tools.nu
use main.nu [NAMESPACE, NAME, RUNNER_TOKEN_SECRET, REGISTRY_PORT, names]

# Root's token, which the seed tool reads.
export const ROOT_TOKEN_SECRET = "gitlab-root-token"
# The GitLab observer's: root's too, so it sees everything, and only read_api, so it can change nothing. The seed step seals it into
# the observer's `credentials` section (under-test.nuon, `credentials`).
export const OBSERVER_TOKEN_SECRET = "gitlab-observer-token"
# What the GitLab pair's graph should hold once it has read the seed's dataset (gitlab-seed, docs/architecture/http-observers.md, G4b1).
export const EXPECTED_CONFIGMAP = "gitlab-seed-expected"
const POD = "gitlab-0"
const SCRATCH = "/tmp/polar-under-test"

# Ruby for `gitlab-rails runner`: root's token named `name`, with `scopes`, set to the one in `token_file` (made again if it exists),
# and its file removed.
export def root_token_ruby [token_file: string, name: string = "polar-test", scopes: list<string> = ["api" "read_api" "read_registry"]] {
    let scoped = ($scopes | each {|s| $":($s)" } | str join ", ")
    [
        $"token = File.read\('($token_file)'\).strip"
        $"File.delete\('($token_file)'\)"
        "user = User.find_by_username!('root')"
        $"pat = user.personal_access_tokens.find_by\(name: '($name)'\) || user.personal_access_tokens.build\(name: '($name)', scopes: [($scoped)], expires_at: 300.days.from_now\)"
        "pat.set_token(token)"
        "pat.save!"
    ] | str join "\n"
}

# Ruby for `gitlab-rails runner`: the instance runner `polar-test`, made as root once, its token written to `token_file`.
export def runner_ruby [token_file: string] {
    [
        "user = User.find_by_username!('root')"
        "runner = Ci::Runner.find_by(description: 'polar-test')"
        "if runner.nil?"
        "  made = Ci::Runners::CreateRunnerService.new(user: user, params: { runner_type: 'instance_type', description: 'polar-test', run_untagged: true }).execute"
        "  raise made.message unless made.success?"
        "  runner = made.payload[:runner]"
        "end"
        $"File.write\('($token_file)', runner.token\)"
    ] | str join "\n"
}

def exec_in [stdin: any, ...args: string] {
    let r = ($stdin | do { ^kubectl -n $NAMESPACE exec -i $POD -c $NAME -- ...$args } | complete)
    if $r.exit_code != 0 { error make --unspanned { msg: $"in the test GitLab, ($args | first 2 | str join ' ') failed: ($r.stderr | lines | last 3 | str join '; ')" } }
    $r.stdout
}

# Runs `ruby` with `gitlab-rails runner`, after writing `files` (path -> content) beside it, all on stdin. Rails runs as the `git`
# user, so the scratch directory and what is in it are git's, and no one else's.
def rails [ruby: string, files: record = {}] {
    exec_in null "install" "-d" "-o" "git" "-g" "git" "-m" "700" $SCRATCH | ignore
    let written = ($files | transpose path content | append { path: $"($SCRATCH)/run.rb", content: $ruby })
    for f in $written { exec_in $f.content "sh" "-c" $"umask 077 && cat > ($f.path) && chown git:git ($f.path)" | ignore }
    exec_in null "gitlab-rails" "runner" $"($SCRATCH)/run.rb" | ignore
}

# A Secret in the namespace holding `value` under `key`, through stdin.
def secret_of [name: string, key: string, value: string] {
    let r = ({ apiVersion: "v1", kind: "Secret", metadata: { name: $name, namespace: $NAMESPACE }, type: "Opaque", data: { $key: ($value | encode base64) } }
        | to json | do { ^kubectl apply -f - } | complete)
    if $r.exit_code != 0 { error make --unspanned { msg: $"could not make secret/($name) in ($NAMESPACE): ($r.stderr | str trim)" } }
}

def main [target_dir: string, repo_root: string] {
    # GitLab as the layer last made it: a run that changes its template (a polar-init rebuilt, say) restarts it after Flux has
    # called the layer ready, and the seed would meet it booting (a 502, 2026-11-07 on u7c).
    let rolled = (^kubectl -n $NAMESPACE rollout status $"statefulset/($NAME)" --timeout=20m | complete)
    if $rolled.exit_code != 0 { error make --unspanned { msg: $"the test GitLab did not come up: ($rolled.stderr | str trim)" } }
    # What it wrote into the pod goes however this ends: a token is never left behind.
    try { made } catch {|e|
        try { exec_in null "rm" "-rf" $SCRATCH | ignore }
        error make --unspanned { msg: $e.msg }
    }
    exec_in null "rm" "-rf" $SCRATCH | ignore
    seed $repo_root
}

# A local port forwarded to `remote` on GitLab's Service, for as long as `body` runs; stopped by its own PID however it ends.
def through_forward [remote: int, body: closure] {
    let log = (mktemp)
    let pid = (^bash -c $"kubectl -n ($NAMESPACE) port-forward svc/($NAME) :($remote) > ($log) 2>&1 & echo $!" | str trim | into int)
    let stop = {|| if $pid > 1 { ^kill $pid | complete | ignore }; rm -f $log }
    let port = (try {
        mut found: any = null
        for _ in 1..60 {
            let at = (open --raw $log | parse --regex 'Forwarding from 127\.0\.0\.1:(?<port>\d+)' | get -o 0.port)
            if $at != null { $found = ($at | into int); break }
            sleep 500ms
        }
        if $found == null { error make --unspanned { msg: $"no forward to GitLab: (open --raw $log | str trim)" } }
        $found
    } catch {|e| do $stop; error make --unspanned { msg: $e.msg } })
    let out = (try { do $body $port } catch {|e| do $stop; error make --unspanned { msg: $e.msg } })
    do $stop
    $out
}

# The seed's dataset made in GitLab, what is missing of it, and what the GitLab pair's graph should then hold kept in a ConfigMap: run from
# this machine through forwards to GitLab and its registry, checking their certificate by the cluster's CA under GitLab's own name, root's
# token on stdin; the mirror holds this checkout's `main` (`repo_root`).
def seed [repo_root: string] {
    let ca = (mktemp)
    ^kubectl -n $NAMESPACE get configmap polar-ca -o jsonpath='{.data.ca\.pem}' | save --force $ca
    let token = (^kubectl -n $NAMESPACE get secret $ROOT_TOKEN_SECRET -o jsonpath='{.data.token}' | decode base64 | decode)
    let tool = (tools command "gitlab-seed")
    let r = (try {
        through_forward 443 {|port|
            through_forward $REGISTRY_PORT {|registry|
                $token | do {
                    (^($tool | first) ...($tool | skip 1) make --url $"https://(names | first)" --connect $"127.0.0.1:($port)" --ca $ca
                        --registry-url $"https://(names | first):($REGISTRY_PORT)" --registry-connect $"127.0.0.1:($registry)" --repo $repo_root)
                } | complete
            }
        }
    } catch {|e| rm -f $ca; error make --unspanned { msg: $e.msg } })
    rm -f $ca
    if $r.exit_code != 0 { error make --unspanned { msg: $"the seed failed: ($r.stderr | lines | last 3 | str join '; ')" } }
    for line in ($r.stderr | lines | where {|l| ($l | str starts-with "made ") or ($l | str starts-with "the runner ") }) { print $"  ($line)" }
    let applied = ({ apiVersion: "v1", kind: "ConfigMap", metadata: { name: $EXPECTED_CONFIGMAP, namespace: $NAMESPACE }, data: { "expected.json": $r.stdout } }
        | to json | do { ^kubectl apply -f - } | complete)
    if $applied.exit_code != 0 { error make --unspanned { msg: $"could not keep what the graph should hold: ($applied.stderr | str trim)" } }
    print $"  the seed: what the graph should hold is in configmap/($EXPECTED_CONFIGMAP)"
}

def made [] {
    if (secret_exists $ROOT_TOKEN_SECRET $NAMESPACE) {
        print $"  root's token: secret/($ROOT_TOKEN_SECRET) is there"
    } else {
        let token = $"glpat-(random_token 24)"
        let file = $"($SCRATCH)/root-token"
        rails (root_token_ruby $file) { $file: $token }
        secret_of $ROOT_TOKEN_SECRET "token" $token
        print $"  root's token: made, in secret/($ROOT_TOKEN_SECRET)"
    }
    if (secret_exists $OBSERVER_TOKEN_SECRET $NAMESPACE) {
        print $"  the observer's token: secret/($OBSERVER_TOKEN_SECRET) is there"
    } else {
        let token = $"glpat-(random_token 24)"
        let file = $"($SCRATCH)/observer-token"
        rails (root_token_ruby $file "polar-observer" ["read_api"]) { $file: $token }
        secret_of $OBSERVER_TOKEN_SECRET "token" $token
        print $"  the observer's token: made, read_api only, in secret/($OBSERVER_TOKEN_SECRET)"
    }
    if (secret_exists $RUNNER_TOKEN_SECRET $NAMESPACE) {
        print $"  the runner: secret/($RUNNER_TOKEN_SECRET) is there"
    } else {
        let file = $"($SCRATCH)/runner-token"
        rails (runner_ruby $file)
        let token = (exec_in null "sh" "-c" $"cat ($file) && rm -f ($file)" | str trim)
        if not ($token | str starts-with "glrt-") { error make --unspanned { msg: "the runner's token is not one GitLab makes (glrt-...)" } }
        secret_of $RUNNER_TOKEN_SECRET "token" $token
        print $"  the runner: registered, its token in secret/($RUNNER_TOKEN_SECRET)"
    }
}
