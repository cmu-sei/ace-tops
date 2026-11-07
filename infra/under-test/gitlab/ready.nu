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
# ready: root's personal access token, for the seed tool and, escrowed, the GitLab observer; and the runner, created as root and
# its authentication token given to the runner's Deployment. Each is made once, kept in a Secret in the cluster, and never
# printed: the token is made here and goes into the pod on stdin, the runner's comes out on stdout into a Secret on stdin.

use ../../secrets-lib.nu [random_token, secret_exists]
use main.nu [NAMESPACE, NAME, RUNNER_TOKEN_SECRET]

# Root's token, which the seed tool and the observer's escrow read.
export const ROOT_TOKEN_SECRET = "gitlab-root-token"
const POD = "gitlab-0"
const SCRATCH = "/tmp/polar-under-test"

# Ruby for `gitlab-rails runner`: root's token set to the one in `token_file` (made again if it exists), and its file removed.
export def root_token_ruby [token_file: string] {
    [
        $"token = File.read\('($token_file)'\).strip"
        $"File.delete\('($token_file)'\)"
        "user = User.find_by_username!('root')"
        "pat = user.personal_access_tokens.find_by(name: 'polar-test') || user.personal_access_tokens.build(name: 'polar-test', scopes: [:api, :read_api, :read_registry], expires_at: 300.days.from_now)"
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

# Runs `ruby` with `gitlab-rails runner`, after writing `files` (path -> content) beside it, all on stdin.
def rails [ruby: string, files: record = {}] {
    exec_in null "mkdir" "-p" "-m" "700" $SCRATCH | ignore
    for f in ($files | transpose path content) { exec_in $f.content "sh" "-c" $"umask 077 && cat > ($f.path)" | ignore }
    exec_in $ruby "sh" "-c" $"umask 077 && cat > ($SCRATCH)/run.rb" | ignore
    exec_in null "gitlab-rails" "runner" $"($SCRATCH)/run.rb" | ignore
}

# A Secret in the namespace holding `value` under `key`, through stdin.
def secret_of [name: string, key: string, value: string] {
    let r = ({ apiVersion: "v1", kind: "Secret", metadata: { name: $name, namespace: $NAMESPACE }, type: "Opaque", data: { $key: ($value | encode base64) } }
        | to json | do { ^kubectl apply -f - } | complete)
    if $r.exit_code != 0 { error make --unspanned { msg: $"could not make secret/($name) in ($NAMESPACE): ($r.stderr | str trim)" } }
}

def main [target_dir: string, repo_root: string] {
    if (secret_exists $ROOT_TOKEN_SECRET $NAMESPACE) {
        print $"  root's token: secret/($ROOT_TOKEN_SECRET) is there"
    } else {
        let token = $"glpat-(random_token 24)"
        let file = $"($SCRATCH)/root-token"
        rails (root_token_ruby $file) { $file: $token }
        secret_of $ROOT_TOKEN_SECRET "token" $token
        print $"  root's token: made, in secret/($ROOT_TOKEN_SECRET)"
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
    exec_in null "rm" "-rf" $SCRATCH | ignore
}
