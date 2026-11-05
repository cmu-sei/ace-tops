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

# Asks a running agent what configuration is in force, with your own certificate
# (docs/architecture/dynamic-settings.md, "Asking an agent what is in force"), and prints what it says as JSON; with
# --template, a file to edit and sign, filled in from it.
#
#   nu infra/running-config.nu jira-observer --user alice
#   nu infra/running-config.nu jira-observer --user alice --template > settings.json
#   just running-config jira-observer alice
#
# It reaches the broker through a port-forward it starts and stops itself, as cassini-shutdown.nu does.

const INFRA = (path self | path dirname)

use tools.nu
use cassini-shutdown.nu [cassini_server_name with_broker_forward]

# What polar-running-config is given.
export def ask_args [agent: string, user: string, dir: string, port: int, server_name: string] {
    [$agent "--user" $user "--dir" $dir "--broker" $"127.0.0.1:($port)" "--server-name" $server_name]
}

# What polar-sign is given to write the file from an answer on standard input.
export def template_args [agent: string, dir: string, scaffold: string] {
    ["template" $agent "--settings" "--running" "-" "--dir" $dir]
    | append (if ($scaffold | is-empty) { [] } else { ["--scaffold" $scaffold] })
}

def main [
    agent: string
    --user: string = ""       # whose certificate to ask with; the current user by default
    --template                # print a file to edit and sign, not the answer
    --scaffold: string = ""   # the agent's scaffold, for --template; ~/.config/polar-admin/scaffolds by default
    --port: int = 18081       # the local end of the forward
    --namespace: string = "polar"
] {
    let user = (if ($user | is-empty) { $env.USER? | default "" } else { $user })
    let dir = ($env.HOME | path join ".config/polar-admin")
    for f in [$"($user).crt" $"($user).key" "ca.pem"] {
        if not ($dir | path join $f | path exists) {
            error make { msg: $"($dir)/($f) is not there: run `just user-cert-install ($user)` or `just admin-claim` first" }
        }
    }
    let name = (cassini_server_name (open ($INFRA | path join "config/services.nuon")) (open ($INFRA | path join "config/cluster.nuon")))
    let asked = (with_broker_forward $namespace $port {
        let t = (tools command "polar-running-config")
        run-external ($t | first) ...($t | skip 1) ...(ask_args $agent $user $dir $port $name) | complete
    })
    if $asked.exit_code != 0 {
        error make { msg: ($asked.stderr | lines | where {|l| not ($l =~ '^(warning|help|\s+(-->|\||=)|\s*[0-9]+ \||\s*$)') } | str join "\n") }
    }
    if not $template { return ($asked.stdout | str trim) }
    let t = (tools command "polar-sign")
    let wrote = ($asked.stdout | run-external ($t | first) ...($t | skip 1) ...(template_args $agent $dir $scaffold) | complete)
    if $wrote.exit_code != 0 {
        error make { msg: ($wrote.stderr | str trim) }
    }
    $wrote.stdout | str trim --right
}
