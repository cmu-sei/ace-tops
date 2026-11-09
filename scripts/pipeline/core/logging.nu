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

# Logging module for CI/CD pipeline scripts.
#
# `log-info` / `log-warn` / `log-error` / `log-debug`, each with an optional --component folded into the message, one line
# each: `<date> [<level>] <message>`, coloured by level.
#
# To stdout, where the pipeline's reports go (core/events.nu), and not to stderr as nushell's `std/log` writes: a build's pod
# log is the container's two streams spliced together as the runtime reads them, a piece of one between pieces of the other,
# so a log line on stderr could land inside a long report on stdout and spoil it (found 2026-11-08 rehearsing the watched
# build, docs/architecture/build-orchestrator.md, D4a). On one stream, nu its one writer, each line arrives whole.
#
# `log-debug` is silent unless $env.NU_LOG_LEVEL is "debug" or a number no more than 10, as with `std/log`: its names
# (debug, info, warning, error, critical) or numbers (10 to 50); unset or unknown, info.

const LEVELS = {
    DBG: { rank: 10, colour: "dark_gray" }
    INF: { rank: 20, colour: "default" }
    WRN: { rank: 30, colour: "yellow" }
    ERR: { rank: 40, colour: "red" }
}

def threshold []: nothing -> int {
    let asked = ($env.NU_LOG_LEVEL? | default "" | into string | str trim | str lowercase)
    let named = { debug: 10, info: 20, warning: 30, warn: 30, error: 40, critical: 50 }
    if ($asked in $named) {
        $named | get $asked
    } else {
        try { $asked | into int } catch { 20 }
    }
}

def write [level: string, msg: string, component: string] {
    let at = $LEVELS | get $level
    if $at.rank < (threshold) { return }
    let body = if ($component | is-empty) { $msg } else { $"($component) — ($msg)" }
    print $"(ansi $at.colour)(date now | format date '%Y-%m-%d %H:%M:%S%.3f') [($level)] ($body)(ansi reset)"
}

export def log-info [msg: string, --component: string = ""] {
    write INF $msg $component
}

export def log-warn [msg: string, --component: string = ""] {
    write WRN $msg $component
}

export def log-error [msg: string, --component: string = ""] {
    write ERR $msg $component
}

export def log-debug [msg: string, --component: string = ""] {
    write DBG $msg $component
}
