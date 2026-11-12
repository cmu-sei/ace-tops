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

# infra/way-back.nu
#
# What a run says when it cannot reach Polar's git server after the handoff (docs/architecture/cluster-bootstrap.md, "A build
# that stops what publishing needs"). A build that stops the server, or what the server needs to start, blocks its own fix:
# Flux says what it broke, and the way back is a bootstrap server brought up from this machine's mirror (`up.nu
# --bootstrap-again`). A run never takes it by itself: moving Flux's source is a person's decision. Kept apart from kubectl
# so it can be tested (infra/tests/way-back.nu).

use deploy-objects.nu [FLUX_NS]

# Reasons a Kustomization gives while it waits, on another or on its own reconcile: not what broke.
const WAITING = ["DependencyNotReady" "Progressing" ""]

# The Kustomizations Flux reports failed, from what `kubectl get kustomizations -o json` listed: each with its reason and the first
# line of its message.
export def failed_layers [items: list] {
    $items | each {|k|
        let ready = ($k.status?.conditions? | default [] | where type == "Ready" | get -o 0 | default {})
        {
            name: $k.metadata.name
            status: ($ready | get -o status | default "")
            reason: ($ready | get -o reason | default "")
            message: ($ready | get -o message | default "" | lines | get -o 0 | default "" | str substring 0..160)
        }
    } | where {|l| $l.status == "False" and $l.reason not-in $WAITING } | reject status
}

# What a run says after `cause`, which is that the server could not be reached: what Flux reports failed and the way back; that
# nothing failed, so the server is down for another reason; or, `failed` null, that Flux could not be asked.
export def way_back [target: string, failed: any, cause: string] {
    if $failed == null {
        return $"($cause). Flux could not be asked what failed \(kubectl -n ($FLUX_NS) get kustomizations\); if a build stopped the server: nu infra/up.nu ($target) --bootstrap-again"
    }
    if ($failed | is-empty) {
        return $"($cause). Flux reports no layer failed, so the server is down for another reason: kubectl -n polar get pods -l name=polar-git-server"
    }
    let named = ($failed | each {|l| if ($l.message | is-empty) { $"($l.name): ($l.reason)" } else { $"($l.name): ($l.reason) -- ($l.message)" } } | str join "; ")
    $"($cause). Flux reports what the deployment broke: ($named). Its fix cannot reach a server it stopped; publish it through a bootstrap server from this machine's mirror: nu infra/up.nu ($target) --bootstrap-again \(the next plain run hands off again\)"
}

# `way_back`, asking Flux.
export def why_unreachable [target: string, cause: string] {
    let got = (do { ^kubectl -n $FLUX_NS get kustomizations.kustomize.toolkit.fluxcd.io -o json } | complete)
    let failed = if $got.exit_code == 0 { failed_layers ($got.stdout | from json | get items) } else { null }
    way_back $target $failed $cause
}
