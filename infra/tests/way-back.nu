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

# Tests for infra/way-back.nu: what a run says when Polar's git server cannot be reached.
#
#   nu infra/tests/way-back.nu

use std/assert
use ../way-back.nu [failed_layers, way_back]

def kustomization [name: string, status: string, reason: string, message: string = ""] {
    { metadata: { name: $name }, status: { conditions: [{ type: "Ready", status: $status, reason: $reason, message: $message }] } }
}

def main [] {
    let tests = [
        {
            name: "a layer is failed when Flux says it is not Ready for a reason other than waiting"
            body: {
                let items = [
                    (kustomization "polar-cert-issuer" "False" "HealthCheckFailed" "health check failed after 1m: [Deployment/polar/cert-issuer status: 'Failed']\nmore")
                    (kustomization "polar-identity" "False" "DependencyNotReady" "dependency 'flux-system/polar-cassini' is not ready")
                    (kustomization "polar-agents" "Unknown" "Progressing" "Reconciliation in progress")
                    (kustomization "polar-core" "True" "ReconciliationSucceeded")
                    (kustomization "polar-graph" "False" "BuildFailed" "")
                    { metadata: { name: "polar-new" } }
                ]
                assert equal (failed_layers $items) [
                    { name: "polar-cert-issuer", reason: "HealthCheckFailed", message: "health check failed after 1m: [Deployment/polar/cert-issuer status: 'Failed']" }
                    { name: "polar-graph", reason: "BuildFailed", message: "" }
                ]
            }
        }
        {
            name: "what Flux reports failed is named, with the way back through a bootstrap server"
            body: {
                let said = (way_back "sandbox-local" [{ name: "polar-cert-issuer", reason: "HealthCheckFailed", message: "Deployment/polar/cert-issuer failed" } { name: "polar-graph", reason: "BuildFailed", message: "" }] "cannot read the deployment repository")
                assert ($said | str starts-with "cannot read the deployment repository. ")
                assert ($said | str contains "polar-cert-issuer: HealthCheckFailed -- Deployment/polar/cert-issuer failed; polar-graph: BuildFailed")
                assert ($said | str contains "nu infra/up.nu sandbox-local --bootstrap-again")
            }
        }
        {
            name: "when Flux reports nothing failed, the run does not suggest bootstrapping again"
            body: {
                let said = (way_back "sandbox-local" [] "cannot read the deployment repository")
                assert ($said | str contains "no layer failed")
                assert not ($said | str contains "--bootstrap-again")
            }
        }
        {
            name: "when Flux cannot be asked, the run says so, and what to run if a build stopped the server"
            body: {
                let said = (way_back "sandbox-local" null "cannot read the deployment repository")
                assert ($said | str contains "could not be asked")
                assert ($said | str contains "nu infra/up.nu sandbox-local --bootstrap-again")
            }
        }
    ]

    let results = ($tests | each {|t|
        try { do $t.body; { name: $t.name, error: null } } catch {|e| { name: $t.name, error: $e.msg } }
    })
    for r in $results {
        if $r.error == null { print $"  ok    ($r.name)" } else { print -e $"  FAIL  ($r.name): ($r.error)" }
    }
    let failed = ($results | where error != null | length)
    if $failed > 0 { print -e $"($failed) of ($results | length) failed"; exit 1 }
    print $"all ($results | length) passed"
}
