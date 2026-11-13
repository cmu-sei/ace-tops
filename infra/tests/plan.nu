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

# infra/tests/up.nu
#
# Tests of what up.nu (infra/plan.nu) decides to run for a target.
#
#   nu infra/tests/up.nu

use std/assert
use ../plan.nu [build_forwards, build_plan, deployed_charts, needs_runtime, plan_secrets, secret_lines]

def config [charts: list, order: list] {
    { charts: ($charts | each {|c| $"/layers/x/($c)/main.nu" }), apply_order: $order, cert_issuer_ca_configmap: "polar-ca" }
}

def on [plan: list, id: string] {
    $plan | where id == $id | first | get on
}

def main [] {
    let tests = [
        {
            # The plan names every Secret a run makes, where each comes from, and never a value (the port's review, step A).
            name: "the plan names each Secret its steps make and where it comes from, and never a value"
            body: {
                let target = [
                    { namespace: "polar", name: "polar-graph-pw", from: { sops: ["graph_password"] } }
                    { namespace: "polar", name: "cassini-shutdown-token", from: { generated: "token" } }
                ]
                let c = (config ["cert-issuer" "neo4j"] ["namespaces.yaml" "credentials-agent.yaml" "polar-git-server.yaml" "polar-scheduler-observer.yaml"] | insert gitops true)
                let secrets = (plan_secrets (build_plan $c false) $target)
                let named = ($secrets | each {|s| $"($s.namespace)/($s.name)" })
                for expected in ["polar/cert-issuer-ca" "polar/polar-graph-pw" "polar/cassini-shutdown-token" "polar-deploy/polar-deploy-git-tls" "flux-system/deploy-repo-auth"] {
                    assert ($expected in $named) $"($expected) in ($named)"
                }
                # No agent copies the deployment, so none is given a key of the deployment PKI (runtime-attestation.md, C2, O3).
                assert (not ("polar/deployment-reader" in $named)) ($named | to nuon)
                # Handed off, Flux reads Polar's git server with another Secret, and there is no deployment git server.
                let handed = ($c | insert handed_off true)
                let named_after = (plan_secrets (build_plan $c false { handed_off: true }) $target | each {|s| $"($s.namespace)/($s.name)" })
                assert ("flux-system/deployment-auth" in $named_after) ($named_after | to nuon)
                assert ("polar-deploy/polar-deploy-git-tls" not-in $named_after)
                # A step that does not run makes none.
                let direct = (config ["neo4j"] ["namespaces.yaml"])
                let few = (plan_secrets (build_plan $direct false) $target | each {|s| $"($s.namespace)/($s.name)" })
                assert ("polar/cert-issuer-ca" not-in $few)
                assert ("flux-system/deploy-repo-auth" not-in $few)
                assert ("polar/polar-graph-pw" in $few)
                let lines = (secret_lines $secrets | str join "\n")
                assert ($lines | str contains "polar/polar-graph-pw")
                assert ($lines | str contains "graph_password")
                assert ($lines | str contains "generated once")
                assert ($lines | str contains "no value is shown")
            }
        }
        {
            name: "a target declares its Secrets as data, each with where it comes from and no value"
            body: {
                let declared = (^$nu.current-exe ($env.FILE_PWD | path join "../targets/sandbox-local/secrets.nu") declared | from json)
                assert equal ($declared | each {|s| $"($s.namespace)/($s.name)" } | sort) [
                    "polar-graph/neo4j-secret" "polar/cassini-shutdown-token" "polar/polar-graph-pw"
                ]
                assert equal ($declared | where name == "neo4j-secret" | first | get from.sops) ["neo4j_auth"]
                assert equal ($declared | where name == "cassini-shutdown-token" | first | get from.generated) "token"
                for s in $declared { assert ("value" not-in ($s | columns)) }
            }
        }
        {
            name: "a workload that is in the apply order but not among the charts is deployed"
            body: {
                let c = (config ["cert-issuer" "neo4j"] ["namespaces.yaml" "credentials-agent-resources.yaml" "credentials-agent.yaml" "polar-git-server.yaml"])
                let d = (deployed_charts $c)
                assert ("credentials-agent" in $d)
                assert ("polar-git-server" in $d)
                assert ("cert-issuer" in $d)
            }
        }
        {
            name: "a cluster handed off to Polar's git server has no deployment git server to run, and publishes through a forward to Polar's"
            body: {
                let c = (config ["cert-issuer" "neo4j"] ["namespaces.yaml" "credentials-agent.yaml" "polar-git-server.yaml" "polar-scheduler-observer.yaml"] | insert gitops true)
                let on = {|plan, id| $plan | where id == $id | first | get on }
                let before = (build_plan $c false)
                assert (do $on $before "deploy-host")
                assert (not (do $on $before "deployment-forward"))
                assert (do $on $before "handoff") "a new cluster is handed off at the end of its bring-up"
                let after = (build_plan $c false { handed_off: true })
                assert (not (do $on $after "deploy-host"))
                assert (do $on $after "deployment-forward")
                assert (do $on $after "publish")
                assert (do $on $after "handoff") "what is left of the bootstrap is removed, on any run"
                let ids = ($after | get id)
                let at = {|id| $ids | enumerate | where item == $id | first | get index }
                assert ((do $at "deployment-forward") < (do $at "publish"))
                assert ((do $at "seed") < (do $at "handoff"))
                # --bootstrap-again, to recover: it runs the bootstrap server and hands nothing off in that run.
                let recovering = (build_plan $c false { bootstrap_again: true })
                assert (do $on $recovering "deploy-host")
                assert (not (do $on $recovering "handoff"))
            }
        }
        {
            # docs/architecture/configurations-under-test.md, CT3: what needs a configuration under test running, after Flux has it.
            name: "a cluster carrying a configuration under test runs its steps once Flux has it, and one carrying none skips them"
            body: {
                let c = (config ["cert-issuer" "neo4j"] ["namespaces.yaml" "credentials-agent.yaml" "polar-git-server.yaml" "polar-scheduler-observer.yaml"] | insert gitops true)
                let on = {|plan, id| $plan | where id == $id | first | get on }
                assert (not (do $on (build_plan $c false) "under-test"))
                let carrying = (build_plan $c false { under_test: ["gitlab"] })
                assert (do $on $carrying "under-test")
                let ids = ($carrying | get id)
                let at = {|id| $ids | enumerate | where item == $id | first | get index }
                assert ((do $at "flux-wait") < (do $at "under-test"))
                assert ((do $at "pods") < (do $at "under-test"))
            }
        }
        {
            name: "a container runtime is needed here only to build images (--dev) with the registry on this machine"
            body: {
                let c = (config ["cert-issuer" "neo4j"] ["namespaces.yaml" "credentials-agent.yaml" "polar-git-server.yaml"])
                assert (not (needs_runtime (build_plan $c false))) "applying prebuilt images asks the agents on the cluster"
                assert (needs_runtime (build_plan $c true)) "--dev starts the registry"
                assert (not (needs_runtime (build_plan ($c | insert gitops true) false))) "the deployment git server runs in the cluster"
            }
        }
        {
            name: "a registry in the cluster comes before the images, the images before the render, and building them then needs no runtime here"
            body: {
                let c = (config ["cert-issuer" "neo4j"] ["namespaces.yaml" "credentials-agent.yaml" "polar-git-server.yaml"])
                let ids = (build_plan $c true { in_cluster: true, import_from: "docker.io/acme" } | where on | get id)
                let at = {|id| $ids | enumerate | where item == $id | first | get index }
                assert ((do $at "registry") < (do $at "images"))
                assert ((do $at "images") < (do $at "render"))
                assert (($ids | where $it == "images" | length) == 1) "one images step, whether the images are built or copied"
                assert (on (build_plan $c false { in_cluster: true, import_from: "docker.io/acme" }) "images") "an import is the images step"
                assert (not (needs_runtime (build_plan $c true { in_cluster: true }))) "--dev pushes to the registry in the cluster"
                assert (not (needs_runtime (build_plan ($c | insert gitops true) false { in_cluster: true }))) "a gitops target with its registry in the cluster needs nothing here"
                let plain = (build_plan $c false | where on | get id)
                assert ("registry" not-in $plain)
                assert ("images" not-in $plain) "nothing is built or copied unless asked"
            }
        }
        {
            name: "the admin flow runs when the credentials agent is deployed through the catalog"
            body: {
                let plan = (build_plan (config ["neo4j"] ["namespaces.yaml" "credentials-agent.yaml"]) false)
                assert (on $plan "admin")
                assert (on $plan "browser")
            }
        }
        {
            name: "the seed runs only with the credentials agent, the git server and the scheduler's observer all deployed"
            body: {
                let all = ["namespaces.yaml" "credentials-agent.yaml" "polar-git-server.yaml" "polar-scheduler-observer.yaml"]
                assert (on (build_plan (config [] $all) false) "seed")
                for missing in ["credentials-agent.yaml" "polar-git-server.yaml" "polar-scheduler-observer.yaml"] {
                    let order = ($all | where {|f| $f != $missing })
                    assert (not (on (build_plan (config [] $order) false) "seed")) $"seed ran without ($missing)"
                }
            }
        }
        {
            name: "the seed comes after the admin flow, which makes the account that signs it, and before the browser, which waits for a person"
            body: {
                let plan = (build_plan (config [] ["credentials-agent.yaml" "polar-git-server.yaml" "polar-scheduler-observer.yaml"]) false)
                let ids = ($plan | get id)
                let at = {|id| $ids | enumerate | where item == $id | first | get index }
                assert ((do $at "seed") > (do $at "admin"))
                let full = (build_plan (config ["neo4j"] ["credentials-agent.yaml" "polar-git-server.yaml" "polar-scheduler-observer.yaml"]) false | get id)
                assert (($full | enumerate | where item == "seed" | first | get index) < ($full | enumerate | where item == "browser" | first | get index))
            }
        }
        {
            name: "each forward names the namespace and service the Justfile forwards it from"
            body: {
                let c = (config ["neo4j"] ["credentials-agent.yaml" "polar-git-server.yaml" "polar-scheduler-observer.yaml"])
                let justfile = (open --raw ($env.FILE_PWD | path join ".." ".." "Justfile"))
                for f in (build_forwards $c) {
                    assert ($justfile | str contains $"start_pf ($f.name) ") $"($f.name) is a forward the Justfile starts"
                    let line = ($justfile | lines | where {|l| $l | str contains $"start_pf ($f.name) " } | first)
                    let words = ($line | split row --regex '\s+' | where {|w| $w | is-not-empty })
                    assert equal ($words | skip 2 | first 2) [$f.ns $f.svc] $"($f.name): ($line)"
                }
            }
        }
        {
            name: "the git server is port-forwarded when the seed will push to it"
            body: {
                let c = (config [] ["credentials-agent.yaml" "polar-git-server.yaml" "polar-scheduler-observer.yaml"])
                assert ("git" in (build_forwards $c | get name))
                assert ("git" not-in (build_forwards (config [] ["credentials-agent.yaml"]) | get name))
            }
        }
        {
            name: "a target that is not gitops applies its layers itself, and has no deployment host, publish or Flux steps"
            body: {
                let plan = (build_plan (config ["neo4j"] ["namespaces.yaml" "credentials-agent.yaml"]) false)
                assert (on $plan "infra")
                for id in ["secrets" "deploy-host" "publish" "flux" "flux-wait"] { assert (not (on $plan $id)) }
            }
        }
        {
            name: "a gitops target creates its secrets, publishes and waits for Flux in place of applying, and still runs the steps that need workloads"
            body: {
                let c = ((config ["neo4j"] ["namespaces.yaml" "credentials-agent.yaml" "polar-git-server.yaml" "polar-scheduler-observer.yaml"]) | insert gitops true)
                let plan = (build_plan $c false)
                assert (not (on $plan "infra"))
                for id in ["secrets" "deploy-host" "publish" "flux" "flux-wait" "admin" "seed" "browser"] { assert (on $plan $id) }
                # Flux comes after the CA and the secrets it does not own, and the workload steps after Flux
                let order = ($plan | get id)
                assert (($order | enumerate | where item == "ca" | first | get index) < ($order | enumerate | where item == "secrets" | first | get index))
                assert (($order | enumerate | where item == "secrets" | first | get index) < ($order | enumerate | where item == "publish" | first | get index))
                assert (($order | enumerate | where item == "flux-wait" | first | get index) < ($order | enumerate | where item == "admin" | first | get index))
            }
        }
    ]

    let results = ($tests | each {|t|
        let r = (try { do $t.body; null } catch {|e| $e.msg })
        { name: $t.name, error: $r }
    })
    for r in $results {
        if $r.error == null {
            print $"  ok    ($r.name)"
        } else {
            print -e $"  FAIL  ($r.name): ($r.error)"
        }
    }
    let failed = ($results | where error != null | length)
    if $failed > 0 {
        print -e $"($failed) of ($results | length) failed"
        exit 1
    }
    print $"all ($results | length) passed"
}

