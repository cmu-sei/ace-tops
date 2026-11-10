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

# infra/plan.nu
#
# What up.nu decides to run, and what it forwards, for a target. Pure: it reads the target's own config.

# What the target deploys, by name: the chart directories, and the workloads the catalog renders, which
# have no chart and are known by their manifests in the apply order (`<name>.yaml`, and
# `<name>-resources.yaml` for the ones with resources).
export def deployed_charts [config: record] {
    let charts = ($config.charts | each {|c| $c | path dirname | path basename })
    let workloads = ($config.apply_order | each {|f| $f | str replace --regex '(-resources)?\.yaml$' '' })
    $charts | append $workloads | uniq
}

# The plan: one record per step, with whether it runs and why not.
# `options`: `in_cluster`, the target keeps its registry in its cluster (infra/cluster-registry.nu); `import_from`, where the
# published images are copied from (`--import-from`), or "". A step's `runtime` says it starts a container on this machine.
use deploy-objects.nu [AUTH_SECRET, FLUX_NS, POLAR_AUTH_SECRET]
use deploy-repo.nu [NAMESPACE, SERVICE]

# The Secrets the steps of `plan` that run make, each with where it comes from and never a value: the cluster's CA, the target's
# own (`target`, what its secrets.nu declares), the deployment git server's and the configuration agent's certificates of the
# deployment PKI, and Flux's. What a person reviews before a run (the port's review, "a plan's description names every secret").
export def plan_secrets [plan: list, target: list] {
    let on = ($plan | where on | get id)
    let made = {|step, namespace, name, by| { step: $step, namespace: $namespace, name: $name, from: { made: $by } } }
    mut secrets = []
    if "ca" in $on {
        $secrets = ($secrets | append (do $made "ca" "polar" "cert-issuer-ca" "the cluster's CA certificate and key, made once by polar-admin-grant bootstrap-ca and kept"))
    }
    if ("infra" in $on) or ("secrets" in $on) {
        $secrets = ($secrets | append ($target | each {|t| $t | insert step "secrets" }))
    }
    if "deploy-host" in $on {
        $secrets = ($secrets | append [
            (do $made "deploy-host" $NAMESPACE $"($SERVICE)-tls" "the deployment git server's certificate and key, from the deployment PKI on this machine")
            (do $made "deploy-host" "polar" "deployment-reader" "the configuration agent's certificate and key for copying the deployment, from the deployment PKI")
        ])
    }
    if "flux" in $on {
        let name = (if "deployment-forward" in $on { $POLAR_AUTH_SECRET } else { $AUTH_SECRET })
        $secrets = ($secrets | append (do $made "flux" $FLUX_NS $name "Flux's certificate and key of the deployment PKI, and the CA of the server it reads"))
    }
    $secrets
}

# `secrets` as the plan prints them: each by namespace and name, with where it comes from.
export def secret_lines [secrets: list] {
    if ($secrets | is-empty) { return [] }
    let source = {|from|
        if ($from.sops? | default null) != null {
            $"from SOPS: ($from.sops | str join ', ')"
        } else if ($from.generated? | default null) != null {
            $"generated once \(($from.generated)\) and kept"
        } else {
            $from.made
        }
    }
    let header = ["  secrets   (each by name and where it comes from; no value is shown)"]
    $header ++ ($secrets | each {|s| $"    ($s.namespace)/($s.name): (do $source $s.from)" })
}

export def build_plan [config: record, dev: bool, options: record = {}] {
    let in_cluster = ($options.in_cluster? | default false)
    let import_from = ($options.import_from? | default "")
    # Polar's git server holds the deployment, read from where Flux reads (infra/flux.nu); `bootstrap_again` is a run recovering through a bootstrap server (`up.nu --bootstrap-again`).
    let handed_off = ($options.handed_off? | default false)
    let bootstrap_again = ($options.bootstrap_again? | default false)
    # The configurations under test this run carries (`up.nu --under-test`, infra/under-test.nu).
    let under_test = ($options.under_test? | default [])
    let d = (deployed_charts $config)
    let order = $config.apply_order
    let ca_cm = ($config.cert_issuer_ca_configmap? | default "")
    let has_ci = ("cert-issuer" in $d)
    let has_ca_agent = ("credentials-agent" in $d)
    let has_neo4j = ("neo4j" in $d)
    let has_seed = ($has_ca_agent and ("polar-git-server" in $d) and ("polar-scheduler-observer" in $d))
    let has_core = ($has_ci or ("cassini" in $d) or $has_ca_agent or $has_neo4j)
    # A gitops target is not applied by up.nu: its layers are committed, signed, to a deployment git server in
    # the cluster (in no layer), and Flux applies them. up.nu still does what has to exist before Flux (namespaces, the CA, the
    # secrets) and what needs running workloads after it (the admin flow, the seed, the browser).
    let gitops = ($config.gitops? | default false)

    [
        { id: "preflight", title: "preflight", on: true, why: "" }
        # Before anything that pulls a Polar image: the render's scaffold pods, and Flux's own controllers.
        { id: "registry", title: "registry in the cluster", on: $in_cluster, why: "the target's registry is not in its cluster (cluster.registry_in_cluster)" }
        # Every image the target runs, before the render: the render asks the agents' images for their scaffolds, and a target that
        # pins its images by digest names the ones just pushed. Copied from where they are published (--import-from), built from
        # this checkout (--dev), or both, in that order; with neither, they are in the registry already. Without a registry in the
        # cluster, building starts the host's (`just registry-host-up`).
        { id: "images", title: "images", on: ($dev or ($import_from | is-not-empty)), runtime: ($dev and (not $in_cluster)), why: "pass --dev to build them, or --import-from <registry>/<account> to copy the published ones; without either, the render asks the ones already in the registry" }
        { id: "render", title: "render", on: true, why: "" }
        { id: "namespaces", title: "namespaces", on: ("namespaces.yaml" in $order), why: "target has no namespaces.yaml in its apply order" }
        {
            id: "ca"
            title: "cluster CA"
            on: ($has_ci and ($ca_cm | is-not-empty))
            why: (if not $has_ci { "target does not deploy cert-issuer" } else { "target does not use a provisioned CA (cert_issuer_ca_configmap is empty)" })
        }
        { id: "infra", title: "secrets and infrastructure", on: (not $gitops), why: "the layers are applied by Flux (gitops target)" }
        { id: "secrets", title: "secrets", on: $gitops, why: "up.nu creates the secrets in the infrastructure step" }
        { id: "deploy-host", title: "deployment git server", on: ($gitops and not $handed_off), why: (if $handed_off { "Polar's git server holds the deployment" } else { "target is not applied by Flux" }) }
        { id: "deployment-forward", title: "a forward to Polar's git server", on: ($gitops and $handed_off), why: "the deployment is on the deployment git server" }
        { id: "publish", title: "publish the layers", on: $gitops, why: "target is not applied by Flux" }
        { id: "flux", title: "install Flux", on: $gitops, why: "target is not applied by Flux" }
        { id: "flux-wait", title: "wait for Flux to reconcile", on: $gitops, why: "target is not applied by Flux" }
        { id: "pods", title: "waiting for core services", on: $has_core, why: "target deploys none of cert-issuer, cassini, credentials-agent, neo4j" }
        # What needs a configuration under test running, once Flux has its layer ready: each one's `ready` script.
        { id: "under-test", title: "configurations under test", on: ($under_test | is-not-empty), why: "this cluster carries no configuration under test (--under-test)" }
        { id: "forwards", title: "port-forwards", on: ($has_ca_agent or $has_neo4j), why: "target deploys neither credentials-agent nor neo4j" }
        { id: "admin", title: "admin flow", on: $has_ca_agent, why: "target does not deploy credentials-agent" }
        {
            id: "seed"
            title: "seed the schedules repository"
            on: $has_seed
            why: "target does not deploy all of credentials-agent, polar-git-server and polar-scheduler-observer"
        }
        {
            id: "handoff"
            title: "hand the deployment to Polar's git server"
            on: ($gitops and $has_seed and not $bootstrap_again)
            why: (if $bootstrap_again { "recovering through the bootstrap server: the next run hands off again" } else { "target is not applied by Flux, or has no git server and configuration agent" })
        }
        {
            id: "browser"
            title: "browser certificate and Neo4j password"
            on: ($has_ca_agent and $has_neo4j)
            why: (if not $has_neo4j { "target does not deploy neo4j" } else { "no credentials-agent, so no user certificate to import" })
        }
    ]
}

# Whether the enabled steps of `plan` need a container runtime on this machine: only building the images (`--dev`), which starts
# the host's registry unless the target's registry is in its cluster. No other step needs one: the agents are asked about
# themselves on the cluster, and a gitops target's deployment git server runs there too.
export def needs_runtime [plan: list] {
    $plan | where on | any {|s| $s.runtime? | default false }
}

# Port-forwards needed by the admin and browser steps, and only those: each the namespace and service `just
# port-forwards-up` forwards it from, by which a forward already running is found (forwards.nu).
export def build_forwards [config: record] {
    let d = (deployed_charts $config)
    mut f = []
    if "credentials-agent" in $d {
        $f = ($f | append { name: "observer", ns: "polar", svc: "credentials-agent-observer" })
    }
    if "neo4j" in $d {
        $f = ($f | append { name: "neo4j", ns: "polar-graph", svc: "polar-db-svc" })
    }
    # The seed pushes to the git server from this machine.
    if ("credentials-agent" in $d) and ("polar-git-server" in $d) and ("polar-scheduler-observer" in $d) {
        $f = ($f | append { name: "git", ns: "polar", svc: "polar-git-server" })
    }
    $f
}
