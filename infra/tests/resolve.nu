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

# infra/tests/resolve.nu
#
# Tests of what the resolver produces for the real catalog: the shutdown budget, the
# grace period derived from it, and the health settings the agent reads. The pure
# rules are in tests/rules.nu; these are about the wiring around them.
#
#   POLAR_TEST_CLUSTER_KUBECONFIG=<kubeconfig> nu infra/tests/resolve.nu
#   POLAR_SCAFFOLD_DIR=<dir> nu infra/tests/resolve.nu      no cluster: the tests that need one are skipped
#
# It acts only on the cluster POLAR_TEST_CLUSTER_KUBECONFIG names, never the ambient KUBECONFIG (infra/test-cluster.nu).

use std/assert
use ../test-cluster.nu
use ../cluster-registry.nu
use ../registry.nu [node_registry]
use ../attested.nu [attest_also_problems attested_namespaces server_also_problems floor_entries_also role_namespaces added_namespaces]

const RESOLVER = (path self | path dirname | path dirname | path join "resolve.nu")

# What each catalog workload's code declares it needs to drain
# (with_shutdown_budget in its supervisor). The deployment must give at least this.
const BUDGETS = {
    kube-observer: 20
    kube-consumer: 45
    jira-observer: 40
    jira-processor: 40
    credentials-agent: 50
    credentials-agent-observer: 40
    cassini: 20
    oci-registry-resolver: 20
    git-repo-observer: 40
    git-repo-processor: 45
    git-repo-controller: 10
}

# The record the template takes, as the pipeline gets it.
def resolve [name: string] {
    ^nu $RESOLVER json $name | from json
}

const INFRA = (path self | path dirname | path dirname)

# The target a test reads a workload under: sandbox-local, unless that target leaves it out (`enabled: false`), in which case
# the whole catalog's, a throwaway target of this run with nothing left out.
def target_for [name: string] {
    if ($name in (^nu $RESOLVER names | from json)) { "sandbox-local" } else { $env.POLAR_TEST_WHOLE_CATALOG }
}

# sandbox-local's config with the topology in force set, for what depends on it.
def laid_out [topology: string] {
    open ($INFRA | path join "targets/sandbox-local/config.nuon") | upsert cluster.placement.topology $topology
}

# The record for a workload under another target.
def resolve_for [target: string, name: string] {
    ^nu $RESOLVER json $name --target $target | from json
}

# The settings the rules read.
def settings [name: string] {
    ^nu $RESOLVER settings $name | from json
}

# What the agent will be given for a variable: from its environment, or, for an agent that reads
# a configuration document, from the document the resolver wrote.
def env_value [r: record, name: string, target: string = "sandbox-local"] {
    if ($r.env | where name == "POLAR_CONFIG" | is-empty) {
        $r.env | where name == $name | get -o 0.value
    } else {
        let maps = (^nu $RESOLVER resources $r.name --target $target | from json | get config_maps)
        $maps | first | get content | from json | get sections | each {|s| $s.variables } | flatten
        | where name == $name | get -o 0.value
    }
}

# Runs `body` with a throwaway target whose config.nuon is `config`, and removes it afterwards, so a test can
# say what a target would change (a workload's issuer, whether the floor is enforced).
def with_target [config: record, body: closure] {
    let name = $"zz-test-(random chars --length 8)"
    let dir = ($INFRA | path join "targets" $name)
    mkdir $dir
    $config | to nuon | save --force ($dir | path join "config.nuon")
    try {
        let out = (do $body $name)
        rm -rf $dir
        $out
    } catch {|e|
        rm -rf $dir
        error make { msg: $e.msg }
    }
}

# Runs `body` with `target`'s cluster carrying a throwaway configuration under test that adds `adds` (infra/under-test.nu), and
# removes both afterwards.
def with_under_test [target: string, adds: record, body: closure] {
    let name = $"zz-test-(random chars --length 8 | str downcase)"
    let dir = ($INFRA | path join "under-test" $name)
    let inputs = ($INFRA | path join "targets" $target "cluster-inputs.nuon")
    mkdir $dir
    # Its layer holds what it enables, as a declaration's must (infra/under-test.nu, layer_problems).
    let files = ($adds.workloads? | default {} | columns | each {|w| $"($w).yaml" })
    { adds: $adds, layer: { files: $files, wait_for: [] } } | to nuon | save --force ($dir | path join "under-test.nuon")
    { cluster: null, workloads: {}, under_test: [$name] } | to nuon | save --force $inputs
    try {
        let out = (do $body)
        rm -rf $dir $inputs
        $out
    } catch {|e|
        rm -rf $dir $inputs
        error make { msg: $e.msg }
    }
}

# An error as nu prints it, with its message's line breaks (and the `|` it starts each wrapped line with) taken out, so a test
# reads the message, not where it wrapped.
def unwrapped [] {
    $in | str replace --all --regex '\n\s*\|?\s*' ' '
}

# Runs `body` with POLAR_SCAFFOLD_DIR a copy of the scaffolds in which `workload`'s `section` declares `variable` too.
def with_scaffold_variable [workload: string, section: string, variable: string, body: closure] {
    let dir = (mktemp --directory)
    cp -r ($env.POLAR_SCAFFOLD_DIR | path join "*" | into glob) $dir
    let file = ($dir | path join $"($workload).json")
    let scaffold = (open $file)
    let template = ($scaffold.sections | where name == $section | first | get variables | first)
    $scaffold | update sections {|s| $s.sections | each {|sec|
        if $sec.name != $section { $sec } else { $sec | update variables ($sec.variables | append ($template | update name $variable)) }
    } } | to json | save --force $file
    try {
        let out = (with-env { POLAR_SCAFFOLD_DIR: $dir } { do $body })
        rm -rf $dir
        $out
    } catch {|e|
        rm -rf $dir
        error make { msg: $e.msg }
    }
}

# The workload object (Deployment or Job) `render-catalog.nu` renders for `name` under `target`.
def object_of [name: string, target: string] {
    let out = (mktemp --directory)
    let r = (do { ^nu ($INFRA | path join "render-catalog.nu") $target $out --only $name } | complete)
    if $r.exit_code != 0 {
        rm -rf $out
        error make { msg: $"the render of ($name) failed: ($r.stderr | lines | last 5 | str join '; ')" }
    }
    let docs = (open --raw ($out | path join $"($name).yaml") | split row "\n---\n" | each {|d| $d | from yaml })
    rm -rf $out
    $docs | where {|d| ($d.kind? | default "") in ["Job" "Deployment" "PodTemplate"] } | first
}

# The pod `render-catalog.nu` renders for `name` under `target`, read back from its output.
def pod_of [name: string, target: string] {
    let out = (mktemp --directory)
    let r = (do { ^nu ($INFRA | path join "render-catalog.nu") $target $out --only $name } | complete)
    if $r.exit_code != 0 {
        rm -rf $out
        error make { msg: $"the render of ($name) failed: ($r.stderr | lines | last 5 | str join '; ')" }
    }
    let docs = (open --raw ($out | path join $"($name).yaml") | split row "\n---\n" | each {|d| $d | from yaml })
    rm -rf $out
    let o = ($docs | where {|d| ($d.kind? | default "") in ["Job" "Deployment" "PodTemplate"] } | first)
    if $o.kind == "PodTemplate" { $o.template.spec } else { $o.spec.template.spec }
}

def init_env_value [r: record, name: string] {
    $r.init_env | where name == $name | get -o 0.value
}

# Every workload `target` runs, resolved in one process (resolve.nu's `resolve`: the record `json` and `resources` are
# made from), as { name, r }.
def resolve_all [target: string] {
    let names = (^nu $RESOLVER names --target $target | from json)
    # Sourced, not used: a module may not export a command of its own name.
    let code = ("source '" + $RESOLVER + "'; $env.EGRESS_TEST_NAMES | from json | each {|n| { name: $n, r: (resolve $n $env.EGRESS_TEST_TARGET) } } | to json --raw")
    let r = (with-env { EGRESS_TEST_NAMES: ($names | to json --raw), EGRESS_TEST_TARGET: $target } { do { ^nu -c $code } | complete })
    if $r.exit_code != 0 { error make { msg: $"resolving ($target) failed: ($r.stderr | lines | last 5 | str join '; ')" } }
    $r.stdout | from json
}

# The variables a workload's agent declares, from its scaffold.
def declared_of [name: string] {
    open ($env.POLAR_SCAFFOLD_DIR | path join $"($name).json") | get sections | each {|s| $s.variables | get name } | flatten
}

# The variables of the document a resolved workload is given, as { section, name, value }.
def document_variables [r: record] {
    $r.config_map.content | from json | get sections | each {|s| $s.variables | each {|v| { section: $s.name, name: $v.name, value: $v.value } } } | flatten
}

# A certificate-shaped PEM block (base64 of random bytes): what the render checks of a CA file.
def fake_pem [] {
    "-----BEGIN CERTIFICATE-----\n" + (random binary 48 | encode base64) + "\n-----END CERTIFICATE-----\n"
}

# Writes `content` to `file` inside the test target `target`'s directory.
def target_file [target: string, file: string, content: string] {
    let p = ($INFRA | path join "targets" $target $file)
    mkdir ($p | path dirname)
    $content | save --force $p
}

const EGRESS_AGENTS = ["git-repo-observer" "jira-observer" "oci-registry-resolver" "openapi-observer"]

# The tests that run `resolve.nu check`: its agent checks run each agent's image on the cluster (`agent_checks`), so
# they run only on a cluster named for the tests (infra/test-cluster.nu), and are skipped otherwise.
const CLUSTER_TESTS = [
    "the state agent's first schema is made from every workload's scaffold, and a read nobody owns fails the check"
    "a target that runs an agent needing the state agent and not the state agent fails the check"
    "enabled is true or false and nothing else"
    "a disabled workload that is still in the target's apply order is a problem, named"
    "a target that disables a workload and leaves it out of its apply order checks clean"
    "the real catalog passes `check`, including the agent's own environment check"
    "a bootstrap identity cannot be moved onto the credentials agent"
    "an issuer that is neither is refused"
    "workloads still asking cert-issuer are listed as pending while the floor is off, and refused once it is enforced"
    "on the sandbox-local target no catalog workload asks cert-issuer directly but the bootstrap identities"
]

def main [] {
    # The cluster this run may act on: only the one POLAR_TEST_CLUSTER_KUBECONFIG names, never the ambient KUBECONFIG.
    # Without it, KUBECONFIG is pointed at a path kubectl cannot load, and the tests that need a cluster are skipped.
    let cluster = (test-cluster pin)
    # The agents' scaffolds, asked of their images on that cluster once for the whole run (it needs the images in the
    # registry): every resolve below reads them. The whole catalog's target has nothing left out, so it covers every workload.
    # The images are asked of a registry the cluster has: the one in the cluster of POLAR_TEST_REGISTRY_TARGET (default
    # sandbox-local), through its forward, as up.nu does. An address already in the
    # environment wins.
    # Scaffolds already given (POLAR_SCAFFOLD_DIR set, say from the workspace's own binaries' `--scaffold`) are used as
    # they are, and left in place: then the tests that need no cluster run without one.
    let preset = ($env.POLAR_SCAFFOLD_DIR? | default "")
    if ($preset | is-empty) and $cluster == null {
        print (test-cluster skip_line "every test here: they read the agents' scaffolds, collected on the cluster unless POLAR_SCAFFOLD_DIR gives them")
        return
    }
    # A throwaway target running the whole catalog, for what sandbox-local leaves out (the secret harness), removed at the end.
    $env.POLAR_TEST_WHOLE_CATALOG = $"zz-test-whole-(random chars --length 8)"
    let whole_catalog = ($INFRA | path join "targets" $env.POLAR_TEST_WHOLE_CATALOG)
    mkdir $whole_catalog
    let real = (open ($INFRA | path join "targets/sandbox-local/config.nuon"))
    $real | update workloads {|c| $c.workloads | items {|n, w| { $n: ($w | reject -o enabled) } } | reduce --fold {} {|it, acc| $acc | merge $it } }
    | to nuon | save --force ($whole_catalog | path join "config.nuon")
    let scaffolds = if ($preset | is-not-empty) { $preset } else {
        let registry_target = ($env.POLAR_TEST_REGISTRY_TARGET? | default "sandbox-local")
        if (cluster-registry settings_of (cluster-registry cluster_of $registry_target)) != null {
            if ($env.POLAR_REGISTRY? | default "" | is-empty) { $env.POLAR_REGISTRY = (cluster-registry ensure $registry_target) }
            if ($env.POLAR_NODE_REGISTRY? | default "" | is-empty) { $env.POLAR_NODE_REGISTRY = (node_registry $registry_target) }
        }
        let collecting = (mktemp --directory)
        let collected = (do { ^nu $RESOLVER collect-scaffolds $collecting --target $env.POLAR_TEST_WHOLE_CATALOG } | complete)
        if $collected.exit_code != 0 {
            rm -rf $collecting $whole_catalog
            print -e $"cannot run: the agents could not be asked for their scaffolds on ($cluster) \(this needs the cluster and their images in the registry\):\n($collected.stderr | lines | last 8 | str join "\n")"
            exit 1
        }
        $collecting
    }
    $env.POLAR_SCAFFOLD_DIR = $scaffolds

    let tests = {
        # docs/architecture/key-custody.md, step 4: with the daemon, a pod's keys are the daemon's, and none is a file.
        "with the custody daemon a pod's certificates are the daemon's and no key variable is given": {
            let r = (resolve "kube-observer")
            assert ($r.custody != null) "the daemon is in the pod"
            assert ($r.certs | all {|c| $c | str contains ":custody:" }) $"($r.certs)"
            assert equal (env_value $r "TLS_CLIENT_KEY") null
            assert equal (env_value $r "POLAR_CUSTODY_SOCKET") "/run/polar-custody/custody.sock"
            assert equal (init_env_value $r "POLAR_CUSTODY_SOCKET") "/run/polar-custody/custody.sock"
            assert ($r.volumes | any {|v| $v.name == "polar-custody" })
            assert ($r.mounts | any {|m| $m.path == "/run/polar-custody" })
            assert ($r.init_mounts | any {|m| $m.path == "/run/polar-custody" })
        }

        "the custody daemon is a native sidecar before polar-init, apart, with IPC_LOCK alone": {
            let pod = (pod_of "kube-observer" "sandbox-local")
            let init = ($pod.initContainers | get name)
            assert equal $init ["polar-custody" "polar-init"]
            let daemon = ($pod.initContainers | first)
            assert equal $daemon.restartPolicy "Always"
            assert equal $daemon.securityContext.runAsUser 1001
            assert equal $daemon.securityContext.runAsGroup 1000
            assert equal $daemon.securityContext.capabilities.drop ["ALL"]
            assert equal $daemon.securityContext.capabilities.add ["IPC_LOCK"]
            let daemon_env = ($daemon.env | reduce --fold {} {|e, acc| $acc | insert $e.name ($e.value? | default "") })
            assert equal $daemon_env.POLAR_CUSTODY_SOCKET "/run/polar-custody/custody.sock"
            assert equal $daemon_env.POLAR_CUSTODY_CA_CERT "/etc/polar-ca/ca.pem"
            assert equal $daemon_env.POLAR_CUSTODY_INSTALLER_UID "1000"
            assert equal $daemon_env.POLAR_CUSTODY_WORKLOAD_UIDS "1000"
            # Where it watches, as its pod, for its own revocation (docs/architecture/key-custody.md, step 5): the
            # broker the pod's own clients are given.
            let polar_init = ($pod.initContainers | get 1)
            let client_env = ($polar_init.env | reduce --fold {} {|e, acc| $acc | insert $e.name ($e.value? | default "") })
            assert equal $daemon_env.BROKER_ADDR $client_env.BROKER_ADDR
            assert equal $daemon_env.CASSINI_SERVER_NAME $client_env.CASSINI_SERVER_NAME
            assert ($daemon_env.BROKER_ADDR | str starts-with $"($daemon_env.CASSINI_SERVER_NAME):") "the address is the name's"
            assert ($polar_init.env | where name == "TLS_CLIENT_KEY" | is-empty) "polar-init has no key file either"
            for c in [$daemon $polar_init ($pod.containers | first)] {
                assert ($c.volumeMounts | any {|m| $m.mountPath == "/run/polar-custody" }) $"($c.name) shares the socket"
            }
        }

        "the broker's server key and the git server's two keys are the daemon's": {
            let cassini = (resolve "cassini")
            assert equal $cassini.certs ["server:/etc/tls/certs:custody:cassini-ip-svc.polar.svc.cluster.local"]
            assert equal (env_value $cassini "TLS_SERVER_KEY") null
            assert equal (env_value $cassini "POLAR_CUSTODY_SOCKET") "/run/polar-custody/custody.sock"
            let git = (resolve_for "sandbox-local" "polar-git-server")
            assert equal ($git.certs | length) 2
            assert ($git.certs | all {|c| $c | str contains ":custody:" }) $"($git.certs)"
            assert equal (env_value $git "POLAR_GIT_SERVER_KEY") null
        }

        "cert-issuer has no daemon, and a workload that says custody false keeps its key files": {
            let ci = (resolve "cert-issuer")
            assert equal ($ci.custody? | default null) null
            # The scheduler observer clones with the git command, which reads its key from a file.
            let s = (resolve "polar-scheduler-observer")
            assert equal $s.custody null
            assert ($s.certs | all {|c| $c | str contains ":ecdsa-p256:" })
            assert equal (env_value $s "TLS_CLIENT_KEY") "/etc/tls/certs/key.pem"
        }

        # up.nu prepares the images `resolve.nu images` lists, and refuses a render naming one it did not.
        "the images a target's catalog runs include the custody daemon's when its pods have one": {
            let on = (^nu $RESOLVER images | from json)
            assert ($on | any {|i| $i | str contains "/polar-custody:" }) $"($on)"
            with_target { cluster: { custody: { enabled: false } }, workloads: {} } {|t|
                let off = (^nu $RESOLVER images --target $t | from json)
                assert ($off | all {|i| not ($i | str contains "/polar-custody:") }) $"($off)"
            }
        }

        # An agent that encrypts has its escrow key only through the custody daemon's custodian (key-custody.md, step 9):
        # with custody off, its render is refused and says why (the maintainer, 2026-10-28).
        "a target with custody off refuses an agent that encrypts": {
            with_target { cluster: { custody: { enabled: false } }, workloads: {} } {|t|
                let r = (do { ^nu $RESOLVER json kube-consumer --target $t } | complete)
                assert ($r.exit_code != 0) "kube-consumer encrypts, and has no daemon"
                assert ($r.stderr | str contains "kube-consumer") $r.stderr
                assert ($r.stderr | str contains "custody") $r.stderr
            }
        }

        # docs/architecture/placement.md: sandbox-local laid out on separate nodes gives each workload its own pool;
        # the open pool's (services) is given nothing. The mapping is the maintainer's (2026-10-28).
        "under the separated topology every workload is placed in its pool, and the open pool's in none": {
            let pools = {
                core: [credentials-agent cert-issuer cassini git-repo-controller polar-git-server attestation-agent]
                # The build workload runs foreign code: the low-trust side (docs/architecture/build-orchestrator.md, O2a).
                observers: [git-repo-observer jira-observer kube-observer polar-scheduler-observer credentials-agent-observer oci-registry-resolver openapi-observer build-runner]
                writers: [kube-consumer git-repo-processor jira-processor polar-scheduler soft-state-observer soft-state-processor openapi-processor build-processor]
            }
            let placed = ($pools | transpose pool names | each {|p| $p.names | each {|n| { name: $n, pool: $p.pool } } } | flatten)
            with_target (laid_out "separated") {|t|
                let names = (^nu $RESOLVER names --target $t | from json)
                for n in $names {
                    let r = (resolve_for $t $n)
                    let want = ($placed | where name == $n | get -o 0.pool)
                    if $want == null {
                        assert equal $r.placement null $n
                    } else {
                        assert equal $r.placement { key: "polar.dev/pool", pool: $want } $n
                    }
                }
                # every workload the mapping names runs there, so none of it is untested
                for p in $placed { assert ($p.name in $names) $p.name }
                # the harness is the open pool's
                assert equal (resolve_for $t "harness-sink").placement null
            }
        }

        "the single topology places nothing, and it is the one the target deploys in by default": {
            # A throwaway copy of the target, so this machine's own cluster-inputs.nuon, whatever it chose, is not read.
            with_target (open ($INFRA | path join "targets/sandbox-local/config.nuon")) {|t|
                assert equal (^nu $RESOLVER topology --target $t | str trim) "single"
                for n in (^nu $RESOLVER names --target $t | from json) {
                    assert equal (resolve_for $t $n).placement null $n
                }
            }
        }

        # The same target, laid out differently for one cluster: cluster-inputs.nuon overrides the target's default both ways.
        "a cluster's own choice of topology overrides the target's": {
            with_target (laid_out "single") {|t|
                target_file $t "cluster-inputs.nuon" ({ cluster: null, topology: "separated", workloads: {} } | to nuon)
                assert equal (^nu $RESOLVER topology --target $t | str trim) "separated"
                assert equal (resolve_for $t "cassini").placement { key: "polar.dev/pool", pool: "core" }
            }
            with_target (laid_out "separated") {|t|
                target_file $t "cluster-inputs.nuon" ({ cluster: null, topology: "single", workloads: {} } | to nuon)
                assert equal (resolve_for $t "cassini").placement null
            }
        }

        "a topology the target does not name is refused, naming the ones it does": {
            with_target (laid_out "three-node") {|t|
                let r = (do { ^nu $RESOLVER json cassini --target $t } | complete)
                assert ($r.exit_code != 0) "an unknown topology rendered"
                assert ($r.stderr | str contains "three-node") $r.stderr
                assert ($r.stderr | str contains "separated") $r.stderr
            }
        }

        "a target that declares placement refuses a workload whose pool it lacks": {
            with_target { cluster: { placement: { topology: "t", topologies: { t: ["core"] } } }, workloads: {} } {|t|
                let r = (do { ^nu $RESOLVER json kube-consumer --target $t } | complete)
                assert ($r.exit_code != 0) "kube-consumer asks for writers"
                assert ($r.stderr | str contains "kube-consumer") $r.stderr
                assert ($r.stderr | str contains "writers") $r.stderr
                assert ((resolve_for $t "cassini").placement == { key: "polar.dev/pool", pool: "core" })
            }
            # and a target that would set a workload's pool itself: the pool is the catalog's
            with_target { cluster: { placement: { topology: "t", topologies: { t: ["core" "writers"] } } }, workloads: { cassini: { pool: "writers" } } } {|t|
                let r = (do { ^nu $RESOLVER json cassini --target $t } | complete)
                assert ($r.exit_code != 0) "the target set cassini's pool"
                assert ($r.stderr | str contains "catalog") $r.stderr
            }
        }

        # docs/architecture/runtime-attestation.md: the attestation agent reads pods and what owns them in Polar's namespaces,
        # and nothing else: no ClusterRole, and a Role in each namespace it is told to watch.
        "the attestation agent is given the deployment CA to check the record with, read-only": {
            let r = (resolve "attestation-agent")
            assert equal (env_value $r "POLAR_ATTESTATION_DEPLOYMENT_CA") "/etc/polar-deploy-ca/ca.pem"
            assert equal ($r.volumes | where name == "polar-deploy-ca" | first).config_map "polar-deploy-ca"
            let mount = ($r.mounts | where name == "polar-deploy-ca" | first)
            assert equal $mount.path "/etc/polar-deploy-ca"
            assert $mount.read_only
        }

        "the attestation agent gets a read-only Role in each namespace Polar attests, and no ClusterRole": {
            # Polar's own: sandbox-local as committed attests no other (a copy, so this machine's cluster-inputs.nuon, which
            # may carry a configuration under test that adds one, infra/under-test.nu, is not read).
            with_target (open ($INFRA | path join "targets/sandbox-local/config.nuon")) {|t|
                let resources = (^nu $RESOLVER resources attestation-agent --target $t | from json)
                assert equal $resources.cluster_roles []
                let namespaces = ($resources.namespaced_roles | get namespace | sort)
                # Polar's own and the build namespace, whose pods the credentials agent issues to.
                assert equal $namespaces ["polar" "polar-auth" "polar-builds" "polar-graph"]
                for role in $resources.namespaced_roles {
                    let verbs = ($role.rules | get verbs | flatten | uniq | sort)
                    assert equal $verbs ["get" "list" "watch"] $role.namespace
                    let kinds = ($role.rules | get resources | flatten | sort)
                    assert equal $kinds ["deployments" "jobs" "pods" "replicasets" "statefulsets"] $role.namespace
                }
                assert equal (env_value (resolve_for $t "attestation-agent") "POLAR_ATTESTATION_NAMESPACES" $t | split row "," | sort) ["polar" "polar-auth" "polar-builds" "polar-graph"]
            }
        }

        # docs/architecture/http-observers.md, "GitLab": a namespace that is not Polar's, whose pods Polar's CA issues to, is one
        # the attestation agent attests, or the credentials agent refuses its pods as not found.
        "the namespaces beyond Polar's first are made with their Pod Security, the build namespace's restricted warned and audited, nothing enforced": {
            let cluster = {
                namespaces: { polar: "polar", graph: "polar-graph", auth: "polar-auth", builds: "polar-builds" }
                pod_security: { builds: { enforce: "baseline", warn: "restricted", audit: "restricted" } }
                attest_also: ["gitlab-test"]
            }
            assert equal (added_namespaces $cluster) [
                { name: "polar-builds", labels: {
                    "pod-security.kubernetes.io/enforce": "baseline"
                    "pod-security.kubernetes.io/warn": "restricted"
                    "pod-security.kubernetes.io/audit": "restricted"
                } }
                { name: "gitlab-test", labels: {} }
            ]
            # As committed, sandbox-local's: the build namespace, as decided (docs/architecture/build-orchestrator.md, 5d): Polar refuses
            # what a build pod may not have, and Pod Security only records, so a custody sidecar's IPC_LOCK is not refused there.
            let committed = (open ($INFRA | path join "config/cluster.nuon"))
            assert equal ((added_namespaces ($committed | reject -o attest_also)) | get name) ["polar-builds"]
            assert equal ((added_namespaces $committed) | first | get labels) {
                "pod-security.kubernetes.io/warn": "restricted"
                "pod-security.kubernetes.io/audit": "restricted"
            }
            # A Pod Security level that is not one is refused, and so is a key the cluster does not have.
            for bad in [{ builds: { enforce: "lenient" } } { nowhere: { enforce: "baseline" } }] {
                let refused = (try { added_namespaces ($cluster | update pod_security $bad); null } catch {|e| $e.msg })
                assert ($refused != null) $"($bad)"
            }
        }

        "a capability's Role goes in the namespace it names alone, in every attested one when it names none, and a key the cluster lacks is refused": {
            let cluster = { namespaces: { polar: "polar", graph: "polar-graph", builds: "polar-builds" }, attest_also: ["gitlab-test"] }
            assert equal (role_namespaces { name: "r", rules: [] } $cluster "pod-read") ["polar" "polar-graph" "polar-builds" "gitlab-test"]
            assert equal (role_namespaces { name: "r", namespace: "builds", rules: [] } $cluster "job-run") ["polar-builds"]
            let refused = (try { role_namespaces { name: "r", namespace: "nowhere", rules: [] } $cluster "job-run"; null } catch {|e| $e.msg })
            assert ($refused != null and ($refused | str contains "nowhere")) $"($refused)"
        }

        # docs/architecture/build-orchestrator.md, 5b, 5c and revised 3: the build workload is a PodTemplate in the build namespace,
        # which the orchestrator makes each build's Job from. A build pod holds no Polar identity: no certificate, no custody
        # daemon, no polar-init, no Cassini client; the orchestrator relays what it prints. No Polar binary of its own runs in it,
        # so it has no scaffold, no document, no health and no probe.
        "the build workload is a template in the build namespace, with no identity, on its environment": {
            let r = (resolve "build-runner")
            assert equal $r.kind "template"
            assert equal $r.namespace "polar-builds" "the entry names the namespace by its key, builds"
            assert equal $r.restart_policy "Never" "a build runs once; its Job, not the pod, is what is retried"
            assert equal $r.service_account "build-runner"
            assert equal $r.needs [] "no Cassini, no tracing, no pinned CA: nothing of Polar's in the pod"
            assert equal $r.env [] "no client environment"
            assert equal $r.volumes [] "no token, no certificate, no CA, no socket"
            assert equal $r.mounts []
            assert equal $r.automount_sa_token false
            assert equal (^nu $RESOLVER resources build-runner | from json | get config_maps) [] "no document's ConfigMap"
            assert equal $r.workspace "/workspace" "where build-fetch unpacks and the pipeline builds (orchestrator_core::WORKSPACE_PATH)"
            for absent in [custody certs init_env init_mounts polar_init_image dep_checks probe instances] {
                assert ($absent not-in ($r | columns)) $"($absent): the template takes nothing of an identity"
            }
        }

        "the build workload's PodTemplate: the fetch, then one pipeline container on the fetch image until a build replaces it, and nothing of Polar's": {
            use ../rules.nu [is_multi_instance]
            let o = (object_of "build-runner" "sandbox-local")
            assert equal $o.kind "PodTemplate"
            assert equal $o.metadata.name "build-runner"
            assert equal $o.metadata.namespace "polar-builds"
            assert (not (is_multi_instance $o)) "its pods are never issued, so they are not instances of an identity"
            assert equal $o.template.metadata.labels { name: "build-runner" }
            let pod = $o.template.spec
            assert equal $pod.serviceAccountName "build-runner"
            assert equal $pod.automountServiceAccountToken false
            assert equal $pod.restartPolicy "Never"
            assert equal ($pod.initContainers | get name) ["fetch"]
            assert equal ($pod.containers | get name) ["pipeline"]
            let fetch = ($pod.initContainers | first)
            let pipeline = ($pod.containers | first)
            assert ($fetch.image | str contains "/build-fetch") $fetch.image
            assert equal $pipeline.image $fetch.image "decision 5c: the pipeline runs the fetch image until the orchestrator replaces it"
            assert equal ($fetch.restartPolicy? | default null) null "the fetch runs once, before the pipeline, not as a sidecar"
            assert equal ($fetch.env | where name == "CYCLOPS_WORKSPACE" | get value) ["/workspace"]
            # Decision 4: a build runs hardened, non-root, with no privilege escalation, every capability dropped and the default
            # seccomp profile, until its signed mapping says otherwise (the orchestrator, O2c).
            for c in [$fetch $pipeline] {
                assert equal ($c.volumeMounts | get name) ["workspace"] $"($c.name) mounts the workspace alone"
                assert equal ($c.volumeMounts | first | get mountPath) "/workspace" $c.name
                assert equal $c.securityContext.capabilities.drop ["ALL"] $c.name
                assert equal ($c.securityContext.capabilities.add? | default null) null $c.name
                assert equal $c.securityContext.runAsNonRoot true $c.name
                assert equal $c.securityContext.allowPrivilegeEscalation false $c.name
                assert equal $c.securityContext.seccompProfile.type "RuntimeDefault" $c.name
            }
            assert equal ($pipeline.env? | default []) [] "the pipeline is told nothing of Polar's"
            assert equal ($pod.volumes | get name) ["workspace"]
            assert equal ($pipeline.livenessProbe? | default null) null "no polar-healthcheck in a pipeline image"
            assert equal ($pipeline.restartPolicy? | default null) null
        }

        "a template that would hold an identity, publish or read a document is refused": {
            let real = (open ($INFRA | path join "targets/sandbox-local/config.nuon"))
            for case in [
                { change: { provides: ["cassini"] }, says: "identity" }
                { change: { custody: true }, says: "identity" }
                { change: { topics: [{ name: "polar.provenance.events", access: "publish", purpose: "x", unprompted: "y" }] }, says: "relay" }
                { change: { config: "document" }, says: "env" }
            ] {
                with_target ($real | upsert workloads.build-runner $case.change) {|t|
                    let r = (do { ^nu $RESOLVER json build-runner --target $t } | complete)
                    assert ($r.exit_code != 0) $"($case.change) is refused"
                    assert ($r.stderr | str contains $case.says) $"($case.change): ($r.stderr)"
                }
            }
        }

        "a workload's namespace is named by its key in the cluster's namespaces, and one that is not a key is a name": {
            assert equal (resolve "kube-observer").namespace "polar"
            assert equal (resolve "build-runner").namespace "polar-builds"
            with_target { workloads: { kube-observer: { namespace: "elsewhere" } } } {|t|
                assert equal (resolve_for $t "kube-observer").namespace "elsewhere"
            }
        }

        "a target may name more namespaces Polar attests, and not one that is Polar's own, Kubernetes' or not a name": {
            let own = ["polar" "polar-graph" "polar-auth"]
            assert equal (attest_also_problems ["gitlab-test"] $own) []
            assert equal (attest_also_problems [] $own) []
            for bad in [["polar-graph"] ["kube-system"] ["default"] ["Bad_Name"] [""] ["gitlab-test" "gitlab-test"]] {
                assert ((attest_also_problems $bad $own) | is-not-empty) $"($bad)"
            }
            assert ((attest_also_problems "gitlab-test" $own) | is-not-empty) "a list"
            let cluster = { namespaces: { polar: "polar", graph: "polar-graph", auth: "polar-auth" } }
            assert equal (attested_namespaces $cluster) $own
            assert equal (attested_namespaces ($cluster | insert attest_also ["gitlab-test"])) [...$own "gitlab-test"]
            # What the render is told, to make the namespace as it makes Polar's: none for sandbox-local as committed (a copy, so
            # this machine's cluster-inputs.nuon, whatever it carries, is not read).
            with_target (open ($INFRA | path join "targets/sandbox-local/config.nuon")) {|t|
                assert equal (^nu $RESOLVER attest-also --target $t | from json) []
            }
        }

        # As Neo4j's (render.nu, neo4j_floor_entries): a server the credentials agent vouches for, in a namespace Polar attests,
        # with the names its init container asks for.
        "a target may name more servers the floor admits, each in a namespace Polar attests": {
            let attested = ["polar" "polar-graph" "gitlab-test"]
            let entry = { namespace: "gitlab-test", service_account: "gitlab", names: ["gitlab.gitlab-test.svc.cluster.local"] }
            assert equal (server_also_problems [$entry] $attested) []
            assert equal (server_also_problems [] $attested) []
            for bad in [
                ($entry | update namespace "elsewhere")
                ($entry | update names [])
                ($entry | update names ["not a name"])
                ($entry | update service_account "")
                ($entry | reject names)
            ] {
                assert ((server_also_problems [$bad] $attested) | is-not-empty) $"($bad)"
            }
            assert equal (floor_entries_also [$entry]) [{
                workload: "system:serviceaccount:gitlab-test:gitlab", cert_type: "SERVER"
                names: ["gitlab.gitlab-test.svc.cluster.local"], vouched_only: true, publish: [], subscribe: [], groups: []
            }]
            with_target (open ($INFRA | path join "targets/sandbox-local/config.nuon")) {|t|
                assert equal (^nu $RESOLVER server-also --target $t | from json) [] "sandbox-local as committed names none"
            }
        }

        # docs/architecture/configurations-under-test.md, CT1: what a cluster carries under test is the resolver's as the target's
        # own would be, and judged as it is; what would change the target stops it.
        "a cluster's configurations under test add to its target as the resolver reads it, and only add": {
            let adds = {
                cluster: {
                    attest_also: ["gitlab-test"]
                    issuance: { server_also: [{ namespace: "gitlab-test", service_account: "gitlab", names: ["gitlab.gitlab-test.svc.cluster.local"] }] }
                }
            }
            with_target (open ($INFRA | path join "targets/sandbox-local/config.nuon")) {|t|
                with_under_test $t $adds {
                    assert equal (^nu $RESOLVER attest-also --target $t | from json) ["gitlab-test"]
                    assert equal (^nu $RESOLVER server-also --target $t | from json | get workload) ["system:serviceaccount:gitlab-test:gitlab"]
                    # CT2: a server it adds is under test, and its certificate says so.
                    assert equal (^nu $RESOLVER server-also --target $t | from json | get groups) [["under-test"]]
                }
                # Judged as the target's: a server in a namespace nothing attests.
                with_under_test $t ($adds | reject cluster.attest_also) {
                    let r = (do { ^nu $RESOLVER server-also --target $t } | complete)
                    assert ($r.exit_code != 0) "a server in a namespace nothing attests"
                }
                with_under_test $t { cluster: { issuance: { floor_enforced: false } } } {
                    let r = (do { ^nu $RESOLVER attest-also --target $t } | complete)
                    assert ($r.exit_code != 0 and ($r.stderr | str contains "floor_enforced")) $r.stderr
                }
                # The secret harness's precedent: a workload the target leaves out, run while it is what is tested.
                assert ("secret-harness-owner" not-in (^nu $RESOLVER names --target $t | from json))
                with_under_test $t { workloads: { secret-harness-owner: { enabled: true } } } {
                    assert ("secret-harness-owner" in (^nu $RESOLVER names --target $t | from json))
                    # CT2: the certificate of what it enables carries g:under-test, and no other workload's does.
                    let model = (env_value (resolve_for $t credentials-agent) "CREDENTIALS_AGENT_AUTHORITY_MODEL" $t | from json)
                    let marked = ($model.workloads | where {|w| "under-test" in ($w.groups? | default []) } | get workload)
                    assert equal $marked ["secret-harness-owner"]
                }
                # Without one, none is.
                let model = (env_value (resolve_for $t credentials-agent) "CREDENTIALS_AGENT_AUTHORITY_MODEL" $t | from json)
                assert ($model.workloads | all {|w| "under-test" not-in ($w.groups? | default []) })
                for refused in [
                    [{ workloads: { jira-observer: { env: [{ name: "JIRA_URL", value: "https://elsewhere.example" }] } } } "JIRA_URL"]
                    [{ workloads: { no-such-workload: { enabled: true } } } "no-such-workload"]
                ] {
                    with_under_test $t $refused.0 {
                        let r = (do { ^nu $RESOLVER names --target $t } | complete)
                        assert ($r.exit_code != 0 and ($r.stderr | str contains $refused.1)) $r.stderr
                    }
                }
            }
        }

        "no other workload's capabilities give it a namespaced Role": {
            for n in (^nu $RESOLVER names | from json | where {|n| $n != "attestation-agent" }) {
                assert equal (^nu $RESOLVER resources $n | from json | get namespaced_roles) [] $n
            }
        }

        # docs/architecture/cluster-bootstrap.md, "Handing off to Polar's git server": the deployment is a repository of Polar's git server, whose commits the pipeline must have
        # signed, that Flux may read and nothing may write yet. The server is given the deployment CA to check them with.
        "the configuration agent is given what it copies the deployment with, and only it": {
            # A throwaway copy of the target, so this machine's own cluster-inputs.nuon, whichever way it is, is not read.
            with_target (open ($INFRA | path join "targets/sandbox-local/config.nuon")) {|t|
                let r = (resolve_for $t "polar-scheduler-observer")
                assert (env_value $r "POLAR_SCHEDULER_DEPLOYMENT_SOURCE_URL" $t | str contains "polar-deploy-git.polar-deploy.svc") "the bootstrap repository"
                assert (env_value $r "POLAR_SCHEDULER_DEPLOYMENT_TARGET_URL" $t | str ends-with "/deployment.git")
                assert equal (env_value $r "POLAR_SCHEDULER_DEPLOYMENT_SOURCE_KEY" $t) "/etc/polar-deployment-reader/tls.key"
                let volume = ($r.volumes | where name == "deployment-reader" | first)
                assert equal $volume.secret "deployment-reader"
                assert ($r.mounts | where name == "deployment-reader" | first | get read_only)
                for n in (^nu $RESOLVER names --target $t | from json | where {|n| $n != "polar-scheduler-observer" }) {
                    assert ((resolve_for $t $n).volumes | where name == "deployment-reader" | is-empty) $n
                }
            }
        }

        "once handed off, the configuration agent has no copy settings, no key of the deployment PKI and no write to the deployment": {
            let handed = (open ($INFRA | path join "targets/sandbox-local/config.nuon"))
            with_target $handed {|t|
                target_file $t "cluster-inputs.nuon" ({ cluster: null, handed_off: true, workloads: {} } | to nuon)
                let observer = (resolve_for $t "polar-scheduler-observer")
                assert equal (env_value $observer "POLAR_SCHEDULER_DEPLOYMENT_SOURCE_URL" $t) null
                assert (env_value $observer "POLAR_SCHEDULER_DEPLOYMENT_URL" $t | str ends-with "/deployment.git") "it still delivers the signed record"
                assert equal (env_value $observer "POLAR_SCHEDULER_DEPLOYMENT_TARGET_URL" $t) null
                assert ($observer.volumes | where name == "deployment-reader" | is-empty)
                let repos = (env_value (resolve_for $t "polar-git-server") "POLAR_GIT_SERVER_REPOS" $t | from json | get repos)
                let deployment = ($repos | where name == "deployment" | first)
                assert equal $deployment.writers []
                assert ("polar-scheduler-observer.polar.serviceaccount.cluster.local" in $deployment.readers) "it still reads"
            }
        }

        "the git server holds the deployment, only signed commits go into it, and Flux reads it under the deployment PKI's name": {
            # A throwaway copy of the target, so this machine's own cluster-inputs.nuon, whichever way it is, is not read.
            with_target (open ($INFRA | path join "targets/sandbox-local/config.nuon")) {|t|
                let r = (resolve_for $t "polar-git-server")
                let repos = (env_value $r "POLAR_GIT_SERVER_REPOS" $t | from json | get repos)
                let deployment = ($repos | where name == "deployment" | first)
                assert equal $deployment.signed_by { ca: "/etc/polar-deploy-ca/ca.pem", signer: "pipeline" }
                assert ("deployment:flux" in $deployment.readers)
                # The configuration agent writes until the handoff is done, which is safe since the server takes only what the pipeline signed.
                assert equal $deployment.writers ["polar-scheduler-observer.polar.serviceaccount.cluster.local"]
                assert equal (env_value $r "POLAR_GIT_SERVER_DEPLOYMENT_CA" $t) "/etc/polar-deploy-ca/ca.pem"
                let volume = ($r.volumes | where name == "polar-deploy-ca" | first)
                assert equal $volume.config_map "polar-deploy-ca"
                let mount = ($r.mounts | where name == "polar-deploy-ca" | first)
                assert equal $mount.path "/etc/polar-deploy-ca"
                assert $mount.read_only
                # and the schedules have no such rule: they are signed document by document
                assert (($repos | where name == "polar-schedules" | first | get -o signed_by) == null)
            }
        }

        "the git server holds the evidence repository, seeded once, written by its administrators, each record signed by its collector": {
            with_target (open ($INFRA | path join "targets/sandbox-local/config.nuon")) {|t|
                let repos = (env_value (resolve_for $t "polar-git-server") "POLAR_GIT_SERVER_REPOS" $t | from json | get repos)
                let evidence = ($repos | where name == "polar-evidence" | first)
                assert equal $evidence.seed "polar-evidence"
                assert equal $evidence.readers []
                assert equal $evidence.writers []
                # A record is signed by whoever collected it, so no one signer is required of a commit (an open question, docs/architecture/http-observers.md)
                assert (($evidence | get -o signed_by) == null)
                assert ($INFRA | path join "seeds/polar-evidence/README.md" | path exists)
            }
        }

        # nix-usernetes' contract: the selector and the toleration both, or the pod stays Pending on a tainted node.
        "a placed pod has the pool's selector and its toleration, in both templates": {
            with_target (laid_out "separated") {|t|
                for n in [kube-consumer cert-issuer] {
                    let spec = (pod_of $n $t)
                    let pool = (if $n == "cert-issuer" { "core" } else { "writers" })
                    assert equal $spec.nodeSelector { "polar.dev/pool": $pool } $n
                    assert equal $spec.tolerations [{ key: "polar.dev/pool", operator: "Equal", value: $pool, effect: "NoSchedule" }] $n
                }
            }
            with_target (laid_out "single") {|t|
                for n in [kube-consumer cert-issuer] {
                    let plain = (pod_of $n $t)
                    assert equal ($plain.nodeSelector? | default null) null $n
                    assert equal ($plain.tolerations? | default null) null $n
                }
            }
        }

        # The broker's memory (the maintainer, 2026-11-01): its container's limit is its cgroup's memory.max, which its
        # memory controller reads for its ceiling (docs/architecture/cassini-backpressure.md, "Runtime budget"). 1 GiB,
        # requested as it is limited; no other workload sets any.
        "the broker's container is given 1 GiB of memory, requested and limited, and no other workload any": {
            for t in [sandbox-local] {
                assert equal (resolve_for $t "cassini").memory { request: "1Gi", limit: "1Gi" } $t
                let broker = (pod_of "cassini" $t | get containers | where name == "cassini" | first)
                assert equal $broker.resources { requests: { memory: "1Gi" }, limits: { memory: "1Gi" } } $t
            }
            for n in (^nu $RESOLVER names --target sandbox-local | from json | where {|n| $n != "cassini" }) {
                assert equal (resolve_for sandbox-local $n).memory null $n
            }
            let plain = (pod_of "kube-consumer" "sandbox-local" | get containers | first)
            assert equal ($plain.resources? | default null) null "nothing set where the catalog sets nothing"
        }

        "a target may give a workload other memory, in either template, and memory that is not a quantity or a request over its limit is refused": {
            with_target { workloads: { cert-issuer: { memory: { request: "256Mi", limit: "512Mi" } } } } {|t|
                assert equal (resolve_for $t "cert-issuer").memory { request: "256Mi", limit: "512Mi" }
                # cert-issuer is the `ca` kind, whose template is its own (schema/ca.dhall)
                let issuer = (pod_of "cert-issuer" $t | get containers | first)
                assert equal $issuer.resources { requests: { memory: "256Mi" }, limits: { memory: "512Mi" } }
            }
            assert equal ((pod_of "cert-issuer" "sandbox-local" | get containers | first).resources? | default null) null
            for bad in [{ request: "2Gi", limit: "1Gi" } { request: "1Gi", limit: "lots" }] {
                with_target { workloads: { cassini: { memory: $bad } } } {|t|
                    let r = (do { ^nu $RESOLVER json cassini --target $t } | complete)
                    assert ($r.exit_code != 0) $"($bad | to nuon) was taken"
                    assert ($r.stderr | str contains "cassini") $r.stderr
                    assert ($r.stderr | str contains "memory") $r.stderr
                }
            }
        }

        # Flux waits on what each layer's wait_for names, as deploy-objects.nu turns it into a health check; one that names
        # nothing the render makes fails the publish (2026-10-28: the targets still waited on Jobs that had become
        # Deployments). So every wait of the exemplar targets is checked against their render.
        # The load harness finds the broker by its pods' labels, to read its image and restart it with a run's settings
        # (2026-10-28: it still asked for job-name=cassini, which a Deployment's pods do not carry).
        "the load harness's broker selector names the pods of the broker's rendered Deployment": {
            use ../load-harness.nu [BROKER_SELECTOR]
            let broker = (object_of "cassini" "sandbox-local")
            assert equal $broker.kind "Deployment"
            let labels = $broker.spec.template.metadata.labels
            for kv in ($BROKER_SELECTOR | split row "," | each {|p| $p | split row "=" }) {
                assert equal ($labels | get -o $kv.0) $kv.1 $"the broker's pods are not labelled ($kv.0)=($kv.1)"
            }
        }

        "every wait of a target's layers names a workload its render makes": {
            use ../deploy-objects.nu [health_check, documents, BOOTSTRAP_LAYERS]
            for t in [sandbox-local] {
                let out = (mktemp --directory)
                let cat = (do { ^nu ($INFRA | path join "render-catalog.nu") $t ($out | path join "catalog") } | complete)
                assert equal $cat.exit_code 0 $cat.stderr
                let charts = (do { ^nu ($INFRA | path join "render.nu") $t --charts-into ($out | path join "charts") } | complete)
                assert equal $charts.exit_code 0 $charts.stderr
                let config = (^nu ($INFRA | path join "targets" $t "target.nu") | from nuon)
                # The bootstrap layers (Flux itself) are up.nu's to apply, never published, so never a health check.
                for layer in ($config.apply_layers | where name not-in $BOOTSTRAP_LAYERS) {
                    let docs = ($layer.files | each {|f|
                        let found = ([($out | path join "catalog" $f) ($out | path join "charts" $f)] | where {|p| $p | path exists })
                        if ($found | is-empty) { [] } else { documents (open --raw ($found | first)) }
                    } | flatten)
                    for w in $layer.wait_for {
                        let checked = (try { health_check $w $docs; null } catch {|e| $e.msg })
                        assert equal $checked null $"($t), layer ($layer.name), ($w.ref)"
                    }
                }
                rm -rf $out
            }
        }

        # docs/architecture/authority-model.md, "Multi-instance workloads": the load harness's producer is multi-instance
        # where the credentials agent issues it (its object marked, its pods each an instance in the model), and one
        # instance where a target still has cert-issuer issue it; every other workload is one.
        "the harness producer is multi-instance where the credentials agent issues it, and nothing else is": {
            use ../rules.nu [is_multi_instance, parallelism_problems]
            let o = (object_of "harness-producer" "sandbox-local")
            assert (is_multi_instance $o) "sandbox-local"
            assert equal (parallelism_problems [($o | update spec.parallelism 3)]) [] "it may run three at once"
            assert equal (resolve_for "sandbox-local" "harness-producer").instances "many"
            let on_cert_issuer = (open ($INFRA | path join "targets/sandbox-local/config.nuon") | update workloads.harness-producer.issuer "cert-issuer")
            with_target $on_cert_issuer {|t|
                assert equal (resolve_for $t "harness-producer").instances "one" "issued by cert-issuer there"
            }
            assert (not (is_multi_instance (object_of "harness-sink" "sandbox-local")))
            # The build workload's pods are never issued (docs/architecture/build-orchestrator.md, revised 3): no instances to speak of.
            for n in (^nu $RESOLVER names --target sandbox-local | from json | where {|n| $n not-in ["harness-producer" "build-runner"] }) {
                assert equal (resolve_for "sandbox-local" $n).instances "one" $n
            }
        }

        # docs/architecture/deployments.md, step 4: every workload restarts in place, a Deployment of one; the load harness,
        # which runs to completion, is a Job of the `run` kind.
        "every workload is a Deployment that restarts in place, the load harness a Job, and the build workload a PodTemplate": {
            use ../rules.nu [in_place_problems]
            for t in [sandbox-local] {
                for n in (^nu $RESOLVER names --target $t | from json) {
                    let o = (object_of $n $t)
                    if $n in [harness-producer harness-sink] {
                        assert equal $o.kind "Job" $"($t) ($n)"
                        assert equal $o.spec.template.spec.restartPolicy "Never" $n
                    } else if $n == "build-runner" {
                        assert equal $o.kind "PodTemplate" $"($t) ($n)"
                        assert equal $o.template.spec.restartPolicy "Never" $n
                    } else {
                        assert equal $o.kind "Deployment" $"($t) ($n)"
                        assert equal (in_place_problems [$o]) [] $"($t) ($n)"
                        # cert-issuer has no polar-init, which is what the rule looks for, so its own are checked here.
                        assert equal $o.spec.replicas 1 $n
                        assert equal $o.spec.strategy.type "Recreate" $n
                        let c = ($o.spec.template.spec.containers | first)
                        assert equal $c.restartPolicy "Always" $n
                        assert equal $c.restartPolicyRules [{ action: "RestartAllContainers", exitCodes: { operator: "NotIn", values: [] } }] $n
                    }
                }
            }
        }

        # A container restarted alone finds no marker and exits, so its pod restarts whole: polar-init leaves the
        # marker where the workload takes it, in the health volume, for a Deployment and not for a run's Job.
        "polar-init leaves the start marker where the workload takes it, in a Deployment's pod alone": {
            let marker = "/var/run/polar-health/started-by-polar-init"
            let r = (resolve "kube-consumer")
            assert equal (env_value $r "POLAR_START_MARKER") $marker
            assert equal (init_env_value $r "POLAR_INIT_START_MARKER") $marker
            assert ($r.init_mounts | any {|m| $m.name == "polar-health" and $m.path == "/var/run/polar-health" }) $"($r.init_mounts)"
            let job = (resolve_for sandbox-local "harness-sink")
            assert equal (env_value $job "POLAR_START_MARKER" sandbox-local) null
            assert equal (init_env_value $job "POLAR_INIT_START_MARKER") null
        }

        # A kept certificate must outlast the point the agent rejuvenates at, so polar-init is told the same number.
        "polar-init is told the threshold its workload rejuvenates at, in a Deployment's pod alone": {
            let r = (resolve "polar-scheduler-observer")
            assert equal (init_env_value $r "POLAR_HEALTH_REJUVENATION_SECS") (env_value $r "POLAR_HEALTH_REJUVENATION_SECS")
            assert ((init_env_value $r "POLAR_HEALTH_REJUVENATION_SECS") != null)
            let job = (resolve_for sandbox-local "harness-sink")
            assert equal (init_env_value $job "POLAR_HEALTH_REJUVENATION_SECS") null
        }

        "a target with custody off renders every pod with key files, as before": {
            with_target { cluster: { custody: { enabled: false } }, workloads: {} } {|t|
                let r = (resolve_for $t "kube-observer")
                assert equal $r.custody null
                assert ($r.certs | all {|c| $c | str contains ":ecdsa-p256:" })
                assert equal (env_value $r "TLS_CLIENT_KEY" $t) "/etc/tls/certs/key.pem"
                assert equal (env_value $r "POLAR_CUSTODY_SOCKET" $t) null
            }
        }

        "the credentials agent is given the authority model: every workload of the target, by its one identity": {
            # The credentials agent as this workspace builds it (the images on the cluster may predate the model), and
            # every other agent as its image has it.
            let dir = (mktemp --directory)
            cp ($env.POLAR_SCAFFOLD_DIR | path join "*.json" | into glob) $dir
            let agents = ($INFRA | path dirname | path join "src/agents")
            let built = (do { cd $agents; ^cargo build -q -p credentials-agent-consumer --bin credentials-agent-consumer } | complete)
            assert equal $built.exit_code 0 $"cannot build the credentials agent: ($built.stderr | lines | last 3 | str join '; ')"
            let target_dir = ($env.CARGO_TARGET_DIR? | default ($agents | path join "target"))
            ^($target_dir | path join "debug/credentials-agent-consumer") --scaffold | save --force ($dir | path join "credentials-agent.json")
            let model = (with-env { POLAR_SCAFFOLD_DIR: $dir } {
                env_value (resolve_for "sandbox-local" "credentials-agent") "CREDENTIALS_AGENT_AUTHORITY_MODEL"
            })
            rm -rf $dir
            let m = ($model | from json)
            assert equal $m.format 1
            let named = ($m.workloads | get workload)
            for w in ["cassini" "credentials-agent" "credentials-agent-observer" "polar-scheduler" "polar-scheduler-observer" "polar-git-server" "kube-observer"] {
                assert ($w in $named) $"($w) is not in the model: ($named | str join ', ')"
            }
            for w in $m.workloads {
                assert equal $w.identity $"($w.workload).polar.serviceaccount.cluster.local"
            }
            # A build pod holds no Polar identity (docs/architecture/build-orchestrator.md, revised 3): nothing to issue it.
            assert ("build-runner" not-in $named) "the build workload is never issued"
            assert (not ($model | str contains "system:serviceaccount")) "a token subject in the model"
            let observer = ($m.workloads | where workload == "credentials-agent-observer" | first)
            assert equal [$observer.issuer $observer.bootstrap] ["cert-issuer" true]
        }
        # docs/architecture/soft-state.md: the state agent reads the graph, and its health does not depend on it.
        "the state agent is given the graph's connection, and neither waits for nor watches Neo4j": {
            let r = (resolve "soft-state-observer")
            assert ("graph-read" in $r.needs) ($r.needs | str join ",")
            assert ("graph-write" not-in $r.needs) ($r.needs | str join ",")
            assert equal (env_value $r "GRAPH_CLIENT_CERT") "/etc/tls/certs/cert.pem"
            assert ((env_value $r "GRAPH_ENDPOINT") | str starts-with "bolt+s://")
            assert equal $r.certs ["client:/etc/tls/certs:custody:"]
            assert ($r.dep_checks | all {|d| not ($d | str contains "neo4j") and not ($d | str contains "polar-db") }) ($r.dep_checks | str join ",")
            let deps = (env_value $r "POLAR_HEALTH_DEP_ENDPOINTS")
            assert equal ($deps | split row "," | length) 1 $deps
        }

        "the state agent's first schema is made from every workload's scaffold, and a read nobody owns fails the check": {
            # Stand-in graph declarations on the real scaffolds: jira-processor owns JiraIssue, jira-observer reads it.
            let dir = (mktemp --directory)
            cp ($env.POLAR_SCAFFOLD_DIR | path join "*.json" | into glob) $dir
            let declare = {|name: string, graph: list|
                let file = ($dir | path join $"($name).json")
                open $file | upsert graph $graph | to json | save --force $file
            }
            do $declare "jira-processor" [{ label: "JiraIssue", access: "owns", purpose: "the issues" }]
            do $declare "jira-observer" [{ label: "JiraIssue", access: "reads", purpose: "its cursor" }]
            let schema = (with-env { POLAR_SCAFFOLD_DIR: $dir } { ^nu $RESOLVER state-schema } | from json)
            assert equal ($schema | columns) ["workloads"]
            let observer = ($schema.workloads | where workload == "jira-observer" | first)
            assert equal $observer { workload: "jira-observer", identity: "jira-observer.polar.serviceaccount.cluster.local", owns: [], reads: ["JiraIssue"] }
            assert equal ($schema.workloads | where workload == "jira-processor" | first | get owns) ["JiraIssue"]
            # The state agent's document carries no floor and no readers: its schema is signed configuration.
            let r = (with-env { POLAR_SCAFFOLD_DIR: $dir } { resolve "soft-state-observer" })
            for name in ["SOFT_STATE_FLOOR" "POLAR_STATE_READERS"] {
                assert equal (with-env { POLAR_SCAFFOLD_DIR: $dir } { env_value $r $name }) null $name
            }
            # Its reply family is over the served workloads, as the scheduler's is.
            assert ((with-env { POLAR_SCAFFOLD_DIR: $dir } { env_value $r "POLAR_SERVED_WORKLOADS" }) | str contains "jira-observer")
            # A read of a label no workload owns is named by the check.
            do $declare "jira-observer" [{ label: "JiraIssue", access: "reads", purpose: "its cursor" } { label: "Nobody", access: "reads", purpose: "x" }]
            let checked = (with-env { POLAR_SCAFFOLD_DIR: $dir } { do { ^nu $RESOLVER check } | complete })
            rm -rf $dir
            assert ($checked.exit_code != 0) "the check passed"
            assert ($checked.stderr | str contains "jira-observer reads Nobody, and no workload in sandbox-local owns it") $checked.stderr
            assert (not ($checked.stderr | str contains "reads JiraIssue")) $checked.stderr
        }

        "a target that runs an agent needing the state agent and not the state agent fails the check": {
            let config = (open ($INFRA | path join "targets/sandbox-local/config.nuon"))
            let workloads = ($config.workloads | upsert soft-state-observer { enabled: false, issuer: "credentials-agent" })
            with_target ($config | upsert workloads $workloads) {|t|
                let checked = (do { ^nu $RESOLVER check --target $t } | complete)
                assert ($checked.exit_code != 0) "the check passed"
                assert ($checked.stderr | str contains "jira-observer needs soft-state, which needs the workload soft-state-observer") $checked.stderr
            }
        }

        "every workload's budget is in what the agent is given, as the code declared": {
            for w in ($BUDGETS | transpose name secs) {
                let t = (target_for $w.name)
                let r = (resolve_for $t $w.name)
                assert equal (env_value $r "POLAR_SHUTDOWN_BUDGET_SECS" $t) ($w.secs | into string) $"($w.name)"
            }
        }

        "the grace period is the budget plus the margin": {
            for w in ($BUDGETS | transpose name secs) {
                let r = (resolve_for (target_for $w.name) $w.name)
                assert equal $r.termination_grace_secs ($w.secs + 10) $"($w.name)"
            }
        }

        "the grace period is never set separately from the budget": {
            # It is derived, so a workload entry cannot make the two disagree.
            for w in ($BUDGETS | transpose name secs) {
                let t = (target_for $w.name)
                let r = (resolve_for $t $w.name)
                assert (($r.termination_grace_secs) > (env_value $r "POLAR_SHUTDOWN_BUDGET_SECS" $t | into int)) $"($w.name)"
            }
        }

        "the image an agent's check pulls is a row of images.nuon, and the crate it builds is named separately": {
            # The check pulls by the image's name; the crate (cargo -p) is named for the package. For a workload
            # whose crate is not named for its image, the two differ, and looking the package up in the images
            # table finds no row (cassini-broker, polar-scheduler-observer).
            let rows = (open ($INFRA | path join "images.nuon") | get image)
            let names = (^nu $RESOLVER names | from json)
            assert (($names | length) > 0) "the catalog lists workloads"
            for n in $names {
                let a = (^nu $RESOLVER agent-names $n | from json)
                assert ($a.image in $rows) $"($n): image '($a.image)' has no row in images.nuon"
            }
        }

        "a workload whose crate is not named for its image is checked as that crate, and pulled as that image": {
            let a = (^nu $RESOLVER agent-names cassini | from json)
            assert equal $a { image: "cassini", package: "cassini-broker" }
            let b = (^nu $RESOLVER agent-names polar-scheduler-observer | from json)
            assert equal $b { image: "scheduler-observer", package: "polar-scheduler-observer" }
            # One named for its image is both.
            let c = (^nu $RESOLVER agent-names kube-consumer | from json)
            assert equal $c.image $c.package
        }

        "a workload a target disables is left out of what is listed and rendered for that target, and only that target": {
            with_target { workloads: { kube-observer: { enabled: false } } } {|t|
                let names = (^nu $RESOLVER names --target $t | from json)
                assert (not ("kube-observer" in $names)) "the disabled workload was listed"
                assert ("kube-consumer" in $names) "a workload that is not disabled was dropped"
                assert ("kube-observer" in (^nu $RESOLVER names | from json)) "the default target lost it"
            }
        }

        "the images of a workload a target disables are not built for it": {
            with_target { workloads: { kube-observer: { enabled: false } } } {|t|
                let with = (^nu $RESOLVER document-images | from json)
                let without = (^nu $RESOLVER document-images --target $t | from json)
                assert ("kube-observer" in $with)
                assert (not ("kube-observer" in $without)) "its image would be built for nothing"
                assert ("kube-consumer" in $without)
            }
        }

        "resolving a workload the target disables says so, and does not pretend it is unknown": {
            with_target { workloads: { kube-observer: { enabled: false } } } {|t|
                let off = (do { ^nu $RESOLVER json kube-observer --target $t } | complete)
                assert ($off.exit_code != 0)
                assert ($off.stderr | str contains "not enabled") $off.stderr
                assert ($off.stderr | str contains $t) $off.stderr
                let unknown = (do { ^nu $RESOLVER json no-such-workload --target $t } | complete)
                assert ($unknown.stderr | str contains "no workload named") $unknown.stderr
            }
        }

        "enabled is true or false and nothing else": {
            with_target { workloads: { kube-observer: { enabled: "no" } } } {|t|
                let r = (do { ^nu $RESOLVER check --target $t } | complete)
                assert ($r.exit_code != 0)
                assert (($r.stdout + $r.stderr) | str contains "enabled") ($r.stdout + $r.stderr)
            }
        }

        "a disabled workload that is still in the target's apply order is a problem, named": {
            with_target { workloads: { kube-observer: { enabled: false } } } {|t|
                let target_nu = ($INFRA | path join "targets" $t "target.nu")
                '{ apply_order: ["kube-observer-resources.yaml", "kube-observer.yaml", "kube-consumer.yaml"] } | to nuon' | save --force $target_nu
                let r = (do { ^nu $RESOLVER check --target $t } | complete)
                let out = ($r.stdout + $r.stderr)
                assert ($r.exit_code != 0) $out
                assert ($out | str contains "kube-observer.yaml") $out
                assert ($out | str contains "kube-observer-resources.yaml") $out
                assert (not ($out | str contains "kube-consumer.yaml")) "a workload that is enabled was named"
            }
        }

        "a target that disables a workload and leaves it out of its apply order checks clean": {
            # Starting from a real target's configuration: a bare one has no Jira address and fails for that alone.
            let real = (open ($INFRA | path join "targets/sandbox-local/config.nuon"))
            with_target ($real | merge deep { workloads: { kube-observer: { enabled: false } } }) {|t|
                let target_nu = ($INFRA | path join "targets" $t "target.nu")
                '{ apply_order: ["kube-consumer.yaml"] } | to nuon' | save --force $target_nu
                let r = (do { ^nu $RESOLVER check --target $t } | complete)
                assert equal $r.exit_code 0 ($r.stdout + $r.stderr)
            }
        }

        "the health settings the agent validates are in what the agent is given": {
            let r = (resolve "kube-consumer")
            assert equal (env_value $r "POLAR_HEALTH_REJUVENATION_SECS") "300"
            assert equal (env_value $r "POLAR_HEALTH_STALE_SECS") "90"
            assert equal (env_value $r "POLAR_HEALTH_TICK_SECS") "30"
            assert equal (env_value $r "POLAR_HEALTH_EXPIRY_SECS") "60"
        }

        "the settings the rules read are available for each workload": {
            let st = (settings "kube-consumer")
            assert equal $st.shutdown.budget_secs 45
            assert equal $st.shutdown.grace_margin_secs 10
            assert equal $st.shutdown.termination_grace_secs 55
            assert equal $st.health.rejuvenation_secs 300
        }

        "the real catalog passes `check`, including the agent's own environment check": {
            let r = (^nu ($RESOLVER) check | complete)
            assert equal $r.exit_code 0 $r.stderr
            assert ($r.stdout | str contains "resolve cleanly")
        }

        "the credentials consumer keeps its ledger on a persistent volume it is given as a claim": {
            let r = (resolve "credentials-agent")
            let data = ($r.volumes | where name == "credentials-agent-data")
            assert equal ($data | length) 1
            assert equal ($data | first | get claim) "credentials-agent-data"
            assert equal ($r.mounts | where name == "credentials-agent-data" | first | get path) "/var/lib/credentials-agent"
            let res = (^nu $RESOLVER resources credentials-agent | from json)
            assert equal ($res.pvcs | get name) ["credentials-agent-data"]
        }

        "a workload whose code does not need the graph can still be given it": {
            # The consumer writes the graph through its own section and must not need it to be
            # healthy, so the entry provides it; the pod gets the same as for any graph-write.
            let r = (resolve "credentials-agent")
            assert ("graph-write" in $r.needs)
            assert (env_value $r "GRAPH_ENDPOINT" | is-not-empty)
            assert (env_value $r "POLAR_HEALTH_DEP_ENDPOINTS" | str contains "polar-db-svc")
            assert equal (env_value $r "POLAR_CAPABILITIES" | split row "," | sort) ($r.needs | sort)
        }

        "a workload that must start without its dependencies is watched for them but does not wait at start": {
            let consumer = (resolve "credentials-agent")
            assert equal $consumer.dep_checks []
            let health = (env_value $consumer "POLAR_HEALTH_DEP_ENDPOINTS")
            assert ($health | str contains "cassini-ip-svc")
            assert ($health | str contains "polar-db-svc")
            # and one that does not say so waits, as every agent did
            assert (resolve "kube-consumer" | get dep_checks | is-not-empty)
        }

        "only an agent that needs encryption escrows a key in init, and the escrow authority does not": {
            # The escrowed keypair is read only by a crypto actor, so the bootstrap follows the `encryption` need
            # the scaffold declares (docs/architecture/policy-enforcement.md, "Decisions", 2026-10-22).
            # jira-observer since 3.0.0: its credential is an escrowed secret its crypto actor opens (jira.md, "The credential").
            for name in ["kube-consumer" "jira-observer"] {
                let r = (resolve $name)
                assert equal (init_env_value $r "POLAR_INIT_ESCROW_BOOTSTRAP") "true" $"($name) escrows its key"
                assert ("encryption" in $r.needs) $"($name) needs encryption"
            }
            for name in ["kube-observer" "credentials-agent" "credentials-agent-observer"] {
                let r = (resolve $name)
                assert ("encryption" not-in $r.needs) $"($name) does not need encryption"
                assert equal (init_env_value $r "POLAR_INIT_ESCROW_BOOTSTRAP") null $"($name) escrows nothing"
            }
            # and the old switch is gone from every pod
            for name in ["kube-consumer" "credentials-agent" "cassini"] {
                assert ((resolve $name).init_env | where name == "POLAR_INIT_SKIP_ESCROW_BOOTSTRAP" | is-empty)
            }
        }

        "the observer is a Service on the port its code listens on": {
            let r = (resolve "credentials-agent-observer")
            assert equal $r.ports [8080]
            assert equal (env_value $r "CREDENTIALS_AGENT_OBSERVER_PORT") "8080"
            let res = (^nu $RESOLVER resources credentials-agent-observer | from json)
            assert equal ($res.services | get name) ["credentials-agent-observer"]
            assert equal ($res.services | first | get selector) "credentials-agent-observer"
            assert equal ($res.services | first | get ports | get port) [8080]
        }

        "both trust cert-issuer's CA from the first request, as a mounted file": {
            for n in ["credentials-agent" "credentials-agent-observer"] {
                let r = (resolve $n)
                assert ($r.volumes | any {|v| $v.name == "polar-ca" and $v.config_map == "polar-ca" }) $n
                assert ($r.init_env | any {|e| $e.name == "POLAR_INIT_CA_CERT" and $e.value == "/etc/polar-ca/ca.pem" }) $n
                assert ($r.init_mounts | any {|m| $m.path == "/etc/polar-ca" }) $n
            }
            assert equal (env_value (resolve "credentials-agent") "CREDENTIALS_AGENT_CA_CERT") "/etc/polar-ca/ca.pem"
        }

        "every workload that runs polar-init trusts cert-issuer's CA as a mounted file, and cert-issuer, the CA, and a template, which is never issued, mount none": {
            # The observer path verifies what it is issued against the pinned CA (docs/architecture/core-restarts.md,
            # "The plan", step 1), so no workload is left to fetch it unverified.
            for n in (^nu $RESOLVER names | from json) {
                let r = (resolve $n)
                if $r.kind in ["ca" "template"] {
                    assert (not ($r.volumes | any {|v| $v.name == "polar-ca" })) $n
                } else {
                    assert ($r.volumes | any {|v| $v.name == "polar-ca" and $v.config_map == "polar-ca" }) $n
                    assert ($r.init_env | any {|e| $e.name == "POLAR_INIT_CA_CERT" and $e.value == "/etc/polar-ca/ca.pem" }) $n
                    assert ($r.init_mounts | any {|m| $m.path == "/etc/polar-ca" }) $n
                    # And on the observer path, whose offers it is to believe (step 1c).
                    if (init_env_value $r "POLAR_INIT_ISSUER") == "credentials-agent" {
                        assert equal (init_env_value $r "POLAR_INIT_CREDENTIALS_AGENT_IDENTITY") "credentials-agent.polar.serviceaccount.cluster.local" $n
                    }
                }
            }
        }

        "the consumer is told where cert-issuer is, from the catalog's facts": {
            let r = (resolve "credentials-agent")
            assert equal (env_value $r "CREDENTIALS_AGENT_CERT_ISSUER_URL") $r.cert_issuer_url
        }

        "the broker is a service, not a client: it needs nothing and is not given a Cassini client": {
            let r = (resolve "cassini")
            assert ("cassini" not-in $r.needs)
            assert equal $r.kind "service"
            # none of the client's variables are in its document, and it does not wait for Cassini
            let maps = (^nu $RESOLVER resources cassini | from json | get config_maps)
            let sections = ($maps | first | get content | from json | get sections | get name)
            assert ("cassini-client" not-in $sections)
            assert ("cassini-broker" in $sections)
            assert equal $r.dep_checks []
        }

        "the broker is given a server certificate for the Cassini service's name, read-only": {
            # With the custody daemon (the default), its key the daemon's; on key files, its key a file beside it.
            let r = (resolve "cassini")
            assert equal $r.certs ["server:/etc/tls/certs:custody:cassini-ip-svc.polar.svc.cluster.local"]
            assert ($r.mounts | any {|m| $m.name == "polar-certs" and $m.read_only })
            assert equal (env_value $r "TLS_SERVER_CERT_CHAIN") "/etc/tls/certs/cert.pem"
            assert equal (env_value $r "CASSINI_BIND_ADDR") "0.0.0.0:8080"
            with_target { cluster: { custody: { enabled: false } }, workloads: {} } {|t|
                let r = (resolve_for $t "cassini")
                assert equal $r.certs ["server:/etc/tls/certs:ecdsa-p256:cassini-ip-svc.polar.svc.cluster.local"]
                assert ($r.mounts | any {|m| $m.name == "polar-certs" and $m.read_only })
                assert equal (env_value $r "TLS_SERVER_CERT_CHAIN" $t) "/etc/tls/certs/cert.pem"
                assert equal (env_value $r "TLS_SERVER_KEY" $t) "/etc/tls/certs/key.pem"
                assert equal (env_value $r "CASSINI_BIND_ADDR" $t) "0.0.0.0:8080"
            }
        }

        "the broker's shutdown token is a secret the pod is given from a Secret": {
            let r = (resolve "cassini")
            let token = ($r.env | where name == "CASSINI_SHUTDOWN_TOKEN")
            assert equal ($token | length) 1
            assert equal ($token | first | get secret) "cassini-shutdown-token"
            assert equal ($token | first | get key) "token"
            assert equal ($token | first | get value) null
        }

        "the broker starts without the escrow bootstrap, which needs the broker": {
            assert equal (init_env_value (resolve "cassini") "POLAR_INIT_ESCROW_BOOTSTRAP") null
        }

        "the broker's Service has the name its clients use, selects the broker, and exposes the one port it listens on": {
            let r = (resolve "cassini")
            assert equal $r.ports [8080]
            let res = (^nu $RESOLVER resources cassini | from json)
            let service = ($res.services | first)
            assert equal $service.name "cassini-ip-svc"
            assert equal $service.selector "cassini"
            assert equal ($service.ports | get port) [8080]
            assert equal ($service.ports | get name) ["cassini-tcp"]
        }

        "every workload exports its traces to Jaeger's OTLP port, not the UI's": {
            for n in ["cassini" "kube-consumer" "kube-observer" "jira-observer" "jira-processor" "credentials-agent" "credentials-agent-observer"] {
                let r = (resolve $n)
                assert equal (env_value $r "JAEGER_OTLP_ENDPOINT") "http://jaeger-svc.polar.svc.cluster.local:4318/v1/traces" $n
            }
        }

        "the broker's logging is the deployment's section every agent has, not a variable of its own": {
            let r = (resolve "cassini")
            assert equal (env_value $r "CASSINI_LOG") null
            assert equal (env_value $r "RUST_LOG") null "the default, info, is not written down"
        }

        "the broker's health check watches the CA's certificate as well as its own": {
            let r = (resolve "cassini")
            assert equal (env_value $r "POLAR_HEALTH_CERTS") "/etc/tls/certs/cert.pem,/etc/tls/certs/ca.pem"
            # an agent still watches its own certificate only
            let agent = (resolve "kube-consumer")
            assert equal (env_value $agent "POLAR_HEALTH_CERTS") "/etc/tls/certs/cert.pem"
        }

        "a kind can extend another and change only what differs": {
            let kinds = (open ($RESOLVER | path dirname | path join "config/kinds.nuon"))
            assert equal ($kinds.service.extends) "agent"
            # not a client, but it still sends its traces, and its polar-init pins cert-issuer's CA
            assert equal ($kinds.service | get -o needs) ["tracing" "pinned-ca"]
            # cert-issuer is the CA: it extends the service and pins nothing
            assert equal ($kinds.ca.extends) "service"
            assert equal ($kinds.ca | get -o needs) ["tracing"]
        }

        "the resolver is given no registry credentials: they are its signed credentials section's": {
            let r = (resolve_for "sandbox-local" "oci-registry-resolver")
            assert equal ($r.volumes | where name == "oci-registry-auth" | length) 0
            assert equal ($r.mounts | where name == "oci-registry-auth" | length) 0
            assert equal (env_value $r "DOCKER_CONFIG") null
        }

        "the resolver speaks http to the cluster's own development registry, which the target names": {
            let r = (resolve_for "sandbox-local" "oci-registry-resolver")
            assert ((env_value $r "OCI_INSECURE_REGISTRIES") | str contains (node_registry "sandbox-local"))
        }

        "the git observer is a plain agent: Cassini only, its cache in the pod, and no graph": {
            let r = (resolve "git-repo-observer")
            assert ("graph-write" not-in $r.needs)
            assert equal (env_value $r "POLAR_CACHE_ROOT") "/var/lib/git-repo-observer/cache"
            assert ($r.mounts | any {|m| $m.path == "/var/lib/git-repo-observer" and not $m.read_only })
            assert equal $r.service_account "git-repo-observer"
        }

        "the git processor writes to the graph and needs no cache; the controller does neither": {
            let r = (resolve "git-repo-processor")
            assert ("graph-write" in $r.needs)
            assert equal $r.service_account "git-repo-processor"
            let c = (resolve "git-repo-controller")
            assert ("graph-write" not-in $c.needs)
            assert equal $c.service_account "git-repo-controller"
            assert ($c.mounts | where path =~ "cache" | is-empty)
        }

        "a volume that is not a Secret with items has none": {
            let r = (resolve "kube-consumer")
            assert ($r.volumes | all {|v| $v.items == [] })
        }

        "the bootstrap identities ask cert-issuer, and every other workload does until a target moves it": {
            # An empty target, so this says what the catalog's defaults are and not how far the rollout has got.
            with_target { workloads: {} } {|t|
                for n in [cassini credentials-agent credentials-agent-observer] {
                    let r = (^nu $RESOLVER json $n --target $t | from json)
                    let st = (^nu $RESOLVER settings $n --target $t | from json)
                    assert equal $st.issuer "cert-issuer" $n
                    assert $st.bootstrap $n
                    assert ($r.cert_issuer_url | str starts-with "https://cert-issuer.") $n
                }
                let k = (^nu $RESOLVER json kube-consumer --target $t | from json)
                let ks = (^nu $RESOLVER settings kube-consumer --target $t | from json)
                assert equal $ks.issuer "cert-issuer"
                assert (not $ks.bootstrap)
                assert equal (init_env_value $k "POLAR_INIT_ISSUER") null
            }
        }

        "a workload moved onto the credentials agent is told the observer's address and not cert-issuer's": {
            with_target { workloads: { kube-consumer: { issuer: "credentials-agent" } } } {|t|
                let r = (^nu $RESOLVER json kube-consumer --target $t | from json)
                assert equal (^nu $RESOLVER settings kube-consumer --target $t | from json | get issuer) "credentials-agent"
                assert equal (init_env_value $r "POLAR_INIT_ISSUER") "credentials-agent"
                assert equal (init_env_value $r "POLAR_INIT_OBSERVER_URL") "http://credentials-agent-observer.polar.svc.cluster.local:8080"
                assert equal (init_env_value $r "POLAR_INIT_CREDENTIALS_AGENT_IDENTITY") "credentials-agent.polar.serviceaccount.cluster.local"
                assert equal $r.cert_issuer_url ""
            }
        }

        "the identity a workload checks the credentials agent's offers against is the catalog's credentials agent": {
            # docs/architecture/core-restarts.md, "1c in detail": polar-init seals its token only to an offer signed by
            # a signing certificate naming the credentials agent, as `model_facts` writes identities.
            with_target { workloads: { kube-consumer: { issuer: "credentials-agent" }, credentials-agent: { namespace: "polar-creds" } } } {|t|
                let r = (^nu $RESOLVER json kube-consumer --target $t | from json)
                assert equal (init_env_value $r "POLAR_INIT_CREDENTIALS_AGENT_IDENTITY") "credentials-agent.polar-creds.serviceaccount.cluster.local"
                assert equal (^nu $RESOLVER identity credentials-agent --target $t | str trim) "credentials-agent.polar-creds.serviceaccount.cluster.local"
            }
            # A bootstrap service asks cert-issuer, and is offered nothing to check.
            assert equal (init_env_value (resolve "cassini") "POLAR_INIT_CREDENTIALS_AGENT_IDENTITY") null
        }

        "a bootstrap identity cannot be moved onto the credentials agent": {
            with_target { workloads: { cassini: { issuer: "credentials-agent" } } } {|t|
                let r = (^nu $RESOLVER check --target $t | complete)
                assert ($r.exit_code != 0)
                assert ($r.stderr | str contains "cassini")
            }
        }

        "an issuer that is neither is refused": {
            with_target { workloads: { kube-consumer: { issuer: "vault" } } } {|t|
                let r = (^nu $RESOLVER check --target $t | complete)
                assert ($r.exit_code != 0)
                assert ($r.stderr | str contains "vault")
            }
        }

        "workloads still asking cert-issuer are listed as pending while the floor is off, and refused once it is enforced": {
            # Everything on cert-issuer, as the catalog's defaults have it. The Jira observer and cert-issuer need the
            # settings a target gives them (cert-issuer the token issuers it trusts), or `check` would fail for those and
            # not for what this is about.
            let jira = {
                jira-observer: { env: [
                    { name: "JIRA_URL", value: "https://example.atlassian.net" }
                ] }
                cert-issuer: { env: [
                    { name: "CERT_ISSUER_ISSUERS", value: [{
                        issuer: "https://kubernetes.default.svc.cluster.local"
                        audience: ["polar-cert-issuer.local"]
                        jwks_uri: "https://kubernetes.default.svc.cluster.local/openid/v1/jwks"
                        workload_identity_claim: "sub"
                        instance_binding_claim: "kubernetes.io/pod/uid"
                        identity_normalization: { strategy: "kubernetes_service_account", cluster_domain: "cluster.local" }
                        identity_scope_claim: null
                        allowed_algorithms: ["RS256"]
                        jwks_cache_ttl_min: { secs: 30, nanos: 0 }
                        jwks_cache_ttl_max: { secs: 3600, nanos: 0 }
                    }] }
                ] }
            }
            with_target { workloads: $jira } {|t|
                let off = (^nu $RESOLVER check --target $t | complete)
                assert equal $off.exit_code 0 $off.stderr
                assert ($off.stdout | str contains "pending")
                assert ($off.stdout | str contains "kube-consumer")
            }
            with_target { cluster: { issuance: { floor_enforced: true } }, workloads: $jira } {|t|
                let on = (^nu $RESOLVER check --target $t | complete)
                assert ($on.exit_code != 0)
                assert ($on.stderr | str contains "kube-consumer")
            }
        }

        "on the sandbox-local target no catalog workload asks cert-issuer directly but the bootstrap identities": {
            # The state phase 6 of the cert-issuer isolation reached (docs/architecture/cert-issuer-isolation.md).
            let r = (^nu $RESOLVER check | complete)
            assert equal $r.exit_code 0 $r.stderr
            assert (not ($r.stdout | str contains "pending"))
        }

        # The test above runs each agent's image, so it needs a cluster, and a workload left on cert-issuer was only found when
        # its pod could not start. This reads the settings alone.
        "a workload on the sandbox-local target asks the credentials agent for its certificates unless it is a bootstrap identity, or a template, which asks for none": {
            for n in (^nu $RESOLVER names | from json) {
                # A template's pods hold no Polar identity (docs/architecture/build-orchestrator.md, revised 3): no polar-init asks.
                if (resolve $n).kind == "template" {
                    assert ("polar_init_image" not-in (resolve $n | columns)) $n
                    continue
                }
                let s = (settings $n)
                assert ($s.bootstrap or $s.issuer == "credentials-agent") $"($n) asks ($s.issuer)"
            }
        }

        "the floor is written from the catalog: the bootstrap identities, then a vouched-only entry for each server certificate on the credentials agent": {
            let f = (^nu $RESOLVER floor | from json)
            let cassini = ($f | where workload == "system:serviceaccount:polar:cassini" | first)
            assert equal $cassini.certType "SERVER"
            assert equal $cassini.names ["cassini-ip-svc.polar.svc.cluster.local"]
            assert (not $cassini.vouchedOnly)
            for w in [credentials-agent credentials-agent-observer] {
                let e = ($f | where workload == $"system:serviceaccount:polar:($w)" | first)
                assert equal $e.certType "CLIENT"
            }
            # A workload still on cert-issuer has no entry; one moved onto the credentials agent that is issued a
            # server certificate has a vouched-only one.
            with_target { workloads: {} } {|t|
                let before = (^nu $RESOLVER floor --target $t | from json)
                assert equal ($before | where workload == "system:serviceaccount:polar:polar-git-server" | length) 0
            }
            with_target { workloads: { polar-git-server: { issuer: "credentials-agent" } } } {|t|
                let moved = (^nu $RESOLVER floor --target $t | from json)
                let g = ($moved | where workload == "system:serviceaccount:polar:polar-git-server" | first)
                assert equal $g.certType "SERVER"
                assert $g.vouchedOnly
                assert equal $g.names ["polar-git-server.polar.svc.cluster.local"]
            }
        }

        "scaffolds writes one file for each agent, named by the name the agent gives itself": {
            # Stand-in scaffolds, so nothing is built: one per workload, each naming its agent differently from
            # the workload, to show the file is named by what the agent says.
            let stubs = (mktemp --directory)
            let out = (mktemp --directory)
            let names = (^nu $RESOLVER names | from json)
            for n in $names {
                { agent: { name: $"agent-of-($n)" }, sections: [], runtime: [] } | to json | save --force ($stubs | path join $"($n).json")
            }
            let agents = ($names | where {|n| (resolve $n).kind in ["agent" "run"] } | length)
            with-env { POLAR_SCAFFOLD_DIR: $stubs } { ^nu $RESOLVER scaffolds $out | ignore }
            let written = (ls $out | get name | each {|f| $f | path basename } | sort)
            assert equal ($written | length) $agents
            assert ($written | all {|f| $f | str starts-with "agent-of-" })
            let one = (open ($out | path join ($written | first)))
            assert ($one.agent.name | str starts-with "agent-of-")
            rm -rf $stubs $out
        }

        "a graph agent presents the pod's one client certificate to Neo4j and does not ask for a second": {
            # Two client certificates for one pod instance is what the credentials agent refuses (and a second
            # would revoke the first), and the second was the same identity and type with no extra names, so
            # Neo4j is shown the certificate the pod already has.
            # With the custody daemon (the default), the key is the daemon's and neo4rs is handed its configuration; on
            # key files, the key is the file beside the certificate.
            for n in [kube-consumer jira-processor polar-scheduler git-repo-processor credentials-agent] {
                let r = (resolve $n)
                assert equal $r.certs ["client:/etc/tls/certs:custody:"] $n
                assert ($r.volumes | where name == "neo4j-client-tls" | is-empty) $n
                assert ($r.mounts | where name == "neo4j-client-tls" | is-empty) $n
                assert ($r.init_mounts | where name == "neo4j-client-tls" | is-empty) $n
                assert equal (env_value $r "GRAPH_CLIENT_CERT") "/etc/tls/certs/cert.pem" $n
                assert equal (env_value $r "GRAPH_CLIENT_KEY") null $n
                assert equal (env_value $r "POLAR_CUSTODY_SOCKET") "/run/polar-custody/custody.sock" $n
                assert equal (env_value $r "GRAPH_CA_CERT") "/etc/tls/certs/ca.pem" $n
            }
            # kube-consumer encrypts, so with custody off it is refused, not rendered on key files ("a target with custody
            # off refuses an agent that encrypts").
            with_target { cluster: { custody: { enabled: false } }, workloads: {} } {|t|
                for n in [jira-processor polar-scheduler git-repo-processor credentials-agent] {
                    let r = (resolve_for $t $n)
                    assert equal $r.certs ["client:/etc/tls/certs:ecdsa-p256:"] $n
                    assert ($r.volumes | where name == "neo4j-client-tls" | is-empty) $n
                    assert ($r.mounts | where name == "neo4j-client-tls" | is-empty) $n
                    assert ($r.init_mounts | where name == "neo4j-client-tls" | is-empty) $n
                    assert equal (env_value $r "GRAPH_CLIENT_CERT" $t) "/etc/tls/certs/cert.pem" $n
                    assert equal (env_value $r "GRAPH_CLIENT_KEY" $t) "/etc/tls/certs/key.pem" $n
                    assert equal (env_value $r "GRAPH_CA_CERT" $t) "/etc/tls/certs/ca.pem" $n
                }
            }
        }

        "the health check watches the one certificate a graph agent has": {
            let r = (resolve "kube-consumer")
            let certs = (env_value $r "POLAR_HEALTH_CERTS")
            assert ($certs | str contains "/etc/tls/certs/cert.pem")
            assert (not ($certs | str contains "neo4j-client-tls"))
        }

        "the address of a service comes from services.nuon, and a service with no URL is an error": {
            let url = (^nu $RESOLVER service-url credentials-agent-observer | str trim)
            assert equal $url "http://credentials-agent-observer.polar.svc.cluster.local:8080"
            let missing = (^nu $RESOLVER service-url cassini | complete)
            assert ($missing.exit_code != 0)
            let unknown = (^nu $RESOLVER service-url no-such-service | complete)
            assert ($unknown.exit_code != 0)
        }

        # docs/architecture/egress.md: a target that sets nothing renders as before.
        "for every real target, egress absent and egress {} resolve every workload the same": {
            for t in ["sandbox-local"] {
                let config = (open ($INFRA | path join "targets" $t "config.nuon"))
                let cluster = ($config.cluster? | default {} | reject -o egress)
                let absent = (with_target ($config | upsert cluster $cluster) {|x| resolve_all $x })
                let empty = (with_target ($config | upsert cluster ($cluster | insert egress {})) {|x| resolve_all $x })
                assert ($absent | is-not-empty) $t
                assert equal $empty $absent $t
            }
        }

        "with a proxy and a CA, each agent that declares the egress section gains exactly them, and nothing else changes": {
            let config = (open ($INFRA | path join "targets/sandbox-local/config.nuon"))
            let pem = (fake_pem)
            let base = (with_target $config {|t| resolve_all $t })
            let egress = { proxy: "http://proxy.corp.example:3128", ca_file: "trust/corp-root-ca.pem" }
            let with = (with_target ($config | upsert cluster (($config.cluster? | default {}) | insert egress $egress)) {|t|
                target_file $t "trust/corp-root-ca.pem" $pem
                resolve_all $t
            })
            # A template runs no Polar binary of its own, so it has no scaffold and declares nothing.
            let declaring = ($with | where {|w| $w.r.kind != "template" } | get name | where {|n| "POLAR_EGRESS_PROXY" in (declared_of $n) } | sort)
            assert equal $declaring $EGRESS_AGENTS
            assert equal ($with | get name) ($base | get name)
            for w in $with {
                let b = ($base | where name == $w.name | first | get r)
                let r = $w.r
                for k in [init_env init_mounts custody env] {
                    assert equal ($r | get $k) ($b | get $k) $"($w.name): ($k)"
                }
                if not ($w.name in $declaring) {
                    assert equal $r $b $w.name
                    continue
                }
                let cm = $"($w.name)-egress-ca"
                let fields = [name secret audience config_map claim items]
                assert equal ($r.volumes | where name != "polar-egress-ca") $b.volumes $w.name
                assert equal ($r.volumes | where name == "polar-egress-ca" | select ...$fields) [{ name: "polar-egress-ca", secret: null, audience: null, config_map: $cm, claim: null, items: [] }] $w.name
                assert equal ($r.mounts | where name != "polar-egress-ca") $b.mounts $w.name
                assert equal ($r.mounts | where name == "polar-egress-ca" | select name path read_only) [{ name: "polar-egress-ca", path: "/etc/polar-egress-ca", read_only: true }] $w.name
                assert equal $r.resources.config_maps [{ name: $cm, key: "ca.pem", content: $pem }] $w.name
                assert equal $b.resources.config_maps [] $w.name
                assert equal (document_variables $r | where section != "egress") (document_variables $b | where section != "egress") $w.name
                assert (document_variables $b | where section == "egress" | get value | all {|v| $v == null }) $w.name
                let given = (document_variables $r | where section == "egress" | reduce --fold {} {|v, acc| $acc | insert $v.name $v.value })
                assert equal $given.POLAR_EGRESS_PROXY "http://proxy.corp.example:3128" $w.name
                assert equal $given.POLAR_EGRESS_NO_PROXY "localhost,127.0.0.1,::1,.svc,.cluster.local" $w.name
                assert equal $given.POLAR_EGRESS_CA_CERT "/etc/polar-egress-ca/ca.pem" $w.name
                let rest = [volumes mounts config_map resources _from]
                assert equal ($r | reject ...$rest) ($b | reject ...$rest) $w.name
            }
        }

        "an agent is given the proxy and a bypass list that keeps the cluster's own names, and its document stays the first ConfigMap": {
            let config = (open ($INFRA | path join "targets/sandbox-local/config.nuon"))
            let egress = { proxy: "http://proxy.corp.example:3128", no_proxy: [".corp.example" "10.20.0.0/16"], ca_file: "trust/ca.pem" }
            with_target ($config | upsert cluster (($config.cluster? | default {}) | insert egress $egress)) {|t|
                target_file $t "trust/ca.pem" (fake_pem)
                let r = (resolve_for $t "jira-observer")
                assert equal (env_value $r "POLAR_EGRESS_PROXY" $t) "http://proxy.corp.example:3128"
                let bypass = (env_value $r "POLAR_EGRESS_NO_PROXY" $t | split row ",")
                for host in [".svc" ".cluster.local" "localhost" ".corp.example" "10.20.0.0/16"] {
                    assert ($host in $bypass) $"($host) in ($bypass)"
                }
                let maps = (^nu $RESOLVER resources jira-observer --target $t | from json | get config_maps | get name)
                assert equal $maps ["jira-observer-config" "jira-observer-egress-ca"]
            }
        }

        # Since 3.0.0 the catalog gives jira-observer no Secret: its credential is its signed `credentials` section
        # (docs/architecture/jira.md, "The credential"). So a target that reads a site anonymously, as sandbox-local reads
        # Apache's, needs nothing taken out: its pod has no Secret reference, its document no token or email. A target that
        # still sets JIRA_TOKEN or JIRA_EMAIL is refused by name, as any variable the agent does not declare.
        "a target that reads Jira anonymously renders jira-observer with no credential and no Secret": {
            let config = (open ($INFRA | path join "targets/sandbox-local/config.nuon"))
            let anonymous = [
                { name: "JIRA_URL", value: "https://issues.apache.org/jira" }
                { name: "JIRA_ANONYMOUS", value: "true" }
            ]
            let with_env = {|entries| $config | upsert workloads ($config.workloads | upsert jira-observer {|w| $w.jira-observer | upsert env $entries }) }
            with_target (do $with_env $anonymous) {|t|
                let r = (resolve_for $t "jira-observer")
                assert ($r.env | where secret != null | is-empty) $"a Secret is referenced: ($r.env | where secret != null)"
                assert equal (env_value $r "JIRA_ANONYMOUS" $t) "true"
                let maps = (^nu $RESOLVER resources jira-observer --target $t | from json | get config_maps)
                let names = ($maps | first | get content | from json | get sections | each {|s| $s.variables | get name } | flatten)
                for gone in ["JIRA_TOKEN" "JIRA_EMAIL"] { assert ($gone not-in $names) $"($gone) is in the document" }
                let pod = (pod_of "jira-observer" $t)
                let refs = ($pod.containers | each {|c| $c.env? | default [] } | flatten | where {|e| $e.valueFrom?.secretKeyRef? != null })
                assert ($refs | is-empty) $"the pod reads a Secret: ($refs)"
                # and nothing the catalog or the target gives it is a problem (the agents' own judgement needs a cluster)
                let checked = (^nu $RESOLVER check --target $t | complete)
                let jira = ($checked.stderr | lines | where {|l| ($l | str contains "jira-observer") or ($l | str contains "JIRA_") })
                assert ($jira | is-empty) $"($jira)"
            }
            for gone in ["JIRA_TOKEN" "JIRA_EMAIL"] {
                with_target (do $with_env ($anonymous | append { name: $gone, value: "x" })) {|t|
                    let checked = (^nu $RESOLVER check --target $t | complete)
                    assert ($checked.exit_code != 0)
                    assert ($checked.stderr | str contains $"($gone) is set by") $checked.stderr
                    assert ($checked.stderr | str contains "jira-observer does not declare it") $checked.stderr
                }
            }
        }

        # docs/architecture/egress.md, "The cluster's own CA, for one workload", with configurations under test.
        "a configuration under test may have a workload trust the cluster's CA, and the target and the cluster's inputs may not": {
            let config = (open ($INFRA | path join "targets/sandbox-local/config.nuon"))
            let ca = { name: "POLAR_EGRESS_CLUSTER_CA", value: "/etc/polar-ca/ca.pem" }
            # A configuration under test configures what it enables, which the target leaves out (CT2).
            let left_out = ($config | upsert workloads.jira-observer.enabled false)
            with_target $left_out {|t|
                with_under_test $t { workloads: { jira-observer: { enabled: true, env: [$ca] } } } {
                    # The egress section as an image built since the variable was added declares it (lib/src/egress.rs), whatever
                    # the test cluster's images are.
                    with_scaffold_variable "jira-observer" "egress" "POLAR_EGRESS_CLUSTER_CA" {
                        let r = (do { ^nu $RESOLVER json jira-observer --target $t } | complete)
                        assert ($r.exit_code == 0) $r.stderr
                        assert equal (env_value ($r.stdout | from json) "POLAR_EGRESS_CLUSTER_CA" $t) "/etc/polar-ca/ca.pem"
                    }
                }
                with_under_test $t { workloads: { jira-observer: { enabled: true, env: [($ca | update value "/etc/elsewhere/ca.pem")] } } } {
                    let r = (do { ^nu $RESOLVER json jira-observer --target $t } | complete)
                    assert ($r.exit_code != 0 and ($r.stderr | unwrapped | str contains "/etc/polar-ca/ca.pem")) $r.stderr
                }
            }
            let workloads = ($config.workloads | upsert jira-observer {|w| $w.jira-observer | upsert env (($w.jira-observer.env? | default []) | append $ca) })
            with_target ($config | upsert workloads $workloads) {|t|
                let r = (do { ^nu $RESOLVER json jira-observer --target $t } | complete)
                assert ($r.exit_code != 0 and ($r.stderr | unwrapped | str contains "a catalog entry or a configuration under test")) $r.stderr
            }
            with_target $config {|t|
                { cluster: null, workloads: { jira-observer: { env: [$ca] } } } | to nuon | save --force ($INFRA | path join "targets" $t "cluster-inputs.nuon")
                let r = (do { ^nu $RESOLVER json jira-observer --target $t } | complete)
                assert ($r.exit_code != 0 and ($r.stderr | unwrapped | str contains "a catalog entry or a configuration under test")) $r.stderr
            }
        }

        "a target that sets an egress variable itself is refused, and so is a CA file that holds a key": {
            let config = (open ($INFRA | path join "targets/sandbox-local/config.nuon"))
            let workloads = ($config.workloads | upsert jira-observer {|w|
                $w.jira-observer | upsert env (($w.jira-observer.env? | default []) | append { name: "POLAR_EGRESS_PROXY", value: "http://proxy.corp.example:3128" })
            })
            with_target ($config | upsert workloads $workloads) {|t|
                let r = (do { ^nu $RESOLVER json jira-observer --target $t } | complete)
                assert ($r.exit_code != 0) "refused"
                assert ($r.stderr | unwrapped | str contains "POLAR_EGRESS_PROXY is set by") $r.stderr
                assert ($r.stderr | unwrapped | str contains "it is the cluster's egress setting: set cluster.egress instead") $r.stderr
            }
            let key = $"-----BEGIN (['PRIVATE' 'KEY'] | str join ' ')-----\nAAAA\n-----END (['PRIVATE' 'KEY'] | str join ' ')-----\n"
            with_target ($config | upsert cluster (($config.cluster? | default {}) | insert egress { ca_file: "trust/ca.pem" })) {|t|
                target_file $t "trust/ca.pem" ((fake_pem) + $key)
                let r = (do { ^nu $RESOLVER json jira-observer --target $t } | complete)
                assert ($r.exit_code != 0) "refused"
                assert ($r.stderr | str contains "cluster.egress.ca_file trust/ca.pem holds a private key") $r.stderr
            }
        }

        "the template does not see the settings record": {
            # render-catalog hands the template record to json-to-dhall, which rejects
            # a field its schema does not have.
            let r = (resolve "kube-consumer")
            assert ("_settings" not-in ($r | columns))
            assert ("termination_grace_secs" in ($r | columns))
        }
    }

    let names = ($tests | columns)
    let unknown = ($CLUSTER_TESTS | where {|n| $n not-in $names })
    let results = ($tests | transpose name body | each {|t|
        if $cluster == null and $t.name in $CLUSTER_TESTS {
            { name: $t.name, error: null, skipped: true }
        } else {
            try {
                do $t.body
                { name: $t.name, error: null, skipped: false }
            } catch {|e|
                { name: $t.name, error: $e.msg, skipped: false }
            }
        }
    }) ++ ($unknown | each {|n| { name: $n, error: "named in CLUSTER_TESTS, and no test has that name", skipped: false } })
    if ($preset | is-empty) { rm -rf $scaffolds }
    rm -rf $whole_catalog

    for r in $results {
        if $r.skipped {
            print (test-cluster skip_line $r.name)
        } else if $r.error == null {
            print $"  ok    ($r.name)"
        } else {
            print -e $"  FAIL  ($r.name): ($r.error)"
        }
    }

    let failed = ($results | where error != null | length)
    let skipped = ($results | where skipped | length)
    if $failed > 0 {
        print -e $"($failed) of ($results | length) failed"
        exit 1
    }
    let ran = ($results | length) - $skipped
    print $"all ($ran) run passed(if $skipped > 0 { $', ($skipped) skipped for want of a cluster' } else { '' })"
}
