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

# infra/tests/under-test-gitlab.nu
#
# The test GitLab, the first configuration under test (docs/architecture/configurations-under-test.md, CT3): its declaration is
# one, what its chart renders, and what its scripts tell GitLab.
#
#   nu infra/tests/under-test-gitlab.nu

use std/assert
use ../under-test/gitlab/main.nu *
use ../under-test/gitlab/ready.nu [root_token_ruby, runner_ruby]
use ../under-test.nu [declaration, adds_problems, layer_problems, marked]

const REG = "localhost:30500"

# What render.nu gives a chart under infra/under-test/ (`under_test_context`), as sandbox-local's would be.
def context [] {
    {
        output_dir: "/unused", chart_dir: "/unused", underTest: "gitlab"
        polarInitImage: $"($REG)/polar-init:latest"
        credentialsObserverUrl: "http://credentials-agent-observer.polar.svc.cluster.local:8080"
        credentialsAgentIdentity: "credentials-agent.polar.serviceaccount.cluster.local"
        certIssuerAudience: "polar-cert-issuer-neo4j.local"
        storageClass: "managed-csi"
        registry: $REG
    }
}

def main [] {
    let infra = ($env.FILE_PWD | path dirname)
    let tests = {
        "it is a configuration under test the repository declares, which only adds to sandbox-local, and its layer holds what it renders": {
            let d = (declaration $infra "gitlab")
            assert equal (adds_problems $d.adds (open ($infra | path join "targets/sandbox-local/config.nuon"))) []
            assert equal (layer_problems [$d]) []
            assert ($d.secrets | str ends-with "under-test/gitlab/secrets.nu")
            assert ($d.ready | str ends-with "under-test/gitlab/ready.nu")
            assert equal (marked [$d]).servers.0.service_account "gitlab"
            assert equal $d.layer.files ["gitlab-test.yaml"]
            assert equal ($d.layer.wait_for | get ref) ["statefulset/gitlab"]
        }

        "GitLab is told its address, the credentials agent's certificate, its registry, and no more than a test needs": {
            let c = (omnibus_config)
            assert ($c | str contains "external_url 'https://gitlab.gitlab-test.svc.cluster.local'")
            assert ($c | str contains "nginx['ssl_certificate'] = '/etc/gitlab-tls/cert.pem'")
            assert ($c | str contains "nginx['ssl_certificate_key'] = '/etc/gitlab-tls/key.pem'")
            assert ($c | str contains "registry_external_url 'https://gitlab.gitlab-test.svc.cluster.local:5050'")
            assert ($c | str contains "registry_nginx['ssl_certificate'] = '/etc/gitlab-tls/cert.pem'")
            assert ($c | str contains "letsencrypt['enable'] = false")
            assert ($c | str contains "prometheus_monitoring['enable'] = false")
        }

        "its polar-init is the shared one, asking the credentials agent for the names the floor admits, into GitLab's directory": {
            let init = (polar_init (context)).container
            assert equal $init.image $"($REG)/polar-init:latest"
            assert equal $init.command ["polar-init"]
            # Its tag moves, so a node pulls it each time (render.nu, the pull policy check), as Neo4j's does.
            assert equal $init.imagePullPolicy "Always"
            let given = ($init.env | reduce --fold {} {|e, acc| $acc | insert $e.name ($e.value? | default null) })
            assert equal $given.POLAR_INIT_ISSUER "credentials-agent"
            assert equal $given.POLAR_INIT_OBSERVER_URL "http://credentials-agent-observer.polar.svc.cluster.local:8080"
            assert equal $given.POLAR_INIT_CREDENTIALS_AGENT_IDENTITY "credentials-agent.polar.serviceaccount.cluster.local"
            assert equal $given.POLAR_INIT_CA_CERT "/etc/polar-ca/ca.pem"
            assert equal $given.POLAR_INIT_CERT_ISSUER_URL "" "not a bootstrap identity"
            # The names it asks for are the declaration's floor entry's: what the floor admits for it.
            let admitted = (declared | get adds.cluster.issuance.server_also | where namespace == "gitlab-test" | first)
            assert equal $admitted.service_account "gitlab"
            assert equal $init.args ["--cert" $"server:/etc/gitlab-tls:ecdsa-p256:($admitted.names | str join ',')"]
            assert equal ($init.volumeMounts | get mountPath) ["/workspace" "/etc/gitlab-tls" "/etc/polar-ca"]
        }

        "the pod's only token is polar-init's, with Neo4j's audience, and GitLab reads its certificate without writing it": {
            let sts = (statefulset (context))
            let pod = $sts.spec.template.spec
            assert equal $pod.automountServiceAccountToken false
            assert equal $pod.serviceAccountName "gitlab"
            let init = ($pod.initContainers | first)
            let token_name = ($init.volumeMounts | where mountPath == "/workspace" | first | get name)
            let token = ($pod.volumes | where name == $token_name | first)
            assert equal $token.projected.sources.0.serviceAccountToken.audience "polar-cert-issuer-neo4j.local"
            let gitlab = ($pod.containers | first)
            assert equal $gitlab.image $"($REG)/gitlab-ce:19.5.3-ce.0"
            assert equal ($gitlab.volumeMounts | where name == "gitlab-tls" | first) { name: "gitlab-tls", mountPath: "/etc/gitlab-tls", readOnly: true }
            assert (($gitlab.volumeMounts | where name == $token_name) | is-empty) "GitLab itself has no token"
            assert equal ($gitlab.env | where name == "GITLAB_ROOT_PASSWORD" | first | get valueFrom.secretKeyRef.name) "gitlab-root"
            assert equal $sts.metadata.namespace "gitlab-test"
            assert equal ($sts.spec.volumeClaimTemplates.0.spec.storageClassName) "managed-csi"
            assert ("polar-ca" in ($pod.volumes | get name))
        }

        "the runner reaches GitLab by the cluster's CA, runs jobs on the declared images, and may act only in its own namespace": {
            let c = (runner_config $REG)
            assert ($c | str contains "url = \"https://gitlab.gitlab-test.svc.cluster.local\"")
            assert ($c | str contains "tls-ca-file = \"/etc/polar-ca/ca.pem\"")
            assert ($c | str contains "namespace = \"gitlab-test\"")
            # Each image it names outside an `image:` line is one the declaration lists, which the render pins.
            for i in (declared | get images) { assert ($c | str contains $"\"($REG)/($i)\"") $i }
            let objects = (runner_objects $REG)
            assert (($objects | where kind in ["ClusterRole" "ClusterRoleBinding"]) | is-empty)
            assert (($objects | each {|o| $o.metadata.namespace }) | all {|n| $n == "gitlab-test" })
        }

        "the runner's token is in no file of the render and on no command line": {
            let all = (objects (context) | to json)
            assert ($all | str contains "@RUNNER_TOKEN@") "the template's placeholder"
            assert (not ($all | str contains "glrt-"))
            let runner = (runner_objects $REG | where kind == "Deployment" | first | get spec.template.spec)
            let start = ($runner.containers.0.command | last)
            assert ($start | str contains "getline t < f") "read from its file"
            assert ($runner.volumes | any {|v| ($v.secret?.secretName? | default "") == "gitlab-runner-token" })
        }

        "everything it renders is in its namespace, and its workloads are what the layer waits for and the record marks": {
            let objects = (objects (context))
            assert (($objects | each {|o| $o.metadata.namespace }) | all {|n| $n == "gitlab-test" })
            assert equal ($objects | where kind in ["StatefulSet" "Deployment"] | get metadata.name) ["gitlab" "gitlab-runner"]
        }

        "what the ready script tells GitLab reads the token from a file it then removes, and makes the runner once": {
            let r = (root_token_ruby "/tmp/x/root-token")
            assert ($r | str contains "File.read('/tmp/x/root-token')")
            assert ($r | str contains "File.delete('/tmp/x/root-token')")
            assert (not ($r | str contains "glpat-")) "no token in the script"
            let s = (runner_ruby "/tmp/x/runner-token")
            assert ($s | str contains "Ci::Runner.find_by(description: 'polar-test')")
            assert ($s | str contains "File.write('/tmp/x/runner-token', runner.token)")
        }
    }

    let results = ($tests | transpose name body | each {|t|
        try {
            do $t.body
            { name: $t.name, error: null }
        } catch {|e|
            { name: $t.name, error: $e.msg }
        }
    })
    for r in $results {
        if $r.error == null { print $"  ok    ($r.name)" } else { print -e $"  FAIL  ($r.name): ($r.error)" }
    }
    let failed = ($results | where error != null | length)
    if $failed > 0 {
        print -e $"($failed) of ($results | length) failed"
        exit 1
    }
    print $"all ($results | length) passed"
}
