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

# infra/under-test/gitlab/main.nu
#
# The test GitLab's chart (docs/architecture/configurations-under-test.md, CT3), rendered into its layer, `under-test-gitlab`, by
# render.nu, which gives it `under_test_context`. GitLab CE (Omnibus) with its server certificate from the credentials agent, as
# Neo4j's: polar-init is the shared one (schema/functions.dhall), with Neo4j's token audience; its names are the declaration's
# floor entry's, so what the pod asks for is what the floor admits. And a runner with the Kubernetes executor, allowed only this
# namespace, whose token the ready script gives it.
#
# Writes:
#   <output_dir>/gitlab-test.yaml

const HERE = (path self | path dirname)
const INFRA = (path self | path dirname | path dirname | path dirname)
export const NAMESPACE = "gitlab-test"
export const NAME = "gitlab"
const RUNNER = "gitlab-runner"
const REGISTRY_PORT = 5050
const TLS_DIR = "/etc/gitlab-tls"
const CA_DIR = "/etc/polar-ca"
# The runner's token, from the Secret the ready script makes, and where the runner reads it: never on a command line.
export const RUNNER_TOKEN_SECRET = "gitlab-runner-token"
const TOKEN_DIR = "/etc/gitlab-runner-token"
const TOKEN_PLACEHOLDER = "@RUNNER_TOKEN@"

# The declaration beside this chart.
export def declared [] { open ($HERE | path join "under-test.nuon") }

# GitLab's names: the declaration's floor entry's, which its certificate carries; the first is its address.
export def names [] {
    declared | get adds.cluster.issuance.server_also | where namespace == $NAMESPACE and service_account == $NAME | first | get names
}

# `<image>:<tag>` of infra/images.nuon under `registry`: the render pins it.
def image [registry: string, row: string] { $"($registry)/($row)" }

# GITLAB_OMNIBUS_CONFIG: its address, its certificate from the credentials agent, its registry on the same certificate, and no
# more than a test needs running (no monitoring, one Puma, a small Sidekiq).
export def omnibus_config [] {
    let host = (names | first)
    [
        $"external_url 'https://($host)'"
        $"nginx['ssl_certificate'] = '($TLS_DIR)/cert.pem'"
        $"nginx['ssl_certificate_key'] = '($TLS_DIR)/key.pem'"
        "letsencrypt['enable'] = false"
        $"registry_external_url 'https://($host):($REGISTRY_PORT)'"
        $"registry_nginx['ssl_certificate'] = '($TLS_DIR)/cert.pem'"
        $"registry_nginx['ssl_certificate_key'] = '($TLS_DIR)/key.pem'"
        "gitlab_rails['packages_enabled'] = true"
        "prometheus_monitoring['enable'] = false"
        "puma['worker_processes'] = 0"
        "sidekiq['concurrency'] = 5"
        "gitlab_kas['enable'] = false"
    ] | str join "\n"
}

# polar-init and its token volume, from the functions every chart that is not a bootstrap identity uses (as ACE's and Neo4j's):
# a server certificate from the credentials agent, for GitLab's names, into GitLab's own TLS directory.
export def polar_init [context: record] {
    let schema = ($INFRA | path join "schema")
    let expression = $"
let kubernetes = ($schema)/kubernetes.dhall
let Constants = ($schema)/constants.dhall
let Functions = ($schema)/functions.dhall
in  { container =
        Functions.makePolarInitContainer
          \"($context.polarInitImage)\"
          \"Always\"
          Constants.saTokenVolumeName
          \"\"
          \(Functions.credentialsAgentIssuerEnv \"($context.credentialsObserverUrl)\" \"($context.credentialsAgentIdentity)\"\)
          Constants.saTokenPath
          [ kubernetes.VolumeMount::{ name = \"gitlab-tls\", mountPath = \"($TLS_DIR)\" }, Constants.polarCaMount ]
          \([] : List Text\)
          [ \"server:($TLS_DIR):ecdsa-p256:(names | str join ',')\" ]
    , tokenVolume = Constants.saTokenVolume \"($context.certIssuerAudience)\"
    , caVolume = Constants.polarCaVolume
    }
"
    let r = ($expression | ^dhall-to-json --omit-empty | complete)
    if $r.exit_code != 0 { error make { msg: $"the test GitLab's polar-init: ($r.stderr | str trim)" } }
    $r.stdout | from json
}

export def service [] {
    {
        apiVersion: "v1", kind: "Service"
        metadata: { name: $NAME, namespace: $NAMESPACE }
        spec: {
            selector: { app: $NAME }
            ports: [
                { name: "https", port: 443, targetPort: 443 }
                { name: "registry", port: $REGISTRY_PORT, targetPort: $REGISTRY_PORT }
            ]
        }
    }
}

# GitLab's SSH host keys, made by its embedded OpenSSL where there are none. On a FIPS kernel the image's own OpenSSH, which
# GitLab's start script runs to make them, cannot start ("PRNG is not seeded"); the embedded OpenSSL can. Its OpenSSH is off
# (`GITLAB_DISABLE_OPENSSH`), since the test reads GitLab over HTTPS alone.
export def host_keys [image: string] {
    let make = [
        "set -e"
        "o=/opt/gitlab/embedded/bin/openssl"
        "for t in rsa ecdsa ed25519; do"
        "  f=/etc/gitlab/ssh_host_${t}_key"
        "  [ -f \"$f\" ] && continue"
        "  case $t in"
        "    rsa) $o genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out \"$f\" ;;"
        "    ecdsa) $o genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out \"$f\" ;;"
        "    ed25519) $o genpkey -algorithm ED25519 -out \"$f\" ;;"
        "  esac"
        "  chmod 0600 \"$f\""
        "  $o pkey -in \"$f\" -pubout -out \"$f.pub\""
        "done"
    ] | str join "\n"
    {
        name: "gitlab-host-keys"
        image: $image
        command: ["sh" "-c" $make]
        volumeMounts: [{ name: "data", mountPath: "/etc/gitlab", subPath: "config" }]
    }
}

# GitLab: its only token is polar-init's; it reads its certificate and never writes it.
export def statefulset [context: record] {
    let init = (polar_init $context)
    let gitlab_image = (image $context.registry "gitlab-ce:19.5.3-ce.0")
    {
        apiVersion: "apps/v1", kind: "StatefulSet"
        metadata: { name: $NAME, namespace: $NAMESPACE }
        spec: {
            serviceName: $NAME
            replicas: 1
            selector: { matchLabels: { app: $NAME } }
            template: {
                metadata: { labels: { app: $NAME } }
                spec: {
                    serviceAccountName: $NAME
                    automountServiceAccountToken: false
                    initContainers: [$init.container (host_keys $gitlab_image)]
                    containers: [{
                        name: $NAME
                        image: $gitlab_image
                        env: [
                            { name: "GITLAB_OMNIBUS_CONFIG", value: (omnibus_config) }
                            { name: "GITLAB_DISABLE_OPENSSH", value: "true" }
                            { name: "GITLAB_ROOT_PASSWORD", valueFrom: { secretKeyRef: { name: "gitlab-root", key: "password" } } }
                        ]
                        ports: [{ containerPort: 443, name: "https" } { containerPort: $REGISTRY_PORT, name: "registry" }]
                        readinessProbe: { httpGet: { path: "/-/readiness", port: 443, scheme: "HTTPS" }, initialDelaySeconds: 60, periodSeconds: 10, failureThreshold: 60 }
                        resources: { requests: { memory: "4Gi", cpu: "1" } }
                        volumeMounts: [
                            { name: "data", mountPath: "/var/opt/gitlab", subPath: "data" }
                            { name: "data", mountPath: "/etc/gitlab", subPath: "config" }
                            { name: "data", mountPath: "/var/log/gitlab", subPath: "logs" }
                            { name: "gitlab-tls", mountPath: $TLS_DIR, readOnly: true }
                            { name: "shm", mountPath: "/dev/shm" }
                        ]
                    }]
                    volumes: [
                        { name: "gitlab-tls", emptyDir: {} }
                        $init.tokenVolume
                        $init.caVolume
                        { name: "shm", emptyDir: { medium: "Memory", sizeLimit: "256Mi" } }
                    ]
                }
            }
            volumeClaimTemplates: [{
                metadata: { name: "data" }
                spec: { accessModes: ["ReadWriteOnce"], storageClassName: $context.storageClass, resources: { requests: { storage: "30Gi" } } }
            }]
        }
    }
}

# The runner's config.toml, but for its token: a Kubernetes executor in this namespace, trusting GitLab by the cluster's CA, its
# job and helper images the declaration's, which the render pins here.
export def runner_config [registry: string] {
    let images = (declared | get images)
    let job = ($images | where {|i| $i | str starts-with "busybox:" } | first)
    let helper = ($images | where {|i| $i | str starts-with "gitlab-runner-helper:" } | first)
    [
        "concurrent = 2"
        "[[runners]]"
        "  name = \"polar-test\""
        $"  url = \"https://(names | first)\""
        $"  token = \"($TOKEN_PLACEHOLDER)\""
        $"  tls-ca-file = \"($CA_DIR)/ca.pem\""
        "  executor = \"kubernetes\""
        "  [runners.kubernetes]"
        $"    namespace = \"($NAMESPACE)\""
        $"    image = \"(image $registry $job)\""
        $"    helper_image = \"(image $registry $helper)\""
        $"    service_account = \"($RUNNER)\""
    ] | str join "\n"
}

# The runner: its own ServiceAccount, allowed in this namespace only what the Kubernetes executor does with a job's pod. Its
# config.toml is written at start from the template, with the token read from its file, so the token is on no command line.
export def runner_objects [registry: string] {
    let start = $"awk -v f=($TOKEN_DIR)/token 'BEGIN { getline t < f } { gsub\(\"($TOKEN_PLACEHOLDER)\", t\) } 1' /etc/gitlab-runner-template/config.toml > /tmp/config.toml && exec gitlab-runner run --config /tmp/config.toml --working-directory /tmp"
    [
        { apiVersion: "v1", kind: "ServiceAccount", metadata: { name: $RUNNER, namespace: $NAMESPACE } }
        {
            apiVersion: "rbac.authorization.k8s.io/v1", kind: "Role"
            metadata: { name: $RUNNER, namespace: $NAMESPACE }
            rules: [
                { apiGroups: [""], resources: ["pods" "pods/exec" "pods/attach" "pods/log" "secrets" "configmaps" "services"], verbs: ["get" "list" "watch" "create" "update" "patch" "delete"] }
            ]
        }
        {
            apiVersion: "rbac.authorization.k8s.io/v1", kind: "RoleBinding"
            metadata: { name: $RUNNER, namespace: $NAMESPACE }
            roleRef: { apiGroup: "rbac.authorization.k8s.io", kind: "Role", name: $RUNNER }
            subjects: [{ kind: "ServiceAccount", name: $RUNNER, namespace: $NAMESPACE }]
        }
        {
            apiVersion: "v1", kind: "ConfigMap"
            metadata: { name: "gitlab-runner-template", namespace: $NAMESPACE }
            data: { "config.toml": (runner_config $registry) }
        }
        {
            apiVersion: "apps/v1", kind: "Deployment"
            metadata: { name: $RUNNER, namespace: $NAMESPACE }
            spec: {
                replicas: 1
                selector: { matchLabels: { app: $RUNNER } }
                template: {
                    metadata: { labels: { app: $RUNNER } }
                    spec: {
                        serviceAccountName: $RUNNER
                        containers: [{
                            name: $RUNNER
                            image: (image $registry "gitlab-runner:alpine-v19.5.3")
                            command: ["sh" "-c" $start]
                            volumeMounts: [
                                { name: "template", mountPath: "/etc/gitlab-runner-template", readOnly: true }
                                { name: "token", mountPath: $TOKEN_DIR, readOnly: true }
                                { name: "polar-ca", mountPath: $CA_DIR, readOnly: true }
                            ]
                        }]
                        volumes: [
                            { name: "template", configMap: { name: "gitlab-runner-template" } }
                            { name: "token", secret: { secretName: $RUNNER_TOKEN_SECRET } }
                            { name: "polar-ca", configMap: { name: "polar-ca" } }
                        ]
                    }
                }
            }
        }
    ]
}

# Everything the layer holds.
export def objects [context: record] {
    [
        { apiVersion: "v1", kind: "ServiceAccount", metadata: { name: $NAME, namespace: $NAMESPACE } }
        (service)
        (statefulset $context)
        ...(runner_objects $context.registry)
    ]
}

def main [context_nuon: string] {
    let context = ($context_nuon | from nuon)
    mkdir $context.output_dir
    print "  rendering the test GitLab -> gitlab-test.yaml"
    objects $context | each {|o| $o | to yaml } | str join "---\n" | save --force ($context.output_dir | path join "gitlab-test.yaml")
}
