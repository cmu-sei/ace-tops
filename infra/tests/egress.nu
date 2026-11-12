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

# infra/tests/egress.nu
#
# The check at the end of up.nu that a pod can reach an outside host: the probe's Job (git-repo-observer's image,
# run once with `--probe-egress`, its document and egress CA and nothing else), how the agent's verdict is read, what
# is said for each, and that the check reports and never stops the bring-up (a person working offline has a working
# cluster).
#
# And the target's egress setting (cluster.egress: a proxy, the hosts that bypass it, a CA): what is accepted, what
# is refused and how it is said, the bypass list the render writes, and what an agent's pod is given for it.
#
#   nu infra/tests/egress.nu

use std/assert
use ../egress.nu *

const IMAGE = "registry.polar:5000/git-observer@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# git-repo-observer's workload as the chart renders it (a Deployment, as on u7c), in the parts the probe reads: polar-init,
# the token it presents, its certificates and its Secret, its document, the egress CA and its cache.
def rendered_job [] {
    {
        apiVersion: "apps/v1", kind: "Deployment"
        metadata: { name: "git-repo-observer", namespace: "polar" }
        spec: { template: { spec: {
            serviceAccountName: "git-repo-observer"
            automountServiceAccountToken: false
            nodeSelector: { "polar.dev/pool": "observers" }
            securityContext: { runAsNonRoot: true, seccompProfile: { type: "RuntimeDefault" } }
            initContainers: [{ name: "polar-init", image: "registry.polar:5000/polar-init@sha256:aa", volumeMounts: [{ name: "token", mountPath: "/var/run/token" }] }]
            containers: [{
                name: "git-repo-observer"
                image: $IMAGE
                securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } }
                env: [
                    { name: "POLAR_CONFIG", value: "/etc/polar/config.json" }
                    { name: "POLAR_CUSTODY_SOCKET", value: "/run/polar-custody/sock" }
                    { name: "GIT_TOKEN", valueFrom: { secretKeyRef: { name: "git-repo-observer-secrets", key: "token" } } }
                ]
                volumeMounts: [
                    { name: "config", mountPath: "/etc/polar" }
                    { name: "polar-egress-ca", mountPath: "/etc/polar-egress-ca", readOnly: true }
                    { name: "certs", mountPath: "/etc/tls/certs" }
                    { name: "secrets", mountPath: "/etc/secrets" }
                    { name: "cache", mountPath: "/var/lib/git-repo-observer/cache" }
                ]
            }]
            volumes: [
                { name: "config", configMap: { name: "git-repo-observer-config" } }
                { name: "polar-egress-ca", configMap: { name: "git-repo-observer-egress-ca" } }
                { name: "token", projected: { sources: [{ serviceAccountToken: { path: "token", audience: "polar" } }] } }
                { name: "certs", emptyDir: {} }
                { name: "secrets", secret: { secretName: "git-repo-observer-secrets" } }
                { name: "cache", emptyDir: {} }
            ]
        } } }
    }
}

# A volume of any kind a pod may have.
def random_volume [i: int] {
    let name = $"extra-($i)"
    match (random int 0..4) {
        0 => { name: $name, configMap: { name: $"cm-($i)" } }
        1 => { name: $name, secret: { secretName: $"s-($i)" } }
        2 => { name: $name, emptyDir: {} }
        3 => { name: $name, projected: { sources: [{ serviceAccountToken: { path: "token" } }] } }
        _ => { name: $name, persistentVolumeClaim: { claimName: $"c-($i)" } }
    }
}

# One line of the agent's verdict, as it prints it.
def line [protocol: string, verdict: string, detail: string] {
    { agent: "git-repo-observer", protocol: $protocol, host: "example.org", verdict: $verdict, detail: $detail } | to json --raw
}

def has [lines: list, needle: string] { $lines | any {|l| $l | str contains $needle } }

# A cluster's settings with `egress` as given (absent when it is the string "absent").
def cluster_with [egress: any] {
    let base = { domain: "cluster.local" }
    if $egress == "absent" { $base } else { $base | insert egress $egress }
}

# A certificate-shaped block: base64 of random bytes between the PEM lines. Not a certificate; the render checks the
# shape, and the agent parses it.
def fake_pem [] {
    let body = (random binary 48 | encode base64)
    $"-----BEGIN CERTIFICATE-----\n($body)\n-----END CERTIFICATE-----\n"
}

# Runs `body` with a target directory named zz-egress-test holding `files` (path -> content), and removes it after.
def with_target_dir [files: record, body: closure] {
    let root = (mktemp --directory)
    let dir = ($root | path join "zz-egress-test")
    mkdir $dir
    for f in ($files | transpose path content) {
        let p = ($dir | path join $f.path)
        mkdir ($p | path dirname)
        $f.content | save --force --raw $p
    }
    let r = (try { { value: (do $body $dir), error: null } } catch {|e| { value: null, error: $e.msg } })
    rm -rf $root
    if $r.error != null { error make { msg: $r.error } }
    $r.value
}

# The message settings_of refuses `egress` with, or null when it accepts it.
def refusal [egress: any, files: record = {}] {
    with_target_dir $files {|dir| try { settings_of (cluster_with $egress) $dir; null } catch {|e| $e.msg } }
}

const PROXY_SHAPE = "a proxy is an http:// or https:// URL with a host and a port, such as http://proxy.example.org:3128"
const ENTRY_SHAPE = "is not a host, .domain suffix, IP address or CIDR (no commas, spaces or empty entries)"
const T = "infra/targets/zz-egress-test"

def label [] { random chars --length (random int 1..8) | str lowercase | str replace --all --regex '[^a-z0-9]' 'x' }

# A random no_proxy entry: a host, a .suffix, an address, a CIDR, a default again, or nothing new.
def random_entry [domain: string] {
    match (random int 0..5) {
        0 => $"(label).(label)"
        1 => $".(label).(label)"
        2 => $"10.(random int 0..255).(random int 0..255).(random int 1..254)"
        3 => $"172.(random int 16..31).0.0/(random int 8..30)"
        4 => (["localhost" "127.0.0.1" "::1" ".svc" $".($domain)"] | get (random int 0..4))
        _ => "fd00::1"
    }
}

def main [] {
    let tests = [
        {
            name: "the probe's Job runs the agent's image once, with its document and egress CA and nothing else"
            body: {
                let j = (probe_job (rendered_job) "egress-probe-abc123" "https://example.org/r.git")
                assert equal $j.kind "Job"
                assert equal $j.metadata.namespace "polar"
                assert equal $j.metadata.labels { "polar.dev/probe": "egress" }
                assert equal $j.spec.backoffLimit 0
                let pod = $j.spec.template.spec
                assert equal $j.spec.template.metadata.labels { "polar.dev/probe": "egress" }
                assert equal $pod.restartPolicy "Never"
                assert equal $pod.automountServiceAccountToken false
                assert equal ($pod | get -o initContainers) null
                assert equal ($pod | get -o serviceAccountName) null
                assert equal ($pod.containers | length) 1
                let c = ($pod.containers | first)
                assert equal $c.image $IMAGE
                assert equal $c.command ["git-repo-observer" "--probe-egress" "https://example.org/r.git"]
                assert equal $c.env [{ name: "POLAR_CONFIG", value: "/etc/polar/config.json" }]
                assert equal $c.securityContext (rendered_job).spec.template.spec.containers.0.securityContext
                assert equal ($pod.volumes | get name) ["config" "polar-egress-ca" "tmp"]
                assert equal ($c.volumeMounts | get name) ["config" "polar-egress-ca" "tmp"]
                assert equal $pod.nodeSelector { "polar.dev/pool": "observers" }
                assert equal $pod.securityContext { runAsNonRoot: true, seccompProfile: { type: "RuntimeDefault" } }
            }
        }
        {
            name: "a workload rendered as a Job gives the same probe as one rendered as a Deployment"
            body: {
                let as_job = (rendered_job | update apiVersion "batch/v1" | update kind "Job")
                assert equal (probe_job $as_job "p" "https://example.org/") (probe_job (rendered_job) "p" "https://example.org/")
            }
        }
        {
            name: "a Job of whatever volumes and environment keeps only ConfigMaps and the document, never a Secret or a token"
            body: {
                for _ in 1..50 {
                    let extra = (1..(random int 0..6) | each {|i| random_volume $i })
                    let job = (rendered_job | update spec.template.spec.volumes {|j| $j.spec.template.spec.volumes ++ $extra }
                        | update spec.template.spec.containers.0.volumeMounts {|j| $j.spec.template.spec.containers.0.volumeMounts ++ ($extra | each {|v| { name: $v.name, mountPath: $"/v/($v.name)" } }) })
                    let pod = (probe_job $job "p" "https://example.org/").spec.template.spec
                    for v in $pod.volumes {
                        assert ((($v.configMap? | default null) != null) or $v.name == "tmp") ($v | to nuon)
                    }
                    let mounted = ($pod.containers.0.volumeMounts | get name)
                    assert equal ($pod.volumes | get name | sort) ($mounted | sort)
                    assert ($pod.containers.0.env | all {|e| $e.name == "POLAR_CONFIG" and ($e.valueFrom? | default null) == null })
                }
            }
        }
        {
            name: "an image not pinned by digest is not probed: its pod would not be what its owner pins"
            body: {
                let job = (rendered_job | update spec.template.spec.containers.0.image "registry/git-observer:latest")
                let refused = (try { probe_job $job "p" "https://example.org/"; null } catch {|e| $e.msg })
                assert ($refused | str contains "not pinned by digest")
            }
        }
        {
            name: "the verdict is the agent's: the first protocol that did not reach, or reached"
            body: {
                let reached = (line "git" "reached" "it listed 2 refs")
                let dns = (line "http" "dns" "failed to lookup address")
                assert equal (probe_verdict { exit: 0, logs: $reached, reason: "" }) { verdict: "reached", detail: "it listed 2 refs" }
                assert equal (probe_verdict { exit: 1, logs: ([$reached $dns] | str join "\n"), reason: "" }) { verdict: "dns", detail: "failed to lookup address" }
            }
        }
        {
            name: "a pod that printed no verdict is other, and says why"
            body: {
                let v = (probe_verdict { exit: null, logs: "", reason: "ErrImagePull: not found" })
                assert equal $v.verdict "other"
                assert ($v.detail | str contains "ErrImagePull: not found")
                let w = (probe_verdict { exit: 2, logs: "ERROR: git-repo-observer has no operation that goes outside the cluster", reason: "Error" })
                assert ($w.detail | str contains "no operation that goes outside")
            }
        }
        {
            name: "the DNS advice says what is wrong, that offline can ignore it, and where to look"
            body: {
                let l = (egress_lines "dns" "https://example.org/r" "failed to resolve address")
                assert (has $l "cannot resolve names outside the cluster")
                assert (has $l "offline")
                assert (has $l "kubectl -n kube-system logs -l k8s-app=kube-dns")
                assert (has $l "5300")
            }
        }
        {
            name: "the unreachable advice does not blame DNS"
            body: {
                let l = (egress_lines "unreachable" "https://example.org/r" "Connection refused")
                assert (has $l "could not connect")
                assert (not (has $l "cannot resolve"))
            }
        }
        {
            name: "a certificate not trusted points at the egress CA, and a proxy at the proxy"
            body: {
                assert (has (egress_lines "tls" "https://example.org/r" "the SSL certificate is invalid") "cluster.egress.ca_file")
                let p = (egress_lines "proxy" "https://example.org/r" "proxy returned unexpected status: 403")
                assert (has $p "cluster.egress.proxy")
                assert (has $p "403")
            }
        }
        {
            name: "an answer nobody recognises is shown, not hidden"
            body: {
                let l = (egress_lines "other" "https://example.org/r" "something nobody has seen")
                assert (has $l "something nobody has seen")
            }
        }
        {
            name: "a probe that reached: one line saying so"
            body: {
                let r = (egress_report "https://example.org/r" {|u| { skipped: false, exit: 0, logs: (line "git" "reached" "ok"), reason: "" } })
                assert equal $r.verdict "reached"
                assert equal $r.lines ["pods can reach https://example.org/r"]
            }
        }
        {
            name: "no agent to probe as is said plainly, and is not a failure"
            body: {
                let r = (egress_report "https://example.org/r" {|u| { skipped: true, exit: null, logs: "", reason: "" } })
                assert equal $r.verdict "skipped"
                assert (has $r.lines "no git-repo-observer is deployed")
                assert (has $r.lines "was not checked")
            }
        }
        {
            name: "the probe is given the URL it is to try"
            body: {
                let r = (egress_report "https://example.org/the-url" {|u| { skipped: false, exit: 1, logs: (line "git" "other" $"asked ($u)"), reason: "" } })
                assert (has $r.lines "asked https://example.org/the-url")
            }
        }
        {
            name: "egress absent, empty or all null is no egress"
            body: {
                for egress in ["absent" {} { proxy: null } { proxy: null, no_proxy: null, ca_file: null }] {
                    assert equal (with_target_dir {} {|dir| settings_of (cluster_with $egress) $dir }) null ($egress | to nuon)
                }
            }
        }
        {
            name: "every setting that cannot work is refused, and says why"
            body: {
                let pem = (fake_pem)
                let key = $"-----BEGIN (['PRIVATE' 'KEY'] | str join ' ')-----\nAAAA\n-----END (['PRIVATE' 'KEY'] | str join ' ')-----\n"
                let big = ($pem + ("x" | fill --character "x" --width 1048576))
                let cases = [
                    [egress files msg];
                    ["proxy" {} "cluster.egress is string: it is a record with any of proxy, no_proxy, ca_file"]
                    [[1 2] {} "cluster.egress is list<int>: it is a record with any of proxy, no_proxy, ca_file"]
                    [{ proxi: "http://p:3128" } {} "cluster.egress.proxi is not a setting: the settings are proxy, no_proxy, ca_file"]
                    [{ proxy: "socks5://proxy.corp.example:1080" } {} $"cluster.egress.proxy is 'socks5://proxy.corp.example:1080': ($PROXY_SHAPE)"]
                    [{ proxy: "http://proxy.corp.example" } {} $"cluster.egress.proxy is 'http://proxy.corp.example': ($PROXY_SHAPE)"]
                    [{ proxy: "proxy.corp.example:3128" } {} $"cluster.egress.proxy is 'proxy.corp.example:3128': ($PROXY_SHAPE)"]
                    [{ proxy: "http://proxy.corp.example:99999" } {} $"cluster.egress.proxy is 'http://proxy.corp.example:99999': ($PROXY_SHAPE)"]
                    [{ proxy: "http://proxy:3128/a/path" } {} $"cluster.egress.proxy is 'http://proxy:3128/a/path': ($PROXY_SHAPE)"]
                    [{ proxy: 3128 } {} $"cluster.egress.proxy is '3128': ($PROXY_SHAPE)"]
                    [{ proxy: "http://user:pw@proxy.corp.example:3128" } {} "cluster.egress.proxy names a user or password: it is written into a ConfigMap, and a proxy that needs credentials is not supported"]
                    [{ proxy: "http://user@proxy" } {} "cluster.egress.proxy names a user or password: it is written into a ConfigMap, and a proxy that needs credentials is not supported"]
                    [{ no_proxy: [".corp.example"] } {} "cluster.egress.no_proxy is set but cluster.egress.proxy is not: there is nothing to bypass"]
                    [{ proxy: "http://p:3128", no_proxy: ".corp.example" } {} "cluster.egress.no_proxy is string: it is a list of hosts, .domain suffixes, IP addresses and CIDRs"]
                    [{ proxy: "http://p:3128", no_proxy: ["a.example,b.example"] } {} $"cluster.egress.no_proxy entry 'a.example,b.example' ($ENTRY_SHAPE)"]
                    [{ proxy: "http://p:3128", no_proxy: ["a.example b.example"] } {} $"cluster.egress.no_proxy entry 'a.example b.example' ($ENTRY_SHAPE)"]
                    [{ proxy: "http://p:3128", no_proxy: [""] } {} $"cluster.egress.no_proxy entry '' ($ENTRY_SHAPE)"]
                    [{ proxy: "http://p:3128", no_proxy: [".ok.example" 5] } {} $"cluster.egress.no_proxy entry '5' ($ENTRY_SHAPE)"]
                    [{ proxy: "http://p:3128", no_proxy: ["*"] } {} "cluster.egress.no_proxy has '*', which sends nothing through the proxy: remove cluster.egress.proxy instead"]
                    [{ ca_file: "/etc/ssl/certs/corp.pem" } {} $"cluster.egress.ca_file is '/etc/ssl/certs/corp.pem': it is a path inside ($T)"]
                    [{ ca_file: "../local/trust/corp.pem" } {} $"cluster.egress.ca_file is '../local/trust/corp.pem': it is a path inside ($T)"]
                    [{ ca_file: "trust/../../x.pem" } {} $"cluster.egress.ca_file is 'trust/../../x.pem': it is a path inside ($T)"]
                    [{ ca_file: "" } {} $"cluster.egress.ca_file is '': it is a path inside ($T)"]
                    [{ ca_file: "trust/missing.pem" } {} $"cluster.egress.ca_file trust/missing.pem does not exist \(it is read relative to ($T)\)"]
                    [{ ca_file: "trust" } { "trust/a.pem": $pem } $"cluster.egress.ca_file trust does not exist \(it is read relative to ($T)\)"]
                    [{ ca_file: "trust/corp.pem" } { "trust/corp.pem": "just some text\n" } "cluster.egress.ca_file trust/corp.pem holds no PEM certificate (no -----BEGIN CERTIFICATE----- block)"]
                    [{ ca_file: "trust/corp.pem" } { "trust/corp.pem": "-----BEGIN CERTIFICATE-----\nnot base64 at all!\n-----END CERTIFICATE-----\n" } "cluster.egress.ca_file trust/corp.pem holds a CERTIFICATE block that is not base64"]
                    [{ ca_file: "trust/corp.pem" } { "trust/corp.pem": ($pem + $key) } "cluster.egress.ca_file trust/corp.pem holds a private key: it must hold only CA certificates, and it is published in a ConfigMap"]
                    [{ ca_file: "trust/corp.pem" } { "trust/corp.pem": $big } $"cluster.egress.ca_file trust/corp.pem is ($big | str length) bytes, more than a ConfigMap holds"]
                ]
                for c in $cases {
                    assert equal (refusal $c.egress $c.files) $c.msg ($c.egress | to nuon)
                }
            }
        }
        {
            name: "a refusal of a proxy with credentials never repeats the password"
            body: {
                for proxy in ["http://user:s3cret@proxy:3128" "socks5://user:s3cret@proxy:1080" "http://user:s3cret@" "ftp://u:s3cret@x"] {
                    let msg = (refusal { proxy: $proxy })
                    assert ($msg != null) $proxy
                    assert (not ($msg | str contains "s3cret")) $msg
                }
            }
        }
        {
            name: "what is accepted comes back with the bypass list's defaults, the CA's text, and nothing else"
            body: {
                let pem = ((fake_pem) + (fake_pem))
                let s = (with_target_dir { "trust/corp-root-ca.pem": $pem } {|dir|
                    settings_of (cluster_with { proxy: "http://proxy.corp.example:3128", no_proxy: [".corp.example" "10.20.0.0/16"], ca_file: "trust/corp-root-ca.pem" }) $dir
                })
                assert equal $s {
                    proxy: "http://proxy.corp.example:3128"
                    no_proxy: ["localhost" "127.0.0.1" "::1" ".svc" ".cluster.local" ".corp.example" "10.20.0.0/16"]
                    ca_pem: $pem
                }
                for proxy in ["https://proxy.corp.example:8443" "http://10.20.0.5:3128/" "http://[fd00::1]:3128"] {
                    assert equal (refusal { proxy: $proxy }) null $proxy
                }
                let ca_only = (with_target_dir { "corp.pem": $pem } {|dir| settings_of (cluster_with { ca_file: "corp.pem" }) $dir })
                assert equal $ca_only.proxy null
                assert equal $ca_only.ca_pem $pem
            }
        }
        {
            name: "property: the bypass list starts with the five defaults, has no duplicate or comma, and keeps the rest in order"
            body: {
                for _ in 1..200 {
                    let domain = (1..(random int 1..3) | each { label } | str join ".")
                    let extra = (0..(random int 0..8) | each { random_entry $domain })
                    let got = (no_proxy_of $domain $extra)
                    let defaults = ["localhost" "127.0.0.1" "::1" ".svc" $".($domain)"]
                    assert equal ($got | first 5) $defaults ($extra | to nuon)
                    assert equal ($got | uniq | length) ($got | length) ($got | to nuon)
                    assert equal ($got | skip 5) ($extra | where {|e| $e not-in $defaults } | uniq) ($extra | to nuon)
                    assert ($got | all {|e| not ($e | str contains ",") }) ($got | to nuon)
                }
            }
        }
        {
            name: "property: a pod gains nothing unless there is egress and its agent declares the section"
            body: {
                let empty = { env: [], volumes: [], mounts: [], config_maps: [] }
                let others = ["POLAR_EGRESS_NO_PROXY" "POLAR_EGRESS_CA_CERT" "JIRA_URL" "POLAR_CACHE_ROOT" "TLS_CA_CERT"]
                for _ in 1..200 {
                    let declared = ($others | where {|_| random bool })
                    let settings = {
                        proxy: (if (random bool) { $"http://(label).example:(random int 1..65535)" } else { null })
                        no_proxy: (["localhost" "127.0.0.1" "::1" ".svc" ".cluster.local"] ++ (0..(random int 0..3) | each { $".(label)" }))
                        ca_pem: (if (random bool) { fake_pem } else { null })
                    }
                    let workload = (label)
                    assert equal (egress_entries $settings $workload $declared) $empty ($declared | to nuon)
                    let any_declared = (if (random bool) { $declared | append "POLAR_EGRESS_PROXY" } else { $declared })
                    assert equal (egress_entries null $workload $any_declared) $empty ($any_declared | to nuon)
                }
            }
        }
        {
            name: "a pod whose agent declares the section is given the proxy, the bypass list and the CA"
            body: {
                let pem = (fake_pem)
                let declared = ["POLAR_EGRESS_PROXY" "POLAR_EGRESS_NO_PROXY" "POLAR_EGRESS_CA_CERT"]
                let settings = { proxy: "http://proxy.corp.example:3128", no_proxy: ["localhost" ".svc" ".corp.example"], ca_pem: $pem }
                assert equal (egress_entries $settings "jira-observer" $declared) {
                    env: [
                        { name: "POLAR_EGRESS_PROXY", value: "http://proxy.corp.example:3128", secret: null, key: null, from: "egress" }
                        { name: "POLAR_EGRESS_NO_PROXY", value: "localhost,.svc,.corp.example", secret: null, key: null, from: "egress" }
                        { name: "POLAR_EGRESS_CA_CERT", value: "/etc/polar-egress-ca/ca.pem", secret: null, key: null, from: "egress" }
                    ]
                    volumes: [{ name: "polar-egress-ca", secret: null, audience: null, config_map: "jira-observer-egress-ca", from: "egress" }]
                    mounts: [{ name: "polar-egress-ca", path: "/etc/polar-egress-ca", read_only: true, from: "egress" }]
                    config_maps: [{ name: "jira-observer-egress-ca", key: "ca.pem", content: $pem }]
                }
                let proxy_only = (egress_entries ($settings | update ca_pem null) "jira-observer" $declared)
                assert equal ($proxy_only.env | get name) ["POLAR_EGRESS_PROXY" "POLAR_EGRESS_NO_PROXY"]
                assert equal [$proxy_only.volumes $proxy_only.mounts $proxy_only.config_maps] [[] [] []]
                let ca_only = (egress_entries ($settings | update proxy null) "jira-observer" $declared)
                assert equal ($ca_only.env | get name) ["POLAR_EGRESS_CA_CERT"]
            }
        }
        {
            # docs/architecture/egress.md, "The cluster's own CA, for one workload": a catalog entry or a configuration under test
            # (docs/architecture/configurations-under-test.md) trusts it, and only the file every pod has; nothing else sets an
            # egress variable, which is the cluster's setting.
            name: "only a catalog entry or a configuration under test trusts the cluster's CA, and only its own file; no one else sets egress"
            body: {
                let ca = { name: $CLUSTER_CA_VAR, value: $CLUSTER_CA_FILE }
                let proxy = { name: "POLAR_EGRESS_PROXY", value: "http://proxy.corp.example:3128" }
                let other = { name: "JIRA_URL", value: "https://jira.example" }
                for from in ["catalog" "under-test"] {
                    assert equal (env_problems "gitlab-observer" [{ from: $from, env: [$ca $other] }]) [] $from
                    let wrong = (env_problems "gitlab-observer" [{ from: $from, env: [($ca | update value "/etc/elsewhere/ca.pem")] }])
                    assert (($wrong | length) == 1 and ($wrong.0 | str contains $CLUSTER_CA_FILE)) $"($from): ($wrong | to nuon)"
                }
                for from in ["catalog" "target" "under-test" "cluster"] {
                    let refused = (env_problems "jira-observer" [{ from: $from, env: [$proxy] }])
                    assert (($refused | length) == 1 and ($refused.0 | str contains "set cluster.egress instead")) $"($from): ($refused | to nuon)"
                }
                for from in ["target" "cluster"] {
                    let refused = (env_problems "gitlab-observer" [{ from: $from, env: [$ca] }])
                    assert (($refused | length) == 1 and ($refused.0 | str contains "a catalog entry or a configuration under test")) $"($from): ($refused | to nuon)"
                }
                assert equal (env_problems "jira-observer" [{ from: "target", env: [$other] } { from: "cluster", env: [] }]) []
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
