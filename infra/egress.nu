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

# infra/egress.nu
#
# Whether a pod can reach a host outside the cluster. The git agents need it to read a repository that is not in the
# cluster, and it fails quietly when the cluster's DNS has nowhere to send a name it does not own: git says "Could
# not resolve host" long after the bring-up that caused it. up.nu runs this at the end and says what it finds. It
# reports and never stops the bring-up: a cluster used offline is a working cluster.
#
# The probe is the agent's own (docs/architecture/egress.md, "The probe"): git-repo-observer's image, run once as
# `git-repo-observer --probe-egress URL` in a Job of its own in Polar's namespace. It goes out as the observer does, with
# the observer's egress settings (its document, and the egress CA it mounts) through its own git client, and presents no
# credential: the Job has no init container, so no certificate, and no ServiceAccount token. It prints its verdict as
# JSON. The Job is deleted once its verdict is read. Its pod is owned by the Job, whose template pins the image by digest,
# so the attestation agent holds it to that owner and finds nothing (runtime-attestation.md, C2, O4); a Job is not held
# to the signed record.
#
# And the target's way out (docs/architecture/egress.md): `cluster.egress` in its config.nuon, a proxy, the hosts that
# bypass it, and a CA to trust beside the system's, all optional. `settings_of` judges it; `egress_entries` is what a
# workload whose agent declares the egress section (polar::egress) is given for it. A target that sets nothing gives
# nothing, and every pod is as it was.

use agent-pods.nu [pod_outcome]

const POLAR = "polar"

# The cluster's own CA, which a workload may be told to trust beside the system's roots (docs/architecture/egress.md, "The cluster's
# own CA, for one workload"): the file every agent pod has (resolve.nu, CUSTODY.ca_cert).
export const CLUSTER_CA_VAR = "POLAR_EGRESS_CLUSTER_CA"
export const CLUSTER_CA_FILE = "/etc/polar-ca/ca.pem"

# Who gives a workload an env entry, as `env_problems` names them.
const GIVERS = { catalog: "its catalog entry", target: "the target's config", under-test: "a configuration under test", cluster: "this cluster's inputs" }

# The agent the probe runs as: its workload (a Job, named as the chart named it) and the command its image runs. The images
# set a Cmd and no Entrypoint (agent-pods.nu), so the Job names the command, and the binary is on the image's PATH.
export const PROBE_WORKLOAD = "git-repo-observer"
const PROBE_BINARY = "git-repo-observer"
export const PROBE_LABEL = "polar.dev/probe"
const DEFAULT_URL = "https://github.com/octocat/Hello-World"

# How long the probe's pod may run once it has started: the agent's own bounds are 15 seconds to connect and 120 for
# an answer. And how long up.nu waits for it, its image's pull included.
const PROBE_DEADLINE_SECS = 150
const PROBE_WAIT = 4min

# The URL probed: POLAR_EGRESS_PROBE_URL if set.
export def probe_url [] { $env.POLAR_EGRESS_PROBE_URL? | default $DEFAULT_URL }

# The probe's Job, from the rendered Job of the workload it runs as (`job`, as the cluster holds it): its image, as pinned,
# its placement, and its hardening; its document and egress CA, the ConfigMaps it mounts; and nothing else: no init
# container, no Secret, no ServiceAccount token, and of its environment only where its document is. Never retried, gone
# a while after it ends whether anyone deletes it or not.
export def probe_job [job: record, name: string, url: string] {
    let workload = $job.metadata.name
    let pod = $job.spec.template.spec
    let container = ($pod.containers | where name == $workload | get -o 0)
    if $container == null { error make --unspanned { msg: $"($workload) has no container named for it to probe as" } }
    if not ($container.image =~ '@sha256:[0-9a-f]{64}$') {
        error make --unspanned { msg: $"($workload)'s image is not pinned by digest \(($container.image)\): a probe of it would not be what its owner pins" }
    }
    let config_maps = ($pod.volumes? | default [] | where {|v| ($v.configMap? | default null) != null })
    let kept = ($config_maps | get name)
    let mounts = ($container.volumeMounts? | default [] | where {|m| $m.name in $kept })
    let document = ($container.env? | default [] | where name == "POLAR_CONFIG" | where {|e| ($e.valueFrom? | default null) == null })
    let placement = ($pod | select -o nodeSelector tolerations affinity | transpose k v | where v != null | reduce --fold {} {|p, acc| $acc | insert $p.k $p.v })
    let labels = { $PROBE_LABEL: "egress" }
    {
        apiVersion: "batch/v1"
        kind: "Job"
        metadata: { name: $name, namespace: $job.metadata.namespace, labels: $labels }
        spec: {
            backoffLimit: 0
            activeDeadlineSeconds: $PROBE_DEADLINE_SECS
            ttlSecondsAfterFinished: 600
            template: {
                metadata: { labels: $labels }
                spec: ({
                    restartPolicy: "Never"
                    automountServiceAccountToken: false
                    enableServiceLinks: false
                    securityContext: ($pod.securityContext? | default {})
                    containers: [{
                        name: "probe"
                        image: $container.image
                        imagePullPolicy: ($container.imagePullPolicy? | default "IfNotPresent")
                        command: [$PROBE_BINARY "--probe-egress" $url]
                        env: $document
                        securityContext: ($container.securityContext? | default {})
                        volumeMounts: ($mounts ++ [{ name: "tmp", mountPath: "/tmp" }])
                    }]
                    volumes: ($config_maps ++ [{ name: "tmp", emptyDir: {} }])
                } | merge $placement)
            }
        }
    }
}

# What the probe found, from its pod's exit code and log (`r`: { exit, logs, reason }): { verdict, detail }. The agent
# prints one JSON line for each protocol it goes out with; the verdict is the first that did not reach, or reached. A pod
# that printed none says why in its reason or its last lines.
export def probe_verdict [r: record] {
    let found = ($r.logs | lines | each {|l| try { $l | from json } catch { null } } | where {|v| ($v | describe | str starts-with "record") and ($v.verdict? | default null) != null })
    if ($found | is-empty) {
        let said = ($r.logs | lines | where {|l| $l | is-not-empty } | last 3 | str join " | ")
        let why = ([$r.reason? $said] | compact --empty | str join ": ")
        return { verdict: "other", detail: $"the probe gave no verdict \(exit ($r.exit | default 'none')\)(if ($why | is-empty) { '' } else { $': ($why)' })" }
    }
    let failed = ($found | where verdict != "reached")
    let chosen = if ($failed | is-empty) { $found | first } else { $failed | first }
    { verdict: $chosen.verdict, detail: ($chosen.detail? | default "") }
}

# The lines to print for a verdict. Every one is a note: none of them stops anything.
export def egress_lines [verdict: string, url: string, detail: string] {
    match $verdict {
        "reached" => [$"pods can reach ($url)"]
        "dns" => [
            $"pods cannot resolve names outside the cluster \(the probe could not resolve the host in ($url)\). Anything that reads a repository outside the cluster, such as the git agents, will fail until they can. If you are working offline, ignore this."
            "CoreDNS sends names it does not own to the upstream in its Corefile. Its errors: kubectl -n kube-system logs -l k8s-app=kube-dns --tail=20"
            "If the cluster's DNS forwards to a resolver that runs only on the host (a second systemd-resolved listener, say), is that listener there: ss -lun 'sport = :5300' (the port is whatever the cluster forwards to)"
        ]
        "unreachable" => [
            $"pods resolved the name but could not connect to ($url), or the attempt hung. Check the host's network, VPN and firewall. If you are working offline, ignore this."
        ]
        "tls" => [
            $"pods reached ($url) and did not trust its certificate: ($detail). Something between that presents its own \(a TLS-inspecting proxy\) needs its CA in the target's cluster.egress.ca_file."
        ]
        "proxy" => [
            $"the way out is through cluster.egress.proxy, and the proxy could not be reached or would not open the way to ($url): ($detail)"
        ]
        _ => [
            $"the outside-access probe of ($url) failed in a way this check does not recognise: ($detail | lines | where {|l| $l | is-not-empty } | first | default '')"
        ]
    }
}

# Runs `probe` (url -> { skipped, exit, logs, reason }) and says what it found. Returns { verdict, lines }.
export def egress_report [url: string, probe: closure] {
    let r = (do $probe $url)
    if $r.skipped {
        return { verdict: "skipped", lines: [$"no ($PROBE_WORKLOAD) is deployed, and the probe runs as that agent, so access to the outside was not checked"] }
    }
    let v = (probe_verdict $r)
    { verdict: $v.verdict, lines: (egress_lines $v.verdict $url $v.detail) }
}

# The probe against the cluster: the probe's Job, made from the cluster's $PROBE_WORKLOAD Job, waited for, read, and deleted.
export def kube_probe [url: string] {
    let got = (^kubectl -n $POLAR get job $PROBE_WORKLOAD -o json | complete)
    if $got.exit_code != 0 { return { skipped: true, exit: null, logs: "", reason: "" } }
    let name = $"egress-probe-(random chars --length 6 | str lowercase)"
    let job = (probe_job ($got.stdout | from json) $name $url)
    let made = ($job | to json | ^kubectl create -f - | complete)
    if $made.exit_code != 0 { error make --unspanned { msg: $"the cluster refused the probe's Job: ($made.stderr | str trim)" } }
    let r = (try { wait_probe $name } catch {|e| { exit: null, logs: "", reason: $e.msg } })
    ^kubectl -n $POLAR delete job $name --cascade=background --wait=false --ignore-not-found | complete | ignore
    $r | insert skipped false
}

# Waits for the probe's pod to finish, or to be stuck, or for PROBE_WAIT: { exit, logs, reason }.
def wait_probe [name: string] {
    let deadline = ((date now) + $PROBE_WAIT)
    loop {
        let listed = (^kubectl -n $POLAR get pods -l $"job-name=($name)" -o json | complete)
        let pod = if $listed.exit_code == 0 { $listed.stdout | from json | get items | get -o 0 } else { null }
        let out = if $pod == null { { state: "running", exit: null, reason: "" } } else { pod_outcome $pod }
        if $out.state == "done" {
            let logs = (^kubectl -n $POLAR logs $pod.metadata.name | complete)
            return { exit: $out.exit, logs: $logs.stdout, reason: $out.reason }
        }
        if $out.state == "stuck" { return { exit: null, logs: "", reason: $out.reason } }
        if (date now) > $deadline { return { exit: null, logs: "", reason: $"the probe did not finish within ($PROBE_WAIT)" } }
        sleep 2sec
    }
}

# ── The target's egress setting (pure, but for reading the CA file) ──────────

const EGRESS_KEYS = ["proxy" "no_proxy" "ca_file"]

# The most a ConfigMap holds: Kubernetes refuses one whose data is over 1 MiB.
const CONFIG_MAP_BYTES = 1048576

# Where a pod finds the egress CA: a ConfigMap of the workload's own, mounted read-only.
const CA_VOLUME = "polar-egress-ca"
const CA_DIR = "/etc/polar-egress-ca"
const CA_KEY = "ca.pem"

# The variable whose declaration says an agent takes the egress section (polar::egress::SECTION).
const SENTINEL = "POLAR_EGRESS_PROXY"

const PROXY_SHAPE = "a proxy is an http:// or https:// URL with a host and a port, such as http://proxy.example.org:3128"
const ENTRY_SHAPE = "is not a host, .domain suffix, IP address or CIDR (no commas, spaces or empty entries)"

def refuse [msg: string] { error make --unspanned { msg: $msg } }

# A value as a message shows it: text as it is, anything else as nuon.
def shown [value: any] { if ($value | describe) == "string" { $value } else { $value | to nuon } }

# What reaches the proxy is never the cluster's own: loopback, every Service (`.svc`, and the cluster's domain), then
# what the target adds, each once, in that order. Written only when there is a proxy.
export def no_proxy_of [domain: string, extra: list] {
    ["localhost" "127.0.0.1" "::1" ".svc" $".($domain)"] ++ $extra | uniq
}

# An http or https URL with a host and a port, nothing after it but a slash, and no user or password: the value is
# written into a ConfigMap, which is no place for a credential. A refusal never repeats what may be one.
def check_proxy [proxy: any] {
    let shape = $"cluster.egress.proxy is '(shown $proxy)': ($PROXY_SHAPE)"
    if ($proxy | describe) != "string" { refuse $shape }
    if ($proxy =~ '^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]*@') {
        refuse "cluster.egress.proxy names a user or password: it is written into a ConfigMap, and a proxy that needs credentials is not supported"
    }
    let m = ($proxy | parse --regex '^(?<scheme>https?)://(?<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?):(?<port>[0-9]{1,5})/?$')
    if ($m | is-empty) { refuse $shape }
    let port = ($m.0.port | into int)
    if $port < 1 or $port > 65535 { refuse $shape }
}

# One entry of the bypass list as hyper-util reads it: a host, a .domain suffix, an IPv4 or IPv6 address, or a CIDR.
def entry_ok [entry: string] {
    let label = '[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?'
    let host = ('^\.?' + $label + '(?:\.' + $label + ')*$')
    let v4 = '^[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?:/[0-9]{1,2})?$'
    let v6 = '^[0-9A-Fa-f]*:[0-9A-Fa-f:.]*(?:/[0-9]{1,3})?$'
    ($entry =~ $host) or ($entry =~ $v4) or ($entry =~ $v6)
}

def check_no_proxy [extra: any] {
    let kind = ($extra | describe)
    if not ($kind | str starts-with "list") {
        refuse $"cluster.egress.no_proxy is ($kind): it is a list of hosts, .domain suffixes, IP addresses and CIDRs"
    }
    for e in $extra {
        if $e == "*" {
            refuse "cluster.egress.no_proxy has '*', which sends nothing through the proxy: remove cluster.egress.proxy instead"
        }
        if ($e | describe) != "string" or not (entry_ok $e) {
            refuse $"cluster.egress.no_proxy entry '(shown $e)' ($ENTRY_SHAPE)"
        }
    }
}

# The CA file's text: a file of the target's own directory, small enough for a ConfigMap, of PEM certificates only.
def check_ca [ca_file: any, target_dir: string] {
    let inside = $"infra/targets/($target_dir | path basename)"
    let named = (shown $ca_file)
    if ($ca_file | describe) != "string" or ($ca_file | is-empty) or ($ca_file | str starts-with "/") or (".." in ($ca_file | path split)) {
        refuse $"cluster.egress.ca_file is '($named)': it is a path inside ($inside)"
    }
    let path = ($target_dir | path join $ca_file)
    if ($path | path type) != "file" {
        refuse $"cluster.egress.ca_file ($ca_file) does not exist \(it is read relative to ($inside)\)"
    }
    let size = (ls $path | get 0.size | into int)
    if $size > $CONFIG_MAP_BYTES {
        refuse $"cluster.egress.ca_file ($ca_file) is ($size) bytes, more than a ConfigMap holds"
    }
    let raw = (open --raw $path)
    let text = if ($raw | describe) == "string" { $raw } else { try { $raw | decode utf-8 } catch { "" } }
    if ($text =~ '-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----') {
        refuse $"cluster.egress.ca_file ($ca_file) holds a private key: it must hold only CA certificates, and it is published in a ConfigMap"
    }
    let blocks = ($text | parse --regex '-----BEGIN CERTIFICATE-----(?<body>[\s\S]*?)-----END CERTIFICATE-----')
    if ($blocks | is-empty) {
        refuse $"cluster.egress.ca_file ($ca_file) holds no PEM certificate \(no -----BEGIN CERTIFICATE----- block\)"
    }
    for b in $blocks {
        let body = ($b.body | str replace --all --regex '\s' '')
        let decodes = (try { $body | decode base64 | ignore; true } catch { false })
        if ($body | is-empty) or (not $decodes) {
            refuse $"cluster.egress.ca_file ($ca_file) holds a CERTIFICATE block that is not base64"
        }
    }
    $text
}

# The target's egress setting, from its merged cluster settings (`cluster.nuon` under the target's own) and its directory
# (infra/targets/<t>, which the CA file is read from): { proxy, no_proxy (with the defaults), ca_pem }, or null when it
# sets none (`egress` absent, empty, or every key null). Anything that cannot work is an error that says why.
export def settings_of [cluster: record, target_dir: string] {
    let e = ($cluster.egress? | default null)
    if $e == null { return null }
    let kind = ($e | describe)
    if not ($kind | str starts-with "record") {
        refuse $"cluster.egress is ($kind): it is a record with any of proxy, no_proxy, ca_file"
    }
    for k in ($e | columns) {
        if not ($k in $EGRESS_KEYS) {
            refuse $"cluster.egress.($k) is not a setting: the settings are proxy, no_proxy, ca_file"
        }
    }
    let proxy = ($e.proxy? | default null)
    let extra = ($e.no_proxy? | default null)
    let ca_file = ($e.ca_file? | default null)
    if $proxy == null and $extra == null and $ca_file == null { return null }
    if $proxy != null { check_proxy $proxy }
    if $extra != null {
        if $proxy == null {
            refuse "cluster.egress.no_proxy is set but cluster.egress.proxy is not: there is nothing to bypass"
        }
        check_no_proxy $extra
    }
    let ca_pem = if $ca_file == null { null } else { check_ca $ca_file $target_dir }
    { proxy: $proxy, no_proxy: (no_proxy_of $cluster.domain ($extra | default [])), ca_pem: $ca_pem }
}

def egress_variable [name: string, value: string] {
    { name: $name, value: $value, secret: null, key: null, from: "egress" }
}

# What `workload` is given for the egress setting `settings` (settings_of), when its agent declares the egress section
# (`declared`, the variables its scaffold declares, has POLAR_EGRESS_PROXY): the variables, written into its document,
# and for a CA the ConfigMap that holds it, a volume of it and its mount. Nothing, otherwise.
export def egress_entries [settings: any, workload: string, declared: list] {
    let none = { env: [], volumes: [], mounts: [], config_maps: [] }
    if $settings == null or not ($SENTINEL in $declared) { return $none }
    let proxy = if $settings.proxy == null { [] } else {
        [
            (egress_variable "POLAR_EGRESS_PROXY" $settings.proxy)
            (egress_variable "POLAR_EGRESS_NO_PROXY" ($settings.no_proxy | str join ","))
        ]
    }
    if $settings.ca_pem == null { return ($none | update env $proxy) }
    let config_map = $"($workload)-egress-ca"
    {
        env: ($proxy | append (egress_variable "POLAR_EGRESS_CA_CERT" $"($CA_DIR)/($CA_KEY)"))
        volumes: [{ name: $CA_VOLUME, secret: null, audience: null, config_map: $config_map, from: "egress" }]
        mounts: [{ name: $CA_VOLUME, path: $CA_DIR, read_only: true, from: "egress" }]
        config_maps: [{ name: $config_map, key: $CA_KEY, content: $settings.ca_pem }]
    }
}

# Why the env entries `given` a workload, each `{ from: catalog | target | under-test | cluster, env }`, may not stand: the way out is
# the cluster's setting (cluster.egress, `egress_entries`), so no one sets an egress variable, except that a catalog entry or a
# configuration under test may have the workload trust the cluster's own CA, by its one file.
export def env_problems [workload: string, given: list] {
    $given | each {|g|
        let who = ($GIVERS | get $g.from)
        $g.env | where {|e| $e.name | str starts-with "POLAR_EGRESS_" } | each {|e|
            if $e.name != $CLUSTER_CA_VAR {
                $"($workload): ($e.name) is set by ($who), but it is the cluster's egress setting: set cluster.egress instead"
            } else if $g.from not-in ["catalog" "under-test"] {
                $"($workload): ($CLUSTER_CA_VAR) is set by ($who): only a catalog entry or a configuration under test has a workload trust the cluster's CA"
            } else if $e.value != $CLUSTER_CA_FILE {
                $"($workload): ($CLUSTER_CA_VAR) is ($e.value), and the cluster's own CA is ($CLUSTER_CA_FILE), which every pod has"
            }
        } | compact
    } | flatten
}
