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

# infra/targets/sandbox-local/secrets.nu
#
# Creates Kubernetes secrets and ConfigMaps required by the minimal Polar
# profile: neo4j, cassini, cert-issuer, jaeger, jira, kube agents.
#
# Reads encrypted secrets from secrets.sops.yaml (shared team secrets)
# and user.sops.yaml (user-specific secrets), decrypting with SOPS.
# A Secret made from them is updated when they change; one made here (the
# shutdown token) is made once and kept (infra/secrets-lib.nu).
#
# Called by infra/up.nu after namespaces are created.

use ../../secrets-lib.nu *

# The Secrets this target makes, as data: each by namespace and name, with the SOPS keys its fields are made from (`data`,
# field: key) or the field generated once (`generated`). `main` makes them from this, and the plan names them from it
# (`declared`), never a value. A key in `defaults` has that value when the SOPS files give none; `optional` Secrets are
# skipped, with a warning, when their keys are missing.
export const SECRETS = [
    { namespace: "polar-graph", name: "neo4j-secret", from: { sops: ["neo4j_auth"] }, data: { secret: "neo4j_auth" } }
    # The token that lets a client ask the broker to shut down. Made here, once; a re-run finds it and leaves it. Read it with:
    # kubectl -n polar get secret cassini-shutdown-token -o jsonpath='{.data.token}' | base64 -d
    { namespace: "polar", name: "cassini-shutdown-token", from: { generated: "token" } }
    { namespace: "polar", name: "polar-graph-pw", from: { sops: ["graph_password"] }, data: { secret: "graph_password" } }
    {
        namespace: "polar-auth", name: "keycloak-admin-secret", from: { sops: ["keycloak_admin_user", "keycloak_admin_password"] }
        data: { username: "keycloak_admin_user", password: "keycloak_admin_password" }, defaults: { keycloak_admin_user: "admin" }
        required: "keycloak_admin_password", optional: true
    }
    {
        namespace: "polar-auth", name: "keycloak-db-secret", from: { sops: ["keycloak_db_password"] }
        data: { password: "keycloak_db_password" }, required: "keycloak_db_password", optional: true
    }
]

# What this target makes, as the plan names it: no value.
def "main declared" [] {
    $SECRETS | each {|s| $s | select namespace name from } | to json --raw | print
}

def main [target_dir: string, repo_root: string] {
    print "── secrets ──"
    print "  Decrypting secrets..."

    # A file that will not decrypt matters only if it leaves a secret the cluster needs unmade.
    let checked = (secrets_check $target_dir (existing_required_secrets))
    let secrets = $checked.secrets
    let failures = $checked.failures
    if ($checked.problems | is-not-empty) {
        for p in $checked.problems { print -e $"  FAILED: ($p)" }
        exit 1
    }
    for f in $failures {
        print $"    note: could not decrypt ($f.file) \(($f.reason)\); every secret needed already exists"
    }
    # A value stored base64-encoded would reach the workload still encoded: Kubernetes encodes it again.
    for w in $checked.warnings { print $"    WARNING: ($w)" }

    print "  Creating and updating secrets..."
    print ""

    for namespace in ($SECRETS | get namespace | uniq) {
        print $"  [($namespace)]"
        for d in ($SECRETS | where namespace == $namespace) {
            if ($d.from.generated? | default null) != null {
                kubectl_generated_secret $d.name $d.namespace [$"($d.from.generated)=(random_token)"]
                continue
            }
            let value = {|key| $secrets | get -o $key | default "" | default -e ($d.defaults? | default {} | get -o $key | default "") }
            let required = ($d.required? | default ($d.data | values | first))
            if (do $value $required | is-empty) {
                if ($d.optional? | default false) and not (secret_exists $d.name $d.namespace) {
                    print $"    WARNING: ($required) not set -- skipping ($d.name)"
                }
                continue
            }
            kubectl_sops_secret $d.name $d.namespace ($d.data | items {|field, key| $"($field)=(do $value $key)" })
        }
        print ""
    }
    print "  secrets: done"
    print ""
}
