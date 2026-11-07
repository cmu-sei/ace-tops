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

# infra/under-test/gitlab/sources.nu
#
# The GitLab observer's `sources` section for the test GitLab (docs/architecture/http-observers.md, G4d), printed as the JSON body the
# seed step signs (`make` in under-test.nuon): one source per query in src/agents/gitlab-http/queries, POSTed to the test GitLab's
# GraphQL endpoint with its `gitlab` credential, each paged by GraphQL's cursor, ten to a page; a project's pipelines, jobs, registry
# and packages, and a group's members, are follow-ups of the projects and groups sources, a query per item.

use main.nu [names]

const QUERIES = (path self | path dirname | path join "../../../src/agents/gitlab-http/queries")
# The credential, an entry of the observer's `credentials` section (under-test.nuon, `credentials`).
export const CREDENTIAL = "gitlab"
# Read every five minutes: often enough for a test, gentle on a GitLab with one Puma.
const INTERVAL = 300
# Items followed in one read: every project the seed makes, and the mirror, with room to spare.
const MAX_ITEMS = 100

def query [name: string] { open --raw ($QUERIES | path join $"($name).graphql") }

def paged [connection: string] { { style: "graphql", connection: $connection } }

def read_of [name: string, graphql: record, paging: any] {
    let s = { name: $"gitlab-($name)", url: $"https://(names | first)/api/graphql", interval_secs: $INTERVAL, credential: $CREDENTIAL, graphql: $graphql }
    if $paging == null { $s } else { $s | insert paging $paging }
}

# A follow-up of each item of `parent`'s pages: `name`'s query, by the item's full path, paged at `connection`.
def follow [name: string, parent: string, items: string, connection: string] {
    read_of $name {
        query: (query $parent)
        each: { items: $items, query: (query $name), variables: [{ name: "fullPath", from: "/fullPath" }], paging: (paged $connection), max_items: $MAX_ITEMS }
    } (paged $"/data/($parent)")
}

export def all_sources [] {
    [
        (read_of "metadata" { query: (query "metadata") } null)
        (read_of "projects" { query: (query "projects") } (paged "/data/projects"))
        (read_of "users" { query: (query "users") } (paged "/data/users"))
        (read_of "groups" { query: (query "groups") } (paged "/data/groups"))
        (read_of "runners" { query: (query "runners") } (paged "/data/runners"))
        (follow "project-pipelines" "projects" "/data/projects/nodes" "/data/project/pipelines")
        (follow "project-jobs" "projects" "/data/projects/nodes" "/data/project/jobs")
        (follow "project-container-repositories" "projects" "/data/projects/nodes" "/data/project/containerRepositories")
        (follow "project-packages" "projects" "/data/projects/nodes" "/data/project/packages")
        (follow "group-members" "groups" "/data/groups/nodes" "/data/group/groupMembers")
    ]
}

def main [] {
    { sources: (all_sources) } | to json --raw
}
