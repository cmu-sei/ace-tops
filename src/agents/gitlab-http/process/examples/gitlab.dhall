-- ACE Tool
--
-- Copyright 2026 Carnegie Mellon University.
--
-- NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS
-- FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
-- EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
-- PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE
-- MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
-- TRADEMARK, OR COPYRIGHT INFRINGEMENT.
--
-- Licensed under a MIT (SEI)-style license, please see license.txt or contact
-- permission@sei.cmu.edu for full terms.
--
-- [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited
-- distribution.  Please see Copyright notice for non-US Government use and distribution.
--
-- This Software includes and/or makes use of Third-Party Software each subject to its own license.
--
-- DM26-0670

-- GitLab's GraphQL pages, as the GitLab observer reads them (docs/architecture/http-observers.md, "GitLab"): each node keyed
-- by the origin of the GitLab it came from and GitLab's own id. Every page is `data`; each rule reads the list its query
-- brings back, and says by `when` which entries are its own where lists share a shape.
let Checks = List { any_of : List { path : Text, prefixes : List Text } }

let every = [] : Checks

let over =
      \(list : Text) ->
        [ { key = "i", value = "item", over = list, only = [] : List Text } ]

let once = [] : List { key : Text, value : Text, over : Text, only : List Text }

let has = \(path : Text) -> [ { any_of = [ { path = path, prefixes = [] : List Text } ] } ]

let keyed = [ { name = "origin", from = "origin" }, { name = "id", from = "item.id" } ]

let nothing = [] : List { name : Text, from : Text }

let at = \(path : Text) -> [ { name = "origin", from = "origin" }, { name = "id", from = path } ]

in  { guard = [ { any_of = [ { path = "body.data", prefixes = [] : List Text } ] } ]
    , rules =
      [ { name = "project"
        , parent = ""
        , each = over "body.data.projects.nodes"
        , when = every
        , label = "GitlabProject"
        , keys = keyed
        , set =
          [ { name = "full_path", from = "item.fullPath" }
          , { name = "name", from = "item.name" }
          , { name = "description", from = "item.description" }
          , { name = "visibility", from = "item.visibility" }
          , { name = "archived", from = "item.archived" }
          , { name = "created_at", from = "item.createdAt" }
          , { name = "last_activity_at", from = "item.lastActivityAt" }
          , { name = "web_url", from = "item.webUrl" }
          ]
        , edge = ""
        }
      , { name = "instance"
        , parent = ""
        , each = once
        , when = has "body.data.metadata"
        , label = "GitlabInstance"
        , keys = [ { name = "origin", from = "origin" } ]
        , set =
          [ { name = "version", from = "body.data.metadata.version" }
          , { name = "revision", from = "body.data.metadata.revision" }
          , { name = "enterprise", from = "body.data.metadata.enterprise" }
          ]
        , edge = ""
        }
      , { name = "user"
        , parent = ""
        , each = over "body.data.users.nodes"
        , when = every
        , label = "GitlabUser"
        , keys = keyed
        , set =
          [ { name = "username", from = "item.username" }
          , { name = "name", from = "item.name" }
          , { name = "state", from = "item.state" }
          , { name = "bot", from = "item.bot" }
          , { name = "created_at", from = "item.createdAt" }
          , { name = "web_url", from = "item.webUrl" }
          ]
        , edge = ""
        }
      , { name = "group"
        , parent = ""
        , each = over "body.data.groups.nodes"
        , when = every
        , label = "GitlabGroup"
        , keys = keyed
        , set =
          [ { name = "full_path", from = "item.fullPath" }
          , { name = "name", from = "item.name" }
          , { name = "visibility", from = "item.visibility" }
          , { name = "created_at", from = "item.createdAt" }
          , { name = "web_url", from = "item.webUrl" }
          ]
        , edge = ""
        }
      , { name = "parent_group"
        , parent = "group"
        , each = once
        , when = has "item.parent"
        , label = "GitlabGroup"
        , keys = [ { name = "origin", from = "origin" }, { name = "id", from = "item.parent.id" } ]
        , set = [] : List { name : Text, from : Text }
        , edge = "SUBGROUP_OF"
        }
      , { name = "runner"
        , parent = ""
        , each = over "body.data.runners.nodes"
        , when = every
        , label = "GitlabRunner"
        , keys = keyed
        , set =
          [ { name = "description", from = "item.description" }
          , { name = "runner_type", from = "item.runnerType" }
          , { name = "status", from = "item.status" }
          , { name = "paused", from = "item.paused" }
          , { name = "created_at", from = "item.createdAt" }
          ]
        , edge = ""
        }
      , { name = "pipelines_project"
        , parent = ""
        , each = once
        , when = has "body.data.project.pipelines"
        , label = "GitlabProject"
        , keys = at "body.data.project.id"
        , set = nothing
        , edge = ""
        }
      , { name = "pipeline"
        , parent = "pipelines_project"
        , each = over "body.data.project.pipelines.nodes"
        , when = every
        , label = "GitlabPipeline"
        , keys = keyed
        , set =
          [ { name = "iid", from = "item.iid" }
          , { name = "status", from = "item.status" }
          , { name = "ref", from = "item.ref" }
          , { name = "sha", from = "item.sha" }
          , { name = "source", from = "item.source" }
          , { name = "created_at", from = "item.createdAt" }
          , { name = "finished_at", from = "item.finishedAt" }
          , { name = "duration", from = "item.duration" }
          ]
        , edge = "HAS_PIPELINE"
        }
      , { name = "job_pipeline"
        , parent = ""
        , each = over "body.data.project.jobs.nodes"
        , when = has "item.pipeline"
        , label = "GitlabPipeline"
        , keys = at "item.pipeline.id"
        , set = nothing
        , edge = ""
        }
      , { name = "job"
        , parent = "job_pipeline"
        , each = once
        , when = every
        , label = "GitlabJob"
        , keys = keyed
        , set =
          [ { name = "name", from = "item.name" }
          , { name = "status", from = "item.status" }
          , { name = "stage", from = "item.stage.name" }
          , { name = "created_at", from = "item.createdAt" }
          , { name = "finished_at", from = "item.finishedAt" }
          , { name = "duration", from = "item.duration" }
          ]
        , edge = "HAS_JOB"
        }
      , { name = "job_runner"
        , parent = "job"
        , each = once
        , when = has "item.runner"
        , label = "GitlabRunner"
        , keys = at "item.runner.id"
        , set = nothing
        , edge = "EXECUTED_BY"
        }
      , { name = "repositories_project"
        , parent = ""
        , each = once
        , when = has "body.data.project.containerRepositories"
        , label = "GitlabProject"
        , keys = at "body.data.project.id"
        , set = nothing
        , edge = ""
        }
      , { name = "container_repository"
        , parent = "repositories_project"
        , each = over "body.data.project.containerRepositories.nodes"
        , when = every
        , label = "GitlabContainerRepository"
        , keys = keyed
        , set =
          [ { name = "name", from = "item.name" }
          , { name = "path", from = "item.path" }
          , { name = "location", from = "item.location" }
          , { name = "created_at", from = "item.createdAt" }
          , { name = "tags_count", from = "item.tagsCount" }
          ]
        , edge = "HAS_CONTAINER_REPOSITORY"
        }
      , { name = "packages_project"
        , parent = ""
        , each = once
        , when = has "body.data.project.packages"
        , label = "GitlabProject"
        , keys = at "body.data.project.id"
        , set = nothing
        , edge = ""
        }
      , { name = "package"
        , parent = "packages_project"
        , each = over "body.data.project.packages.nodes"
        , when = every
        , label = "GitlabPackage"
        , keys = keyed
        , set =
          [ { name = "name", from = "item.name" }
          , { name = "version", from = "item.version" }
          , { name = "package_type", from = "item.packageType" }
          , { name = "status", from = "item.status" }
          , { name = "created_at", from = "item.createdAt" }
          ]
        , edge = "HAS_PACKAGE"
        }
      , { name = "members_group"
        , parent = ""
        , each = once
        , when = has "body.data.group.groupMembers"
        , label = "GitlabGroup"
        , keys = at "body.data.group.id"
        , set = nothing
        , edge = ""
        }
      , { name = "member"
        , parent = "members_group"
        , each = over "body.data.group.groupMembers.nodes"
        , when = has "item.user"
        , label = "GitlabUser"
        , keys = at "item.user.id"
        , set = nothing
        , edge = "HAS_MEMBER"
        }
      ]
    }
