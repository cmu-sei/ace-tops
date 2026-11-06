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
      ]
    }
