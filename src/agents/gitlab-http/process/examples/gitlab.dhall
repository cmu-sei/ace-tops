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

in  { guard = [ { any_of = [ { path = "body.data", prefixes = [] : List Text } ] } ]
    , rules =
      [ { name = "project"
        , parent = ""
        , each = over "body.data.projects.nodes"
        , when = every
        , label = "GitlabProject"
        , keys = [ { name = "origin", from = "origin" }, { name = "id", from = "item.id" } ]
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
      ]
    }
