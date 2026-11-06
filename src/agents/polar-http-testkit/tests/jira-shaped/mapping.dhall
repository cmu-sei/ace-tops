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

-- A Jira-shaped mapping, for the kit's test kind only (docs/architecture/http-observers.md, "Evidence", bite 7): Jira's
-- projects, groups and group members come as pages of one envelope, `{ startAt, maxResults, total, isLast, values }`, so
-- each rule says by `when` which entries are its own.
let Steps = List { key : Text, value : Text, over : Text, only : List Text }

let values = [ { key = "i", value = "item", over = "body.values", only = [] : List Text } ]

let has = \(path : Text) -> [ { any_of = [ { path = path, prefixes = [] : List Text } ] } ]

in  { guard = has "body.values"
    , rules =
      [ { name = "project"
        , parent = ""
        , each = values
        , when = has "item.projectTypeKey"
        , label = "JiraTestProject"
        , keys = [ { name = "id", from = "item.id" } ]
        , set =
          [ { name = "key", from = "item.key" }
          , { name = "name", from = "item.name" }
          , { name = "project_type", from = "item.projectTypeKey" }
          ]
        , edge = ""
        }
      , { name = "lead"
        , parent = "project"
        , each = [] : Steps
        , when = has "item.lead"
        , label = "JiraTestUser"
        , keys = [ { name = "account_id", from = "item.lead.accountId" } ]
        , set = [ { name = "display_name", from = "item.lead.displayName" } ]
        , edge = "LED_BY"
        }
      , { name = "group"
        , parent = ""
        , each = values
        , when = has "item.groupId"
        , label = "JiraTestGroup"
        , keys = [ { name = "group_id", from = "item.groupId" } ]
        , set = [ { name = "name", from = "item.name" } ]
        , edge = ""
        }
      , { name = "member"
        , parent = ""
        , each = values
        , when = has "item.accountType"
        , label = "JiraTestUser"
        , keys = [ { name = "account_id", from = "item.accountId" } ]
        , set =
          [ { name = "display_name", from = "item.displayName" }
          , { name = "active", from = "item.active" }
          , { name = "account_type", from = "item.accountType" }
          ]
        , edge = ""
        }
      ]
    }
