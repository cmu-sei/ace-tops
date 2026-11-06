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

-- OpenAPI and Swagger documents: an application and its endpoints. `paths` has the same shape in 2.0, 3.0 and 3.1.

{ guard =
  [ { any_of =
      [ { path = "body.openapi", prefixes = [ "3." ] }
      , { path = "body.swagger", prefixes = [ "2." ] }
      ]
    }
  , { any_of = [ { path = "body.paths", prefixes = [] : List Text } ] }
  , { any_of = [ { path = "body.info.title", prefixes = [] : List Text } ] }
  ]
, rules =
  [ { name = "application"
    , parent = ""
    , each = [] : List { key : Text, value : Text, over : Text, only : List Text }
    , when = [] : List { any_of : List { path : Text, prefixes : List Text } }
    , label = "OpenApiApplication"
    , keys = [ { name = "source", from = "source" } ]
    , set =
      [ { name = "title", from = "body.info.title" }
      , { name = "api_version", from = "body.info.version" }
      , { name = "description", from = "body.info.description" }
      , { name = "license", from = "body.info.license.name" }
      , { name = "openapi", from = "body.openapi" }
      , { name = "swagger", from = "body.swagger" }
      ]
    , edge = ""
    }
  , { name = "endpoint"
    , parent = "application"
    , each =
      [ { key = "path", value = "item", over = "body.paths", only = [] : List Text }
      , { key = "method"
        , value = "operation"
        , over = "item"
        , only = [ "get", "put", "post", "delete", "options", "head", "patch", "trace" ]
        }
      ]
    , when = [] : List { any_of : List { path : Text, prefixes : List Text } }
    , label = "OpenApiEndpoint"
    , keys =
      [ { name = "source", from = "source" }
      , { name = "method", from = "method" }
      , { name = "path", from = "path" }
      ]
    , set =
      [ { name = "operation_id", from = "operation.operationId" }
      , { name = "summary", from = "operation.summary" }
      , { name = "description", from = "operation.description" }
      , { name = "deprecated", from = "operation.deprecated" }
      ]
    , edge = "HAS_ENDPOINT"
    }
  ]
}
