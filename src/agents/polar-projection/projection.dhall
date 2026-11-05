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

-- The type of a projection: how one kind of document becomes nodes and edges in the graph
-- (docs/architecture/http-observers.md). `polar-sign` checks an author's file against it, with imports off, so a file
-- cannot name this one and is given the type by the tool. The agent judges the JSON again and trusts none of this.
--
-- It is flat because a Dhall type cannot refer to itself, and has no Optional because a signed document cannot hold a
-- null: an empty `parent`, `edge` or `only` means there is none.
--
-- What a path may start from: `source` (the source's signed name), `body` (the document), and what a step binds.

let Field =
    -- A property: its name in the graph, and the path its value comes from.
      { name : Text, from : Text }

let Step =
    -- For each entry at the path `over`, an object's or a list's, binding its key and its value. `only`, if any, keeps
    -- the keys named.
      { key : Text, value : Text, over : Text, only : List Text }

let Rule =
      { -- What another rule names as its parent. Unique.
        name : Text
      , -- The rule this one runs inside, once per node it wrote, seeing what it bound. It must come earlier.
        parent : Text
      , each : List Step
      , label : Text
      , -- What identifies the node. Each must be there, or that node is skipped.
        keys : List Field
      , -- What else it holds. One that is not there is left off.
        set : List Field
      , -- The type of the edge from the parent's node to this one.
        edge : Text
      }

in  { rules : List Rule }
