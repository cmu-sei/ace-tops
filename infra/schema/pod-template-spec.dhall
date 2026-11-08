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


-- infra/schema/pod-template-spec.dhall
--
-- The record `infra/resolve.nu json <workload>` produces for a workload of kind "template", as a Dhall type: the pod every
-- catalog workload shares (agent-spec.dhall, `Pod`), and what a PodTemplate adds to it. render-catalog.nu checks the
-- resolved JSON against it with `json-to-dhall`, as it does an agent's.

let T = ./agent-spec.dhall

let Spec =
        T.Pod
      ⩓ { name : Text
        , kind : Text
        , namespace : Text
        -- The image the template's containers run until something of Polar's replaces one: for the build workload, the
        -- fetch image (docs/architecture/build-orchestrator.md, 5c).
        , image : Text
        , instances : < one | many >
        , needs : List Text
        -- Where the fetch unpacks the source and the pipeline builds: orchestrator_core::WORKSPACE_PATH.
        , workspace : Text
        , memory : Optional { request : Text, limit : Text }
        }

in  { Spec }
