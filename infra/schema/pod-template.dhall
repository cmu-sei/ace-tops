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


-- infra/schema/pod-template.dhall
--
-- The build workload's pod setup, as a PodTemplate in the build namespace (docs/architecture/build-orchestrator.md, 5b and
-- 5c), which the build orchestrator reads and makes each build's Job from. On the base every catalog pod has
-- (agent-pod.dhall), with no identity: a build pod holds no Polar certificate, custody daemon or polar-init (revised 3).
--
--   fetch      an init container: build-fetch reads the source archive from Polar's registry by digest, checks it and
--              unpacks it into the workspace. The orchestrator gives it the archive's digest for each build.
--   pipeline   the one container, on the same image until the orchestrator replaces it with the repository's pipeline
--              image, pinned by its signed mapping. It reports what the build did by printing `polar-report` lines,
--              which the orchestrator reads from its log, judges and relays.
--
-- The names are the orchestrator's (orchestrator-backend-k8s, job.rs). Structure only: every fact arrives in the Spec.

let kubernetes = ./kubernetes.dhall

let Constants = ./constants.dhall

let functions = ./functions.dhall

let T = ./agent-spec.dhall

let P = ./pod-template-spec.dhall

let AgentPod = ./agent-pod.dhall

let render =
      λ(v : P.Spec) →
        let pod = AgentPod.base v.(T.Base)

        -- A build runs hardened (docs/architecture/build-orchestrator.md, decision 4): non-root, no privilege escalation, every
        -- capability dropped, the default seccomp profile. The orchestrator relaxes the pipeline's only as its signed mapping
        -- says.
        let hardened =
                  Constants.DropAllCapSecurityContext
              //  { allowPrivilegeEscalation = Some False
                  , seccompProfile = Some kubernetes.SeccompProfile::{
                    , type = "RuntimeDefault"
                    }
                  }

        -- Shared by the fetch, which writes it, and the pipeline, which builds in it.
        let workspace = "workspace"

        let workspaceMount =
              kubernetes.VolumeMount::{ name = workspace, mountPath = v.workspace }

        -- Shared by the fetch, which lays out the build's dependencies there, each by its digest, with Cargo's configuration for
        -- them, and the pipeline, whose Cargo home it is: Cargo checks a git dependency out there (D3b).
        let dependencies = "dependencies"

        let dependenciesMount =
              kubernetes.VolumeMount::{ name = dependencies, mountPath = v.dependencies }

        -- It speaks to nobody: no certificate, no socket, only the registry and the workspace.
        let fetch =
              kubernetes.Container::{
              , name = "fetch"
              , image = Some v.image
              , imagePullPolicy = Some v.pull_policy
              , terminationMessagePolicy = Some Constants.TerminationMessageFromLogs
              , securityContext = Some hardened
              , env = Some
                [ kubernetes.EnvVar::{
                  , name = "CYCLOPS_WORKSPACE"
                  , value = Some v.workspace
                  }
                , kubernetes.EnvVar::{
                  , name = "CYCLOPS_DEPENDENCY_ROOT"
                  , value = Some v.dependencies
                  }
                ]
              , volumeMounts = Some [ workspaceMount, dependenciesMount ]
              }

        let pipeline =
              kubernetes.Container::{
              , name = "pipeline"
              , image = Some v.image
              , imagePullPolicy = Some v.pull_policy
              , terminationMessagePolicy = Some Constants.TerminationMessageFromLogs
              , securityContext = Some hardened
              , resources = functions.memoryOf v.memory
              , env = Some
                  (   pod.env
                    # [ kubernetes.EnvVar::{
                        , name = "CARGO_HOME"
                        , value = Some "${v.dependencies}/cargo"
                        }
                      ]
                  )
              , volumeMounts = Some (pod.mounts # [ workspaceMount, dependenciesMount ])
              }

        let podSpec =
              pod.spec
              with volumes = Some
                  (   pod.volumes
                    # [ kubernetes.Volume::{
                        , name = workspace
                        , emptyDir = Some kubernetes.EmptyDirVolumeSource::{=}
                        }
                      , kubernetes.Volume::{
                        , name = dependencies
                        , emptyDir = Some kubernetes.EmptyDirVolumeSource::{=}
                        }
                      ]
                  )
              with initContainers = Some [ fetch ]
              with containers = [ pipeline ]

        in  functions.podTemplateOf
              { name = v.name
              , namespace = v.namespace
              -- Its pods are never issued, so they are not instances of an identity.
              , instances = < one | many >.one
              , pod = podSpec
              }

in  render
