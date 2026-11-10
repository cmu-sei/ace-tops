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

-- infra/schema/agent.dhall
--
-- The one Job template every catalog agent shares (observers, consumers,
-- processors). It holds structure only. Every fact (which env, which
-- volumes, which dependency checks) arrives in the Spec, resolved from
-- infra/config by infra/resolve.nu. Nothing here branches on which agent it
-- is; variation is data.
--
-- If a workload does not fit this shape, it stays a custom chart (the escape
-- hatch). Do not add a Bool to the Spec to make it fit.

let kubernetes = ./kubernetes.dhall

let Constants = ./constants.dhall

let functions = ./functions.dhall

let T = ./agent-spec.dhall

let AgentPod = ./agent-pod.dhall

let Prelude =
      https://prelude.dhall-lang.org/package.dhall
        sha256:931cbfae9d746c4611b07633ab1e547637ab4ba138b16bf65ef1b9ad66a60b7f

let render =
      λ(v : T.Spec) →
        let restart = functions.restartOf v.job

        -- The pod every catalog workload shares, with an agent's identity (agent-pod.dhall), and the agent's own container in it.
        let pod = AgentPod.base v.(T.Base)

        let env = pod.env

        let mounts = pod.mounts

        let podSpec =
              pod.spec
              with initContainers = Some (AgentPod.identity v.(T.Pod))
              with containers =
                [ kubernetes.Container::{
                  , name = v.name
                  , restartPolicy = restart.restartPolicy
                  , restartPolicyRules = restart.restartPolicyRules
                  , terminationMessagePolicy = Some Constants.TerminationMessageFromLogs
                  , image = Some v.image
                  , imagePullPolicy = Some v.pull_policy
                  , securityContext = Some Constants.HardenedSecurityContext
                  , resources = functions.memoryOf v.memory
                  , env = Some env
                  , ports =
                      if    Prelude.List.null Natural v.ports
                      then  None (List kubernetes.ContainerPort.Type)
                      else  Some
                              ( Prelude.List.map
                                  Natural
                                  kubernetes.ContainerPort.Type
                                  ( λ(port : Natural) →
                                      kubernetes.ContainerPort::{ containerPort = port }
                                  )
                                  v.ports
                              )
                  , volumeMounts = Some mounts
                  , livenessProbe = Some kubernetes.Probe::{
                    , exec = Some { command = Some [ "polar-healthcheck" ] }
                    , initialDelaySeconds = Some v.probe.initial_delay_secs
                    , periodSeconds = Some v.probe.period_secs
                    , failureThreshold = Some v.probe.failure_threshold
                    , timeoutSeconds = Some v.probe.timeout_secs
                    }
                  }
                ]

        in  functions.workloadOf
              { name = v.name
              , namespace = v.namespace
              , job = v.job
              , instances = v.instances
              , pod = podSpec
              }

in  render
