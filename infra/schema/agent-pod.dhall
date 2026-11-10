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


-- infra/schema/agent-pod.dhall
--
-- The pod every catalog workload's is built on, from what its Spec says (agent-spec.dhall), in two parts:
--
--   base       its account, volumes, environment and mounts, restart, grace and placement, as a PodSpec with no
--              container of its own (`Base`). Every pod has it.
--   identity   its identity's init containers: the custody daemon, when the pod's keys are its, then polar-init, which
--              gets the pod its certificates (`Pod`). An agent's pod has it; a build's has none
--              (docs/architecture/build-orchestrator.md, revised 3).
--
-- The agent template (agent.dhall) puts both together and adds the agent's container; the PodTemplate (pod-template.dhall)
-- takes the base and adds a build's fetch and pipeline. Like agent.dhall, it holds structure only.

let kubernetes = ./kubernetes.dhall

let Constants = ./constants.dhall

let functions = ./functions.dhall

let T = ./agent-spec.dhall

let Prelude =
      https://prelude.dhall-lang.org/package.dhall
        sha256:931cbfae9d746c4611b07633ab1e547637ab4ba138b16bf65ef1b9ad66a60b7f

let toEnv =
      λ(e : T.EnvEntry) →
        kubernetes.EnvVar::{
        , name = e.name
        , value = e.value
        , valueFrom =
            Prelude.Optional.map
              Text
              kubernetes.EnvVarSource.Type
              ( λ(secretName : Text) →
                  kubernetes.EnvVarSource::{
                  , secretKeyRef = Some kubernetes.SecretKeySelector::{
                    , name = Some secretName
                    , key = Prelude.Optional.default Text "" e.key
                    }
                  }
              )
              e.secret
        }

let toVolume =
      λ(expiration : Natural) →
      λ(x : T.VolumeEntry) →
        kubernetes.Volume::{
        , name = x.name
        , emptyDir =
            if    Prelude.Optional.null Text x.secret
               && Prelude.Optional.null Text x.audience
               && Prelude.Optional.null Text x.config_map
               && Prelude.Optional.null Text x.claim
            then  Some kubernetes.EmptyDirVolumeSource::{=}
            else  None kubernetes.EmptyDirVolumeSource.Type
        , secret =
            Prelude.Optional.map
              Text
              kubernetes.SecretVolumeSource.Type
              ( λ(secretName : Text) →
                  kubernetes.SecretVolumeSource::{
                  , secretName = Some secretName
                  , items =
                      if    Prelude.List.null { key : Text, path : Text } x.items
                      then  None (List kubernetes.KeyToPath.Type)
                      else  Some
                              ( Prelude.List.map
                                  { key : Text, path : Text }
                                  kubernetes.KeyToPath.Type
                                  ( λ(i : { key : Text, path : Text }) →
                                      kubernetes.KeyToPath::{ key = i.key, path = i.path }
                                  )
                                  x.items
                              )
                  }
              )
              x.secret
        , configMap =
            Prelude.Optional.map
              Text
              kubernetes.ConfigMapVolumeSource.Type
              ( λ(configMapName : Text) →
                  kubernetes.ConfigMapVolumeSource::{
                  , name = Some configMapName
                  }
              )
              x.config_map
        , persistentVolumeClaim =
            Prelude.Optional.map
              Text
              kubernetes.PersistentVolumeClaimVolumeSource.Type
              ( λ(claimName : Text) →
                  kubernetes.PersistentVolumeClaimVolumeSource::{
                  , claimName = claimName
                  }
              )
              x.claim
        , projected =
            Prelude.Optional.map
              Text
              kubernetes.ProjectedVolumeSource.Type
              ( λ(audience : Text) →
                  kubernetes.ProjectedVolumeSource::{
                  , sources = Some
                    [ kubernetes.VolumeProjection::{
                      , serviceAccountToken = Some kubernetes.ServiceAccountTokenProjection::{
                        , path = "token"
                        , audience = Some audience
                        , expirationSeconds = Some
                            expiration
                        }
                      }
                    ]
                  }
              )
              x.audience
        }

let toMount =
      λ(m : T.MountEntry) →
        kubernetes.VolumeMount::{
        , name = m.name
        , mountPath = m.path
        , readOnly = if m.read_only then Some True else None Bool
        }

let toInitMount =
      λ(m : T.InitMountEntry) →
        kubernetes.VolumeMount::{ name = m.name, mountPath = m.path }

let base =
      λ(v : T.Base) →
        let volumes =
              Prelude.List.map
                T.VolumeEntry
                kubernetes.Volume.Type
                (toVolume v.sa_token_expiration_secs)
                v.volumes

        let env =
                Prelude.List.map T.EnvEntry kubernetes.EnvVar.Type toEnv v.env

        let mounts =
                Prelude.List.map T.MountEntry kubernetes.VolumeMount.Type toMount v.mounts

        let placed = functions.placementOf v.placement

        let spec =
              kubernetes.PodSpec::{
              , nodeSelector = placed.nodeSelector
              , tolerations = placed.tolerations
              , imagePullSecrets = Some v.pull_secrets
              , serviceAccountName = Some v.service_account
              , automountServiceAccountToken = v.automount_sa_token
              , volumes = Some volumes
              , restartPolicy = Some v.restart_policy
              , terminationGracePeriodSeconds = Some v.termination_grace_secs
              , containers = [] : List kubernetes.Container.Type
              }

        in  { env, volumes, mounts, spec }

let identity =
      λ(v : T.Pod) →
        -- The custody daemon, when the pod's keys are its (docs/architecture/key-custody.md, step 4): a native sidecar,
        -- an init container that runs for the pod's whole life, declared before polar-init so it starts first. Its own
        -- UID; the pod's group, which it shares its socket with; every capability dropped but IPC_LOCK, so its memory
        -- locks.
        let custodySidecar =
              merge
                { None = [] : List kubernetes.Container.Type
                , Some =
                    λ(c : T.Custody) →
                      [ kubernetes.Container::{
                        , name = "polar-custody"
                        , image = Some c.image
                        , imagePullPolicy = Some v.pull_policy
                        , restartPolicy = Some "Always"
                        , terminationMessagePolicy = Some Constants.TerminationMessageFromLogs
                        , securityContext = Some
                            (     kubernetes.SecurityContext::{
                                  , runAsUser = Some c.daemon_uid
                                  , runAsGroup = Some c.group
                                  , runAsNonRoot = Some True
                                  , capabilities = Some kubernetes.Capabilities::{
                                    , drop = Some [ "ALL" ]
                                    , add = Some [ "IPC_LOCK" ]
                                    }
                                  }
                              //  Constants.hardening
                            )
                        , env = Some
                          [ kubernetes.EnvVar::{
                            , name = "POLAR_CUSTODY_SOCKET"
                            , value = Some c.socket
                            }
                          , kubernetes.EnvVar::{
                            , name = "POLAR_CUSTODY_CA_CERT"
                            , value = Some c.ca_cert
                            }
                          , kubernetes.EnvVar::{
                            , name = "POLAR_CUSTODY_INSTALLER_UID"
                            , value = Some (Natural/show c.installer_uid)
                            }
                          , kubernetes.EnvVar::{
                            , name = "POLAR_CUSTODY_WORKLOAD_UIDS"
                            , value = Some c.workload_uids
                            }
                          -- Where it watches, as its pod, for its own revocation (docs/architecture/key-custody.md,
                          -- step 5): the broker every client in the pod is given.
                          , kubernetes.EnvVar::{
                            , name = "BROKER_ADDR"
                            , value = Some Constants.cassiniAddr
                            }
                          , kubernetes.EnvVar::{
                            , name = "CASSINI_SERVER_NAME"
                            , value = Some Constants.cassiniDNSName
                            }
                          ]
                        , volumeMounts = Some
                          [ kubernetes.VolumeMount::{
                            , name = c.volume
                            , mountPath = c.dir
                            }
                          , kubernetes.VolumeMount::{
                            , name = c.ca_volume
                            , mountPath = c.ca_dir
                            , readOnly = Some True
                            }
                          ]
                        }
                      ]
                }
                v.custody

        -- polar-init's client environment: with the daemon, no key file.
        let clientEnv =
              merge
                { None = Constants.commonClientEnv
                , Some = λ(_ : T.Custody) → Constants.custodyClientEnv
                }
                v.custody

        -- The daemon, when the pod's keys are its, then polar-init, which gets the pod its certificates.
        in      custodySidecar
              # [ functions.makePolarInitContainerWith
                    clientEnv
                    v.polar_init_image
                    v.pull_policy
                    v.sa_token_volume
                    v.cert_issuer_url
                    ( Prelude.List.map
                        T.EnvEntry
                        kubernetes.EnvVar.Type
                        toEnv
                        v.init_env
                    )
                    v.sa_token_path
                    ( Prelude.List.map
                        T.InitMountEntry
                        kubernetes.VolumeMount.Type
                        toInitMount
                        v.init_mounts
                    )
                    v.dep_checks
                    v.certs
                ]

in  { base, identity }
