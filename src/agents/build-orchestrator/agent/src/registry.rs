/*
   ACE Tool

   Copyright 2026 Carnegie Mellon University.

   NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS
   FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
   EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
   PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE
   MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
   TRADEMARK, OR COPYRIGHT INFRINGEMENT.

   Licensed under a MIT (SEI)-style license, please see license.txt or contact
   permission@sei.cmu.edu for full terms.

   [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited
   distribution.  Please see Copyright notice for non-US Government use and distribution.

   This Software includes and/or makes use of Third-Party Software each subject to its own license.

   DM26-0670
*/

//! The registry: a record of each build the orchestrator holds, as its job actor moves it through its states (Vaughn's,
//! with adoption added and bounded). In memory: a restarted orchestrator knows only the builds it adopts. The records of
//! builds that ended are kept up to [`ENDED_KEPT`], the oldest let go first, so a long-running orchestrator does not grow.

use orchestrator_core::types::{BuildRecord, BuildRequest, BuildState};
use ractor::{Actor, ActorProcessingErr, ActorRef, RpcReplyPort};
use std::collections::{HashMap, VecDeque};
use tracing::{error, info, warn};
use uuid::Uuid;

/// How many records of ended builds are kept.
pub const ENDED_KEPT: usize = 1024;

pub enum RegistryMessage {
    /// A build admitted, in Pending.
    Insert(BuildRequest),
    /// A Job found running at start: its record begins Scheduled.
    Adopt(BuildRequest),
    /// A state transition of a build held. Only the fields that are `Some` overwrite the record's.
    Transition {
        build_id: Uuid,
        next_state: BuildState,
        backend_handle: Option<String>,
        resolved_image: Option<String>,
        failure_reason: Option<String>,
    },
    Get(Uuid, RpcReplyPort<Option<BuildRecord>>),
}

pub struct BuildRegistry;

#[derive(Default)]
pub struct RegistryState {
    records: HashMap<Uuid, BuildRecord>,
    /// The builds that ended, oldest first.
    ended: VecDeque<Uuid>,
}

impl RegistryState {
    /// A build ended: its record is kept, and the oldest ended past the bound let go.
    fn ended(&mut self, build_id: Uuid) {
        self.ended.push_back(build_id);
        while self.ended.len() > ENDED_KEPT {
            if let Some(oldest) = self.ended.pop_front() {
                self.records.remove(&oldest);
            }
        }
    }
}

#[ractor::async_trait]
impl Actor for BuildRegistry {
    type Msg = RegistryMessage;
    type State = RegistryState;
    type Arguments = ();

    async fn pre_start(
        &self,
        _: ActorRef<Self::Msg>,
        _: (),
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(RegistryState::default())
    }

    async fn handle(
        &self,
        _: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            RegistryMessage::Insert(request) => {
                info!(build_id = %request.build_id, "a build is held");
                state
                    .records
                    .insert(request.build_id, BuildRecord::new(request));
            }
            RegistryMessage::Adopt(request) => {
                info!(build_id = %request.build_id, "a running build is adopted");
                let mut record = BuildRecord::new(request);
                record.state = BuildState::Scheduled;
                state.records.insert(record.build_id, record);
            }
            RegistryMessage::Transition {
                build_id,
                next_state,
                backend_handle,
                resolved_image,
                failure_reason,
            } => {
                let Some(record) = state.records.get_mut(&build_id) else {
                    warn!(%build_id, "a transition of a build not held");
                    return Ok(());
                };
                // A transition the state machine does not have is the sender's mistake; the record stays as it was.
                if let Err(e) = record.transition(next_state) {
                    error!(%build_id, "a transition refused: {e}");
                    return Ok(());
                }
                if let Some(handle) = backend_handle {
                    record.backend_handle = Some(handle);
                }
                if let Some(image) = resolved_image {
                    record.resolved_image = Some(image);
                }
                if let Some(reason) = failure_reason {
                    record.failure_reason = Some(reason);
                }
                if record.state.is_terminal() {
                    state.ended(build_id);
                }
            }
            RegistryMessage::Get(build_id, reply) => {
                let _ = reply.send(state.records.get(&build_id).cloned());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchestrator_core::types::SourceRef;

    fn request() -> BuildRequest {
        BuildRequest {
            build_id: Uuid::new_v4(),
            source: SourceRef::Git {
                url: "https://example.test/r.git".into(),
                commit_sha: "a".repeat(40),
            },
            pipeline_image: None,
            requested_at: chrono::Utc::now(),
            metadata: Default::default(),
            command: vec![],
        }
    }

    async fn get(registry: &ActorRef<RegistryMessage>, id: Uuid) -> Option<BuildRecord> {
        ractor::call!(registry, RegistryMessage::Get, id).unwrap()
    }

    fn to(id: Uuid, next_state: BuildState) -> RegistryMessage {
        RegistryMessage::Transition {
            build_id: id,
            next_state,
            backend_handle: None,
            resolved_image: None,
            failure_reason: None,
        }
    }

    #[tokio::test]
    async fn a_build_moves_as_its_state_machine_says_and_no_other_way() {
        let (registry, handle) = Actor::spawn(None, BuildRegistry, ()).await.unwrap();
        let r = request();
        let id = r.build_id;
        registry.cast(RegistryMessage::Insert(r)).unwrap();
        registry.cast(to(id, BuildState::Running)).unwrap();
        assert_eq!(get(&registry, id).await.unwrap().state, BuildState::Pending);
        registry.cast(to(id, BuildState::PreparingSource)).unwrap();
        registry.cast(to(id, BuildState::Failed)).unwrap();
        assert_eq!(get(&registry, id).await.unwrap().state, BuildState::Failed);

        let adopted = request();
        let aid = adopted.build_id;
        registry.cast(RegistryMessage::Adopt(adopted)).unwrap();
        registry.cast(to(aid, BuildState::Running)).unwrap();
        assert_eq!(
            get(&registry, aid).await.unwrap().state,
            BuildState::Running
        );
        registry.stop(None);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn the_oldest_ended_builds_are_let_go_past_the_bound() {
        let (registry, handle) = Actor::spawn(None, BuildRegistry, ()).await.unwrap();
        let mut ids = Vec::new();
        for _ in 0..ENDED_KEPT + 2 {
            let r = request();
            ids.push(r.build_id);
            registry.cast(RegistryMessage::Insert(r)).unwrap();
            registry
                .cast(to(*ids.last().unwrap(), BuildState::Cancelled))
                .unwrap();
        }
        let running = request();
        let rid = running.build_id;
        registry.cast(RegistryMessage::Insert(running)).unwrap();
        assert!(get(&registry, ids[0]).await.is_none());
        assert!(get(&registry, ids[1]).await.is_none());
        assert!(get(&registry, ids[2]).await.is_some());
        assert!(
            get(&registry, rid).await.is_some(),
            "a build not ended is never let go"
        );
        registry.stop(None);
        handle.await.unwrap();
    }
}
