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

//! The build processor's supervisor: it receives what builds report (relayed by the orchestrator, each in its `BuildReport`
//! envelope), what the orchestrator saw of the builds it ran, and what the resolver verified, each on its own topic through
//! the builder's subscriptions and believed only there (`project::believed_on`), projects
//! each event (`project`) and hands the writes to the graph controller the builder started, and tells health what the
//! broker says (the builder tells it what the graph says). An event it cannot read, or cannot project, is dropped with a warning and the next is read: the broker keeps
//! no log, so what is dropped is gone, and nothing here claims otherwise.

use crate::{AGENT_NAME, aging, project, settings};
use chrono::Utc;
use polar::ProvenanceEvent;
use polar::graph::controller::GraphControllerMsg;
use polar_agent_builder::{
    AgentBuilder, Configured, GraphHandle, HealthClient, HealthHandle, InfrastructureEvent,
    InfrastructureSupervisorMessage, Subscription,
};
use ractor::concurrency::Duration;
use ractor::{Actor, ActorProcessingErr, ActorRef, SupervisionEvent, async_trait};
use tracing::{debug, error, info, warn};

/// How often builds are looked over for one whose end never came (`crate::aging`).
const SWEEP_EVERY: Duration = Duration::from_secs(300);
/// How long the graph has to answer which builds are stale.
const SWEEP_READ_SECS: u64 = 30;
/// What it needs to drain beyond the graph controller's queue, which the builder runs to its end and counts: the
/// infrastructure's own children stopping, with room to spare.
pub const SHUTDOWN_BUDGET: std::time::Duration = std::time::Duration::from_secs(15);

pub enum ProcessorMessage {
    ClientEvent {
        event: cassini_types::ClientEvent,
    },
    Received(ProvenanceEvent),
    /// The bound a build may go unheard of, changed by a signed update.
    LostAfterChanged(std::time::Duration),
    /// Time to look for builds whose end never came.
    Sweep,
    PrepareShutdown,
}

pub struct ProcessorSupervisor;

pub struct ProcessorState {
    healthcheck: HealthHandle,
    infrastructure: ActorRef<InfrastructureSupervisorMessage>,
    /// The builder's: it reports the graph's health and drains it at the end.
    graph: GraphHandle,
    /// From `PrepareShutdown` on: what arrives then is not written, and no sweep starts.
    shutting_down: bool,
    lost_after: std::time::Duration,
}

impl ProcessorSupervisor {
    /// An event as it came on `topic`, archived by the agent that published it: on the build stream, a report in the
    /// `BuildReport` envelope the orchestrator relayed it in, believed for the envelope's build ([`project::relayed`]);
    /// elsewhere, the event itself. `None` if it is not, and why is logged. No pipeline publishes since build pods hold no
    /// identity (docs/architecture/build-orchestrator.md, revised 3), so no other form is read.
    pub fn decode(topic: &str, payload: &[u8]) -> Option<ProvenanceEvent> {
        if topic == polar::topics::PROVENANCE_EVENTS {
            let envelope = match rkyv::from_bytes::<polar::events::BuildReport, rkyv::rancor::Error>(
                payload,
            ) {
                Ok(envelope) => envelope,
                Err(e) => {
                    warn!("not a relayed report on {topic} -- dropped: {e}");
                    return None;
                }
            };
            return project::relayed(envelope)
                .inspect_err(|why| warn!("a relayed report refused -- dropped: {why}"))
                .ok();
        }
        rkyv::from_bytes::<ProvenanceEvent, rkyv::rancor::Error>(payload)
            .inspect_err(|e| warn!("not a provenance event on {topic} -- dropped: {e}"))
            .ok()
    }

    /// A subscription to `topic` that hands over each event believed there ([`project::believed_on`]): a registry fact
    /// on the build stream, a build's execution on it, or a build's report on the resolver's topic, is dropped with a
    /// warning.
    fn stream(topic: &'static str, to: &ActorRef<ProcessorMessage>) -> Subscription {
        let to = to.clone();
        Subscription::new(topic, move |incoming| {
            let Some(event) = Self::decode(topic, &incoming.payload) else {
                return;
            };
            if !project::believed_on(topic, &event) {
                warn!(
                    publisher = ?incoming.published_by,
                    word = ?project::whose_word(&event),
                    "an event that is not believed on {topic} -- dropped"
                );
                return;
            }
            if let Err(e) = to.cast(ProcessorMessage::Received(event)) {
                error!("failed to hand an event to the supervisor: {e}");
            }
        })
    }

    /// Judges lost every build started and not heard of for `lost_after`, and hands the judgement to the graph
    /// controller. A graph that does not answer is tried again at the next sweep.
    async fn sweep(controller: ActorRef<GraphControllerMsg>, lost_after: std::time::Duration) {
        let now = Utc::now();
        let query = aging::stale_builds(&aging::cutoff(now, lost_after));
        let rows = match ractor::rpc::call(
            &controller,
            |reply| GraphControllerMsg::Query(query, reply),
            Some(Duration::from_secs(SWEEP_READ_SECS)),
        )
        .await
        {
            Ok(ractor::rpc::CallResult::Success(Ok(rows))) => rows,
            Ok(ractor::rpc::CallResult::Success(Err(e))) => {
                warn!("builds could not be looked over for one whose end never came: {e}");
                return;
            }
            _ => {
                warn!("the graph did not answer which builds are stale; the next sweep asks again");
                return;
            }
        };
        let stale: Vec<String> = rows
            .iter()
            .filter_map(|row| row.get::<String>("build_id").ok())
            .collect();
        if stale.is_empty() {
            return;
        }
        info!(
            builds = ?stale,
            "judged lost: started and not heard of for {lost_after:?}"
        );
        if let Some(op) = aging::judged_lost(stale, now, lost_after)
            && let Err(e) = controller.cast(GraphControllerMsg::Op(op))
        {
            warn!("the judgement could not be handed to the graph controller: {e}");
        }
    }

    /// Projects one event and hands its writes to the graph controller as one transaction, all or none. An event that
    /// cannot be projected (a manifest that is not OCI JSON) writes nothing and is dropped with a warning.
    fn write(state: &ProcessorState, event: ProvenanceEvent) -> Result<(), ActorProcessingErr> {
        let op = match project::transaction(event, &Utc::now().to_rfc3339()) {
            Ok(Some(op)) => op,
            Ok(None) => return Ok(()),
            Err(e) => {
                warn!(error = %e, "event could not be projected -- dropped");
                return Ok(());
            }
        };
        if let Err(e) = state.graph.write(op) {
            warn!("{e} -- event not written");
        }
        Ok(())
    }
}

#[async_trait]
impl Actor for ProcessorSupervisor {
    type Msg = ProcessorMessage;
    type State = ProcessorState;
    type Arguments = Configured;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        configured: Configured,
    ) -> Result<Self::State, ActorProcessingErr> {
        debug!("{myself:?} starting");
        let resources = AgentBuilder::new(myself.clone(), AGENT_NAME)
            .with_subscription(Self::stream(polar::topics::PROVENANCE_EVENTS, &myself))
            .with_subscription(Self::stream(polar::topics::PROVENANCE_EXECUTIONS, &myself))
            .with_subscription(Self::stream(polar::topics::PROVENANCE_RESOLUTIONS, &myself))
            .with_lifecycle_handler(|event| Some(ProcessorMessage::ClientEvent { event }))
            .into_configured(configured)
            .build()
            .await?;
        resources
            .infrastructure_events
            .subscribe(myself.clone(), |event| match event {
                InfrastructureEvent::PrepareShutdown => Some(ProcessorMessage::PrepareShutdown),
            });
        let lost_after = match resources
            .configuration
            .follow_group(
                settings::VARIABLES,
                settings::lost_after,
                &myself,
                ProcessorMessage::LostAfterChanged,
            )
            .await
        {
            Ok(lost_after) => lost_after,
            Err(e) => {
                // The bound is judged with the rest of the configuration at start, so this is the configuration actor
                // not answering: keep the default and say so, rather than end the agent.
                let fallback = settings::DEFAULT_LOST_AFTER;
                warn!(
                    "the bound for a lost build is not followed ({e}); {fallback:?} until a restart"
                );
                fallback
            }
        };
        myself.send_interval(SWEEP_EVERY, || ProcessorMessage::Sweep);

        Ok(ProcessorState {
            healthcheck: resources.healthcheck,
            infrastructure: resources.infrastructure,
            graph: resources
                .graph
                .ok_or("the builder started no graph controller for a graph-write agent")?,
            shutting_down: false,
            lost_after,
        })
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            ProcessorMessage::ClientEvent { event } => match event {
                cassini_types::ClientEvent::Registered { .. } => {
                    let _ = state.healthcheck.cassini_connected();
                }
                cassini_types::ClientEvent::TransportError { reason } => {
                    warn!("Transport error (non-fatal, awaiting reconnect): {reason}");
                    let _ = state.healthcheck.cassini_disconnected();
                }
                _ => {}
            },
            ProcessorMessage::Received(event) => {
                if state.shutting_down {
                    warn!("ending -- event not written");
                    return Ok(());
                }
                Self::write(state, event)?;
            }
            ProcessorMessage::LostAfterChanged(lost_after) => {
                info!("a build is judged lost after {lost_after:?} unheard of");
                state.lost_after = lost_after;
            }
            ProcessorMessage::Sweep => {
                if state.shutting_down {
                    return Ok(());
                }
                // Off the mailbox: the read waits on the graph, and events keep coming.
                ractor::concurrency::spawn(Self::sweep(
                    state.graph.actor().clone(),
                    state.lost_after,
                ));
            }
            ProcessorMessage::PrepareShutdown => {
                info!("PrepareShutdown received; nothing more is written or swept");
                state.shutting_down = true;
            }
        }
        Ok(())
    }

    async fn handle_supervisor_evt(
        &self,
        _myself: ActorRef<Self::Msg>,
        event: SupervisionEvent,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match event {
            SupervisionEvent::ActorStarted(actor) => debug!("{actor:?} started"),
            // Its one child is the infrastructure: its ending is the end of the handshake, or a failure, and either way
            // the process exits non-zero so the pod starts afresh.
            SupervisionEvent::ActorTerminated(actor, _, reason) => {
                info!("{actor:?} terminated: {reason:?}");
                if actor.get_id() == state.infrastructure.get_id() {
                    std::process::exit(1);
                }
            }
            SupervisionEvent::ActorFailed(actor, reason) => {
                error!("{actor:?} failed: {reason:?}");
                if actor.get_id() == state.infrastructure.get_id() {
                    std::process::exit(1);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ProcessorSupervisor;
    use polar::ProvenanceEvent;

    use polar::events::BuildReport;
    use polar::topics::{PROVENANCE_EVENTS, PROVENANCE_EXECUTIONS, PROVENANCE_RESOLUTIONS};

    fn completed() -> ProvenanceEvent {
        ProvenanceEvent::ExecutionCompleted {
            build_id: "b1".into(),
            duration_secs: 3,
            at: "2026-10-16T00:00:00Z".into(),
            log: None,
            refused_reports: 0,
        }
    }

    fn stage(build_id: &str) -> ProvenanceEvent {
        ProvenanceEvent::StageStarted {
            build_id: build_id.into(),
            stage_name: "build".into(),
            stage_id: "s1".into(),
            at: "2026-10-16T00:00:00Z".into(),
        }
    }

    fn relayed(build_id: &str, report: ProvenanceEvent) -> Vec<u8> {
        rkyv::to_bytes::<rkyv::rancor::Error>(&BuildReport {
            build_id: build_id.into(),
            report,
        })
        .unwrap()
        .to_vec()
    }

    #[test]
    fn an_event_the_orchestrator_archived_is_read_on_its_topic() {
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&completed()).unwrap();
        for topic in [PROVENANCE_EXECUTIONS, PROVENANCE_RESOLUTIONS] {
            match ProcessorSupervisor::decode(topic, &bytes) {
                Some(ProvenanceEvent::ExecutionCompleted {
                    build_id,
                    duration_secs,
                    at,
                    ..
                }) => assert_eq!(
                    (build_id.as_str(), duration_secs, at.as_str()),
                    ("b1", 3, "2026-10-16T00:00:00Z")
                ),
                other => panic!("expected the build's completion, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_build_stream_reads_relayed_reports_and_nothing_else() {
        assert!(matches!(
            ProcessorSupervisor::decode(PROVENANCE_EVENTS, &relayed("b1", stage("b1"))),
            Some(ProvenanceEvent::StageStarted { .. })
        ));
        // Not the envelope's build: refused.
        assert!(
            ProcessorSupervisor::decode(PROVENANCE_EVENTS, &relayed("b1", stage("b2"))).is_none()
        );
        // A bare event, as a pipeline once published it, archived or as JSON: not a relayed report.
        let bare = rkyv::to_bytes::<rkyv::rancor::Error>(&stage("b1")).unwrap();
        assert!(ProcessorSupervisor::decode(PROVENANCE_EVENTS, &bare).is_none());
        let json = serde_json::to_vec(&stage("b1")).unwrap();
        assert!(ProcessorSupervisor::decode(PROVENANCE_EVENTS, &json).is_none());
        assert!(
            ProcessorSupervisor::decode(
                PROVENANCE_EXECUTIONS,
                &serde_json::to_vec(&completed()).unwrap()
            )
            .is_none()
        );
    }

    #[test]
    fn what_is_not_an_event_is_dropped_not_fatal() {
        for topic in [
            PROVENANCE_EVENTS,
            PROVENANCE_EXECUTIONS,
            PROVENANCE_RESOLUTIONS,
        ] {
            assert!(ProcessorSupervisor::decode(topic, b"not an event").is_none());
            assert!(ProcessorSupervisor::decode(topic, &[]).is_none());
        }
    }
}
