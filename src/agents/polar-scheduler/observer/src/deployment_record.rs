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

//! The deployment's signed record, delivered to the attestation agent (docs/architecture/runtime-attestation.md, "What the images
//! are checked against"). It is read from the deployment repository and published as it is, again on every look, so an attestation
//! agent that has just started hears it within one interval. This agent is not trusted with it, and does not read it: the attestation
//! agent verifies it against the deployment CA and refuses an older one.

use crate::git_ops::{Remote, file_at_main};
use cassini_client::TcpClientMessage;
use polar_agent_builder::ConfigurationHandle;
use polar_agent_builder::configuration::FollowError;
use polar_scheduler_common::DEPLOYMENT_RECORD_TOPIC;
use ractor::{Actor, ActorProcessingErr, ActorRef};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Where `deploy-repo.nu publish` puts it.
const RECORD_FILE: &str = "deployment-record.json";

pub struct DeploymentRecordActor;

pub struct DeploymentRecordArgs {
    pub repository: Remote,
    pub work: PathBuf,
    pub tcp_client: ActorRef<TcpClientMessage>,
    /// What it follows how often it looks from (`settings::DEPLOYMENT_RECORD_SECS`).
    pub configuration: ConfigurationHandle,
}

pub struct DeploymentRecordState {
    args: DeploymentRecordArgs,
    delivered: Option<String>,
    /// What says it is time to look.
    timer: ractor::concurrency::JoinHandle<()>,
}

#[derive(Debug, Clone)]
pub enum DeploymentRecordMessage {
    Tick,
    /// A signed update changed how often it looks.
    IntervalChanged(Duration),
}

/// The actor holds its timer, so it follows how often it looks. The answer is the interval in force.
async fn follow_interval(
    configuration: &ConfigurationHandle,
    myself: &ActorRef<DeploymentRecordMessage>,
) -> Result<Duration, FollowError> {
    let names: [&dyn polar_env::Described; 1] = [&crate::settings::DEPLOYMENT_RECORD_SECS];
    configuration
        .follow_group(
            &names,
            |config: &polar_env::Config| {
                crate::settings::seconds(config, &crate::settings::DEPLOYMENT_RECORD_SECS)
            },
            myself,
            DeploymentRecordMessage::IntervalChanged,
        )
        .await
}

#[ractor::async_trait]
impl Actor for DeploymentRecordActor {
    type Msg = DeploymentRecordMessage;
    type State = DeploymentRecordState;
    type Arguments = DeploymentRecordArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: DeploymentRecordArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        let interval = follow_interval(&args.configuration, &myself).await?;
        let timer = myself.send_interval(interval, || DeploymentRecordMessage::Tick);
        Ok(DeploymentRecordState {
            args,
            delivered: None,
            timer,
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        msg: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        if let DeploymentRecordMessage::IntervalChanged(interval) = msg {
            state.timer.abort();
            state.timer = myself.send_interval(interval, || DeploymentRecordMessage::Tick);
            return Ok(());
        }
        let (repository, work) = (state.args.repository.clone(), state.args.work.clone());
        let read =
            tokio::task::spawn_blocking(move || file_at_main(&repository, RECORD_FILE, &work))
                .await
                .map_err(|e| ActorProcessingErr::from(e.to_string()))?;
        match read {
            Ok(Some(record)) => {
                if state.delivered.as_deref() != Some(record.as_str()) {
                    info!("delivering a new deployment record to the attestation agent");
                }
                state.args.tcp_client.cast(TcpClientMessage::publish(
                    DEPLOYMENT_RECORD_TOPIC.to_string(),
                    record.clone().into_bytes(),
                    None,
                ))?;
                state.delivered = Some(record);
            }
            Ok(None) => debug!("the deployment repository holds no record yet"),
            // Polar's git server is replaced now and then, and the next look tries again.
            Err(e) => warn!("could not read the deployment's record: {e:#}"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A timer's tick is counted, and a change of its setting replaces it.
    #[tokio::test]
    async fn the_interval_is_followed_and_a_new_one_replaces_the_timer() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        struct Counter;
        #[ractor::async_trait]
        impl Actor for Counter {
            type Msg = DeploymentRecordMessage;
            type State = Arc<AtomicUsize>;
            type Arguments = Arc<AtomicUsize>;
            async fn pre_start(
                &self,
                _: ActorRef<Self::Msg>,
                count: Self::Arguments,
            ) -> Result<Self::State, ActorProcessingErr> {
                Ok(count)
            }
            async fn handle(
                &self,
                _: ActorRef<Self::Msg>,
                message: Self::Msg,
                count: &mut Self::State,
            ) -> Result<(), ActorProcessingErr> {
                if matches!(message, DeploymentRecordMessage::Tick) {
                    count.fetch_add(1, SeqCst);
                }
                Ok(())
            }
        }
        let ticks = Arc::new(AtomicUsize::new(0));
        let (myself, _) = Actor::spawn(None, Counter, ticks.clone()).await.unwrap();
        let env: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let configuration = ConfigurationHandle::spawn(
            None,
            "scheduler-observer",
            polar_env::Config::builder(&env)
                .register(&crate::settings::SECTION)
                .build(),
            None,
            myself.get_cell(),
        )
        .await
        .unwrap();
        let interval = follow_interval(&configuration, &myself).await.unwrap();
        assert_eq!(interval, Duration::from_secs(30));
        // Followed by this actor, and depending on it: the check's answer for this variable alone.
        let problems = configuration
            .dynamic_settings_problems(&[&crate::settings::SECTION])
            .await
            .unwrap();
        assert!(
            !problems
                .iter()
                .any(|problem| problem.contains("POLAR_SCHEDULER_DEPLOYMENT_RECORD_SECS")),
            "{problems:?}"
        );

        let remote = || Remote {
            url: "https://nowhere.invalid/x.git".to_string(),
            tls: crate::git_ops::GitTls {
                ca_cert: None,
                client_cert: None,
                client_key: None,
            },
        };
        struct Client;
        #[ractor::async_trait]
        impl Actor for Client {
            type Msg = TcpClientMessage;
            type State = ();
            type Arguments = ();
            async fn pre_start(
                &self,
                _: ActorRef<Self::Msg>,
                _: (),
            ) -> Result<(), ActorProcessingErr> {
                Ok(())
            }
        }
        let (tcp_client, _) = Actor::spawn(None, Client, ()).await.unwrap();
        let mut state = DeploymentRecordState {
            args: DeploymentRecordArgs {
                repository: remote(),
                work: PathBuf::from("/nowhere"),
                tcp_client,
                configuration: configuration.clone(),
            },
            delivered: None,
            timer: myself
                .send_interval(Duration::from_secs(3600), || DeploymentRecordMessage::Tick),
        };
        DeploymentRecordActor
            .handle(
                myself.clone(),
                DeploymentRecordMessage::IntervalChanged(Duration::from_millis(10)),
                &mut state,
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(ticks.load(SeqCst) > 1);

        DeploymentRecordActor
            .handle(
                myself,
                DeploymentRecordMessage::IntervalChanged(Duration::from_secs(3600)),
                &mut state,
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let then = ticks.load(SeqCst);
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(ticks.load(SeqCst), then);
    }
}
