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

//! The copy of the deployment from the bootstrap repository to Polar's own git server, once the agents are up (docs/architecture/cluster-bootstrap.md, "Handing off to Polar's git server"). It
//! runs until the handoff is done and the setting that starts it goes, since the bootstrap repository can gain a commit after the first copy. A failed copy is reported and tried again: the server
//! judges every commit, so what this agent does cannot put anything there that the pipeline did not sign.

use crate::git_ops::{Remote, copy_main};
use polar_agent_builder::ConfigurationHandle;
use polar_agent_builder::configuration::FollowError;
use ractor::{Actor, ActorProcessingErr, ActorRef};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, info, warn};

pub struct DeploymentCopyActor;

pub struct DeploymentCopyArgs {
    pub source: Remote,
    pub target: Remote,
    pub work: PathBuf,
    /// What it follows how often it looks from (`settings::DEPLOYMENT_COPY_SECS`).
    pub configuration: ConfigurationHandle,
}

pub struct DeploymentCopyState {
    args: DeploymentCopyArgs,
    copied: Option<String>,
    /// What says it is time to look.
    timer: ractor::concurrency::JoinHandle<()>,
}

#[derive(Debug, Clone)]
pub enum DeploymentCopyMessage {
    Tick,
    /// A signed update changed how often it looks.
    IntervalChanged(Duration),
}

/// The actor holds its timer, so it follows how often it looks. The answer is the interval in force.
async fn follow_interval(
    configuration: &ConfigurationHandle,
    myself: &ActorRef<DeploymentCopyMessage>,
) -> Result<Duration, FollowError> {
    let names: [&dyn polar_env::Described; 1] = [&crate::settings::DEPLOYMENT_COPY_SECS];
    configuration
        .follow_group(
            &names,
            |config: &polar_env::Config| {
                crate::settings::seconds(config, &crate::settings::DEPLOYMENT_COPY_SECS)
            },
            myself,
            DeploymentCopyMessage::IntervalChanged,
        )
        .await
}

#[ractor::async_trait]
impl Actor for DeploymentCopyActor {
    type Msg = DeploymentCopyMessage;
    type State = DeploymentCopyState;
    type Arguments = DeploymentCopyArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: DeploymentCopyArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        let interval = follow_interval(&args.configuration, &myself).await?;
        let timer = myself.send_interval(interval, || DeploymentCopyMessage::Tick);
        Ok(DeploymentCopyState {
            args,
            copied: None,
            timer,
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        msg: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        if let DeploymentCopyMessage::IntervalChanged(interval) = msg {
            state.timer.abort();
            state.timer = myself.send_interval(interval, || DeploymentCopyMessage::Tick);
            return Ok(());
        }
        let (source, target, work) = (
            state.args.source.clone(),
            state.args.target.clone(),
            state.args.work.clone(),
        );
        let copied = tokio::task::spawn_blocking(move || copy_main(&source, &target, &work))
            .await
            .map_err(|e| ActorProcessingErr::from(e.to_string()))?;
        match copied {
            Ok(commit) if state.copied.as_deref() != Some(commit.as_str()) => {
                info!(commit, "the deployment is copied to Polar's git server");
                state.copied = Some(commit);
            }
            Ok(_) => debug!("the deployment's copy is current"),
            Err(e) => warn!("could not copy the deployment: {e:#}"),
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
            type Msg = DeploymentCopyMessage;
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
                if matches!(message, DeploymentCopyMessage::Tick) {
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
        assert_eq!(interval, Duration::from_secs(10));
        // Followed by this actor, and depending on it: the check's answer for this variable alone.
        let problems = configuration
            .dynamic_settings_problems(&[&crate::settings::SECTION])
            .await
            .unwrap();
        assert!(
            !problems
                .iter()
                .any(|problem| problem.contains("POLAR_SCHEDULER_DEPLOYMENT_COPY_SECS")),
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
        let mut state = DeploymentCopyState {
            args: DeploymentCopyArgs {
                source: remote(),
                target: remote(),
                work: PathBuf::from("/nowhere"),
                configuration: configuration.clone(),
            },
            copied: None,
            timer: myself.send_interval(Duration::from_secs(3600), || DeploymentCopyMessage::Tick),
        };
        DeploymentCopyActor
            .handle(
                myself.clone(),
                DeploymentCopyMessage::IntervalChanged(Duration::from_millis(10)),
                &mut state,
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(ticks.load(SeqCst) > 1);

        DeploymentCopyActor
            .handle(
                myself,
                DeploymentCopyMessage::IntervalChanged(Duration::from_secs(3600)),
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
