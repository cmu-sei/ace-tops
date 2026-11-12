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
//! agent verifies it against the deployment CA and refuses an older one. It is asked of the git server over Cassini (src/reads.rs),
//! with the commit last read, so an unchanged repository sends nothing but its answer.

use crate::reads::ReadsMain;
use cassini_client::TcpClientMessage;
use polar_agent_builder::ConfigurationHandle;
use polar_agent_builder::configuration::FollowError;
use polar_git_server_common::MainRead;
use polar_scheduler_common::DEPLOYMENT_RECORD_TOPIC;
use ractor::{Actor, ActorProcessingErr, ActorRef};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Where `deploy-repo.nu publish` puts it.
const RECORD_FILE: &str = "deployment-record.json";

pub struct DeploymentRecordActor;

pub struct DeploymentRecordArgs {
    /// The deployment repository on Polar's git server.
    pub repo: String,
    pub reads: Arc<dyn ReadsMain>,
    pub tcp_client: ActorRef<TcpClientMessage>,
    /// What it follows how often it looks from (`settings::DEPLOYMENT_RECORD_SECS`).
    pub configuration: ConfigurationHandle,
}

pub struct DeploymentRecordState {
    args: DeploymentRecordArgs,
    delivered: Option<String>,
    /// The commit last read, when it held the record.
    have: Option<String>,
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
            have: None,
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
        let paths = [RECORD_FILE.to_string()];
        let read = state
            .args
            .reads
            .read_main(&state.args.repo, &paths, state.have.as_deref())
            .await;
        let record = match read {
            Ok(MainRead::Files { commit, files }) => {
                match files.into_iter().find(|f| f.path == RECORD_FILE) {
                    Some(file) => match String::from_utf8(file.content) {
                        Ok(record) => {
                            state.have = Some(commit);
                            Some(record)
                        }
                        Err(_) => {
                            warn!("the deployment's record is not text");
                            None
                        }
                    },
                    // What main says, not what was read before: a record that is gone is not delivered again.
                    None => {
                        debug!("the deployment repository holds no record");
                        state.have = None;
                        state.delivered = None;
                        None
                    }
                }
            }
            // Delivered again on every look, so an attestation agent that has just started hears it.
            Ok(MainRead::Unchanged { .. }) => state.delivered.clone(),
            Ok(MainRead::NoMain) => {
                debug!("the deployment repository holds no record yet");
                None
            }
            // Polar's git server is replaced now and then, and the next look tries again.
            Ok(MainRead::Refused { why } | MainRead::NotNow { why }) | Err(why) => {
                warn!("could not read the deployment's record: {why}");
                None
            }
        };
        if let Some(record) = record {
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_git_server_common::{FileAt, FileKind};
    use std::sync::Mutex;

    /// What a look asked for: the repository, the paths and the commit it had.
    type Asked = (String, Vec<String>, Option<String>);

    /// Answers each look with the next of its answers, and "unchanged" once they are spent; and keeps what it was asked.
    #[derive(Default)]
    struct Scripted {
        answers: Mutex<std::collections::VecDeque<Result<MainRead, String>>>,
        asked: Mutex<Vec<Asked>>,
    }

    #[ractor::async_trait]
    impl ReadsMain for Scripted {
        async fn read_main(
            &self,
            repo: &str,
            paths: &[String],
            have: Option<&str>,
        ) -> Result<MainRead, String> {
            self.asked.lock().unwrap().push((
                repo.into(),
                paths.to_vec(),
                have.map(str::to_string),
            ));
            self.answers
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(MainRead::Unchanged { commit: "c".into() }))
        }
    }

    /// Keeps what it is asked to publish.
    struct Published;

    #[ractor::async_trait]
    impl Actor for Published {
        type Msg = TcpClientMessage;
        type State = Arc<Mutex<Vec<String>>>;
        type Arguments = Arc<Mutex<Vec<String>>>;
        async fn pre_start(
            &self,
            _: ActorRef<Self::Msg>,
            kept: Self::Arguments,
        ) -> Result<Self::State, ActorProcessingErr> {
            Ok(kept)
        }
        async fn handle(
            &self,
            _: ActorRef<Self::Msg>,
            message: Self::Msg,
            kept: &mut Self::State,
        ) -> Result<(), ActorProcessingErr> {
            if let TcpClientMessage::Publish { topic, payload, .. } = message {
                assert_eq!(topic, DEPLOYMENT_RECORD_TOPIC);
                kept.lock()
                    .unwrap()
                    .push(String::from_utf8(payload).unwrap());
            }
            Ok(())
        }
    }

    fn record(commit: &str, text: Option<&str>) -> Result<MainRead, String> {
        Ok(MainRead::Files {
            commit: commit.into(),
            files: text
                .map(|t| FileAt {
                    path: RECORD_FILE.into(),
                    kind: FileKind::Plain,
                    content: t.into(),
                })
                .into_iter()
                .collect(),
        })
    }

    /// The record is the file main holds, delivered on every look, again when main is unchanged; a repository that holds
    /// none yet, or that could not be read, delivers nothing and is not an error; and each look gives the commit last read.
    #[tokio::test]
    async fn the_record_is_delivered_as_main_holds_it_on_every_look() {
        let scripted = Arc::new(Scripted::default());
        scripted.answers.lock().unwrap().extend([
            Ok(MainRead::NoMain),
            record("c1", None),
            record("c2", Some("{\"r\":1}")),
            Ok(MainRead::Unchanged {
                commit: "c2".into(),
            }),
            Err("timed out waiting for a reply".into()),
            record("c3", Some("{\"r\":2}")),
            record("c4", None),
            record("c4", None),
        ]);
        let kept = Arc::new(Mutex::new(Vec::new()));
        let (tcp_client, _) = Actor::spawn(None, Published, kept.clone()).await.unwrap();
        let (myself, _) = Actor::spawn(None, Published, Arc::new(Mutex::new(Vec::new())))
            .await
            .unwrap();
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
        let (recorder, _) = Actor::spawn(
            None,
            DeploymentRecordActor,
            DeploymentRecordArgs {
                repo: "deployment".into(),
                reads: scripted.clone(),
                tcp_client,
                configuration,
            },
        )
        .await
        .unwrap();
        // Its own timer is thirty seconds off: each look is asked for here, and taken in order.
        for _ in 0..8 {
            recorder.cast(DeploymentRecordMessage::Tick).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            *kept.lock().unwrap(),
            ["{\"r\":1}", "{\"r\":1}", "{\"r\":2}"],
            "delivered when read, again when unchanged, the new one, and not once it is gone"
        );
        let asked = scripted.asked.lock().unwrap();
        assert!(asked.iter().all(|(repo, paths, _)| repo == "deployment" && paths == &[RECORD_FILE.to_string()]));
        let haves: Vec<Option<&str>> = asked.iter().map(|(_, _, have)| have.as_deref()).collect();
        assert_eq!(
            haves,
            [
                None,
                None,
                None,
                Some("c2"),
                Some("c2"),
                Some("c2"),
                Some("c3"),
                None
            ]
        );
    }

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
                repo: "deployment".into(),
                reads: Arc::new(Scripted::default()),
                tcp_client,
                configuration: configuration.clone(),
            },
            delivered: None,
            have: None,
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
