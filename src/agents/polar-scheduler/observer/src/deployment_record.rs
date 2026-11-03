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
use polar_scheduler_common::DEPLOYMENT_RECORD_TOPIC;
use ractor::{Actor, ActorProcessingErr, ActorRef};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, info, warn};

/// How often it looks.
const INTERVAL: Duration = Duration::from_secs(30);

/// Where `deploy-repo.nu publish` puts it.
const RECORD_FILE: &str = "deployment-record.json";

pub struct DeploymentRecordActor;

pub struct DeploymentRecordArgs {
    pub repository: Remote,
    pub work: PathBuf,
    pub tcp_client: ActorRef<TcpClientMessage>,
}

pub struct DeploymentRecordState {
    args: DeploymentRecordArgs,
    delivered: Option<String>,
}

#[derive(Debug, Clone)]
pub enum DeploymentRecordMessage {
    Tick,
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
        myself.send_interval(INTERVAL, || DeploymentRecordMessage::Tick);
        Ok(DeploymentRecordState {
            args,
            delivered: None,
        })
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        _msg: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
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
