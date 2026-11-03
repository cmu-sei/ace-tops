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
use ractor::{Actor, ActorProcessingErr, ActorRef};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, info, warn};

/// How often it looks for what is new.
const INTERVAL: Duration = Duration::from_secs(10);

pub struct DeploymentCopyActor;

pub struct DeploymentCopyArgs {
    pub source: Remote,
    pub target: Remote,
    pub work: PathBuf,
}

pub struct DeploymentCopyState {
    args: DeploymentCopyArgs,
    copied: Option<String>,
}

#[derive(Debug, Clone)]
pub enum DeploymentCopyMessage {
    Tick,
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
        myself.send_interval(INTERVAL, || DeploymentCopyMessage::Tick);
        Ok(DeploymentCopyState { args, copied: None })
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        _msg: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
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
