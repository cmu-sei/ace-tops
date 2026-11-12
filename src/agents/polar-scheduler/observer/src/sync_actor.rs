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

//! Keeps the checkout as the git server says `polar-schedules`' `main` is (src/reads.rs, over Cassini; runtime-attestation.md,
//! slice C, C2, O2): on an interval and whenever told, it asks, giving the commit it has, and writes what changed
//! (src/checkout.rs). Until its first read has been answered it asks again with a growing wait, since the server may not
//! answer yet (it starts beside the observer, and its pod is replaced now and then); a refusal then is final, since asking
//! again cannot change it, and ends the observer. After that a failed read is said, and the next one tries again.

use crate::reads::ReadsMain;
use polar_git_server_common::MainRead;
use ractor::{Actor, ActorProcessingErr, ActorRef};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

/// The first wait before asking again, and the longest.
const FIRST_RETRY: Duration = Duration::from_secs(2);
const LONGEST_RETRY: Duration = Duration::from_secs(30);

pub struct GitSyncActor;

pub struct GitSyncArgs {
    pub repo_path: PathBuf,
    /// The repository on Polar's git server.
    pub repo: String,
    pub reads: Arc<dyn ReadsMain>,
    /// Read on this interval as well; none means only [`SyncMessage::Now`] reads.
    pub interval: Option<Duration>,
    /// Told after each read that brought the checkout up to date, so what it brought is read: the watcher rescans.
    pub pulled: Option<Pulled>,
}

/// What is told that a read brought the checkout up to date.
pub type Pulled = std::sync::Arc<dyn Fn() + Send + Sync>;

pub struct GitSyncState {
    repo_path: PathBuf,
    repo: String,
    reads: Arc<dyn ReadsMain>,
    pulled: Option<Pulled>,
    /// The commit the checkout holds, when main has one.
    have: Option<String>,
    /// Whether a read has been answered yet.
    answered: bool,
    /// How long until the first read is asked again.
    retry: Duration,
}

#[derive(Debug, Clone)]
pub enum SyncMessage {
    /// The interval elapsed.
    Tick,
    /// The server said it changed, or the observer joined Cassini.
    Now,
    /// The first read was not answered, and is asked again.
    Retry,
}

#[ractor::async_trait]
impl Actor for GitSyncActor {
    type Msg = SyncMessage;
    type State = GitSyncState;
    type Arguments = GitSyncArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: GitSyncArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        match args.interval {
            Some(interval) => {
                info!(
                    "GitSyncActor starting, will read {} every {}s and when told",
                    args.repo,
                    interval.as_secs()
                );
                myself.send_interval(interval, || SyncMessage::Tick);
            }
            None => info!("GitSyncActor starting, will read {} when told", args.repo),
        }
        Ok(GitSyncState {
            repo_path: args.repo_path,
            repo: args.repo,
            reads: args.reads,
            pulled: args.pulled,
            have: None,
            answered: false,
            retry: FIRST_RETRY,
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        msg: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        info!(?msg, repo = %state.repo, "reading the repository's main");
        let read = state
            .reads
            .read_main(&state.repo, &[], state.have.as_deref())
            .await;
        let failed = match read {
            Ok(MainRead::Files { commit, files }) => {
                let dir = state.repo_path.clone();
                match tokio::task::spawn_blocking(move || crate::checkout::apply(&dir, &files))
                    .await
                    .map_err(|e| ActorProcessingErr::from(e.to_string()))?
                {
                    Ok(_) => {
                        info!(%commit, "the checkout holds main");
                        state.have = Some(commit);
                        state.answered = true;
                        if let Some(tell) = &state.pulled {
                            tell();
                        }
                        None
                    }
                    Err(why) => Some(why),
                }
            }
            Ok(MainRead::Unchanged { .. }) => None,
            // A repository with nothing yet holds no schedules: that is its word, and the checkout holds nothing.
            Ok(MainRead::NoMain) => {
                let dir = state.repo_path.clone();
                match tokio::task::spawn_blocking(move || crate::checkout::apply(&dir, &[]))
                    .await
                    .map_err(|e| ActorProcessingErr::from(e.to_string()))?
                {
                    Ok(_) => {
                        if !state.answered
                            && let Some(tell) = &state.pulled
                        {
                            tell();
                        }
                        state.have = None;
                        state.answered = true;
                        None
                    }
                    Err(why) => Some(why),
                }
            }
            Ok(MainRead::Refused { why }) if !state.answered => {
                return Err(format!("the git server refused to read {}: {why}", state.repo).into());
            }
            Ok(MainRead::Refused { why }) => {
                error!(repo = %state.repo, "the git server refused a read: {why}");
                None
            }
            Ok(MainRead::NotNow { why }) => Some(why),
            Err(why) => Some(why),
        };
        if let Some(why) = failed {
            if !state.answered {
                warn!(
                    "the repository does not answer yet ({why}); asking again in {}s",
                    state.retry.as_secs()
                );
                myself.send_after(state.retry, || SyncMessage::Retry);
                state.retry = (state.retry * 2).min(LONGEST_RETRY);
            } else {
                warn!("could not read the repository ({why}); the next read tries again");
            }
        }
        Ok(())
    }
}
