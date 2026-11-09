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

#![deny(clippy::disallowed_methods)]

use crate::status::{Outcome, StatusTracker};
use git_agent_common::GitRepositoryMessage;
use git_agent_common::RepoObservationConfig;
use git_agent_common::RepositorySet;
use git_agent_common::status::{GIT_REPO_OBSERVATION_STATUS, ObservationStatus};
use git2::{Oid, Repository};
use polar::cassini::TcpClient;
use polar::graph::nodes::git::RepoId;
use polar::topics::GIT_REPOSITORY_EVENTS;
use polar_agent_builder::ConfigurationHandle;
use polar_agent_builder::protocol::ProtocolHandle;
use ractor::{Actor, ActorProcessingErr, ActorRef, SpawnErr, SupervisionEvent, async_trait};
use rkyv::{Archive, Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, error, info, instrument, trace, warn};

pub const SERVICE_NAME: &str = "polar.git.observer";
pub const REPO_SUPERVISOR_NAME: &str = "polar.git.observer.repo.supervisor";

/// How long a worker that is being replaced is given to stop: it may be in the middle of a fetch.
const WORKER_GRACE: ractor::concurrency::Duration = ractor::concurrency::Duration::from_secs(30);

pub mod agent;
pub mod credentials;
pub mod fetch;
pub mod settings;
pub mod status;
pub mod supervisor;

fn git_time_to_epoch_ms(t: &git2::Time) -> i64 {
    t.seconds() * 1000
}

/// The refs to read in the clone for the refs an author asked for. A bare clone's `refs/heads/main` stops
/// moving after the clone; a fetch advances only `refs/remotes/<remote>/main`. So a configured `refs/heads/X`
/// is read from `refs/remotes/<remote>/X`, the remote being the first one fetched (`origin` when none is
/// named). Anything else (`refs/remotes/...`, `refs/tags/...`, a name that is not a full ref) is taken as
/// written, and an empty list stays empty, for the default branch to be found after the clone.
pub fn tracked_refs(remotes: &[String], refs: &[String]) -> Vec<String> {
    let remote = remotes.first().map(String::as_str).unwrap_or("origin");
    refs.iter()
        .map(|r| match r.strip_prefix("refs/heads/") {
            Some(branch) => format!("refs/remotes/{remote}/{branch}"),
            None => r.clone(),
        })
        .collect()
}

/* ============================
 * Shared types
 * ============================
 */

/* ============================
 * Event emission
 * ============================
 */

#[instrument(skip(client))]
pub fn send_event(
    client: TcpClient,
    event: GitRepositoryMessage,
    topic: String,
) -> Result<(), ActorProcessingErr> {
    info!("Forwarding event to topic {topic}");
    git_agent_common::publish_event(&client, &topic, &event).map_err(ActorProcessingErr::from)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

/// Says what became of an attempt. Failing to say so is logged and never fails the attempt: the status is for
/// people, and the observation is the work.
fn publish_status(client: &TcpClient, status: &ObservationStatus) {
    if let Err(e) = git_agent_common::publish_event(client, GIT_REPO_OBSERVATION_STATUS, status) {
        warn!("could not publish the status of {}: {e}", status.repo_id);
    }
}

/* ============================
 * Supervisor
 * ============================
 */

/// Git Observer Supervisor
///
/// Enforces one worker per repo invariant.
/// Workers own exclusive access to a single git repository.
/// Git crawling is parallelized safely across repositories.
///
/// No shared mutable state. If you think you need locks here,
/// you have already made a mistake.
pub struct GitRepoSupervisor;

/// A worker that is running, and the configuration it was started with, as announced.
struct RunningWorker {
    actor: ActorRef<GitRepoWorkerMsg>,
    config: RepoObservationConfig,
}

pub struct GitRepoSupervisorState {
    cache_root: PathBuf,
    /// What each worker follows its settings from.
    configuration: ConfigurationHandle,
    workers: HashMap<RepoId, RunningWorker>,
    tcp_client: TcpClient,
    protocols: ProtocolHandle,
}

pub struct GitRepoSupervisorArgs {
    cache_root: PathBuf,
    /// What each worker follows its settings from.
    pub configuration: ConfigurationHandle,
    tcp_client: TcpClient,
    /// Where each worker asks for its repository.
    protocols: ProtocolHandle,
}

#[derive(Serialize, Deserialize, Archive, Debug)]
pub enum RepoSupervisorMessage {
    SpawnWorker {
        config: RepoObservationConfig,
    },
    StopWorker {
        repo_id: RepoId,
    },
    /// The `credentials` section was replaced: a repository that was waiting for its credential tries again.
    CredentialsChanged,
    /// Everything the controller wants observed. Each repository is started, or replaced if its settings
    /// changed, or left alone if it is as announced; and if the set is `complete`, the workers of repositories
    /// it does not name are stopped.
    Reconcile {
        set: RepositorySet,
    },
}

/// What a failed attempt to start a repository's worker means for the supervisor of all of them.
///
/// A worker already running (the repository was announced twice) is expected. A worker that cannot
/// start (an unreachable host, bad credentials) is that repository's problem and is logged: it
/// used to fail the supervisor, which ended the whole agent. Nothing starts it again until the
/// repository is announced again.
pub fn tolerate_spawn_failure(repo_id: &RepoId, error: SpawnErr) -> Result<(), ActorProcessingErr> {
    match error {
        SpawnErr::ActorAlreadyRegistered(name) => {
            debug!("worker {name} already running, ignoring duplicate discovery event");
            Ok(())
        }
        SpawnErr::StartupFailed(reason) => {
            error!("the worker for {repo_id} could not start, so it is not observed: {reason}");
            Ok(())
        }
        other => Err(other.into()),
    }
}

impl GitRepoSupervisor {
    /// Makes sure a worker is running for `config`: starts one, or replaces the one running if the settings
    /// changed, or leaves it alone if it is as announced.
    async fn ensure_worker(
        myself: &ActorRef<RepoSupervisorMessage>,
        state: &mut GitRepoSupervisorState,
        config: RepoObservationConfig,
    ) -> Result<(), ActorProcessingErr> {
        trace!("Received SpawnWorker message");
        let repo_id = config.repo_id.clone();

        // The same announcement again is nothing to do. A changed one replaces the worker: the
        // clone in the cache is reused, so only the settings change.
        match state.workers.get(&repo_id) {
            Some(running) if running.config == config => {
                debug!("worker for {repo_id} already running with this configuration");
                return Ok(());
            }
            Some(_) => {
                info!("the configuration of {repo_id} changed; restarting its worker");
                if let Some(old) = state.workers.remove(&repo_id)
                    && let Err(e) = old
                        .actor
                        .stop_and_wait(Some("configuration changed".into()), Some(WORKER_GRACE))
                        .await
                {
                    warn!("the old worker for {repo_id} did not stop in time: {e:?}");
                }
            }
            None => {}
        }

        let announced = config.clone();
        let args = GitRepoWorkerArgs {
            config,
            protocols: state.protocols.clone(),
            repo_path: state.cache_root.join(repo_id.to_string()),
            tcp_client: state.tcp_client.clone(),
            configuration: state.configuration.clone(),
        };

        match Actor::spawn_linked(
            Some(format!("{SERVICE_NAME}.{}.worker", repo_id)),
            GitRepoWorker,
            args,
            myself.clone().into(),
        )
        .await
        {
            Ok((actor, _)) => {
                state.workers.insert(
                    repo_id,
                    RunningWorker {
                        actor,
                        config: announced,
                    },
                );
            }
            Err(e) => tolerate_spawn_failure(&repo_id, e)?,
        }
        Ok(())
    }
}

#[async_trait]
impl Actor for GitRepoSupervisor {
    type Msg = RepoSupervisorMessage;
    type State = GitRepoSupervisorState;
    type Arguments = GitRepoSupervisorArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: GitRepoSupervisorArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        debug!(
            "{myself:?} starting. Creating directories at {:?}",
            args.cache_root
        );

        std::fs::create_dir_all(&args.cache_root)
            .map_err(|e| ActorProcessingErr::from(e.to_string()))?;

        Ok(GitRepoSupervisorState {
            cache_root: args.cache_root,
            configuration: args.configuration,
            tcp_client: args.tcp_client,
            protocols: args.protocols,
            workers: HashMap::new(),
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        msg: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match msg {
            RepoSupervisorMessage::SpawnWorker { config } => {
                Self::ensure_worker(&myself, state, config).await?;
            }
            RepoSupervisorMessage::Reconcile { set } => {
                let named: std::collections::HashSet<RepoId> =
                    set.repositories.iter().map(|c| c.repo_id.clone()).collect();
                for config in set.repositories {
                    Self::ensure_worker(&myself, state, config).await?;
                }
                if set.complete {
                    let gone: Vec<RepoId> = state
                        .workers
                        .keys()
                        .filter(|id| !named.contains(*id))
                        .cloned()
                        .collect();
                    for repo_id in gone {
                        // The clone stays in the cache: it is reused if the repository is named again.
                        if let Some(worker) = state.workers.remove(&repo_id) {
                            info!("{repo_id} is no longer in the set; stopping its worker");
                            worker.actor.stop(Some("no longer in the set".into()));
                        }
                    }
                }
            }
            RepoSupervisorMessage::CredentialsChanged => {
                for worker in state.workers.values() {
                    if let Err(e) = worker.actor.cast(GitRepoWorkerMsg::CredentialsChanged) {
                        warn!("could not tell a worker the credentials changed: {e}");
                    }
                }
            }
            RepoSupervisorMessage::StopWorker { repo_id } => {
                // The clone stays in the cache: it is reused if the repository is observed again.
                match state.workers.remove(&repo_id) {
                    Some(worker) => worker.actor.stop(Some("asked to stop".into())),
                    None => warn!("asked to stop the worker for {repo_id}, which is not running"),
                }
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
            SupervisionEvent::ActorFailed(cell, reason) => {
                error!("worker {cell:?} failed: {reason:?}");
                state
                    .workers
                    .retain(|_, w| w.actor.get_id() != cell.get_id());
            }
            SupervisionEvent::ActorTerminated(cell, _, reason) => {
                warn!("worker {cell:?} terminated: {reason:?}");
                state
                    .workers
                    .retain(|_, w| w.actor.get_id() != cell.get_id());
            }
            _ => {}
        }
        Ok(())
    }
}

/* ============================
 * Worker
 * ============================
 */

#[derive(Serialize, Deserialize, Archive, Debug)]
pub enum GitRepoWorkerMsg {
    /// Fetch + export new data incrementally.
    Observe,
    /// The `credentials` section was replaced. A worker waiting for its credential tries at once; any other
    /// ignores it, since it asks for its credential again at every fetch.
    CredentialsChanged,
    /// A signed update changed the batch: the next one published is this size.
    PublishBatchChanged(usize),
}

pub struct GitRepoWorker;

pub struct GitRepoWorkerState {
    config: RepoObservationConfig,
    repo_path: PathBuf,
    tcp_client: TcpClient,
    protocols: ProtocolHandle,
    /// The clone, opened to read once an attempt has it up to date, and closed when the attempt is over. It is the
    /// handler's that makes the clone, and only the handler's that reaches the repository's host.
    repo: Option<Repository>,
    /// Each ref's checkpoint: what of it was published.
    checkpoints: HashMap<String, Checkpoint>,
    /// How many events are published at once (`settings::PUBLISH_BATCH`).
    publish_batch: usize,
    /// The last attempt could not go ahead (its credential is missing or unusable, or the clone or the fetch
    /// failed).
    waiting: bool,
    /// What the attempts so far amount to, for the status published after each.
    status: StatusTracker,
    /// The next scheduled attempt, replaced whenever one runs so there is never more than one.
    next: Option<tokio::task::JoinHandle<Result<(), ractor::MessagingErr<GitRepoWorkerMsg>>>>,
}

pub struct GitRepoWorkerArgs {
    config: RepoObservationConfig,
    repo_path: PathBuf,
    tcp_client: TcpClient,
    protocols: ProtocolHandle,
    /// What the worker follows its batch from (`settings::PUBLISH_BATCH`).
    configuration: ConfigurationHandle,
}

/// The event a commit found on `ref_name` is published as.
fn commit_event(repo_id: RepoId, ref_name: &str, commit: &git2::Commit) -> GitRepositoryMessage {
    debug!("Found commit for ref_name {ref_name} in repo {repo_id:?}");

    let observed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();

    GitRepositoryMessage::CommitDiscovered {
        ref_name: ref_name.to_string(),
        observed_at: observed_at.to_string(),
        repo: repo_id,
        oid: commit.id().to_string(),
        committer: commit.committer().to_string(),
        time: git_time_to_epoch_ms(&commit.time()), // convert to ms to keep in line with other timestamps
        message: commit.message().unwrap_or_default().to_string(),
        parents: commit.parent_ids().map(|id| id.to_string()).collect(),
    }
}

/// The event a ref's move from `old` to `new` is published as.
fn ref_update_event(
    repo_id: RepoId,
    ref_name: &str,
    old: Option<Oid>,
    new: Oid,
) -> GitRepositoryMessage {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();

    GitRepositoryMessage::RefUpdated {
        repo: repo_id,
        ref_name: ref_name.to_string(),
        old: old.map(|o| o.to_string()),
        new: new.to_string(),
        observed_at: now.to_string(),
    }
}

/// Where an observation's events go: the agent's client, or a test's stand-in.
pub trait EventSink: Sync {
    /// Publishes `event` on the repository events topic, waiting while the client has no room; `Err` if it was not
    /// accepted.
    fn publish(
        &self,
        event: &GitRepositoryMessage,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send;
}

impl EventSink for TcpClient {
    async fn publish(&self, event: &GitRepositoryMessage) -> Result<(), String> {
        git_agent_common::publish_event_when_ready(self, GIT_REPOSITORY_EVENTS, event).await
    }
}

/// Where a ref's next walk starts: what of it was published.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Checkpoint {
    /// The tip last published whole, its update accepted: what the next update says the ref moved from.
    pub tip: Option<Oid>,
    /// The published commits that no other published commit descends from: the walk hides them, and so everything
    /// they descend from. One commit on a linear history (the last of the last batch taken); the tip, once all of it
    /// is published. A single last commit would do for a linear history; with merges it would hide only its own
    /// ancestors, and a sibling branch's commits published before it would be published again.
    pub frontier: Vec<Oid>,
}

/// What one walk of a ref will publish: its tip, and the commits its checkpoint does not cover, oldest first (reverse
/// topological order: every commit after its parents). At most `max_depth` back from the tip; deeper ones are skipped,
/// as before. Only their ids are held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefPlan {
    pub tip: Oid,
    pub oids: Vec<Oid>,
}

/// Plans a walk of `ref_name` from its checkpoint.
pub fn plan_ref(
    repo: &Repository,
    ref_name: &str,
    checkpoint: &Checkpoint,
    max_depth: usize,
) -> Result<RefPlan, git2::Error> {
    let tip = repo
        .find_reference(ref_name)?
        .target()
        .ok_or_else(|| git2::Error::from_str("ref has no target"))?;
    let mut walk = repo.revwalk()?;
    walk.set_sorting(git2::Sort::TOPOLOGICAL)?;
    walk.push(tip)?;
    for published in &checkpoint.frontier {
        let _ = walk.hide(*published);
    }
    // Children before parents, nearest the tip first: the first `max_depth` are those nearest it.
    let mut oids = Vec::new();
    for oid in walk {
        if oids.len() >= max_depth {
            break;
        }
        oids.push(oid?);
    }
    oids.reverse();
    Ok(RefPlan { tip, oids })
}

/// One batch's events, each with its commit and the commit's parents (for the checkpoint).
pub type Batch = Vec<(GitRepositoryMessage, Oid, Vec<Oid>)>;

/// The events of `oids`, in order.
pub fn batch_events(
    repo: &Repository,
    repo_id: &RepoId,
    ref_name: &str,
    oids: &[Oid],
) -> Result<Batch, git2::Error> {
    oids.iter()
        .map(|oid| {
            let commit = repo.find_commit(*oid)?;
            Ok((
                commit_event(repo_id.clone(), ref_name, &commit),
                commit.id(),
                commit.parent_ids().collect(),
            ))
        })
        .collect()
}

/// Publishes one batch, in order, and moves the checkpoint past it if the client took all of it. A batch refused
/// leaves the checkpoint after the last batch taken: nothing is lost, and only this batch's events taken before the
/// refusal are published again (the consumers' writes are MERGE-style, cassini-client-reliability.md, 5a).
pub async fn publish_batch(
    sink: &impl EventSink,
    ref_name: &str,
    batch: Batch,
    checkpoint: &mut Checkpoint,
) -> bool {
    for (event, _, _) in &batch {
        if let Err(e) = sink.publish(event).await {
            error!(
                "{ref_name}: a commit was not accepted ({e}); the next walk starts after the last batch taken"
            );
            return false;
        }
    }
    for (_, oid, parents) in batch {
        checkpoint
            .frontier
            .retain(|published| !parents.contains(published));
        checkpoint.frontier.push(oid);
    }
    true
}

/// Publishes the ref's update once all its commits were taken, and moves its checkpoint to the tip. A ref already at
/// the tip its checkpoint holds has not moved and is not reported again (as in `observe_refs`): a consumer acting on
/// `RefUpdated` would otherwise act on every pass.
pub async fn publish_ref_update(
    sink: &impl EventSink,
    repo_id: &RepoId,
    ref_name: &str,
    checkpoint: &mut Checkpoint,
    tip: Oid,
) -> bool {
    if checkpoint.tip == Some(tip) {
        return true;
    }
    if let Err(e) = sink
        .publish(&ref_update_event(
            repo_id.clone(),
            ref_name,
            checkpoint.tip,
            tip,
        ))
        .await
    {
        error!("{ref_name}: its update was not accepted ({e}); it is published again next time");
        return false;
    }
    checkpoint.tip = Some(tip);
    checkpoint.frontier = vec![tip];
    true
}

/// Publishes what `ref_name` has that its checkpoint does not, oldest first, in batches of `batch` events, moving the
/// checkpoint after each batch the client took, then the ref's update; returns whether all of it was taken. What is
/// held at once is the walk's commit ids and one batch's events, not a whole walk's (cassini-backpressure.md, the
/// decisions reviewed with the maintainer, 17). The worker does the same a step at a time, borrowing its repository
/// only between publishes (`Repository` is not `Sync`).
pub async fn publish_ref(
    sink: &impl EventSink,
    repo: &Repository,
    repo_id: &RepoId,
    ref_name: &str,
    checkpoint: &mut Checkpoint,
    max_depth: usize,
    batch: usize,
) -> Result<bool, git2::Error> {
    let plan = plan_ref(repo, ref_name, checkpoint, max_depth)?;
    for chunk in plan.oids.chunks(batch.max(1)) {
        let events = batch_events(repo, repo_id, ref_name, chunk)?;
        if !publish_batch(sink, ref_name, events, checkpoint).await {
            return Ok(false);
        }
    }
    Ok(publish_ref_update(sink, repo_id, ref_name, checkpoint, plan.tip).await)
}

impl GitRepoWorker {
    pub(crate) fn resolve_default_refs(repo: &Repository) -> Vec<String> {
        match repo.find_reference("refs/remotes/origin/HEAD") {
            Ok(head_ref) => match head_ref.symbolic_target() {
                Some(target) => {
                    debug!("resolved default ref to {target}");
                    vec![target.to_string()]
                }
                None => {
                    warn!(
                        "refs/remotes/origin/HEAD has no symbolic target, falling back to refs/remotes/origin/main"
                    );
                    vec!["refs/remotes/origin/main".to_string()]
                }
            },
            Err(e) => {
                warn!(
                    "could not read refs/remotes/origin/HEAD ({e}), falling back to refs/remotes/origin/main"
                );
                vec!["refs/remotes/origin/main".to_string()]
            }
        }
    }

    pub fn walk_commits_incremental<F>(
        repo: &Repository,
        ref_name: &str,
        last_seen: Option<Oid>,
        max_depth: usize,
        mut on_commit: F,
    ) -> Result<Option<Oid>, git2::Error>
    where
        F: FnMut(&git2::Commit),
    {
        let reference = repo.find_reference(ref_name)?;
        let tip = reference
            .target()
            .ok_or_else(|| git2::Error::from_str("ref has no target"))?;

        let mut revwalk = repo.revwalk()?;
        revwalk.push(tip)?;

        if let Some(stop) = last_seen {
            let _ = revwalk.hide(stop);
        }

        let mut newest_seen: Option<Oid> = None;

        for (depth, oid) in revwalk.enumerate() {
            if depth >= max_depth {
                break;
            }
            let oid = oid?;
            let commit = repo.find_commit(oid)?;
            on_commit(&commit);
            if newest_seen.is_none() {
                newest_seen = Some(oid);
            }
        }

        Ok(newest_seen)
    }
    /// One attempt to observe the repository: ask the handler for it up to date, with the credential it names, then
    /// publish what is new. An attempt that cannot go ahead because the credential is missing or unusable, or the clone
    /// or the fetch failed, is logged and leaves the worker waiting for the next (the next fetch time, or the credentials
    /// changing); it does not end the worker. However it ends, the status is published, so a person can see which it was
    /// without reading this pod's log.
    async fn attempt(&self, state: &mut GitRepoWorkerState) {
        let outcome = self.try_to_observe(state).await;
        let status = state.status.record(outcome, now_ms());
        publish_status(&state.tcp_client, &status);
    }

    async fn try_to_observe(&self, state: &mut GitRepoWorkerState) -> Outcome {
        let had_a_clone = state.repo_path.exists();
        let walk = match fetch::fetch(
            &state.protocols,
            &state.config,
            &state.repo_path,
            &state.checkpoints,
        )
        .await
        {
            Ok(walk) => walk,
            Err(failure) => {
                let outcome = Outcome::of_failure(&failure, had_a_clone);
                match outcome {
                    Outcome::PendingCredential => info!(
                        "{} is waiting for the credential it names",
                        state.config.repo_id
                    ),
                    _ => warn!("{} is not up to date: {failure}", state.config.repo_id),
                }
                state.waiting = true;
                return outcome;
            }
        };

        // Each ref is published a batch at a time, oldest first, its checkpoint moving after each batch taken
        // (`publish_ref`). The repository is borrowed only between publishes: it is not Sync, and this future must be Send.
        let repo_id = state.config.repo_id.clone();
        let mut observed = Repository::open_bare(&state.repo_path).map(|repo| {
            state.repo = Some(repo);
        });
        if observed.is_ok() {
            'refs: for (ref_name, plan) in walk {
                for chunk in plan.oids.chunks(state.publish_batch.max(1)) {
                    let events = match state.repo.as_ref() {
                        Some(repo) => batch_events(repo, &repo_id, &ref_name, chunk),
                        None => break 'refs,
                    };
                    let events = match events {
                        Ok(events) => events,
                        Err(e) => {
                            observed = Err(e);
                            break 'refs;
                        }
                    };
                    let checkpoint = state.checkpoints.entry(ref_name.clone()).or_default();
                    if !publish_batch(&state.tcp_client, &ref_name, events, checkpoint).await {
                        continue 'refs;
                    }
                }
                let checkpoint = state.checkpoints.entry(ref_name.clone()).or_default();
                publish_ref_update(&state.tcp_client, &repo_id, &ref_name, checkpoint, plan.tip)
                    .await;
            }
        }
        state.repo = None;
        match observed {
            Ok(()) => {
                state.waiting = false;
                Outcome::Observed {
                    tips: state
                        .checkpoints
                        .iter()
                        .filter_map(|(name, checkpoint)| {
                            Some((name.clone(), checkpoint.tip?.to_string()))
                        })
                        .collect(),
                }
            }
            Err(e) => {
                // The worker stays, and the next attempt starts from where this one stopped.
                error!(
                    "{} could not be read after its fetch: {e}",
                    state.config.repo_id
                );
                state.waiting = true;
                Outcome::FetchFailed(e.message().to_string())
            }
        }
    }

    /// As [`observe_refs`](Self::observe_refs), moving `last_seen` to every tip at once.
    pub fn observe_repository<F>(
        repo: &Repository,
        obs_config: &RepoObservationConfig,
        last_seen: &mut HashMap<String, Oid>,
        on_commit: F,
        on_ref_update: impl FnMut(&str, Option<Oid>, Oid),
    ) -> Result<(), git2::Error>
    where
        F: FnMut(&str, &git2::Commit),
    {
        let tips = Self::observe_refs(repo, obs_config, last_seen, on_commit, on_ref_update)?;
        last_seen.extend(tips);
        Ok(())
    }

    /// Walks each ref from its `last_seen`, calling `on_commit` for each commit found and
    /// `on_ref_update` for the ref, and returns each ref's tip, for `last_seen` once what was found is published.
    pub fn observe_refs<F>(
        repo: &Repository,
        obs_config: &RepoObservationConfig,
        last_seen: &HashMap<String, Oid>,
        mut on_commit: F,
        mut on_ref_update: impl FnMut(&str, Option<Oid>, Oid),
    ) -> Result<Vec<(String, Oid)>, git2::Error>
    where
        F: FnMut(&str, &git2::Commit),
    {
        let mut tips = Vec::new();

        for ref_name in &obs_config.refs {
            let reference = match repo.find_reference(ref_name) {
                Ok(r) => r,
                Err(e) => {
                    warn!("ref {ref_name} not found ({e}), skipping");
                    continue;
                }
            };
            let tip = match reference.target() {
                Some(t) => t,
                None => {
                    warn!("ref {ref_name} has no direct target, skipping");
                    continue;
                }
            };
            debug!(
                "observing {ref_name}: tip={tip}, last_seen={:?}",
                last_seen.get(ref_name)
            );

            let prev = last_seen.get(ref_name).copied();

            Self::walk_commits_incremental(repo, ref_name, prev, obs_config.max_depth, |commit| {
                on_commit(ref_name, commit)
            })?;

            // A ref that is where the last pass left it has not been updated, and is not reported as if it had:
            // every consumer would otherwise have to know to ignore an event whose `old` is its `new`.
            if prev != Some(tip) {
                on_ref_update(ref_name, prev, tip);
            }
            tips.push((ref_name.to_string(), tip));
        }

        Ok(tips)
    }
}

impl GitRepoWorker {
    /// The worker holds the batch, so it follows it. The answer is the batch in force.
    async fn follow_batch(
        configuration: &ConfigurationHandle,
        myself: &ActorRef<GitRepoWorkerMsg>,
    ) -> Result<usize, polar_agent_builder::configuration::FollowError> {
        let names: [&dyn polar_env::Described; 1] = [&settings::PUBLISH_BATCH];
        configuration
            .follow_group(
                &names,
                settings::publish_batch,
                myself,
                GitRepoWorkerMsg::PublishBatchChanged,
            )
            .await
    }
}

#[async_trait]
impl Actor for GitRepoWorker {
    type Msg = GitRepoWorkerMsg;
    type State = GitRepoWorkerState;
    type Arguments = GitRepoWorkerArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: GitRepoWorkerArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        debug!("{myself:?} starting");
        // Nothing is cloned here: the repository may name a credential that has not arrived, and the first
        // attempt (post_start) is the one that finds out.
        let publish_batch = Self::follow_batch(&args.configuration, &myself).await?;
        let mut config = args.config;
        config.refs = tracked_refs(&config.remotes, &config.refs);
        Ok(GitRepoWorkerState {
            repo_path: args.repo_path,
            tcp_client: args.tcp_client,
            protocols: args.protocols,
            repo: None,
            checkpoints: HashMap::new(),
            publish_batch,
            waiting: false,
            status: StatusTracker::new(config.repo_id.clone()),
            config,
            next: None,
        })
    }

    async fn post_start(
        &self,
        myself: ActorRef<Self::Msg>,
        _state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        debug!("{myself:?} started");
        myself.cast(GitRepoWorkerMsg::Observe)?;
        Ok(())
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        msg: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match msg {
            GitRepoWorkerMsg::Observe => {
                trace!("Received Observe message");
                if let Some(earlier) = state.next.take() {
                    earlier.abort();
                }

                self.attempt(state).await;

                state.next = Some(myself.send_after(
                    std::time::Duration::from_secs(state.config.frequency),
                    || GitRepoWorkerMsg::Observe,
                ));
            }
            GitRepoWorkerMsg::PublishBatchChanged(batch) => {
                state.publish_batch = batch;
            }
            GitRepoWorkerMsg::CredentialsChanged => {
                if state.waiting {
                    debug!(
                        "the credentials changed; {} tries again",
                        state.config.repo_id
                    );
                    myself.cast(GitRepoWorkerMsg::Observe)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cassini_client::TcpClientMessage;
    use git_agent_common::status::ObservationState;
    use polar_agent_builder::protocol::CredentialSource;
    use polar_agent_builder::protocol::testing::{GitOrigin, Site, git_handle};
    use polar_crypto::registry::{GitCredential, HttpCredential, UseRefusal};
    use polar_crypto::{CryptoError, Zeroizing};
    use std::sync::{Arc, Mutex};

    /// What the fake CryptoActor says to a request for a git credential.
    #[derive(Clone, Default)]
    enum Answer {
        Found {
            username: &'static str,
            secret: &'static [u8],
        },
        #[default]
        NotRegistered,
        HostNotBound,
    }

    /// Answers as it is told, and records what the handler asks of it: one for each attempt of a repository with a
    /// credential.
    #[derive(Default)]
    struct Recorder {
        answer: Mutex<Answer>,
        asked: Mutex<Vec<(String, String)>>,
    }

    #[async_trait]
    impl CredentialSource for Recorder {
        async fn http(&self, name: String, _: String) -> Result<HttpCredential, CryptoError> {
            // The git observer never asks for one.
            Err(CryptoError::SecretNotRegistered(name))
        }
        async fn git(&self, name: String, host: String) -> Result<GitCredential, CryptoError> {
            self.asked.lock().unwrap().push((name.clone(), host));
            match self.answer.lock().unwrap().clone() {
                Answer::Found { username, secret } => Ok(GitCredential {
                    kind: polar_crypto::registry::SecretKind::Token,
                    username: username.to_string(),
                    secret: Zeroizing::new(secret.to_vec()),
                    host_key: None,
                }),
                Answer::NotRegistered => Err(CryptoError::SecretNotRegistered(name)),
                Answer::HostNotBound => Err(CryptoError::Use(UseRefusal::HostNotBound)),
            }
        }
        async fn bound_to(&self, _: String) -> Result<Option<String>, CryptoError> {
            Ok(None)
        }
    }

    /// The real handler, with the credentials the recorder answers with.
    async fn handler() -> (Site, Arc<Recorder>) {
        let crypto = Arc::new(Recorder::default());
        let site = git_handle(
            fetch::OPERATIONS,
            Some(crypto.clone() as Arc<dyn CredentialSource>),
        )
        .await;
        (site, crypto)
    }

    /// Takes whatever the worker would publish, and says nothing.
    struct Sink {
        received: Arc<Mutex<Vec<TcpClientMessage>>>,
    }

    #[async_trait]
    impl Actor for Sink {
        type Msg = TcpClientMessage;
        type State = ();
        type Arguments = ();

        async fn pre_start(
            &self,
            _: ActorRef<Self::Msg>,
            _: (),
        ) -> Result<Self::State, ActorProcessingErr> {
            Ok(())
        }

        async fn handle(
            &self,
            _: ActorRef<Self::Msg>,
            message: Self::Msg,
            _: &mut Self::State,
        ) -> Result<(), ActorProcessingErr> {
            self.received.lock().unwrap().push(message);
            Ok(())
        }
    }

    struct Rig {
        worker: ActorRef<GitRepoWorkerMsg>,
        crypto: Arc<Recorder>,
        received: Arc<Mutex<Vec<TcpClientMessage>>>,
        cache: tempfile::TempDir,
        _site: Site,
    }

    async fn start(config: RepoObservationConfig) -> Rig {
        let received = Arc::new(Mutex::new(Vec::new()));
        let (sink, _) = Actor::spawn(
            None,
            Sink {
                received: received.clone(),
            },
            (),
        )
        .await
        .unwrap();
        let (site, crypto) = handler().await;
        let cache = tempfile::tempdir().unwrap();
        let (worker, _) = Actor::spawn(
            None,
            GitRepoWorker,
            GitRepoWorkerArgs {
                repo_path: cache.path().join("clone"),
                config,
                tcp_client: TcpClient::from_actor_ref(sink),
                protocols: site.handle.clone(),
                configuration: configuration().await,
            },
        )
        .await
        .unwrap();
        Rig {
            worker,
            crypto,
            received,
            cache,
            _site: site,
        }
    }

    #[test]
    fn a_branch_is_read_from_the_remote_tracking_ref_a_fetch_advances() {
        let origin = vec!["origin".to_string()];
        let refs = |r: &[&str]| r.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            tracked_refs(&origin, &refs(&["refs/heads/main", "refs/heads/feature/x"])),
            refs(&["refs/remotes/origin/main", "refs/remotes/origin/feature/x"])
        );
        // the first remote is the one fetched; none named is origin
        assert_eq!(
            tracked_refs(
                &["upstream".to_string(), "origin".to_string()],
                &refs(&["refs/heads/dev"])
            ),
            refs(&["refs/remotes/upstream/dev"])
        );
        assert_eq!(
            tracked_refs(&[], &refs(&["refs/heads/dev"])),
            refs(&["refs/remotes/origin/dev"])
        );
        // anything else is as written, and nothing stays nothing
        assert_eq!(
            tracked_refs(
                &origin,
                &refs(&["refs/remotes/origin/main", "refs/tags/v1", "HEAD", "main"])
            ),
            refs(&["refs/remotes/origin/main", "refs/tags/v1", "HEAD", "main"])
        );
        assert!(tracked_refs(&origin, &[]).is_empty());
    }

    #[tokio::test]
    async fn a_worker_reads_the_refs_a_fetch_advances_not_the_ones_the_clone_froze() {
        let (_origin, repo, config, _stand_in) = local_origin(1).await;
        let sig = git2::Signature::now("t", "t@example.org").unwrap();
        let tree = repo
            .find_tree(repo.treebuilder(None).unwrap().write().unwrap())
            .unwrap();
        let rig = start(config).await;
        until("the first commit", || {
            published_commits(&rig.received).contains(&"first".to_string())
        })
        .await;
        // A second commit arrives at the origin; only a fetch into refs/remotes can show it.
        let first = repo
            .find_reference("refs/heads/main")
            .unwrap()
            .peel_to_commit()
            .unwrap();
        repo.commit(
            Some("refs/heads/main"),
            &sig,
            &sig,
            "second",
            &tree,
            &[&first],
        )
        .unwrap();
        until("the second commit", || {
            published_commits(&rig.received).contains(&"second".to_string())
        })
        .await;
        assert_eq!(
            published_commits(&rig.received),
            ["first", "second"],
            "what was published is not published again"
        );
        rig.worker.stop(None);
    }

    /// The messages of the commits the worker has published so far.
    fn published_commits(received: &Mutex<Vec<TcpClientMessage>>) -> Vec<String> {
        received
            .lock()
            .unwrap()
            .iter()
            .filter_map(|m| match m {
                TcpClientMessage::Publish { payload, .. } => {
                    let mut aligned = rkyv::util::AlignedVec::<16>::new();
                    aligned.extend_from_slice(payload);
                    match rkyv::from_bytes::<GitRepositoryMessage, rkyv::rancor::Error>(&aligned) {
                        Ok(GitRepositoryMessage::CommitDiscovered { message, .. }) => Some(message),
                        _ => None,
                    }
                }
                _ => None,
            })
            .collect()
    }

    /// The statuses the worker has published so far, oldest first.
    fn published_statuses(received: &Mutex<Vec<TcpClientMessage>>) -> Vec<ObservationStatus> {
        received
            .lock()
            .unwrap()
            .iter()
            .filter_map(|m| match m {
                TcpClientMessage::Publish { topic, payload, .. }
                    if topic == GIT_REPO_OBSERVATION_STATUS =>
                {
                    let mut aligned = rkyv::util::AlignedVec::<16>::new();
                    aligned.extend_from_slice(payload);
                    rkyv::from_bytes::<ObservationStatus, rkyv::rancor::Error>(&aligned).ok()
                }
                _ => None,
            })
            .collect()
    }

    fn last_status(rig: &Rig) -> Option<ObservationStatus> {
        published_statuses(&rig.received).pop()
    }

    /// A repository with one commit on `main`, as a bare origin on disk, a stand-in that serves it, and the configuration
    /// that observes it. Whatever it is in the directory, it is at each request.
    async fn local_origin(
        frequency: u64,
    ) -> (
        tempfile::TempDir,
        Repository,
        RepoObservationConfig,
        GitOrigin,
    ) {
        let origin = tempfile::tempdir().unwrap();
        let repo = Repository::init_bare(origin.path()).unwrap();
        {
            let sig = git2::Signature::now("t", "t@example.org").unwrap();
            let tree = repo
                .find_tree(repo.treebuilder(None).unwrap().write().unwrap())
                .unwrap();
            repo.commit(Some("refs/heads/main"), &sig, &sig, "first", &tree, &[])
                .unwrap();
        }
        repo.set_head("refs/heads/main").unwrap();
        let stand_in = GitOrigin::serving(origin.path()).await;
        let url = stand_in.url();
        let mut config = RepoObservationConfig::new(
            RepoId::from_url(&url),
            url,
            vec!["origin".into()],
            None,
            vec!["refs/heads/main".into()],
        );
        config.frequency = frequency;
        (origin, repo, config, stand_in)
    }

    #[tokio::test]
    async fn a_repository_waiting_for_its_credential_says_so() {
        let rig = start(private_repo()).await;
        until("a status", || last_status(&rig).is_some()).await;
        settle().await;
        let statuses = published_statuses(&rig.received);
        assert_eq!(statuses.len(), 1, "one attempt, one status");
        assert_eq!(statuses[0].state, ObservationState::PendingCredential);
        assert_eq!(statuses[0].repo_id, private_repo().repo_id);
        assert_eq!(statuses[0].reason, None);
        assert_eq!(statuses[0].consecutive_failures, 0);
        rig.worker.stop(None);
    }

    #[tokio::test]
    async fn a_credential_bound_to_another_host_is_a_failure_that_says_why() {
        let rig = start(private_repo()).await;
        *rig.crypto.answer.lock().unwrap() = Answer::HostNotBound;
        until("the first attempt", || asked(&rig) >= 1).await;
        until("a status", || last_status(&rig).is_some()).await;
        let status = last_status(&rig).unwrap();
        assert_eq!(status.state, ObservationState::Failing);
        assert!(
            status
                .reason
                .as_deref()
                .unwrap()
                .starts_with("the credential cannot be used:"),
            "{:?}",
            status.reason
        );
        assert_eq!(status.consecutive_failures, 1);
        rig.worker.stop(None);
    }

    #[tokio::test]
    async fn a_clone_that_fails_is_a_failure_that_counts_and_the_worker_goes_on() {
        let url = "https://localhost:1/status/r.git";
        let rig = start(private_repo_at(url)).await;
        *rig.crypto.answer.lock().unwrap() = Answer::Found {
            username: "svc",
            secret: b"tok",
        };
        rig.worker
            .cast(GitRepoWorkerMsg::CredentialsChanged)
            .unwrap();
        until("a failed clone", || {
            last_status(&rig).is_some_and(|s| s.state == ObservationState::Failing)
        })
        .await;
        let first = last_status(&rig).unwrap();
        assert!(
            first
                .reason
                .as_deref()
                .unwrap()
                .starts_with("the clone failed:"),
            "{:?}",
            first.reason
        );
        rig.worker.cast(GitRepoWorkerMsg::Observe).unwrap();
        until("a second failure", || {
            last_status(&rig).is_some_and(|s| s.consecutive_failures == 2)
        })
        .await;
        rig.worker.stop(None);
    }

    #[tokio::test]
    async fn a_repository_that_is_fetched_is_observing_with_its_tips_and_the_time() {
        let (_origin, repo, config, _stand_in) = local_origin(900).await;
        let tip = repo.refname_to_id("refs/heads/main").unwrap().to_string();
        let before = now_ms();
        let rig = start(config).await;
        until("observing", || {
            last_status(&rig).is_some_and(|s| s.state == ObservationState::Observing)
        })
        .await;
        let status = last_status(&rig).unwrap();
        assert_eq!(status.reason, None);
        assert_eq!(status.consecutive_failures, 0);
        assert!(status.last_success.unwrap() >= before);
        assert_eq!(
            status.tips,
            vec![("refs/remotes/origin/main".to_string(), tip)]
        );
        rig.worker.stop(None);
    }

    #[tokio::test]
    async fn a_fetch_that_fails_does_not_end_the_worker_and_the_next_attempt_recovers() {
        let (origin, repo, config, _stand_in) = local_origin(900).await;
        let rig = start(config).await;
        until("observing", || {
            last_status(&rig).is_some_and(|s| s.state == ObservationState::Observing)
        })
        .await;
        let observed_at = last_status(&rig).unwrap().last_success;

        // The origin goes away: the next fetch cannot work.
        let gone = origin.path().with_extension("gone");
        std::fs::rename(origin.path(), &gone).unwrap();
        rig.worker.cast(GitRepoWorkerMsg::Observe).unwrap();
        until("a failed fetch", || {
            last_status(&rig).is_some_and(|s| s.state == ObservationState::Failing)
        })
        .await;
        let failing = last_status(&rig).unwrap();
        assert!(
            failing
                .reason
                .as_deref()
                .unwrap()
                .starts_with("the fetch failed:"),
            "{:?}",
            failing.reason
        );
        assert_eq!(failing.consecutive_failures, 1);
        assert_eq!(
            failing.last_success, observed_at,
            "the last success is still the last success"
        );
        assert!(
            !failing.tips.is_empty(),
            "where the refs were is still known"
        );
        assert!(
            rig.worker.get_status() != ractor::ActorStatus::Stopped
                && rig.worker.get_status() != ractor::ActorStatus::Stopping,
            "a failed fetch ended the worker"
        );

        // It comes back, with a new commit; the same worker sees it.
        std::fs::rename(&gone, origin.path()).unwrap();
        let sig = git2::Signature::now("t", "t@example.org").unwrap();
        let tree = repo
            .find_tree(repo.treebuilder(None).unwrap().write().unwrap())
            .unwrap();
        let first = repo
            .find_reference("refs/heads/main")
            .unwrap()
            .peel_to_commit()
            .unwrap();
        repo.commit(
            Some("refs/heads/main"),
            &sig,
            &sig,
            "second",
            &tree,
            &[&first],
        )
        .unwrap();
        rig.worker.cast(GitRepoWorkerMsg::Observe).unwrap();
        until("observing again", || {
            last_status(&rig).is_some_and(|s| s.state == ObservationState::Observing)
        })
        .await;
        let recovered = last_status(&rig).unwrap();
        assert_eq!(recovered.reason, None);
        assert_eq!(recovered.consecutive_failures, 0);
        assert!(published_commits(&rig.received).contains(&"second".to_string()));
        rig.worker.stop(None);
    }

    #[tokio::test]
    async fn a_credentials_change_hurries_a_failing_fetch_but_not_a_healthy_repository() {
        let (origin, _repo, config, _stand_in) = local_origin(900).await;
        let rig = start(config).await;
        until("observing", || {
            last_status(&rig).is_some_and(|s| s.state == ObservationState::Observing)
        })
        .await;
        settle().await;
        let healthy = published_statuses(&rig.received).len();
        rig.worker
            .cast(GitRepoWorkerMsg::CredentialsChanged)
            .unwrap();
        settle().await;
        assert_eq!(
            published_statuses(&rig.received).len(),
            healthy,
            "a repository that is being observed has no reason to try again because credentials changed"
        );

        let gone = origin.path().with_extension("gone");
        std::fs::rename(origin.path(), &gone).unwrap();
        rig.worker.cast(GitRepoWorkerMsg::Observe).unwrap();
        until("a failed fetch", || {
            last_status(&rig).is_some_and(|s| s.state == ObservationState::Failing)
        })
        .await;
        let failing = published_statuses(&rig.received).len();
        // Its frequency is 900 s: only the message can make the next attempt now.
        rig.worker
            .cast(GitRepoWorkerMsg::CredentialsChanged)
            .unwrap();
        until("an attempt made because the credentials changed", || {
            published_statuses(&rig.received).len() > failing
        })
        .await;

        // Once it has recovered it is healthy again, and a change of credentials is nothing to it.
        std::fs::rename(&gone, origin.path()).unwrap();
        rig.worker.cast(GitRepoWorkerMsg::Observe).unwrap();
        until("observing again", || {
            last_status(&rig).is_some_and(|s| s.state == ObservationState::Observing)
        })
        .await;
        settle().await;
        let recovered = published_statuses(&rig.received).len();
        rig.worker
            .cast(GitRepoWorkerMsg::CredentialsChanged)
            .unwrap();
        settle().await;
        assert_eq!(published_statuses(&rig.received).len(), recovered);
        rig.worker.stop(None);
    }

    struct SupervisorRig {
        supervisor: ActorRef<RepoSupervisorMessage>,
        crypto: Arc<Recorder>,
        _cache: tempfile::TempDir,
        _site: Site,
    }

    async fn start_supervisor() -> SupervisorRig {
        let received = Arc::new(Mutex::new(Vec::new()));
        let (sink, _) = Actor::spawn(None, Sink { received }, ()).await.unwrap();
        let (site, crypto) = handler().await;
        let cache = tempfile::tempdir().unwrap();
        let (supervisor, _) = Actor::spawn(
            None,
            GitRepoSupervisor,
            GitRepoSupervisorArgs {
                cache_root: cache.path().to_path_buf(),
                configuration: configuration().await,
                tcp_client: TcpClient::from_actor_ref(sink),
                protocols: site.handle.clone(),
            },
        )
        .await
        .unwrap();
        SupervisorRig {
            supervisor,
            crypto,
            _cache: cache,
            _site: site,
        }
    }

    fn private_repo_at(url: &str) -> RepoObservationConfig {
        RepoObservationConfig::new(
            RepoId::from_url(url),
            url.into(),
            vec!["origin".into()],
            None,
            Vec::new(),
        )
        .with_credential("gh")
    }

    #[tokio::test]
    async fn the_same_announcement_again_changes_nothing_and_a_changed_one_replaces_the_worker() {
        let rig = start_supervisor().await;
        let asked = || rig.crypto.asked.lock().unwrap().len();
        let config = private_repo_at("https://localhost:1/restart/r.git");
        rig.supervisor
            .cast(RepoSupervisorMessage::SpawnWorker {
                config: config.clone(),
            })
            .unwrap();
        until("the first attempt", || asked() == 1).await;

        // Announced again, unchanged: no new worker, so no new attempt.
        rig.supervisor
            .cast(RepoSupervisorMessage::SpawnWorker {
                config: config.clone(),
            })
            .unwrap();
        settle().await;
        assert_eq!(
            asked(),
            1,
            "an identical announcement started another attempt"
        );

        // Announced with a setting changed: the old worker is stopped and a new one starts.
        let mut changed = config.clone();
        changed.frequency = 901;
        rig.supervisor
            .cast(RepoSupervisorMessage::SpawnWorker { config: changed })
            .unwrap();
        until("the new worker's first attempt", || asked() == 2).await;

        // Only the new worker is alive: telling the workers makes exactly one more attempt.
        rig.supervisor
            .cast(RepoSupervisorMessage::CredentialsChanged)
            .unwrap();
        until("one more attempt", || asked() == 3).await;
        settle().await;
        assert_eq!(asked(), 3, "the replaced worker is still running");
        rig.supervisor.stop(None);
    }

    #[tokio::test]
    async fn repositories_are_restarted_one_at_a_time_each_by_its_own_change() {
        let rig = start_supervisor().await;
        let asked = || rig.crypto.asked.lock().unwrap().len();
        let (a, b) = (
            private_repo_at("https://localhost:1/two/a.git"),
            private_repo_at("https://localhost:1/two/b.git"),
        );
        for config in [a.clone(), b.clone()] {
            rig.supervisor
                .cast(RepoSupervisorMessage::SpawnWorker { config })
                .unwrap();
        }
        until("both first attempts", || asked() == 2).await;
        let mut changed = a.clone();
        changed.max_depth = 7;
        rig.supervisor
            .cast(RepoSupervisorMessage::SpawnWorker { config: changed })
            .unwrap();
        until("a's new worker", || asked() == 3).await;
        rig.supervisor
            .cast(RepoSupervisorMessage::CredentialsChanged)
            .unwrap();
        // a's new worker and b's untouched one: two attempts, not three.
        until("both asked again", || asked() == 5).await;
        settle().await;
        assert_eq!(asked(), 5);
        rig.supervisor.stop(None);
    }

    fn asked(rig: &Rig) -> usize {
        rig.crypto.asked.lock().unwrap().len()
    }

    async fn until(what: &str, mut condition: impl FnMut() -> bool) {
        for _ in 0..600 {
            if condition() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("timed out waiting for {what}");
    }

    async fn settle() {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    /// A repository that is reached over https with a credential, at a host nothing listens on.
    fn private_repo() -> RepoObservationConfig {
        RepoObservationConfig::new(
            RepoId::from_url("https://localhost:1/o/r.git"),
            "https://localhost:1/o/r.git".into(),
            Vec::new(),
            None,
            Vec::new(),
        )
        .with_credential("gh")
    }

    #[tokio::test]
    async fn a_repository_whose_credential_has_not_arrived_waits_and_clones_nothing() {
        let rig = start(private_repo()).await;
        until("the first attempt", || asked(&rig) == 1).await;
        settle().await;
        assert_eq!(asked(&rig), 1, "it asked again before anything changed");
        assert!(!rig.cache.path().join("clone").exists());
        assert!(
            published_commits(&rig.received).is_empty(),
            "no commit is published for a repository that was not cloned"
        );
        rig.worker.stop(None);
    }

    #[tokio::test]
    async fn a_waiting_repository_tries_again_at_once_when_the_credentials_change() {
        let rig = start(private_repo()).await;
        until("the first attempt", || asked(&rig) == 1).await;
        // Its frequency is 900 s, so only the message can make the second attempt happen now.
        rig.worker
            .cast(GitRepoWorkerMsg::CredentialsChanged)
            .unwrap();
        until("a second attempt", || asked(&rig) == 2).await;
        settle().await;
        assert_eq!(asked(&rig), 2, "one message made more than one attempt");
        rig.worker.stop(None);
    }

    #[tokio::test]
    async fn a_credential_that_has_arrived_is_asked_for_and_a_clone_that_fails_waits_for_the_next_attempt()
     {
        let url = "https://localhost:1/found/r.git";
        let rig = start(private_repo_at(url)).await;
        until("the first attempt", || asked(&rig) == 1).await;
        assert!(
            !rig.cache.path().join("clone").exists(),
            "nothing is cloned before the credential is there"
        );
        *rig.crypto.answer.lock().unwrap() = Answer::Found {
            username: "svc",
            secret: b"tok",
        };
        rig.worker
            .cast(GitRepoWorkerMsg::CredentialsChanged)
            .unwrap();
        until("a second attempt", || asked(&rig) == 2).await;
        assert_eq!(
            rig.crypto.asked.lock().unwrap()[1],
            ("gh".to_string(), "localhost".to_string())
        );
        // The clone is tried with it, and fails; the worker is still alive and still waiting, so the next change tries the
        // clone again.
        until("the clone to fail", || {
            last_status(&rig).is_some_and(|s| {
                s.reason
                    .as_deref()
                    .is_some_and(|r| r.starts_with("the clone failed:"))
            })
        })
        .await;
        rig.worker
            .cast(GitRepoWorkerMsg::CredentialsChanged)
            .unwrap();
        until("a third attempt", || asked(&rig) == 3).await;
        rig.worker.stop(None);
    }

    /// The whole way: a repository waiting for its credential gets it, the handler presents it to a real TLS server that
    /// wants it, and what is there is published.
    #[tokio::test]
    async fn a_credential_that_arrives_is_presented_and_the_repository_is_observed() {
        let (_origin, _repo, mut config, stand_in) = local_origin(900).await;
        stand_in.asks_for("svc", "tok");
        config.repo_url = stand_in.url_over_tls().await;
        let rig = start(config.with_credential("gh")).await;
        until("the first attempt", || asked(&rig) == 1).await;
        *rig.crypto.answer.lock().unwrap() = Answer::Found {
            username: "svc",
            secret: b"tok",
        };
        rig.worker
            .cast(GitRepoWorkerMsg::CredentialsChanged)
            .unwrap();
        until("the commit to be published", || {
            published_commits(&rig.received).contains(&"first".to_string())
        })
        .await;
        assert_eq!(
            last_status(&rig).unwrap().state,
            ObservationState::Observing
        );
        assert!(
            stand_in
                .presented()
                .await
                .iter()
                .flatten()
                .any(|presented| presented == "Basic c3ZjOnRvaw=="),
            "svc:tok was presented"
        );
        rig.worker.stop(None);
    }

    /// A credential the host refuses is a failure that says so, and the credentials changing tries again only with what the
    /// handler then allows.
    #[tokio::test]
    async fn a_credential_the_host_refuses_is_a_failure_that_says_so() {
        let (_origin, _repo, mut config, stand_in) = local_origin(900).await;
        stand_in.asks_for("svc", "another");
        config.repo_url = stand_in.url_over_tls().await;
        let rig = start(config.with_credential("gh")).await;
        *rig.crypto.answer.lock().unwrap() = Answer::Found {
            username: "svc",
            secret: b"tok",
        };
        rig.worker.cast(GitRepoWorkerMsg::Observe).unwrap();
        until("a refusal", || {
            last_status(&rig).is_some_and(|s| {
                s.reason.as_deref().is_some_and(|r| {
                    r.starts_with("the credential cannot be used:") && r.contains("refused")
                })
            })
        })
        .await;
        assert!(published_commits(&rig.received).is_empty());
        rig.worker.stop(None);
    }

    #[tokio::test]
    async fn a_public_repository_that_wants_a_login_fails_and_is_offered_nothing() {
        let (_origin, _repo, config, stand_in) = local_origin(900).await;
        stand_in.asks_for("svc", "tok");
        let rig = start(config).await;
        until("a failed clone", || {
            last_status(&rig).is_some_and(|s| {
                s.reason
                    .as_deref()
                    .is_some_and(|r| r.starts_with("the clone failed:"))
            })
        })
        .await;
        assert_eq!(asked(&rig), 0);
        assert!(stand_in.presented().await.iter().all(Option::is_none));
        rig.worker.stop(None);
    }

    #[tokio::test]
    async fn a_credential_bound_to_another_host_is_not_used_and_nothing_is_cloned() {
        let rig = start(private_repo()).await;
        *rig.crypto.answer.lock().unwrap() = Answer::HostNotBound;
        until("the first attempt", || asked(&rig) >= 1).await;
        settle().await;
        assert!(!rig.cache.path().join("clone").exists());
        assert!(published_commits(&rig.received).is_empty());
        rig.worker.stop(None);
    }

    #[tokio::test]
    async fn a_public_repository_is_observed_without_asking_for_a_credential() {
        let (_origin, _repo, mut config, _stand_in) = local_origin(900).await;
        config.refs = vec!["refs/remotes/origin/main".into()];
        let rig = start(config).await;
        until("the commit to be published", || {
            !rig.received.lock().unwrap().is_empty()
        })
        .await;
        assert_eq!(asked(&rig), 0);
        assert!(rig.cache.path().join("clone").exists());
        rig.worker.stop(None);
    }

    /// With no refs configured, the default branch the clone found is what is observed.
    #[tokio::test]
    async fn a_repository_with_no_refs_configured_observes_its_default_branch() {
        let (_origin, _repo, mut config, _stand_in) = local_origin(900).await;
        config.refs = Vec::new();
        let rig = start(config).await;
        until("the commit to be published", || {
            published_commits(&rig.received).contains(&"first".to_string())
        })
        .await;
        rig.worker.stop(None);
    }

    // Paused time, so that "the old timer would have fired by now" is exact and not a race.
    #[tokio::test(start_paused = true)]
    async fn an_attempt_made_early_replaces_the_scheduled_one_instead_of_adding_to_it() {
        let mut config = private_repo();
        config.frequency = 10;
        let rig = start(config).await;
        until("the first attempt", || asked(&rig) == 1).await;
        tokio::time::advance(std::time::Duration::from_secs(3)).await;
        rig.worker
            .cast(GitRepoWorkerMsg::CredentialsChanged)
            .unwrap();
        until("the early attempt", || asked(&rig) == 2).await;
        // The first schedule would fire at 10 s; the early attempt moved it to 13 s.
        tokio::time::advance(std::time::Duration::from_secs(8)).await;
        settle().await;
        assert_eq!(asked(&rig), 2, "the earlier schedule still fired");
        tokio::time::advance(std::time::Duration::from_secs(3)).await;
        until("the rescheduled attempt", || asked(&rig) == 3).await;
        rig.worker.stop(None);
    }

    fn set(urls: &[&str], complete: bool) -> RepositorySet {
        RepositorySet {
            repositories: urls.iter().map(|u| private_repo_at(u)).collect(),
            complete,
        }
    }

    /// How many workers there are: each one that is waiting for its credential asks once when told they changed.
    async fn workers_in(rig: &SupervisorRig) -> usize {
        settle().await;
        let before = rig.crypto.asked.lock().unwrap().len();
        rig.supervisor
            .cast(RepoSupervisorMessage::CredentialsChanged)
            .unwrap();
        settle().await;
        rig.crypto.asked.lock().unwrap().len() - before
    }

    fn reconcile(rig: &SupervisorRig, set: RepositorySet) {
        rig.supervisor
            .cast(RepoSupervisorMessage::Reconcile { set })
            .unwrap();
    }

    #[tokio::test]
    async fn a_set_starts_a_worker_for_each_repository_in_it() {
        let rig = start_supervisor().await;
        reconcile(
            &rig,
            set(
                &[
                    "https://localhost:1/set/a.git",
                    "https://localhost:1/set/b.git",
                    "https://localhost:1/set/c.git",
                ],
                false,
            ),
        );
        assert_eq!(workers_in(&rig).await, 3);
        rig.supervisor.stop(None);
    }

    #[tokio::test]
    async fn the_same_set_again_changes_nothing_and_a_changed_repository_is_replaced() {
        let rig = start_supervisor().await;
        let urls = [
            "https://localhost:1/again/a.git",
            "https://localhost:1/again/b.git",
        ];
        reconcile(&rig, set(&urls, true));
        assert_eq!(workers_in(&rig).await, 2);
        let asks_before = rig.crypto.asked.lock().unwrap().len();
        reconcile(&rig, set(&urls, true));
        settle().await;
        assert_eq!(
            rig.crypto.asked.lock().unwrap().len(),
            asks_before,
            "an identical set started new workers"
        );
        let mut changed = set(&urls, true);
        changed.repositories[0].frequency = 901;
        reconcile(&rig, changed);
        settle().await;
        assert_eq!(
            rig.crypto.asked.lock().unwrap().len(),
            asks_before + 1,
            "only the changed repository should have a new worker"
        );
        assert_eq!(
            workers_in(&rig).await,
            2,
            "the replaced worker is still running"
        );
        rig.supervisor.stop(None);
    }

    #[tokio::test]
    async fn a_complete_set_stops_the_workers_it_does_not_name() {
        let rig = start_supervisor().await;
        reconcile(
            &rig,
            set(
                &[
                    "https://localhost:1/drop/a.git",
                    "https://localhost:1/drop/b.git",
                    "https://localhost:1/drop/c.git",
                ],
                true,
            ),
        );
        assert_eq!(workers_in(&rig).await, 3);
        reconcile(&rig, set(&["https://localhost:1/drop/b.git"], true));
        assert_eq!(workers_in(&rig).await, 1);
        rig.supervisor.stop(None);
    }

    #[tokio::test]
    async fn an_incomplete_set_stops_nothing_but_still_starts_what_is_new() {
        let rig = start_supervisor().await;
        reconcile(
            &rig,
            set(
                &[
                    "https://localhost:1/inc/a.git",
                    "https://localhost:1/inc/b.git",
                ],
                true,
            ),
        );
        assert_eq!(workers_in(&rig).await, 2);
        reconcile(&rig, set(&["https://localhost:1/inc/c.git"], false));
        assert_eq!(
            workers_in(&rig).await,
            3,
            "the two it did not name must survive, and c start"
        );
        rig.supervisor.stop(None);
    }

    #[tokio::test]
    async fn an_empty_set_stops_everything_only_if_it_is_complete() {
        let rig = start_supervisor().await;
        reconcile(
            &rig,
            set(
                &[
                    "https://localhost:1/empty/a.git",
                    "https://localhost:1/empty/b.git",
                ],
                true,
            ),
        );
        assert_eq!(workers_in(&rig).await, 2);
        reconcile(&rig, set(&[], false));
        assert_eq!(
            workers_in(&rig).await,
            2,
            "an incomplete empty set stopped workers"
        );
        reconcile(&rig, set(&[], true));
        assert_eq!(workers_in(&rig).await, 0);
        rig.supervisor.stop(None);
    }

    #[tokio::test]
    async fn a_repository_that_was_dropped_is_observed_again_when_a_later_set_names_it() {
        let rig = start_supervisor().await;
        let url = "https://localhost:1/back/a.git";
        reconcile(&rig, set(&[url], true));
        assert_eq!(workers_in(&rig).await, 1);
        reconcile(&rig, set(&[], true));
        assert_eq!(workers_in(&rig).await, 0);
        reconcile(&rig, set(&[url], true));
        assert_eq!(workers_in(&rig).await, 1);
        rig.supervisor.stop(None);
    }

    /// The live configuration, as the builder gives it, with the observer's defaults.
    async fn configuration() -> ConfigurationHandle {
        struct Parent;
        #[async_trait]
        impl Actor for Parent {
            type Msg = ();
            type State = ();
            type Arguments = ();
            async fn pre_start(&self, _: ActorRef<()>, _: ()) -> Result<(), ActorProcessingErr> {
                Ok(())
            }
        }
        let (parent, _) = Actor::spawn(None, Parent, ()).await.unwrap();
        let env: HashMap<String, String> = HashMap::new();
        ConfigurationHandle::spawn(
            None,
            crate::agent::AGENT_NAME,
            polar_env::Config::builder(&env)
                .register(&settings::SECTION)
                .build(),
            None,
            parent.get_cell(),
        )
        .await
        .unwrap()
    }

    /// A worker follows the batch while it runs, and a new one is what the next publish goes by. At least one.
    #[tokio::test]
    async fn a_worker_follows_the_batch_and_the_next_publish_goes_by_it() {
        struct Deaf;
        #[async_trait]
        impl Actor for Deaf {
            type Msg = GitRepoWorkerMsg;
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
        let configuration = configuration().await;
        let (myself, _) = Actor::spawn(None, Deaf, ()).await.unwrap();
        assert_eq!(
            GitRepoWorker::follow_batch(&configuration, &myself)
                .await
                .unwrap(),
            settings::DEFAULT_PUBLISH_BATCH
        );
        assert_eq!(
            configuration
                .dynamic_settings_problems(&[&settings::SECTION])
                .await
                .unwrap(),
            Vec::<String>::new()
        );
        // A new one is what the next publish goes by.
        let (site, _crypto) = handler().await;
        let url = "https://nowhere.invalid/a.git";
        let mut state = GitRepoWorkerState {
            config: RepoObservationConfig::new(
                RepoId::from_url(url),
                url.to_string(),
                vec!["origin".to_string()],
                None,
                Vec::new(),
            ),
            repo_path: PathBuf::from("/nowhere"),
            tcp_client: TcpClient::from_actor_ref(
                Actor::spawn(
                    None,
                    Sink {
                        received: Arc::new(Mutex::new(Vec::new())),
                    },
                    (),
                )
                .await
                .unwrap()
                .0,
            ),
            protocols: site.handle.clone(),
            repo: None,
            checkpoints: HashMap::new(),
            publish_batch: settings::DEFAULT_PUBLISH_BATCH,
            waiting: false,
            status: StatusTracker::new(RepoId::from_url(url)),
            next: None,
        };
        GitRepoWorker
            .handle(myself, GitRepoWorkerMsg::PublishBatchChanged(3), &mut state)
            .await
            .unwrap();
        assert_eq!(state.publish_batch, 3);

        // Zero is taken as one, so it does not stop a worker.
        let mut zero = (*configuration.current().await.unwrap()).clone();
        zero.apply_overrides(&[("POLAR_GIT_PUBLISH_BATCH", "0")])
            .unwrap();
        assert_eq!(settings::publish_batch(&zero).unwrap(), 1);
    }
}
