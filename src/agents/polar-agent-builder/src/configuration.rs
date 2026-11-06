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

//! The ConfigurationActor: the runtime shell around the layered [`polar_env::Config`].
//!
//! It owns the agent's configuration, takes versioned overrides, and tells subscribers when
//! values change. Design: `docs/architecture/configuration.md`, section 5.
//!
//! What it does, and what it deliberately leaves to others:
//!
//! - **Transactional.** An override is parsed by the variable's own declaration and every
//!   section's relations are re-checked on the result. If anything is wrong nothing changes and
//!   the refusal names the variable. Only `Dynamic` variables accept overrides, so the agent's
//!   code, not the repository, decides what may change at runtime.
//! - **Monotonic.** Each update carries a version that must be higher than the last one
//!   applied, so an old update cannot be replayed over a newer one. A refused update does not
//!   advance the version, so a corrected one can be sent again under the same number.
//! - **Notified by message.** An actor that holds a value follows it ([`ConfigurationHandle::follow`]): it gets the
//!   value in force, and each new one as a message of its own, which it knows what to do with. Subscribers of the
//!   port receive [`ConfigChanged`] and read [`ConfigurationHandle::current`] again. The values are read where the
//!   follower is, so no closure of theirs runs inside this actor; only an agent's judge does, a pure function.
//! - **Followed, or says so.** An update to a variable nobody follows applies, and its outcome says it does nothing
//!   until something that follows it starts. `docs/architecture/dynamic-settings.md`.
//! - **Recorded.** Every applied and refused update is kept (the latest [`HISTORY`]) and logged,
//!   with its version. Values are never recorded: a secret's value appears nowhere.
//!
//! **Updates are signed.** The only way in from outside is [`ConfigurationHandle::submit`], which takes a
//! signed document and runs the checks in [`crate::signed`] first: who signed it, that it is for this
//! agent, and that the signer may make the change. Only a document that passes reaches the checks above.
//! An agent with no CA to verify against refuses every document. It does not depend on Cassini: an agent
//! runs on its environment alone until something submits an update.

use crate::runtime::{RuntimeChanged, RuntimeSection, RuntimeValue};
use crate::signed::{Rejection, UpdateVerifier, VerifiedDocument};
use polar_env::{Config, Described, Mutability, Readable, Resolved, Section};
use polar_policy::PolicyMessage;
use polar_scheduler_common::ConfigurationOutcome;
use polar_scheduler_common::running::RunningConfiguration;
use polar_signing::Authority;
use ractor::{Actor, ActorProcessingErr, ActorRef, OutputPort, RpcReplyPort};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// How many of the latest updates are kept for [`ConfigurationHandle::history`].
pub const HISTORY: usize = 100;

/// How long a read of the actor (the configuration, a runtime section, the history) may take before it is
/// reported as failed: a read is answered at once, so one that waits this long is waiting behind other work or
/// on an actor that no longer answers. A submit is not bounded by it (see [`ConfigurationHandle::submit`]).
const CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Why an update was not applied. Nothing changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The version was not higher than the last one applied: a replay, or an old update arriving
    /// late.
    Stale { applied: u64 },
    /// The update would put the agent in a state its startup check refuses, or names a
    /// variable that does not exist or may not change. Every problem, not the first.
    Invalid(Vec<String>),
    /// The document was not accepted: it is unsigned, signed by someone untrusted or not allowed to,
    /// altered, or for another agent. Nothing about its contents was acted on.
    Unverified(Rejection),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The names whose effective value changed (empty if the update changed nothing), and what the agent's judge
    /// said about it ([`SectionJudge`](crate::runtime::SectionJudge)), if anything.
    Applied {
        changed: Vec<String>,
        notes: Vec<String>,
    },
    Refused(Refusal),
}

/// One update, as recorded. Carries names and reasons, never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigEvent {
    /// The version the update carried. Zero for a document refused before its payload could be
    /// trusted, since its claimed version means nothing then.
    pub version: u64,
    pub outcome: ApplyOutcome,
    /// Who signed it (username or identity, and certificate serial), when it was verified.
    pub signer: Option<String>,
}

/// Sent on the output port when an update changed at least one value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigChanged {
    pub version: u64,
    pub changed: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigurationError {
    /// The actor did not answer.
    Unavailable(String),
}

impl std::fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigurationError::Unavailable(why) => {
                write!(f, "the configuration actor did not answer: {why}")
            }
        }
    }
}

impl std::error::Error for ConfigurationError {}

/// Why [`ConfigurationHandle::follow`] gave no value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FollowError {
    /// The actor did not answer, and nothing is followed.
    Unavailable(ConfigurationError),
    /// The configuration in force does not read. It is followed all the same: the next value that reads arrives as a
    /// message.
    Unreadable(String),
}

impl std::fmt::Display for FollowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FollowError::Unavailable(why) => write!(f, "{why}"),
            FollowError::Unreadable(why) => write!(f, "the settings do not read: {why}"),
        }
    }
}

impl std::error::Error for FollowError {}

/// An agent's judge of its settings as a whole, beyond what its sections check, such as the placeholder address a
/// section must accept so that the agent can stay up and say so (`PolarAgent::SETTINGS_JUDGE`). Pure: it runs inside
/// the actor, on every update that changes a value.
pub type SettingsJudge = fn(&Config) -> Result<(), String>;

/// Whether an update is refused, by what the judge says of the settings before and after it. Only one that would
/// break settings that work: while they do not work any update goes through, or an agent held on them could not even
/// have its logging changed, nor be mended in two steps.
pub(crate) fn breaks_what_works(
    in_force: Result<(), String>,
    candidate: Result<(), String>,
) -> Option<String> {
    match (in_force, candidate) {
        (Ok(()), Err(why)) => Some(why),
        _ => None,
    }
}

/// What an outcome says of a variable that changed and that nothing follows.
fn nothing_follows(name: &str) -> String {
    format!(
        "nothing follows {name} now: what starts next reads it, at the latest at the agent's next restart"
    )
}

/// How to see whether a follower's value depends on a variable, for [`ConfigurationHandle::dynamic_settings_problems`].
type Depends = Arc<dyn Fn(&Config, &Config) -> Result<bool, String> + Send + Sync>;

/// Someone following variables, as the actor keeps them.
#[derive(Clone)]
pub struct Follower {
    names: Vec<&'static str>,
    actor: ractor::ActorCell,
    /// Each new configuration goes here. The value is read and compared at the far end, not in the actor.
    configs: Option<tokio::sync::mpsc::UnboundedSender<Arc<Config>>>,
    depends: Option<Depends>,
}

impl Follower {
    fn alive(&self) -> bool {
        !matches!(
            self.actor.get_status(),
            ractor::ActorStatus::Stopping | ractor::ActorStatus::Stopped
        ) && self
            .configs
            .as_ref()
            .is_none_or(|configs| !configs.is_closed())
    }
}

pub enum ConfigurationMessage {
    Apply {
        version: u64,
        changes: Vec<(String, String)>,
        reply: RpcReplyPort<ApplyOutcome>,
    },
    /// A signed document delivered on the agent's configuration topic: verified, then applied, with no
    /// reply. Handled in the order delivered; what became of it is in the history and the log.
    Deliver(serde_json::Value),
    /// A signed document from outside: verified, then applied.
    Submit {
        document: serde_json::Value,
        reply: RpcReplyPort<ApplyOutcome>,
    },
    Current(RpcReplyPort<Arc<Config>>),
    History(RpcReplyPort<Vec<ConfigEvent>>),
    /// The latest accepted body of a runtime section, if any has arrived.
    Runtime {
        section: String,
        reply: RpcReplyPort<Option<RuntimeValue>>,
    },
    /// Someone follows these variables from now on. The answer is the configuration in force at that moment, so no
    /// update falls between what they read and what they are sent.
    Follow {
        follower: Follower,
        reply: RpcReplyPort<Arc<Config>>,
    },
    /// Who follows what, and the configuration in force.
    Followers(RpcReplyPort<(Arc<Config>, Vec<Follower>)>),
    /// A signed question about the configuration in force, with the identity the broker stamped on it.
    Question {
        document: serde_json::Value,
        published_by: Option<String>,
        reply: RpcReplyPort<Result<RunningConfiguration, Rejection>>,
    },
}

pub struct ConfigurationActor;

pub struct ConfigurationArgs {
    pub config: Config,
    /// How signed documents are checked. `None` refuses every document.
    pub verifier: Option<UpdateVerifier>,
    /// This agent's name, which its outcome events carry.
    pub agent: String,
    pub changes: Arc<OutputPort<ConfigChanged>>,
    /// Where each outcome is announced, for whoever puts it on the wire.
    pub outcomes: Arc<OutputPort<ConfigurationOutcome>>,
    /// The runtime sections this agent declares: only these are accepted, each judged by its own check.
    pub runtime_sections: &'static [&'static RuntimeSection],
    /// Where a replaced runtime section is announced.
    pub runtime_changes: Arc<OutputPort<RuntimeChanged>>,
    /// The agent's policy actor. When there is one with a policy loaded, it is asked before the signer's
    /// certificate whether they may make a change (docs/architecture/authority-distribution.md).
    pub policy: Option<ActorRef<PolicyMessage>>,
    /// The agent's judge of a runtime section before it is replaced, if it has one.
    pub judge: Option<Arc<dyn crate::runtime::SectionJudge>>,
    /// The agent's judge of its settings as a whole, if it has one.
    pub settings_judge: Option<SettingsJudge>,
}

pub struct ConfigurationState {
    config: Config,
    verifier: Option<UpdateVerifier>,
    agent: String,
    current: Arc<Config>,
    last_version: u64,
    history: VecDeque<ConfigEvent>,
    changes: Arc<OutputPort<ConfigChanged>>,
    outcomes: Arc<OutputPort<ConfigurationOutcome>>,
    /// Outcomes announced so far.
    sequence: u64,
    runtime_sections: &'static [&'static RuntimeSection],
    runtime_changes: Arc<OutputPort<RuntimeChanged>>,
    /// The latest accepted body of each runtime section, by name. Versions are per section.
    runtime: HashMap<String, RuntimeValue>,
    policy: Option<ActorRef<PolicyMessage>>,
    judge: Option<Arc<dyn crate::runtime::SectionJudge>>,
    settings_judge: Option<SettingsJudge>,
    followers: Vec<Follower>,
}

/// The id and version a document says it has, read without trusting any of it: only to label an outcome.
fn claimed(document: &serde_json::Value) -> (Option<String>, Option<u64>) {
    let payload = &document["payload"];
    (
        payload["id"].as_str().map(str::to_string),
        payload["version"].as_u64(),
    )
}

/// What an outcome is called in an event, and the reasons that go with it. No value appears in either:
/// the reasons are names and problems, which never repeat a secret.
fn describe_outcome(outcome: &ApplyOutcome) -> (&'static str, Vec<String>, Vec<String>) {
    use polar_scheduler_common::outcome::{APPLIED, INVALID, STALE, UNCHANGED, UNVERIFIED};
    match outcome {
        ApplyOutcome::Applied { changed, notes } if changed.is_empty() => {
            (UNCHANGED, vec![], notes.clone())
        }
        ApplyOutcome::Applied { changed, notes } => (APPLIED, changed.clone(), notes.clone()),
        ApplyOutcome::Refused(Refusal::Stale { applied }) => (
            STALE,
            vec![],
            vec![format!("the version in force is {applied}")],
        ),
        ApplyOutcome::Refused(Refusal::Invalid(problems)) => (INVALID, vec![], problems.clone()),
        ApplyOutcome::Refused(Refusal::Unverified(rejection)) => {
            (UNVERIFIED, vec![], vec![rejection.to_string()])
        }
    }
}

fn describe_signer(signer: &polar_signing::SignerInfo) -> String {
    format!(
        "{} (serial {})",
        signer
            .username
            .as_deref()
            .or(signer.identity.as_deref())
            .unwrap_or("unknown"),
        signer.serial
    )
}

impl ConfigurationState {
    /// A signed document: verified first, applied only if it passes. A configuration document changes
    /// the agent's variables; a runtime document replaces a section of what it works on.
    ///
    /// Verification is in stages with the question of authority in the middle: the signature and the shape
    /// first, then whether this signer may make this change (the policy first and the certificate second, see
    /// [`crate::policy_authority`]), then whether their certificate has been revoked.
    async fn submit(&mut self, document: &serde_json::Value) -> ApplyOutcome {
        let Some(verifier) = &self.verifier else {
            return self.reject(claimed(document), Rejection::NotConfigured);
        };
        let opened = match verifier.open(document) {
            Ok(opened) => opened,
            Err(rejection) => return self.reject(claimed(document), rejection),
        };
        // A section that is made of policy answers to its own capability and to nothing else; policy is not
        // asked, because a rule that governed its own authorship could lock out every author.
        let capability_only = opened.runtime_section().and_then(|name| {
            self.runtime_sections
                .iter()
                .find(|section| section.name == name)
                .and_then(|section| match section.authority {
                    crate::runtime::SectionAuthority::Capability(capability) => Some(capability),
                    crate::runtime::SectionAuthority::Runtime => None,
                })
        });
        let admitted = match capability_only {
            Some(capability) => polar_signing::RequireCapability(capability)
                .authorize(opened.signer(), opened.payload()),
            None => {
                let request = opened.request_replacing(&self.agent, &self.config.overridden());
                // The certificate's answer is cheap and does not change while we ask policy; it is what
                // policy falls back to when it does not speak to the request.
                let floor = verifier.floor(&opened);
                crate::policy_authority::admit(self.policy.as_ref(), &request, || floor.clone())
                    .await
            }
        };
        if let Err(refusal) = admitted {
            return self.reject(claimed(document), Rejection::Unauthorized(refusal));
        }
        let Some(verifier) = &self.verifier else {
            return self.reject(claimed(document), Rejection::NotConfigured);
        };
        match verifier.close(opened) {
            Ok(VerifiedDocument::Configuration(verified)) => {
                let signer = describe_signer(&verified.signer);
                info!(id = %verified.id, version = verified.version, %signer, "signed configuration verified");
                self.apply(
                    Some(verified.id),
                    verified.version,
                    &verified.changes,
                    Some(signer),
                )
            }
            Ok(VerifiedDocument::Runtime(verified)) => {
                let signer = describe_signer(&verified.signer);
                info!(id = %verified.id, section = %verified.section, version = verified.version, %signer, "signed runtime document verified");
                self.apply_runtime(
                    verified.id,
                    verified.version,
                    &verified.section,
                    verified.body,
                    signer,
                )
                .await
            }
            Err(rejection) => self.reject(claimed(document), rejection),
        }
    }

    /// Replaces a runtime section, if the agent declares it, the version is higher than the section's
    /// last, the body fits, and the agent's judge, if it has one, accepts it. Otherwise nothing changes, and
    /// a refused document does not spend its version, so a corrected one can go under the same number.
    async fn apply_runtime(
        &mut self,
        id: String,
        version: u64,
        section: &str,
        body: serde_json::Value,
        signer: String,
    ) -> ApplyOutcome {
        let outcome = match self.runtime_sections.iter().find(|s| s.name == section) {
            None => ApplyOutcome::Refused(Refusal::Invalid(vec![format!(
                "{} declares no runtime section `{section}`",
                self.agent
            )])),
            Some(declared) => {
                let held = self.runtime.get(section).map(|v| v.version).unwrap_or(0);
                if version <= held {
                    ApplyOutcome::Refused(Refusal::Stale { applied: held })
                } else {
                    let judged = match ((declared.validate)(&body), &self.judge) {
                        (Err(problems), _) => Err(problems),
                        (Ok(()), None) => Ok(Vec::new()),
                        (Ok(()), Some(judge)) => {
                            let candidate = crate::runtime::Candidate {
                                section,
                                version,
                                signer: &signer,
                                body: &body,
                            };
                            judge.judge(&candidate, &self.runtime).await
                        }
                    };
                    match judged {
                        Err(problems) => ApplyOutcome::Refused(Refusal::Invalid(problems)),
                        Ok(notes) => {
                            self.runtime.insert(
                                section.to_string(),
                                RuntimeValue {
                                    version,
                                    id: id.clone(),
                                    body,
                                    signer: signer.clone(),
                                },
                            );
                            ApplyOutcome::Applied {
                                changed: vec![section.to_string()],
                                notes,
                            }
                        }
                    }
                }
            }
        };
        match &outcome {
            ApplyOutcome::Applied { .. } => {
                info!(section, version, "runtime section replaced");
                self.runtime_changes.send(RuntimeChanged {
                    section: section.to_string(),
                    version,
                });
            }
            ApplyOutcome::Refused(why) => {
                warn!(section, version, ?why, "runtime document refused");
            }
        }
        self.record(Some(id), Some(version), version, Some(signer), &outcome);
        outcome
    }

    fn reject(
        &mut self,
        (id, version): (Option<String>, Option<u64>),
        rejection: Rejection,
    ) -> ApplyOutcome {
        warn!(%rejection, "signed configuration refused");
        let outcome = ApplyOutcome::Refused(Refusal::Unverified(rejection));
        self.record(id, version, 0, None, &outcome);
        outcome
    }

    /// Judges a question about the configuration in force, and answers it if it is admitted: policy first, and where it
    /// is silent the certificate, as for a signed update. Taken in this actor's turn, so the answer is one configuration.
    async fn question(
        &self,
        document: &serde_json::Value,
        published_by: Option<&str>,
    ) -> Result<RunningConfiguration, Rejection> {
        let Some(verifier) = &self.verifier else {
            return Err(Rejection::NotConfigured);
        };
        let opened = crate::running::open(verifier, document, published_by)?;
        let floor = verifier.settings_floor(opened.signer(), opened.payload());
        crate::policy_authority::admit(self.policy.as_ref(), &opened.request(&self.agent), || {
            floor.clone()
        })
        .await
        .map_err(Rejection::Unauthorized)?;
        let id = crate::running::close(verifier, opened)?;
        Ok(crate::running::answer(
            id,
            &self.agent,
            &self.config,
            self.last_version,
            &self.runtime,
        ))
    }

    /// Keeps the outcome in the history and announces it. `version` is what the history keeps; the
    /// event carries `claimed_version`, which is only meaningful for a verified document.
    fn record(
        &mut self,
        id: Option<String>,
        claimed_version: Option<u64>,
        version: u64,
        signer: Option<String>,
        outcome: &ApplyOutcome,
    ) {
        if self.history.len() == HISTORY {
            self.history.pop_front();
        }
        self.history.push_back(ConfigEvent {
            version,
            outcome: outcome.clone(),
            signer: signer.clone(),
        });

        let (status, changed, detail) = describe_outcome(outcome);
        self.sequence += 1;
        self.outcomes.send(ConfigurationOutcome {
            agent: self.agent.clone(),
            id,
            version: claimed_version,
            status: status.to_string(),
            changed,
            detail,
            signer,
            at_unix_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            sequence: self.sequence,
        });
    }

    /// Why the agent's judge refuses this candidate, if it does.
    fn judged(&self, candidate: &Config, changed: &[&'static str]) -> Option<String> {
        if changed.is_empty() {
            return None;
        }
        let judge = self.settings_judge?;
        breaks_what_works(judge(&self.config), judge(candidate))
    }

    /// What to say of the variables that changed and that nothing follows now. Names only.
    fn nothing_follows(&mut self, changed: &[&'static str]) -> Vec<String> {
        self.followers.retain(Follower::alive);
        changed
            .iter()
            .filter(|name| !self.followers.iter().any(|f| f.names.contains(*name)))
            .map(|name| nothing_follows(name))
            .collect()
    }

    fn apply(
        &mut self,
        id: Option<String>,
        version: u64,
        changes: &[(String, String)],
        signer: Option<String>,
    ) -> ApplyOutcome {
        let outcome = if version <= self.last_version {
            ApplyOutcome::Refused(Refusal::Stale {
                applied: self.last_version,
            })
        } else {
            let pairs: Vec<(&str, &str)> = changes
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            let mut candidate = self.config.clone();
            match candidate.replace_overrides(&pairs) {
                Ok(changed) => match self.judged(&candidate, &changed) {
                    Some(why) => ApplyOutcome::Refused(Refusal::Invalid(vec![why])),
                    None => {
                        self.config = candidate;
                        self.last_version = version;
                        let notes = self.nothing_follows(&changed);
                        ApplyOutcome::Applied {
                            changed: changed.into_iter().map(str::to_string).collect(),
                            notes,
                        }
                    }
                },
                Err(problems) => ApplyOutcome::Refused(Refusal::Invalid(problems)),
            }
        };

        match &outcome {
            ApplyOutcome::Applied { changed, .. } => {
                info!(version, ?changed, "configuration update applied");
                if !changed.is_empty() {
                    self.current = Arc::new(self.config.clone());
                    self.changes.send(ConfigChanged {
                        version,
                        changed: changed.clone(),
                    });
                    for follower in &self.followers {
                        if let Some(configs) = &follower.configs {
                            let _ = configs.send(self.current.clone());
                        }
                    }
                }
            }
            ApplyOutcome::Refused(why) => {
                warn!(version, ?why, "configuration update refused");
            }
        }
        self.record(id, Some(version), version, signer, &outcome);
        outcome
    }
}

#[ractor::async_trait]
impl Actor for ConfigurationActor {
    type Msg = ConfigurationMessage;
    type State = ConfigurationState;
    type Arguments = ConfigurationArgs;

    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        args: ConfigurationArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(ConfigurationState {
            current: Arc::new(args.config.clone()),
            config: args.config,
            verifier: args.verifier,
            agent: args.agent,
            last_version: 0,
            history: VecDeque::new(),
            changes: args.changes,
            outcomes: args.outcomes,
            sequence: 0,
            runtime_sections: args.runtime_sections,
            runtime_changes: args.runtime_changes,
            runtime: HashMap::new(),
            policy: args.policy,
            judge: args.judge,
            settings_judge: args.settings_judge,
            followers: Vec::new(),
        })
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            ConfigurationMessage::Apply {
                version,
                changes,
                reply,
            } => {
                let outcome = state.apply(None, version, &changes, None);
                let _ = reply.send(outcome);
            }
            ConfigurationMessage::Deliver(document) => {
                state.submit(&document).await;
            }
            ConfigurationMessage::Submit { document, reply } => {
                let outcome = state.submit(&document).await;
                let _ = reply.send(outcome);
            }
            ConfigurationMessage::Current(reply) => {
                let _ = reply.send(state.current.clone());
            }
            ConfigurationMessage::History(reply) => {
                let _ = reply.send(state.history.iter().cloned().collect());
            }
            ConfigurationMessage::Runtime { section, reply } => {
                let _ = reply.send(state.runtime.get(&section).cloned());
            }
            ConfigurationMessage::Follow { follower, reply } => {
                state.followers.retain(Follower::alive);
                state.followers.push(follower);
                let _ = reply.send(state.current.clone());
            }
            ConfigurationMessage::Followers(reply) => {
                let _ = reply.send((state.current.clone(), state.followers.clone()));
            }
            ConfigurationMessage::Question {
                document,
                published_by,
                reply,
            } => {
                let _ = reply.send(state.question(&document, published_by.as_deref()).await);
            }
        }
        Ok(())
    }
}

/// How the rest of an agent uses the ConfigurationActor, without touching ractor.
#[derive(Clone)]
pub struct ConfigurationHandle {
    actor: ActorRef<ConfigurationMessage>,
    changes: Arc<OutputPort<ConfigChanged>>,
    outcomes: Arc<OutputPort<ConfigurationOutcome>>,
    runtime_changes: Arc<OutputPort<RuntimeChanged>>,
}

impl ConfigurationHandle {
    /// Starts the actor on `config`, as a child of `supervisor`, for an agent with no runtime sections.
    pub async fn spawn(
        name: Option<String>,
        agent: impl Into<String>,
        config: Config,
        verifier: Option<UpdateVerifier>,
        supervisor: ractor::ActorCell,
    ) -> Result<Self, ActorProcessingErr> {
        Self::spawn_with_runtime(name, agent, config, verifier, &[], supervisor).await
    }

    /// Starts the actor on `config`, as a child of `supervisor`, accepting runtime documents for the
    /// sections the agent declares.
    pub async fn spawn_with_runtime(
        name: Option<String>,
        agent: impl Into<String>,
        config: Config,
        verifier: Option<UpdateVerifier>,
        runtime_sections: &'static [&'static RuntimeSection],
        supervisor: ractor::ActorCell,
    ) -> Result<Self, ActorProcessingErr> {
        Self::spawn_full(
            name,
            agent,
            config,
            verifier,
            runtime_sections,
            None,
            None,
            None,
            supervisor,
        )
        .await
    }

    /// Starts the actor with everything: runtime sections, the policy actor to ask before the signer's
    /// certificate whether a change is allowed, the agent's judge of a runtime section and its judge of its settings.
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn_full(
        name: Option<String>,
        agent: impl Into<String>,
        config: Config,
        verifier: Option<UpdateVerifier>,
        runtime_sections: &'static [&'static RuntimeSection],
        policy: Option<ActorRef<PolicyMessage>>,
        judge: Option<Arc<dyn crate::runtime::SectionJudge>>,
        settings_judge: Option<SettingsJudge>,
        supervisor: ractor::ActorCell,
    ) -> Result<Self, ActorProcessingErr> {
        let changes = Arc::new(OutputPort::default());
        let outcomes = Arc::new(OutputPort::default());
        let runtime_changes = Arc::new(OutputPort::default());
        let (actor, _) = Actor::spawn_linked(
            name,
            ConfigurationActor,
            ConfigurationArgs {
                config,
                verifier,
                agent: agent.into(),
                changes: changes.clone(),
                outcomes: outcomes.clone(),
                runtime_sections,
                runtime_changes: runtime_changes.clone(),
                policy,
                judge,
                settings_judge,
            },
            supervisor,
        )
        .await
        .map_err(ActorProcessingErr::from)?;
        Ok(Self {
            actor,
            changes,
            outcomes,
            runtime_changes,
        })
    }

    /// The latest accepted body of a runtime section and its version; none until one has arrived.
    pub async fn runtime(&self, section: &str) -> Result<Option<RuntimeValue>, ConfigurationError> {
        let section = section.to_string();
        self.call(|reply| ConfigurationMessage::Runtime { section, reply })
            .await
    }

    /// Where a replaced runtime section is announced. Subscribe with a mapping into your own message type,
    /// then read [`runtime`](Self::runtime).
    pub fn runtime_changes(&self) -> Arc<OutputPort<RuntimeChanged>> {
        self.runtime_changes.clone()
    }

    /// Puts a signed question to the actor: the configuration in force, or why it was refused.
    pub async fn question(
        &self,
        document: serde_json::Value,
        published_by: Option<String>,
    ) -> Result<Result<RunningConfiguration, Rejection>, ConfigurationError> {
        self.call_within(
            |reply| ConfigurationMessage::Question {
                document,
                published_by,
                reply,
            },
            None,
        )
        .await
    }

    /// The configuration as it stands now, with every override applied. Read again after a
    /// [`ConfigChanged`].
    pub async fn current(&self) -> Result<Arc<Config>, ConfigurationError> {
        self.call(ConfigurationMessage::Current).await
    }

    /// What every declared variable resolves to now and where it came from (values of secrets
    /// are hidden).
    pub async fn report(&self) -> Result<Vec<Resolved>, ConfigurationError> {
        Ok(self.current().await?.report())
    }

    /// Takes a signed document from outside: verifies it (see [`crate::signed`]), and applies it only
    /// if every check passes. This is the way an update gets in.
    ///
    /// The answer is the document's outcome, and it waits for the agent's judge however long the judgement
    /// takes (the credentials agent's authority model takes seconds on a loaded machine), so it has no
    /// [`CALL_TIMEOUT`]: it fails only if the actor stops before it answers.
    pub async fn submit(
        &self,
        document: serde_json::Value,
    ) -> Result<ApplyOutcome, ConfigurationError> {
        self.call_within(
            |reply| ConfigurationMessage::Submit { document, reply },
            None,
        )
        .await
    }

    /// Hands over a signed document without waiting for the outcome, in order with the others. The
    /// outcome is recorded in the history and the log.
    pub fn deliver(&self, document: serde_json::Value) {
        if let Err(e) = self.actor.cast(ConfigurationMessage::Deliver(document)) {
            warn!("the configuration actor did not take a delivered document: {e}");
        }
    }

    /// Applies an update without checking who sent it. Only for tests, this crate's and, with the `testing` feature, an
    /// agent's: nothing else may change the configuration without a verified signature.
    #[cfg(any(test, feature = "testing"))]
    pub async fn apply_unchecked(
        &self,
        version: u64,
        changes: Vec<(String, String)>,
    ) -> Result<ApplyOutcome, ConfigurationError> {
        self.call(|reply| ConfigurationMessage::Apply {
            version,
            changes,
            reply,
        })
        .await
    }

    /// The latest updates, applied and refused, oldest first.
    pub async fn history(&self) -> Result<Vec<ConfigEvent>, ConfigurationError> {
        self.call(ConfigurationMessage::History).await
    }

    /// Where each outcome is announced: every document handled, applied or refused, with the reason.
    /// The infrastructure puts these on Cassini for the scheduler to record.
    pub fn outcomes(&self) -> Arc<OutputPort<ConfigurationOutcome>> {
        self.outcomes.clone()
    }

    /// Where changes are announced. Subscribe with a mapping into your own message type, as
    /// for the other ports; then read [`current`](Self::current).
    pub fn changes(&self) -> Arc<OutputPort<ConfigChanged>> {
        self.changes.clone()
    }

    /// `actor` follows the variable: the value in force is the answer, and each value after it that differs arrives as
    /// `message(value)`. The mapping only makes the message; what a new value means is the actor's to decide in its
    /// own `handle`. Called from its `pre_start`, an actor started again later has the value signed since and not what
    /// the render gave it.
    pub async fn follow<V, M>(
        &self,
        variable: &'static V,
        actor: &ActorRef<M>,
        message: impl Fn(V::Out) -> M + Send + Sync + 'static,
    ) -> Result<V::Out, FollowError>
    where
        V: Readable + Send + Sync + 'static,
        V::Out: PartialEq + Clone + Send + Sync + 'static,
        M: ractor::Message,
    {
        self.follow_group(
            &[variable as &dyn Described],
            move |config: &Config| config.read(variable).map_err(|e| e.to_string()),
            actor,
            message,
        )
        .await
    }

    /// As [`follow`](Self::follow), for variables that mean something only together: `read` makes one value of them, and
    /// an update that changes several is one message, so that no one sees a new address with the old way of reaching
    /// it. `read` is pure, and `names` says what it reads.
    pub async fn follow_group<T, M>(
        &self,
        names: &[&dyn Described],
        read: impl Fn(&Config) -> Result<T, String> + Send + Sync + 'static,
        actor: &ActorRef<M>,
        message: impl Fn(T) -> M + Send + Sync + 'static,
    ) -> Result<T, FollowError>
    where
        T: PartialEq + Clone + Send + Sync + 'static,
        M: ractor::Message,
    {
        let read = Arc::new(read);
        let (configs, mut incoming) = tokio::sync::mpsc::unbounded_channel::<Arc<Config>>();
        let depends: Depends = {
            let read = read.clone();
            Arc::new(move |before, after| Ok(read(before)? != read(after)?))
        };
        let follower = Follower {
            names: names.iter().map(|variable| variable.desc().name).collect(),
            actor: actor.get_cell(),
            configs: Some(configs),
            depends: Some(depends),
        };
        // Not bounded by CALL_TIMEOUT: the actor may be judging a document, and a follower can wait for it.
        let in_force = self
            .call_within(
                |reply| ConfigurationMessage::Follow { follower, reply },
                None,
            )
            .await
            .map_err(FollowError::Unavailable)?;
        let first = read(&in_force);

        let mut last = first.as_ref().ok().cloned();
        let actor = actor.clone();
        tokio::spawn(async move {
            while let Some(config) = incoming.recv().await {
                match read(&config) {
                    Ok(value) if last.as_ref() != Some(&value) => {
                        last = Some(value.clone());
                        if actor.cast(message(value)).is_err() {
                            return;
                        }
                    }
                    Ok(_) => {}
                    Err(why) => {
                        warn!("a followed setting does not read, and the last value stands: {why}")
                    }
                }
            }
        });
        first.map_err(FollowError::Unreadable)
    }

    /// `actor` reacts to these variables by its own means, not through [`follow`](Self::follow): a held supervisor,
    /// which on any change asks the agent to try again.
    pub(crate) async fn followed_by(
        &self,
        names: Vec<&'static str>,
        actor: ractor::ActorCell,
    ) -> Result<(), ConfigurationError> {
        let follower = Follower {
            names,
            actor,
            configs: None,
            depends: None,
        };
        self.call_within(
            |reply| ConfigurationMessage::Follow { follower, reply },
            None,
        )
        .await
        .map(|_| ())
    }

    /// For an agent's tests, once its actors have registered: every Dynamic variable of `sections` that nothing
    /// follows, that its follower's value does not depend on, or that a test cannot change. Read-only: it changes copies.
    pub async fn dynamic_settings_problems(
        &self,
        sections: &[&Section],
    ) -> Result<Vec<String>, ConfigurationError> {
        let (current, followers) = self.call(ConfigurationMessage::Followers).await?;
        let report = current.report();
        let mut problems = Vec::new();
        for desc in sections
            .iter()
            .flat_map(|section| section.vars.iter())
            .map(|variable| variable.desc())
        {
            let name = desc.name;
            let following: Vec<&Follower> = followers
                .iter()
                .filter(|follower| follower.alive() && follower.names.contains(&name))
                .collect();
            if desc.mutability != Mutability::Dynamic {
                if !following.is_empty() {
                    problems.push(format!(
                        "{name} is followed, but it is static: no update can reach it"
                    ));
                }
                continue;
            }
            if following.is_empty() {
                problems.push(format!("{name} is Dynamic, and nothing follows it"));
                continue;
            }
            let now = report
                .iter()
                .find(|resolved| resolved.name == name)
                .and_then(|resolved| resolved.value.as_deref());
            let Some(other) = desc.another_value(now) else {
                problems.push(format!(
                    "{name} cannot be changed by a test: give its declaration an .example()"
                ));
                continue;
            };
            let mut changed = (*current).clone();
            if let Err(why) = changed.apply_overrides(&[(name, other.as_str())]) {
                problems.push(format!(
                    "{name} cannot be changed by a test: {}",
                    why.join("; ")
                ));
                continue;
            }
            for follower in following {
                let Some(depends) = &follower.depends else {
                    continue;
                };
                match depends(&current, &changed) {
                    Ok(true) => {}
                    Ok(false) => problems.push(format!(
                        "{name} is followed, and what its follower is told does not depend on it"
                    )),
                    Err(why) => problems.push(format!(
                        "{name} changed makes settings that do not read: {why}"
                    )),
                }
            }
        }
        Ok(problems)
    }

    async fn call<T: Send + 'static>(
        &self,
        build: impl FnOnce(RpcReplyPort<T>) -> ConfigurationMessage,
    ) -> Result<T, ConfigurationError> {
        self.call_within(build, Some(CALL_TIMEOUT)).await
    }

    async fn call_within<T: Send + 'static>(
        &self,
        build: impl FnOnce(RpcReplyPort<T>) -> ConfigurationMessage,
        timeout: Option<Duration>,
    ) -> Result<T, ConfigurationError> {
        match self.actor.call(build, timeout).await {
            Ok(ractor::rpc::CallResult::Success(value)) => Ok(value),
            Ok(ractor::rpc::CallResult::Timeout) => {
                Err(ConfigurationError::Unavailable("timed out".to_string()))
            }
            Ok(ractor::rpc::CallResult::SenderError) => Err(ConfigurationError::Unavailable(
                "the actor stopped before it answered".to_string(),
            )),
            Err(e) => Err(ConfigurationError::Unavailable(e.to_string())),
        }
    }
}

/// The built-in subscription every agent has to its own configuration topic: the scheduler processor
/// publishes a signed document for `agent` there, and it goes to the verifying actor. A message that is not
/// a configuration notification, or is for another agent, is dropped; one that is for this agent is verified
/// by the actor like any other, whoever published it.
pub fn subscription(agent: &str, configuration: ConfigurationHandle) -> crate::Subscription {
    let agent = agent.to_string();
    crate::Subscription::new(
        polar_scheduler_common::configuration_topic(&agent),
        move |incoming| {
            let notification = match rkyv::from_bytes::<
                polar_scheduler_common::ConfigurationNotification,
                rkyv::rancor::Error,
            >(&incoming.payload)
            {
                Ok(notification) => notification,
                Err(e) => {
                    warn!("a message on the configuration topic is not a notification: {e}");
                    return;
                }
            };
            if notification.agent != agent {
                warn!(
                    "a configuration notification for `{}` reached `{agent}`; dropped",
                    notification.agent
                );
                return;
            }
            match serde_json::from_str::<serde_json::Value>(&notification.document_json) {
                Ok(document) => configuration.deliver(document),
                Err(e) => warn!("a delivered configuration document is not JSON: {e}"),
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_env::{Defaulted, Described, Optional, Required, Section};
    use std::collections::HashMap;
    use std::sync::Mutex;

    static HOST: Required<String> = Required::text("HOST", "the host to talk to");
    static LOW: Defaulted<u64> = Defaulted::number("LOW", "lower bound", "1").dynamic();
    static HIGH: Defaulted<u64> = Defaulted::number("HIGH", "upper bound", "10").dynamic();
    static TOKEN: Optional<String> = Optional::text("TOKEN", "an api token").secret().dynamic();
    static VARS: &[&dyn Described] = &[&HOST, &LOW, &HIGH, &TOKEN];

    fn bounds_in_order(env: &dyn polar_env::Env) -> Vec<String> {
        let (low, high) = (LOW.read(env).unwrap(), HIGH.read(env).unwrap());
        if low >= high {
            vec![format!("LOW ({low}) must be below HIGH ({high})")]
        } else {
            vec![]
        }
    }

    static SECTION: Section = Section {
        name: "example",
        vars: VARS,
        relations: bounds_in_order,
    };

    fn config() -> Config {
        let env: HashMap<String, String> = [("HOST".to_string(), "h".to_string())].into();
        Config::builder(&env).register(&SECTION).build()
    }

    async fn handle() -> (ConfigurationHandle, Arc<Mutex<Vec<ConfigChanged>>>) {
        spawn_handle(None).await
    }

    async fn spawn_handle(
        verifier: Option<UpdateVerifier>,
    ) -> (ConfigurationHandle, Arc<Mutex<Vec<ConfigChanged>>>) {
        // A parent for the actor to be linked to.
        struct Parent;
        #[ractor::async_trait]
        impl Actor for Parent {
            type Msg = ();
            type State = ();
            type Arguments = ();
            async fn pre_start(&self, _: ActorRef<()>, _: ()) -> Result<(), ActorProcessingErr> {
                Ok(())
            }
        }
        let (parent, _) = Actor::spawn(None, Parent, ()).await.unwrap();
        let handle = ConfigurationHandle::spawn(None, AGENT, config(), verifier, parent.get_cell())
            .await
            .unwrap();

        // A subscriber, as a domain actor would be: it receives a message per change.
        struct Sink(Arc<Mutex<Vec<ConfigChanged>>>);
        #[ractor::async_trait]
        impl Actor for Sink {
            type Msg = ConfigChanged;
            type State = ();
            type Arguments = ();
            async fn pre_start(
                &self,
                _: ActorRef<Self::Msg>,
                _: (),
            ) -> Result<(), ActorProcessingErr> {
                Ok(())
            }
            async fn handle(
                &self,
                _: ActorRef<Self::Msg>,
                message: Self::Msg,
                _: &mut (),
            ) -> Result<(), ActorProcessingErr> {
                self.0.lock().unwrap().push(message);
                Ok(())
            }
        }
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (sink, _) = Actor::spawn(None, Sink(seen.clone()), ()).await.unwrap();
        handle.changes().subscribe(sink, Some);
        (handle, seen)
    }

    fn change(name: &str, value: &str) -> Vec<(String, String)> {
        vec![(name.to_string(), value.to_string())]
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn a_dynamic_variable_changes_and_subscribers_are_told_once() {
        let (config, seen) = handle().await;
        assert_eq!(config.current().await.unwrap().read(&HIGH).unwrap(), 10);

        let outcome = config
            .apply_unchecked(1, change("HIGH", "20"))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            ApplyOutcome::Applied {
                changed: vec!["HIGH".to_string()],
                notes: vec![nothing_follows("HIGH")],
            }
        );
        assert_eq!(config.current().await.unwrap().read(&HIGH).unwrap(), 20);

        settle().await;
        assert_eq!(
            *seen.lock().unwrap(),
            [ConfigChanged {
                version: 1,
                changed: vec!["HIGH".to_string()]
            }]
        );

        // The report says where the value came from.
        let report = config.report().await.unwrap();
        let high = report.iter().find(|r| r.name == "HIGH").unwrap();
        assert_eq!(high.source, polar_env::Source::Override);
    }

    #[tokio::test]
    async fn a_static_or_unknown_variable_is_refused_by_name_and_nothing_changes() {
        let (config, seen) = handle().await;
        let outcome = config
            .apply_unchecked(1, change("HOST", "elsewhere"))
            .await
            .unwrap();
        let ApplyOutcome::Refused(Refusal::Invalid(problems)) = outcome else {
            panic!("expected a refusal");
        };
        assert!(problems[0].contains("HOST"), "{problems:?}");
        let outcome = config
            .apply_unchecked(1, change("NOPE", "1"))
            .await
            .unwrap();
        let ApplyOutcome::Refused(Refusal::Invalid(problems)) = outcome else {
            panic!("expected a refusal");
        };
        assert!(problems[0].contains("NOPE"), "{problems:?}");

        assert_eq!(config.current().await.unwrap().read(&HOST).unwrap(), "h");
        settle().await;
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_update_the_startup_check_would_refuse_is_refused_whole() {
        let (config, _) = handle().await;
        // LOW would be above HIGH, and the first change alone would be fine.
        let outcome = config
            .apply_unchecked(
                1,
                vec![
                    ("HIGH".to_string(), "50".to_string()),
                    ("LOW".to_string(), "60".to_string()),
                ],
            )
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            ApplyOutcome::Refused(Refusal::Invalid(_))
        ));
        let current = config.current().await.unwrap();
        assert_eq!(
            (current.read(&LOW).unwrap(), current.read(&HIGH).unwrap()),
            (1, 10)
        );
    }

    #[tokio::test]
    async fn an_old_or_repeated_version_cannot_be_replayed_over_a_newer_one() {
        let (config, _) = handle().await;
        config
            .apply_unchecked(5, change("HIGH", "20"))
            .await
            .unwrap();
        config
            .apply_unchecked(6, change("HIGH", "30"))
            .await
            .unwrap();

        for stale in [6, 5, 1] {
            let outcome = config
                .apply_unchecked(stale, change("HIGH", "99"))
                .await
                .unwrap();
            assert_eq!(
                outcome,
                ApplyOutcome::Refused(Refusal::Stale { applied: 6 }),
                "version {stale}"
            );
        }
        assert_eq!(config.current().await.unwrap().read(&HIGH).unwrap(), 30);
        // Version zero is never valid: nothing has been applied at zero.
        assert!(matches!(
            config
                .apply_unchecked(0, change("HIGH", "40"))
                .await
                .unwrap(),
            ApplyOutcome::Refused(Refusal::Stale { .. })
        ));
    }

    #[tokio::test]
    async fn an_applied_update_replaces_the_updates_before_it() {
        let (config, seen) = handle().await;
        config
            .apply_unchecked(1, vec![("LOW".to_string(), "5".to_string())])
            .await
            .unwrap();
        let outcome = config
            .apply_unchecked(2, vec![("HIGH".to_string(), "20".to_string())])
            .await
            .unwrap();
        // LOW was not named, so it is back to what it was, and that is a change like any other.
        assert_eq!(
            outcome,
            ApplyOutcome::Applied {
                changed: vec!["LOW".to_string(), "HIGH".to_string()],
                notes: vec![nothing_follows("LOW"), nothing_follows("HIGH")],
            }
        );
        let now = config.current().await.unwrap();
        assert_eq!(now.read(&LOW).unwrap(), 1);
        assert_eq!(now.read(&HIGH).unwrap(), 20);
        assert_eq!(now.overridden(), ["HIGH"]);
        settle().await;
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_refused_update_leaves_the_overrides_before_it_in_force() {
        let (config, _) = handle().await;
        config
            .apply_unchecked(1, vec![("LOW".to_string(), "5".to_string())])
            .await
            .unwrap();
        let outcome = config
            .apply_unchecked(2, vec![("HIGH".to_string(), "1".to_string())])
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            ApplyOutcome::Refused(Refusal::Invalid(_))
        ));
        assert_eq!(config.current().await.unwrap().read(&LOW).unwrap(), 5);
    }

    #[tokio::test]
    async fn a_refused_update_does_not_use_up_its_version() {
        let (config, _) = handle().await;
        let bad = config
            .apply_unchecked(1, change("HIGH", "not a number"))
            .await
            .unwrap();
        assert!(matches!(bad, ApplyOutcome::Refused(Refusal::Invalid(_))));
        // The corrected update can be sent again under the same number.
        let good = config
            .apply_unchecked(1, change("HIGH", "12"))
            .await
            .unwrap();
        assert!(matches!(good, ApplyOutcome::Applied { .. }));
    }

    #[tokio::test]
    async fn a_blank_value_returns_the_variable_to_what_it_was() {
        let (config, seen) = handle().await;
        config
            .apply_unchecked(1, change("HIGH", "20"))
            .await
            .unwrap();
        config.apply_unchecked(2, change("HIGH", "")).await.unwrap();
        assert_eq!(config.current().await.unwrap().read(&HIGH).unwrap(), 10);
        settle().await;
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn an_update_that_changes_nothing_advances_the_version_but_tells_no_one() {
        let (config, seen) = handle().await;
        let outcome = config
            .apply_unchecked(1, change("HIGH", "10"))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            ApplyOutcome::Applied {
                changed: vec![],
                notes: Vec::new()
            }
        );
        settle().await;
        assert!(seen.lock().unwrap().is_empty());
        assert!(matches!(
            config
                .apply_unchecked(1, change("HIGH", "11"))
                .await
                .unwrap(),
            ApplyOutcome::Refused(Refusal::Stale { applied: 1 })
        ));
    }

    #[tokio::test]
    async fn the_history_records_every_update_and_never_a_secret() {
        let (config, _) = handle().await;
        config
            .apply_unchecked(1, change("TOKEN", "hunter2-the-secret-value"))
            .await
            .unwrap();
        config
            .apply_unchecked(1, change("HIGH", "20"))
            .await
            .unwrap(); // stale
        config
            .apply_unchecked(2, change("LOW", "99"))
            .await
            .unwrap(); // invalid: LOW above HIGH

        let history = config.history().await.unwrap();
        assert_eq!(history.len(), 3);
        assert!(matches!(history[0].outcome, ApplyOutcome::Applied { .. }));
        assert!(matches!(
            history[1].outcome,
            ApplyOutcome::Refused(Refusal::Stale { .. })
        ));
        assert!(matches!(
            history[2].outcome,
            ApplyOutcome::Refused(Refusal::Invalid(_))
        ));
        let everything = format!("{history:?}{:?}", config.report().await.unwrap());
        assert!(!everything.contains("hunter2"), "{everything}");

        // And the secret is still in force.
        assert_eq!(
            config
                .current()
                .await
                .unwrap()
                .read(&TOKEN)
                .unwrap()
                .as_deref(),
            Some("hunter2-the-secret-value")
        );
    }

    #[tokio::test]
    async fn the_history_keeps_only_the_latest() {
        let (config, _) = handle().await;
        for version in 1..=(HISTORY as u64 + 20) {
            config
                .apply_unchecked(version, change("HIGH", &(10 + version).to_string()))
                .await
                .unwrap();
        }
        let history = config.history().await.unwrap();
        assert_eq!(history.len(), HISTORY);
        assert_eq!(history.first().unwrap().version, 21);
        assert_eq!(history.last().unwrap().version, HISTORY as u64 + 20);
    }

    // -- signed documents -------------------------------------------------------------------

    use polar_signing::Trust;
    use polar_signing::testing::{self as certs, ALICE_ACCOUNT_ID, Spec, now, root, signer};
    use serde_json::{Value, json};

    const AGENT: &str = "hello-agent";

    struct Signed {
        ca: certs::Authority,
    }

    impl Signed {
        fn new() -> Self {
            Self {
                ca: root("Polar Internal CA"),
            }
        }

        fn verifier(&self) -> UpdateVerifier {
            UpdateVerifier::new(
                Trust::from_pem(std::slice::from_ref(&self.ca.pem)).unwrap(),
                AGENT,
            )
            .with_clock(now)
        }

        fn update(&self, spec: Spec, version: u64, agent: &str, changes: Value) -> Value {
            let s = signer(&self.ca, spec);
            polar_signing::sign(
                json!({"type": "configuration", "id": "u", "target": {"agent": agent}, "version": version, "changes": changes}),
                &[s.cert_pem],
                &s.key_pem,
            )
            .unwrap()
            .to_value()
        }

        fn high(&self, version: u64, value: &str) -> Value {
            self.update(
                Spec::default(),
                version,
                AGENT,
                json!([{"name": "HIGH", "value": value}]),
            )
        }
    }

    async fn high(config: &ConfigurationHandle) -> u64 {
        config.current().await.unwrap().read(&HIGH).unwrap()
    }

    #[tokio::test]
    async fn a_signed_update_is_applied_and_the_history_says_who_signed_it() {
        let signed = Signed::new();
        let (config, seen) = spawn_handle(Some(signed.verifier())).await;
        let outcome = config.submit(signed.high(1, "20")).await.unwrap();
        assert_eq!(
            outcome,
            ApplyOutcome::Applied {
                changed: vec!["HIGH".to_string()],
                notes: vec![nothing_follows("HIGH")],
            }
        );
        assert_eq!(high(&config).await, 20);
        settle().await;
        assert_eq!(seen.lock().unwrap().len(), 1);

        let history = config.history().await.unwrap();
        assert_eq!(history[0].version, 1);
        let who = history[0].signer.as_deref().unwrap();
        assert!(who.contains("alice") && who.contains("serial"), "{who}");
    }

    #[tokio::test]
    async fn an_unsigned_update_is_refused_and_the_value_stays() {
        let signed = Signed::new();
        let (config, seen) = spawn_handle(Some(signed.verifier())).await;
        // What an unsigned update would look like: the payload, bare.
        let bare = json!({"type": "configuration", "id": "u", "target": {"agent": AGENT}, "version": 1,
                          "changes": [{"name": "HIGH", "value": "20"}]});
        let outcome = config.submit(bare).await.unwrap();
        assert!(matches!(
            outcome,
            ApplyOutcome::Refused(Refusal::Unverified(Rejection::Layout(_)))
        ));
        assert_eq!(high(&config).await, 10);
        settle().await;
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_wrongly_signed_update_is_refused_and_the_value_stays() {
        let signed = Signed::new();
        let (config, _) = spawn_handle(Some(signed.verifier())).await;

        // Altered after signing.
        let mut tampered = signed.high(1, "20");
        tampered["payload"]["changes"][0]["value"] = json!("50");
        assert!(matches!(
            config.submit(tampered).await.unwrap(),
            ApplyOutcome::Refused(Refusal::Unverified(Rejection::Signature(_)))
        ));

        // Signed by a CA this agent does not trust.
        let rogue = Signed::new();
        assert!(matches!(
            config.submit(rogue.high(1, "20")).await.unwrap(),
            ApplyOutcome::Refused(Refusal::Unverified(Rejection::Signature(_)))
        ));
        assert_eq!(high(&config).await, 10);
    }

    #[tokio::test]
    async fn an_update_from_a_signer_who_may_not_is_refused_and_the_value_stays() {
        let signed = Signed::new();
        let (config, _) = spawn_handle(Some(signed.verifier())).await;
        let doc = signed.update(
            Spec {
                capabilities: vec!["c:grant"],
                ..Spec::default()
            },
            1,
            AGENT,
            json!([{"name": "HIGH", "value": "20"}]),
        );
        assert!(matches!(
            config.submit(doc).await.unwrap(),
            ApplyOutcome::Refused(Refusal::Unverified(Rejection::Unauthorized(_)))
        ));
        assert_eq!(high(&config).await, 10);
    }

    #[tokio::test]
    async fn a_valid_old_or_repeated_document_cannot_be_replayed() {
        let signed = Signed::new();
        let (config, _) = spawn_handle(Some(signed.verifier())).await;
        let five = signed.high(5, "20");
        config.submit(five.clone()).await.unwrap();
        config.submit(signed.high(6, "30")).await.unwrap();
        assert_eq!(high(&config).await, 30);

        // The very same signed document again, and an older one: both verify, and both are stale.
        for replay in [five, signed.high(3, "99")] {
            assert_eq!(
                config.submit(replay).await.unwrap(),
                ApplyOutcome::Refused(Refusal::Stale { applied: 6 })
            );
        }
        assert_eq!(high(&config).await, 30);
    }

    #[tokio::test]
    async fn a_document_signed_for_another_agent_is_refused() {
        let signed = Signed::new();
        let (config, _) = spawn_handle(Some(signed.verifier())).await;
        let doc = signed.update(
            Spec::default(),
            1,
            "another-agent",
            json!([{"name": "HIGH", "value": "20"}]),
        );
        assert!(matches!(
            config.submit(doc).await.unwrap(),
            ApplyOutcome::Refused(Refusal::Unverified(Rejection::WrongTarget { .. }))
        ));
        assert_eq!(high(&config).await, 10);
    }

    #[tokio::test]
    async fn an_agent_with_no_ca_to_verify_against_refuses_everything() {
        let signed = Signed::new();
        let (config, _) = spawn_handle(None).await;
        assert_eq!(
            config.submit(signed.high(1, "20")).await.unwrap(),
            ApplyOutcome::Refused(Refusal::Unverified(Rejection::NotConfigured))
        );
        assert_eq!(high(&config).await, 10);
    }

    #[tokio::test]
    async fn a_signature_does_not_let_a_signer_change_what_the_agent_does_not_allow() {
        let signed = Signed::new();
        let (config, _) = spawn_handle(Some(signed.verifier())).await;
        // HOST is Static, LOW above HIGH breaks a relation: a valid signature is not a way round either.
        let doc = signed.update(
            Spec::default(),
            1,
            AGENT,
            json!([{"name": "HOST", "value": "elsewhere"}]),
        );
        assert!(matches!(
            config.submit(doc).await.unwrap(),
            ApplyOutcome::Refused(Refusal::Invalid(_))
        ));
        let doc = signed.update(
            Spec::default(),
            2,
            AGENT,
            json!([{"name": "LOW", "value": "99"}]),
        );
        assert!(matches!(
            config.submit(doc).await.unwrap(),
            ApplyOutcome::Refused(Refusal::Invalid(_))
        ));
        assert_eq!(config.current().await.unwrap().read(&HOST).unwrap(), "h");
        // Refused for its contents, but it was verified, so the history says who sent it.
        let history = config.history().await.unwrap();
        assert!(history.iter().all(|e| e.signer.is_some()));
    }

    #[tokio::test]
    async fn refusals_and_the_history_never_hold_a_secret_value() {
        let signed = Signed::new();
        let (config, _) = spawn_handle(Some(signed.verifier())).await;
        let secret = "hunter2-the-secret-value";

        // Applied: the value is in force and recorded nowhere.
        let applied = signed.update(
            Spec::default(),
            1,
            AGENT,
            json!([{"name": "TOKEN", "value": secret}]),
        );
        config.submit(applied).await.unwrap();
        // Refused after tampering, and refused for the wrong agent: neither repeats it.
        let mut tampered = signed.update(
            Spec::default(),
            2,
            AGENT,
            json!([{"name": "TOKEN", "value": secret}]),
        );
        tampered["payload"]["version"] = json!(9);
        let outcomes = vec![
            config.submit(tampered).await.unwrap(),
            config
                .submit(signed.update(
                    Spec::default(),
                    3,
                    "another-agent",
                    json!([{"name": "TOKEN", "value": secret}]),
                ))
                .await
                .unwrap(),
        ];
        let everything = format!(
            "{outcomes:?}{:?}{:?}",
            config.history().await.unwrap(),
            config.report().await.unwrap()
        );
        assert!(!everything.contains("hunter2"), "{everything}");
        assert_eq!(
            config
                .current()
                .await
                .unwrap()
                .read(&TOKEN)
                .unwrap()
                .as_deref(),
            Some(secret)
        );
    }

    // -- delivery on the agent's configuration topic ----------------------------------------

    fn notification(agent: &str, document: &Value) -> polar_router::IncomingMessage {
        let payload = rkyv::to_bytes::<rkyv::rancor::Error>(
            &polar_scheduler_common::ConfigurationNotification {
                agent: agent.to_string(),
                document_json: document.to_string(),
            },
        )
        .unwrap()
        .to_vec();
        polar_router::IncomingMessage {
            topic: polar_scheduler_common::configuration_topic(agent),
            payload,
            published_by: None,
            published_instance: None,
            trace_ctx: None,
        }
    }

    #[tokio::test]
    async fn a_document_delivered_on_the_topic_is_verified_and_applied_in_order() {
        let signed = Signed::new();
        let (config, seen) = spawn_handle(Some(signed.verifier())).await;
        let sub = subscription(AGENT, config.clone());
        assert_eq!(sub.topic, "agent.hello-agent.configuration");

        // Delivered back to back: both are applied, the later last.
        (sub.deliver)(notification(AGENT, &signed.high(1, "20")));
        (sub.deliver)(notification(AGENT, &signed.high(2, "30")));
        settle().await;
        assert_eq!(high(&config).await, 30);
        assert_eq!(seen.lock().unwrap().len(), 2);
        let history = config.history().await.unwrap();
        assert_eq!(
            history.iter().map(|e| e.version).collect::<Vec<_>>(),
            [1, 2]
        );
        assert!(history.iter().all(|e| e.signer.is_some()));
    }

    #[tokio::test]
    async fn what_arrives_on_the_topic_is_verified_whoever_published_it() {
        let signed = Signed::new();
        let (config, _) = spawn_handle(Some(signed.verifier())).await;
        let sub = subscription(AGENT, config.clone());

        // Unsigned, and signed by a CA this agent does not trust: delivered, then refused.
        let unsigned = json!({"payload": {"type": "configuration", "id": "u", "target": {"agent": AGENT}, "version": 1,
                              "changes": [{"name": "HIGH", "value": "99"}]}, "signature": {}});
        (sub.deliver)(notification(AGENT, &unsigned));
        (sub.deliver)(notification(AGENT, &Signed::new().high(2, "99")));
        settle().await;
        assert_eq!(high(&config).await, 10);
        let history = config.history().await.unwrap();
        assert_eq!(history.len(), 2);
        assert!(
            history
                .iter()
                .all(|e| matches!(e.outcome, ApplyOutcome::Refused(Refusal::Unverified(_))))
        );
    }

    #[tokio::test]
    async fn a_notification_for_another_agent_or_that_is_not_one_is_dropped() {
        let signed = Signed::new();
        let (config, _) = spawn_handle(Some(signed.verifier())).await;
        let sub = subscription(AGENT, config.clone());

        (sub.deliver)(notification("another-agent", &signed.high(1, "20")));
        (sub.deliver)(polar_router::IncomingMessage {
            topic: sub.topic.clone(),
            payload: vec![1, 2, 3],
            published_by: None,
            published_instance: None,
            trace_ctx: None,
        });
        // A notification whose document is not JSON.
        let mut bad = notification(AGENT, &json!({}));
        bad.payload = rkyv::to_bytes::<rkyv::rancor::Error>(
            &polar_scheduler_common::ConfigurationNotification {
                agent: AGENT.to_string(),
                document_json: "not json".to_string(),
            },
        )
        .unwrap()
        .to_vec();
        (sub.deliver)(bad);
        settle().await;
        // None of them reached the actor, so nothing is recorded and the value is as it was.
        assert!(config.history().await.unwrap().is_empty());
        assert_eq!(high(&config).await, 10);
    }

    // -- outcomes -----------------------------------------------------------------------------

    struct OutcomeSink(Arc<Mutex<Vec<ConfigurationOutcome>>>);

    #[ractor::async_trait]
    impl Actor for OutcomeSink {
        type Msg = ConfigurationOutcome;
        type State = Arc<Mutex<Vec<ConfigurationOutcome>>>;
        type Arguments = ();
        async fn pre_start(
            &self,
            _: ActorRef<Self::Msg>,
            _: (),
        ) -> Result<Self::State, ActorProcessingErr> {
            Ok(self.0.clone())
        }
        async fn handle(
            &self,
            _: ActorRef<Self::Msg>,
            message: Self::Msg,
            state: &mut Self::State,
        ) -> Result<(), ActorProcessingErr> {
            state.lock().unwrap().push(message);
            Ok(())
        }
    }

    async fn watch(config: &ConfigurationHandle) -> Arc<Mutex<Vec<ConfigurationOutcome>>> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (sink, _) = Actor::spawn(None, OutcomeSink(seen.clone()), ())
            .await
            .unwrap();
        config.outcomes().subscribe(sink, Some);
        seen
    }

    fn statuses(seen: &Arc<Mutex<Vec<ConfigurationOutcome>>>) -> Vec<String> {
        seen.lock()
            .unwrap()
            .iter()
            .map(|o| o.status.clone())
            .collect()
    }

    #[tokio::test]
    async fn every_document_is_announced_with_what_became_of_it() {
        let signed = Signed::new();
        let (config, _) = spawn_handle(Some(signed.verifier())).await;
        let seen = watch(&config).await;

        config.submit(signed.high(1, "20")).await.unwrap(); // applied
        config.submit(signed.high(2, "20")).await.unwrap(); // verified, changes nothing
        config.submit(signed.high(2, "30")).await.unwrap(); // not newer
        config
            .submit(signed.update(
                Spec::default(),
                3,
                AGENT,
                json!([{"name": "HOST", "value": "elsewhere"}]),
            ))
            .await
            .unwrap(); // static
        let mut tampered = signed.high(4, "40");
        tampered["payload"]["version"] = json!(9);
        config.submit(tampered).await.unwrap(); // altered
        settle().await;

        assert_eq!(
            statuses(&seen),
            ["applied", "unchanged", "stale", "invalid", "unverified"]
        );
        let all = seen.lock().unwrap().clone();

        // Applied: names what changed, says who signed it, and what it claimed.
        assert_eq!(all[0].agent, AGENT);
        assert_eq!(all[0].id.as_deref(), Some("u"));
        assert_eq!(all[0].version, Some(1));
        assert_eq!(all[0].changed, vec!["HIGH".to_string()]);
        assert!(all[0].signer.as_deref().unwrap().contains("alice"));
        assert!(all[0].at_unix_secs > 1_700_000_000);

        // Refused for what it asks: the reason names the variable.
        assert!(
            all[3].detail.iter().any(|d| d.contains("HOST")),
            "{:?}",
            all[3].detail
        );
        assert!(all[3].signer.is_some());

        // Not verified: no signer, and the reason says why. What it claimed is only a label.
        assert!(all[4].signer.is_none());
        assert_eq!(all[4].version, Some(9));
        assert!(!all[4].detail.is_empty());

        // Counted, so two in the same second are two events.
        assert_eq!(
            all.iter().map(|o| o.sequence).collect::<Vec<_>>(),
            [1, 2, 3, 4, 5]
        );
    }

    #[tokio::test]
    async fn a_document_delivered_on_the_topic_is_announced_too() {
        let signed = Signed::new();
        let (config, _) = spawn_handle(Some(signed.verifier())).await;
        let seen = watch(&config).await;
        let sub = subscription(AGENT, config.clone());
        (sub.deliver)(notification(AGENT, &signed.high(1, "20")));
        // Garbage and unsigned: the unsigned one is announced, the garbage never reached the actor.
        (sub.deliver)(polar_router::IncomingMessage {
            topic: sub.topic.clone(),
            payload: vec![1, 2],
            published_by: None,
            published_instance: None,
            trace_ctx: None,
        });
        (sub.deliver)(notification(
            AGENT,
            &json!({"payload": {"id": "x"}, "signature": {}}),
        ));
        settle().await;
        assert_eq!(statuses(&seen), ["applied", "unverified"]);
        assert_eq!(seen.lock().unwrap()[1].id.as_deref(), Some("x"));
    }

    #[tokio::test]
    async fn an_agent_with_no_ca_announces_that_it_refused_everything() {
        let signed = Signed::new();
        let (config, _) = spawn_handle(None).await;
        let seen = watch(&config).await;
        config.submit(signed.high(1, "20")).await.unwrap();
        settle().await;
        assert_eq!(statuses(&seen), ["unverified"]);
        assert!(seen.lock().unwrap()[0].detail[0].contains("no CA"));
    }

    #[tokio::test]
    async fn no_outcome_ever_holds_a_secret_value() {
        let signed = Signed::new();
        let (config, _) = spawn_handle(Some(signed.verifier())).await;
        let seen = watch(&config).await;
        let secret = "hunter2-the-secret-value";

        // Applied, refused after tampering, refused for another agent, and refused for a bad
        // companion value in the same document: none repeats the secret.
        config
            .submit(signed.update(
                Spec::default(),
                1,
                AGENT,
                json!([{"name": "TOKEN", "value": secret}]),
            ))
            .await
            .unwrap();
        let mut tampered = signed.update(
            Spec::default(),
            2,
            AGENT,
            json!([{"name": "TOKEN", "value": secret}]),
        );
        tampered["payload"]["version"] = json!(9);
        config.submit(tampered).await.unwrap();
        config
            .submit(signed.update(
                Spec::default(),
                3,
                "another-agent",
                json!([{"name": "TOKEN", "value": secret}]),
            ))
            .await
            .unwrap();
        config
            .submit(signed.update(
                Spec::default(),
                4,
                AGENT,
                json!([{"name": "TOKEN", "value": secret}, {"name": "LOW", "value": "99"}]),
            ))
            .await
            .unwrap();
        settle().await;
        let everything = format!("{:?}", seen.lock().unwrap());
        assert!(!everything.contains("hunter2"), "{everything}");
        assert_eq!(seen.lock().unwrap().len(), 4);
    }

    // -- runtime documents ------------------------------------------------------------------------

    fn validate_repositories(body: &Value) -> Result<(), Vec<String>> {
        let Some(list) = body.get("repositories").and_then(Value::as_array) else {
            return Err(vec!["`repositories` must be a list".to_string()]);
        };
        let problems: Vec<String> = list
            .iter()
            .enumerate()
            .filter(|(_, r)| r.get("url").and_then(Value::as_str).is_none())
            .map(|(i, _)| format!("repositories[{i}].url must be text"))
            .collect();
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }

    static REPOSITORIES: crate::runtime::RuntimeSection = crate::runtime::RuntimeSection {
        authority: crate::runtime::SectionAuthority::Runtime,
        name: "repositories",
        doc: "The repositories to observe.",
        body: "{}",
        validate: validate_repositories,
    };

    static ADMISSION: crate::runtime::RuntimeSection = crate::runtime::RuntimeSection {
        authority: crate::runtime::SectionAuthority::Runtime,
        name: "admission",
        doc: "Under what rules a proposal is accepted.",
        body: "{}",
        validate: |_| Ok(()),
    };

    static RUNTIME_SECTIONS: [&crate::runtime::RuntimeSection; 3] =
        [&REPOSITORIES, &ADMISSION, &RULES];

    /// A section only a holder of one capability may change, and that policy never governs.
    static RULES: crate::runtime::RuntimeSection = crate::runtime::RuntimeSection {
        authority: crate::runtime::SectionAuthority::Capability(
            cert_issuer_common::capability::Capability::UpdatePolicy,
        ),
        name: "rules",
        doc: "The rules.",
        body: "{}",
        validate: |_| Ok(()),
    };

    async fn runtime_handle(
        verifier: UpdateVerifier,
    ) -> (
        ConfigurationHandle,
        Arc<Mutex<Vec<crate::runtime::RuntimeChanged>>>,
    ) {
        struct Parent;
        #[ractor::async_trait]
        impl Actor for Parent {
            type Msg = ();
            type State = ();
            type Arguments = ();
            async fn pre_start(&self, _: ActorRef<()>, _: ()) -> Result<(), ActorProcessingErr> {
                Ok(())
            }
        }
        let (parent, _) = Actor::spawn(None, Parent, ()).await.unwrap();
        let handle = ConfigurationHandle::spawn_with_runtime(
            None,
            AGENT,
            config(),
            Some(verifier),
            &RUNTIME_SECTIONS,
            parent.get_cell(),
        )
        .await
        .unwrap();

        struct Sink(Arc<Mutex<Vec<crate::runtime::RuntimeChanged>>>);
        #[ractor::async_trait]
        impl Actor for Sink {
            type Msg = crate::runtime::RuntimeChanged;
            type State = ();
            type Arguments = ();
            async fn pre_start(
                &self,
                _: ActorRef<Self::Msg>,
                _: (),
            ) -> Result<(), ActorProcessingErr> {
                Ok(())
            }
            async fn handle(
                &self,
                _: ActorRef<Self::Msg>,
                message: Self::Msg,
                _: &mut (),
            ) -> Result<(), ActorProcessingErr> {
                self.0.lock().unwrap().push(message);
                Ok(())
            }
        }
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (sink, _) = Actor::spawn(None, Sink(seen.clone()), ()).await.unwrap();
        handle.runtime_changes().subscribe(sink, Some);
        (handle, seen)
    }

    impl Signed {
        fn runtime(&self, section: &str, version: u64, body: Value) -> Value {
            self.runtime_by(
                Spec {
                    capabilities: vec!["c:update-runtime"],
                    ..Spec::default()
                },
                section,
                version,
                body,
            )
        }

        fn runtime_by(&self, spec: Spec, section: &str, version: u64, body: Value) -> Value {
            let s = signer(&self.ca, spec);
            polar_signing::sign(
                json!({"type": "runtime", "id": format!("{section}-{version}"), "target": {"agent": AGENT},
                       "section": section, "version": version, "body": body}),
                &[s.cert_pem],
                &s.key_pem,
            )
            .unwrap()
            .to_value()
        }
    }

    fn repos(urls: &[&str]) -> Value {
        json!({"repositories": urls.iter().map(|u| json!({"url": u})).collect::<Vec<_>>()})
    }

    /// A judge that refuses `repositories` while the `admission` in force says it is closed, and otherwise accepts,
    /// noting what it judged: it sees the candidate and the sections in force.
    struct Gatekeeper;

    #[ractor::async_trait]
    impl crate::runtime::SectionJudge for Gatekeeper {
        async fn judge(
            &self,
            candidate: &crate::runtime::Candidate<'_>,
            in_force: &HashMap<String, RuntimeValue>,
        ) -> Result<Vec<String>, Vec<String>> {
            let (section, candidate) = (candidate.section, candidate.body);
            let closed = in_force
                .get("admission")
                .is_some_and(|held| held.body["closed"] == json!(true));
            if section == "repositories" && closed {
                let asked = candidate["repositories"].as_array().map_or(0, Vec::len);
                return Err(vec![format!(
                    "admission is closed, so {asked} repositories are refused"
                )]);
            }
            Ok(vec![format!("{section} judged")])
        }
    }

    async fn judged_handle(verifier: UpdateVerifier) -> ConfigurationHandle {
        judged_handle_by(verifier, Arc::new(Gatekeeper)).await
    }

    async fn judged_handle_by(
        verifier: UpdateVerifier,
        judge: Arc<dyn crate::runtime::SectionJudge>,
    ) -> ConfigurationHandle {
        struct Parent;
        #[ractor::async_trait]
        impl Actor for Parent {
            type Msg = ();
            type State = ();
            type Arguments = ();
            async fn pre_start(&self, _: ActorRef<()>, _: ()) -> Result<(), ActorProcessingErr> {
                Ok(())
            }
        }
        let (parent, _) = Actor::spawn(None, Parent, ()).await.unwrap();
        ConfigurationHandle::spawn_full(
            None,
            AGENT,
            config(),
            Some(verifier),
            &RUNTIME_SECTIONS,
            None,
            Some(judge),
            None,
            parent.get_cell(),
        )
        .await
        .unwrap()
    }

    /// A judge that takes longer than a read of the actor may wait, as the credentials agent's authority
    /// model does on a loaded machine.
    struct Slow;

    #[ractor::async_trait]
    impl crate::runtime::SectionJudge for Slow {
        async fn judge(
            &self,
            candidate: &crate::runtime::Candidate<'_>,
            _: &HashMap<String, RuntimeValue>,
        ) -> Result<Vec<String>, Vec<String>> {
            tokio::time::sleep(CALL_TIMEOUT * 3).await;
            Ok(vec![format!("{} judged slowly", candidate.section)])
        }
    }

    /// A submit's answer is its document's outcome, so it waits for the judge however long the judgement
    /// takes; only the actor's end cuts it short.
    #[tokio::test(start_paused = true)]
    async fn a_submit_is_answered_however_long_its_judgement_takes() {
        let signed = Signed::new();
        let config = judged_handle_by(signed.verifier(), Arc::new(Slow)).await;
        let outcome = config
            .submit(signed.runtime("repositories", 1, repos(&["https://a.example/r.git"])))
            .await;
        assert_eq!(
            outcome,
            Ok(ApplyOutcome::Applied {
                changed: vec!["repositories".to_string()],
                notes: vec!["repositories judged slowly".to_string()],
            })
        );
        assert_eq!(
            config
                .runtime("repositories")
                .await
                .unwrap()
                .map(|held| held.version),
            Some(1)
        );
    }

    #[tokio::test]
    async fn a_judge_s_refusal_leaves_the_section_in_force_and_its_acceptance_carries_its_notes() {
        let signed = Signed::new();
        let config = judged_handle(signed.verifier()).await;
        let seen = watch(&config).await;
        let first = config
            .submit(signed.runtime("repositories", 1, repos(&["https://a.example/r.git"])))
            .await
            .unwrap();
        assert_eq!(
            first,
            ApplyOutcome::Applied {
                changed: vec!["repositories".to_string()],
                notes: vec!["repositories judged".to_string()],
            }
        );
        config
            .submit(signed.runtime("admission", 1, json!({"closed": true})))
            .await
            .unwrap();
        let refused = config
            .submit(signed.runtime("repositories", 2, repos(&["https://b.example/r.git"])))
            .await
            .unwrap();
        assert_eq!(
            refused,
            ApplyOutcome::Refused(Refusal::Invalid(vec![
                "admission is closed, so 1 repositories are refused".to_string()
            ]))
        );
        // The section in force stays.
        let held = config.runtime("repositories").await.unwrap().unwrap();
        assert_eq!(
            (held.version, held.body),
            (1, repos(&["https://a.example/r.git"]))
        );
        settle().await;
        {
            let seen = seen.lock().unwrap();
            assert_eq!(
                seen.iter().map(|o| o.status.as_str()).collect::<Vec<_>>(),
                ["applied", "applied", "invalid"]
            );
            // The notes go with the applied outcome; the reasons with the refused one.
            assert_eq!(seen[0].detail, ["repositories judged"]);
            assert_eq!(
                seen[2].detail,
                ["admission is closed, so 1 repositories are refused"]
            );
        }
        // A refused version is not spent: once admission opens, the same version is accepted.
        config
            .submit(signed.runtime("admission", 2, json!({"closed": false})))
            .await
            .unwrap();
        let again = config
            .submit(signed.runtime("repositories", 2, repos(&["https://b.example/r.git"])))
            .await
            .unwrap();
        assert!(matches!(again, ApplyOutcome::Applied { .. }), "{again:?}");
    }

    #[tokio::test]
    async fn a_runtime_document_is_held_whole_and_subscribers_are_told_which_section() {
        let signed = Signed::new();
        let (config, seen) = runtime_handle(signed.verifier()).await;
        assert!(config.runtime("repositories").await.unwrap().is_none());

        let outcome = config
            .submit(signed.runtime("repositories", 1, repos(&["https://a.example/r.git"])))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            ApplyOutcome::Applied {
                changed: vec!["repositories".to_string()],
                notes: Vec::new(),
            }
        );
        let held = config.runtime("repositories").await.unwrap().unwrap();
        assert_eq!(held.version, 1);
        assert_eq!(held.body, repos(&["https://a.example/r.git"]));
        // Who signed it is kept with it, by name and certificate serial, for the record an update carries.
        assert!(
            held.signer.contains("alice") && held.signer.contains("serial"),
            "{}",
            held.signer
        );
        settle().await;
        assert_eq!(
            *seen.lock().unwrap(),
            [crate::runtime::RuntimeChanged {
                section: "repositories".to_string(),
                version: 1
            }]
        );

        // The next version replaces the section whole: nothing of the first is left in it.
        config
            .submit(signed.runtime("repositories", 2, repos(&["https://b.example/r.git"])))
            .await
            .unwrap();
        let held = config.runtime("repositories").await.unwrap().unwrap();
        assert_eq!(held.version, 2);
        assert_eq!(held.body, repos(&["https://b.example/r.git"]));
    }

    #[tokio::test]
    async fn an_old_runtime_version_cannot_replace_a_newer_one_and_versions_are_per_section() {
        let signed = Signed::new();
        let (config, _) = runtime_handle(signed.verifier()).await;
        config
            .submit(signed.runtime("repositories", 5, repos(&["https://a.example/r.git"])))
            .await
            .unwrap();

        // A replay, and an old one arriving late.
        for old in [5, 3] {
            let outcome = config
                .submit(signed.runtime("repositories", old, repos(&["https://evil.example/r.git"])))
                .await
                .unwrap();
            assert_eq!(
                outcome,
                ApplyOutcome::Refused(Refusal::Stale { applied: 5 })
            );
        }
        assert_eq!(
            config.runtime("repositories").await.unwrap().unwrap().body,
            repos(&["https://a.example/r.git"])
        );

        // Another section has a count of its own: its version 1 is not older than repositories 5.
        let outcome = config
            .submit(signed.runtime("admission", 1, json!({})))
            .await
            .unwrap();
        assert!(
            matches!(outcome, ApplyOutcome::Applied { .. }),
            "{outcome:?}"
        );

        // And so do the agent's own configuration versions: runtime 5 does not make config 1 stale.
        let outcome = config.submit(signed.high(1, "20")).await.unwrap();
        assert!(
            matches!(outcome, ApplyOutcome::Applied { .. }),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn a_section_the_agent_did_not_declare_is_refused_by_name_and_nothing_is_held() {
        let signed = Signed::new();
        let (config, seen) = runtime_handle(signed.verifier()).await;
        let outcome = config
            .submit(signed.runtime("credentials", 1, json!({})))
            .await
            .unwrap();
        match outcome {
            ApplyOutcome::Refused(Refusal::Invalid(problems)) => {
                assert!(problems[0].contains("credentials"), "{problems:?}");
                assert!(problems[0].contains(AGENT), "{problems:?}");
            }
            other => panic!("{other:?}"),
        }
        assert!(config.runtime("credentials").await.unwrap().is_none());
        settle().await;
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_body_that_does_not_fit_is_refused_with_every_problem_and_the_version_is_not_spent() {
        let signed = Signed::new();
        let (config, _) = runtime_handle(signed.verifier()).await;
        config
            .submit(signed.runtime("repositories", 1, repos(&["https://a.example/r.git"])))
            .await
            .unwrap();

        let bad = json!({"repositories": [{"url": 1}, {"nope": true}]});
        match config
            .submit(signed.runtime("repositories", 2, bad))
            .await
            .unwrap()
        {
            ApplyOutcome::Refused(Refusal::Invalid(problems)) => {
                assert_eq!(
                    problems.len(),
                    2,
                    "every problem, not the first: {problems:?}"
                );
                assert!(problems[0].contains("repositories[0].url"), "{problems:?}");
            }
            other => panic!("{other:?}"),
        }
        // What was held stays, and the corrected document can go under the same number.
        assert_eq!(
            config
                .runtime("repositories")
                .await
                .unwrap()
                .unwrap()
                .version,
            1
        );
        let outcome = config
            .submit(signed.runtime("repositories", 2, repos(&["https://c.example/r.git"])))
            .await
            .unwrap();
        assert!(
            matches!(outcome, ApplyOutcome::Applied { .. }),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn only_the_runtime_capability_changes_a_runtime_section() {
        let signed = Signed::new();
        let (config, _) = runtime_handle(signed.verifier()).await;
        // Holds update-configuration (the default signer): may change how the agent runs, not this.
        let outcome = config
            .submit(signed.runtime_by(
                Spec::default(),
                "repositories",
                1,
                repos(&["https://a.example/r.git"]),
            ))
            .await
            .unwrap();
        assert!(
            matches!(
                outcome,
                ApplyOutcome::Refused(Refusal::Unverified(Rejection::Unauthorized(_)))
            ),
            "{outcome:?}"
        );
        assert!(config.runtime("repositories").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn an_agent_with_no_runtime_sections_refuses_a_runtime_document() {
        // The ordinary agent: nothing declared, so nothing to hold.
        let signed = Signed::new();
        let (config, _) = spawn_handle(Some(signed.verifier())).await;
        let outcome = config
            .submit(signed.runtime("repositories", 1, repos(&[])))
            .await
            .unwrap();
        assert!(
            matches!(outcome, ApplyOutcome::Refused(Refusal::Invalid(_))),
            "{outcome:?}"
        );
    }

    // -- policy first, the certificate second ------------------------------------------------------

    async fn policy_handle(
        verifier: UpdateVerifier,
        policy_source: Option<&str>,
    ) -> ConfigurationHandle {
        use polar_permissions::PermissionsActor;
        use polar_policy::{PolicyActor, PolicyActorArgs, PolicyMessage};
        struct Parent;
        #[ractor::async_trait]
        impl Actor for Parent {
            type Msg = ();
            type State = ();
            type Arguments = ();
            async fn pre_start(&self, _: ActorRef<()>, _: ()) -> Result<(), ActorProcessingErr> {
                Ok(())
            }
        }
        let (parent, _) = Actor::spawn(None, Parent, ()).await.unwrap();
        let (permissions, _) = Actor::spawn(None, PermissionsActor, ()).await.unwrap();
        let (policy, _) = Actor::spawn(
            None,
            PolicyActor,
            PolicyActorArgs {
                permissions_actor: permissions,
            },
        )
        .await
        .unwrap();
        if let Some(source) = policy_source {
            ractor::call!(policy, |reply| PolicyMessage::UpdatePolicy {
                policy_source: source.to_string(),
                reply,
            })
            .unwrap()
            .unwrap();
        }
        ConfigurationHandle::spawn_full(
            None,
            AGENT,
            config(),
            Some(verifier),
            &RUNTIME_SECTIONS,
            Some(policy),
            None,
            None,
            parent.get_cell(),
        )
        .await
        .unwrap()
    }

    fn is_unauthorized(outcome: &ApplyOutcome) -> bool {
        matches!(
            outcome,
            ApplyOutcome::Refused(Refusal::Unverified(Rejection::Unauthorized(_)))
        )
    }

    #[tokio::test]
    async fn a_policy_that_permits_admits_a_runtime_signer_whose_certificate_would_not() {
        let signed = Signed::new();
        // alice holds update-configuration only (the default signer), and the policy lets her change a section.
        let config = policy_handle(
            signed.verifier(),
            Some(&format!(
                r#"permit(principal == Identity::"{ALICE_ACCOUNT_ID}", action == Action::"update-runtime", resource == Section::"{AGENT}/repositories");"#
            )),
        )
        .await;
        let outcome = config
            .submit(signed.runtime_by(
                Spec::default(),
                "repositories",
                1,
                repos(&["https://a.example/r.git"]),
            ))
            .await
            .unwrap();
        assert!(
            matches!(outcome, ApplyOutcome::Applied { .. }),
            "{outcome:?}"
        );
        // The permit was for that section: another section is left to the certificate, which refuses.
        let outcome = config
            .submit(signed.runtime_by(Spec::default(), "admission", 1, json!({})))
            .await
            .unwrap();
        assert!(is_unauthorized(&outcome), "{outcome:?}");
    }

    #[tokio::test]
    async fn a_policy_that_forbids_refuses_a_signer_whose_certificate_would_admit() {
        let signed = Signed::new();
        let config = policy_handle(
            signed.verifier(),
            Some(&format!(
                r#"forbid(principal == Identity::"{ALICE_ACCOUNT_ID}", action == Action::"update-runtime", resource == Section::"{AGENT}/admission");"#
            )),
        )
        .await;
        // The runtime capability would admit her to every section; the policy takes one away.
        let outcome = config
            .submit(signed.runtime("admission", 1, json!({})))
            .await
            .unwrap();
        assert!(is_unauthorized(&outcome), "{outcome:?}");
        assert!(config.runtime("admission").await.unwrap().is_none());
        let outcome = config
            .submit(signed.runtime("repositories", 1, repos(&[])))
            .await
            .unwrap();
        assert!(
            matches!(outcome, ApplyOutcome::Applied { .. }),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn policy_decides_configuration_per_variable_and_every_variable_must_be_admitted() {
        let signed = Signed::new();
        // Policy forbids alice from LOW; the certificate admits her to everything else.
        let config = policy_handle(
            signed.verifier(),
            Some(&format!(
                r#"forbid(principal == Identity::"{ALICE_ACCOUNT_ID}", action == Action::"update-configuration", resource == Variable::"{AGENT}/LOW");"#
            )),
        )
        .await;
        let outcome = config.submit(signed.high(1, "20")).await.unwrap();
        assert!(
            matches!(outcome, ApplyOutcome::Applied { .. }),
            "{outcome:?}"
        );
        let both = signed.update(
            Spec::default(),
            2,
            AGENT,
            json!([{"name": "HIGH", "value": "30"}, {"name": "LOW", "value": "1"}]),
        );
        let outcome = config.submit(both).await.unwrap();
        assert!(is_unauthorized(&outcome), "{outcome:?}");
        assert_eq!(
            high(&config).await,
            20,
            "nothing of a refused document is applied"
        );
    }

    /// A document that does not name a variable takes its override away, so that is a change to that variable: a signer
    /// policy keeps off it cannot do it by leaving it out.
    #[tokio::test]
    async fn taking_an_override_away_needs_the_same_permission_as_setting_it() {
        let signed = Signed::new();
        let config = policy_handle(
            signed.verifier(),
            Some(&format!(
                r#"forbid(principal == Identity::"{ALICE_ACCOUNT_ID}", action == Action::"update-configuration", resource == Variable::"{AGENT}/LOW");"#
            )),
        )
        .await;
        // Allowed for HIGH alone: nothing holds LOW yet, so this document touches only HIGH.
        let first = config.submit(signed.high(1, "20")).await.unwrap();
        assert!(matches!(first, ApplyOutcome::Applied { .. }), "{first:?}");
        config
            .apply_unchecked(2, vec![("LOW".to_string(), "5".to_string())])
            .await
            .unwrap();
        // Now LOW is held, by someone who may: the same signer naming only HIGH would take it away, and may not.
        let outcome = config.submit(signed.high(3, "30")).await.unwrap();
        assert!(is_unauthorized(&outcome), "{outcome:?}");
        assert!(format!("{outcome:?}").contains("LOW"), "{outcome:?}");
        assert_eq!(config.current().await.unwrap().read(&LOW).unwrap(), 5);
    }

    // -- a question about the configuration in force --------------------------------------

    /// A question signed by `spec`'s holder, valid for a minute from now.
    fn question(signed: &Signed, spec: Spec, agent: &str) -> Value {
        window_question(signed, spec, agent, now() as u64, now() as u64 + 60)
    }

    fn window_question(signed: &Signed, spec: Spec, agent: &str, from: u64, to: u64) -> Value {
        let s = signer(&signed.ca, spec);
        polar_signing::sign_in(
            polar_signing::Domain::RUNNING_CONFIGURATION_QUESTION,
            polar_scheduler_common::running::question_payload(agent, "q1", from, to),
            &[s.cert_pem],
            &s.key_pem,
        )
        .unwrap()
        .to_value()
    }

    fn stamped() -> Option<String> {
        Some(ALICE_ACCOUNT_ID.to_string())
    }

    #[tokio::test]
    async fn who_may_change_the_settings_may_ask_what_they_are() {
        let signed = Signed::new();
        let (config, _) = spawn_handle(Some(signed.verifier())).await;
        config.submit(signed.high(3, "20")).await.unwrap();
        let answer = config
            .question(question(&signed, Spec::default(), AGENT), stamped())
            .await
            .unwrap()
            .unwrap();
        assert_eq!((answer.id.as_str(), answer.agent.as_str()), ("q1", AGENT));
        assert_eq!(answer.version, 3);
        let high = answer.settings.iter().find(|s| s.name == "HIGH").unwrap();
        assert_eq!(
            (high.value.as_deref(), high.source.as_str()),
            (Some("20"), "override")
        );
    }

    #[tokio::test]
    async fn a_question_from_one_without_the_capability_is_refused() {
        let signed = Signed::new();
        let (config, _) = spawn_handle(Some(signed.verifier())).await;
        let spec = Spec {
            capabilities: vec!["c:update-runtime"],
            ..Spec::default()
        };
        let got = config
            .question(question(&signed, spec, AGENT), stamped())
            .await
            .unwrap();
        assert!(matches!(got, Err(Rejection::Unauthorized(_))), "{got:?}");
    }

    #[tokio::test]
    async fn a_question_is_believed_only_from_its_signer() {
        let signed = Signed::new();
        let (config, _) = spawn_handle(Some(signed.verifier())).await;
        for sender in [None, Some("mallory.polar.svc.cluster.local".to_string())] {
            let got = config
                .question(question(&signed, Spec::default(), AGENT), sender)
                .await
                .unwrap();
            assert!(matches!(got, Err(Rejection::Unauthorized(_))), "{got:?}");
        }
    }

    #[tokio::test]
    async fn a_question_for_another_agent_is_refused() {
        let signed = Signed::new();
        let (config, _) = spawn_handle(Some(signed.verifier())).await;
        let got = config
            .question(
                question(&signed, Spec::default(), "another-agent"),
                stamped(),
            )
            .await
            .unwrap();
        assert!(matches!(got, Err(Rejection::WrongTarget { .. })), "{got:?}");
    }

    #[tokio::test]
    async fn a_question_outside_its_time_is_refused() {
        let signed = Signed::new();
        let (config, _) = spawn_handle(Some(signed.verifier())).await;
        let now = now() as u64;
        for (from, to) in [
            (now - 600, now - 300),
            // Longer than a question may last.
            (
                now,
                now + polar_scheduler_common::running::MAX_QUESTION_VALIDITY_SECS + 1,
            ),
        ] {
            let document = window_question(&signed, Spec::default(), AGENT, from, to);
            let got = config.question(document, stamped()).await.unwrap();
            assert!(matches!(got, Err(Rejection::Window(_))), "{got:?}");
        }
    }

    /// A signature made for one purpose does not verify for another, in either direction.
    #[tokio::test]
    async fn a_question_and_an_update_cannot_stand_in_for_each_other() {
        let signed = Signed::new();
        let (config, _) = spawn_handle(Some(signed.verifier())).await;
        let got = config
            .question(signed.high(1, "20"), stamped())
            .await
            .unwrap();
        assert!(matches!(got, Err(Rejection::Signature(_))), "{got:?}");
        let outcome = config
            .submit(question(&signed, Spec::default(), AGENT))
            .await
            .unwrap();
        assert!(
            matches!(
                outcome,
                ApplyOutcome::Refused(Refusal::Unverified(Rejection::Signature(_)))
            ),
            "{outcome:?}"
        );
        // The right domain and another kind of payload is refused as well.
        let s = signer(&signed.ca, Spec::default());
        let other = polar_signing::sign_in(
            polar_signing::Domain::RUNNING_CONFIGURATION_QUESTION,
            json!({"type": "configuration", "id": "u", "target": {"agent": AGENT}, "version": 1, "changes": []}),
            &[s.cert_pem],
            &s.key_pem,
        )
        .unwrap()
        .to_value();
        let got = config.question(other, stamped()).await.unwrap();
        assert!(matches!(got, Err(Rejection::WrongType { .. })), "{got:?}");
    }

    #[tokio::test]
    async fn an_agent_with_no_ca_answers_no_question() {
        let signed = Signed::new();
        let (config, _) = spawn_handle(None).await;
        let got = config
            .question(question(&signed, Spec::default(), AGENT), stamped())
            .await
            .unwrap();
        assert!(matches!(got, Err(Rejection::NotConfigured)), "{got:?}");
    }

    #[tokio::test]
    async fn a_question_from_a_revoked_certificate_is_refused() {
        struct All;
        impl crate::signed::Revocation for All {
            fn is_revoked(&self, _: &polar_signing::SignerInfo) -> bool {
                true
            }
        }
        let signed = Signed::new();
        let (config, _) =
            spawn_handle(Some(signed.verifier().with_revocation(Arc::new(All)))).await;
        let got = config
            .question(question(&signed, Spec::default(), AGENT), stamped())
            .await
            .unwrap();
        assert!(matches!(got, Err(Rejection::Revoked(_))), "{got:?}");
    }

    #[tokio::test]
    async fn policy_decides_a_question_first_and_the_certificate_where_it_is_silent() {
        let signed = Signed::new();
        let no_capability = || Spec {
            capabilities: vec![],
            ..Spec::default()
        };
        let forbids = format!(
            r#"forbid(principal == Identity::"{ALICE_ACCOUNT_ID}", action == Action::"read-configuration", resource == Agent::"{AGENT}");"#
        );
        let permits = format!(
            r#"permit(principal == Identity::"{ALICE_ACCOUNT_ID}", action == Action::"read-configuration", resource == Agent::"{AGENT}");"#
        );
        let silent = r#"forbid(principal == Identity::"nobody", action == Action::"read-configuration", resource);"#;
        let cases: [(&str, Spec, bool); 4] = [
            (&forbids, Spec::default(), false),
            (&permits, no_capability(), true),
            (silent, Spec::default(), true),
            (silent, no_capability(), false),
        ];
        for (rules, spec, answered) in cases {
            let config = policy_handle(signed.verifier(), Some(rules)).await;
            let got = config
                .question(question(&signed, spec, AGENT), stamped())
                .await
                .unwrap();
            assert_eq!(got.is_ok(), answered, "{rules}: {got:?}");
        }
    }

    #[tokio::test]
    async fn without_a_loaded_policy_or_one_that_is_silent_the_certificate_decides_as_before() {
        let signed = Signed::new();
        for source in [
            None,
            Some(r#"permit(principal == Identity::"nobody", action, resource);"#),
        ] {
            let config = policy_handle(signed.verifier(), source).await;
            let outcome = config.submit(signed.high(1, "20")).await.unwrap();
            assert!(
                matches!(outcome, ApplyOutcome::Applied { .. }),
                "{source:?} {outcome:?}"
            );
            // And a signer the certificate does not admit stays refused.
            let no_capability = signed.update(
                Spec {
                    capabilities: vec!["c:grant"],
                    ..Spec::default()
                },
                2,
                AGENT,
                json!([{"name": "HIGH", "value": "30"}]),
            );
            let outcome = config.submit(no_capability).await.unwrap();
            assert!(is_unauthorized(&outcome), "{source:?} {outcome:?}");
        }
    }

    #[tokio::test]
    async fn a_section_declared_for_one_capability_needs_exactly_that_and_policy_cannot_change_it()
    {
        let signed = Signed::new();
        let by = |capability: &'static str| Spec {
            capabilities: vec![capability],
            ..Spec::default()
        };
        // Policy forbids alice every section, and permits alice the rules section; neither counts for it.
        let config = policy_handle(
            signed.verifier(),
            Some(&format!(
                r#"forbid(principal == Identity::"{ALICE_ACCOUNT_ID}", action == Action::"update-runtime", resource == Section::"{AGENT}/rules");
                   permit(principal == Identity::"{ALICE_ACCOUNT_ID}", action == Action::"update-runtime", resource == Section::"{AGENT}/rules");"#
            )),
        )
        .await;

        // The holder of the section's own capability is admitted, whatever policy says of her.
        let outcome = config
            .submit(signed.runtime_by(by("c:update-policy"), "rules", 1, json!({})))
            .await
            .unwrap();
        assert!(
            matches!(outcome, ApplyOutcome::Applied { .. }),
            "{outcome:?}"
        );

        // The runtime capability, which admits the other sections, does not admit this one.
        let outcome = config
            .submit(signed.runtime_by(by("c:update-runtime"), "rules", 2, json!({})))
            .await
            .unwrap();
        assert!(is_unauthorized(&outcome), "{outcome:?}");

        // And a policy permit cannot stand in for the capability.
        let permit_only = policy_handle(
            signed.verifier(),
            Some(&format!(
                r#"permit(principal == Identity::"{ALICE_ACCOUNT_ID}", action, resource == Section::"{AGENT}/rules");"#
            )),
        )
        .await;
        let outcome = permit_only
            .submit(signed.runtime_by(Spec::default(), "rules", 1, json!({})))
            .await
            .unwrap();
        assert!(is_unauthorized(&outcome), "{outcome:?}");
    }

    // -- following ---------------------------------------------------------------------

    /// An actor following something, as a domain actor would, keeping every message it is sent.
    struct Keeper<T>(Arc<Mutex<Vec<T>>>);
    #[ractor::async_trait]
    impl<T: Send + Sync + 'static> Actor for Keeper<T> {
        type Msg = T;
        type State = ();
        type Arguments = ();
        async fn pre_start(&self, _: ActorRef<T>, _: ()) -> Result<(), ActorProcessingErr> {
            Ok(())
        }
        async fn handle(
            &self,
            _: ActorRef<T>,
            message: T,
            _: &mut (),
        ) -> Result<(), ActorProcessingErr> {
            self.0.lock().unwrap().push(message);
            Ok(())
        }
    }

    async fn keeper<T: Send + Sync + 'static>() -> (ActorRef<T>, Arc<Mutex<Vec<T>>>) {
        let kept = Arc::new(Mutex::new(Vec::new()));
        let (actor, _) = Actor::spawn(None, Keeper(kept.clone()), ()).await.unwrap();
        (actor, kept)
    }

    #[tokio::test]
    async fn a_follower_gets_the_value_in_force_and_each_new_one() {
        let (config, _) = handle().await;
        let (actor, kept) = keeper::<u64>().await;
        assert_eq!(config.follow(&HIGH, &actor, |v| v).await.unwrap(), 10);

        config
            .apply_unchecked(1, change("HIGH", "20"))
            .await
            .unwrap();
        config
            .apply_unchecked(2, change("HIGH", "30"))
            .await
            .unwrap();
        settle().await;
        assert_eq!(*kept.lock().unwrap(), [20, 30]);
    }

    /// One who follows a variable hears nothing of another, nor of an update that leaves the value as it was.
    #[tokio::test]
    async fn a_follower_is_told_only_when_its_value_differs() {
        let (config, _) = handle().await;
        let (actor, kept) = keeper::<u64>().await;
        config.follow(&HIGH, &actor, |v| v).await.unwrap();

        config.apply_unchecked(1, change("LOW", "2")).await.unwrap();
        config
            .apply_unchecked(2, change("HIGH", "10"))
            .await
            .unwrap();
        settle().await;
        assert!(kept.lock().unwrap().is_empty());

        config
            .apply_unchecked(3, change("HIGH", "11"))
            .await
            .unwrap();
        settle().await;
        assert_eq!(*kept.lock().unwrap(), [11]);
    }

    /// An update that changes two variables of a group is one message, holding both.
    #[tokio::test]
    async fn settings_that_change_together_arrive_as_one_value() {
        let (config, _) = handle().await;
        let (actor, kept) = keeper::<(u64, u64)>().await;
        let bounds = |c: &Config| -> Result<(u64, u64), String> {
            Ok((
                c.read(&LOW).map_err(|e| e.to_string())?,
                c.read(&HIGH).map_err(|e| e.to_string())?,
            ))
        };
        let names: [&dyn Described; 2] = [&LOW, &HIGH];
        assert_eq!(
            config
                .follow_group(&names, bounds, &actor, |v| v)
                .await
                .unwrap(),
            (1, 10)
        );

        config
            .apply_unchecked(
                1,
                vec![
                    ("LOW".to_string(), "5".to_string()),
                    ("HIGH".to_string(), "50".to_string()),
                ],
            )
            .await
            .unwrap();
        settle().await;
        assert_eq!(*kept.lock().unwrap(), [(5, 50)]);
    }

    /// An actor started again after an update has the signed value, not the one the render gave it.
    #[tokio::test]
    async fn one_who_follows_after_an_update_has_its_value() {
        let (config, _) = handle().await;
        config
            .apply_unchecked(1, change("HIGH", "20"))
            .await
            .unwrap();
        let (actor, kept) = keeper::<u64>().await;
        assert_eq!(config.follow(&HIGH, &actor, |v| v).await.unwrap(), 20);
        settle().await;
        assert!(kept.lock().unwrap().is_empty());
    }

    /// However quickly updates come, the follower ends on the value in force, each value in its order.
    #[tokio::test]
    async fn a_burst_of_updates_loses_nothing() {
        let (config, _) = handle().await;
        let (actor, kept) = keeper::<u64>().await;
        config.follow(&HIGH, &actor, |v| v).await.unwrap();
        for version in 1..=200u64 {
            config
                .apply_unchecked(version, change("HIGH", &(version + 10).to_string()))
                .await
                .unwrap();
        }
        settle().await;
        assert_eq!(
            *kept.lock().unwrap(),
            (1..=200u64).map(|v| v + 10).collect::<Vec<_>>()
        );
    }

    fn notes(outcome: ApplyOutcome) -> Vec<String> {
        match outcome {
            ApplyOutcome::Applied { notes, .. } => notes,
            refused => panic!("{refused:?}"),
        }
    }

    /// An update to something nobody follows applies, and its outcome says it does nothing yet. A follower that has
    /// stopped follows nothing.
    #[tokio::test]
    async fn an_update_nothing_follows_says_so() {
        let (config, _) = handle().await;
        let said = notes(
            config
                .apply_unchecked(1, change("HIGH", "20"))
                .await
                .unwrap(),
        );
        assert_eq!(said.len(), 1, "{said:?}");
        assert!(said[0].contains("HIGH"), "{said:?}");
        assert!(said[0].contains("next restart"), "{said:?}");
        assert!(said[0].contains("what starts next"), "{said:?}");

        let (actor, _) = keeper::<u64>().await;
        config.follow(&HIGH, &actor, |v| v).await.unwrap();
        let said = notes(
            config
                .apply_unchecked(2, change("HIGH", "30"))
                .await
                .unwrap(),
        );
        assert!(said.is_empty(), "{said:?}");

        actor.stop_and_wait(None, None).await.unwrap();
        let said = notes(
            config
                .apply_unchecked(3, change("HIGH", "40"))
                .await
                .unwrap(),
        );
        assert!(said[0].contains("HIGH"), "{said:?}");
    }

    /// What an update that changed nothing says of no one.
    #[tokio::test]
    async fn an_update_that_changes_nothing_has_no_such_note() {
        let (config, _) = handle().await;
        let said = notes(
            config
                .apply_unchecked(1, change("HIGH", "10"))
                .await
                .unwrap(),
        );
        assert!(said.is_empty(), "{said:?}");
    }

    async fn judged_by(judge: SettingsJudge) -> ConfigurationHandle {
        struct Parent;
        #[ractor::async_trait]
        impl Actor for Parent {
            type Msg = ();
            type State = ();
            type Arguments = ();
            async fn pre_start(&self, _: ActorRef<()>, _: ()) -> Result<(), ActorProcessingErr> {
                Ok(())
            }
        }
        let (parent, _) = Actor::spawn(None, Parent, ()).await.unwrap();
        ConfigurationHandle::spawn_full(
            None,
            AGENT,
            config(),
            None,
            &[],
            None,
            None,
            Some(judge),
            parent.get_cell(),
        )
        .await
        .unwrap()
    }

    /// The settings work while HIGH is an even number.
    fn even(config: &Config) -> Result<(), String> {
        let high = config.read(&HIGH).map_err(|e| e.to_string())?;
        if high % 2 == 0 {
            Ok(())
        } else {
            Err("HIGH must be even".to_string())
        }
    }

    /// An update that would break settings that work is refused, the values stay and its version is not spent.
    #[tokio::test]
    async fn an_update_that_breaks_working_settings_is_refused() {
        let config = judged_by(even).await;
        let outcome = config
            .apply_unchecked(1, change("HIGH", "21"))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            ApplyOutcome::Refused(Refusal::Invalid(vec!["HIGH must be even".to_string()]))
        );
        assert_eq!(config.current().await.unwrap().read(&HIGH).unwrap(), 10);
        // The corrected one goes under the same number.
        assert!(matches!(
            config
                .apply_unchecked(1, change("HIGH", "22"))
                .await
                .unwrap(),
            ApplyOutcome::Applied { .. }
        ));
    }

    /// While the settings do not work any update goes through: one to something else (an agent held on them can have
    /// its logging changed), one that leaves them broken, and the one that mends them.
    #[tokio::test]
    async fn while_settings_do_not_work_any_update_applies() {
        fn odd_first(config: &Config) -> Result<(), String> {
            even(config)
        }
        let env: HashMap<String, String> = [
            ("HOST".to_string(), "h".to_string()),
            ("HIGH".to_string(), "11".to_string()),
        ]
        .into();
        let start = Config::builder(&env).register(&SECTION).build();
        struct Parent;
        #[ractor::async_trait]
        impl Actor for Parent {
            type Msg = ();
            type State = ();
            type Arguments = ();
            async fn pre_start(&self, _: ActorRef<()>, _: ()) -> Result<(), ActorProcessingErr> {
                Ok(())
            }
        }
        let (parent, _) = Actor::spawn(None, Parent, ()).await.unwrap();
        let config = ConfigurationHandle::spawn_full(
            None,
            AGENT,
            start,
            None,
            &[],
            None,
            None,
            Some(odd_first),
            parent.get_cell(),
        )
        .await
        .unwrap();
        for (version, name, value) in [(1, "LOW", "2"), (2, "HIGH", "13"), (3, "HIGH", "14")] {
            assert!(
                matches!(
                    config
                        .apply_unchecked(version, change(name, value))
                        .await
                        .unwrap(),
                    ApplyOutcome::Applied { .. }
                ),
                "{name}={value}"
            );
        }
        // And now they work, so they are kept working.
        assert!(matches!(
            config
                .apply_unchecked(4, change("HIGH", "15"))
                .await
                .unwrap(),
            ApplyOutcome::Refused(Refusal::Invalid(_))
        ));
    }

    proptest::proptest! {
        /// The rule, for every pair of answers: refused exactly when what works would stop working, with the reason given.
        #[test]
        fn an_update_is_refused_exactly_when_it_breaks_what_works(
            in_force in proptest::option::of("[a-z]{1,4}"),
            candidate in proptest::option::of("[a-z]{1,4}"),
        ) {
            let answer = |why: &Option<String>| why.clone().map_or(Ok(()), Err);
            let refused = breaks_what_works(answer(&in_force), answer(&candidate));
            proptest::prop_assert_eq!(
                refused,
                if in_force.is_none() { candidate } else { None }
            );
        }

        /// For any sequence of updates, settings that start working are working after each, the follower ends on the
        /// value in force, and it was told nothing twice running.
        #[test]
        fn working_settings_stay_working_and_a_follower_ends_on_what_is_in_force(
            updates in proptest::collection::vec(11u64..60, 0..24),
        ) {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            runtime.block_on(async {
                let config = judged_by(even).await;
                let (actor, kept) = keeper::<u64>().await;
                config.follow(&HIGH, &actor, |v| v).await.unwrap();
                for (index, high) in updates.iter().enumerate() {
                    let _ = config
                        .apply_unchecked(index as u64 + 1, change("HIGH", &high.to_string()))
                        .await
                        .unwrap();
                    let current = config.current().await.unwrap();
                    assert!(even(&current).is_ok(), "{high}");
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
                let in_force = config.current().await.unwrap().read(&HIGH).unwrap();
                let told = kept.lock().unwrap().clone();
                assert_eq!(told.last().copied().unwrap_or(10), in_force);
                assert!(told.windows(2).all(|pair| pair[0] != pair[1]), "{told:?}");
            });
        }
    }

    // -- the shared check ----------------------------------------------------------------

    static PHRASE: Defaulted<String> = Defaulted::text("PHRASE", "a phrase", "hello").dynamic();
    static SAID: Defaulted<String> = Defaulted::text("SAID", "what is said", "hello")
        .example("goodbye")
        .dynamic();
    static COUNT: Defaulted<u64> = Defaulted::number("COUNT", "a count", "1").dynamic();
    static FIXED: Defaulted<u64> = Defaulted::number("FIXED", "fixed", "1");
    static CHECKED_VARS: &[&dyn Described] = &[&SAID, &COUNT];
    static CHECKED: Section = Section {
        name: "checked",
        vars: CHECKED_VARS,
        relations: |_| Vec::new(),
    };
    static NO_EXAMPLE_VARS: &[&dyn Described] = &[&PHRASE];
    static NO_EXAMPLE: Section = Section {
        name: "no-example",
        vars: NO_EXAMPLE_VARS,
        relations: |_| Vec::new(),
    };
    static WITH_FIXED_VARS: &[&dyn Described] = &[&FIXED];
    static WITH_FIXED: Section = Section {
        name: "with-fixed",
        vars: WITH_FIXED_VARS,
        relations: |_| Vec::new(),
    };

    async fn checked_handle(sections: &[&'static Section]) -> ConfigurationHandle {
        struct Parent;
        #[ractor::async_trait]
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
        let mut builder = Config::builder(&env);
        for section in sections {
            builder = builder.register(section);
        }
        ConfigurationHandle::spawn(None, AGENT, builder.build(), None, parent.get_cell())
            .await
            .unwrap()
    }

    /// A Dynamic variable nothing follows is named, and one followed is not.
    #[tokio::test]
    async fn the_shared_check_fails_a_dynamic_variable_nothing_follows() {
        let config = checked_handle(&[&CHECKED]).await;
        let problems = config.dynamic_settings_problems(&[&CHECKED]).await.unwrap();
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(problems.iter().any(|p| p.contains("SAID")), "{problems:?}");
        assert!(problems.iter().any(|p| p.contains("COUNT")), "{problems:?}");

        let (actor, _) = keeper::<String>().await;
        config.follow(&SAID, &actor, |v| v).await.unwrap();
        let (counter, _) = keeper::<u64>().await;
        config.follow(&COUNT, &counter, |v| v).await.unwrap();
        assert_eq!(
            config.dynamic_settings_problems(&[&CHECKED]).await.unwrap(),
            Vec::<String>::new()
        );

        counter.stop_and_wait(None, None).await.unwrap();
        let problems = config.dynamic_settings_problems(&[&CHECKED]).await.unwrap();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("COUNT"), "{problems:?}");
    }

    /// A group that says it follows a variable and whose value does not depend on it is found out.
    #[tokio::test]
    async fn the_shared_check_fails_a_follower_whose_value_ignores_the_variable() {
        let config = checked_handle(&[&CHECKED]).await;
        let (actor, _) = keeper::<u64>().await;
        let names: [&dyn Described; 2] = [&SAID, &COUNT];
        config
            .follow_group(
                &names,
                |c: &Config| c.read(&COUNT).map_err(|e| e.to_string()),
                &actor,
                |v| v,
            )
            .await
            .unwrap();
        let problems = config.dynamic_settings_problems(&[&CHECKED]).await.unwrap();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("SAID"), "{problems:?}");
        assert!(problems[0].contains("does not depend"), "{problems:?}");
    }

    /// Text with no example cannot be changed by a test, and that is said rather than passed over.
    #[tokio::test]
    async fn the_shared_check_fails_a_variable_it_cannot_change() {
        let config = checked_handle(&[&NO_EXAMPLE]).await;
        let (actor, _) = keeper::<String>().await;
        config.follow(&PHRASE, &actor, |v| v).await.unwrap();
        let problems = config
            .dynamic_settings_problems(&[&NO_EXAMPLE])
            .await
            .unwrap();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("example"), "{problems:?}");
    }

    /// Following a Static variable is a mistake: no update can reach it.
    #[tokio::test]
    async fn the_shared_check_fails_following_a_static_variable() {
        let config = checked_handle(&[&WITH_FIXED]).await;
        let (actor, _) = keeper::<u64>().await;
        config.follow(&FIXED, &actor, |v| v).await.unwrap();
        let problems = config
            .dynamic_settings_problems(&[&WITH_FIXED])
            .await
            .unwrap();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("FIXED"), "{problems:?}");
        assert!(problems[0].contains("static"), "{problems:?}");
    }
}
