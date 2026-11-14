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

//! The store's side of the witness (docs/architecture/record-store.md, "Bite 5"): at most once a second, each log that
//! grew since its last co-signed checkpoint has its checkpoint signed and brought to the attestation agent's witness as
//! tlog-witness's add-checkpoint, over Cassini; a co-signature that verifies under the pinned witness key is kept and
//! served. The witness's key is a Dynamic setting, signed at run time; until it is pinned, nothing is submitted.
//!
//! What it holds to: one submission in flight per log; an answer counts only from the witness the key names, for the
//! submission in flight, about the checkpoint submitted; a conflict is submitted again once, from the witness's size;
//! a refusal on consistency, or a rollback seen after that retry, is said as an error each time.

use crate::logs::LogsMessage;
use crate::logs::Submission;
use attestation_common::witness::{
    AddCheckpoint, Answer, Envelope, Refusal, WITNESS_REQUESTS_TOPIC, Witnessed, decode_witnessed,
    encode_add_checkpoint,
};
use polar_env::Described;
use polar_log::checkpoint::NoteVerifier;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

/// How often a log that grew is submitted: at most once a second, while entries arrive (decided 2026-11-11).
pub const CADENCE: Duration = Duration::from_secs(1);

/// The cadence's name, as the agent's topics give it as the cause of a submission.
pub const CADENCE_NAME: &str = "witness-cadence";

/// How long a submission waits for its answer before the witness is taken to be away and it is submitted again.
pub const PATIENCE: Duration = Duration::from_secs(10);

/// The suffix of a witness key's name after the witness's identity (runtime-attestation.md, "The witness of the store's
/// logs").
pub const WITNESS_KEY_SUFFIX: &str = "/witness";

pub use crate::settings::WITNESS_KEY;

/// A submission in flight.
#[derive(Debug, Clone)]
struct Pending {
    correlation: String,
    size: u64,
    checkpoint: String,
    sent: Instant,
    /// Submitted again after a conflict.
    retried: bool,
}

/// What an answer asks of the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Keep the co-signature over the checkpoint submitted.
    Keep { checkpoint: String, line: String },
    /// Submit again, from the size the witness holds.
    Resubmit { old: u64 },
}

/// The pinned witness, and each log's submission in flight and what the store believes the witness holds.
pub struct Witnessing {
    origin: String,
    witness: Option<(NoteVerifier, String)>,
    believed: BTreeMap<String, u64>,
    pending: BTreeMap<String, Pending>,
    away: BTreeMap<String, bool>,
    unpinned_said: bool,
    sent: u64,
}

impl Witnessing {
    /// For the store whose checkpoints name `origin/<log>`.
    pub fn new(origin: &str) -> Self {
        Self {
            origin: origin.to_string(),
            witness: None,
            believed: BTreeMap::new(),
            pending: BTreeMap::new(),
            away: BTreeMap::new(),
            unpinned_said: false,
            sent: 0,
        }
    }

    /// Pins the witness's verifier key, or unpins it. A key that is not a witness's is refused, and nothing is pinned.
    pub fn pin(&mut self, key: Option<&str>) -> Result<(), String> {
        self.pending.clear();
        self.witness = None;
        let Some(key) = key else {
            return Ok(());
        };
        let verifier = NoteVerifier::parse(key).map_err(|e| e.to_string())?;
        if !verifier.is_cosigner() {
            return Err(format!("{} is not a co-signer's key", verifier.name()));
        }
        let identity = verifier
            .name()
            .strip_suffix(WITNESS_KEY_SUFFIX)
            .filter(|identity| !identity.is_empty())
            .ok_or_else(|| format!("{} does not name a witness's key", verifier.name()))?
            .to_string();
        self.witness = Some((verifier, identity));
        self.unpinned_said = false;
        Ok(())
    }

    /// Whether the witness is away for `log`: it did not answer, or refused it as unknown, since it last co-signed.
    pub fn away(&self, log: &str) -> bool {
        self.away.get(log).copied().unwrap_or(false)
    }

    /// The pinned witness's key.
    pub fn witness(&self) -> Option<&NoteVerifier> {
        self.witness.as_ref().map(|(key, _)| key)
    }

    /// The logs to submit now, each from the size the witness is believed to hold, given each log's size and its latest
    /// co-signed size. A submission unanswered past `PATIENCE` is given up: the witness is away.
    pub fn due(&mut self, now: Instant, logs: &[(String, u64, Option<u64>)]) -> Vec<(String, u64)> {
        if self.witness.is_none() {
            if !self.unpinned_said {
                warn!(
                    "no witness key is pinned: the logs are not witnessed, and readers are served no checkpoint"
                );
                self.unpinned_said = true;
            }
            return Vec::new();
        }
        let mut due = Vec::new();
        for (name, size, cosigned) in logs {
            if let Some(pending) = self.pending.get(name) {
                if now.duration_since(pending.sent) < PATIENCE {
                    continue;
                }
                self.said_away(name, "the witness did not answer");
                self.pending.remove(name);
            }
            if *cosigned == Some(*size) {
                continue;
            }
            let believed = *self
                .believed
                .entry(name.clone())
                .or_insert(cosigned.unwrap_or(0));
            due.push((name.clone(), believed));
        }
        due
    }

    /// Records the submission of `log`'s signed checkpoint: the request to publish.
    pub fn sent(
        &mut self,
        log: &str,
        submission: Submission,
        now: Instant,
        retried: bool,
    ) -> Vec<u8> {
        let Submission {
            old,
            proof,
            checkpoint,
            size,
        } = submission;
        self.sent += 1;
        let correlation = format!("{log}-{}", self.sent);
        self.pending.insert(
            log.to_string(),
            Pending {
                correlation: correlation.clone(),
                size,
                checkpoint: checkpoint.clone(),
                sent: now,
                retried,
            },
        );
        encode_add_checkpoint(&Envelope {
            correlation_id: correlation,
            payload: AddCheckpoint {
                old,
                proof,
                checkpoint,
            },
        })
    }

    /// Records that `log`'s co-signed checkpoint of `size` leaves is kept: whether it covers more than the one before.
    pub fn kept(&mut self, log: &str, size: u64) -> bool {
        let grew = self
            .believed
            .insert(log.to_string(), size)
            .is_none_or(|was| was < size);
        if self.away.insert(log.to_string(), false) == Some(true) {
            info!(log, size, "the witness co-signs again");
        }
        grew
    }

    /// What an answer published by `published_by` asks: the log it is about and the step, or nothing (it is not the
    /// witness's, not about a submission in flight, or a refusal, said here).
    pub fn answered(
        &mut self,
        published_by: Option<&str>,
        payload: &[u8],
    ) -> Option<(String, Step, bool)> {
        let (_, identity) = self.witness.as_ref()?;
        if published_by != Some(identity.as_str()) {
            warn!(
                from = ?published_by,
                "an answer on the witness's reply topic not from the pinned witness is dropped"
            );
            return None;
        }
        let envelope: Envelope<Witnessed> = match decode_witnessed(payload) {
            Ok(envelope) => envelope,
            Err(why) => {
                warn!(%why, "the witness's answer does not decode");
                return None;
            }
        };
        let (log, pending) = self
            .pending
            .iter()
            .find(|(_, p)| p.correlation == envelope.correlation_id)
            .map(|(log, p)| (log.clone(), p.clone()))?;
        let Witnessed {
            origin,
            size,
            answer,
        } = envelope.payload;
        if origin.as_deref() != Some(format!("{}/{log}", self.origin).as_str())
            || size != Some(pending.size)
        {
            debug!(
                log,
                ?origin,
                ?size,
                "an answer about another checkpoint is dropped"
            );
            return None;
        }
        self.pending.remove(&log);
        match answer {
            Answer::Cosigned(line) => Some((
                log,
                Step::Keep {
                    checkpoint: pending.checkpoint,
                    line,
                },
                false,
            )),
            Answer::Conflict(held) if !pending.retried => {
                info!(
                    log,
                    held, "the witness holds another size: submitted again from it"
                );
                self.believed.insert(log.clone(), held);
                Some((log, Step::Resubmit { old: held }, true))
            }
            Answer::Conflict(held) => {
                error!(
                    log,
                    held, "the witness holds another size again, after a retry from its own"
                );
                None
            }
            Answer::Refused(why @ (Refusal::UnknownOrigin | Refusal::Untrusted)) => {
                self.said_away(&log, &format!("{why}: is each key pinned in the other?"));
                None
            }
            Answer::Refused(Refusal::Malformed) if pending.retried => {
                error!(
                    log,
                    size = pending.size,
                    "the witness co-signed more of this log than it holds: a rollback of the store's log"
                );
                None
            }
            Answer::Refused(why) => {
                error!(log, size = pending.size, %why, "the witness refused the store's checkpoint");
                None
            }
        }
    }

    fn said_away(&mut self, log: &str, why: &str) {
        if self.away.insert(log.to_string(), true) != Some(true) {
            warn!(
                log,
                why, "the log is not witnessed: its last co-signed checkpoint is served"
            );
        }
    }
}

/// What the witness client is told.
pub enum WitnessMessage {
    /// The cadence: submit each log that grew.
    Tick,
    /// The witness's key, as signed now.
    Key(Option<String>),
    /// An answer on the store's reply topic.
    Answer {
        payload: Vec<u8>,
        published_by: Option<String>,
    },
}

pub struct WitnessActor;

pub struct WitnessArgs {
    pub origin: String,
    pub logs: ractor::ActorRef<LogsMessage>,
    pub client: ractor::ActorRef<cassini_client::TcpClientMessage>,
    pub configuration: polar_agent_builder::ConfigurationHandle,
}

pub struct WitnessState {
    witnessing: Witnessing,
    logs: ractor::ActorRef<LogsMessage>,
    client: ractor::ActorRef<cassini_client::TcpClientMessage>,
}

impl WitnessState {
    /// Says that `log` is witnessed to `size` leaves, so its readers read what they may now see.
    fn announce(&self, log: &str, size: u64) {
        let event = polar_git_server_common::LogWitnessed {
            log: log.to_string(),
            size,
        };
        if let Err(e) = self
            .client
            .send_message(cassini_client::TcpClientMessage::publish(
                polar_git_server_common::LOG_WITNESSED_TOPIC.to_string(),
                polar_git_server_common::encode_witnessed(&event),
                None,
            ))
        {
            warn!(log, size, error = %e, "cannot say the log is witnessed");
        }
    }

    /// Signs `log`'s checkpoint now and brings it to the witness, from `old`.
    async fn submit(&mut self, log: &str, old: u64, retried: bool) {
        let submission = match ractor::call!(self.logs, |reply| LogsMessage::Submission {
            log: log.to_string(),
            old,
            reply
        }) {
            Ok(Ok(submission)) => submission,
            Ok(Err(why)) => {
                error!(log, old, %why, "the store cannot prove its log from the size the witness holds");
                return;
            }
            Err(e) => {
                error!(log, error = %e, "the store's logs did not answer");
                return;
            }
        };
        let payload = self
            .witnessing
            .sent(log, submission, Instant::now(), retried);
        if let Err(e) = self
            .client
            .send_message(cassini_client::TcpClientMessage::publish(
                WITNESS_REQUESTS_TOPIC.to_string(),
                payload,
                None,
            ))
        {
            error!(log, error = %e, "cannot bring the checkpoint to the witness");
        }
    }
}

#[ractor::async_trait]
impl ractor::Actor for WitnessActor {
    type Msg = WitnessMessage;
    type State = WitnessState;
    type Arguments = WitnessArgs;

    async fn pre_start(
        &self,
        myself: ractor::ActorRef<Self::Msg>,
        args: WitnessArgs,
    ) -> Result<Self::State, ractor::ActorProcessingErr> {
        let mut witnessing = Witnessing::new(&args.origin);
        let key = args
            .configuration
            .follow(&WITNESS_KEY, &myself, WitnessMessage::Key)
            .await
            .map_err(|e| format!("cannot follow {}: {e}", WITNESS_KEY.desc().name))?;
        if let Err(why) = witnessing.pin(key.as_deref()) {
            warn!(%why, "the witness key signed is not one: nothing is witnessed until it is");
        }
        // A checkpoint at the store's start, then at most once a second.
        myself.send_message(WitnessMessage::Tick)?;
        myself.send_interval(CADENCE, || WitnessMessage::Tick);
        Ok(WitnessState {
            witnessing,
            logs: args.logs,
            client: args.client,
        })
    }

    async fn handle(
        &self,
        _: ractor::ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ractor::ActorProcessingErr> {
        match message {
            WitnessMessage::Tick => {
                let logs = match ractor::call!(state.logs, LogsMessage::Witnessing) {
                    Ok(logs) => logs,
                    Err(e) => {
                        error!(error = %e, "the store's logs did not answer");
                        return Ok(());
                    }
                };
                for (log, old) in state.witnessing.due(Instant::now(), &logs) {
                    state.submit(&log, old, false).await;
                }
            }
            WitnessMessage::Key(key) => match state.witnessing.pin(key.as_deref()) {
                Ok(()) => info!(pinned = key.is_some(), "the witness key changed"),
                Err(why) => {
                    warn!(%why, "the witness key signed is not one: nothing is witnessed until it is")
                }
            },
            WitnessMessage::Answer {
                payload,
                published_by,
            } => {
                let Some((log, step, retried)) =
                    state.witnessing.answered(published_by.as_deref(), &payload)
                else {
                    return Ok(());
                };
                match step {
                    Step::Resubmit { old } => state.submit(&log, old, retried).await,
                    Step::Keep { checkpoint, line } => {
                        let Some(witness) = state.witnessing.witness().cloned() else {
                            return Ok(());
                        };
                        match ractor::call!(state.logs, |reply| LogsMessage::KeepCosigned {
                            log: log.clone(),
                            checkpoint,
                            line,
                            witness,
                            reply
                        }) {
                            Ok(Ok(size)) => {
                                if state.witnessing.kept(&log, size) {
                                    state.announce(&log, size);
                                }
                            }
                            Ok(Err(why)) => {
                                error!(log, %why, "the witness's co-signature is not kept")
                            }
                            Err(e) => error!(log, error = %e, "the store's logs did not answer"),
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attestation_common::witness::encode_witnessed;
    use p256::ecdsa::SigningKey;
    use polar_log::checkpoint::Cosigner;

    const ORIGIN: &str = "polar-git-server.polar.serviceaccount.cluster.local";
    const IDENTITY: &str = "attestation-agent.polar.serviceaccount.cluster.local";

    fn key() -> String {
        Cosigner::new(
            &format!("{IDENTITY}{WITNESS_KEY_SUFFIX}"),
            SigningKey::from_slice(&[9; 32]).unwrap(),
        )
        .unwrap()
        .verifier_key()
    }

    fn pinned() -> Witnessing {
        let mut w = Witnessing::new(ORIGIN);
        w.pin(Some(&key())).unwrap();
        w
    }

    fn answer(correlation: &str, size: u64, answer: Answer) -> Vec<u8> {
        encode_witnessed(&Envelope {
            correlation_id: correlation.to_string(),
            payload: Witnessed {
                origin: Some(format!("{ORIGIN}/evidence")),
                size: Some(size),
                answer,
            },
        })
    }

    fn sub(old: u64, proof: Vec<[u8; 32]>, checkpoint: &str, size: u64) -> Submission {
        Submission {
            old,
            proof,
            checkpoint: checkpoint.to_string(),
            size,
        }
    }

    fn evidence(size: u64, cosigned: Option<u64>) -> Vec<(String, u64, Option<u64>)> {
        vec![("evidence".to_string(), size, cosigned)]
    }

    #[test]
    fn nothing_is_submitted_until_a_witness_key_is_pinned_and_only_a_witness_s_is() {
        let mut w = Witnessing::new(ORIGIN);
        assert!(w.due(Instant::now(), &evidence(3, None)).is_empty());
        let checkpoint_key = polar_log::checkpoint::NoteSigner::new(
            &format!("{IDENTITY}{WITNESS_KEY_SUFFIX}"),
            SigningKey::from_slice(&[9; 32]).unwrap(),
        )
        .unwrap()
        .verifier_key();
        // A checkpoint key, or a co-signer's not named for a witness, is not pinned.
        assert!(w.pin(Some(&checkpoint_key)).is_err());
        let other = Cosigner::new("someone/else", SigningKey::from_slice(&[9; 32]).unwrap())
            .unwrap()
            .verifier_key();
        assert!(w.pin(Some(&other)).is_err());
        assert!(w.witness().is_none());
        assert!(w.pin(Some("not a key")).is_err());
        w.pin(Some(&key())).unwrap();
        assert_eq!(
            w.witness().map(NoteVerifier::name),
            Some(format!("{IDENTITY}{WITNESS_KEY_SUFFIX}").as_str())
        );
        assert_eq!(
            w.due(Instant::now(), &evidence(3, None)),
            [("evidence".to_string(), 0)]
        );
        w.pin(None).unwrap();
        assert!(w.due(Instant::now(), &evidence(3, None)).is_empty());
    }

    /// A log already co-signed at its size is not submitted; one that grew is, from the size co-signed; one in flight is
    /// not, until the witness has been given `PATIENCE` to answer.
    #[test]
    fn a_log_is_submitted_when_it_grew_once_at_a_time_and_again_when_unanswered() {
        let mut w = pinned();
        let now = Instant::now();
        assert!(w.due(now, &evidence(3, Some(3))).is_empty());
        assert_eq!(
            w.due(now, &evidence(5, Some(3))),
            [("evidence".to_string(), 3)]
        );
        w.sent("evidence", sub(3, vec![], "note", 5), now, false);
        assert!(
            w.due(
                now + PATIENCE - Duration::from_millis(1),
                &evidence(6, Some(3))
            )
            .is_empty()
        );
        assert!(!w.away("evidence"));
        assert_eq!(
            w.due(now + PATIENCE, &evidence(6, Some(3))),
            [("evidence".to_string(), 3)]
        );
        assert!(
            w.away("evidence"),
            "unanswered past PATIENCE, the witness is away"
        );
        w.kept("evidence", 6);
        assert!(!w.away("evidence"), "co-signed again, it is back");
    }

    /// What a Cassini client is asked to publish, kept by topic.
    struct Published;

    #[ractor::async_trait]
    impl ractor::Actor for Published {
        type Msg = cassini_client::TcpClientMessage;
        type State = std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>;
        type Arguments = Self::State;
        async fn pre_start(
            &self,
            _: ractor::ActorRef<Self::Msg>,
            kept: Self::State,
        ) -> Result<Self::State, ractor::ActorProcessingErr> {
            Ok(kept)
        }
        async fn handle(
            &self,
            _: ractor::ActorRef<Self::Msg>,
            message: Self::Msg,
            kept: &mut Self::State,
        ) -> Result<(), ractor::ActorProcessingErr> {
            if let cassini_client::TcpClientMessage::Publish { topic, payload, .. } = message {
                kept.lock().unwrap().push((topic, payload));
            }
            Ok(())
        }
    }

    /// The announcement that a log is witnessed further names the log and its size, on the topic readers hear.
    #[tokio::test]
    async fn a_log_witnessed_further_is_announced_with_its_size() {
        let dir = tempfile::tempdir().unwrap();
        let kept = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (client, _) = ractor::Actor::spawn(None, Published, kept.clone())
            .await
            .unwrap();
        let (logs, _) = ractor::Actor::spawn(
            None,
            crate::logs::LogsActor,
            crate::logs::LogsArgs {
                root: dir.path().to_path_buf(),
                origin: ORIGIN.into(),
                signer: std::sync::Arc::new(crate::logs::testing::KeySigner::new(ORIGIN)),
            },
        )
        .await
        .unwrap();
        let state = WitnessState {
            witnessing: pinned(),
            logs,
            client,
        };
        state.announce("schedules", 21);
        for _ in 0..100 {
            if !kept.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let kept = kept.lock().unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].0, polar_git_server_common::LOG_WITNESSED_TOPIC);
        assert_eq!(
            polar_git_server_common::decode_witnessed(&kept[0].1).unwrap(),
            polar_git_server_common::LogWitnessed {
                log: "schedules".into(),
                size: 21
            }
        );
    }

    /// A kept co-signature is announced only when it covers more than the one before, so readers are told once per
    /// growth (docs/architecture/record-store.md, "Bite 6").
    #[test]
    fn a_kept_co_signature_is_news_only_when_it_covers_more() {
        let mut w = pinned();
        assert!(w.kept("evidence", 5));
        assert!(!w.kept("evidence", 5));
        assert!(w.kept("evidence", 6));
        assert!(w.kept("schedules", 1), "each log is its own");
    }

    /// A co-signature is kept only when it answers the submission in flight, about the checkpoint submitted, from the
    /// pinned witness.
    #[test]
    fn an_answer_counts_only_from_the_witness_for_what_is_in_flight() {
        let mut w = pinned();
        let now = Instant::now();
        w.due(now, &evidence(5, None));
        w.sent("evidence", sub(0, vec![], "the note", 5), now, false);
        let line = Answer::Cosigned("— line".to_string());
        assert_eq!(
            w.answered(Some("mallory"), &answer("evidence-1", 5, line.clone())),
            None
        );
        assert_eq!(
            w.answered(None, &answer("evidence-1", 5, line.clone())),
            None
        );
        assert_eq!(
            w.answered(Some(IDENTITY), &answer("evidence-9", 5, line.clone())),
            None
        );
        assert_eq!(
            w.answered(Some(IDENTITY), &answer("evidence-1", 4, line.clone())),
            None
        );
        assert_eq!(w.answered(Some(IDENTITY), b"not an answer"), None);
        let mut elsewhere = decode_witnessed(&answer("evidence-1", 5, line.clone())).unwrap();
        elsewhere.payload.origin = Some(format!("{ORIGIN}/schedules"));
        assert_eq!(
            w.answered(Some(IDENTITY), &encode_witnessed(&elsewhere)),
            None
        );
        assert_eq!(
            w.answered(Some(IDENTITY), &answer("evidence-1", 5, line.clone())),
            Some((
                "evidence".to_string(),
                Step::Keep {
                    checkpoint: "the note".to_string(),
                    line: "— line".to_string()
                },
                false
            ))
        );
        // Answered once: the same answer again is about nothing in flight.
        assert_eq!(
            w.answered(Some(IDENTITY), &answer("evidence-1", 5, line)),
            None
        );
        w.kept("evidence", 5);
        assert_eq!(
            w.due(now, &evidence(7, Some(5))),
            [("evidence".to_string(), 5)]
        );
    }

    /// A conflict is submitted again once, from the witness's size, and believed from then on; a second conflict is
    /// not followed.
    #[test]
    fn a_conflict_is_submitted_again_once_from_the_witness_s_size() {
        let mut w = pinned();
        let now = Instant::now();
        w.due(now, &evidence(5, None));
        w.sent("evidence", sub(0, vec![], "n", 5), now, false);
        assert_eq!(
            w.answered(
                Some(IDENTITY),
                &answer("evidence-1", 5, Answer::Conflict(2))
            ),
            Some(("evidence".to_string(), Step::Resubmit { old: 2 }, true))
        );
        w.sent("evidence", sub(2, vec![[1; 32]], "n", 5), now, true);
        assert_eq!(
            w.answered(
                Some(IDENTITY),
                &answer("evidence-2", 5, Answer::Conflict(3))
            ),
            None
        );
        // Believed from the first conflict: the next submission is from 2.
        assert_eq!(
            w.due(now, &evidence(5, None)),
            [("evidence".to_string(), 2)]
        );
    }

    /// A refusal keeps nothing and leaves nothing in flight, so the log is submitted again at the next tick.
    #[test]
    fn a_refusal_keeps_nothing_and_the_log_is_submitted_again() {
        for (refusal, retried) in [
            (Refusal::UnknownOrigin, false),
            (Refusal::Untrusted, false),
            (Refusal::Malformed, false),
            (Refusal::Malformed, true),
            (Refusal::Inconsistent, false),
        ] {
            let mut w = pinned();
            let now = Instant::now();
            w.due(now, &evidence(5, Some(1)));
            w.sent("evidence", sub(1, vec![], "n", 5), now, retried);
            assert_eq!(
                w.answered(
                    Some(IDENTITY),
                    &answer("evidence-1", 5, Answer::Refused(refusal))
                ),
                None,
                "{refusal:?}"
            );
            assert_eq!(
                w.due(now, &evidence(5, Some(1))),
                [("evidence".to_string(), 1)],
                "{refusal:?}"
            );
            // Refused as unknown, the witness is away: the keys are not pinned in each other.
            assert_eq!(
                w.away("evidence"),
                matches!(refusal, Refusal::UnknownOrigin | Refusal::Untrusted),
                "{refusal:?}"
            );
        }
    }
}
