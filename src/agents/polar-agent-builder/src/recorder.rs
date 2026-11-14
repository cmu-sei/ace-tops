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

//! Getting an agent's evidence records into `polar-evidence` (docs/architecture/record-store.md, "Attestation verdicts as
//! records"): each is signed with the agent's [`RecordSigner`] (the pod's signing key, through its crypto actor) and sent
//! to the git server over Cassini, one at a time and in the order they were
//! made. A record the server cannot take now is kept and sent again, within a bound
//! ([`BOUND`]); one past the bound, or one the server or the signer refuses for good, is logged at ERROR, never lost
//! silently.
//!
//! [`Outbox`] is the rule, a pure state machine over the clock it is given; [`Recorder`] is the actor around it, which signs
//! through the builder's signer and publishes through the Cassini client.

use crate::signer::{EvidenceRecord, RecordSigner, SignError};
use polar_git_server_common::{AddRecord, Envelope, RecordAdded, decode_added, encode_add};
use ractor::{Actor, ActorProcessingErr, ActorRef};
use std::collections::VecDeque;
use std::sync::Arc;
use tracing::{error, info, warn};

/// The most records kept unsent. A day of standings and a crash a minute for hours fit; past it, what is new is dropped,
/// at ERROR, so the oldest evidence is kept.
pub const BOUND: usize = 1000;

/// How long an answer is waited for before the record is sent again (seconds).
pub const ANSWER_WAIT_SECS: i64 = 30;

/// How long the head waits before it is tried again, when the server could not take it now or the signer could not be
/// asked (seconds).
pub const RETRY_SECS: i64 = 30;

struct Kept {
    record: EvidenceRecord,
    /// The signed document as it is sent: once signed, the same bytes every time, so a record the server took before its
    /// answer was lost is found there already.
    signed: Option<String>,
}

/// What to do next.
#[derive(Debug, Clone, PartialEq)]
pub enum Next {
    /// Nothing now: nothing kept, an answer awaited, or a retry not yet due.
    Wait,
    /// Sign the record at the head.
    Sign(EvidenceRecord),
    /// Send the record at the head, signed, under this correlation id.
    Send {
        correlation_id: String,
        signed: String,
    },
}

/// What an answer came to.
#[derive(Debug, Clone, PartialEq)]
pub enum Answered {
    /// The server holds `record`, at `path`.
    Taken {
        path: String,
        record: EvidenceRecord,
    },
    /// The server will never take it as it is: dropped.
    Refused { why: String },
    /// The server could not take it now: it is sent again later.
    NotNow { why: String },
    /// An answer to no request awaited now (a late one, or another's): nothing changes.
    NotAwaited,
}

/// The records waiting to go, in order, and the one in flight.
pub struct Outbox {
    kept: VecDeque<Kept>,
    bound: usize,
    in_flight: Option<(String, i64)>,
    not_before: i64,
    prefix: String,
    sent: u64,
}

impl Outbox {
    /// An empty outbox keeping at most `bound` records, its correlation ids starting `prefix`.
    pub fn new(bound: usize, prefix: impl Into<String>) -> Self {
        Self {
            kept: VecDeque::new(),
            bound,
            in_flight: None,
            not_before: i64::MIN,
            prefix: prefix.into(),
            sent: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.kept.len()
    }

    pub fn is_empty(&self) -> bool {
        self.kept.is_empty()
    }

    /// Keeps `record` behind what is kept; past the bound it is given back, dropped.
    pub fn keep(&mut self, record: EvidenceRecord) -> Result<(), EvidenceRecord> {
        if self.kept.len() >= self.bound {
            return Err(record);
        }
        self.kept.push_back(Kept {
            record,
            signed: None,
        });
        Ok(())
    }

    /// What to do at `now` (seconds).
    pub fn next(&mut self, now: i64) -> Next {
        if let Some((_, sent_at)) = &self.in_flight {
            if now - sent_at < ANSWER_WAIT_SECS {
                return Next::Wait;
            }
            // No answer in time: sent again, under a new id, the same bytes.
            self.in_flight = None;
        }
        if now < self.not_before {
            return Next::Wait;
        }
        let Some(head) = self.kept.front() else {
            return Next::Wait;
        };
        match &head.signed {
            None => Next::Sign(head.record.clone()),
            Some(signed) => {
                self.sent += 1;
                let correlation_id = format!("{}-{}", self.prefix, self.sent);
                let signed = signed.clone();
                self.in_flight = Some((correlation_id.clone(), now));
                Next::Send {
                    correlation_id,
                    signed,
                }
            }
        }
    }

    /// The head is signed, as `signed`.
    pub fn signed(&mut self, signed: String) {
        if let Some(head) = self.kept.front_mut() {
            head.signed = Some(signed);
        }
    }

    /// The head could not be signed: for good (`permanent`), when it is dropped and given back, or for now, when it is tried
    /// again later.
    pub fn not_signed(&mut self, permanent: bool, now: i64) -> Option<EvidenceRecord> {
        if permanent {
            return self.kept.pop_front().map(|kept| kept.record);
        }
        self.not_before = now + RETRY_SECS;
        None
    }

    /// The head could not be handed to the Cassini client: it is sent again later.
    pub fn not_sent(&mut self, now: i64) {
        self.in_flight = None;
        self.not_before = now + RETRY_SECS;
    }

    /// The server's answer to `correlation_id`, at `now`.
    pub fn answered(&mut self, correlation_id: &str, added: RecordAdded, now: i64) -> Answered {
        if self.in_flight.as_ref().map(|(id, _)| id.as_str()) != Some(correlation_id) {
            return Answered::NotAwaited;
        }
        self.in_flight = None;
        match added {
            RecordAdded::Committed { path, .. } | RecordAdded::AlreadyThere { path } => {
                match self.kept.pop_front() {
                    Some(kept) => Answered::Taken {
                        path,
                        record: kept.record,
                    },
                    None => Answered::NotAwaited,
                }
            }
            RecordAdded::Refused { why } => {
                self.kept.pop_front();
                Answered::Refused { why }
            }
            RecordAdded::NotNow { why } => {
                self.not_before = now + RETRY_SECS;
                Answered::NotNow { why }
            }
        }
    }
}

/// Hands a request's bytes to the agent's Cassini client, for the git server's request topic.
pub type Publish = Arc<dyn Fn(Vec<u8>) -> Result<(), String> + Send + Sync>;

/// Told of each record once the git server holds it, and where: for an agent that remembers what it has recorded.
pub type Taken = Arc<dyn Fn(EvidenceRecord, String) + Send + Sync>;

pub enum RecorderMessage {
    /// A record to get into `polar-evidence`.
    Keep(EvidenceRecord),
    /// Something arrived on the agent's evidence reply topic, published (the broker says) by `published_by`.
    Answer {
        payload: Vec<u8>,
        published_by: Option<String>,
    },
    /// Time to look whether something is due.
    Tick,
}

pub struct RecorderArgs {
    pub signer: Arc<dyn RecordSigner>,
    pub publish: Publish,
    /// The git server's identity: an answer counts only from it.
    pub server: String,
    /// What its correlation ids start with, so a restarted agent's are not its predecessor's.
    pub prefix: String,
    pub clock: fn() -> i64,
    /// Told of each record the server holds; none, and it is only logged.
    pub taken: Option<Taken>,
}

pub struct RecorderState {
    outbox: Outbox,
    args: RecorderArgs,
}

/// How often it looks whether something is due.
pub const TICK: std::time::Duration = std::time::Duration::from_secs(5);

/// The git server's identity in the agent's own namespace and domain, from the agent's own `<workload>.<namespace>.
/// serviceaccount.<domain>`, as an asker finds the attestation agent's.
pub fn server_identity(own_identity: &str) -> Option<String> {
    let workload = cert_issuer_common::identity::workload_of(own_identity)?;
    Some(format!(
        "polar-git-server{}",
        &own_identity[workload.len()..]
    ))
}

/// The bytes a signed record is sent as: the document as JSON, as `polar-sign` writes one.
fn text_of(document: &polar_signing::Document) -> String {
    let text =
        serde_json::to_string_pretty(&document.to_value()).expect("a signed document is JSON");
    format!("{text}\n")
}

fn about(record: &EvidenceRecord) -> String {
    format!(
        "{} {}",
        record.payload()["type"].as_str().unwrap_or("?"),
        record.payload()["subject"]
    )
}

pub struct Recorder;

impl Recorder {
    /// Does what is due, until it has to wait.
    async fn drive(state: &mut RecorderState) {
        loop {
            let now = (state.args.clock)();
            match state.outbox.next(now) {
                Next::Wait => return,
                Next::Sign(record) => match state.args.signer.sign(record).await {
                    Ok(document) => state.outbox.signed(text_of(&document)),
                    Err(SignError::Refused(why)) => {
                        if let Some(dropped) = state.outbox.not_signed(true, now) {
                            error!(
                                "an evidence record was dropped, since it may not be signed: {why}: {}",
                                about(&dropped)
                            );
                        }
                    }
                    Err(SignError::Unavailable(why)) => {
                        warn!("an evidence record could not be signed now, and is kept: {why}");
                        state.outbox.not_signed(false, now);
                        return;
                    }
                },
                Next::Send {
                    correlation_id,
                    signed,
                } => {
                    let request = encode_add(&Envelope {
                        correlation_id,
                        payload: AddRecord { record: signed },
                    });
                    if let Err(why) = (state.args.publish)(request) {
                        warn!("an evidence record could not be sent now, and is kept: {why}");
                        state.outbox.not_sent(now);
                    }
                    return;
                }
            }
        }
    }
}

#[ractor::async_trait]
impl Actor for Recorder {
    type Msg = RecorderMessage;
    type State = RecorderState;
    type Arguments = RecorderArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: RecorderArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        myself.send_interval(TICK, || RecorderMessage::Tick);
        Ok(RecorderState {
            outbox: Outbox::new(BOUND, args.prefix.clone()),
            args,
        })
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            RecorderMessage::Keep(record) => {
                if let Err(dropped) = state.outbox.keep(record) {
                    error!(
                        "an evidence record was dropped: {BOUND} wait to be sent already: {}",
                        about(&dropped)
                    );
                }
            }
            RecorderMessage::Answer {
                payload,
                published_by,
            } => {
                if published_by.as_deref() != Some(state.args.server.as_str()) {
                    warn!(
                        publisher = published_by.as_deref().unwrap_or("unverified"),
                        "dropped an answer about an evidence record that is not the git server's"
                    );
                    return Ok(());
                }
                let envelope = match decode_added(&payload) {
                    Ok(envelope) => envelope,
                    Err(why) => {
                        warn!("dropped an answer about an evidence record: {why}");
                        return Ok(());
                    }
                };
                let now = (state.args.clock)();
                match state
                    .outbox
                    .answered(&envelope.correlation_id, envelope.payload, now)
                {
                    Answered::Taken { path, record } => {
                        info!(path, "an evidence record is in polar-evidence");
                        if let Some(taken) = &state.args.taken {
                            taken(record, path);
                        }
                    }
                    Answered::Refused { why } => {
                        error!("the git server refused an evidence record, which is dropped: {why}")
                    }
                    Answered::NotNow { why } => {
                        warn!(
                            "the git server could not take an evidence record now, and it is kept: {why}"
                        )
                    }
                    Answered::NotAwaited => {}
                }
            }
            RecorderMessage::Tick => {}
        }
        Self::drive(state).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;
    use std::sync::Mutex;

    fn record(n: u64) -> EvidenceRecord {
        let fields = match json!({ "subject": { "n": n.to_string() } }) {
            serde_json::Value::Object(fields) => fields,
            _ => unreachable!(),
        };
        EvidenceRecord::new("attestation-report", fields).unwrap()
    }

    fn n_of(record: &EvidenceRecord) -> u64 {
        record.payload()["subject"]["n"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap()
    }

    fn committed(path: &str) -> RecordAdded {
        RecordAdded::Committed {
            path: path.into(),
            commit: "c".into(),
        }
    }

    #[test]
    fn records_go_in_order_one_at_a_time_and_each_is_signed_once() {
        let mut outbox = Outbox::new(10, "p");
        outbox.keep(record(1)).unwrap();
        outbox.keep(record(2)).unwrap();
        let Next::Sign(first) = outbox.next(0) else {
            panic!()
        };
        assert_eq!(n_of(&first), 1);
        outbox.signed("one".into());
        let Next::Send {
            correlation_id,
            signed,
        } = outbox.next(0)
        else {
            panic!()
        };
        assert_eq!(signed, "one");
        assert_eq!(outbox.next(1), Next::Wait, "one in flight at a time");
        // No answer in time: the same bytes again, under another id.
        let Next::Send {
            correlation_id: again,
            signed,
        } = outbox.next(ANSWER_WAIT_SECS)
        else {
            panic!()
        };
        assert_eq!(signed, "one");
        assert_ne!(again, correlation_id);
        assert_eq!(
            outbox.answered(&correlation_id, committed("a"), 31),
            Answered::NotAwaited,
            "a late answer"
        );
        assert_eq!(
            outbox.answered(&again, RecordAdded::AlreadyThere { path: "a".into() }, 31),
            Answered::Taken {
                path: "a".into(),
                record: record(1)
            }
        );
        let Next::Sign(second) = outbox.next(31) else {
            panic!()
        };
        assert_eq!(n_of(&second), 2);
    }

    #[test]
    fn not_now_waits_and_goes_again_and_a_refusal_drops_it() {
        let mut outbox = Outbox::new(10, "p");
        outbox.keep(record(1)).unwrap();
        outbox.keep(record(2)).unwrap();
        outbox.next(0);
        outbox.signed("one".into());
        let Next::Send { correlation_id, .. } = outbox.next(0) else {
            panic!()
        };
        assert!(matches!(
            outbox.answered(
                &correlation_id,
                RecordAdded::NotNow { why: "disk".into() },
                1
            ),
            Answered::NotNow { .. }
        ));
        assert_eq!(outbox.next(1 + RETRY_SECS - 1), Next::Wait);
        let Next::Send {
            correlation_id,
            signed,
        } = outbox.next(1 + RETRY_SECS)
        else {
            panic!()
        };
        assert_eq!(signed, "one");
        assert_eq!(
            outbox.answered(
                &correlation_id,
                RecordAdded::Refused { why: "no".into() },
                40
            ),
            Answered::Refused { why: "no".into() }
        );
        assert_eq!(outbox.len(), 1);
    }

    #[test]
    fn past_the_bound_what_is_new_is_given_back_and_a_record_the_signer_refuses_is_dropped() {
        let mut outbox = Outbox::new(2, "p");
        outbox.keep(record(1)).unwrap();
        outbox.keep(record(2)).unwrap();
        assert_eq!(outbox.keep(record(3)).map_err(|r| n_of(&r)), Err(3));
        outbox.next(0);
        assert!(outbox.not_signed(false, 0).is_none());
        assert_eq!(outbox.next(RETRY_SECS - 1), Next::Wait);
        assert!(matches!(outbox.next(RETRY_SECS), Next::Sign(_)));
        assert_eq!(
            outbox.not_signed(true, RETRY_SECS).map(|r| n_of(&r)),
            Some(1)
        );
        assert_eq!(outbox.len(), 1);
    }

    #[test]
    fn the_server_is_the_git_server_of_the_agent_s_own_namespace() {
        assert_eq!(
            server_identity("attestation-agent.polar.serviceaccount.cluster.local").as_deref(),
            Some("polar-git-server.polar.serviceaccount.cluster.local")
        );
        assert_eq!(server_identity("not an identity"), None);
    }

    #[derive(Debug, Clone)]
    enum Event {
        Keep,
        Tick(i64),
        Signed,
        NotSigned(bool),
        NotSent,
        Answer(u8, bool),
    }

    fn an_event() -> impl Strategy<Value = Event> {
        prop_oneof![
            Just(Event::Keep),
            (0i64..40).prop_map(Event::Tick),
            Just(Event::Signed),
            any::<bool>().prop_map(Event::NotSigned),
            Just(Event::NotSent),
            (0u8..4, any::<bool>()).prop_map(|(k, stale)| Event::Answer(k, stale)),
        ]
    }

    proptest! {
        // Over any sequence of events: what is kept never passes the bound; records are first sent in the order they were
        // kept, each only once all before it are settled; and every record kept is, at the end, taken, refused, dropped (and
        // said) or still kept: none is lost silently.
        #[test]
        fn none_is_lost_and_they_go_in_order(events in prop::collection::vec(an_event(), 0..60)) {
            let mut outbox = Outbox::new(5, "p");
            let (mut made, mut now) = (0u64, 0i64);
            let mut settled: Vec<u64> = Vec::new();
            let mut dropped: Vec<u64> = Vec::new();
            let mut first_sent: Vec<u64> = Vec::new();
            let mut last: Option<(String, u64)> = None;
            for event in events {
                let head = outbox.kept.front().map(|k| n_of(&k.record));
                match event {
                    Event::Keep => {
                        made += 1;
                        if let Err(r) = outbox.keep(record(made)) {
                            dropped.push(n_of(&r));
                        }
                    }
                    Event::Tick(dt) => now += dt,
                    Event::Signed => if let Next::Sign(r) = outbox.next(now) {
                        outbox.signed(n_of(&r).to_string());
                    },
                    Event::NotSigned(permanent) => if let Next::Sign(_) = outbox.next(now)
                        && let Some(r) = outbox.not_signed(permanent, now)
                    {
                        dropped.push(n_of(&r));
                    },
                    Event::NotSent => if let Next::Send { .. } = outbox.next(now) {
                        outbox.not_sent(now);
                    },
                    Event::Answer(kind, stale) => {
                        if let Next::Send { correlation_id, signed } = outbox.next(now) {
                            let n: u64 = signed.parse().unwrap();
                            prop_assert_eq!(Some(n), head);
                            if !first_sent.contains(&n) {
                                first_sent.push(n);
                            }
                            last = Some((correlation_id, n));
                        }
                        if let Some((id, n)) = last.clone() {
                            let id = if stale { format!("{id}-stale") } else { id };
                            let added = match kind {
                                0 => committed("a"),
                                1 => RecordAdded::AlreadyThere { path: "a".into() },
                                2 => RecordAdded::Refused { why: "no".into() },
                                _ => RecordAdded::NotNow { why: "later".into() },
                            };
                            match outbox.answered(&id, added, now) {
                                Answered::Taken { .. } | Answered::Refused { .. } => {
                                    prop_assert!(!stale);
                                    settled.push(n);
                                    last = None;
                                }
                                Answered::NotNow { .. } => prop_assert!(!stale),
                                Answered::NotAwaited => {}
                            }
                        }
                    }
                }
                prop_assert!(outbox.len() <= 5);
            }
            // In order: each first sent after every record before it.
            prop_assert!(first_sent.windows(2).all(|w| w[0] < w[1]));
            // None lost: every record made is settled, dropped, or still kept, once.
            let mut accounted: Vec<u64> = settled.iter().chain(&dropped).copied()
                .chain(outbox.kept.iter().map(|k| n_of(&k.record))).collect();
            accounted.sort();
            prop_assert_eq!(accounted, (1..=made).collect::<Vec<_>>());
        }
    }

    // The actor against a stub server: a record is signed through the signer, sent, and settled by the server's answer;
    // an answer from anyone but the server changes nothing.
    struct Signs;

    #[ractor::async_trait]
    impl RecordSigner for Signs {
        async fn sign(&self, record: EvidenceRecord) -> Result<polar_signing::Document, SignError> {
            Ok(polar_signing::Document {
                payload: record.payload().clone(),
                signature: polar_signing::SignatureBlock {
                    algorithm: polar_signing::Algorithm::EcdsaP256Sha256,
                    value: vec![0; 64],
                    certificate_chain: vec![],
                },
            })
        }
    }

    const SERVER: &str = "polar-git-server.polar.serviceaccount.cluster.local";

    #[tokio::test]
    async fn the_recorder_sends_a_signed_record_and_settles_it_on_the_server_s_answer() {
        let sent: Arc<Mutex<Vec<Envelope<AddRecord>>>> = Arc::default();
        let seen = sent.clone();
        let taken: Arc<Mutex<Vec<(u64, String)>>> = Arc::default();
        let noted = taken.clone();
        let (recorder, _) = Actor::spawn(
            None,
            Recorder,
            RecorderArgs {
                signer: Arc::new(Signs),
                publish: Arc::new(move |bytes| {
                    seen.lock()
                        .unwrap()
                        .push(polar_git_server_common::decode_add(&bytes).unwrap());
                    Ok(())
                }),
                server: SERVER.to_string(),
                prefix: "test".to_string(),
                clock: || 0,
                taken: Some(Arc::new(move |record, path| {
                    noted.lock().unwrap().push((n_of(&record), path))
                })),
            },
        )
        .await
        .unwrap();
        let settle = || async { tokio::time::sleep(std::time::Duration::from_millis(50)).await };
        recorder.cast(RecorderMessage::Keep(record(1))).unwrap();
        recorder.cast(RecorderMessage::Keep(record(2))).unwrap();
        settle().await;
        let first = sent.lock().unwrap().clone();
        assert_eq!(first.len(), 1, "one in flight");
        let document: serde_json::Value = serde_json::from_str(&first[0].payload.record).unwrap();
        assert_eq!(document["payload"]["subject"]["n"], "1");
        let answer = |id: &str| {
            polar_git_server_common::encode_added(&Envelope {
                correlation_id: id.to_string(),
                payload: committed("attestation-report/1/x.json"),
            })
        };
        // From someone else: nothing changes.
        recorder
            .cast(RecorderMessage::Answer {
                payload: answer(&first[0].correlation_id),
                published_by: Some("mallory.polar.serviceaccount.cluster.local".into()),
            })
            .unwrap();
        settle().await;
        assert_eq!(sent.lock().unwrap().len(), 1);
        assert!(taken.lock().unwrap().is_empty());
        recorder
            .cast(RecorderMessage::Answer {
                payload: answer(&first[0].correlation_id),
                published_by: Some(SERVER.into()),
            })
            .unwrap();
        settle().await;
        let all = sent.lock().unwrap().clone();
        assert_eq!(all.len(), 2, "the next goes once the first is taken");
        assert_eq!(
            *taken.lock().unwrap(),
            [(1, "attestation-report/1/x.json".to_string())],
            "the agent is told which record the server holds, and where"
        );
        let document: serde_json::Value = serde_json::from_str(&all[1].payload.record).unwrap();
        assert_eq!(document["payload"]["subject"]["n"], "2");
        recorder.stop(None);
    }
}
