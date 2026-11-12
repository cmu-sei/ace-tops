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

//! LedgerActor: the single, serialized writer (and reader) for the
//! Credentials Agent's event log and derived state.
//!
//! The hash chain requires strict, single-writer, sequential
//! ordering -- a grant, a revocation, and an issuance all append to
//! the *same* chain, and two of those landing on independent,
//! concurrently-running actors could race on append order, corrupting
//! the tamper-evidence property the whole log exists for. Unlike
//! jira/process's topic-per-actor convention (safe there because its
//! four data streams have no ordering relationship to each other at
//! all), this needs one actor, not several -- a ractor mailbox is
//! already naturally serialized (one message processed at a time, by
//! construction), the same property that already makes
//! GraphControllerActor safe for concurrent callers to write through.
//!
//! EventLog and CredentialsState are colocated here deliberately, not
//! split across two owners -- if they were separate, a grant lookup
//! could race against a concurrent append and see a stale view. Every
//! read and write going through this same actor's mailbox gives a
//! consistent, race-free view of derived state for free.
//!
//! Graph projection is deliberately *not* owned here -- see
//! projection.rs's own module doc for why. This actor's only
//! involvement is a fire-and-forget notification to ProjectionActor
//! after each successful append+fold; it has no state of its own
//! about graph availability, checkpoints, or anything else
//! graph-related.

use crate::ledger_checkpoint::{Checkpoints, Kept};
use crate::projection::ProjectionMessage;
use crate::state::{CertificateRecord, CredentialsState, GrantRecord};
use credentials_agent_common::events::CredentialsEvent;
use credentials_agent_common::issuance::WorkloadCertType;
use credentials_agent_common::ledger::Read;
use polar::event_log::{EventLog, EventLogError};
use polar_log::entry::{CONTINUATION, Continuation, Leaf};
use polar_log::file::{FileLog, LogError, Replayed};
use ractor::{Actor, ActorProcessingErr, ActorRef, OutputPort, RpcReplyPort, async_trait};
use std::sync::Arc;
use std::time::Duration;

pub struct LedgerActor;

/// How long a starting ledger waits for the log to be let go of: longer than a replaced credentials agent's drain and
/// grace period (50 s and 60 s), after which its process has ended and the operating system has let go of its lock.
pub const LEDGER_LOCK_WAIT: Duration = Duration::from_secs(90);

/// Asks `open` again every `every`, for up to `wait`, while another holder has what it opens: a replaced credentials
/// agent still draining, whose appends would fork the ledger if this one appended too.
async fn waiting_for<T, E>(
    path: &str,
    wait: Duration,
    every: Duration,
    held: impl Fn(&E) -> bool,
    open: impl Fn() -> Result<T, E>,
) -> Result<T, E> {
    let since = std::time::Instant::now();
    let mut said = false;
    loop {
        match open() {
            Ok(opened) => return Ok(opened),
            Err(e) if held(&e) && since.elapsed() < wait => {
                if !said {
                    tracing::warn!(
                        "the ledger at {path} is held by another process (a credentials agent still draining?); \
                         waiting up to {wait:?} for it to be let go of"
                    );
                    said = true;
                }
                tokio::time::sleep(every).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Opens the JSON ledger at `path`, kept before 2026-11-11, waiting while another holder has it.
pub async fn open_log(
    path: &str,
    wait: Duration,
    every: Duration,
) -> Result<(EventLog<CredentialsEvent>, Vec<CredentialsEvent>), String> {
    waiting_for(
        path,
        wait,
        every,
        |e| matches!(e, polar::event_log::EventLogError::Held { .. }),
        || EventLog::open(path),
    )
    .await
    .map_err(|e| format!("Failed to open event log at {path}: {e}"))
}

/// This agent's identity as cert-issuer reads it off its connection: the first DNS name of its own certificate, at
/// `cert_path`. Its session offers, its keys' certificates and its ledger's checkpoints name it.
pub fn own_identity(cert_path: &str) -> Result<String, String> {
    std::fs::read_to_string(cert_path)
        .map_err(|e| format!("cannot read this agent's certificate: {e}"))
        .and_then(|pem| {
            cert_issuer_common::permission::extract_own_identity(&pem)
                .map_err(|e| format!("this agent's certificate names no identity: {e}"))
        })
}

/// The writer this agent names in the entries it makes: its platform version, as the store names its own.
pub fn writer() -> String {
    format!("{} {}", polar_version::PLATFORM, polar_version::TARGET)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The leaf `event` is appended as, by `writer`, admitted at `admitted_at_ms`: this agent brings every entry itself.
pub(crate) fn leaf_of(event: &CredentialsEvent, writer: &str, admitted_at_ms: u64) -> Leaf {
    Leaf {
        entry: credentials_agent_common::ledger::entry_of(event, writer).encode(),
        admitted_at_ms,
        submitter: crate::supervisor::SERVICE_NAME.to_string(),
    }
}

/// The ledger key (`CREDENTIALS_LEDGER_KEY_PATH`) and whose it is: what signs the ledger's checkpoints, and the identity
/// they name (docs/architecture/record-store.md, "L2, checkpoints").
#[derive(Debug, Clone)]
pub struct LedgerKey {
    pub path: String,
    /// This agent's identity, as its certificate names it.
    pub identity: String,
}

/// What opening the ledger found.
// It is made twice at a start, and taken apart at once, so boxing the ledger is not worth it.
#[allow(clippy::large_enum_variant)]
pub enum Opening {
    /// Every event it holds, by its sequence number, the log to append to, and what signs its checkpoints.
    Ready {
        log: FileLog,
        events: Vec<(u64, CredentialsEvent)>,
        checkpoints: Checkpoints,
    },
    /// Why the agent serves nothing, in one line: an entry it must understand and cannot, a ledger that is damaged, or
    /// one that is not the ledger it signed.
    Refused(String),
}

/// What one replayed frame is to this agent: an event, the first entry carrying on the JSON ledger, one it passes
/// over, or why it may not go on.
// Each is made once per frame and its event moved on at once, so boxing the event is not worth it.
#[allow(clippy::large_enum_variant)]
enum Replay {
    Event(CredentialsEvent),
    Continues,
    PassedOver { kind: String, version: u64 },
    Refused(String),
}

fn replay(seq: u64, replayed: Replayed) -> Replay {
    let entry = match replayed {
        Replayed::Entry { entry, .. } => entry,
        Replayed::Malformed { why, .. } => {
            return Replay::Refused(format!(
                "the ledger's entry {seq} is not an entry ({why}): it serves nothing until the ledger is looked at"
            ));
        }
    };
    if entry.kind == CONTINUATION {
        return if seq == 0 {
            Replay::Continues
        } else {
            Replay::Refused(format!(
                "the ledger's entry {seq} says the ledger carries on another, which only its first may: it serves \
                 nothing until the ledger is looked at"
            ))
        };
    }
    match credentials_agent_common::ledger::read(&entry) {
        Read::Decoded(event) => Replay::Event(event),
        Read::Unknown if entry.critical => Replay::Refused(format!(
            "the ledger holds {} v{} (entry {seq}), written by {}, which this agent ({}) cannot read: it serves \
             nothing until a version that can is deployed",
            entry.kind,
            entry.version,
            entry.writer,
            writer()
        )),
        Read::Unknown => Replay::PassedOver {
            kind: entry.kind,
            version: entry.version,
        },
        Read::Malformed(why) => Replay::Refused(format!(
            "the ledger's entry {seq} ({} v{}, written by {}) is not what its writer should have written ({why}): it \
             serves nothing until the ledger is looked at",
            entry.kind, entry.version, entry.writer
        )),
    }
}

/// Why the JSON ledger at `json` is not copied, when what it holds is the reason, in one line: an event this agent
/// does not read, or a ledger that is damaged. A restart would find the same, so the agent stays up and says so, as it
/// does for the ledger. None for what a restart may change: another holder, or the disk.
fn json_refusal(json: &str, e: &EventLogError) -> Option<String> {
    match e {
        EventLogError::EventDeserialize { line, kind, .. } => Some(format!(
            "the JSON ledger at {json} holds, at line {line}, {} that this agent ({}) does not read (written by a \
             newer version most likely): nothing is copied, and it serves nothing until a version that reads it is \
             deployed",
            kind.as_deref().map_or("an event".to_string(), |k| format!(
                "an event of kind `{k}`"
            )),
            writer()
        )),
        EventLogError::Parse { line, .. }
        | EventLogError::ChainBroken { line, .. }
        | EventLogError::IntegrityCheckFailed { line, .. } => Some(format!(
            "the JSON ledger at {json} is damaged at line {line} ({e}): nothing is copied, and it serves nothing until \
             the ledger is looked at"
        )),
        _ => None,
    }
}

/// Copies the JSON ledger at `json` into a new ledger at `path`, once (docs/architecture/record-store.md, "The
/// credentials ledger on the log", 7): a first entry carrying on the JSON ledger (its last hash and how many it held),
/// then every event as the current version of its kind, admitted when the JSON ledger appended it. It is written
/// beside, as `<path>.copying`, and renamed when whole, so a copy cut short is made again; the JSON ledger is checked
/// as it is read, and kept read-only. Every event is read back as it was before anything is renamed.
async fn copy_json_ledger(
    json: &str,
    path: &str,
    wait: Duration,
    every: Duration,
) -> Result<Option<String>, String> {
    let (old, _) = match waiting_for(
        json,
        wait,
        every,
        |e| matches!(e, EventLogError::Held { .. }),
        || EventLog::<CredentialsEvent>::open(json),
    )
    .await
    {
        Ok(opened) => opened,
        Err(e) => {
            return match json_refusal(json, &e) {
                Some(why) => Ok(Some(why)),
                None => Err(format!("Failed to open event log at {json}: {e}")),
            };
        }
    };
    let entries = old
        .entries()
        .map_err(|e| format!("reading the JSON ledger at {json}: {e}"))?;
    let digest = hex::decode(old.current_hash())
        .map_err(|e| format!("the JSON ledger's last hash is not hex: {e}"))?;
    let writer = writer();
    let continuation = Continuation {
        old_kind: "jsonl".to_string(),
        alg: "sha256".to_string(),
        digest,
        count: entries.len() as u64,
    };
    let mut leaves = vec![Leaf {
        entry: continuation.entry(&writer).encode(),
        admitted_at_ms: now_ms(),
        submitter: crate::supervisor::SERVICE_NAME.to_string(),
    }];
    for (n, replayed) in entries.iter().enumerate() {
        let leaf = leaf_of(
            &replayed.event,
            &writer,
            replayed.timestamp.timestamp_millis().max(0) as u64,
        );
        let entry = polar_log::entry::Entry::decode(&leaf.entry).map_err(|e| e.to_string())?;
        if credentials_agent_common::ledger::read(&entry) != Read::Decoded(replayed.event.clone()) {
            return Err(format!(
                "the JSON ledger's entry {n} does not read back as it was: nothing is copied"
            ));
        }
        leaves.push(leaf);
    }
    let copying = format!("{path}.copying");
    match std::fs::remove_file(&copying) {
        Ok(()) => tracing::warn!(
            "a copy of the JSON ledger that did not finish was found at {copying}, and is made again"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("removing {copying}: {e}")),
    }
    let mut log = FileLog::open(std::path::Path::new(&copying))
        .map_err(|e| e.to_string())?
        .log;
    log.append_all(&leaves).map_err(|e| e.to_string())?;
    drop(log);
    std::fs::rename(&copying, path).map_err(|e| format!("renaming {copying} to {path}: {e}"))?;
    if let Some(dir) = std::path::Path::new(path).parent() {
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| format!("syncing {}: {e}", dir.display()))?;
    }
    // An older agent given this volume again opens the JSON ledger to append, and is refused: it cannot fork it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(json, std::fs::Permissions::from_mode(0o400))
            .map_err(|e| format!("making {json} read-only: {e}"))?;
    }
    tracing::info!(
        "copied the JSON ledger at {json} ({} entries, its last hash {}) into the ledger at {path}; the JSON ledger is \
         kept, read-only",
        entries.len(),
        old.current_hash()
    );
    Ok(None)
}

/// Opens the ledger at `path`, waiting up to `wait` (asking again every `every`) while another holder has it, and
/// replays it (docs/architecture/record-store.md, "The credentials ledger on the log"). When there is none yet and
/// `json` names a JSON ledger, that is copied into it first. An entry this agent must understand and cannot, one not
/// written as its kind says, or a damaged ledger, is a refusal: the agent stays up and serves nothing, since a restart
/// would find the same. An entry of a kind it may pass over is counted and said. Only then is the ledger `key` read,
/// made if this is the first start, and the checkpoint kept beside the ledger checked: a ledger that no longer holds
/// it is a refusal too ("L2, checkpoints").
pub async fn open_ledger(
    path: &str,
    json: Option<&str>,
    key: &LedgerKey,
    wait: Duration,
    every: Duration,
) -> Result<Opening, String> {
    if let Some(json) = json
        && !std::path::Path::new(path).exists()
        && std::path::Path::new(json).exists()
        && let Some(why) = copy_json_ledger(json, path, wait, every).await?
    {
        return Ok(Opening::Refused(why));
    }
    let opened = match waiting_for(
        path,
        wait,
        every,
        |e| matches!(e, LogError::Held { .. }),
        || FileLog::open(std::path::Path::new(path)),
    )
    .await
    {
        Ok(opened) => opened,
        Err(e @ LogError::Damaged { .. }) => {
            return Ok(Opening::Refused(format!(
                "{e}: it serves nothing until the ledger is looked at"
            )));
        }
        Err(e) => return Err(format!("Failed to open the ledger at {path}: {e}")),
    };
    if let Some(bytes) = opened.torn {
        tracing::warn!(
            "the ledger's last entry was cut short ({bytes} bytes), by a write that did not finish, and was cut back"
        );
    }
    let mut events = Vec::with_capacity(opened.replayed.len());
    let mut passed_over: std::collections::BTreeMap<(String, u64), usize> = Default::default();
    for (seq, replayed) in opened.replayed.into_iter().enumerate() {
        match replay(seq as u64, replayed) {
            Replay::Event(event) => events.push((seq as u64, event)),
            Replay::Continues => {}
            Replay::PassedOver { kind, version } => {
                *passed_over.entry((kind, version)).or_default() += 1
            }
            Replay::Refused(why) => return Ok(Opening::Refused(why)),
        }
    }
    for ((kind, version), count) in passed_over {
        tracing::warn!(
            kind,
            version,
            count,
            "the ledger holds entries of a kind this agent does not know and may pass over; passed over"
        );
    }
    let checkpoints = match Checkpoints::open(std::path::Path::new(path), &opened.log, key)? {
        Kept::Ready(checkpoints) => checkpoints,
        Kept::Refused(why) => return Ok(Opening::Refused(why)),
    };
    Ok(Opening::Ready {
        log: opened.log,
        events,
        checkpoints,
    })
}

pub struct LedgerActorArgs {
    /// The ledger (`CREDENTIALS_LEDGER_PATH`).
    pub log_path: String,
    /// The JSON ledger kept before 2026-11-11 (`CREDENTIALS_EVENT_LOG_PATH`), copied into the ledger if it has none yet.
    pub copy_from: Option<String>,
    /// What signs the ledger's checkpoints.
    pub key: LedgerKey,
    pub projection_actor: ActorRef<ProjectionMessage>,
}

/// How often at most the ledger's checkpoint is signed while entries are appended, as the store signs its logs'.
pub const CHECKPOINT_EVERY: Duration = Duration::from_secs(1);

pub struct LedgerActorState {
    log: FileLog,
    checkpoints: Checkpoints,
    /// Whether a checkpoint is to be signed at the next tick, already asked for.
    checkpoint_due: bool,
    /// Where the ledger key's latest certificate is kept.
    key_certificate: std::path::PathBuf,
    /// The platform version this agent names as the writer of what it appends.
    writer: String,
    credentials_state: CredentialsState,
    projection_actor: ActorRef<ProjectionMessage>,
    /// Told when an event adds a revoked serial, for whoever publishes the set to the agents.
    revocation_changes: Arc<OutputPort<RevokedChanged>>,
    /// The renewal rule's admissions not yet recorded (docs/architecture/deployments.md, "The renewal rule").
    admissions: crate::renewal::Admissions,
}

/// Why a secret was not stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretStoreError {
    /// Another identity stored a secret by this name.
    NameTaken,
    /// The identity that stored it is storing it again, with other labels.
    LabelsChanged,
    /// The ledger could not append it.
    Ledger(String),
}

/// An event added to the set of revoked certificate serials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedChanged {
    /// How many serials are revoked now.
    pub count: usize,
}

pub enum LedgerMessage {
    /// Signs the ledger's checkpoint, if it grew since the last: at most once every [`CHECKPOINT_EVERY`].
    Checkpoint,
    /// The ledger key's certificate, renewed: kept beside the key, for whoever checks its checkpoints.
    KeyCertified(Vec<String>),
    /// Appends `event` to the log, then folds it into derived state --
    /// in that order, so a reader can never observe a state change
    /// that isn't yet durable. Replies with an error string on a
    /// genuine append failure (disk I/O, or -- should it ever somehow
    /// happen at runtime rather than only at startup replay -- a
    /// broken hash chain).
    Append {
        event: CredentialsEvent,
        reply: RpcReplyPort<Result<(), String>>,
    },
    /// Assigns the next sequence number to an update of `kind` at `version` that is about to be published, and
    /// records that it was, in one append. The numbering is the ledger's so that it goes on rising across
    /// restarts. Replies with the sequence.
    PublishAuthority {
        kind: String,
        version: u64,
        /// What the document does, as the authority model judged it before it was accepted, if it did.
        effect: Option<credentials_agent_common::events::AuthorityEffect>,
        reply: RpcReplyPort<Result<u64, String>>,
    },
    /// Every account certificate not revoked: the persons a change of authority is judged for.
    ActiveAccounts(RpcReplyPort<Vec<crate::state::AccountCertificateRecord>>),
    /// Each account's username and its account ID, which a policy's or groups document's usernames are converted by.
    AccountNames(RpcReplyPort<std::collections::BTreeMap<String, String>>),
    /// The highest sequence number published so far; 0 before any.
    AuthoritySequence(RpcReplyPort<u64>),
    /// The serial of every certificate an explicit revocation named, in order.
    RevokedSerials(RpcReplyPort<Vec<String>>),
    /// The revoked set as it is published at `now` (Unix seconds), and its version (`published_revocations`).
    PublishedRevocations {
        now: i64,
        /// The serials, those of them revoked for a compromise, and the version.
        reply: RpcReplyPort<(Vec<String>, Vec<String>, u64)>,
    },
    /// The port on which a newly revoked serial is announced.
    RevocationChanges(RpcReplyPort<Arc<OutputPort<RevokedChanged>>>),
    /// The active grant for `identity`, if any.
    CheckGrant {
        identity: String,
        reply: RpcReplyPort<Option<GrantRecord>>,
    },
    /// Whether `(identity, instance_binding)` currently holds a valid,
    /// unrevoked certificate of this type. Asked per type, since a pod
    /// instance may hold one client and one server certificate. Not the
    /// renewal rule, which is [`LedgerMessage::Admit`].
    CheckRenewal {
        identity: String,
        instance_binding: String,
        cert_type: WorkloadCertType,
        reply: RpcReplyPort<bool>,
    },
    /// The renewal rule (docs/architecture/deployments.md, "The renewal rule"): whether `identity`'s pod
    /// `instance_binding` may be issued a certificate of `cert_type` for `key` (the SubjectPublicKeyInfo its CSR asks
    /// for, none when it does not read) at `now`, which it may unless it was issued one, or admitted to be, within the
    /// bound for another key; the same key is the same request asked again ("A retry is not a second request").
    /// Admitting records `now`; asks are answered one at a time, so two at once for different keys are never both
    /// admitted.
    Admit {
        identity: String,
        instance_binding: String,
        cert_type: WorkloadCertType,
        key: Option<Vec<u8>>,
        now: i64,
        reply: RpcReplyPort<bool>,
    },
    /// Gives back the admission made at `at`, for an issuance that did not happen.
    Release {
        identity: String,
        instance_binding: String,
        cert_type: WorkloadCertType,
        at: i64,
    },
    /// Where cert-issuer's record has been read to (docs/architecture/cert-issuer-isolation.md, "Step 2"): its log and its
    /// last entry read, or none before any page.
    RecordCursor {
        reply: RpcReplyPort<Option<(String, u64)>>,
    },
    /// Takes a page of cert-issuer's record: its certificates the ledger has not recorded are recorded, each flagged
    /// unexpected when signed on a token alone for an identity not in `bootstrap` (none: no model, so nothing can be
    /// called unexpected), and the cursor moves, in one
    /// append. Nothing is appended for a page that holds nothing new and moves nothing. Replies with the cursor.
    TakeRecordPage {
        page: cert_issuer_common::record::RecordReply,
        bootstrap: Option<std::collections::BTreeSet<String>>,
        reply: RpcReplyPort<Result<Option<(String, u64)>, String>>,
    },
    /// Records a report of the attestation agent's, unless it is already recorded. Replies with whether it was new.
    TakeAttestationReport {
        event: CredentialsEvent,
        reply: RpcReplyPort<Result<bool, String>>,
    },
    /// The current, non-revoked certificate for `identity`, if any --
    /// regardless of instance_binding. Backs the certificate-lookup
    /// query: one agent asking for another's public cert so it can
    /// encrypt a payload directly to it.
    CheckCertificate {
        identity: String,
        reply: RpcReplyPort<Option<CertificateRecord>>,
    },
    /// The live custodian certificate `identity` holds, if any (docs/architecture/key-custody.md, "Part A's
    /// bootstrap: the custodian").
    CustodianCertificate {
        identity: String,
        /// The pod UID the broker stamped beside the requester, when it is one pod of a multi-instance workload's.
        instance: Option<String>,
        reply: RpcReplyPort<Option<CertificateRecord>>,
    },
    /// The certificate `identity` connects with, whose groups policy reads at the request gate: its workload's client
    /// certificate, or else its account's, while that is not revoked (docs/architecture/authority-model.md, slice 9).
    RequesterCertificate {
        identity: String,
        reply: RpcReplyPort<Option<String>>,
    },
    /// Whether `identity` already holds a currently-issued agent
    /// escrow-identity (CertType::Service) certificate -- the
    /// identity-scoped analog of CheckRenewal's own
    /// (identity, instance_binding)-scoped check for ordinary mTLS
    /// issuance. AgentEscrowIssuanceHandler's own version of "pods
    /// cannot request their own renewal." A bare bool, mirroring
    /// CheckRenewal's own shape exactly -- not CheckCertificate's,
    /// since this consumer never needs the full record, only whether
    /// one exists. CheckAgentEscrowKey, below, is the record-
    /// returning counterpart for the consumer that does.
    CheckAgentEscrowRenewal {
        identity: String,
        reply: RpcReplyPort<bool>,
    },
    /// The current agent escrow-identity (CertType::Service)
    /// certificate record for `identity`, if one has ever been
    /// issued -- mirrors CheckCertificate's own Option<Record> shape.
    /// Backs the agent escrow-key query: AgentEscrowKeyHandler
    /// genuinely needs the full record (its certificate_pem
    /// specifically, to extract the public key from) to answer that
    /// query, unlike CheckAgentEscrowRenewal above.
    CheckAgentEscrowKey {
        identity: String,
        reply: RpcReplyPort<Option<crate::state::AgentEscrowCertificateRecord>>,
    },
    /// The provisioned-but-unclaimed account record for `username`,
    /// if any -- the claim-flow's own analog of CheckGrant. `None`
    /// means either never provisioned, or already claimed (single-use,
    /// same as a Grant).
    CheckProvisionedAccount {
        username: String,
        reply: RpcReplyPort<Option<crate::state::ProvisionedAccountRecord>>,
    },
    /// Whether the one-time admin-bootstrap path has ever succeeded --
    /// checked before allowing a via_bootstrap AccountProvisioned to
    /// fold a second time.
    CheckBootstrapCompleted { reply: RpcReplyPort<bool> },
    /// The account certificate with this serial, revoked or not.
    CheckAccountCertificateBySerial {
        serial: String,
        reply: RpcReplyPort<Option<crate::state::AccountCertificateRecord>>,
    },
    /// The account holding (or last holding) this username, if any.
    CheckAccountForUsername {
        username: String,
        reply: RpcReplyPort<Option<crate::state::AccountCertificateRecord>>,
    },
    /// Records a signature-verified admin action atomically: refused
    /// (`Ok(false)`) if its payload hash was already recorded, appended
    /// and folded (`Ok(true)`) otherwise. The check and the append are
    /// one message on the single-writer actor, so two identical
    /// submissions can never both be recorded.
    RecordAdminAction {
        event: CredentialsEvent,
        reply: RpcReplyPort<Result<bool, String>>,
    },
    /// The current, escrowed secret for `name`, if one has ever been
    /// stored -- backs the general secret-retrieve mechanism.
    /// Mirrors CheckCertificate/CheckAgentEscrowKey's own
    /// Option<T> shape.
    /// Stores a secret, if its name is free or already the storing identity's own: checked and appended in
    /// one step, so two identities racing for a fresh name cannot both win.
    StoreSecret {
        event: CredentialsEvent,
        reply: RpcReplyPort<Result<(), SecretStoreError>>,
    },
    CheckSecret {
        name: String,
        reply: RpcReplyPort<Option<crate::state::StoredSecret>>,
    },
    /// Full (sequence number, event) history, re-read from the log -- used by
    /// ProjectionActor for catch-up: replaying and re-folding through
    /// history to reconstruct correct historical context at each
    /// point (e.g. whether a grant existed at the moment a specific
    /// past event happened), not just "everything after X" taken in
    /// isolation.
    GetFullHistory {
        reply: RpcReplyPort<Result<Vec<(u64, CredentialsEvent)>, String>>,
    },
}

#[async_trait]
impl Actor for LedgerActor {
    type Msg = LedgerMessage;
    type State = LedgerActorState;
    type Arguments = LedgerActorArgs;

    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        args: LedgerActorArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        // The agent's start has already refused to serve a ledger it cannot read (`agent.rs`); one found so now is
        // an error, not a hold.
        let (log, events, mut checkpoints) = match open_ledger(
            &args.log_path,
            args.copy_from.as_deref(),
            &args.key,
            LEDGER_LOCK_WAIT,
            Duration::from_secs(1),
        )
        .await
        .map_err(ActorProcessingErr::from)?
        {
            Opening::Ready {
                log,
                events,
                checkpoints,
            } => (log, events, checkpoints),
            Opening::Refused(why) => return Err(ActorProcessingErr::from(why)),
        };
        // A checkpoint at the start, unless the one kept is of this tree already.
        let kept = checkpoints.signed();
        if let Some(size) = checkpoints.sign(&log).map_err(ActorProcessingErr::from)? {
            match kept {
                None => tracing::info!(
                    size,
                    key = checkpoints.verifier_key(),
                    "the ledger had no checkpoint kept; signed its first"
                ),
                Some(kept) => {
                    tracing::info!(size, kept, "signed the ledger's checkpoint at its start")
                }
            }
        }

        let event_count = events.len();
        let events: Vec<CredentialsEvent> = events.into_iter().map(|(_, e)| e).collect();
        let credentials_state = CredentialsState::from_events(&events);
        tracing::info!(
            "LedgerActor: replayed {event_count} event(s) from {} into current state",
            args.log_path
        );

        Ok(LedgerActorState {
            log,
            checkpoints,
            checkpoint_due: false,
            key_certificate: crate::ledger_checkpoint::certificate_path(std::path::Path::new(
                &args.key.path,
            )),
            writer: writer(),
            credentials_state,
            projection_actor: args.projection_actor,
            revocation_changes: Arc::new(OutputPort::default()),
            admissions: crate::renewal::Admissions::default(),
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            LedgerMessage::Checkpoint => {
                state.checkpoint_due = false;
                if let Err(e) = state.checkpoints.sign(&state.log) {
                    // Tried again a second later; the ledger itself is whole.
                    tracing::error!("the ledger's checkpoint was not kept: {e}");
                }
            }
            LedgerMessage::KeyCertified(chain) => {
                match crate::ledger_checkpoint::write_whole(
                    &state.key_certificate,
                    chain.concat().as_bytes(),
                ) {
                    Ok(()) => tracing::info!(
                        "the ledger key's certificate is kept at {}",
                        state.key_certificate.display()
                    ),
                    Err(e) => tracing::error!("the ledger key's certificate was not kept: {e}"),
                }
            }
            LedgerMessage::StoreSecret { event, reply } => {
                let result = match &event {
                    CredentialsEvent::SecretStored {
                        name,
                        stored_by,
                        labels,
                        ..
                    } => state
                        .credentials_state
                        .check_store(name, stored_by, labels)
                        .and_then(|()| {
                            append_and_project(state, &event).map_err(SecretStoreError::Ledger)
                        }),
                    _ => Err(SecretStoreError::Ledger(
                        "not a SecretStored event".to_string(),
                    )),
                };
                let _ = reply.send(result);
            }
            LedgerMessage::Append { event, reply } => {
                let result = append_and_project(state, &event);
                let _ = reply.send(result);
            }
            LedgerMessage::PublishAuthority {
                kind,
                version,
                effect,
                reply,
            } => {
                let sequence = state.credentials_state.last_authority_sequence() + 1;
                let result = append_and_project(
                    state,
                    &CredentialsEvent::AuthorityPublished {
                        sequence,
                        kind,
                        version,
                        timestamp: polar::time::now_millis(),
                        effect,
                    },
                )
                .map(|()| sequence);
                let _ = reply.send(result);
            }
            LedgerMessage::ActiveAccounts(reply) => {
                let _ = reply.send(state.credentials_state.active_account_certificates());
            }
            LedgerMessage::AccountNames(reply) => {
                let _ = reply.send(state.credentials_state.account_names());
            }
            LedgerMessage::AuthoritySequence(reply) => {
                let _ = reply.send(state.credentials_state.last_authority_sequence());
            }
            LedgerMessage::RevokedSerials(reply) => {
                let _ = reply.send(state.credentials_state.revoked_serials());
            }
            LedgerMessage::PublishedRevocations { now, reply } => {
                let (serials, version) = state.credentials_state.published_revocations(now);
                let compromised = state.credentials_state.compromised_among(&serials);
                let _ = reply.send((serials, compromised, version));
            }
            LedgerMessage::RevocationChanges(reply) => {
                let _ = reply.send(state.revocation_changes.clone());
            }
            LedgerMessage::RecordAdminAction { event, reply } => {
                let CredentialsEvent::AdminActionRecorded { payload_hash, .. } = &event else {
                    let _ = reply.send(Err("not an AdminActionRecorded event".to_string()));
                    return Ok(());
                };
                if state.credentials_state.admin_action_seen(payload_hash) {
                    let _ = reply.send(Ok(false));
                    return Ok(());
                }
                let result = append_and_project(state, &event).map(|()| true);
                let _ = reply.send(result);
            }
            LedgerMessage::CheckGrant { identity, reply } => {
                let grant = state.credentials_state.grant_for(&identity).cloned();
                let _ = reply.send(grant);
            }
            LedgerMessage::CheckRenewal {
                identity,
                instance_binding,
                cert_type,
                reply,
            } => {
                let has_valid = state.credentials_state.has_valid_certificate(
                    &identity,
                    &instance_binding,
                    cert_type,
                );
                let _ = reply.send(has_valid);
            }
            LedgerMessage::Admit {
                identity,
                instance_binding,
                cert_type,
                key,
                now,
                reply,
            } => {
                let admitted = state.admissions.admit(
                    &state.credentials_state,
                    &identity,
                    &instance_binding,
                    cert_type,
                    key.as_deref(),
                    now,
                );
                let _ = reply.send(admitted);
            }
            LedgerMessage::Release {
                identity,
                instance_binding,
                cert_type,
                at,
            } => {
                state
                    .admissions
                    .release(&identity, &instance_binding, cert_type, at);
            }
            LedgerMessage::RecordCursor { reply } => {
                let _ = reply.send(state.credentials_state.record_cursor());
            }
            LedgerMessage::TakeRecordPage {
                page,
                bootstrap,
                reply,
            } => {
                let now = polar::time::now_millis();
                let result = match state.credentials_state.reported_page(
                    &page,
                    bootstrap.as_ref(),
                    now,
                ) {
                    None => Ok(()),
                    Some(event) => {
                        if let CredentialsEvent::CertificatesReported { certificates, .. } = &event
                        {
                            for c in certificates.iter().filter(|c| c.unexpected) {
                                tracing::warn!(
                                    identity = %c.identity,
                                    serial = %c.serial,
                                    "cert-issuer signed a certificate on a token alone for an identity that is not a bootstrap service"
                                );
                            }
                        }
                        append_and_project(state, &event)
                    }
                };
                let _ = reply.send(result.map(|()| state.credentials_state.record_cursor()));
            }
            LedgerMessage::TakeAttestationReport { event, reply } => {
                let known = matches!(
                    &event,
                    CredentialsEvent::AttestationReported { pod_uid, finding, .. }
                        if state.credentials_state.knows_attestation_report(pod_uid, finding)
                );
                let result = if known {
                    Ok(false)
                } else {
                    append_and_project(state, &event).map(|()| true)
                };
                let _ = reply.send(result);
            }
            LedgerMessage::CheckCertificate { identity, reply } => {
                let record = state.credentials_state.certificate_for(&identity).cloned();
                let _ = reply.send(record);
            }
            LedgerMessage::CustodianCertificate {
                identity,
                instance,
                reply,
            } => {
                let record = state
                    .credentials_state
                    .custodian_certificate_of(&identity, instance.as_deref())
                    .cloned();
                let _ = reply.send(record);
            }
            LedgerMessage::RequesterCertificate { identity, reply } => {
                let pem = state
                    .credentials_state
                    .requester_certificate(&identity)
                    .map(str::to_string);
                let _ = reply.send(pem);
            }
            LedgerMessage::CheckAgentEscrowRenewal { identity, reply } => {
                let has_one = state
                    .credentials_state
                    .has_agent_escrow_certificate(&identity);
                let _ = reply.send(has_one);
            }
            LedgerMessage::CheckAgentEscrowKey { identity, reply } => {
                let record = state
                    .credentials_state
                    .agent_escrow_certificate_for(&identity)
                    .cloned();
                let _ = reply.send(record);
            }
            LedgerMessage::CheckProvisionedAccount { username, reply } => {
                let record = state
                    .credentials_state
                    .provisioned_account_for(&username)
                    .cloned();
                let _ = reply.send(record);
            }
            LedgerMessage::CheckBootstrapCompleted { reply } => {
                let _ = reply.send(state.credentials_state.bootstrap_completed());
            }
            LedgerMessage::CheckAccountCertificateBySerial { serial, reply } => {
                let record = state
                    .credentials_state
                    .account_certificate_by_serial(&serial)
                    .cloned();
                let _ = reply.send(record);
            }
            LedgerMessage::CheckAccountForUsername { username, reply } => {
                let record = state
                    .credentials_state
                    .account_for_username(&username)
                    .cloned();
                let _ = reply.send(record);
            }
            LedgerMessage::CheckSecret { name, reply } => {
                let secret = state.credentials_state.secret_for(&name).cloned();
                let _ = reply.send(secret);
            }
            LedgerMessage::GetFullHistory { reply } => {
                let _ = reply.send(history(&state.log));
            }
        }
        // Whatever was appended is signed within a second: one tick for every append until then.
        if !state.checkpoint_due && state.checkpoints.signed() != Some(state.log.size()) {
            state.checkpoint_due = true;
            drop(myself.send_after(CHECKPOINT_EVERY, || LedgerMessage::Checkpoint));
        }
        Ok(())
    }
}

/// Every event the ledger holds, by its sequence number, read back from the file: what was replayed at start, and
/// appended since.
fn history(log: &FileLog) -> Result<Vec<(u64, CredentialsEvent)>, String> {
    let mut events = Vec::new();
    for seq in 0..log.size() {
        let leaf = log
            .leaf(seq)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("the ledger's entry {seq} is gone"))?;
        let replayed = match polar_log::entry::Entry::decode(&leaf.entry) {
            Ok(entry) => Replayed::Entry { seq, leaf, entry },
            Err(e) => Replayed::Malformed {
                seq,
                why: e.to_string(),
            },
        };
        match replay(seq, replayed) {
            Replay::Event(event) => events.push((seq, event)),
            Replay::Continues | Replay::PassedOver { .. } => {}
            Replay::Refused(why) => return Err(why),
        }
    }
    Ok(events)
}

/// Appends `event` durably, folds it into derived state, and notifies
/// the projection -- in that order, so a reader can never observe a
/// state change that isn't yet durable.
fn append_and_project(
    state: &mut LedgerActorState,
    event: &CredentialsEvent,
) -> Result<(), String> {
    let seq = state
        .log
        .append(&leaf_of(event, &state.writer, now_ms()))
        .map_err(|e| e.to_string())?;
    let revoked_before = state.credentials_state.revoked_serials().len();
    let superseded_serials = state.credentials_state.apply(event);
    let revoked_after = state.credentials_state.revoked_serials().len();
    if revoked_after > revoked_before {
        state.revocation_changes.send(RevokedChanged {
            count: revoked_after,
        });
    }
    let _ = state
        .projection_actor
        .cast(ProjectionMessage::ProjectEvent {
            seq,
            event: event.clone(),
            superseded_serials,
        });
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use credentials_agent_common::events::GrantReason;

    #[tokio::test]
    async fn a_json_ledger_is_waited_for_until_it_is_let_go_of_and_then_opened() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("events.jsonl")
            .to_str()
            .unwrap()
            .to_string();
        let (held, _) = EventLog::<CredentialsEvent>::open(&path).unwrap();
        let letting_go = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            drop(held);
        });
        let since = std::time::Instant::now();
        open_log(&path, Duration::from_secs(5), Duration::from_millis(20))
            .await
            .unwrap();
        assert!(since.elapsed() >= Duration::from_millis(300), "it waited");
        letting_go.await.unwrap();
    }

    #[tokio::test]
    async fn a_json_ledger_never_let_go_of_is_not_opened() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("events.jsonl")
            .to_str()
            .unwrap()
            .to_string();
        let (_held, _) = EventLog::<CredentialsEvent>::open(&path).unwrap();
        let why = match open_log(&path, Duration::from_millis(200), Duration::from_millis(20)).await
        {
            Err(why) => why,
            Ok(_) => panic!("opened a log another holder has open"),
        };
        assert!(why.contains("held"), "{why}");
    }

    /// The events in the ledger at `path`, one to a line as their Debug form says them, read from a copy so a ledger
    /// actor may hold it meanwhile; empty when there is no ledger.
    pub(crate) fn events_in(path: impl AsRef<std::path::Path>) -> String {
        let Ok(bytes) = std::fs::read(path) else {
            return String::new();
        };
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("ledger.log");
        std::fs::write(&copy, bytes).unwrap();
        let log = FileLog::open(&copy).unwrap().log;
        history(&log)
            .unwrap()
            .into_iter()
            .map(|(_, e)| format!("{e:?}\n"))
            .collect()
    }

    fn grant(n: i64) -> CredentialsEvent {
        CredentialsEvent::Grant {
            target_identity: format!("agent-{n}"),
            permissions: vec![],
            granted_by: "admin".into(),
            timestamp: n,
            reason: GrantReason::ServiceOnboarding,
        }
    }

    fn unattested(n: i64) -> CredentialsEvent {
        CredentialsEvent::IssuedUnattested {
            identity: format!("agent-{n}"),
            instance_binding: "pod-uid".into(),
            serial: None,
            why: "the attestor did not answer".into(),
            timestamp: n,
        }
    }

    /// The ledger key beside the ledger at `ledger`, as this agent's: for a test's ledger.
    pub(crate) fn key_beside(ledger: impl AsRef<std::path::Path>) -> LedgerKey {
        LedgerKey {
            path: ledger
                .as_ref()
                .with_file_name("ledger-key.pem")
                .display()
                .to_string(),
            identity: "credentials-agent.polar.serviceaccount.cluster.local".to_string(),
        }
    }

    async fn opened(path: &std::path::Path, json: Option<&std::path::Path>) -> Opening {
        open_ledger(
            path.to_str().unwrap(),
            json.map(|j| j.to_str().unwrap()),
            &key_beside(path),
            Duration::from_secs(5),
            Duration::from_millis(20),
        )
        .await
        .unwrap()
    }

    fn ready(opening: Opening) -> (FileLog, Vec<(u64, CredentialsEvent)>) {
        match opening {
            Opening::Ready { log, events, .. } => (log, events),
            Opening::Refused(why) => panic!("refused: {why}"),
        }
    }

    fn refused(opening: Opening) -> String {
        match opening {
            Opening::Refused(why) => why,
            Opening::Ready { events, .. } => panic!("served {} events", events.len()),
        }
    }

    /// A leaf holding `entry` as this agent would admit it.
    fn leaf_holding(entry: polar_log::entry::Entry) -> Leaf {
        Leaf {
            entry: entry.encode(),
            admitted_at_ms: 1,
            submitter: crate::supervisor::SERVICE_NAME.into(),
        }
    }

    #[tokio::test]
    async fn a_ledger_held_by_another_is_waited_for_and_then_opened() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let held = FileLog::open(&path).unwrap();
        let letting_go = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            drop(held);
        });
        let since = std::time::Instant::now();
        ready(opened(&path, None).await);
        assert!(since.elapsed() >= Duration::from_millis(300), "it waited");
        letting_go.await.unwrap();
    }

    #[tokio::test]
    async fn a_json_ledger_holding_an_event_this_agent_does_not_read_holds_it_and_nothing_is_copied()
     {
        // Another version's event, as serde writes one: a kind this agent's events do not have.
        #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
        enum Newer {
            Rotate { key: String },
        }
        let dir = tempfile::tempdir().unwrap();
        let (path, json) = (
            dir.path().join("ledger.log"),
            dir.path().join("events.jsonl"),
        );
        {
            let (mut old, _) = EventLog::<Newer>::open(&json).unwrap();
            old.append(&Newer::Rotate { key: "k".into() }).unwrap();
        }
        let mode = |p: &std::path::Path| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(p).unwrap().permissions().mode() & 0o777
        };
        let before = mode(&json);

        let why = refused(opened(&path, Some(&json)).await);
        assert!(why.contains("at line 0"), "{why}");
        assert!(why.contains("of kind `Rotate`"), "{why}");
        assert!(why.contains("a version that reads it is deployed"), "{why}");
        assert!(!why.contains('\n'));
        // Nothing copied, nothing made, and the JSON ledger left as it was, for the version that reads it.
        assert!(!path.exists());
        assert!(!dir.path().join("ledger.log.copying").exists());
        assert!(!dir.path().join("ledger-key.pem").exists());
        assert_eq!(mode(&json), before);
    }

    #[tokio::test]
    async fn a_damaged_json_ledger_holds_it_and_nothing_is_copied() {
        let dir = tempfile::tempdir().unwrap();
        let (path, json) = (
            dir.path().join("ledger.log"),
            dir.path().join("events.jsonl"),
        );
        {
            let (mut old, _) = EventLog::<CredentialsEvent>::open(&json).unwrap();
            old.append(&grant(1)).unwrap();
            old.append(&grant(2)).unwrap();
        }
        // An event changed in place: its recorded hash no longer holds.
        let text = std::fs::read_to_string(&json).unwrap();
        std::fs::write(&json, text.replacen("agent-2", "agent-9", 1)).unwrap();

        let why = refused(opened(&path, Some(&json)).await);
        assert!(why.contains("is damaged at line 1"), "{why}");
        assert!(why.contains("until the ledger is looked at"), "{why}");
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn the_json_ledger_is_copied_once_every_event_kept_and_it_is_left_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let (path, json) = (
            dir.path().join("ledger.log"),
            dir.path().join("events.jsonl"),
        );
        let events = vec![grant(1), unattested(2), grant(3)];
        let (last_hash, times) = {
            let (mut old, _) = EventLog::<CredentialsEvent>::open(&json).unwrap();
            for e in &events {
                old.append(e).unwrap();
            }
            let times: Vec<u64> = old
                .entries()
                .unwrap()
                .iter()
                .map(|r| r.timestamp.timestamp_millis() as u64)
                .collect();
            (old.current_hash().to_string(), times)
        };

        let (log, read) = ready(opened(&path, Some(&json)).await);
        // The first entry carries on the JSON ledger; every event follows it, in order, admitted when it was.
        assert_eq!(
            read,
            events
                .iter()
                .cloned()
                .enumerate()
                .map(|(n, e)| (n as u64 + 1, e))
                .collect::<Vec<_>>()
        );
        let first = polar_log::entry::Entry::decode(&log.leaf(0).unwrap().unwrap().entry).unwrap();
        assert_eq!(first.kind, CONTINUATION);
        assert_eq!(
            Continuation::decode(&first.event).unwrap(),
            Continuation {
                old_kind: "jsonl".into(),
                alg: "sha256".into(),
                digest: hex::decode(&last_hash).unwrap(),
                count: 3,
            }
        );
        for (n, at) in times.iter().enumerate() {
            assert_eq!(log.leaf(n as u64 + 1).unwrap().unwrap().admitted_at_ms, *at);
        }
        drop(log);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&json).unwrap().permissions().mode() & 0o777,
                0o400
            );
        }
        assert!(!dir.path().join("ledger.log.copying").exists());

        // Once there is a ledger, the JSON ledger is not copied again: what is appended stays.
        let (mut log, _) = ready(opened(&path, Some(&json)).await);
        log.append(&leaf_of(&grant(4), &writer(), 4)).unwrap();
        drop(log);
        let (_, read) = ready(opened(&path, Some(&json)).await);
        assert_eq!(read.len(), 4);
        assert_eq!(read.last().unwrap(), &(4, grant(4)));
    }

    #[tokio::test]
    async fn a_copy_cut_short_is_made_again() {
        let dir = tempfile::tempdir().unwrap();
        let (path, json) = (
            dir.path().join("ledger.log"),
            dir.path().join("events.jsonl"),
        );
        {
            let (mut old, _) = EventLog::<CredentialsEvent>::open(&json).unwrap();
            old.append(&grant(1)).unwrap();
        }
        std::fs::write(
            dir.path().join("ledger.log.copying"),
            b"a copy that stopped",
        )
        .unwrap();
        let (_, read) = ready(opened(&path, Some(&json)).await);
        assert_eq!(read, vec![(1, grant(1))]);
        assert!(!dir.path().join("ledger.log.copying").exists());
    }

    #[tokio::test]
    async fn an_entry_it_may_pass_over_is_passed_over_and_one_it_must_understand_refuses_the_ledger()
     {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let newer = |critical| polar_log::entry::Entry {
            kind: "credentials.something-new".into(),
            version: 1,
            critical,
            writer: "9.0.0 x86_64-unknown-linux-musl".into(),
            event: vec![0xa0],
        };
        {
            let mut log = FileLog::open(&path).unwrap().log;
            log.append(&leaf_of(&grant(1), &writer(), 1)).unwrap();
            log.append(&leaf_holding(newer(false))).unwrap();
            log.append(&leaf_of(&grant(2), &writer(), 2)).unwrap();
        }
        let (log, read) = ready(opened(&path, None).await);
        assert_eq!(read, vec![(0, grant(1)), (2, grant(2))]);
        assert_eq!(history(&log).unwrap(), read);
        drop(log);

        FileLog::open(&path)
            .unwrap()
            .log
            .append(&leaf_holding(newer(true)))
            .unwrap();
        let why = refused(opened(&path, None).await);
        assert!(why.contains("credentials.something-new v1"), "{why}");
        assert!(why.contains("9.0.0 x86_64-unknown-linux-musl"), "{why}");
        assert!(
            why.contains("until a version that can is deployed"),
            "{why}"
        );
        assert!(!why.contains('\n'));
    }

    #[tokio::test]
    async fn a_held_agent_makes_no_ledger_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        FileLog::open(&path)
            .unwrap()
            .log
            .append(&leaf_holding(polar_log::entry::Entry {
                kind: "credentials.something-new".into(),
                version: 1,
                critical: true,
                writer: "9.0.0 x86_64-unknown-linux-musl".into(),
                event: vec![0xa0],
            }))
            .unwrap();
        refused(opened(&path, None).await);
        assert!(!dir.path().join("ledger-key.pem").exists());
        assert!(!dir.path().join("ledger.checkpoint").exists());
    }

    /// The size of the checkpoint kept beside the ledger at `path`, if one is.
    fn kept_size(path: &std::path::Path) -> Option<u64> {
        let note = std::fs::read_to_string(crate::ledger_checkpoint::kept_path(path)).ok()?;
        note.lines().nth(1)?.parse().ok()
    }

    async fn spawned(path: &std::path::Path) -> ActorRef<LedgerMessage> {
        Actor::spawn(
            None,
            LedgerActor,
            LedgerActorArgs {
                log_path: path.to_str().unwrap().to_string(),
                copy_from: None,
                key: key_beside(path),
                projection_actor: crate::projection::tests::fake_projection_actor().await,
            },
        )
        .await
        .unwrap()
        .0
    }

    #[tokio::test]
    async fn the_ledger_signs_a_checkpoint_at_its_start_and_at_most_once_a_second_while_it_is_appended_to()
     {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        {
            let mut log = FileLog::open(&path).unwrap().log;
            log.append(&leaf_of(&grant(1), &writer(), 1)).unwrap();
        }
        let ledger = spawned(&path).await;
        assert_eq!(kept_size(&path), Some(1), "at its start");
        for n in 2..=6 {
            append(&ledger, grant(n)).await.unwrap();
        }
        assert_eq!(kept_size(&path), Some(1), "not at every append");
        tokio::time::sleep(CHECKPOINT_EVERY + Duration::from_millis(300)).await;
        assert_eq!(kept_size(&path), Some(6), "within a second, all of them");
        ledger.stop(None);

        // Started again, the kept checkpoint is the ledger's, and nothing new is signed.
        let note = std::fs::read(crate::ledger_checkpoint::kept_path(&path)).unwrap();
        let ledger = spawned(&path).await;
        assert!(check_grant(&ledger, "agent-6").await.is_some());
        assert_eq!(
            std::fs::read(crate::ledger_checkpoint::kept_path(&path)).unwrap(),
            note
        );
        ledger.stop(None);
    }

    #[tokio::test]
    async fn a_ledger_put_back_behind_its_checkpoint_is_refused_and_accepted_once_a_person_removes_the_checkpoint()
     {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let older = dir.path().join("older.log");
        let ledger = spawned(&path).await;
        append(&ledger, grant(1)).await.unwrap();
        std::fs::copy(&path, &older).unwrap();
        append(&ledger, grant(2)).await.unwrap();
        tokio::time::sleep(CHECKPOINT_EVERY + Duration::from_millis(300)).await;
        ledger.stop(None);
        tokio::time::sleep(Duration::from_millis(100)).await;

        std::fs::copy(&older, &path).unwrap();
        let why = refused(opened(&path, None).await);
        assert!(
            why.contains("the ledger holds 1 entries, and its last checkpoint was signed at 2"),
            "{why}"
        );
        assert!(
            why.contains("it is not the ledger this agent signed"),
            "{why}"
        );
        assert!(!why.contains('\n'));

        std::fs::remove_file(crate::ledger_checkpoint::kept_path(&path)).unwrap();
        let (_, events) = ready(opened(&path, None).await);
        assert_eq!(events, vec![(0, grant(1))]);
    }

    #[tokio::test]
    async fn the_ledger_keeps_its_key_s_certificate_beside_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let ledger = spawned(&path).await;
        ledger
            .cast(LedgerMessage::KeyCertified(vec![
                "first".into(),
                "\nchain".into(),
            ]))
            .unwrap();
        ledger
            .cast(LedgerMessage::KeyCertified(vec!["renewed".into()]))
            .unwrap();
        let _ = check_grant(&ledger, "nobody").await;
        assert_eq!(
            std::fs::read_to_string(dir.path().join("ledger-key.crt")).unwrap(),
            "renewed"
        );
        ledger.stop(None);
    }

    #[tokio::test]
    async fn an_entry_not_as_its_writer_should_have_made_it_refuses_the_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let mut entry = credentials_agent_common::ledger::entry_of(&grant(1), &writer());
        entry.event.push(0);
        FileLog::open(&path)
            .unwrap()
            .log
            .append(&leaf_holding(entry))
            .unwrap();
        let why = refused(opened(&path, None).await);
        assert!(why.contains("credentials.grant v1"), "{why}");
        assert!(
            why.contains("not what its writer should have written"),
            "{why}"
        );
    }

    #[tokio::test]
    async fn a_damaged_ledger_is_refused_and_not_cut() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        {
            let mut log = FileLog::open(&path).unwrap().log;
            log.append(&leaf_of(&grant(1), &writer(), 1)).unwrap();
            log.append(&leaf_of(&grant(2), &writer(), 2)).unwrap();
        }
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[12] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        let why = refused(opened(&path, None).await);
        assert!(why.contains("damaged"), "{why}");
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[tokio::test]
    async fn the_actor_carries_on_a_copied_ledger_and_its_history_is_by_sequence_number() {
        let dir = tempfile::tempdir().unwrap();
        let (path, json) = (
            dir.path().join("ledger.log"),
            dir.path().join("events.jsonl"),
        );
        {
            let (mut old, _) = EventLog::<CredentialsEvent>::open(&json).unwrap();
            old.append(&grant(1)).unwrap();
        }
        let (ledger, _) = Actor::spawn(
            None,
            LedgerActor,
            LedgerActorArgs {
                log_path: path.to_str().unwrap().to_string(),
                copy_from: Some(json.to_str().unwrap().to_string()),
                projection_actor: crate::projection::tests::fake_projection_actor().await,
                key: crate::ledger::tests::key_beside(&path),
            },
        )
        .await
        .unwrap();
        assert!(check_grant(&ledger, "agent-1").await.is_some());
        append(&ledger, grant(2)).await.unwrap();
        let history = ractor::call!(ledger, |reply| LedgerMessage::GetFullHistory { reply })
            .unwrap()
            .unwrap();
        assert_eq!(history, vec![(1, grant(1)), (2, grant(2))]);
        ledger.stop(None);
    }

    /// The ledger records `username`'s account certificate, whose first DNS name is `account_id`: a person the
    /// authority knows, by both names.
    pub(crate) async fn holds_account(
        ledger: &ActorRef<LedgerMessage>,
        username: &str,
        account_id: &str,
    ) {
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec![account_id.to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .pem();
        ractor::call!(ledger, |reply| LedgerMessage::Append {
            event: CredentialsEvent::AccountCertificateIssued {
                account_id: account_id.to_string(),
                username: username.to_string(),
                serial: format!("serial-{username}"),
                timestamp: 1,
                certificate_pem: certificate,
            },
            reply
        })
        .unwrap()
        .unwrap();
    }

    pub(crate) async fn spawn_ledger(log_path: &str) -> ActorRef<LedgerMessage> {
        let (ledger, _) = Actor::spawn(
            None,
            LedgerActor,
            LedgerActorArgs {
                copy_from: None,
                log_path: log_path.to_string(),
                projection_actor: crate::projection::tests::fake_projection_actor().await,
                key: crate::ledger::tests::key_beside(log_path),
            },
        )
        .await
        .expect("ledger should spawn cleanly");
        ledger
    }

    pub(crate) async fn append(
        ledger: &ActorRef<LedgerMessage>,
        event: CredentialsEvent,
    ) -> Result<(), String> {
        match ractor::rpc::call(ledger, |reply| LedgerMessage::Append { event, reply }, None)
            .await
            .expect("call should succeed")
        {
            ractor::rpc::CallResult::Success(result) => result,
            other => panic!("expected Success, got {other:?}"),
        }
    }

    pub(crate) async fn check_grant(
        ledger: &ActorRef<LedgerMessage>,
        identity: &str,
    ) -> Option<GrantRecord> {
        match ractor::rpc::call(
            ledger,
            |reply| LedgerMessage::CheckGrant {
                identity: identity.to_string(),
                reply,
            },
            None,
        )
        .await
        .expect("call should succeed")
        {
            ractor::rpc::CallResult::Success(result) => result,
            other => panic!("expected Success, got {other:?}"),
        }
    }

    pub(crate) async fn check_certificate(
        ledger: &ActorRef<LedgerMessage>,
        identity: &str,
    ) -> Option<CertificateRecord> {
        match ractor::rpc::call(
            ledger,
            |reply| LedgerMessage::CheckCertificate {
                identity: identity.to_string(),
                reply,
            },
            None,
        )
        .await
        .expect("call should succeed")
        {
            ractor::rpc::CallResult::Success(result) => result,
            other => panic!("expected Success, got {other:?}"),
        }
    }

    pub(crate) async fn check_renewal(
        ledger: &ActorRef<LedgerMessage>,
        identity: &str,
        instance_binding: &str,
    ) -> bool {
        match ractor::rpc::call(
            ledger,
            |reply| LedgerMessage::CheckRenewal {
                identity: identity.to_string(),
                instance_binding: instance_binding.to_string(),
                cert_type: WorkloadCertType::Client,
                reply,
            },
            None,
        )
        .await
        .expect("call should succeed")
        {
            ractor::rpc::CallResult::Success(result) => result,
            other => panic!("expected Success, got {other:?}"),
        }
    }

    pub(crate) async fn admit(
        ledger: &ActorRef<LedgerMessage>,
        identity: &str,
        instance_binding: &str,
        now: i64,
    ) -> bool {
        admit_for(ledger, identity, instance_binding, None, now).await
    }

    pub(crate) async fn admit_for(
        ledger: &ActorRef<LedgerMessage>,
        identity: &str,
        instance_binding: &str,
        key: Option<&[u8]>,
        now: i64,
    ) -> bool {
        ractor::call!(ledger, |reply| LedgerMessage::Admit {
            identity: identity.to_string(),
            instance_binding: instance_binding.to_string(),
            cert_type: WorkloadCertType::Client,
            key: key.map(<[u8]>::to_vec),
            now,
            reply,
        })
        .expect("call should succeed")
    }

    // docs/architecture/deployments.md, "The renewal rule": the ledger admits one issuance per pod and type within the
    // bound, answering one ask at a time, so two asks at once are never both admitted; one given back is lifted.
    #[tokio::test]
    async fn the_ledger_admits_one_ask_of_two_at_once_and_lifts_one_given_back() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = spawn_ledger(dir.path().join("ledger.log").to_str().unwrap()).await;
        let (a, b) = tokio::join!(
            admit(&ledger, "alice", "pod-1", 1000),
            admit(&ledger, "alice", "pod-1", 1000)
        );
        assert!(a ^ b, "one of the two: {a} {b}");
        ledger
            .send_message(LedgerMessage::Release {
                identity: "alice".to_string(),
                instance_binding: "pod-1".to_string(),
                cert_type: WorkloadCertType::Client,
                at: 1000,
            })
            .unwrap();
        assert!(admit(&ledger, "alice", "pod-1", 2000).await, "given back");
        assert!(!admit(&ledger, "alice", "pod-1", 3000).await);
    }

    // docs/architecture/deployments.md, "A retry is not a second request": the same key asked twice at once is one
    // request asked again, and both are admitted; two keys at once are two requests, and one is.
    #[tokio::test]
    async fn the_ledger_admits_the_same_key_twice_at_once_and_one_of_two_keys() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = spawn_ledger(dir.path().join("ledger.log").to_str().unwrap()).await;
        let (same, other) = (b"one key".as_slice(), b"another key".as_slice());
        let (a, b) = tokio::join!(
            admit_for(&ledger, "alice", "pod-1", Some(same), 1000),
            admit_for(&ledger, "alice", "pod-1", Some(same), 1000)
        );
        assert!(a && b, "the same request: {a} {b}");
        let (c, d) = tokio::join!(
            admit_for(&ledger, "bob", "pod-1", Some(same), 1000),
            admit_for(&ledger, "bob", "pod-1", Some(other), 1000)
        );
        assert!(c ^ d, "one of the two: {c} {d}");
    }

    pub(crate) async fn check_agent_escrow_renewal(
        ledger: &ActorRef<LedgerMessage>,
        identity: &str,
    ) -> bool {
        match ractor::rpc::call(
            ledger,
            |reply| LedgerMessage::CheckAgentEscrowRenewal {
                identity: identity.to_string(),
                reply,
            },
            None,
        )
        .await
        .expect("call should succeed")
        {
            ractor::rpc::CallResult::Success(result) => result,
            other => panic!("expected Success, got {other:?}"),
        }
    }

    pub(crate) async fn check_agent_escrow_key(
        ledger: &ActorRef<LedgerMessage>,
        identity: &str,
    ) -> Option<crate::state::AgentEscrowCertificateRecord> {
        match ractor::rpc::call(
            ledger,
            |reply| LedgerMessage::CheckAgentEscrowKey {
                identity: identity.to_string(),
                reply,
            },
            None,
        )
        .await
        .expect("call should succeed")
        {
            ractor::rpc::CallResult::Success(result) => result,
            other => panic!("expected Success, got {other:?}"),
        }
    }

    async fn publish_authority(
        ledger: &ActorRef<LedgerMessage>,
        kind: &str,
        version: u64,
    ) -> Result<u64, String> {
        match ractor::rpc::call(
            ledger,
            |reply| LedgerMessage::PublishAuthority {
                kind: kind.to_string(),
                version,
                effect: None,
                reply,
            },
            None,
        )
        .await
        .expect("call should succeed")
        {
            ractor::rpc::CallResult::Success(result) => result,
            other => panic!("expected Success, got {other:?}"),
        }
    }

    async fn last_authority_sequence(ledger: &ActorRef<LedgerMessage>) -> u64 {
        match ractor::rpc::call(ledger, LedgerMessage::AuthoritySequence, None)
            .await
            .expect("call should succeed")
        {
            ractor::rpc::CallResult::Success(result) => result,
            other => panic!("expected Success, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authority_sequences_are_assigned_in_order_and_go_on_rising_across_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let ledger = spawn_ledger(path.to_str().unwrap()).await;
        assert_eq!(last_authority_sequence(&ledger).await, 0);
        assert_eq!(publish_authority(&ledger, "policy", 1).await, Ok(1));
        assert_eq!(publish_authority(&ledger, "groups", 1).await, Ok(2));
        assert_eq!(last_authority_sequence(&ledger).await, 2);
        ledger.stop_and_wait(None, None).await.unwrap();

        // The agent restarts: the ledger remembers where the numbering was.
        let ledger = spawn_ledger(path.to_str().unwrap()).await;
        assert_eq!(last_authority_sequence(&ledger).await, 2);
        assert_eq!(publish_authority(&ledger, "policy", 2).await, Ok(3));
        ledger.stop(None);
    }

    #[tokio::test]
    async fn the_revoked_serials_are_asked_of_the_ledger_and_a_change_is_announced() {
        use ractor::OutputPort;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let ledger = spawn_ledger(path.to_str().unwrap()).await;

        let port: std::sync::Arc<OutputPort<RevokedChanged>> =
            match ractor::rpc::call(&ledger, LedgerMessage::RevocationChanges, None)
                .await
                .unwrap()
            {
                ractor::rpc::CallResult::Success(port) => port,
                other => panic!("{other:?}"),
            };
        struct Sink(std::sync::Arc<std::sync::Mutex<Vec<RevokedChanged>>>);
        #[async_trait]
        impl Actor for Sink {
            type Msg = RevokedChanged;
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
        let heard = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (sink, _) = Actor::spawn(None, Sink(heard.clone()), ()).await.unwrap();
        port.subscribe(sink, Some);

        let revoke = |serial: &str| CredentialsEvent::Revoke {
            serial: serial.to_string(),
            reason: credentials_agent_common::events::RevocationReason::Compromised,
            revoked_by: "admin".to_string(),
            timestamp: 1000,
        };
        append(&ledger, revoke("0a")).await.unwrap();
        append(&ledger, revoke("0a")).await.unwrap(); // again: nothing new
        append(&ledger, revoke("0b")).await.unwrap();
        // An event that changes nothing about revocation announces nothing.
        append(
            &ledger,
            CredentialsEvent::AuthorityPublished {
                sequence: 1,
                kind: "policy".into(),
                version: 1,
                timestamp: 1,
                effect: None,
            },
        )
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        let serials = match ractor::rpc::call(&ledger, LedgerMessage::RevokedSerials, None)
            .await
            .unwrap()
        {
            ractor::rpc::CallResult::Success(serials) => serials,
            other => panic!("{other:?}"),
        };
        assert_eq!(serials, ["0a", "0b"]);
        assert_eq!(
            heard.lock().unwrap().len(),
            2,
            "one announcement per new serial"
        );
        ledger.stop(None);
    }

    async fn take_page(
        ledger: &ActorRef<LedgerMessage>,
        page: cert_issuer_common::record::RecordReply,
    ) -> Result<Option<(String, u64)>, String> {
        let bootstrap = Some(
            ["cassini.polar.serviceaccount.cluster.local".to_string()]
                .into_iter()
                .collect(),
        );
        ractor::call!(ledger, |reply| LedgerMessage::TakeRecordPage {
            page,
            bootstrap,
            reply
        })
        .unwrap()
    }

    async fn record_cursor(ledger: &ActorRef<LedgerMessage>) -> Option<(String, u64)> {
        ractor::call!(ledger, |reply| LedgerMessage::RecordCursor { reply }).unwrap()
    }

    #[tokio::test]
    async fn a_page_of_cert_issuer_s_record_is_recorded_durably_and_found_after_a_restart() {
        use cert_issuer_common::record::{IssuePath, RecordEntry, RecordReply};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let ledger = spawn_ledger(path.to_str().unwrap()).await;
        assert_eq!(record_cursor(&ledger).await, None);
        let page = RecordReply {
            log: "log-1".to_string(),
            entries: vec![RecordEntry {
                unattested: None,
                log: "log-1".to_string(),
                seq: 3,
                serial: "c3".to_string(),
                identity: "cassini.polar.serviceaccount.cluster.local".to_string(),
                // A client certificate: the lookup is of a requester's (state.rs, certificate_for).
                cert_type: cert_issuer_common::CertType::Client,
                path: IssuePath::TokenOnly,
                instance_binding: Some("pod".to_string()),
                signed_at: 1000,
                not_after: 5000,
                certificate_pem: "pem".to_string(),
            }],
            tickets: Vec::new(),
            more: false,
        };
        assert_eq!(
            take_page(&ledger, page.clone()).await,
            Ok(Some(("log-1".to_string(), 3)))
        );
        let size = std::fs::metadata(&path).unwrap().len();
        // The same page again appends nothing.
        assert_eq!(
            take_page(&ledger, page).await,
            Ok(Some(("log-1".to_string(), 3)))
        );
        assert_eq!(std::fs::metadata(&path).unwrap().len(), size);
        ledger.stop(None);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let again = spawn_ledger(path.to_str().unwrap()).await;
        assert_eq!(record_cursor(&again).await, Some(("log-1".to_string(), 3)));
        let found = ractor::call!(again, |reply| LedgerMessage::CheckCertificate {
            identity: "cassini.polar.serviceaccount.cluster.local".to_string(),
            reply,
        })
        .unwrap()
        .expect("a reported certificate is found after a restart");
        assert_eq!(found.serial, "c3");
        assert!(found.reported);
    }

    #[tokio::test]
    async fn append_then_check_grant_round_trips_through_real_actor_messages() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let ledger = spawn_ledger(path.to_str().unwrap()).await;

        assert!(check_grant(&ledger, "alice").await.is_none());

        append(
            &ledger,
            CredentialsEvent::Grant {
                target_identity: "alice".to_string(),
                permissions: vec![cert_issuer_common::permission::Permission {
                    scope: cert_issuer_common::permission::PermissionScope::ServiceToService,
                    target: None,
                }],
                granted_by: "admin".to_string(),
                timestamp: 1000,
                reason: GrantReason::UserOnboarding,
            },
        )
        .await
        .unwrap();

        let grant = check_grant(&ledger, "alice").await;
        assert!(grant.is_some());
        assert_eq!(grant.unwrap().granted_by, "admin");

        ledger.stop(None);
    }

    #[tokio::test]
    async fn issuance_consumes_grant_and_enables_renewal_check_through_real_actor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let ledger = spawn_ledger(path.to_str().unwrap()).await;

        append(
            &ledger,
            CredentialsEvent::Grant {
                target_identity: "alice".to_string(),
                permissions: vec![cert_issuer_common::permission::Permission {
                    scope: cert_issuer_common::permission::PermissionScope::ServiceToService,
                    target: None,
                }],
                granted_by: "admin".to_string(),
                timestamp: 1000,
                reason: GrantReason::UserOnboarding,
            },
        )
        .await
        .unwrap();

        append(
            &ledger,
            CredentialsEvent::IssuanceCompleted {
                identity: "alice".to_string(),
                instance_binding: "pod-uid-1".to_string(),
                serial: "serial-1".to_string(),
                timestamp: 2000,
                cert_type: credentials_agent_common::issuance::WorkloadCertType::Client,
                grant_key: None,
                certificate_pem: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
                    .to_string(),
            },
        )
        .await
        .unwrap();

        assert!(check_grant(&ledger, "alice").await.is_none());
        assert!(check_renewal(&ledger, "alice", "pod-uid-1").await);
        assert!(!check_renewal(&ledger, "alice", "different-pod-uid").await);

        let cert = check_certificate(&ledger, "alice").await;
        assert!(cert.is_some());
        assert_eq!(
            cert.unwrap().certificate_pem,
            "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
        );
        assert!(check_certificate(&ledger, "nobody").await.is_none());

        ledger.stop(None);
    }

    #[tokio::test]
    async fn agent_escrow_issuance_is_visible_through_the_real_actor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let ledger = spawn_ledger(path.to_str().unwrap()).await;

        assert!(!check_agent_escrow_renewal(&ledger, "git-observer").await);
        assert!(
            check_agent_escrow_key(&ledger, "git-observer")
                .await
                .is_none()
        );

        append(
            &ledger,
            CredentialsEvent::AgentEscrowIssuanceCompleted {
                identity: "git-observer".to_string(),
                instance_binding: "pod-uid-1".to_string(),
                serial: "service-serial-1".to_string(),
                timestamp: 2000,
                certificate_pem:
                    "-----BEGIN CERTIFICATE-----\nfake-service-cert\n-----END CERTIFICATE-----\n"
                        .to_string(),
            },
        )
        .await
        .unwrap();

        assert!(check_agent_escrow_renewal(&ledger, "git-observer").await);
        assert!(!check_agent_escrow_renewal(&ledger, "nobody").await);

        let record = check_agent_escrow_key(&ledger, "git-observer").await;
        assert!(record.is_some());
        assert_eq!(record.unwrap().serial, "service-serial-1");
        assert!(check_agent_escrow_key(&ledger, "nobody").await.is_none());

        ledger.stop(None);
    }

    #[tokio::test]
    async fn state_survives_a_real_stop_and_respawn_against_the_same_log() {
        // The real, end-to-end proof: not just that EventLog replays
        // correctly in isolation (already tested in lib::event_log),
        // but that stopping and respawning the actual LedgerActor
        // against the same file rebuilds correct, queryable state
        // through the real actor message-passing path.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");

        {
            let ledger = spawn_ledger(path.to_str().unwrap()).await;
            append(
                &ledger,
                CredentialsEvent::Grant {
                    target_identity: "alice".to_string(),
                    permissions: vec![cert_issuer_common::permission::Permission {
                        scope: cert_issuer_common::permission::PermissionScope::ServiceToService,
                        target: None,
                    }],
                    granted_by: "admin".to_string(),
                    timestamp: 1000,
                    reason: GrantReason::UserOnboarding,
                },
            )
            .await
            .unwrap();
            append(
                &ledger,
                CredentialsEvent::IssuanceCompleted {
                    identity: "alice".to_string(),
                    instance_binding: "pod-uid-1".to_string(),
                    serial: "serial-1".to_string(),
                    timestamp: 2000,
                    cert_type: credentials_agent_common::issuance::WorkloadCertType::Client,
                    grant_key: None,
                    certificate_pem: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
                        .to_string(),
                },
            )
            .await
            .unwrap();
            ledger.stop_and_wait(None, None).await.unwrap();
        }

        let respawned = spawn_ledger(path.to_str().unwrap()).await;
        assert!(
            check_grant(&respawned, "alice").await.is_none(),
            "grant must still be consumed after a real restart"
        );
        assert!(
            check_renewal(&respawned, "alice", "pod-uid-1").await,
            "the issued certificate must still be on record after a real restart"
        );

        respawned.stop(None);
    }

    pub(crate) async fn record_admin_action(
        ledger: &ActorRef<LedgerMessage>,
        event: CredentialsEvent,
    ) -> Result<bool, String> {
        match ractor::rpc::call(
            ledger,
            |reply| LedgerMessage::RecordAdminAction { event, reply },
            None,
        )
        .await
        .expect("call should succeed")
        {
            ractor::rpc::CallResult::Success(result) => result,
            other => panic!("expected Success, got {other:?}"),
        }
    }

    fn recorded_grant(nonce: &str) -> CredentialsEvent {
        use credentials_agent_common::admin_action::{
            AdminAction, AdminActionBody, SignedAdminAction,
        };
        let payload = AdminActionBody {
            nonce: nonce.to_string(),
            action: AdminAction::Grant {
                target_identity: "alice".to_string(),
                permissions: vec![],
                reason: GrantReason::UserOnboarding,
            },
        }
        .to_payload()
        .unwrap();
        let signed = SignedAdminAction {
            payload,
            author_serial: "a1".to_string(),
            signature: vec![],
        };
        CredentialsEvent::AdminActionRecorded {
            payload_hash: signed.payload_hash(),
            signed,
            author_account_id: "admin-acct".to_string(),
            timestamp: 5000,
            account_id: None,
        }
    }

    #[tokio::test]
    async fn a_recorded_admin_action_takes_effect_once_and_a_replay_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let ledger = spawn_ledger(path.to_str().unwrap()).await;

        assert_eq!(
            record_admin_action(&ledger, recorded_grant("n1")).await,
            Ok(true)
        );
        assert_eq!(
            check_grant(&ledger, "alice").await.unwrap().granted_by,
            "admin-acct"
        );

        // The identical signed payload is a replay.
        assert_eq!(
            record_admin_action(&ledger, recorded_grant("n1")).await,
            Ok(false)
        );
        // The same action with a fresh nonce is a legitimate repeat.
        assert_eq!(
            record_admin_action(&ledger, recorded_grant("n2")).await,
            Ok(true)
        );

        ledger.stop(None);
    }
}
