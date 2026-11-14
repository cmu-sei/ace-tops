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

//! The store's logs (docs/architecture/record-store.md, bite 2): each a named, append-only log of signed facts, kept as a
//! file of frames under the store's volume (`polar_log::file::FileLog`). Every checkpoint is signed with the store's one
//! checkpoint key, which the agent's crypto actor keeps, makes once and has the credentials agent certify
//! (`polar_agent_builder::crypto::CheckpointHandle`): the domain never holds it. Its verifier key is what witnesses and
//! readers pin (decision 5).
//!
//! What this holds to: a log only grows; each leaf carries the time the store admitted it and who brought it; an entry
//! that is not one is never appended; a checkpoint is the log's origin, size and root, signed. Admission beyond the
//! envelope (signatures, policy) is the caller's, per log (bite 3).

use polar_log::checkpoint::{Checkpoint, NoteVerifier, open, open_signed};
use polar_log::entry::{Entry, Leaf};
use polar_log::file::{FileLog, LogError, Replayed};
use polar_log::merkle::{Hash, consistency_proof, inclusion_proof, root};
use polar_log::tiles::{Level, MAX_ENTRY, TILE_WIDTH, Tile, entry_bundle, hash_tile};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LogsError {
    #[error(transparent)]
    Log(#[from] LogError),
    #[error("`{0}` is not a log's name (a-z, 0-9 and -)")]
    Name(String),
    #[error("there is no log `{0}`")]
    NoLog(String),
    #[error("the entry is not one: {0}")]
    NotAnEntry(String),
    #[error("the leaf is {0} bytes, longer than a log served as tiles carries ({MAX_ENTRY})")]
    TooLong(usize),
    #[error("{0}")]
    Range(String),
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("the co-signed checkpoint is not kept: {0}")]
    NotCosigned(String),
    #[error(
        "{path}: the co-signed checkpoint kept is not one of its log's ({why}): the log is not served"
    )]
    Kept { path: PathBuf, why: String },
    #[error("{path}: the frame of leaf {seq} is malformed ({why}): the log is not served")]
    Malformed {
        path: PathBuf,
        seq: u64,
        why: String,
    },
}

/// Whether `name` may name a log.
pub fn is_log_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A checkpoint signed for the witness, with what the witness needs to check it against what it co-signed last.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    /// The size the store believes the witness holds.
    pub old: u64,
    /// The consistency proof from `old` to `size`; empty from 0, and between equal sizes.
    pub proof: Vec<Hash>,
    /// The signed checkpoint, a note.
    pub checkpoint: String,
    pub size: u64,
}

/// The file a log's latest co-signed checkpoint is kept in, beside it.
fn kept_path(root: &Path, name: &str) -> PathBuf {
    root.join(format!("{name}.cosigned"))
}

/// The store's logs.
pub struct Logs {
    root: PathBuf,
    origin: String,
    /// The store's checkpoint verifier key, as the crypto actor gives it: what a kept co-signed checkpoint must open
    /// under, beside the witness's. A public key: the store holds no private one.
    own: NoteVerifier,
    logs: BTreeMap<String, FileLog>,
    /// For each log witnessed, its latest co-signed checkpoint and its size: what readers are served.
    cosigned: BTreeMap<String, (String, u64)>,
    /// For each log, the digest of each entry it holds and where: so the same entry is appended once.
    seen: BTreeMap<String, std::collections::HashMap<Hash, u64>>,
}

/// What [`Logs::append_missing`] did: the sequence of each entry appended, and each left out, with why.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Appended {
    pub appended: Vec<u64>,
    pub left_out: Vec<(String, String)>,
}

/// The digest an entry is known by in a log: SHA-256 of its bytes.
fn digest(entry: &[u8]) -> Hash {
    use sha2::{Digest, Sha256};
    Sha256::digest(entry).into()
}

impl Logs {
    /// The logs under `root`, made if it is new, each log's checkpoints naming `origin/<log>` and signed under the
    /// verifier key `own`. Every log there is replayed now: one that is damaged, or holds a malformed leaf, refuses the
    /// store's start, said with where; so does a kept co-signed checkpoint that is not the store's of the log beside it.
    pub fn open(root: &Path, origin: &str, own: &str) -> Result<Self, LogsError> {
        let io = |source| LogsError::Io {
            path: root.to_path_buf(),
            source,
        };
        let own = NoteVerifier::parse(own).map_err(|e| {
            LogsError::Range(format!(
                "the store's checkpoint key {own} does not read: {e}"
            ))
        })?;
        std::fs::create_dir_all(root).map_err(io)?;
        let mut logs = BTreeMap::new();
        let mut seen = BTreeMap::new();
        for entry in std::fs::read_dir(root).map_err(io)? {
            let path = entry.map_err(io)?.path();
            let Some(name) = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(".log"))
            else {
                continue;
            };
            if !is_log_name(name) {
                continue;
            }
            let opened = FileLog::open(&path)?;
            if let Some(cut) = opened.torn {
                tracing::warn!(
                    log = name,
                    bytes = cut,
                    "a write that did not finish was cut back"
                );
            }
            let mut digests = std::collections::HashMap::new();
            for r in &opened.replayed {
                match r {
                    Replayed::Malformed { seq, why } => {
                        return Err(LogsError::Malformed {
                            path: path.clone(),
                            seq: *seq,
                            why: why.clone(),
                        });
                    }
                    Replayed::Entry { seq, leaf, .. } => {
                        digests.entry(digest(&leaf.entry)).or_insert(*seq);
                    }
                }
            }
            seen.insert(name.to_string(), digests);
            logs.insert(name.to_string(), opened.log);
        }
        let mut held = Self {
            root: root.to_path_buf(),
            origin: origin.to_string(),
            own,
            logs,
            cosigned: BTreeMap::new(),
            seen,
        };
        // A kept checkpoint was checked under the witness's key when it was kept; here it must still be the store's
        // checkpoint of the log beside it, or the two are not one log's, and neither is served.
        let names: Vec<String> = held.logs.keys().cloned().collect();
        for name in names {
            let path = kept_path(root, &name);
            let note = match std::fs::read_to_string(&path) {
                Ok(note) => note,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => return Err(LogsError::Io { path, source }),
            };
            let size = held
                .of_this_log(&name, &note)
                .map_err(|why| LogsError::Kept { path, why })?;
            held.cosigned.insert(name, (note, size));
        }
        Ok(held)
    }

    /// The size of the checkpoint `note` states, when the store's key signed it and it is this log's, as it stands or
    /// as it stood.
    fn of_this_log(&self, name: &str, note: &str) -> Result<u64, String> {
        let (text, _) = open(note, std::slice::from_ref(&self.own)).map_err(|e| e.to_string())?;
        let checkpoint = Checkpoint::parse(&text).map_err(|e| e.to_string())?;
        if checkpoint.origin != format!("{}/{name}", self.origin) {
            return Err(format!("its origin is {}", checkpoint.origin));
        }
        let root = self
            .root_at(name, checkpoint.size)
            .map_err(|e| e.to_string())?;
        if root != checkpoint.root {
            return Err(format!(
                "its root of {} leaves is not the log's",
                checkpoint.size
            ));
        }
        Ok(checkpoint.size)
    }

    /// The log's checkpoint now, unsigned, for the witness, which co-signed `old` last: its text, the proof from there,
    /// and its size. The crypto actor signs the text ([`LogsMessage::Submission`]).
    pub fn submission(&self, name: &str, old: u64) -> Result<(String, Vec<Hash>, u64), LogsError> {
        let text = self.checkpoint_text(name)?;
        let size = self.logs.get(name).map_or(0, FileLog::size);
        let proof = if old == 0 || old == size {
            Vec::new()
        } else {
            self.consistency(name, old, size)?
        };
        Ok((text, proof, size))
    }

    /// Keeps the witness's co-signature `line` over the store's signed `checkpoint` of the log `name`, when the store's
    /// key and the pinned `witness` key both verify it, it is this log's, and it is no older than the one kept: written
    /// to a new file, synced and renamed over, before it is served. Its size.
    pub fn keep_cosigned(
        &mut self,
        name: &str,
        checkpoint: &str,
        line: &str,
        witness: &NoteVerifier,
    ) -> Result<u64, LogsError> {
        let refused = |why: String| LogsError::NotCosigned(why);
        if !witness.is_cosigner() {
            return Err(refused(format!(
                "{} is not a witness's key",
                witness.name()
            )));
        }
        let note = format!("{checkpoint}{line}");
        let opened = open_signed(&note, &[self.own.clone(), witness.clone()])
            .map_err(|e| refused(e.to_string()))?;
        // Only the two keys are trusted, each at most once: both signed when two did.
        if opened.by.len() < 2 {
            return Err(refused(
                "it is not signed by both the store's key and the witness's".to_string(),
            ));
        }
        let size = self.of_this_log(name, &note).map_err(refused)?;
        if let Some((_, kept)) = self.cosigned.get(name)
            && size < *kept
        {
            return Err(refused(format!(
                "it is of {size} leaves, older than the {kept} kept"
            )));
        }
        let path = kept_path(&self.root, name);
        let fresh = self.root.join(format!("{name}.cosigned.new"));
        let io = |path: &Path| {
            let path = path.to_path_buf();
            move |source| LogsError::Io { path, source }
        };
        {
            let mut file = std::fs::File::create(&fresh).map_err(io(&fresh))?;
            std::io::Write::write_all(&mut file, note.as_bytes()).map_err(io(&fresh))?;
            file.sync_all().map_err(io(&fresh))?;
        }
        std::fs::rename(&fresh, &path).map_err(io(&path))?;
        std::fs::File::open(&self.root)
            .and_then(|dir| dir.sync_all())
            .map_err(io(&self.root))?;
        self.cosigned.insert(name.to_string(), (note, size));
        Ok(size)
    }

    /// The log's latest co-signed checkpoint, what readers are served; none before the witness first co-signed it.
    pub fn cosigned(&self, name: &str) -> Option<&str> {
        self.cosigned.get(name).map(|(note, _)| note.as_str())
    }

    /// The size of the log's latest co-signed checkpoint.
    pub fn cosigned_size(&self, name: &str) -> Option<u64> {
        self.cosigned.get(name).map(|(_, size)| *size)
    }

    /// The names of the logs held.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.logs.keys().map(String::as_str)
    }

    fn log(&self, name: &str) -> Result<&FileLog, LogsError> {
        self.logs
            .get(name)
            .ok_or_else(|| LogsError::NoLog(name.to_string()))
    }

    /// Appends `entry` (an envelope's bytes) to the log `name`, made if it is new, as admitted at `now_ms` from
    /// `submitter`: its sequence number. Bytes that are not an entry are refused, and nothing is appended.
    pub fn append(
        &mut self,
        name: &str,
        entry: &[u8],
        submitter: &str,
        now_ms: u64,
    ) -> Result<u64, LogsError> {
        if !is_log_name(name) {
            return Err(LogsError::Name(name.to_string()));
        }
        Entry::decode(entry).map_err(|e| LogsError::NotAnEntry(e.to_string()))?;
        // The log's time never goes back: a clock stepped back admits at the last leaf's time, so "as of" a time is a
        // prefix of the log.
        let last_ms = match self.logs.get(name) {
            Some(log) if log.size() > 0 => {
                log.leaf(log.size() - 1)?.map_or(0, |l| l.admitted_at_ms)
            }
            _ => 0,
        };
        let leaf = Leaf {
            entry: entry.to_vec(),
            admitted_at_ms: now_ms.max(last_ms),
            submitter: submitter.to_string(),
        };
        // Every log is served as tiles, whose bundles carry a leaf of at most MAX_ENTRY bytes: a longer one is refused
        // here, so nothing the log holds is one a reader cannot fetch.
        let length = leaf.encode().len();
        if length > MAX_ENTRY {
            return Err(LogsError::TooLong(length));
        }
        if !self.logs.contains_key(name) {
            let opened = FileLog::open(&self.root.join(format!("{name}.log")))?;
            self.logs.insert(name.to_string(), opened.log);
        }
        let log = self.logs.get_mut(name).expect("made above");
        let seq = log.append(&leaf)?;
        self.seen
            .entry(name.to_string())
            .or_default()
            .entry(digest(entry))
            .or_insert(seq);
        Ok(seq)
    }

    /// Appends `entry` as [`Logs::append`] does, unless the log holds it already: its sequence number, and whether it
    /// was appended now. What a sender sends again after its answer was lost is not added twice.
    pub fn append_once(
        &mut self,
        name: &str,
        entry: &[u8],
        submitter: &str,
        now_ms: u64,
    ) -> Result<(u64, bool), LogsError> {
        if let Some(seq) = self.seen.get(name).and_then(|d| d.get(&digest(entry))) {
            return Ok((*seq, false));
        }
        Ok((self.append(name, entry, submitter, now_ms)?, true))
    }

    /// Appends each of `entries` (an entry's bytes, by the path it came from) that says what no entry of the log says
    /// yet, in path order, as admitted at `now_ms` from `submitter`: what a store keeping no log took meanwhile, brought
    /// in at the next start. An entry is known here by its kind and event, not by its bytes, which also name the version
    /// that wrote it, so one appended before an upgrade is not appended again. One the log cannot take (not an entry, or
    /// too long to serve) is left out and said; anything else refuses, as an append does.
    pub fn append_missing(
        &mut self,
        name: &str,
        entries: &BTreeMap<String, Vec<u8>>,
        submitter: &str,
        now_ms: u64,
    ) -> Result<Appended, LogsError> {
        let says = |entry: &Entry| digest(&[entry.kind.as_bytes(), b"\n", &entry.event].concat());
        let mut held = std::collections::HashSet::new();
        if let Some(log) = self.logs.get(name) {
            for seq in 0..log.size() {
                if let Some(leaf) = log.leaf(seq)?
                    && let Ok(entry) = Entry::decode(&leaf.entry)
                {
                    held.insert(says(&entry));
                }
            }
        }
        let mut done = Appended::default();
        for (path, bytes) in entries {
            let entry = match Entry::decode(bytes) {
                Ok(entry) => entry,
                Err(e) => {
                    done.left_out.push((
                        path.clone(),
                        LogsError::NotAnEntry(e.to_string()).to_string(),
                    ));
                    continue;
                }
            };
            if !held.insert(says(&entry)) {
                continue;
            }
            match self.append(name, bytes, submitter, now_ms) {
                Ok(seq) => done.appended.push(seq),
                Err(e @ LogsError::TooLong(_)) => done.left_out.push((path.clone(), e.to_string())),
                Err(e) => return Err(e),
            }
        }
        Ok(done)
    }

    /// How many leaves the log holds.
    pub fn size(&self, name: &str) -> Result<u64, LogsError> {
        Ok(self.log(name)?.size())
    }

    /// The leaf at `seq`; none past the end.
    pub fn leaf(&self, name: &str, seq: u64) -> Result<Option<Leaf>, LogsError> {
        Ok(self.log(name)?.leaf(seq)?)
    }

    /// The log's checkpoint now, unsigned: the text a C2SP signed note carries, for the crypto actor to sign. A log
    /// nothing was appended to yet is empty.
    pub fn checkpoint_text(&self, name: &str) -> Result<String, LogsError> {
        if !is_log_name(name) {
            return Err(LogsError::Name(name.to_string()));
        }
        let (size, root) = match self.logs.get(name) {
            Some(log) => (log.size(), log.root()),
            None => (0, root(&[])),
        };
        let checkpoint = Checkpoint {
            origin: format!("{}/{name}", self.origin),
            size,
            root,
        };
        Ok(checkpoint.text())
    }

    /// What the log serves at `path` under its prefix, as C2SP tlog-tiles lays a log out: a tile of hashes or a bundle
    /// of leaves. None when `path` names no tile, or one the log has not grown to.
    pub fn tile(&self, name: &str, path: &str) -> Result<Option<Vec<u8>>, LogsError> {
        let (Some(log), Some(tile)) = (self.logs.get(name), Tile::parse(path)) else {
            return Ok(None);
        };
        if tile.level() != Level::Entries {
            return Ok(hash_tile(log.hashes(), tile));
        }
        let Some(from) = tile.index().checked_mul(TILE_WIDTH) else {
            return Ok(None);
        };
        if from.saturating_add(tile.width()) > log.size() {
            return Ok(None);
        }
        let mut leaves = Vec::with_capacity(tile.width() as usize);
        for seq in from..from + tile.width() {
            let leaf = log.leaf(seq)?.ok_or_else(|| {
                LogsError::Range(format!("{name} has no leaf {seq} below its size"))
            })?;
            leaves.push(leaf.encode());
        }
        entry_bundle(&leaves)
            .map(Some)
            .map_err(|e| LogsError::Range(e.to_string()))
    }

    /// The root of the log's tree of its first `size` leaves.
    pub fn root_at(&self, name: &str, size: u64) -> Result<Hash, LogsError> {
        let hashes = self.prefix(name, size)?;
        Ok(root(hashes))
    }

    fn prefix(&self, name: &str, size: u64) -> Result<&[Hash], LogsError> {
        let hashes = self.log(name)?.hashes();
        hashes.get(..size as usize).ok_or_else(|| {
            LogsError::Range(format!("{name} holds {} leaves, not {size}", hashes.len()))
        })
    }

    /// The proof that leaf `seq` is in the log's tree of `size` leaves.
    pub fn inclusion(&self, name: &str, seq: u64, size: u64) -> Result<Vec<Hash>, LogsError> {
        inclusion_proof(seq as usize, self.prefix(name, size)?)
            .ok_or_else(|| LogsError::Range(format!("leaf {seq} is not in a tree of {size}")))
    }

    /// The proof that the log's tree of `old` leaves is the first part of its tree of `new`.
    pub fn consistency(&self, name: &str, old: u64, new: u64) -> Result<Vec<Hash>, LogsError> {
        consistency_proof(old as usize, self.prefix(name, new)?)
            .ok_or_else(|| LogsError::Range(format!("no proof from {old} to {new}")))
    }
}

/// What signs the store's checkpoints: the agent's crypto actor in the store ([`CheckpointHandle`]), a key of its own in a
/// test. A signature line for a checkpoint's text, and the verifier key readers and witnesses pin.
///
/// [`CheckpointHandle`]: polar_agent_builder::crypto::CheckpointHandle
#[ractor::async_trait]
pub trait CheckpointSigner: Send + Sync + 'static {
    async fn sign_line(&self, text: String) -> Result<String, String>;
    async fn verifier_key(&self) -> Result<String, String>;
}

#[ractor::async_trait]
impl CheckpointSigner for polar_agent_builder::crypto::CheckpointHandle {
    async fn sign_line(&self, text: String) -> Result<String, String> {
        self.sign(text).await
    }
    async fn verifier_key(&self) -> Result<String, String> {
        self.key().await.map(|(verifier, _)| verifier)
    }
}

/// The store's identity, from the verifier key its checkpoints are signed under (`<identity>/checkpoint+<id>+<key>`, as
/// the crypto actor names the key): the origin each log's checkpoints carry, `<identity>/<log>`. The crypto actor signs
/// only a checkpoint of that origin, so the store takes it from the key rather than from a setting of its own.
pub fn origin_of(verifier_key: &str) -> Option<String> {
    let name = verifier_key.split('+').next()?;
    let identity = name.strip_suffix("/checkpoint")?;
    (!identity.is_empty()).then(|| identity.to_string())
}

/// What the logs are asked: the one owner of the store's logs, so nothing else writes them.
pub enum LogsMessage {
    /// Appends an entry to a log unless it holds it already, as admitted now: its sequence, and whether it is new.
    AppendOnce {
        log: String,
        entry: Vec<u8>,
        submitter: String,
        reply: ractor::RpcReplyPort<Result<(u64, bool), String>>,
    },
    /// Appends each entry that says what the log does not yet, as admitted now, as [`Logs::append_missing`] does.
    AppendMissing {
        log: String,
        entries: BTreeMap<String, Vec<u8>>,
        submitter: String,
        reply: ractor::RpcReplyPort<Result<Appended, String>>,
    },
    /// The log's latest co-signed checkpoint, what readers are served; none before the witness first co-signed it.
    Cosigned {
        log: String,
        reply: ractor::RpcReplyPort<Option<String>>,
    },
    /// Each log's name, its size, and the size of its latest co-signed checkpoint: what the witness has yet to see.
    Witnessing(ractor::RpcReplyPort<Vec<(String, u64, Option<u64>)>>),
    /// The log's checkpoint now, signed, for a witness that co-signed `old` last, with the proof from there.
    Submission {
        log: String,
        old: u64,
        reply: ractor::RpcReplyPort<Result<Submission, String>>,
    },
    /// Keeps the witness's co-signature over a checkpoint the store submitted, when the pinned key verifies it: its size.
    KeepCosigned {
        log: String,
        checkpoint: String,
        line: String,
        witness: NoteVerifier,
        reply: ractor::RpcReplyPort<Result<u64, String>>,
    },
    /// The leaf at a sequence.
    Leaf {
        log: String,
        seq: u64,
        reply: ractor::RpcReplyPort<Result<Option<Leaf>, String>>,
    },
    /// The tile or entry bundle at a path under the log's prefix; none where there is none.
    Tile {
        log: String,
        path: String,
        reply: ractor::RpcReplyPort<Result<Option<Vec<u8>>, String>>,
    },
    /// The key the checkpoints are signed with, as witnesses pin it.
    VerifierKey(ractor::RpcReplyPort<Result<String, String>>),
}

/// The repository whose readers may read `log`, for each log the store serves to people (docs/architecture/
/// record-store.md, "Bite 3"): a log holds what its repository held, so it is read by the same people.
pub fn governing_repo(log: &str) -> Option<&'static str> {
    match log {
        crate::evidence::EVIDENCE_LOG => Some(polar_git_server_common::EVIDENCE_REPO),
        _ => None,
    }
}

pub struct LogsActor;

pub struct LogsArgs {
    pub root: PathBuf,
    pub origin: String,
    /// What signs the checkpoints: the crypto actor's [`CheckpointHandle`](polar_agent_builder::crypto::CheckpointHandle).
    pub signer: std::sync::Arc<dyn CheckpointSigner>,
}

pub struct LogsState {
    logs: Logs,
    signer: std::sync::Arc<dyn CheckpointSigner>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[ractor::async_trait]
impl ractor::Actor for LogsActor {
    type Msg = LogsMessage;
    type State = LogsState;
    type Arguments = LogsArgs;

    async fn pre_start(
        &self,
        _: ractor::ActorRef<Self::Msg>,
        args: LogsArgs,
    ) -> Result<Self::State, ractor::ActorProcessingErr> {
        let key = args.signer.verifier_key().await?;
        let logs = Logs::open(&args.root, &args.origin, &key)?;
        tracing::info!(root = %args.root.display(), %key, "the store's logs are open");
        Ok(LogsState {
            logs,
            signer: args.signer,
        })
    }

    async fn handle(
        &self,
        _: ractor::ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ractor::ActorProcessingErr> {
        let logs = &mut state.logs;
        match message {
            LogsMessage::AppendOnce {
                log,
                entry,
                submitter,
                reply,
            } => {
                let _ = reply.send(
                    logs.append_once(&log, &entry, &submitter, now_ms())
                        .map_err(|e| e.to_string()),
                );
            }
            LogsMessage::AppendMissing {
                log,
                entries,
                submitter,
                reply,
            } => {
                let _ = reply.send(
                    logs.append_missing(&log, &entries, &submitter, now_ms())
                        .map_err(|e| e.to_string()),
                );
            }
            LogsMessage::Cosigned { log, reply } => {
                let _ = reply.send(logs.cosigned(&log).map(str::to_string));
            }
            LogsMessage::Witnessing(reply) => {
                let sizes = logs
                    .logs
                    .iter()
                    .map(|(name, log)| (name.clone(), log.size(), logs.cosigned_size(name)))
                    .collect();
                let _ = reply.send(sizes);
            }
            LogsMessage::Submission { log, old, reply } => {
                let submitted = match logs.submission(&log, old) {
                    Ok((text, proof, size)) => {
                        state
                            .signer
                            .sign_line(text.clone())
                            .await
                            .map(|line| Submission {
                                old,
                                proof,
                                checkpoint: format!("{text}\n{line}"),
                                size,
                            })
                    }
                    Err(e) => Err(e.to_string()),
                };
                let _ = reply.send(submitted);
            }
            LogsMessage::KeepCosigned {
                log,
                checkpoint,
                line,
                witness,
                reply,
            } => {
                let _ = reply.send(
                    logs.keep_cosigned(&log, &checkpoint, &line, &witness)
                        .map_err(|e| e.to_string()),
                );
            }
            LogsMessage::Tile { log, path, reply } => {
                let _ = reply.send(logs.tile(&log, &path).map_err(|e| e.to_string()));
            }
            LogsMessage::Leaf { log, seq, reply } => {
                let _ = reply.send(logs.leaf(&log, seq).map_err(|e| e.to_string()));
            }
            LogsMessage::VerifierKey(reply) => {
                let _ = reply.send(state.signer.verifier_key().await);
            }
        }
        Ok(())
    }
}

/// A checkpoint key held in process, for tests: in the store it is the crypto actor's, never the domain's.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use super::CheckpointSigner;
    use polar_log::checkpoint::NoteSigner;

    /// Signs as the crypto actor does, under `<identity>/checkpoint`, with a fixed key.
    pub struct KeySigner(NoteSigner);

    impl KeySigner {
        pub fn new(identity: &str) -> Self {
            KeySigner(
                NoteSigner::new(
                    &format!("{identity}/checkpoint"),
                    p256::ecdsa::SigningKey::from_slice(&[7; 32]).expect("a fixed key is a key"),
                )
                .expect("a fixed key signs"),
            )
        }
    }

    #[ractor::async_trait]
    impl CheckpointSigner for KeySigner {
        async fn sign_line(&self, text: String) -> Result<String, String> {
            Ok(self.0.sign_line(&text))
        }
        async fn verifier_key(&self) -> Result<String, String> {
            Ok(self.0.verifier_key())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_log::checkpoint::{NoteSigner, NoteVerifier, open};

    /// A checkpoint key of the test's own, as the crypto actor's signs: `<identity>/checkpoint`.
    fn signer() -> NoteSigner {
        NoteSigner::new(
            &format!("{ORIGIN}/checkpoint"),
            p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap(),
        )
        .unwrap()
    }

    /// The log's checkpoint, signed as the store's crypto actor signs it.
    fn signed(logs: &Logs, name: &str) -> String {
        signer().sign(&logs.checkpoint_text(name).unwrap())
    }

    /// The log's submission for a witness that co-signed `old` last, signed as the logs actor has the crypto actor sign
    /// it.
    fn submit(logs: &Logs, name: &str, old: u64) -> Submission {
        let (text, proof, size) = logs.submission(name, old).unwrap();
        Submission {
            old,
            proof,
            checkpoint: signer().sign(&text),
            size,
        }
    }
    use polar_log::merkle::{leaf_hash, verify_consistency, verify_inclusion};

    const ORIGIN: &str = "polar-git-server.polar.serviceaccount.cluster.local";
    const AGENT: &str = "attestation-agent.polar.serviceaccount.cluster.local";

    fn entry(n: u8) -> Vec<u8> {
        Entry {
            kind: "evidence-record".to_string(),
            version: 1,
            critical: true,
            writer: "3.1.0 x86_64-unknown-linux-musl".to_string(),
            event: vec![n; 4],
        }
        .encode()
    }

    /// docs/architecture/record-store.md, "Bite 3": a reader outside Cassini fetches the log as C2SP tiles and gets
    /// back exactly the leaves the signed checkpoint states; the store serves no tile it has not grown to.
    #[test]
    fn the_log_read_from_its_tiles_is_the_log_its_checkpoint_states() {
        let dir = tempfile::tempdir().unwrap();
        let mut logs = Logs::open(dir.path(), ORIGIN, &signer().verifier_key()).unwrap();
        let pinned = NoteVerifier::parse(&signer().verifier_key()).unwrap();
        let (text, _) = open(&signed(&logs, "evidence"), std::slice::from_ref(&pinned)).unwrap();
        let empty = Checkpoint::parse(&text).unwrap();
        assert_eq!((empty.size, empty.root), (0, root(&[])));
        assert_eq!(logs.tile("evidence", "tile/entries/000.p/1").unwrap(), None);

        for n in 0..=255u8 {
            logs.append("evidence", &entry(n), AGENT, 1_000).unwrap();
        }
        logs.append("evidence", &entry(0).repeat(2), AGENT, 1_000)
            .unwrap_err();
        for n in 0..4u8 {
            let mut e = Entry::decode(&entry(n)).unwrap();
            e.event = vec![n; 9];
            logs.append("evidence", &e.encode(), AGENT, 1_000).unwrap();
        }
        let (text, _) = open(&signed(&logs, "evidence"), std::slice::from_ref(&pinned)).unwrap();
        let checkpoint = Checkpoint::parse(&text).unwrap();
        assert_eq!(checkpoint.size, 260);
        let leaves = polar_log::tiles::read_log(&checkpoint, |path| {
            logs.tile("evidence", path).map_err(|e| e.to_string())
        })
        .unwrap();
        assert_eq!(leaves.len(), 260);
        assert_eq!(
            leaves[259],
            logs.leaf("evidence", 259).unwrap().unwrap().encode()
        );

        let hashes = logs.tile("evidence", "tile/0/001.p/4").unwrap().unwrap();
        assert_eq!(
            hashes,
            logs.log("evidence").unwrap().hashes()[256..].concat()
        );
        let above = logs.tile("evidence", "tile/1/000.p/1").unwrap().unwrap();
        assert_eq!(above, logs.root_at("evidence", 256).unwrap());
        for absent in [
            "tile/entries/001.p/5",
            "tile/entries/001",
            "tile/0/001.p/5",
            "tile/1/000.p/2",
            "tile/0/1",
            "checkpoint",
        ] {
            assert_eq!(logs.tile("evidence", absent).unwrap(), None, "{absent}");
        }
        assert_eq!(
            logs.tile("schedules", "tile/entries/000.p/1").unwrap(),
            None
        );
        assert!(matches!(
            logs.checkpoint_text("Evidence"),
            Err(LogsError::Name(_))
        ));
    }

    /// Every log is served as tiles, so a leaf longer than a bundle carries is refused and nothing is appended.
    /// A log's file made and never written to, as a crash right after making it leaves it, is an empty log: appending
    /// to it starts at 0.
    #[test]
    fn a_log_file_never_written_to_is_an_empty_log() {
        let dir = tempfile::tempdir().unwrap();
        drop(Logs::open(dir.path(), ORIGIN, &signer().verifier_key()).unwrap());
        std::fs::write(dir.path().join("evidence.log"), b"").unwrap();
        let mut logs = Logs::open(dir.path(), ORIGIN, &signer().verifier_key()).unwrap();
        assert_eq!(logs.size("evidence").unwrap(), 0);
        assert_eq!(logs.append("evidence", &entry(0), AGENT, 7).unwrap(), 0);
        assert_eq!(logs.leaf("evidence", 0).unwrap().unwrap().admitted_at_ms, 7);
    }

    #[test]
    fn a_leaf_longer_than_a_bundle_carries_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut logs = Logs::open(dir.path(), ORIGIN, &signer().verifier_key()).unwrap();
        let mut long = Entry::decode(&entry(0)).unwrap();
        long.event = vec![0; MAX_ENTRY];
        assert!(matches!(
            logs.append("evidence", &long.encode(), AGENT, 1),
            Err(LogsError::TooLong(_))
        ));
        assert!(matches!(logs.size("evidence"), Err(LogsError::NoLog(_))));
        // The longest that fits is a leaf of exactly MAX_ENTRY bytes.
        let leaf_length = |event: usize| {
            let mut e = long.clone();
            e.event = vec![0; event];
            let leaf = Leaf {
                entry: e.encode(),
                admitted_at_ms: 1,
                submitter: AGENT.to_string(),
            };
            (leaf.encode().len(), e.encode())
        };
        let fits = (0..MAX_ENTRY)
            .rev()
            .find(|&n| leaf_length(n).0 <= MAX_ENTRY)
            .unwrap();
        assert_eq!(leaf_length(fits).0, MAX_ENTRY);
        assert_eq!(
            logs.append("evidence", &leaf_length(fits).1, AGENT, 1)
                .unwrap(),
            0
        );
        assert!(matches!(
            logs.append("evidence", &leaf_length(fits + 1).1, AGENT, 1),
            Err(LogsError::TooLong(_))
        ));
    }

    #[test]
    fn the_evidence_log_is_read_by_the_evidence_repositorys_readers_and_no_other_log_is_served() {
        assert_eq!(
            governing_repo(crate::evidence::EVIDENCE_LOG),
            Some(polar_git_server_common::EVIDENCE_REPO)
        );
        assert_eq!(governing_repo("schedules"), None);
    }

    #[test]
    fn a_log_only_grows_and_each_leaf_says_when_it_was_admitted_and_from_whom() {
        let dir = tempfile::tempdir().unwrap();
        let mut logs = Logs::open(dir.path(), ORIGIN, &signer().verifier_key()).unwrap();
        assert_eq!(logs.append("evidence", &entry(0), AGENT, 1_000).unwrap(), 0);
        assert_eq!(logs.append("evidence", &entry(1), AGENT, 2_000).unwrap(), 1);
        let leaf = logs.leaf("evidence", 1).unwrap().unwrap();
        assert_eq!(leaf.entry, entry(1));
        assert_eq!(leaf.admitted_at_ms, 2_000);
        assert_eq!(leaf.submitter, AGENT);
        drop(logs);
        let mut logs = Logs::open(dir.path(), ORIGIN, &signer().verifier_key()).unwrap();
        assert_eq!(logs.size("evidence").unwrap(), 2);
        // A clock stepped back does not take the log's time back with it.
        assert_eq!(logs.append("evidence", &entry(2), AGENT, 1_500).unwrap(), 2);
        assert_eq!(
            logs.leaf("evidence", 2).unwrap().unwrap().admitted_at_ms,
            2_000
        );
        logs.append("evidence", &entry(3), AGENT, 2_500).unwrap();
        assert_eq!(
            logs.leaf("evidence", 3).unwrap().unwrap().admitted_at_ms,
            2_500
        );
        assert_eq!(logs.names().collect::<Vec<_>>(), ["evidence"]);
    }

    #[test]
    fn what_is_not_an_entry_or_a_log_s_name_is_refused_and_nothing_appended() {
        let dir = tempfile::tempdir().unwrap();
        let mut logs = Logs::open(dir.path(), ORIGIN, &signer().verifier_key()).unwrap();
        assert!(matches!(
            logs.append("evidence", b"not an entry", AGENT, 1),
            Err(LogsError::NotAnEntry(_))
        ));
        assert!(matches!(logs.size("evidence"), Err(LogsError::NoLog(_))));
        for name in ["", "Evidence", "../evidence", "a/b", "a.log"] {
            assert!(
                matches!(
                    logs.append(name, &entry(0), AGENT, 1),
                    Err(LogsError::Name(_))
                ),
                "{name:?}"
            );
        }
        for name in ["evidence-2", "a", "0"] {
            assert!(logs.append(name, &entry(0), AGENT, 1).is_ok(), "{name:?}");
        }
    }

    /// The crypto actor keeps the checkpoint key in the logs' folder (`POLAR_STORE_CHECKPOINT_KEY`), with its certificate
    /// chain beside it: neither is taken for a log, and opening the logs leaves both as they were.
    #[test]
    fn the_checkpoint_key_beside_the_logs_is_no_log_and_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("checkpoint-key.pem"), "a key").unwrap();
        std::fs::write(dir.path().join("checkpoint-key.chain.pem"), "a chain").unwrap();
        let mut logs = Logs::open(dir.path(), ORIGIN, &signer().verifier_key()).unwrap();
        assert_eq!(logs.names().count(), 0);
        logs.append("evidence", &entry(1), AGENT, 1).unwrap();
        drop(logs);
        let logs = Logs::open(dir.path(), ORIGIN, &signer().verifier_key()).unwrap();
        assert_eq!(logs.names().collect::<Vec<_>>(), ["evidence"]);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("checkpoint-key.pem")).unwrap(),
            "a key"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("checkpoint-key.chain.pem")).unwrap(),
            "a chain"
        );
    }

    // A reader holding the pinned key checks a checkpoint, then that a leaf is in it and that it extends an older one.
    #[test]
    fn a_checkpoint_opens_with_the_pinned_key_and_proves_inclusion_and_growth() {
        let dir = tempfile::tempdir().unwrap();
        let mut logs = Logs::open(dir.path(), ORIGIN, &signer().verifier_key()).unwrap();
        for n in 0..3 {
            logs.append("evidence", &entry(n), AGENT, 1_000).unwrap();
        }
        let pinned = NoteVerifier::parse(&signer().verifier_key()).unwrap();
        let older = signed(&logs, "evidence");
        let (text, _) = open(&older, std::slice::from_ref(&pinned)).unwrap();
        let older = Checkpoint::parse(&text).unwrap();
        assert_eq!(older.origin, format!("{ORIGIN}/evidence"));
        assert_eq!(older.size, 3);
        for n in 3..7 {
            logs.append("evidence", &entry(n), AGENT, 2_000).unwrap();
        }
        let (text, _) = open(&signed(&logs, "evidence"), std::slice::from_ref(&pinned)).unwrap();
        let newer = Checkpoint::parse(&text).unwrap();
        assert_eq!(newer.size, 7);
        let proof = logs.consistency("evidence", 3, 7).unwrap();
        assert!(verify_consistency(3, 7, &older.root, &newer.root, &proof));
        let leaf = logs.leaf("evidence", 5).unwrap().unwrap();
        let proof = logs.inclusion("evidence", 5, 7).unwrap();
        assert!(verify_inclusion(
            5,
            7,
            &leaf_hash(&leaf.encode()),
            &proof,
            &newer.root
        ));
        assert_eq!(logs.root_at("evidence", 3).unwrap(), older.root);
        assert!(matches!(
            logs.inclusion("evidence", 7, 7),
            Err(LogsError::Range(_))
        ));
        assert!(matches!(
            logs.consistency("evidence", 3, 8),
            Err(LogsError::Range(_))
        ));
    }

    // What a sender sends again, after its answer was lost, is not appended twice, and that holds across a restart.
    #[test]
    fn the_same_entry_is_appended_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut logs = Logs::open(dir.path(), ORIGIN, &signer().verifier_key()).unwrap();
        assert_eq!(
            logs.append_once("evidence", &entry(0), AGENT, 1).unwrap(),
            (0, true)
        );
        assert_eq!(
            logs.append_once("evidence", &entry(1), AGENT, 2).unwrap(),
            (1, true)
        );
        assert_eq!(
            logs.append_once("evidence", &entry(0), AGENT, 3).unwrap(),
            (0, false)
        );
        assert_eq!(logs.size("evidence").unwrap(), 2);
        // Another log holds its own.
        assert_eq!(
            logs.append_once("schedules", &entry(0), AGENT, 4).unwrap(),
            (0, true)
        );
        drop(logs);
        let mut logs = Logs::open(dir.path(), ORIGIN, &signer().verifier_key()).unwrap();
        assert_eq!(
            logs.append_once("evidence", &entry(1), AGENT, 5).unwrap(),
            (1, false)
        );
        assert_eq!(logs.size("evidence").unwrap(), 2);
    }

    /// The store's identity is read off the key the crypto actor signs under, and nothing else is taken for one.
    #[test]
    fn the_origin_is_the_identity_the_checkpoint_key_is_named_for() {
        assert_eq!(origin_of(&signer().verifier_key()).as_deref(), Some(ORIGIN));
        assert_eq!(origin_of("x/witness+01234567+AAAA"), None);
        assert_eq!(origin_of("/checkpoint+01234567+AAAA"), None);
        assert_eq!(origin_of(""), None);
    }

    /// `entry(n)` as a version `writer` writes it: the same record, other bytes.
    fn written(n: u8, writer: &str) -> Vec<u8> {
        let mut entry = Entry::decode(&entry(n)).unwrap();
        entry.writer = writer.to_string();
        entry.encode()
    }

    /// What a store keeping no log took meanwhile is brought in at the next start, as the store's, each record once:
    /// one the log holds already, whichever version wrote it, is not appended again, and nor is anything the second
    /// time.
    #[test]
    fn what_the_log_misses_is_appended_once_known_by_what_it_says() {
        let dir = tempfile::tempdir().unwrap();
        let mut logs = Logs::open(dir.path(), ORIGIN, &signer().verifier_key()).unwrap();
        logs.append("evidence", &entry(0), AGENT, 1).unwrap();
        let missing: BTreeMap<String, Vec<u8>> = [
            (
                "a/0.json".to_string(),
                written(0, "3.2.0 x86_64-unknown-linux-musl"),
            ),
            ("b/1.json".to_string(), entry(1)),
        ]
        .into();
        assert_eq!(
            logs.append_missing("evidence", &missing, ORIGIN, 2)
                .unwrap(),
            Appended {
                appended: vec![1],
                left_out: vec![]
            }
        );
        assert_eq!(logs.leaf("evidence", 1).unwrap().unwrap().submitter, ORIGIN);
        assert_eq!(
            logs.append_missing("evidence", &missing, ORIGIN, 3)
                .unwrap(),
            Appended::default()
        );
        assert_eq!(logs.size("evidence").unwrap(), 2);
    }

    /// One the log cannot take is said, and the rest are appended: a start is not refused for one record.
    #[test]
    fn what_the_log_cannot_take_is_left_out_and_said_and_the_rest_appended() {
        let dir = tempfile::tempdir().unwrap();
        let mut logs = Logs::open(dir.path(), ORIGIN, &signer().verifier_key()).unwrap();
        let mut long = Entry::decode(&entry(2)).unwrap();
        long.event = vec![7; MAX_ENTRY];
        let missing: BTreeMap<String, Vec<u8>> = [
            ("a.json".to_string(), b"no entry".to_vec()),
            ("b.json".to_string(), long.encode()),
            ("c.json".to_string(), entry(3)),
        ]
        .into();
        let done = logs
            .append_missing("evidence", &missing, ORIGIN, 1)
            .unwrap();
        assert_eq!(done.appended, vec![0]);
        let left: Vec<&str> = done.left_out.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(left, ["a.json", "b.json"]);
        assert!(
            done.left_out[0].1.contains("not one"),
            "{:?}",
            done.left_out
        );
        assert!(done.left_out[1].1.contains("longer"), "{:?}", done.left_out);
    }

    proptest::proptest! {
        /// Whatever the log held, by whichever writer, bringing in the repository's records leaves the log saying each
        /// of them exactly once, and doing it again appends nothing.
        #[test]
        fn the_log_says_each_record_once_whatever_it_held(
            held in proptest::collection::btree_set(0u8..8, 0..6),
            wanted in proptest::collection::btree_set(0u8..8, 0..8),
            old_writer in proptest::bool::ANY,
        ) {
            let dir = tempfile::tempdir().unwrap();
            let mut logs = Logs::open(dir.path(), ORIGIN, &signer().verifier_key()).unwrap();
            for (t, n) in held.iter().enumerate() {
                let bytes = if old_writer { written(*n, "3.0.0 x86_64-unknown-linux-musl") } else { entry(*n) };
                logs.append("evidence", &bytes, AGENT, t as u64).unwrap();
            }
            let missing: BTreeMap<String, Vec<u8>> =
                wanted.iter().map(|n| (format!("r/{n}.json"), entry(*n))).collect();
            let done = logs.append_missing("evidence", &missing, ORIGIN, 100).unwrap();
            proptest::prop_assert_eq!(done.appended.len(), wanted.difference(&held).count());
            proptest::prop_assert!(done.left_out.is_empty());
            let mut said = Vec::new();
            for seq in 0..logs.size("evidence").unwrap_or(0) {
                said.push(Entry::decode(&logs.leaf("evidence", seq).unwrap().unwrap().entry).unwrap().event[0]);
            }
            let mut unique = said.clone();
            unique.sort();
            unique.dedup();
            proptest::prop_assert_eq!(unique.len(), said.len());
            let all: std::collections::BTreeSet<u8> = held.union(&wanted).copied().collect();
            proptest::prop_assert_eq!(unique.into_iter().collect::<std::collections::BTreeSet<_>>(), all);
            proptest::prop_assert_eq!(
                logs.append_missing("evidence", &missing, ORIGIN, 101).unwrap(),
                Appended::default()
            );
        }
    }

    #[test]
    fn a_log_with_a_malformed_leaf_refuses_the_store_s_start() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = FileLog::open(&dir.path().join("evidence.log")).unwrap().log;
        log.append(&Leaf {
            entry: b"no entry".to_vec(),
            admitted_at_ms: 1,
            submitter: AGENT.to_string(),
        })
        .unwrap();
        drop(log);
        assert!(matches!(
            Logs::open(dir.path(), ORIGIN, &signer().verifier_key()),
            Err(LogsError::Malformed { seq: 0, .. })
        ));
    }

    const WITNESS: &str = "attestation-agent.polar.serviceaccount.cluster.local/witness";

    fn witness() -> (polar_log::checkpoint::Cosigner, NoteVerifier) {
        let cosigner = polar_log::checkpoint::Cosigner::new(
            WITNESS,
            p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap(),
        )
        .unwrap();
        let pinned = NoteVerifier::parse(&cosigner.verifier_key()).unwrap();
        (cosigner, pinned)
    }

    /// The witness's answer to a submission: its co-signature line over the submitted checkpoint.
    fn cosign(cosigner: &polar_log::checkpoint::Cosigner, submitted: &str, time: u64) -> String {
        let (text, _) = submitted.split_at(submitted.rfind("\n\n").unwrap() + 1);
        cosigner.cosign_line(text, time)
    }

    /// docs/architecture/record-store.md, "Bite 5": readers require the witness's co-signature, so a log serves no
    /// checkpoint until one is kept, and then the latest co-signed one, which opens under both keys.
    #[test]
    fn a_log_serves_its_latest_co_signed_checkpoint_and_none_before_it_is_witnessed() {
        let dir = tempfile::tempdir().unwrap();
        let mut logs = Logs::open(dir.path(), ORIGIN, &signer().verifier_key()).unwrap();
        let (cosigner, pinned) = witness();
        let store = NoteVerifier::parse(&signer().verifier_key()).unwrap();
        logs.append("evidence", &entry(0), AGENT, 1).unwrap();
        assert_eq!(logs.cosigned("evidence"), None);

        let first = submit(&logs, "evidence", 0);
        assert_eq!((first.old, first.size), (0, 1));
        assert!(first.proof.is_empty(), "from 0 the proof is empty");
        let line = cosign(&cosigner, &first.checkpoint, 100);
        assert_eq!(
            logs.keep_cosigned("evidence", &first.checkpoint, &line, &pinned)
                .unwrap(),
            1
        );
        let served = logs.cosigned("evidence").unwrap().to_string();
        assert_eq!(served, format!("{}{line}", first.checkpoint));
        let opened =
            polar_log::checkpoint::open_signed(&served, &[store.clone(), pinned.clone()]).unwrap();
        assert_eq!(opened.by.len(), 2);

        // The log grows; until the next co-signature the last co-signed checkpoint is what is served.
        logs.append("evidence", &entry(1), AGENT, 2).unwrap();
        logs.append("evidence", &entry(2), AGENT, 3).unwrap();
        assert_eq!(logs.cosigned("evidence").unwrap(), served);
        let next = submit(&logs, "evidence", 1);
        assert_eq!((next.old, next.size), (1, 3));
        let (old_root, new_root) = (
            logs.root_at("evidence", 1).unwrap(),
            logs.root_at("evidence", 3).unwrap(),
        );
        assert!(verify_consistency(1, 3, &old_root, &new_root, &next.proof));
        let line = cosign(&cosigner, &next.checkpoint, 101);
        assert_eq!(
            logs.keep_cosigned("evidence", &next.checkpoint, &line, &pinned)
                .unwrap(),
            3
        );
        assert_eq!(logs.cosigned_size("evidence"), Some(3));
        // The same size co-signed again, later, is kept: the latest co-signature is served.
        let again = submit(&logs, "evidence", 3);
        assert!(
            again.proof.is_empty(),
            "between equal sizes the proof is empty"
        );
        let later = cosign(&cosigner, &again.checkpoint, 102);
        assert_eq!(
            logs.keep_cosigned("evidence", &again.checkpoint, &later, &pinned)
                .unwrap(),
            3
        );
        assert_eq!(
            logs.cosigned("evidence").unwrap(),
            format!("{}{later}", again.checkpoint)
        );
    }

    /// The store keeps only a co-signature that verifies under the pinned witness key over what it submitted, and never
    /// one for a checkpoint older than the one it keeps.
    #[test]
    fn a_co_signature_that_does_not_verify_or_goes_back_is_never_kept() {
        let dir = tempfile::tempdir().unwrap();
        let mut logs = Logs::open(dir.path(), ORIGIN, &signer().verifier_key()).unwrap();
        let (cosigner, pinned) = witness();
        logs.append("evidence", &entry(0), AGENT, 1).unwrap();
        let one = submit(&logs, "evidence", 0);
        // Another witness key's line, and the witness's over another checkpoint.
        let (stranger, _) = (
            polar_log::checkpoint::Cosigner::new(
                WITNESS,
                p256::ecdsa::SigningKey::from_slice(&[8; 32]).unwrap(),
            )
            .unwrap(),
            (),
        );
        let theirs = cosign(&stranger, &one.checkpoint, 100);
        assert!(matches!(
            logs.keep_cosigned("evidence", &one.checkpoint, &theirs, &pinned),
            Err(LogsError::NotCosigned(_))
        ));
        logs.append("evidence", &entry(1), AGENT, 2).unwrap();
        let two = submit(&logs, "evidence", 0);
        let over_two = cosign(&cosigner, &two.checkpoint, 100);
        assert!(matches!(
            logs.keep_cosigned("evidence", &one.checkpoint, &over_two, &pinned),
            Err(LogsError::NotCosigned(_))
        ));
        // A checkpoint the store's key did not sign.
        let forged = one.checkpoint.replacen("\n1\n", "\n2\n", 1);
        let over_forged = cosign(&cosigner, &forged, 100);
        assert!(matches!(
            logs.keep_cosigned("evidence", &forged, &over_forged, &pinned),
            Err(LogsError::NotCosigned(_))
        ));
        // A key that is not a witness's, though its line verifies over the note's text.
        let plain = NoteSigner::new(
            WITNESS,
            p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap(),
        )
        .unwrap();
        let plain_key = NoteVerifier::parse(&plain.verifier_key()).unwrap();
        let (text, _) = two
            .checkpoint
            .split_at(two.checkpoint.rfind("\n\n").unwrap() + 1);
        assert!(matches!(
            logs.keep_cosigned(
                "evidence",
                &two.checkpoint,
                &plain.sign_line(text),
                &plain_key
            ),
            Err(LogsError::NotCosigned(_))
        ));
        // A log the store does not hold.
        assert!(matches!(
            logs.keep_cosigned("schedules", &two.checkpoint, &over_two, &pinned),
            Err(LogsError::NotCosigned(_))
        ));
        assert_eq!(logs.cosigned("evidence"), None);
        // Size 2 kept, then size 1 offered: refused, and 2 is still served.
        logs.keep_cosigned("evidence", &two.checkpoint, &over_two, &pinned)
            .unwrap();
        let back = cosign(&cosigner, &one.checkpoint, 101);
        assert!(matches!(
            logs.keep_cosigned("evidence", &one.checkpoint, &back, &pinned),
            Err(LogsError::NotCosigned(_))
        ));
        assert_eq!(logs.cosigned_size("evidence"), Some(2));
    }

    /// The kept checkpoint is the store's to serve after a restart; a kept file that is not a checkpoint of the log
    /// beside it is damage, and the store does not start.
    #[test]
    fn the_kept_checkpoint_outlives_a_restart_and_one_not_of_its_log_refuses_the_start() {
        let dir = tempfile::tempdir().unwrap();
        let (cosigner, pinned) = witness();
        let served = {
            let mut logs = Logs::open(dir.path(), ORIGIN, &signer().verifier_key()).unwrap();
            logs.append("evidence", &entry(0), AGENT, 1).unwrap();
            let one = submit(&logs, "evidence", 0);
            let line = cosign(&cosigner, &one.checkpoint, 100);
            logs.keep_cosigned("evidence", &one.checkpoint, &line, &pinned)
                .unwrap();
            logs.cosigned("evidence").unwrap().to_string()
        };
        let logs = Logs::open(dir.path(), ORIGIN, &signer().verifier_key()).unwrap();
        assert_eq!(logs.cosigned("evidence"), Some(served.as_str()));
        assert_eq!(logs.cosigned_size("evidence"), Some(1));
        drop(logs);

        // Another root for size 1, under the store's own key: not this log's checkpoint.
        let kept = dir.path().join("evidence.cosigned");
        let other = {
            let other_dir = tempfile::tempdir().unwrap();
            let mut other = Logs::open(other_dir.path(), ORIGIN, &signer().verifier_key()).unwrap();
            other.append("evidence", &entry(7), AGENT, 1).unwrap();
            submit(&other, "evidence", 0).checkpoint
        };
        std::fs::write(&kept, &other).unwrap();
        assert!(matches!(
            Logs::open(dir.path(), ORIGIN, &signer().verifier_key()),
            Err(LogsError::Kept { .. })
        ));
        std::fs::write(&kept, "not a note").unwrap();
        assert!(matches!(
            Logs::open(dir.path(), ORIGIN, &signer().verifier_key()),
            Err(LogsError::Kept { .. })
        ));
        // A kept file that cannot be read is not taken for one never written.
        std::fs::remove_file(&kept).unwrap();
        std::fs::create_dir(&kept).unwrap();
        assert!(matches!(
            Logs::open(dir.path(), ORIGIN, &signer().verifier_key()),
            Err(LogsError::Io { .. })
        ));
    }
}
