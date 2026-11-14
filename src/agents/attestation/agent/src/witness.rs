/*
  ACE Tool

  Copyright 2026 Carnegie Mellon University.

  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS
  FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
  EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE
  MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
  TRADEMARK, OR COPYRIGHT INFRINGEMENT.

  Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu
  for full terms.

  [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited
  distribution.  Please see Copyright notice for non-US Government use and distribution.

  This Software includes and/or makes use of Third-Party Software each subject to its own license.

  DM26-0670
*/

//! The witness of the store's logs (docs/architecture/runtime-attestation.md, "The witness of the store's logs"): it
//! reads no entries. The store brings it each checkpoint as C2SP tlog-witness's `add-checkpoint`, and it judges the
//! request ([`judge`]) in tlog-witness's order, has the agent's crypto actor co-sign it ([`WitnessCosigner`]: the key is
//! the actor's, never this module's), keeps what was co-signed ([`Kept`]) before it answers, and answers.
//!
//! What it holds to: for each origin, it never co-signs two checkpoints that are not consistent, and the size and time
//! it co-signed never go back, across restarts. A checkpoint the store's key signed that cannot follow what it
//! co-signed is misbehaviour, said as such; a size that is merely not its own is a conflict, answered with its size.

use attestation_common::witness::{AddCheckpoint, Answer, MAX_PROOF, Refusal};
use polar_log::checkpoint::{Checkpoint, ECDSA, NoteError, NoteVerifier, open, open_signed};
use polar_log::merkle::{Hash, root, verify_consistency};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// What co-signs for the witness: the agent's crypto actor ([`polar_agent_builder::crypto::CosignHandle`]), which keeps
/// the witness's key, co-signs only a checkpoint of the store its signed configuration pins, and states the time from its
/// own clock; a key of its own in a test.
#[ractor::async_trait]
pub trait WitnessCosigner: Send + Sync + 'static {
    /// `text`'s co-signature line and the time it states (Unix seconds).
    async fn cosign(&self, text: String) -> Result<(String, u64), String>;
    /// The witness's verifier key, which the store and readers pin.
    async fn key(&self) -> Result<String, String>;
}

#[ractor::async_trait]
impl WitnessCosigner for polar_agent_builder::crypto::CosignHandle {
    async fn cosign(&self, text: String) -> Result<(String, u64), String> {
        polar_agent_builder::crypto::CosignHandle::cosign(self, text).await
    }
    async fn key(&self) -> Result<String, String> {
        polar_agent_builder::crypto::CosignHandle::key(self).await
    }
}

/// The name the store's checkpoint key carries after its identity (`polar_git_server::logs::KEY_NAME`).
const STORE_KEY_SUFFIX: &str = "/checkpoint";

/// The store the witness serves: its pinned verifier key, and the prefix every origin it signs begins with.
pub struct Pinned {
    verifier: NoteVerifier,
    prefix: String,
}

impl Pinned {
    /// The store whose checkpoint key's verifier line is `vkey`: its name is `<identity>/checkpoint`, and its origins
    /// `<identity>/<log>`.
    pub fn parse(vkey: &str) -> Result<Self, String> {
        let vkey = vkey.trim();
        let verifier = NoteVerifier::parse(vkey).map_err(|e| e.to_string())?;
        // A witness's key reads as a verifier too; only a key that signs checkpoints is a store's.
        let signs_checkpoints = vkey.splitn(3, '+').nth(2).is_some_and(|blob| {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(blob)
                .is_ok_and(|b| b.first() == Some(&ECDSA))
        });
        if !signs_checkpoints {
            return Err(format!(
                "the key `{}` does not sign checkpoints",
                verifier.name()
            ));
        }
        let identity = verifier
            .name()
            .strip_suffix(STORE_KEY_SUFFIX)
            .filter(|identity| !identity.is_empty())
            .ok_or_else(|| {
                format!(
                    "the key `{}` is not a store's checkpoint key (`<identity>{STORE_KEY_SUFFIX}`)",
                    verifier.name()
                )
            })?;
        let prefix = format!("{identity}/");
        Ok(Self { verifier, prefix })
    }
}

/// What the witness holds of one origin: the last checkpoint it co-signed, when, and its co-signature, by which a
/// restart knows its own key made what it finds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Held {
    pub size: u64,
    #[serde(with = "root_base64")]
    pub root: Hash,
    /// The time in its co-signature, in Unix seconds.
    pub time: u64,
    /// Its co-signature line, as it answered with it.
    pub line: String,
}

/// The witness's key name: its identity, as its certificate gives it, and `/witness`, as the store's is
/// `<identity>/checkpoint`.
pub fn witness_name(identity: &str) -> String {
    format!("{identity}/witness")
}

/// `checkpoint`, co-signed with `line` stating `time`: what the witness then holds of its origin.
pub fn held(checkpoint: &Checkpoint, line: String, time: u64) -> Held {
    Held {
        size: checkpoint.size,
        root: checkpoint.root,
        time,
        line,
    }
}

/// Whether everything in `holding` was co-signed by the key `own` verifies, as held: each origin's checkpoint, at its
/// time. What its own key did not sign is not what it co-signed, and is damage.
pub fn check_holding(holding: &Holding, own: &NoteVerifier) -> Result<(), String> {
    for (origin, held) in holding {
        let text = Checkpoint {
            origin: origin.clone(),
            size: held.size,
            root: held.root,
        }
        .text();
        let opened = open_signed(&format!("{text}\n{}", held.line), std::slice::from_ref(own))
            .map_err(|e| format!("what it holds of {origin} is not its own co-signature: {e}"))?;
        if opened.by.first().and_then(|signed| signed.cosigned_at) != Some(held.time) {
            return Err(format!(
                "what it holds of {origin} is not its own co-signature at the time held"
            ));
        }
    }
    Ok(())
}

/// What it holds, by origin.
pub type Holding = BTreeMap<String, Held>;

/// A signed checkpoint that cannot follow what the witness co-signed: the store's own key says two things.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Misbehaviour {
    pub origin: String,
    pub held: Option<Held>,
    pub offered_size: u64,
    pub offered_root: Hash,
}

/// What a request comes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Judgement {
    /// Co-sign it at `time`, and keep that before answering.
    Keep {
        origin: String,
        checkpoint: Checkpoint,
        time: u64,
    },
    /// Answer without co-signing; `misbehaviour` when the store's key signed what cannot be.
    Answer {
        origin: Option<String>,
        size: Option<u64>,
        answer: Answer,
        misbehaviour: Option<Misbehaviour>,
    },
}

fn answer(origin: Option<&str>, size: Option<u64>, answer: Answer) -> Judgement {
    Judgement::Answer {
        origin: origin.map(String::from),
        size,
        answer,
        misbehaviour: None,
    }
}

/// What the witness does with `request`, holding `holding`, serving `pinned` (none pinned yet), at `now` (Unix
/// seconds). tlog-witness's order: the store's signature, the checkpoint, its origin, `old` against its size, `old`
/// against what is held, the empty tree, the proof.
pub fn judge(
    pinned: Option<&Pinned>,
    holding: &Holding,
    request: &AddCheckpoint,
    now: u64,
) -> Judgement {
    use Refusal::*;
    let Some(pinned) = pinned else {
        return answer(None, None, Answer::Refused(UnknownOrigin));
    };
    let text = match open(&request.checkpoint, std::slice::from_ref(&pinned.verifier)) {
        Ok((text, _)) => text,
        Err(NoteError::Unsigned | NoteError::BadSignature(_)) => {
            return answer(None, None, Answer::Refused(Untrusted));
        }
        Err(_) => return answer(None, None, Answer::Refused(Malformed)),
    };
    let Ok(checkpoint) = Checkpoint::parse(&text) else {
        return answer(None, None, Answer::Refused(Malformed));
    };
    let origin = checkpoint.origin.as_str();
    let size = checkpoint.size;
    let refuse = |why| answer(Some(origin), Some(size), Answer::Refused(why));
    if !origin.starts_with(&pinned.prefix) || origin.len() == pinned.prefix.len() {
        return refuse(UnknownOrigin);
    }
    let held = holding.get(origin);
    let misbehaved = |why| Judgement::Answer {
        origin: Some(origin.to_string()),
        size: Some(size),
        answer: Answer::Refused(why),
        misbehaviour: Some(Misbehaviour {
            origin: origin.to_string(),
            held: held.cloned(),
            offered_size: size,
            offered_root: checkpoint.root,
        }),
    };
    if request.proof.len() > MAX_PROOF {
        return refuse(Malformed);
    }
    if request.old > size {
        // Signed, and smaller than what was co-signed: the store's key going back on itself.
        return if held.is_some_and(|h| size < h.size) {
            misbehaved(Malformed)
        } else {
            refuse(Malformed)
        };
    }
    let held_size = held.map_or(0, |h| h.size);
    if request.old != held_size {
        return answer(Some(origin), Some(size), Answer::Conflict(held_size));
    }
    if size == 0 && checkpoint.root != root(&[]) {
        return misbehaved(Inconsistent);
    }
    let consistent = match held {
        None => request.proof.is_empty(),
        Some(h) => verify_consistency(h.size, size, &h.root, &checkpoint.root, &request.proof),
    };
    if !consistent {
        return misbehaved(Inconsistent);
    }
    let time = held.map_or(now, |h| now.max(h.time));
    Judgement::Keep {
        origin: origin.to_string(),
        checkpoint,
        time,
    }
}

/// The file of what the witness holds, beside its key.
pub const HOLDING_FILE: &str = "witnessed.json";

/// What the holding file says: the verifier key it was co-signed under, and what is held of each origin. A file of an
/// earlier form holds only the origins.
#[derive(Serialize, Deserialize)]
struct HoldingFile {
    key: String,
    origins: Holding,
}

/// Why the witness cannot start: what it holds is damaged, cannot be read, or is another key's, said with where.
#[derive(Debug, thiserror::Error)]
pub enum Damage {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(
        "{path}: what the witness holds was co-signed under {held}, and its key now is another: its co-signatures \
         could no longer be told from a new witness's"
    )]
    AnotherKey { path: PathBuf, held: String },
    #[error("{path}: {why}")]
    NotItsOwn { path: PathBuf, why: String },
    #[error("{path}: {why}")]
    Unreadable { path: PathBuf, why: String },
}

/// What the witness holds, on its own volume, beside the key its crypto actor keeps. The holding records the verifier
/// key it was co-signed under, so a start with another key (one made again, the old one lost) is said as damage rather
/// than taken for a witness that held nothing: that would co-sign whatever came next.
pub struct Kept {
    dir: PathBuf,
    /// The verifier key the witness co-signs under now.
    key: String,
}

impl Kept {
    /// What is kept under `dir` by the witness whose verifier key is `key`, made empty if there is nothing yet. A holding
    /// recorded under another key is damage; one of the earlier form, which records no key, is taken only when every
    /// co-signature in it verifies under `key`, and is then kept with the key recorded.
    pub fn open(dir: &Path, key: &str) -> Result<(Self, Holding), Damage> {
        let io = |path: &Path| {
            let path = path.to_path_buf();
            move |source| Damage::Io { path, source }
        };
        std::fs::create_dir_all(dir).map_err(io(dir))?;
        let kept = Self {
            dir: dir.to_path_buf(),
            key: key.to_string(),
        };
        let path = dir.join(HOLDING_FILE);
        let unreadable = |why: String| Damage::Unreadable {
            path: path.clone(),
            why,
        };
        let own = NoteVerifier::parse(key)
            .map_err(|e| unreadable(format!("the witness's own key {key} does not read: {e}")))?;
        let holding = match std::fs::read(&path) {
            Ok(bytes) => {
                let (recorded, holding) = match serde_json::from_slice::<HoldingFile>(&bytes) {
                    Ok(file) => (Some(file.key), file.origins),
                    Err(_) => (
                        None,
                        serde_json::from_slice::<Holding>(&bytes)
                            .map_err(|e| unreadable(e.to_string()))?,
                    ),
                };
                if let Some(held) = recorded
                    && held != key
                {
                    return Err(Damage::AnotherKey { path, held });
                }
                check_holding(&holding, &own).map_err(|why| Damage::NotItsOwn {
                    path: path.clone(),
                    why,
                })?;
                holding
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Holding::new(),
            Err(e) => return Err(io(&path)(e)),
        };
        kept.keep(&holding)?;
        Ok((kept, holding))
    }

    /// Keeps `holding` whole, with the key it was co-signed under: written to a new file, synced, renamed over the old
    /// one, the directory synced. Once this returns, a restart finds it.
    pub fn keep(&self, holding: &Holding) -> Result<(), Damage> {
        let path = self.dir.join(HOLDING_FILE);
        let new = self.dir.join(format!("{HOLDING_FILE}.new"));
        let io = |path: &Path| {
            let path = path.to_path_buf();
            move |source| Damage::Io { path, source }
        };
        let bytes = serde_json::to_vec(&HoldingFile {
            key: self.key.clone(),
            origins: holding.clone(),
        })
        .expect("a holding always serializes");
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&new).map_err(io(&new))?;
            file.write_all(&bytes).map_err(io(&new))?;
            file.sync_all().map_err(io(&new))?;
        }
        std::fs::rename(&new, &path).map_err(io(&path))?;
        std::fs::File::open(&self.dir)
            .and_then(|d| d.sync_all())
            .map_err(io(&self.dir))
    }
}

/// What the witness is told: a request as it arrived, and who the broker says sent it; or a new pin, as signed.
pub enum WitnessMessage {
    Request {
        payload: Vec<u8>,
        published_by: Option<String>,
    },
    Pin(Option<String>),
}

/// How the witness answers, and says what it found: the agent's own publishing and reporting, so this actor holds no
/// client of its own.
pub struct WitnessArgs {
    pub kept: Kept,
    /// What co-signs: the crypto actor's [`CosignHandle`](polar_agent_builder::crypto::CosignHandle).
    pub cosigner: std::sync::Arc<dyn WitnessCosigner>,
    pub holding: Holding,
    /// The store's identity, as the broker stamps it: the only sender it answers, and the only name it pins.
    pub store: String,
    /// Where the pin comes from: it follows `POLAR_ATTESTATION_WITNESSED_STORE`, so a pin signed while it runs, or
    /// before it started again, is the one in force.
    pub configuration: polar_agent_builder::configuration::ConfigurationHandle,
    pub publish: std::sync::Arc<dyn Fn(Vec<u8>) -> Result<(), String> + Send + Sync>,
    pub misbehaved: std::sync::Arc<dyn Fn(Misbehaviour) + Send + Sync>,
    pub clock: fn() -> u64,
}

/// What the witness works with once started.
pub struct WitnessState {
    kept: Kept,
    cosigner: std::sync::Arc<dyn WitnessCosigner>,
    holding: Holding,
    store: String,
    publish: std::sync::Arc<dyn Fn(Vec<u8>) -> Result<(), String> + Send + Sync>,
    misbehaved: std::sync::Arc<dyn Fn(Misbehaviour) + Send + Sync>,
    clock: fn() -> u64,
    pinned: Option<Pinned>,
    /// Whether an unpinned request has been said: once, until a pin comes.
    said_unpinned: bool,
}

/// The pin `raw` names, if it is the store's own checkpoint key; a key of another name is said and not taken.
fn pin_of(raw: Option<&str>, store: &str) -> Option<Pinned> {
    let pinned = Pinned::parse(raw?)
        .map_err(|e| tracing::error!("the witnessed store's key is not one: {e}"))
        .ok()?;
    if pinned.prefix != format!("{store}/") {
        tracing::error!(
            store,
            "the witnessed store's key names another store, `{}`: nothing is witnessed",
            pinned.prefix.trim_end_matches('/')
        );
        return None;
    }
    Some(pinned)
}

/// The witness: one request at a time, each judged, kept, co-signed and answered in that order.
pub struct Witness;

#[ractor::async_trait]
impl ractor::Actor for Witness {
    type Msg = WitnessMessage;
    type State = WitnessState;
    type Arguments = WitnessArgs;

    async fn pre_start(
        &self,
        myself: ractor::ActorRef<Self::Msg>,
        args: WitnessArgs,
    ) -> Result<Self::State, ractor::ActorProcessingErr> {
        use polar_agent_builder::configuration::FollowError;
        let raw = match args
            .configuration
            .follow(
                &polar_agent_builder::crypto::WITNESSED_STORE,
                &myself,
                WitnessMessage::Pin,
            )
            .await
        {
            Ok(raw) => raw,
            Err(FollowError::Unreadable(why)) => {
                tracing::error!("the witnessed store's key does not read: {why}");
                None
            }
            Err(e) => return Err(format!("the witness cannot follow its pin: {e}").into()),
        };
        let pinned = pin_of(raw.as_deref(), &args.store);
        let key = args.cosigner.key().await?;
        tracing::info!(
            %key,
            witnessing = pinned.is_some(),
            origins = args.holding.len(),
            "the witness of the store's logs is ready"
        );
        Ok(WitnessState {
            kept: args.kept,
            cosigner: args.cosigner,
            holding: args.holding,
            store: args.store,
            publish: args.publish,
            misbehaved: args.misbehaved,
            clock: args.clock,
            pinned,
            said_unpinned: false,
        })
    }

    async fn handle(
        &self,
        _: ractor::ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ractor::ActorProcessingErr> {
        match message {
            WitnessMessage::Pin(raw) => {
                state.pinned = pin_of(raw.as_deref(), &state.store);
                state.said_unpinned = false;
                tracing::info!(
                    witnessing = state.pinned.is_some(),
                    "the witnessed store's key changed"
                );
            }
            WitnessMessage::Request {
                payload,
                published_by,
            } => take_request(state, &payload, published_by.as_deref()).await,
        }
        Ok(())
    }
}

async fn take_request(state: &mut WitnessState, payload: &[u8], published_by: Option<&str>) {
    use attestation_common::witness::{
        Envelope, Witnessed, decode_add_checkpoint, encode_witnessed,
    };
    if published_by != Some(state.store.as_str()) {
        tracing::warn!(
            sender = published_by.unwrap_or("unverified"),
            "dropped a checkpoint not sent by the store"
        );
        return;
    }
    let request = match decode_add_checkpoint(payload) {
        Ok(request) => request,
        Err(e) => {
            tracing::warn!("dropped a request to witness that is not one: {e}");
            return;
        }
    };
    let now = (state.clock)();
    let witnessed = match judge(state.pinned.as_ref(), &state.holding, &request.payload, now) {
        Judgement::Keep {
            origin,
            checkpoint,
            time,
        } => {
            // The time is the crypto actor's own; it must not go back on what was co-signed for this origin, nor on
            // the time judged (`time`: what the witness held, or now).
            let (line, stated) = match state.cosigner.cosign(checkpoint.text()).await {
                Ok(cosigned) => cosigned,
                Err(e) => {
                    tracing::error!(
                        origin,
                        "the crypto actor did not co-sign, so nothing is answered: {e}"
                    );
                    return;
                }
            };
            if let Some(before) = state.holding.get(&origin)
                && stated < before.time
            {
                tracing::error!(
                    origin,
                    stated,
                    held = before.time,
                    judged = time,
                    "the co-signature's time goes back on what was co-signed, so it is not kept or sent"
                );
                return;
            }
            let held = held(&checkpoint, line, stated);
            let mut next = state.holding.clone();
            next.insert(origin.clone(), held.clone());
            // Kept before it is answered: a co-signature a restart would not find is never sent.
            if let Err(e) = state.kept.keep(&next) {
                tracing::error!(
                    origin,
                    "what the witness co-signs could not be kept, so it is not sent: {e}"
                );
                return;
            }
            // A log seen for the first time is said, so whoever checks a new log sees the witness take it up.
            if !state.holding.contains_key(&origin) {
                tracing::info!(
                    origin,
                    size = held.size,
                    "the witness co-signed a log for the first time"
                );
            }
            state.holding = next;
            tracing::debug!(origin, size = held.size, "co-signed");
            Witnessed {
                origin: Some(origin),
                size: Some(held.size),
                answer: Answer::Cosigned(held.line),
            }
        }
        Judgement::Answer {
            origin,
            size,
            answer,
            misbehaviour,
        } => {
            match (&answer, &misbehaviour) {
                (_, Some(found)) => tracing::error!(
                    origin = found.origin,
                    held = found.held.as_ref().map(|h| h.size),
                    offered = found.offered_size,
                    "the store's key signed a checkpoint that cannot follow what was co-signed: {answer:?}"
                ),
                (Answer::Conflict(held), None) => {
                    tracing::info!(origin, size, held, "the store asked from a size not held")
                }
                (Answer::Refused(Refusal::UnknownOrigin), None) if state.pinned.is_none() => {
                    if !state.said_unpinned {
                        tracing::warn!("no store is pinned, so nothing is co-signed");
                        state.said_unpinned = true;
                    }
                }
                _ => tracing::warn!(origin, size, "refused to co-sign: {answer:?}"),
            }
            if let Some(found) = misbehaviour {
                (state.misbehaved)(found);
            }
            Witnessed {
                origin,
                size,
                answer,
            }
        }
    };
    let answer = Envelope {
        correlation_id: request.correlation_id,
        payload: witnessed,
    };
    if let Err(e) = (state.publish)(encode_witnessed(&answer)) {
        tracing::warn!("could not answer the store: {e}");
    }
}

mod root_base64 {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(root: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(root))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        STANDARD
            .decode(&text)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| serde::de::Error::custom("a root is 32 bytes in base64"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_log::checkpoint::{Cosigner, NoteSigner};
    use polar_log::merkle::{consistency_proof, leaf_hash};
    use proptest::prelude::*;

    const STORE: &str = "polar-git-server.polar.serviceaccount.cluster.local";

    fn store_key(seed: u8) -> NoteSigner {
        let key = p256::ecdsa::SigningKey::from_slice(&[seed.max(1); 32]).unwrap();
        NoteSigner::new(&format!("{STORE}/checkpoint"), key).unwrap()
    }

    fn leaves(n: usize, fork: u8) -> Vec<Hash> {
        (0..n)
            .map(|i| leaf_hash(&[i as u8, (i >> 8) as u8, fork]))
            .collect()
    }

    fn note(signer: &NoteSigner, log: &str, leaves: &[Hash]) -> String {
        signer.sign(
            &Checkpoint {
                origin: format!("{STORE}/{log}"),
                size: leaves.len() as u64,
                root: root(leaves),
            }
            .text(),
        )
    }

    fn request(old: usize, leaves: &[Hash], signer: &NoteSigner) -> AddCheckpoint {
        AddCheckpoint {
            old: old as u64,
            proof: if old == 0 {
                Vec::new()
            } else {
                consistency_proof(old, leaves).unwrap()
            },
            checkpoint: note(signer, "evidence", leaves),
        }
    }

    fn pinned() -> Pinned {
        Pinned::parse(&store_key(1).verifier_key()).unwrap()
    }

    const WITNESS: &str = "attestation-agent.polar.serviceaccount.cluster.local";

    fn witness_key(seed: u8) -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[seed.max(1); 32]).unwrap()
    }

    fn cosigner(key: &p256::ecdsa::SigningKey) -> Cosigner {
        Cosigner::new(&witness_name(WITNESS), key.clone()).unwrap()
    }

    fn own(key: &p256::ecdsa::SigningKey) -> NoteVerifier {
        NoteVerifier::parse(&cosigner(key).verifier_key()).unwrap()
    }

    /// The witness's verifier key, as its crypto actor gives it.
    fn key_of(key: &p256::ecdsa::SigningKey) -> String {
        cosigner(key).verifier_key()
    }

    /// `checkpoint`, co-signed at `time` by `cosigner`, as the crypto actor co-signs it.
    fn cosign(cosigner: &Cosigner, checkpoint: &Checkpoint, time: u64) -> Held {
        held(
            checkpoint,
            cosigner.cosign_line(&checkpoint.text(), time),
            time,
        )
    }

    /// Co-signs as the crypto actor does, with a fixed key, stating the time its clock gives.
    struct KeyCosigner {
        cosigner: Cosigner,
        clock: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    #[ractor::async_trait]
    impl WitnessCosigner for KeyCosigner {
        async fn cosign(&self, text: String) -> Result<(String, u64), String> {
            let time = self.clock.load(std::sync::atomic::Ordering::SeqCst);
            Ok((self.cosigner.cosign_line(&text, time), time))
        }
        async fn key(&self) -> Result<String, String> {
            Ok(self.cosigner.verifier_key())
        }
    }

    /// Judges and, as the witness does, co-signs and keeps what it would.
    fn take(holding: &mut Holding, request: &AddCheckpoint, now: u64) -> Judgement {
        let judged = judge(Some(&pinned()), holding, request, now);
        if let Judgement::Keep {
            origin,
            checkpoint,
            time,
        } = &judged
        {
            holding.insert(
                origin.clone(),
                cosign(&cosigner(&witness_key(5)), checkpoint, *time),
            );
        }
        judged
    }

    fn refused(judged: &Judgement) -> Option<(Refusal, bool)> {
        match judged {
            Judgement::Answer {
                answer: Answer::Refused(why),
                misbehaviour,
                ..
            } => Some((*why, misbehaviour.is_some())),
            _ => None,
        }
    }

    #[test]
    fn only_a_stores_checkpoint_key_is_pinned() {
        assert!(pinned().prefix == format!("{STORE}/"));
        let other = NoteSigner::new(
            "someone/else",
            p256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap(),
        )
        .unwrap();
        assert!(Pinned::parse(&other.verifier_key()).is_err());
        assert!(Pinned::parse("not a key").is_err());
        // A witness's key named like a store's signs no checkpoints.
        let posing = Cosigner::new(&format!("{STORE}/checkpoint"), witness_key(4)).unwrap();
        assert!(Pinned::parse(&posing.verifier_key()).is_err());
    }

    #[test]
    fn its_line_is_its_own_cosignature_of_what_it_holds() {
        let key = witness_key(5);
        let mut holding = Holding::new();
        take(&mut holding, &request(0, &leaves(4, 0), &store_key(1)), 30);
        check_holding(&holding, &own(&key)).unwrap();
        // Another witness's key, another time, another root: none is its own.
        assert!(check_holding(&holding, &own(&witness_key(6))).is_err());
        let origin = format!("{STORE}/evidence");
        let mut later = holding.clone();
        later.get_mut(&origin).unwrap().time = 31;
        assert!(check_holding(&later, &own(&key)).is_err());
        let mut other = holding.clone();
        other.get_mut(&origin).unwrap().root = [9; 32];
        assert!(check_holding(&other, &own(&key)).is_err());
    }

    #[test]
    fn with_no_store_pinned_every_origin_is_unknown() {
        let judged = judge(
            None,
            &Holding::new(),
            &request(0, &leaves(3, 0), &store_key(1)),
            9,
        );
        assert_eq!(refused(&judged), Some((Refusal::UnknownOrigin, false)));
    }

    #[test]
    fn a_first_checkpoint_is_kept_from_nothing() {
        let mut holding = Holding::new();
        let log = leaves(5, 0);
        let judged = take(&mut holding, &request(0, &log, &store_key(1)), 100);
        assert!(matches!(judged, Judgement::Keep { .. }), "{judged:?}");
        assert_eq!(holding[&format!("{STORE}/evidence")].size, 5);
    }

    #[test]
    fn an_empty_log_is_kept_with_the_empty_root_only() {
        let mut holding = Holding::new();
        let judged = take(&mut holding, &request(0, &[], &store_key(1)), 1);
        assert!(matches!(judged, Judgement::Keep { .. }));
        let lie = AddCheckpoint {
            old: 0,
            proof: Vec::new(),
            checkpoint: store_key(1).sign(
                &Checkpoint {
                    origin: format!("{STORE}/evidence"),
                    size: 0,
                    root: [7; 32],
                }
                .text(),
            ),
        };
        let judged = judge(Some(&pinned()), &Holding::new(), &lie, 1);
        assert_eq!(refused(&judged), Some((Refusal::Inconsistent, true)));
    }

    #[test]
    fn a_checkpoint_another_key_signed_is_untrusted() {
        let judged = judge(
            Some(&pinned()),
            &Holding::new(),
            &request(0, &leaves(2, 0), &store_key(2)),
            1,
        );
        assert_eq!(refused(&judged), Some((Refusal::Untrusted, false)));
    }

    #[test]
    fn an_origin_outside_the_stores_name_is_unknown() {
        let signer = store_key(1);
        let request = AddCheckpoint {
            old: 0,
            proof: Vec::new(),
            checkpoint: signer.sign(
                &Checkpoint {
                    origin: "elsewhere/evidence".into(),
                    size: 0,
                    root: root(&[]),
                }
                .text(),
            ),
        };
        let judged = judge(Some(&pinned()), &Holding::new(), &request, 1);
        assert_eq!(refused(&judged), Some((Refusal::UnknownOrigin, false)));
    }

    #[test]
    fn a_size_not_its_own_is_a_conflict_with_its_size() {
        let mut holding = Holding::new();
        let log = leaves(8, 0);
        take(&mut holding, &request(0, &log[..4], &store_key(1)), 1);
        let judged = take(&mut holding, &request(2, &log, &store_key(1)), 2);
        assert!(matches!(
            judged,
            Judgement::Answer {
                answer: Answer::Conflict(4),
                misbehaviour: None,
                ..
            }
        ));
    }

    #[test]
    fn a_fork_is_refused_and_said_as_misbehaviour() {
        let mut holding = Holding::new();
        take(&mut holding, &request(0, &leaves(4, 0), &store_key(1)), 1);
        let mut forked = leaves(6, 1);
        forked[..4].copy_from_slice(&leaves(4, 0));
        forked[1] = leaf_hash(b"rewritten");
        let judged = take(&mut holding, &request(4, &forked, &store_key(1)), 2);
        assert_eq!(refused(&judged), Some((Refusal::Inconsistent, true)));
        assert_eq!(holding[&format!("{STORE}/evidence")].size, 4);
    }

    #[test]
    fn a_signed_rollback_is_said_as_misbehaviour() {
        let mut holding = Holding::new();
        let log = leaves(6, 0);
        take(&mut holding, &request(0, &log, &store_key(1)), 1);
        // The store retried from the witness's size, with a smaller checkpoint.
        let back = AddCheckpoint {
            old: 6,
            proof: Vec::new(),
            checkpoint: note(&store_key(1), "evidence", &log[..3]),
        };
        let judged = take(&mut holding, &back, 2);
        assert_eq!(refused(&judged), Some((Refusal::Malformed, true)));
    }

    #[test]
    fn a_proof_longer_than_any_is_malformed() {
        let mut request = request(0, &leaves(2, 0), &store_key(1));
        request.proof = vec![[0; 32]; MAX_PROOF + 1];
        let judged = judge(Some(&pinned()), &Holding::new(), &request, 1);
        assert_eq!(refused(&judged), Some((Refusal::Malformed, false)));
    }

    #[test]
    fn its_time_never_goes_back() {
        let mut holding = Holding::new();
        let log = leaves(4, 0);
        take(&mut holding, &request(0, &log[..2], &store_key(1)), 50);
        take(&mut holding, &request(2, &log, &store_key(1)), 10);
        assert_eq!(holding[&format!("{STORE}/evidence")].time, 50);
    }

    #[test]
    fn each_origin_is_witnessed_on_its_own() {
        let mut holding = Holding::new();
        let signer = store_key(1);
        take(&mut holding, &request(0, &leaves(3, 0), &signer), 1);
        let other = AddCheckpoint {
            old: 0,
            proof: Vec::new(),
            checkpoint: note(&signer, "schedules", &leaves(2, 9)),
        };
        assert!(matches!(
            take(&mut holding, &other, 1),
            Judgement::Keep { .. }
        ));
        assert_eq!(holding.len(), 2);
    }

    #[test]
    fn what_is_kept_is_found_again() {
        let dir = tempfile::tempdir().unwrap();
        let key = witness_key(5);
        let (kept, holding) = Kept::open(dir.path(), &key_of(&key)).unwrap();
        assert!(holding.is_empty());
        let mut holding = Holding::new();
        holding.insert(
            format!("{STORE}/evidence"),
            cosign(
                &cosigner(&key),
                &Checkpoint {
                    origin: format!("{STORE}/evidence"),
                    size: 3,
                    root: [5; 32],
                },
                7,
            ),
        );
        kept.keep(&holding).unwrap();
        let (_, found) = Kept::open(dir.path(), &key_of(&key)).unwrap();
        assert_eq!(found, holding);
        check_holding(&found, &own(&key)).unwrap();
    }

    /// What is held under another key (the crypto actor made the key again, the old one lost) is damage, and so is a
    /// co-signature in it its own key did not make, or a file that does not read.
    #[test]
    fn what_another_key_co_signed_is_damage() {
        let dir = tempfile::tempdir().unwrap();
        let (kept, _) = Kept::open(dir.path(), &key_of(&witness_key(5))).unwrap();
        kept.keep(&Holding::new()).unwrap();
        assert!(matches!(
            Kept::open(dir.path(), &key_of(&witness_key(6))),
            Err(Damage::AnotherKey { .. })
        ));

        let dir = tempfile::tempdir().unwrap();
        let mut holding = Holding::new();
        let checkpoint = Checkpoint {
            origin: format!("{STORE}/evidence"),
            size: 1,
            root: [1; 32],
        };
        holding.insert(
            checkpoint.origin.clone(),
            cosign(&cosigner(&witness_key(6)), &checkpoint, 1),
        );
        std::fs::write(
            dir.path().join(HOLDING_FILE),
            serde_json::to_vec(&holding).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            Kept::open(dir.path(), &key_of(&witness_key(5))),
            Err(Damage::NotItsOwn { .. })
        ));

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(HOLDING_FILE), b"{\"o/l\": 3").unwrap();
        assert!(matches!(
            Kept::open(dir.path(), &key_of(&witness_key(5))),
            Err(Damage::Unreadable { .. })
        ));
    }

    /// A holding of the earlier form, which records no key (what u7c's witness kept before its key was the crypto
    /// actor's), is taken when its co-signatures are the witness's own, and kept from then on with the key recorded.
    #[test]
    fn an_earlier_holding_of_its_own_is_taken_and_its_key_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let key = witness_key(5);
        let mut holding = Holding::new();
        let checkpoint = Checkpoint {
            origin: format!("{STORE}/evidence"),
            size: 3,
            root: [5; 32],
        };
        holding.insert(
            checkpoint.origin.clone(),
            cosign(&cosigner(&key), &checkpoint, 7),
        );
        std::fs::write(
            dir.path().join(HOLDING_FILE),
            serde_json::to_vec(&holding).unwrap(),
        )
        .unwrap();
        let (_, found) = Kept::open(dir.path(), &key_of(&key)).unwrap();
        assert_eq!(found, holding);
        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join(HOLDING_FILE)).unwrap()).unwrap();
        assert_eq!(written["key"], key_of(&key));
        assert!(matches!(
            Kept::open(dir.path(), &key_of(&witness_key(6))),
            Err(Damage::AnotherKey { .. })
        ));
    }

    /// A witness as the actor runs it, with what it publishes and what it says of misbehaviour caught.
    struct Running {
        state: WitnessState,
        published: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        found: std::sync::Arc<std::sync::Mutex<Vec<Misbehaviour>>>,
        /// The crypto actor's clock, which states each co-signature's time.
        clock: std::sync::Arc<std::sync::atomic::AtomicU64>,
        _dir: tempfile::TempDir,
    }

    fn running(pin: Option<&str>) -> Running {
        let dir = tempfile::tempdir().unwrap();
        let key = witness_key(5);
        let (kept, holding) = Kept::open(dir.path(), &key_of(&key)).unwrap();
        let published = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let found = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (p, f) = (published.clone(), found.clone());
        let clock = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1_700_000_000));
        Running {
            state: WitnessState {
                kept,
                cosigner: std::sync::Arc::new(KeyCosigner {
                    cosigner: cosigner(&key),
                    clock: clock.clone(),
                }),
                holding,
                store: STORE.to_string(),
                publish: std::sync::Arc::new(move |bytes| {
                    p.lock().unwrap().push(bytes);
                    Ok(())
                }),
                misbehaved: std::sync::Arc::new(move |m| f.lock().unwrap().push(m)),
                clock: || 1_700_000_000,
                pinned: pin_of(pin, STORE),
                said_unpinned: false,
            },
            published,
            found,
            clock,
            _dir: dir,
        }
    }

    async fn send(
        running: &mut Running,
        request: AddCheckpoint,
        from: Option<&str>,
    ) -> Option<Answer> {
        use attestation_common::witness::{Envelope, decode_witnessed, encode_add_checkpoint};
        let before = running.published.lock().unwrap().len();
        let bytes = encode_add_checkpoint(&Envelope {
            correlation_id: "c-1".into(),
            payload: request,
        });
        take_request(&mut running.state, &bytes, from).await;
        let published = running.published.lock().unwrap();
        (published.len() > before).then(|| {
            let answer = decode_witnessed(published.last().unwrap()).unwrap();
            assert_eq!(answer.correlation_id, "c-1");
            answer.payload.answer
        })
    }

    #[tokio::test]
    async fn it_answers_the_store_alone() {
        let pin = store_key(1).verifier_key();
        let mut witness = running(Some(&pin));
        let request = request(0, &leaves(3, 0), &store_key(1));
        assert_eq!(send(&mut witness, request.clone(), None).await, None);
        assert_eq!(
            send(
                &mut witness,
                request.clone(),
                Some("intruder.polar.serviceaccount.cluster.local")
            )
            .await,
            None
        );
        assert!(witness.state.holding.is_empty());
        assert!(matches!(
            send(&mut witness, request, Some(STORE)).await,
            Some(Answer::Cosigned(_))
        ));
    }

    #[tokio::test]
    async fn what_it_answers_with_is_kept_first_and_verifies() {
        let pin = store_key(1).verifier_key();
        let mut witness = running(Some(&pin));
        let log = leaves(5, 0);
        let Some(Answer::Cosigned(line)) =
            send(&mut witness, request(0, &log, &store_key(1)), Some(STORE)).await
        else {
            panic!("not co-signed");
        };
        // What a restart finds is what was answered.
        let key = witness_key(5);
        let (_, found) = Kept::open(witness._dir.path(), &key_of(&key)).unwrap();
        assert_eq!(found[&format!("{STORE}/evidence")].line, line);
        // A reader holding both keys opens the co-signed checkpoint, and sees the witness's time.
        let note = format!("{}{line}", note(&store_key(1), "evidence", &log));
        let both = [NoteVerifier::parse(&pin).unwrap(), own(&key)];
        let opened = open_signed(&note, &both).unwrap();
        assert_eq!(opened.by.len(), 2);
        assert_eq!(opened.by[1].cosigned_at, Some(1_700_000_000));
    }

    /// The time is the crypto actor's: one that goes back on what was co-signed for the origin is neither kept nor
    /// sent, so the time a reader sees never goes back.
    #[tokio::test]
    async fn a_co_signature_whose_time_goes_back_is_neither_kept_nor_sent() {
        let pin = store_key(1).verifier_key();
        let mut witness = running(Some(&pin));
        let log = leaves(3, 0);
        assert!(matches!(
            send(&mut witness, request(0, &log, &store_key(1)), Some(STORE)).await,
            Some(Answer::Cosigned(_))
        ));
        witness
            .clock
            .store(1_600_000_000, std::sync::atomic::Ordering::SeqCst);
        let mut grown = log.clone();
        grown.push(leaf_hash(b"next"));
        assert_eq!(
            send(&mut witness, request(3, &grown, &store_key(1)), Some(STORE)).await,
            None
        );
        let held = &witness.state.holding[&format!("{STORE}/evidence")];
        assert_eq!((held.size, held.time), (3, 1_700_000_000));
    }

    #[tokio::test]
    async fn unpinned_it_refuses_every_origin_and_says_so_once() {
        let mut witness = running(None);
        for _ in 0..2 {
            assert_eq!(
                send(
                    &mut witness,
                    request(0, &leaves(2, 0), &store_key(1)),
                    Some(STORE)
                )
                .await,
                Some(Answer::Refused(Refusal::UnknownOrigin))
            );
        }
        assert!(witness.state.said_unpinned);
    }

    #[test]
    fn a_pin_of_another_stores_key_is_not_taken() {
        let other = NoteSigner::new(
            "polar-git-server.elsewhere.serviceaccount.cluster.local/checkpoint",
            p256::ecdsa::SigningKey::from_slice(&[8; 32]).unwrap(),
        )
        .unwrap();
        assert!(pin_of(Some(&other.verifier_key()), STORE).is_none());
        assert!(pin_of(Some(&store_key(1).verifier_key()), STORE).is_some());
        assert!(pin_of(None, STORE).is_none());
    }

    #[tokio::test]
    async fn a_fork_is_answered_refused_and_handed_on_as_misbehaviour() {
        let pin = store_key(1).verifier_key();
        let mut witness = running(Some(&pin));
        send(
            &mut witness,
            request(0, &leaves(4, 0), &store_key(1)),
            Some(STORE),
        )
        .await;
        let mut forked = leaves(6, 0);
        forked[0] = leaf_hash(b"rewritten");
        assert_eq!(
            send(
                &mut witness,
                request(4, &forked, &store_key(1)),
                Some(STORE)
            )
            .await,
            Some(Answer::Refused(Refusal::Inconsistent))
        );
        let found = witness.found.lock().unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].held.as_ref().map(|h| h.size), Some(4));
        assert_eq!(found[0].offered_size, 6);
    }

    /// What the store might bring, from the log the witness last co-signed: that log grown, a leaf of it rewritten
    /// (and grown), an older checkpoint of it, any size claimed for it, the same again; or a restart of the witness.
    #[derive(Debug, Clone)]
    enum Step {
        Grow(usize),
        Rewrite(prop::sample::Index, usize),
        Back(usize),
        Claim(usize, usize),
        Restart,
    }

    fn a_step() -> impl Strategy<Value = Step> {
        prop_oneof![
            (0usize..10).prop_map(Step::Grow),
            (any::<prop::sample::Index>(), 0usize..5).prop_map(|(i, by)| Step::Rewrite(i, by)),
            (0usize..30).prop_map(Step::Back),
            (0usize..30, 0usize..10).prop_map(|(o, by)| Step::Claim(o, by)),
            Just(Step::Restart),
        ]
    }

    proptest! {
        /// For any run of grown, rewritten, rolled back, mis-sized or repeated checkpoints, with restarts between, each
        /// checkpoint the witness co-signs for an origin extends the last it co-signed (that log is a prefix of this
        /// one), and its time never goes back. A witness cannot tell honest growth from a fork it has never seen; it
        /// holds the log to what it already co-signed.
        #[test]
        fn it_never_cosigns_two_checkpoints_that_are_not_consistent(
            steps in prop::collection::vec(a_step(), 1..40),
            times in prop::collection::vec(0u64..100, 40),
        ) {
            let dir = tempfile::tempdir().unwrap();
            let key = witness_key(5);
            let (mut kept, mut holding) = Kept::open(dir.path(), &key_of(&key)).unwrap();
            let signer = store_key(1);
            let mut current: Vec<Hash> = Vec::new();
            let mut fresh = 0u32;
            let mut grow = |log: &mut Vec<Hash>, by: usize| {
                for _ in 0..by {
                    fresh += 1;
                    log.push(leaf_hash(&fresh.to_be_bytes()));
                }
            };
            let mut last: Option<Held> = None;
            for (step, now) in steps.into_iter().zip(times) {
                let held = current.len();
                let (old, log) = match step {
                    Step::Restart => {
                        let (k, h) = Kept::open(dir.path(), &key_of(&key)).unwrap();
                        prop_assert_eq!(&h, &holding);
                        prop_assert!(check_holding(&h, &own(&key)).is_ok());
                        (kept, holding) = (k, h);
                        continue;
                    }
                    Step::Grow(by) => {
                        let mut log = current.clone();
                        grow(&mut log, by);
                        (held, log)
                    }
                    Step::Rewrite(at, by) => {
                        if current.is_empty() {
                            continue;
                        }
                        let mut log = current.clone();
                        log[at.index(held)] = leaf_hash(b"rewritten");
                        grow(&mut log, by);
                        (held, log)
                    }
                    Step::Back(n) => (held, current[..n.min(held)].to_vec()),
                    Step::Claim(old, by) => {
                        let mut log = current.clone();
                        grow(&mut log, by);
                        (old.min(log.len()), log)
                    }
                };
                let request = AddCheckpoint {
                    old: old as u64,
                    proof: if old == 0 { Vec::new() } else { consistency_proof(old, &log).unwrap_or_default() },
                    checkpoint: note(&signer, "evidence", &log),
                };
                let judged = judge(Some(&pinned()), &holding, &request, now);
                if let Judgement::Keep { origin, checkpoint, time } = judged {
                    let new = cosign(&cosigner(&key), &checkpoint, time);
                    let mut next = holding.clone();
                    next.insert(origin, new.clone());
                    kept.keep(&next).unwrap();
                    holding = next;
                    prop_assert_eq!(new.size as usize, log.len());
                    prop_assert_eq!(&log[..current.len()], &current[..], "co-signed a checkpoint that does not extend the last");
                    if let Some(before) = &last {
                        prop_assert!(new.size >= before.size);
                        prop_assert!(new.time >= before.time);
                    }
                    last = Some(new);
                    current = log;
                }
            }
        }
    }
}
