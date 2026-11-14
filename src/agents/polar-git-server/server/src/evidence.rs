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

//! Evidence records sent over Cassini, added to `polar-evidence` by the server itself (docs/architecture/git-server.md,
//! "Inside the boundary"; docs/architecture/polar-eden.md, "Attestation verdicts as records"): a collector that is a
//! workload never pushes with `git`. A record is taken only from a sender the broker stamped, who may write the
//! repository, and only when it verifies in the evidence domain against the CA the server trusts and is the sender's own:
//! signed by the sender, under its signing certificate, of a type it may record (policy first, its certificate where
//! policy is silent). It is written at
//! `<type>/<the subject's values, in the order of their keys>/<sha256 of the record>.json`, as people's tools write
//! theirs, never over a file that is there, and the commit is announced as a push is, the sender its pusher.

use crate::access::{Access, Authorizer, Identity};
use crate::notify::{Notifier, RepoChanged};
use crate::store::{Author, FileAdded, RepoStore, StoreError};
use polar_git_server_common::{
    AddRecord, EVIDENCE_REPO, Envelope, RecordAdded, decode_add, evidence_replies_topic,
};
use polar_signing::Trust;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::warn;

/// How far from the server's clock a commit pushed to the evidence repository may say it was made
/// (docs/architecture/key-custody.md, "Workload signing keys", item 7). A reader verifies a record as of the commit that
/// added it, so that time must be the server's word: a commit backdated into a certificate's life, or one dated ahead,
/// is refused. Ten minutes either way, for the clocks of the people who push; decided here, for review.
pub const PUSHED_WITHIN_SECS: i64 = 600;

/// Why a commit pushed to the evidence repository, made at `committed` (its committer's time), is refused at `now`, or
/// none.
pub fn pushed_time_refusal(committed: Option<i64>, now: i64) -> Option<String> {
    match committed {
        Some(at) if (at - now).abs() <= PUSHED_WITHIN_SECS => None,
        Some(at) => Some(format!(
            "it says it was made at {at}, more than {PUSHED_WITHIN_SECS} seconds from the server's clock ({now}): a \
             record is verified as of the commit that added it, so commit it again now"
        )),
        None => Some("it says no time it was made, against the server's clock".to_string()),
    }
}

/// Whether a push to the evidence repository may be taken: every commit it brings says it was made about now
/// ([`pushed_time_refusal`]). `repo` is the repository with the push's objects in quarantine beside it.
pub fn check_pushed_times(
    repo: &gix::Repository,
    updates: &[crate::pktline::RefUpdate],
    now: i64,
) -> Result<(), String> {
    for pushed in crate::signed::pushed_commits(repo, updates)? {
        if let Some(why) = pushed_time_refusal(crate::signed::committer_time(&pushed.raw), now) {
            return Err(format!("commit {} is refused: {why}", pushed.commit));
        }
    }
    Ok(())
}

/// The records a push to the evidence repository adds, with their bytes, in path order: each `*.json` file outside a
/// hidden folder (as polar-eden reads a checkout) that a ref's new tip holds and its old tip did not hold with those
/// bytes. `repo` holds the push's objects in quarantine. What the store's evidence log takes from a push
/// (docs/architecture/record-store.md, "Pushes to the log"), so the log holds every record the repository holds.
pub fn pushed_records(
    repo: &gix::Repository,
    updates: &[crate::pktline::RefUpdate],
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut added = std::collections::BTreeMap::new();
    for update in updates {
        let new = gix::ObjectId::from_hex(update.new.as_bytes())
            .map_err(|e| format!("{} is not an object id: {e}", update.new))?;
        if new.is_null() {
            continue;
        }
        let old = gix::ObjectId::from_hex(update.old.as_bytes())
            .map_err(|e| format!("{} is not an object id: {e}", update.old))?;
        let before = if old.is_null() {
            Default::default()
        } else {
            record_files(repo, old)?
        };
        for (path, blob) in record_files(repo, new)? {
            if before.get(&path) != Some(&blob) {
                let bytes = repo
                    .find_blob(blob)
                    .map_err(|e| format!("{path} cannot be read: {e}"))?
                    .detach()
                    .data;
                added.insert(path, bytes);
            }
        }
    }
    Ok(added.into_iter().collect())
}

/// Every `*.json` file of `commit`'s tree outside a hidden folder, by path, with its blob.
fn record_files(
    repo: &gix::Repository,
    commit: gix::ObjectId,
) -> Result<std::collections::BTreeMap<String, gix::ObjectId>, String> {
    let root = repo
        .find_commit(commit)
        .and_then(|c| c.tree())
        .map_err(|e| format!("the tree of {commit} cannot be read: {e}"))?
        .id;
    let mut files = std::collections::BTreeMap::new();
    let mut folders = vec![(String::new(), root)];
    while let Some((folder, id)) = folders.pop() {
        let tree = repo
            .find_tree(id)
            .map_err(|e| format!("{folder}/ cannot be read: {e}"))?;
        let entries = tree
            .decode()
            .map_err(|e| format!("{folder}/ cannot be read: {e}"))?
            .entries;
        for entry in entries {
            let name = entry.filename.to_string();
            if name.starts_with('.') {
                continue;
            }
            let at = if folder.is_empty() {
                name.clone()
            } else {
                format!("{folder}/{name}")
            };
            if entry.mode.is_tree() {
                folders.push((at, entry.oid.to_owned()));
            } else if entry.mode.is_blob() && is_record_path(&at) {
                files.insert(at, entry.oid.to_owned());
            }
        }
    }
    Ok(files)
}

/// The longest segment of a record's path.
const MAX_SEGMENT: usize = 128;

/// A segment of a record's path: not empty, not starting with '.', no '/', backslash or control character.
fn segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SEGMENT
        && !value.starts_with('.')
        && !value
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_control())
}

/// Where `record` goes in the evidence repository, once it verifies in the evidence domain under `trust` at `now`; or
/// why it does not.
pub fn place(record: &str, trust: &Trust, now: i64) -> Result<String, String> {
    placed(record, trust, now).map(|(path, _)| path)
}

/// A record that is its sender's own: where it goes, and what policy is asked of it (who signed it, under which
/// certificate, of which type).
pub struct Placed {
    pub path: String,
    pub signer: String,
    pub certificate_pem: String,
    pub record_type: String,
}

/// Where `record` goes in the evidence repository, once it is `sender`'s own (docs/architecture/key-custody.md,
/// "Workload signing keys", items 6 and 8): it verifies as [`place`] has it, its signer is the sender, and it is signed
/// as a workload's record must be, under a signing certificate (`polar_signing::workload_certificate_refusal`). So a
/// writer cannot add a record another signed, nor one its own mTLS key signed. Whether it may record that type is
/// policy's, asked after (`Intake::add`).
pub fn place_senders(
    record: &str,
    sender: &str,
    trust: &Trust,
    now: i64,
) -> Result<Placed, String> {
    let (path, (document, signer)) = placed(record, trust, now)?;
    if signer.identity.as_deref() != Some(sender) {
        return Err(format!(
            "it is signed by {}, not by its sender {sender}",
            signer.identity.as_deref().unwrap_or("no identity")
        ));
    }
    if let Some(why) = polar_signing::workload_certificate_refusal(&document) {
        return Err(why);
    }
    Ok(Placed {
        path,
        signer: sender.to_string(),
        certificate_pem: document.signature.certificate_chain[0].clone(),
        record_type: document.payload["type"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    })
}

/// [`place`], with the document and who signed it.
fn placed(
    record: &str,
    trust: &Trust,
    now: i64,
) -> Result<(String, (polar_signing::Document, polar_signing::SignerInfo)), String> {
    let value: serde_json::Value =
        serde_json::from_str(record).map_err(|e| format!("it is not JSON: {e}"))?;
    let document = polar_signing::Document::from_value(&value)
        .map_err(|e| format!("it is not a signed document: {e}"))?;
    let signer = polar_signing::verify_in(
        polar_signing::Domain::EVIDENCE_RECORD,
        &document,
        trust,
        now,
    )
    .map_err(|e| format!("it does not verify as evidence: {e}"))?;
    let payload = &document.payload;
    let kind = payload["type"].as_str().ok_or("it names no type")?;
    if !segment(kind) {
        return Err(format!("its type `{kind}` cannot name a folder"));
    }
    let subject = payload["subject"]
        .as_object()
        .filter(|s| !s.is_empty())
        .ok_or("it names no subject")?;
    let mut path = vec![kind.to_string()];
    // Sorted here: whether a JSON object keeps the order it was written in depends on serde_json's features in the
    // build, and a record's place must not.
    let subject: std::collections::BTreeMap<_, _> = subject.iter().collect();
    for (key, value) in subject {
        let text = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_string);
        if !segment(&text) {
            return Err(format!("its subject's {key} `{text}` cannot name a folder"));
        }
        path.push(text);
    }
    path.push(format!("{}.json", hex(&Sha256::digest(record.as_bytes()))));
    Ok((path.join("/"), (document, signer)))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What the server needs to take records: the repositories, who may write them, the CA records are verified under, and
/// how a commit is announced.
pub struct Intake {
    pub store: RepoStore,
    pub authorizer: Arc<dyn Authorizer>,
    pub trust: Trust,
    pub notifier: Arc<dyn Notifier>,
    /// What the credentials agent says about policy, which decides first who may record what
    /// (docs/architecture/credentials-policy.md, "Who may sign evidence"); none, and the certificate decides.
    pub policy: Option<ractor::ActorRef<polar_policy::PolicyMessage>>,
    /// The store's logs: a record admitted is appended to the `evidence` log before it is committed to the repository
    /// (docs/architecture/record-store.md, bite 3: the log becomes the record; the repository stays what readers read
    /// until they move). None, and only the repository is written.
    pub logs: Option<ractor::ActorRef<crate::logs::LogsMessage>>,
}

/// The log admitted evidence records are appended to.
pub const EVIDENCE_LOG: &str = "evidence";

/// An evidence record's type in the store's logs.
pub const EVIDENCE_RECORD: &str = "evidence-record";

/// `record`, as the entry the `evidence` log holds: the signed document as its sender sent it, opaque; critical, since a
/// reader that does not know it cannot judge what it says.
pub fn evidence_entry(record: &str) -> Vec<u8> {
    polar_log::entry::Entry {
        kind: EVIDENCE_RECORD.to_string(),
        version: 1,
        critical: true,
        writer: format!("{} {}", polar_version::PLATFORM, polar_version::TARGET),
        event: record.as_bytes().to_vec(),
    }
    .encode()
}

/// Who the server's commits are by.
const SERVER: Author<'static> = Author {
    name: "polar-git-server",
    email: "polar-git-server@localhost",
};

impl Intake {
    /// The answer to a request `published_by` sent, and the topic it goes to; none when there is nobody to answer (no
    /// identity the broker stamped, or one that names no workload) or no request to answer (bytes that are not one),
    /// each said in a warning.
    pub async fn take(
        &self,
        published_by: Option<&str>,
        payload: &[u8],
        now: i64,
    ) -> Option<(String, Envelope<RecordAdded>)> {
        let Some(sender) = published_by else {
            warn!("dropped an evidence record with no sender the broker stamped");
            return None;
        };
        let Some(workload) = cert_issuer_common::identity::workload_of(sender) else {
            warn!(
                sender,
                "dropped an evidence record from an identity that names no workload"
            );
            return None;
        };
        let request = match decode_add(payload) {
            Ok(request) => request,
            Err(why) => {
                warn!(sender, "dropped an evidence record: {why}");
                return None;
            }
        };
        let answer = self.add(sender, &request.payload, now).await;
        if let RecordAdded::Refused { why } | RecordAdded::NotNow { why } = &answer {
            warn!(sender, "an evidence record was not added: {why}");
        }
        Some((
            evidence_replies_topic(workload),
            Envelope {
                correlation_id: request.correlation_id,
                payload: answer,
            },
        ))
    }

    async fn add(&self, sender: &str, request: &AddRecord, now: i64) -> RecordAdded {
        if !self
            .authorizer
            .allows(&Identity(sender.to_string()), EVIDENCE_REPO, Access::Write)
        {
            return RecordAdded::Refused {
                why: format!("{sender} may not add evidence to {EVIDENCE_REPO}"),
            };
        }
        let placed = match place_senders(&request.record, sender, &self.trust, now) {
            Ok(placed) => placed,
            Err(why) => return RecordAdded::Refused { why },
        };
        // What it may record: policy first, both ways, and its certificate's evidence names where policy is silent.
        if let Err(refusal) = polar_agent_builder::policy_authority::admit_evidence(
            self.policy.as_ref(),
            &placed.signer,
            &placed.certificate_pem,
            &placed.record_type,
        )
        .await
        {
            return RecordAdded::Refused {
                why: refusal.to_string(),
            };
        }
        // The log first: it is the record, and the repository is made from what it holds. A record sent again after
        // its answer was lost is found there and not added twice.
        if let Some(logs) = &self.logs {
            let entry = evidence_entry(&request.record);
            match ractor::call!(logs, |reply| crate::logs::LogsMessage::AppendOnce {
                log: EVIDENCE_LOG.to_string(),
                entry,
                submitter: sender.to_string(),
                reply,
            }) {
                Ok(Ok(_)) => {}
                Ok(Err(why)) => return RecordAdded::NotNow { why },
                Err(e) => {
                    return RecordAdded::NotNow {
                        why: format!("the store's logs did not answer: {e}"),
                    };
                }
            }
        }
        let path = placed.path;
        let message = format!(
            "evidence: {path}\n\nSent by {sender} over Cassini and added by polar-git-server."
        );
        match self
            .store
            .add_file(
                EVIDENCE_REPO,
                &path,
                request.record.as_bytes(),
                &SERVER,
                &message,
            )
            .await
        {
            Ok(FileAdded::Committed { old, new }) => {
                self.notifier
                    .repo_changed(RepoChanged {
                        repo: EVIDENCE_REPO.to_string(),
                        refname: "refs/heads/main".to_string(),
                        old: old.unwrap_or_else(|| "0".repeat(40)),
                        new: new.clone(),
                        pusher: sender.to_string(),
                    })
                    .await;
                RecordAdded::Committed { path, commit: new }
            }
            Ok(FileAdded::AlreadyThere) => RecordAdded::AlreadyThere { path },
            Err(e @ (StoreError::BadPath(_) | StoreError::BadName(_))) => {
                RecordAdded::Refused { why: e.to_string() }
            }
            Err(e) => RecordAdded::NotNow { why: e.to_string() },
        }
    }
}

/// A request, as Cassini delivered it.
pub enum IntakeMessage {
    Take {
        payload: Vec<u8>,
        published_by: Option<String>,
    },
}

/// Takes records one at a time, so additions never race each other, and answers each sender on its own topic, the
/// answer stamped with the server's identity for the sender to check.
pub struct IntakeActor;

pub struct IntakeState {
    pub intake: Intake,
    pub client: ractor::ActorRef<cassini_client::TcpClientMessage>,
}

#[ractor::async_trait]
impl ractor::Actor for IntakeActor {
    type Msg = IntakeMessage;
    type State = IntakeState;
    type Arguments = IntakeState;

    async fn pre_start(
        &self,
        _myself: ractor::ActorRef<Self::Msg>,
        state: IntakeState,
    ) -> Result<Self::State, ractor::ActorProcessingErr> {
        Ok(state)
    }

    async fn handle(
        &self,
        _myself: ractor::ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ractor::ActorProcessingErr> {
        let IntakeMessage::Take {
            payload,
            published_by,
        } = message;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        let Some((topic, answer)) = state
            .intake
            .take(published_by.as_deref(), &payload, now)
            .await
        else {
            return Ok(());
        };
        if let Err(e) = state
            .client
            .send_message(cassini_client::TcpClientMessage::publish(
                topic.clone(),
                polar_git_server_common::encode_added(&answer),
                None,
            ))
        {
            tracing::error!(error = %e, topic, "cannot answer about an evidence record");
        }
        Ok(())
    }
}

/// Whether a file of the evidence repository is a record: a `*.json` file outside a hidden folder.
fn is_record_path(path: &str) -> bool {
    path.ends_with(".json") && !path.split('/').any(|segment| segment.starts_with('.'))
}

/// Appends to the `evidence` log each record `polar-evidence`'s `main` holds that the log does not, as `origin`'s, at
/// the store's start: what a push took while the server kept no log (a version without one ran over the same volume,
/// as main's does on a cluster both share), so the log again holds every record the repository holds. A file that is
/// not text, or that the log cannot take, is left out and said; the logs not answering refuses the start.
pub async fn catch_up(
    store: &RepoStore,
    logs: &ractor::ActorRef<crate::logs::LogsMessage>,
    origin: &str,
) -> Result<crate::logs::Appended, String> {
    if !store.exists(EVIDENCE_REPO) {
        return Ok(Default::default());
    }
    let Some((commit, _, files)) = store
        .main_tree(EVIDENCE_REPO)
        .await
        .map_err(|e| format!("{EVIDENCE_REPO} cannot be read: {e}"))?
    else {
        return Ok(Default::default());
    };
    let mut entries = std::collections::BTreeMap::new();
    let mut not_text = Vec::new();
    for file in files {
        if file.kind == polar_git_server_common::FileKind::Link || !is_record_path(&file.path) {
            continue;
        }
        match String::from_utf8(file.content) {
            Ok(record) => {
                entries.insert(file.path, evidence_entry(&record));
            }
            Err(_) => not_text.push((file.path, "it is not text, so it is no record".to_string())),
        }
    }
    let mut done = ractor::call!(logs, |reply| crate::logs::LogsMessage::AppendMissing {
        log: EVIDENCE_LOG.to_string(),
        entries,
        submitter: origin.to_string(),
        reply,
    })
    .map_err(|e| format!("the store's logs did not answer: {e}"))??;
    done.left_out.extend(not_text);
    done.left_out.sort();
    for (path, why) in &done.left_out {
        warn!(%path, %why, "a record of {EVIDENCE_REPO} is left out of the evidence log");
    }
    if !done.appended.is_empty() {
        tracing::info!(
            %commit,
            appended = done.appended.len(),
            "the evidence log was brought to {EVIDENCE_REPO}'s main"
        );
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{RepoAcl, StaticAcl};
    use crate::notify::Recorder;
    use polar_git_server_common::{decode_added, encode_add};
    use polar_signing::testing::{Spec, now, root, signer};
    use serde_json::json;

    const SENDER: &str = "attestation-agent.polar.serviceaccount.cluster.local";

    fn signed(
        domain: polar_signing::Domain,
        payload: serde_json::Value,
        ca: &polar_signing::testing::Authority,
    ) -> String {
        let alice = signer(ca, Spec::default());
        let document = polar_signing::sign_in(
            domain,
            payload,
            std::slice::from_ref(&alice.cert_pem),
            &alice.key_pem,
        )
        .unwrap();
        serde_json::to_string_pretty(&document.to_value()).unwrap()
    }

    /// `payload` signed with a pod's signing key: a documentSigning certificate for `identity`, naming `names`.
    fn from_pod(
        payload: serde_json::Value,
        ca: &polar_signing::testing::Authority,
        identity: &'static str,
        names: Vec<&'static str>,
        eku: rcgen::ExtendedKeyUsagePurpose,
    ) -> String {
        let pod = signer(
            ca,
            Spec {
                identity,
                capabilities: names,
                extended_key_usages: vec![eku],
                ..Spec::default()
            },
        );
        let document = polar_signing::sign_in(
            polar_signing::Domain::EVIDENCE_RECORD,
            payload,
            std::slice::from_ref(&pod.cert_pem),
            &pod.key_pem,
        )
        .unwrap();
        serde_json::to_string_pretty(&document.to_value()).unwrap()
    }

    fn document_signing() -> rcgen::ExtendedKeyUsagePurpose {
        rcgen::ExtendedKeyUsagePurpose::Other(cert_issuer_common::OID_DOCUMENT_SIGNING.to_vec())
    }

    /// The sender's own record, as its signer signs it: under its signing certificate, which may record attestations.
    fn senders(payload: serde_json::Value, ca: &polar_signing::testing::Authority) -> String {
        from_pod(
            payload,
            ca,
            SENDER,
            vec!["c:record-evidence:attestation"],
            document_signing(),
        )
    }

    fn record(target: &str) -> serde_json::Value {
        json!({
            "type": "attestation",
            "subject": { "target": target },
            "result": { "passed": true, "problems": [] },
            "judged_at_unix_secs": now(),
        })
    }

    fn sha(text: &str) -> String {
        hex(&Sha256::digest(text.as_bytes()))
    }

    /// A record that verifies goes under its type and its subject's values, in the order of their keys, named by the
    /// digest of exactly its bytes: as polar-eden and polar-sign place theirs.
    #[test]
    fn a_record_that_verifies_goes_under_its_type_and_subject_named_by_its_digest() {
        let ca = root("Polar test CA");
        let trust = Trust::from_pem(std::slice::from_ref(&ca.pem)).unwrap();
        let text = signed(polar_signing::Domain::EVIDENCE_RECORD, record("u7c"), &ca);
        assert_eq!(
            place(&text, &trust, now()).unwrap(),
            format!("attestation/u7c/{}.json", sha(&text))
        );
        let two = json!({
            "type": "projection-test",
            "subject": { "section": "projection", "agent": "openapi-processor" },
        });
        let text = signed(polar_signing::Domain::EVIDENCE_RECORD, two, &ca);
        assert_eq!(
            place(&text, &trust, now()).unwrap(),
            format!(
                "projection-test/openapi-processor/projection/{}.json",
                sha(&text)
            )
        );
    }

    /// A record is refused when it is not JSON or no signed document, is signed under a CA the server does not trust or
    /// in another domain, or names no type, no subject, or one that cannot name a folder.
    #[test]
    fn what_is_not_a_verifying_record_with_a_place_is_refused_and_says_why() {
        let ca = root("Polar test CA");
        let trust = Trust::from_pem(std::slice::from_ref(&ca.pem)).unwrap();
        let other = root("Another CA");
        let refused = |text: &str, says: &str| {
            let why = place(text, &trust, now()).unwrap_err();
            assert!(why.contains(says), "{says}: {why}");
        };
        refused("not json", "not JSON");
        refused("{\"a\":1}", "not a signed document");
        refused(
            &signed(
                polar_signing::Domain::EVIDENCE_RECORD,
                record("u7c"),
                &other,
            ),
            "does not verify",
        );
        refused(
            &signed(polar_signing::Domain::CONFIGURATION, record("u7c"), &ca),
            "does not verify",
        );
        let mut no_type = record("u7c");
        no_type.as_object_mut().unwrap().remove("type");
        refused(
            &signed(polar_signing::Domain::EVIDENCE_RECORD, no_type, &ca),
            "no type",
        );
        let mut no_subject = record("u7c");
        no_subject["subject"] = json!({});
        refused(
            &signed(polar_signing::Domain::EVIDENCE_RECORD, no_subject, &ca),
            "no subject",
        );
        for bad in ["../up", "a/b", ".hidden", "", "tab\there"] {
            refused(
                &signed(polar_signing::Domain::EVIDENCE_RECORD, record(bad), &ca),
                "cannot name a folder",
            );
        }
        let mut bad_type = record("u7c");
        bad_type["type"] = json!("../x");
        refused(
            &signed(polar_signing::Domain::EVIDENCE_RECORD, bad_type, &ca),
            "cannot name a folder",
        );
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        ca: polar_signing::testing::Authority,
        intake: Intake,
        notes: Arc<Recorder>,
        logs: ractor::ActorRef<crate::logs::LogsMessage>,
    }

    /// A seeded `polar-evidence` that the attestation agent may write and another workload may only read.
    async fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let seed = dir.path().join("seed");
        std::fs::create_dir_all(&seed).unwrap();
        std::fs::write(seed.join("README.md"), "records\n").unwrap();
        let store = RepoStore::new(dir.path().join("repos"));
        store.create(EVIDENCE_REPO).await.unwrap();
        store.seed(EVIDENCE_REPO, &seed).await.unwrap();
        let mut acl = StaticAcl::default();
        acl.repos.insert(
            EVIDENCE_REPO.to_string(),
            RepoAcl {
                readers: ["reader.polar.serviceaccount.cluster.local".to_string()].into(),
                writers: [SENDER.to_string()].into(),
            },
        );
        let ca = root("Polar test CA");
        let notes = Arc::new(Recorder::default());
        let (logs, _) = ractor::Actor::spawn(
            None,
            crate::logs::LogsActor,
            crate::logs::LogsArgs {
                root: dir.path().join("logs"),
                origin: "polar-git-server.polar.serviceaccount.cluster.local".to_string(),
                signer: std::sync::Arc::new(crate::logs::testing::KeySigner::new(
                    "polar-git-server.polar.serviceaccount.cluster.local",
                )),
            },
        )
        .await
        .unwrap();
        let intake = Intake {
            store,
            authorizer: Arc::new(acl),
            trust: Trust::from_pem(std::slice::from_ref(&ca.pem)).unwrap(),
            notifier: notes.clone(),
            policy: None,
            logs: Some(logs.clone()),
        };
        Fixture {
            _dir: dir,
            ca,
            intake,
            notes,
            logs,
        }
    }

    fn request(id: &str, record: &str) -> Vec<u8> {
        encode_add(&Envelope {
            correlation_id: id.to_string(),
            payload: AddRecord {
                record: record.to_string(),
            },
        })
    }

    /// A writer's record is committed at its place, answered on the writer's own topic with the request's correlation id,
    /// and announced as a push by the writer; sent again, it is already there, and nothing more is committed or
    /// announced.
    #[tokio::test]
    async fn a_writers_record_is_committed_answered_and_announced_once() {
        let f = fixture().await;
        let text = senders(record("u7c"), &f.ca);
        let path = format!("attestation/u7c/{}.json", sha(&text));
        let (topic, answer) = f
            .intake
            .take(Some(SENDER), &request("c1", &text), now())
            .await
            .unwrap();
        assert_eq!(topic, "polar-git-evidence-replies.attestation-agent");
        assert_eq!(answer.correlation_id, "c1");
        let RecordAdded::Committed { path: at, commit } = &answer.payload else {
            panic!("{:?}", answer.payload)
        };
        assert_eq!(at, &path);
        assert_eq!(
            f.intake
                .store
                .resolve_ref(EVIDENCE_REPO, "refs/heads/main")
                .await
                .as_ref(),
            Some(commit)
        );
        {
            let notes = f.notes.0.lock().unwrap();
            assert_eq!(notes.len(), 1);
            assert_eq!(notes[0].repo, EVIDENCE_REPO);
            assert_eq!(notes[0].refname, "refs/heads/main");
            assert_eq!(&notes[0].new, commit);
            assert_eq!(notes[0].pusher, SENDER);
        }
        // What is committed is the record, byte for byte.
        let shown = std::process::Command::new("git")
            .env("GIT_DIR", f.intake.store.path(EVIDENCE_REPO).unwrap())
            .args(["show", &format!("main:{path}")])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8(shown.stdout).unwrap(), text);

        let (_, again) = f
            .intake
            .take(Some(SENDER), &request("c2", &text), now())
            .await
            .unwrap();
        assert_eq!(again.correlation_id, "c2");
        assert_eq!(again.payload, RecordAdded::AlreadyThere { path });
        assert_eq!(f.notes.0.lock().unwrap().len(), 1);

        // docs/architecture/record-store.md, bite 3: the store's evidence log holds the record once, as the sender's,
        // admitted at the store's time.
        let logged = logged(&f).await;
        assert_eq!(logged.len(), 1);
        assert_eq!(logged[0].submitter, SENDER);
        let since = |ms: u64| std::time::UNIX_EPOCH + std::time::Duration::from_millis(ms);
        let ago = std::time::SystemTime::now()
            .duration_since(since(logged[0].admitted_at_ms))
            .unwrap();
        assert!(ago < std::time::Duration::from_secs(60), "{ago:?}");
        let entry = polar_log::entry::Entry::decode(&logged[0].entry).unwrap();
        assert_eq!(entry.kind, EVIDENCE_RECORD);
        assert!(entry.critical);
        assert_eq!(entry.event, text.as_bytes());
    }

    /// Every leaf in the store's evidence log, in order; none when nothing was appended.
    async fn logged(f: &Fixture) -> Vec<polar_log::entry::Leaf> {
        let mut leaves = Vec::new();
        loop {
            let leaf = ractor::call!(f.logs, |reply| crate::logs::LogsMessage::Leaf {
                log: EVIDENCE_LOG.to_string(),
                seq: leaves.len() as u64,
                reply,
            })
            .unwrap();
            match leaf {
                Ok(Some(leaf)) => leaves.push(leaf),
                Ok(None) => return leaves,
                // Nothing was ever appended, so there is no log.
                Err(why) if leaves.is_empty() && why.contains("no log") => return leaves,
                Err(why) => panic!("{why}"),
            }
        }
    }

    /// A sender who may not write the repository, a reader among them, is refused, as is a record that does not verify;
    /// neither is committed or announced, and each answer says why.
    #[tokio::test]
    async fn a_sender_who_may_not_write_and_a_record_that_does_not_verify_are_refused() {
        let f = fixture().await;
        let before = f
            .intake
            .store
            .resolve_ref(EVIDENCE_REPO, "refs/heads/main")
            .await;
        let text = senders(record("u7c"), &f.ca);
        for stranger in [
            "reader.polar.serviceaccount.cluster.local",
            "someone-else.polar.serviceaccount.cluster.local",
        ] {
            let (topic, answer) = f
                .intake
                .take(Some(stranger), &request("c", &text), now())
                .await
                .unwrap();
            assert!(
                topic.ends_with(stranger.split('.').next().unwrap()),
                "{topic}"
            );
            let RecordAdded::Refused { why } = answer.payload else {
                panic!("{stranger}: {:?}", answer.payload)
            };
            assert!(why.contains("may not add evidence"), "{why}");
        }
        let foreign = senders(record("u7c"), &root("Another CA"));
        let (_, answer) = f
            .intake
            .take(Some(SENDER), &request("c", &foreign), now())
            .await
            .unwrap();
        assert!(
            matches!(&answer.payload, RecordAdded::Refused { why } if why.contains("does not verify")),
            "{:?}",
            answer.payload
        );
        assert_eq!(
            f.intake
                .store
                .resolve_ref(EVIDENCE_REPO, "refs/heads/main")
                .await,
            before
        );
        assert!(f.notes.0.lock().unwrap().is_empty());
        assert!(logged(&f).await.is_empty());
    }

    /// docs/architecture/key-custody.md, "Workload signing keys", items 6 and 8: a record is taken only from the workload
    /// that signed it, under its signing certificate (never its mTLS one), and only of a type that certificate may record.
    /// Each refusal says why, and nothing is committed or announced.
    #[tokio::test]
    async fn a_record_is_taken_only_from_the_workload_that_signed_it_and_only_of_its_kinds() {
        let f = fixture().await;
        let before = f
            .intake
            .store
            .resolve_ref(EVIDENCE_REPO, "refs/heads/main")
            .await;
        let another = "kube-observer.polar.serviceaccount.cluster.local";
        for (why, text, says) in [
            (
                "another workload's record",
                from_pod(
                    record("u7c"),
                    &f.ca,
                    another,
                    vec!["c:record-evidence:attestation"],
                    document_signing(),
                ),
                "signed by",
            ),
            (
                "a person's record",
                signed(polar_signing::Domain::EVIDENCE_RECORD, record("u7c"), &f.ca),
                "signed by",
            ),
            (
                "its record under its mTLS certificate",
                from_pod(
                    record("u7c"),
                    &f.ca,
                    SENDER,
                    vec!["c:record-evidence:attestation"],
                    rcgen::ExtendedKeyUsagePurpose::ClientAuth,
                ),
                "not a signing certificate",
            ),
            (
                "a kind of record it may not sign",
                from_pod(
                    record("u7c"),
                    &f.ca,
                    SENDER,
                    vec!["c:record-evidence:projection-test"],
                    document_signing(),
                ),
                "may not sign evidence",
            ),
        ] {
            let (_, answer) = f
                .intake
                .take(Some(SENDER), &request("c", &text), now())
                .await
                .unwrap();
            assert!(
                matches!(&answer.payload, RecordAdded::Refused { why: said } if said.contains(says)),
                "{why}: {:?}",
                answer.payload
            );
        }
        assert_eq!(
            f.intake
                .store
                .resolve_ref(EVIDENCE_REPO, "refs/heads/main")
                .await,
            before
        );
        assert!(f.notes.0.lock().unwrap().is_empty());
    }

    // docs/architecture/key-custody.md, "Workload signing keys", item 7: a pushed commit's time is taken only within the
    // window of the server's clock, and a commit that says none is refused.
    #[test]
    fn a_pushed_commit_is_taken_only_when_made_about_now() {
        let now = 1_800_000_000;
        assert_eq!(pushed_time_refusal(Some(now), now), None);
        assert_eq!(
            pushed_time_refusal(Some(now - PUSHED_WITHIN_SECS), now),
            None
        );
        assert_eq!(
            pushed_time_refusal(Some(now + PUSHED_WITHIN_SECS), now),
            None
        );
        for refused in [
            Some(now - PUSHED_WITHIN_SECS - 1),
            Some(now + PUSHED_WITHIN_SECS + 1),
            Some(0),
            None,
        ] {
            assert!(
                pushed_time_refusal(refused, now).is_some_and(|why| why.contains("server's clock")),
                "{refused:?}"
            );
        }
    }

    proptest::proptest! {
        // For every commit time and clock: taken exactly when it says a time within the window of the clock.
        #[test]
        fn a_pushed_commit_s_time_is_judged_by_the_window_alone(
            committed in proptest::option::of(-4_000i64..4_000),
            now in 0i64..2_000_000_000,
        ) {
            let committed = committed.map(|offset| now + offset);
            proptest::prop_assert_eq!(
                pushed_time_refusal(committed, now).is_none(),
                committed.is_some_and(|at| (at - now).abs() <= PUSHED_WITHIN_SECS)
            );
        }
    }

    async fn policy(source: &str) -> ractor::ActorRef<polar_policy::PolicyMessage> {
        let (permissions, _) = ractor::Actor::spawn(None, polar_permissions::PermissionsActor, ())
            .await
            .unwrap();
        let (policy, _) = ractor::Actor::spawn(
            None,
            polar_policy::PolicyActor,
            polar_policy::PolicyActorArgs {
                permissions_actor: permissions,
            },
        )
        .await
        .unwrap();
        ractor::call!(policy, |reply| polar_policy::PolicyMessage::UpdatePolicy {
            policy_source: source.to_string(),
            reply,
        })
        .unwrap()
        .unwrap();
        policy
    }

    async fn take(f: &Fixture, text: String) -> RecordAdded {
        f.intake
            .take(Some(SENDER), &request("c", &text), now())
            .await
            .unwrap()
            .1
            .payload
    }

    // docs/architecture/credentials-policy.md, "Who may sign evidence": what a signer may record is policy first, both ways,
    // and the certificate's evidence names where policy is silent. A permit admits a type the workload's certificate does not
    // name; a forbid refuses one it does.
    #[tokio::test]
    async fn what_a_workload_may_record_is_policy_first_and_its_certificate_where_policy_is_silent()
    {
        let mut f = fixture().await;
        f.intake.policy = Some(
            policy(&format!(
                r#"permit(principal == Identity::"{SENDER}", action == Action::"record-evidence", resource == Evidence::"attestation");"#
            ))
            .await,
        );
        let unnamed = from_pod(
            record("u7c"),
            &f.ca,
            SENDER,
            vec!["c:record-evidence:projection-test"],
            document_signing(),
        );
        assert!(
            matches!(take(&f, unnamed).await, RecordAdded::Committed { .. }),
            "a permit admits what its certificate does not name"
        );
        f.intake.policy = Some(
            policy(&format!(
                r#"forbid(principal == Identity::"{SENDER}", action == Action::"record-evidence", resource);"#
            ))
            .await,
        );
        let named = from_pod(
            record("u7d"),
            &f.ca,
            SENDER,
            vec!["c:record-evidence:attestation"],
            document_signing(),
        );
        assert!(
            matches!(take(&f, named).await, RecordAdded::Refused { why } if why.contains("policy forbids")),
            "a forbid refuses what its certificate names"
        );
        f.intake.policy =
            Some(policy(r#"permit(principal, action == Action::"retrieve", resource);"#).await);
        let silent = from_pod(
            record("u7e"),
            &f.ca,
            SENDER,
            vec!["c:record-evidence:attestation"],
            document_signing(),
        );
        assert!(
            matches!(take(&f, silent).await, RecordAdded::Committed { .. }),
            "where policy is silent, the certificate decides"
        );
    }

    /// With nobody to answer (no identity the broker stamped, or one that names no workload) or no request in the bytes,
    /// nothing is answered and nothing is added.
    #[tokio::test]
    async fn with_nobody_to_answer_or_no_request_nothing_is_answered_or_added() {
        let f = fixture().await;
        let text = senders(record("u7c"), &f.ca);
        assert!(
            f.intake
                .take(None, &request("c", &text), now())
                .await
                .is_none()
        );
        assert!(
            f.intake
                .take(Some("alice"), &request("c", &text), now())
                .await
                .is_none()
        );
        assert!(
            f.intake
                .take(Some(SENDER), b"not a request", now())
                .await
                .is_none()
        );
        assert!(f.notes.0.lock().unwrap().is_empty());
        let log = std::process::Command::new("git")
            .env("GIT_DIR", f.intake.store.path(EVIDENCE_REPO).unwrap())
            .args(["rev-list", "--count", "main"])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8(log.stdout).unwrap().trim(), "1");
    }

    /// A repository that cannot be written now is the server's trouble, not the record's: the answer is not now, for the
    /// sender to send it again.
    #[tokio::test]
    async fn a_repository_that_cannot_be_written_now_is_answered_not_now() {
        let f = fixture().await;
        let text = senders(record("u7c"), &f.ca);
        std::fs::remove_dir_all(f.intake.store.path(EVIDENCE_REPO).unwrap()).unwrap();
        let (_, answer) = f
            .intake
            .take(Some(SENDER), &request("c", &text), now())
            .await
            .unwrap();
        assert!(
            matches!(answer.payload, RecordAdded::NotNow { .. }),
            "{:?}",
            answer.payload
        );
        assert!(decode_added(&polar_git_server_common::encode_added(&answer)).is_ok());
    }

    /// What a push took while the server kept no log (main's server over the same volume) is brought into the evidence
    /// log at the next start, as the store's: the record the intake took is not appended again, the README and a text
    /// file are no records, and a second start appends nothing.
    #[tokio::test]
    async fn a_start_brings_the_evidence_log_to_what_polar_evidence_holds() {
        let f = fixture().await;
        let origin = "polar-git-server.polar.serviceaccount.cluster.local";
        let taken = senders(record("u7c"), &f.ca);
        f.intake
            .take(Some(SENDER), &request("c1", &taken), now())
            .await
            .unwrap();
        let pushed = senders(record("u7d"), &f.ca);
        for (path, text) in [
            (
                format!("attestation/u7d/{}.json", sha(&pushed)),
                pushed.as_str(),
            ),
            ("notes/today.txt".to_string(), "not a record"),
        ] {
            f.intake
                .store
                .add_file(
                    EVIDENCE_REPO,
                    &path,
                    text.as_bytes(),
                    &SERVER,
                    "a push the log missed",
                )
                .await
                .unwrap();
        }
        let done = catch_up(&f.intake.store, &f.logs, origin).await.unwrap();
        assert_eq!(done.appended, vec![1], "{done:?}");
        assert!(done.left_out.is_empty(), "{done:?}");
        let leaf = ractor::call!(f.logs, |reply| crate::logs::LogsMessage::Leaf {
            log: EVIDENCE_LOG.to_string(),
            seq: 1,
            reply
        })
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(leaf.submitter, origin);
        assert_eq!(
            polar_log::entry::Entry::decode(&leaf.entry).unwrap().event,
            pushed.as_bytes()
        );
        assert_eq!(
            catch_up(&f.intake.store, &f.logs, origin).await.unwrap(),
            Default::default()
        );
    }

    #[tokio::test]
    async fn a_store_without_polar_evidence_appends_nothing() {
        let f = fixture().await;
        let dir = tempfile::tempdir().unwrap();
        let none = RepoStore::new(dir.path().join("repos"));
        assert_eq!(
            catch_up(&none, &f.logs, "origin").await.unwrap(),
            Default::default()
        );
    }

    #[test]
    fn a_record_is_a_json_file_outside_a_hidden_folder() {
        assert!(is_record_path("attestation/u7c/ab.json"));
        assert!(is_record_path("a.json"));
        assert!(!is_record_path("README.md"));
        assert!(!is_record_path(".hidden/a.json"));
        assert!(!is_record_path("a/.b/c.json"));
        assert!(!is_record_path("a/.c.json"));
    }
}
