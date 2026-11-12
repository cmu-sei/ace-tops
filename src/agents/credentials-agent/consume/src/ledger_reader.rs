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

//! What `polar-ledger` says of a ledger (docs/architecture/record-store.md, "The credentials ledger on the log", 9): its
//! entries, each with its kind, version, critical mark, writer and time and its event in CBOR's diagnostic notation;
//! whether its frames and tree hold; and, given the JSON ledger it was copied from, whether the copy is that ledger's
//! every event, as it was, when it was. Given the CA, its checkpoint (docs/architecture/record-store.md, "L2,
//! checkpoints"): signed by the key its certificate certifies as the ledger's keeper's checkpoint key, over the ledger's
//! own tree at its size, and, given an older checkpoint, consistent with it. It reads a copy of each file, so none is
//! locked or changed.

use credentials_agent_common::events::CredentialsEvent;
use credentials_agent_common::ledger::{Read, read};
use polar::event_log::EventLog;
use polar_log::checkpoint::{Checkpoint, NoteVerifier};
use polar_log::entry::{CONTINUATION, Continuation, Entry};
use polar_log::file::{FileLog, Replayed};
use std::path::Path;

/// What reading a ledger found: a line for each entry, and what does not hold.
#[derive(Debug, Default)]
pub struct Report {
    pub lines: Vec<String>,
    pub problems: Vec<String>,
}

/// `path` copied into `dir`, so opening it neither locks nor changes it. The copy is this reader's to open for
/// appending, as the logs open: a JSON ledger once copied is kept read-only, and `fs::copy` would keep its mode.
fn copied(path: &Path, dir: &Path) -> Result<std::path::PathBuf, String> {
    let copy = dir.join(path.file_name().unwrap_or_default());
    std::fs::copy(path, &copy).map_err(|e| format!("{}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("{}: {e}", copy.display()))?;
    }
    Ok(copy)
}

/// What a ledger's checkpoint is checked with.
#[derive(Debug, Clone)]
pub struct CheckpointCheck {
    /// The checkpoint, by default the one kept beside the ledger.
    pub checkpoint: std::path::PathBuf,
    /// The ledger key's certificate, by default the one kept beside the key.
    pub certificate: std::path::PathBuf,
    /// The CA the certificate chains to.
    pub ca: std::path::PathBuf,
    /// When the certificate is checked as of (Unix seconds): a checkpoint carries no time, and the certificates last
    /// hours.
    pub at: i64,
    /// An older checkpoint of the same ledger, which the checkpoint must be consistent with.
    pub since: Option<std::path::PathBuf>,
}

/// Reads the ledger at `ledger`, checks it against the JSON ledger at `against` if one is given, and its checkpoint
/// with `checkpoint` if that is given.
pub fn report(
    ledger: &Path,
    against: Option<&Path>,
    checkpoint: Option<&CheckpointCheck>,
) -> Result<Report, String> {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let opened = FileLog::open(&copied(ledger, dir.path())?).map_err(|e| e.to_string())?;
    let mut report = Report::default();
    if let Some(bytes) = opened.torn {
        report.problems.push(format!(
            "its last entry is cut short ({bytes} bytes): a write that did not finish"
        ));
    }
    let mut copied_from = None;
    let mut entries: Vec<(u64, u64, Entry)> = Vec::new();
    for replayed in opened.replayed {
        match replayed {
            Replayed::Malformed { seq, why } => report
                .problems
                .push(format!("entry {seq} is not an entry: {why}")),
            Replayed::Entry { seq, leaf, entry } => {
                let shown = if entry.kind == CONTINUATION {
                    match Continuation::decode(&entry.event) {
                        Ok(c) => {
                            let line = format!(
                                "carries on a {} ledger of {} entries, its last {} {}",
                                c.old_kind,
                                c.count,
                                c.alg,
                                hex::encode(&c.digest)
                            );
                            copied_from = Some(c);
                            line
                        }
                        Err(e) => {
                            report
                                .problems
                                .push(format!("entry {seq} does not say what it carries on: {e}"));
                            String::new()
                        }
                    }
                } else {
                    match read(&entry) {
                        Read::Decoded(_) => minicbor::display(&entry.event).to_string(),
                        Read::Unknown => format!(
                            "(a kind or version this reader does not know) {}",
                            minicbor::display(&entry.event)
                        ),
                        Read::Malformed(why) => {
                            report.problems.push(format!("entry {seq}: {why}"));
                            minicbor::display(&entry.event).to_string()
                        }
                    }
                };
                report.lines.push(format!(
                    "{seq} {} {} v{} {} by {} ({}): {shown}",
                    leaf.admitted_at_ms,
                    entry.kind,
                    entry.version,
                    if entry.critical {
                        "critical"
                    } else {
                        "not critical"
                    },
                    leaf.submitter,
                    entry.writer,
                ));
                entries.push((seq, leaf.admitted_at_ms, entry));
            }
        }
    }
    report.lines.push(format!(
        "{} entries; tree root {}",
        opened.log.size(),
        hex::encode(opened.log.root())
    ));
    if let Some(json) = against {
        check_copy(
            json,
            dir.path(),
            copied_from.as_ref(),
            &entries,
            &mut report,
        )?;
    }
    if let Some(check) = checkpoint {
        check_checkpoint(check, opened.log.hashes(), &mut report);
    }
    Ok(report)
}

/// The checkpoint `note` states, opened with the key `certificate` certifies (PEM) as of `at`, under `ca`: the key of
/// the identity the checkpoint's origin names, `<identity>/ledger`.
fn opened_checkpoint(
    note: &str,
    certificate: &str,
    ca: &polar_signing::Trust,
    at: i64,
) -> Result<(Checkpoint, String), String> {
    // Which identity the note says it is of, read before it is believed: the certificate must be of that identity.
    let text = note
        .split_once("\n\n")
        .map(|(text, _)| format!("{text}\n"))
        .ok_or("it is not a signed note")?;
    let stated = Checkpoint::parse(&text).map_err(|e| e.to_string())?;
    let identity = stated
        .origin
        .strip_suffix("/ledger")
        .ok_or_else(|| format!("its origin `{}` is not a ledger's", stated.origin))?;
    let key = polar_signing::verify_checkpoint_certificate(certificate, ca, at, identity)
        .map_err(|e| format!("the ledger key's certificate is not believed: {e}"))?;
    let key =
        <p256::ecdsa::VerifyingKey as p256::pkcs8::DecodePublicKey>::from_public_key_pem(&key)
            .map_err(|e| format!("the ledger key's certificate holds no P-256 key: {e}"))?;
    let name = crate::ledger_checkpoint::key_name(identity);
    let verifier = NoteVerifier::parse(&polar_log::checkpoint::verifier_key(&name, &key))
        .map_err(|e| e.to_string())?;
    let (text, _) = polar_log::checkpoint::open(note, &[verifier])
        .map_err(|e| format!("it is not signed by the key the certificate certifies: {e}"))?;
    Ok((Checkpoint::parse(&text).map_err(|e| e.to_string())?, name))
}

/// Whether the checkpoint `check` names is signed by the ledger key its certificate certifies, over the tree of the
/// ledger whose leaf hashes are `hashes`, and consistent with the older one it names.
fn check_checkpoint(
    check: &CheckpointCheck,
    hashes: &[polar_log::merkle::Hash],
    report: &mut Report,
) {
    let read =
        |path: &Path| std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()));
    let opened = (|| {
        let ca = polar_signing::Trust::from_pem(&[read(&check.ca)?])
            .map_err(|e| format!("the CA: {e}"))?;
        let certificate = read(&check.certificate)?;
        let newer = opened_checkpoint(&read(&check.checkpoint)?, &certificate, &ca, check.at)?;
        let older = match &check.since {
            Some(since) => Some(
                opened_checkpoint(&read(since)?, &certificate, &ca, check.at)
                    .map_err(|e| format!("the older checkpoint: {e}"))?
                    .0,
            ),
            None => None,
        };
        Ok::<_, String>((newer, older))
    })();
    let ((checkpoint, name), older) = match opened {
        Ok(opened) => opened,
        Err(e) => {
            report.problems.push(format!("its checkpoint: {e}"));
            return;
        }
    };
    if checkpoint.size > hashes.len() as u64 {
        report.problems.push(format!(
            "its checkpoint was signed at {} entries; it holds {}",
            checkpoint.size,
            hashes.len()
        ));
        return;
    }
    if polar_log::merkle::root(&hashes[..checkpoint.size as usize]) != checkpoint.root {
        report.problems.push(format!(
            "its first {} entries are not those its checkpoint was signed over",
            checkpoint.size
        ));
        return;
    }
    report.lines.push(format!(
        "its checkpoint at {} entries, root {}, is signed by {name}, certified for {}'s checkpoints alone as of {}",
        checkpoint.size,
        hex::encode(checkpoint.root),
        checkpoint.origin.trim_end_matches("/ledger"),
        check.at
    ));
    if let Some(older) = older {
        // An empty tree is the start of every tree; RFC 9162's proofs begin at one leaf.
        let consistent = older.origin == checkpoint.origin
            && older.size <= checkpoint.size
            && (older.size == 0
                || polar_log::merkle::consistency_proof(
                    older.size as usize,
                    &hashes[..checkpoint.size as usize],
                )
                .is_some_and(|proof| {
                    polar_log::merkle::verify_consistency(
                        older.size,
                        checkpoint.size,
                        &older.root,
                        &checkpoint.root,
                        &proof,
                    )
                }));
        if consistent {
            report.lines.push(format!(
                "it is consistent with the older checkpoint at {} entries",
                older.size
            ));
        } else {
            report.problems.push(format!(
                "it is not consistent with the older checkpoint at {} entries: the ledger was rewritten between them",
                older.size
            ));
        }
    }
}

/// Whether the ledger's entries after its first are the JSON ledger's, every one, as it was and when it was, and its
/// first names that ledger's last hash and count.
fn check_copy(
    json: &Path,
    dir: &Path,
    continuation: Option<&Continuation>,
    entries: &[(u64, u64, Entry)],
    report: &mut Report,
) -> Result<(), String> {
    let (old, _) =
        EventLog::<CredentialsEvent>::open(copied(json, dir)?).map_err(|e| e.to_string())?;
    let old_entries = old.entries().map_err(|e| e.to_string())?;
    match continuation {
        None => report
            .problems
            .push("its first entry does not carry on a ledger".to_string()),
        Some(c) => {
            if c.count != old_entries.len() as u64 {
                report.problems.push(format!(
                    "it says the JSON ledger held {} entries; it holds {}",
                    c.count,
                    old_entries.len()
                ));
            }
            if hex::encode(&c.digest) != old.current_hash() {
                report.problems.push(format!(
                    "it names the JSON ledger's last hash as {}; it is {}",
                    hex::encode(&c.digest),
                    old.current_hash()
                ));
            }
        }
    }
    let copied: Vec<&(u64, u64, Entry)> = entries.iter().filter(|(seq, _, _)| *seq >= 1).collect();
    for (n, old_entry) in old_entries.iter().enumerate() {
        let Some((seq, admitted, entry)) = copied.get(n) else {
            report
                .problems
                .push(format!("the JSON ledger's entry {n} is not in the ledger"));
            break;
        };
        if read(entry) != Read::Decoded(old_entry.event.clone()) {
            report
                .problems
                .push(format!("entry {seq} is not the JSON ledger's entry {n}"));
        }
        if *admitted != old_entry.timestamp.timestamp_millis() as u64 {
            report.problems.push(format!(
                "entry {seq} was not admitted when the JSON ledger's entry {n} was"
            ));
        }
    }
    if report.problems.is_empty() {
        report.lines.push(format!(
            "the copy holds the JSON ledger's {} entries, as they were and when they were",
            old_entries.len()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use credentials_agent_common::events::GrantReason;

    fn grant(n: i64) -> CredentialsEvent {
        CredentialsEvent::Grant {
            target_identity: format!("agent-{n}"),
            permissions: vec![],
            granted_by: "admin".into(),
            timestamp: n,
            reason: GrantReason::ServiceOnboarding,
        }
    }

    async fn copied_ledger(
        dir: &Path,
        events: &[CredentialsEvent],
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let (path, json) = (dir.join("ledger.log"), dir.join("events.jsonl"));
        {
            let (mut old, _) = EventLog::<CredentialsEvent>::open(&json).unwrap();
            for e in events {
                old.append(e).unwrap();
            }
        }
        let opening = crate::ledger::open_ledger(
            path.to_str().unwrap(),
            Some(json.to_str().unwrap()),
            &crate::ledger::tests::key_beside(&path),
            std::time::Duration::from_secs(1),
            std::time::Duration::from_millis(10),
        )
        .await
        .unwrap();
        assert!(matches!(opening, crate::ledger::Opening::Ready { .. }));
        (path, json)
    }

    #[tokio::test]
    async fn a_copy_is_found_to_be_its_json_ledger_and_each_entry_is_shown() {
        let dir = tempfile::tempdir().unwrap();
        let (path, json) = copied_ledger(dir.path(), &[grant(1), grant(2)]).await;
        let before = std::fs::read(&path).unwrap();
        let report = report(&path, Some(&json), None).unwrap();
        assert!(report.problems.is_empty(), "{:?}", report.problems);
        assert!(
            report.lines[0].contains("carries on a jsonl ledger of 2 entries"),
            "{}",
            report.lines[0]
        );
        assert!(
            report.lines[1].contains("credentials.grant v1 critical by credentials-agent"),
            "{}",
            report.lines[1]
        );
        assert!(
            report.lines[1].contains("\"agent-1\""),
            "{}",
            report.lines[1]
        );
        assert!(
            report
                .lines
                .iter()
                .any(|l| l.contains("as they were and when they were"))
        );
        // Reading it changed nothing.
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    const IDENTITY: &str = "credentials-agent.polar.serviceaccount.cluster.local";

    /// A ledger of `n` grants in `dir`, its checkpoint signed and kept as the agent keeps it, the CA's PEM written beside
    /// it, and the ledger key's checkpoint certificate kept beside the key: the check of them, as of now.
    fn checkpointed(dir: &Path, n: i64) -> CheckpointCheck {
        let path = dir.join("ledger.log");
        let mut log = FileLog::open(&path).unwrap().log;
        for g in 1..=n {
            log.append(&crate::ledger::leaf_of(&grant(g), "writer", g as u64))
                .unwrap();
        }
        let key = crate::ledger::tests::key_beside(&path);
        let crate::ledger_checkpoint::Kept::Ready(mut checkpoints) =
            crate::ledger_checkpoint::Checkpoints::open(&path, &log, &key).unwrap()
        else {
            panic!("refused")
        };
        checkpoints.sign(&log).unwrap();
        let ca = crate::workload_issuance::tests::the_ca();
        std::fs::write(dir.join("ca.pem"), &ca.pem).unwrap();
        certify(dir, polar_signing::testing::checkpoint_spec(IDENTITY));
        CheckpointCheck {
            checkpoint: crate::ledger_checkpoint::kept_path(&path),
            certificate: dir.join("ledger-key.crt"),
            ca: dir.join("ca.pem"),
            at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            since: None,
        }
    }

    /// The ledger key in `dir` certified as `spec` says, kept beside it.
    fn certify(dir: &Path, spec: polar_signing::testing::EscrowSpec) {
        use p256::pkcs8::EncodePublicKey;
        let key =
            crate::authority_key::load_or_generate(dir.join("ledger-key.pem").to_str().unwrap())
                .unwrap();
        let public = key
            .verifying_key()
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .unwrap();
        let cert = polar_signing::testing::escrow_certificate_for(
            crate::workload_issuance::tests::the_ca(),
            spec,
            &public,
        );
        std::fs::write(dir.join("ledger-key.crt"), cert).unwrap();
    }

    fn said(report: &Report) -> String {
        report.problems.join("; ")
    }

    #[test]
    fn a_checkpoint_signed_by_the_certified_ledger_key_over_the_ledger_is_said_to_hold() {
        let dir = tempfile::tempdir().unwrap();
        let check = checkpointed(dir.path(), 3);
        let report = report(&dir.path().join("ledger.log"), None, Some(&check)).unwrap();
        assert!(report.problems.is_empty(), "{}", said(&report));
        assert!(
            report
                .lines
                .iter()
                .any(|l| l.contains("its checkpoint at 3 entries")
                    && l.contains(&format!("signed by {IDENTITY}/checkpoint"))),
            "{:?}",
            report.lines
        );
    }

    #[test]
    fn a_rewritten_ledger_another_key_or_a_certificate_of_another_type_does_not_hold() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let check = checkpointed(dir.path(), 3);

        // The ledger rewritten under its checkpoint.
        let checkpoint = std::fs::read(&check.checkpoint).unwrap();
        std::fs::remove_file(&path).unwrap();
        let mut log = FileLog::open(&path).unwrap().log;
        for g in [1, 2, 9] {
            log.append(&crate::ledger::leaf_of(&grant(g), "writer", g as u64))
                .unwrap();
        }
        drop(log);
        std::fs::write(&check.checkpoint, &checkpoint).unwrap();
        let report_of = |check: &CheckpointCheck| report(&path, None, Some(check)).unwrap();
        assert!(
            said(&report_of(&check)).contains("first 3 entries are not those"),
            "{}",
            said(&report_of(&check))
        );

        // Another key's certificate.
        let elsewhere = tempfile::tempdir().unwrap();
        certify(
            elsewhere.path(),
            polar_signing::testing::checkpoint_spec(IDENTITY),
        );
        let other_key = CheckpointCheck {
            certificate: elsewhere.path().join("ledger-key.crt"),
            ..check.clone()
        };
        assert!(
            said(&report_of(&other_key))
                .contains("not signed by the key the certificate certifies"),
            "{}",
            said(&report_of(&other_key))
        );

        // The ledger key's own, as a signing certificate: the authority key's type.
        certify(dir.path(), polar_signing::testing::authority_spec(IDENTITY));
        assert!(
            said(&report_of(&check)).contains("not believed"),
            "{}",
            said(&report_of(&check))
        );
    }

    #[test]
    fn an_older_checkpoint_of_the_same_ledger_is_consistent_and_one_of_another_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let check = checkpointed(dir.path(), 2);
        let older = dir.path().join("older.checkpoint");
        std::fs::copy(&check.checkpoint, &older).unwrap();
        {
            let mut log = FileLog::open(&path).unwrap().log;
            for g in 3..=5 {
                log.append(&crate::ledger::leaf_of(&grant(g), "writer", g as u64))
                    .unwrap();
            }
            let crate::ledger_checkpoint::Kept::Ready(mut checkpoints) =
                crate::ledger_checkpoint::Checkpoints::open(
                    &path,
                    &log,
                    &crate::ledger::tests::key_beside(&path),
                )
                .unwrap()
            else {
                panic!("refused")
            };
            checkpoints.sign(&log).unwrap();
        }
        let since = CheckpointCheck {
            since: Some(older.clone()),
            ..check
        };
        let report_now = report(&path, None, Some(&since)).unwrap();
        assert!(report_now.problems.is_empty(), "{}", said(&report_now));
        assert!(
            report_now
                .lines
                .iter()
                .any(|l| l.contains("consistent with the older checkpoint at 2 entries"))
        );

        // An older checkpoint the same key signed over another ledger's first two entries.
        let other = tempfile::tempdir().unwrap();
        let other_path = other.path().join("ledger.log");
        std::fs::copy(
            dir.path().join("ledger-key.pem"),
            other.path().join("ledger-key.pem"),
        )
        .unwrap();
        let mut log = FileLog::open(&other_path).unwrap().log;
        for g in [1, 7] {
            log.append(&crate::ledger::leaf_of(&grant(g), "writer", g as u64))
                .unwrap();
        }
        let crate::ledger_checkpoint::Kept::Ready(mut checkpoints) =
            crate::ledger_checkpoint::Checkpoints::open(
                &other_path,
                &log,
                &crate::ledger::tests::key_beside(&other_path),
            )
            .unwrap()
        else {
            panic!("refused")
        };
        checkpoints.sign(&log).unwrap();
        let forked = CheckpointCheck {
            since: Some(crate::ledger_checkpoint::kept_path(&other_path)),
            ..since
        };
        assert!(said(&report(&path, None, Some(&forked)).unwrap()).contains("not consistent"),);
    }

    #[tokio::test]
    async fn a_copy_that_is_not_its_json_ledger_is_said_to_be_so() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = copied_ledger(dir.path(), &[grant(1), grant(2)]).await;
        // Another JSON ledger, of other events.
        let other = tempfile::tempdir().unwrap();
        let other_json = other.path().join("events.jsonl");
        {
            let (mut old, _) = EventLog::<CredentialsEvent>::open(&other_json).unwrap();
            old.append(&grant(1)).unwrap();
            old.append(&grant(3)).unwrap();
            old.append(&grant(4)).unwrap();
        }
        let report = report(&path, Some(&other_json), None).unwrap();
        let said = report.problems.join("; ");
        assert!(said.contains("held 2 entries; it holds 3"), "{said}");
        assert!(said.contains("last hash"), "{said}");
        assert!(
            said.contains("entry 2 is not the JSON ledger's entry 1"),
            "{said}"
        );
        assert!(said.contains("entry 2 is not in the ledger"), "{said}");
    }
}
