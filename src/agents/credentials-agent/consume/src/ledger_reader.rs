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
//! every event, as it was, when it was. It reads a copy of each file, so neither is locked or changed.

use credentials_agent_common::events::CredentialsEvent;
use credentials_agent_common::ledger::{Read, read};
use polar::event_log::EventLog;
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

/// Reads the ledger at `ledger`, and checks it against the JSON ledger at `against` if one is given.
pub fn report(ledger: &Path, against: Option<&Path>) -> Result<Report, String> {
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
    Ok(report)
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
        let report = report(&path, Some(&json)).unwrap();
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
        let report = report(&path, Some(&other_json)).unwrap();
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
