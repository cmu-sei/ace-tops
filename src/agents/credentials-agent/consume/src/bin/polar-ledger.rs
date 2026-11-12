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

//! polar-ledger: reads a credentials ledger for a person (docs/architecture/record-store.md, "The credentials ledger
//! on the log", 9, and "L2, checkpoints").
//!
//!   polar-ledger <ledger.log> [--against <events.jsonl>]
//!                [--ca <ca.pem> [--at <unix seconds>] [--since <older checkpoint>]
//!                 [--checkpoint <file>] [--certificate <file>]]
//!
//! It prints every entry and whether the ledger holds together, and, with `--against`, whether it is a whole copy of
//! that JSON ledger. With `--ca`, it checks the ledger's checkpoint (`ledger.checkpoint` beside it, unless
//! `--checkpoint` says otherwise): signed by the key the ledger key's certificate (`ledger-key.crt` beside it, unless
//! `--certificate` says otherwise) certifies under that CA as the keeper's checkpoint key, as of now or `--at`, and over
//! the ledger's own tree; with `--since`, consistent with an older checkpoint. It reads copies, so the files are neither
//! locked nor changed. It exits non-zero when something does not hold.

// Every Polar binary allocates with Scudo (docs/architecture/broker-baseline.md, "Decided").
#[global_allocator]
static GLOBAL: polar_scudo::Scudo = polar_scudo::Scudo;

const USAGE: &str = "usage: polar-ledger <ledger.log> [--against <events.jsonl>] [--ca <ca.pem> [--at <unix seconds>] \
                     [--since <older checkpoint>] [--checkpoint <file>] [--certificate <file>]]";

fn main() -> std::process::ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(ledger) = args.next() else {
        eprintln!("{USAGE}");
        return std::process::ExitCode::from(2);
    };
    let ledger = std::path::PathBuf::from(ledger);
    let mut flags = std::collections::BTreeMap::new();
    while let Some(flag) = args.next() {
        let known = [
            "--against",
            "--ca",
            "--at",
            "--since",
            "--checkpoint",
            "--certificate",
        ];
        match args.next() {
            Some(value) if known.contains(&flag.as_str()) && !flags.contains_key(&flag) => {
                flags.insert(flag, value);
            }
            _ => {
                eprintln!("{USAGE}");
                return std::process::ExitCode::from(2);
            }
        }
    }
    let at = match flags.get("--at").map(|at| at.parse::<i64>()) {
        None => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        Some(Ok(at)) => at,
        Some(Err(_)) => {
            eprintln!("polar-ledger: --at is Unix seconds");
            return std::process::ExitCode::from(2);
        }
    };
    if !flags.contains_key("--ca") && flags.keys().any(|f| f != "--against") {
        eprintln!("polar-ledger: --at, --since, --checkpoint and --certificate go with --ca");
        return std::process::ExitCode::from(2);
    }
    let check =
        flags.get("--ca").map(
            |ca| credentials_agent_consumer::ledger_reader::CheckpointCheck {
                checkpoint: flags
                    .get("--checkpoint")
                    .map(Into::into)
                    .unwrap_or_else(|| {
                        credentials_agent_consumer::ledger_checkpoint::kept_path(&ledger)
                    }),
                certificate: flags
                    .get("--certificate")
                    .map(Into::into)
                    .unwrap_or_else(|| ledger.with_file_name("ledger-key.crt")),
                ca: ca.into(),
                at,
                since: flags.get("--since").map(Into::into),
            },
        );
    match credentials_agent_consumer::ledger_reader::report(
        &ledger,
        flags.get("--against").map(std::path::Path::new),
        check.as_ref(),
    ) {
        Ok(report) => {
            for line in &report.lines {
                println!("{line}");
            }
            for problem in &report.problems {
                eprintln!("does not hold: {problem}");
            }
            if report.problems.is_empty() {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("polar-ledger: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
