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
//! on the log", 9).
//!
//!   polar-ledger <ledger.log> [--against <events.jsonl>]
//!
//! It prints every entry and whether the ledger holds together, and, with `--against`, whether it is a whole copy of
//! that JSON ledger. It reads copies, so the files are neither locked nor changed. It exits non-zero when something
//! does not hold.

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (ledger, against) = match args.as_slice() {
        [ledger] => (ledger, None),
        [ledger, flag, json] if flag == "--against" => (ledger, Some(json)),
        _ => {
            eprintln!("usage: polar-ledger <ledger.log> [--against <events.jsonl>]");
            return std::process::ExitCode::from(2);
        }
    };
    match credentials_agent_consumer::ledger_reader::report(
        std::path::Path::new(ledger),
        against.map(std::path::Path::new),
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
