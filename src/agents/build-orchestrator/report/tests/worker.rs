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

//! The report reader's answer in a real worker (polar_agent_builder::worker): forked from a process of one thread, locked in
//! seccomp's strict mode, asked line after line, its answers read back on the agent's side. A binary with its own main, since
//! libtest's threads would stop the fork.

use orchestrator_report::*;
use polar_agent_builder::worker::{Work, fork};

/// The reader as a worker's work: the tape and the bounds, made before the lockdown.
struct Reader {
    bounds: Bounds,
    tape: Tape,
}

impl Work for Reader {
    fn max_request(&self) -> usize {
        self.bounds.line
    }
    fn max_answer(&self) -> usize {
        answer_len(&self.bounds)
    }
    fn answer(&mut self, request: &[u8], out: &mut [u8]) -> usize {
        answer(request, &self.bounds, &mut self.tape, out)
    }
}

fn direct(line: &[u8], bounds: &Bounds) -> Result<Report, Refusal> {
    gate(line, bounds)?;
    let mut tape = Tape::new(bounds);
    parse(line, bounds, &mut tape)?;
    Report::read(line, &tape)
}

fn main() {
    let bounds = Bounds {
        line: 64 * 1024,
        tokens: 4096,
        ..Bounds::default()
    };
    let mut worker = fork(move || Reader {
        bounds,
        tape: Tape::new(&bounds),
    })
    .expect("a worker");
    let seeds = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds");
    let mut lines: Vec<Vec<u8>> = std::fs::read_dir(&seeds)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    lines.extend([
        br#"{"type": "execution_started", "build_id": "b"}"#.to_vec(),
        b"{\"a\": [1, 2,".to_vec(),
        vec![0xff, 0xfe, b'{'],
        br#"{"type": "stage_started", "stage_name": "\ud800", "stage_id": "s", "at": "t"}"#
            .to_vec(),
        b"[[[[[[[[[[[[[[1]]]]]]]]]]]]]]".to_vec(),
    ]);
    for line in &lines {
        let answered = worker
            .ask(line)
            .expect("the worker answers every line, a report or a refusal");
        assert_eq!(
            Report::read_answer(line, &answered, &bounds),
            direct(line, &bounds),
            "{}",
            String::from_utf8_lossy(line)
        );
    }
    println!(
        "  ok    {} lines, each read in a locked-down worker as reading it directly reads it",
        lines.len()
    );
    // The worker is still there: nothing a line held made it ask the kernel for anything.
    assert!(worker.ask(b"{}").is_ok());
    println!("  ok    the worker is alive after them all");
    println!("all 2 passed");
}
