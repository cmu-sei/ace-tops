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

//! The report reader as the agent's worker (docs/architecture/build-orchestrator.md, "How a report is read"): forked by the
//! builder before the runtime, locked in seccomp's strict mode, with its tape and buffers made at the bounds signed at
//! start. It runs the gate, the parser and the grammar's check over a line and answers with the tape
//! (`orchestrator_report::answer`); the agent reads the answer back with `Report::read_answer`, at the same bounds.
//!
//! A request carries the bounds the line is to be read at, ahead of the line ([`request`]): the bounds signed now, which
//! a signed update may have narrowed since the fork. The worker reads at the narrower of those and its own
//! (`settings::narrowed`), so an update narrows the reader while the agent runs, and nothing a request says widens it
//! past what it was forked with: the tape's limit only comes down, within what was allocated.

use crate::settings::{self, narrowed};
use orchestrator_report::{Bounds, Tape, answer, answer_len};
use polar_agent_builder::worker::{Work, Worker, WorkerDecl, WorkerError, WorkerHandle, fork};
use std::time::Duration;

/// What the agent asks its reader by.
pub const READER: &str = "report-reader";

/// How long the reader has for one line. A line at its default bound (16 MiB) is read in well under a second in a
/// release build; a reader that takes this long is stuck, and its death is the evidence.
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);

pub const DECL: WorkerDecl = WorkerDecl {
    name: READER,
    fork: fork_reader,
    timeout: READ_TIMEOUT,
};

/// The bounds ahead of a line in a request: five little-endian `u64`s, in the order `Bounds` declares them.
pub const BOUNDS_LEN: usize = 40;

/// What the worker is asked: `line` to be read at `bounds`.
pub fn request(bounds: &Bounds, line: &[u8]) -> Vec<u8> {
    let mut request = Vec::with_capacity(BOUNDS_LEN + line.len());
    for bound in [
        bounds.line,
        bounds.string,
        bounds.depth,
        bounds.tokens,
        bounds.items,
    ] {
        request.extend_from_slice(&(bound as u64).to_le_bytes());
    }
    request.extend_from_slice(line);
    request
}

/// The bounds a request asks for and its line; a request too short for its bounds asks for none, and so is refused.
fn asked(request: &[u8]) -> (Bounds, &[u8]) {
    let Some((head, line)) = request.split_first_chunk::<BOUNDS_LEN>() else {
        let none = Bounds {
            line: 0,
            string: 0,
            depth: 0,
            tokens: 0,
            items: 0,
        };
        return (none, &[]);
    };
    let word = |i: usize| {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&head[i * 8..i * 8 + 8]);
        usize::try_from(u64::from_le_bytes(bytes)).unwrap_or(usize::MAX)
    };
    let bounds = Bounds {
        line: word(0),
        string: word(1),
        depth: word(2),
        tokens: word(3),
        items: word(4),
    };
    (bounds, line)
}

/// The reader's work: the bounds it was forked with and the tape, made at them before the lockdown.
pub struct Reader {
    forked: Bounds,
    tape: Tape,
}

impl Reader {
    pub fn new(forked: Bounds) -> Self {
        Self {
            tape: Tape::new(&forked),
            forked,
        }
    }
}

impl Work for Reader {
    fn max_request(&self) -> usize {
        BOUNDS_LEN.saturating_add(self.forked.line)
    }
    fn max_answer(&self) -> usize {
        answer_len(&self.forked)
    }
    fn answer(&mut self, request: &[u8], out: &mut [u8]) -> usize {
        let (asked, line) = asked(request);
        let bounds = narrowed(&self.forked, &asked);
        // No higher than the capacity allocated at the fork, so parsing never grows the tape.
        self.tape.limit = bounds.tokens;
        answer(line, &bounds, &mut self.tape, out)
    }
}

/// Forks the reader at the bounds in the configuration it was started with: judged already, so they read.
pub fn fork_reader(config: &polar_env::Config) -> Result<Worker, WorkerError> {
    let bounds = settings::reader_bounds(config)
        .map_err(|e| WorkerError::System(format!("its bounds do not read: {e}")))?;
    fork(move || Reader::new(bounds))
}

/// How a build's actor asks the reader: the worker, or a test's stand-in.
#[ractor::async_trait]
pub trait Read: Send + Sync {
    /// The worker's answer to `request` ([`request`]). An error other than too long a request is the worker's death, and
    /// ends the agent.
    async fn read(&self, request: Vec<u8>) -> Result<Vec<u8>, WorkerError>;
}

#[ractor::async_trait]
impl Read for WorkerHandle {
    async fn read(&self, request: Vec<u8>) -> Result<Vec<u8>, WorkerError> {
        self.ask(request).await
    }
}
