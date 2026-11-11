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

//! What a build reports, read so that no byte a build wrote can hurt Polar (docs/architecture/build-orchestrator.md,
//! "How a report is read").
//!
//! A build pod holds no Polar identity: it reports by printing, one line each, [`PREFIX`] and then one JSON object, and the
//! orchestrator reads its log once the pod ends. Every byte of such a line is foreign: written by the repository's
//! pipeline, or by anything it ran. So a line meets the simplest code first, and each step hands the next less to trust:
//!
//! 1. [`gate()`], over the raw bytes: its length, no control character, UTF-8, how deep it nests, how long a string or a
//!    number runs, and only the bytes the grammar has outside a string.
//! 2. [`parse()`], Polar's own parser for one grammar much smaller than JSON's (objects, lists, strings, non-negative
//!    integers and `null`; no float, no boolean, no duplicate key), onto a [`Tape`] of tokens allocated once, at its
//!    bound: a line that needs more is refused.
//! 3. [`check()`], the tape against the grammar of a report: a [`Kind`] a build may report, by its `type`, and for it every
//!    field named, typed and where it must be, an unknown field refused. A build's own execution (started, completed,
//!    failed, cancelled) is no kind of report: that is the orchestrator's to say.
//!
//! All three are proved with Verus, for every input, on the code that runs (`cargo verus verify -p orchestrator-report`, or
//! `just verify`, in the dev shell; build-orchestrator.md, "Proved with Verus"): they terminate, never panic, index out of
//! bounds or overflow; the gate passes a line only within its length, free of control characters, and UTF-8 as
//! `vstd::utf8::valid_utf8` defines it; the parser keeps the tape within its limit and every span inside the line,
//! whatever the line and the bounds; the check reads nothing outside the line or the tape, whatever tape it is given. None
//! has a precondition: what it needs it checks, so the proofs hold for any caller, the unverified ones included. None
//! allocates past what the tape was given, so they can run where nothing may ask for memory (the locked-down worker, O2d2).
//!
//! In the agent, the three run in a locked-down worker (`polar_agent_builder::worker`): [`answer()`], proved as they are,
//! writes what they made into the worker's answer as a header and a 16-byte record for each token, never past its buffer;
//! on the agent's side, [`Report::read_answer`] holds the answer to its shape and bounds, rebuilds the tape, and checks it
//! again before decoding.
//!
//! Then [`Report::read`] decodes a checked line into owned values, its escapes undone: the one step that allocates, and
//! the one not proved. It runs outside the worker, refuses any tape it cannot read, and is held by property tests (every
//! report reads back as itself) and by fuzzing (`fuzz/`: any bytes, through all four steps).
//!
//! The proofs, specifications and ghost variables are Verus's and are erased from a plain build: `vstd` is the crate's
//! one dependency, and a plain `cargo build` compiles what the proofs are about and nothing more.

// Verus reasons about the comparisons themselves, not about `RangeInclusive::contains`: a range is written as two.
#![allow(clippy::manual_range_contains)]

mod answer;
mod gate;
mod grammar;
mod report;
mod tape;

pub use answer::{HEADER, RECORD, answer, answer_len, kind_code, refusal_code};
pub use gate::{Bounds, KEYS, NUMBER_DIGITS, Refusal, gate};
pub use grammar::{Kind, check};
pub use report::{
    ContainerImageCreated, DependencyEdge, FactLabel, FactRef, FactReported, Layer, PackageRef,
    PackageStatusFound, Report, SbomAnalyzed, SecurityAdvisoryFound, StageOutcome,
};
pub use tape::{Tape, Token, parse};

/// What starts a report line in a build's output; any other line is the build's own output.
pub const PREFIX: &str = "polar-report ";

impl Default for Bounds {
    /// Dynamic signed settings, with these defaults (build-orchestrator.md, "Settled with it").
    fn default() -> Self {
        Self {
            line: 16 * 1024 * 1024,
            string: 4096,
            // The deepest a report goes: an SBOM's edges, each a list of references, in the object; and room.
            depth: 6,
            tokens: 1 << 20,
            items: 65_536,
        }
    }
}

impl std::fmt::Display for Refusal {
    /// What was wrong, never what the line said: a line's content goes nowhere.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Refusal::TooLong => "the line is longer than its bound",
            Refusal::Control => "the line holds a control character",
            Refusal::NotUtf8 => "the line is not UTF-8",
            Refusal::OutsideTheGrammar => {
                "the line holds a byte the grammar does not have outside a string"
            }
            Refusal::Unbalanced => "the line's brackets or quotes do not balance",
            Refusal::TooDeep => "the line nests deeper than its bound",
            Refusal::StringTooLong => "a string is longer than its bound",
            Refusal::NumberTooLarge => "a number is larger than its field holds",
            Refusal::BadNumber => "a number is not written as JSON writes one",
            Refusal::BadEscape => {
                "a string holds an escape JSON does not have, or half a surrogate pair"
            }
            Refusal::TooManyTokens => "the line holds more tokens than its bound",
            Refusal::TooManyKeys => "an object has more keys than any of the grammar's",
            Refusal::TooManyItems => "a list has more items than its bound",
            Refusal::DuplicateKey => "an object has a key twice",
            Refusal::NotAValue => "a value the grammar does not have",
            Refusal::Trailing => "something follows the report",
            Refusal::NotAnObject => "the report is not an object",
            Refusal::UnknownKind => "the report is of no kind a build may report",
            Refusal::UnknownKey => "the report has a field its kind does not",
            Refusal::MissingKey => "the report lacks a field its kind must have",
            Refusal::WrongType => "a field's value is not of its type",
            Refusal::UnknownWord => "a field's word is not one of its",
        })
    }
}

impl std::error::Error for Refusal {}
