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

use crate::gate::{Bounds, Refusal, gate};
use crate::grammar::{Kind, check};
use crate::tape::{Tape, Token, parse};
use vstd::prelude::*;

verus! {

/// The bytes of an answer's header, and of each token's record after it.
pub const HEADER: usize = 16;
pub const RECORD: usize = 16;

/// A refusal as the answer says it: 1 and up; 0 is a report read.
pub fn refusal_code(why: Refusal) -> (code: u32)
    ensures
        code >= 1,
{
    match why {
        Refusal::TooLong => 1,
        Refusal::Control => 2,
        Refusal::NotUtf8 => 3,
        Refusal::OutsideTheGrammar => 4,
        Refusal::Unbalanced => 5,
        Refusal::TooDeep => 6,
        Refusal::StringTooLong => 7,
        Refusal::NumberTooLarge => 8,
        Refusal::BadNumber => 9,
        Refusal::BadEscape => 10,
        Refusal::TooManyTokens => 11,
        Refusal::TooManyKeys => 12,
        Refusal::TooManyItems => 13,
        Refusal::DuplicateKey => 14,
        Refusal::NotAValue => 15,
        Refusal::Trailing => 16,
        Refusal::NotAnObject => 17,
        Refusal::UnknownKind => 18,
        Refusal::UnknownKey => 19,
        Refusal::MissingKey => 20,
        Refusal::WrongType => 21,
        Refusal::UnknownWord => 22,
    }
}

pub fn kind_code(kind: Kind) -> u32 {
    match kind {
        Kind::StageStarted => 1,
        Kind::StageCompleted => 2,
        Kind::SecurityAdvisoryFound => 3,
        Kind::PackageStatusFound => 4,
        Kind::ArtifactProduced => 5,
        Kind::SbomAnalyzed => 6,
        Kind::BinaryLinked => 7,
        Kind::ContainerImageCreated => 8,
        Kind::FactReported => 9,
    }
}

/// Writes `value` into `out` at `at`, little-endian, in `width` bytes.
fn put(out: &mut [u8], at: usize, value: u64, width: usize)
    requires
        width <= 8,
        at + width <= old(out)@.len(),
    ensures
        final(out)@.len() == old(out)@.len(),
{
    let n = out.len();
    // What the precondition says, held at run time too, for a caller that is not proved.
    if width > n || at > n - width {
        return;
    }
    let mut k: usize = 0;
    let mut v = value;
    while k < width
        invariant
            k <= width <= 8,
            at + width <= n,
            n == out@.len(),
            out@.len() == old(out)@.len(),
        decreases width - k,
    {
        out[at + k] = (v & 0xff) as u8;
        v >>= 8;
        k += 1;
    }
}

/// How many bytes an answer may take, for a worker at `bounds`: its header, and a record for each token the tape may hold.
pub fn answer_len(bounds: &Bounds) -> (n: usize) {
    let tokens = if bounds.tokens > (usize::MAX - HEADER) / RECORD { (usize::MAX - HEADER) / RECORD } else { bounds.tokens };
    HEADER + RECORD * tokens
}

fn write_refusal(why: Refusal, out: &mut [u8]) -> (n: usize)
    ensures
        n <= old(out)@.len(),
        final(out)@.len() == old(out)@.len(),
{
    if out.len() < HEADER {
        return 0;
    }
    put(out, 0, refusal_code(why) as u64, 4);
    put(out, 4, 0, 4);
    put(out, 8, 0, 8);
    HEADER
}

/// The worker's answer to one line (build-orchestrator.md, O2d2): the gate, the parser and the check, then the tape written
/// into `out` as a header (0 or a refusal's code; the kind's code; how many tokens) and a record of 16 bytes for each token
/// (its tag, then its fields). It writes nothing past `out` and allocates nothing, whatever the line, the bounds and the
/// tape, and returns how much of `out` the answer is. An `out` too small for the tape is a refusal of too many tokens.
pub fn answer(line: &[u8], bounds: &Bounds, tape: &mut Tape, out: &mut [u8]) -> (n: usize)
    ensures
        n <= old(out)@.len(),
        final(out)@.len() == old(out)@.len(),
{
    if let Err(why) = gate(line, bounds) {
        return write_refusal(why, out);
    }
    if let Err(why) = parse(line, bounds, tape) {
        return write_refusal(why, out);
    }
    let kind = match check(line, tape) {
        Ok(kind) => kind,
        Err(why) => return write_refusal(why, out),
    };
    let count = tape.tokens.len();
    let n = out.len();
    if n < HEADER || (n - HEADER) / RECORD < count {
        return write_refusal(Refusal::TooManyTokens, out);
    }
    assert(16 * (count as int) + 16 <= n as int) by (nonlinear_arith)
        requires
            n as int >= 16,
            (n as int - 16) / 16 >= count as int;
    put(out, 0, 0, 4);
    put(out, 4, kind_code(kind) as u64, 4);
    put(out, 8, count as u64, 8);
    let mut i: usize = 0;
    while i < count
        invariant
            count == tape.tokens@.len(),
            HEADER + RECORD * count <= n,
            n == out@.len(),
            out@.len() == old(out)@.len(),
            i <= count,
        decreases count - i,
    {
        assert(16 * (i as int) + 32 <= 16 * (count as int) + 16) by (nonlinear_arith)
            requires
                (i as int) < (count as int);
        let at = HEADER + RECORD * i;
        let (tag, a, b): (u64, u64, u64) = match tape.tokens[i] {
            Token::Object { members, end } => (1, members as u64, end as u64),
            Token::List { items, end } => (2, items as u64, end as u64),
            Token::Key { start, end } => (3, start as u64, end as u64),
            Token::Text { start, end } => (4, start as u64, end as u64),
            Token::Int(n) => (5, 0, n),
            Token::Null => (6, 0, 0),
        };
        put(out, at, tag, 4);
        put(out, at + 4, a, 4);
        put(out, at + 8, b, 8);
        i += 1;
    }
    HEADER + RECORD * count
}

} // verus!
