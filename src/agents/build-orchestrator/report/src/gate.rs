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

use vstd::prelude::*;

verus! {

broadcast use vstd::seq::group_seq_lemmas;

/// How much of a line each step reads before it refuses: Dynamic signed settings (build-orchestrator.md, "Settled with it").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    /// Bytes in one line, the prefix not counted.
    pub line: usize,
    /// Bytes in one string, between its quotes, escapes as written.
    pub string: usize,
    /// How deep objects and lists nest.
    pub depth: usize,
    /// Tokens on a line's tape.
    pub tokens: usize,
    /// Items in one list.
    pub items: usize,
}

/// Why a line is not a report. Each says what was wrong and never what the line said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    TooLong,
    Control,
    NotUtf8,
    OutsideTheGrammar,
    Unbalanced,
    TooDeep,
    StringTooLong,
    NumberTooLarge,
    BadNumber,
    BadEscape,
    TooManyTokens,
    TooManyKeys,
    TooManyItems,
    DuplicateKey,
    NotAValue,
    Trailing,
    NotAnObject,
    UnknownKind,
    UnknownKey,
    MissingKey,
    WrongType,
    UnknownWord,
}

/// The most digits a number may have: a `u64` has at most 20.
pub const NUMBER_DIGITS: usize = 20;

/// The most keys an object of the grammar has: a security advisory's 12, and room.
pub const KEYS: usize = 16;

/// A byte no report holds raw: a C0 control or DEL.
pub open spec fn is_control(b: u8) -> bool {
    b < 0x20 || b == 0x7f
}

/// Whether the scalar that starts at `i` of `line` is well-formed, and its width if it is: the same test as
/// `vstd::utf8::valid_first_scalar` of what is left of the line, made on the bytes themselves.
fn first_scalar(line: &[u8], i: usize) -> (r: Option<usize>)
    requires
        i < line@.len(),
    ensures
        match r {
            Some(width) => {
                &&& 1 <= width <= 4
                &&& i + width <= line@.len()
                &&& vstd::utf8::valid_first_scalar(line@.subrange(i as int, line@.len() as int))
                &&& vstd::utf8::length_of_first_scalar(line@.subrange(i as int, line@.len() as int)) == width
            },
            None => !vstd::utf8::valid_first_scalar(line@.subrange(i as int, line@.len() as int)),
        },
{
    let ghost rest = line@.subrange(i as int, line@.len() as int);
    let n = line.len() - i;
    let b0 = line[i];
    if b0 <= 0x7f {
        return Some(1);
    }
    if 0xc0 <= b0 && b0 <= 0xdf {
        if n < 2 || !(0x80 <= line[i + 1] && line[i + 1] <= 0xbf) {
            return None;
        }
        let cp: u32 = (((b0 & 0x1f) as u32) << 6) | ((line[i + 1] & 0x3f) as u32);
        assert(cp == vstd::utf8::decode_first_codepoint(rest));
        if cp < 0x80 || (0xd800 <= cp && cp <= 0xdfff) {
            return None;
        }
        return Some(2);
    }
    if 0xe0 <= b0 && b0 <= 0xef {
        if n < 3 || !(0x80 <= line[i + 1] && line[i + 1] <= 0xbf) || !(0x80 <= line[i + 2] && line[i + 2] <= 0xbf) {
            return None;
        }
        let cp: u32 = (((b0 & 0x0f) as u32) << 12) | (((line[i + 1] & 0x3f) as u32) << 6) | ((line[i + 2] & 0x3f) as u32);
        assert(cp == vstd::utf8::decode_first_codepoint(rest));
        if cp < 0x800 || (0xd800 <= cp && cp <= 0xdfff) {
            return None;
        }
        return Some(3);
    }
    if 0xf0 <= b0 && b0 <= 0xf7 {
        if n < 4 || !(0x80 <= line[i + 1] && line[i + 1] <= 0xbf) || !(0x80 <= line[i + 2] && line[i + 2] <= 0xbf)
            || !(0x80 <= line[i + 3] && line[i + 3] <= 0xbf) {
            return None;
        }
        let cp: u32 = (((b0 & 0x07) as u32) << 18) | (((line[i + 1] & 0x3f) as u32) << 12) | (((line[i + 2] & 0x3f) as u32) << 6)
            | ((line[i + 3] & 0x3f) as u32);
        assert(cp == vstd::utf8::decode_first_codepoint(rest));
        if cp < 0x10000 || cp > 0x10ffff {
            return None;
        }
        return Some(4);
    }
    None
}

/// Whether `line` is UTF-8, as `vstd::utf8::valid_utf8` defines it: a scalar at a time, from the front.
fn utf8(line: &[u8]) -> (r: bool)
    ensures
        r == vstd::utf8::valid_utf8(line@),
{
    let mut i: usize = 0;
    assert(line@.subrange(0, line@.len() as int) =~= line@);
    while i < line.len()
        invariant
            i <= line@.len(),
            vstd::utf8::valid_utf8(line@.subrange(i as int, line@.len() as int)) == vstd::utf8::valid_utf8(line@),
        decreases line@.len() - i,
    {
        let ghost rest = line@.subrange(i as int, line@.len() as int);
        match first_scalar(line, i) {
            None => {
                return false;
            },
            Some(width) => {
                assert(vstd::utf8::pop_first_scalar(rest) =~= line@.subrange((i + width) as int, line@.len() as int));
                i += width;
            },
        }
    }
    assert(line@.subrange(i as int, line@.len() as int) =~= Seq::<u8>::empty());
    true
}

/// The line, if its bytes could be a report: within its length, UTF-8, no control character, nesting no deeper than its
/// bound, no string or number longer than its bound, and outside a string only what the grammar has there.
pub fn gate(line: &[u8], bounds: &Bounds) -> (r: Result<(), Refusal>)
    ensures
        r is Ok ==> line@.len() <= bounds.line,
        r is Ok ==> forall|i: int| 0 <= i < line@.len() ==> !is_control(#[trigger] line@[i]),
        r is Ok ==> vstd::utf8::valid_utf8(line@),
{
    if line.len() > bounds.line {
        return Err(Refusal::TooLong);
    }
    let mut i: usize = 0;
    while i < line.len()
        invariant
            i <= line@.len(),
            forall|j: int| 0 <= j < i ==> !is_control(#[trigger] line@[j]),
        decreases line@.len() - i,
    {
        if line[i] < 0x20 || line[i] == 0x7f {
            return Err(Refusal::Control);
        }
        i += 1;
    }
    if !utf8(line) {
        return Err(Refusal::NotUtf8);
    }
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    let mut run: usize = 0;
    let mut k: usize = 0;
    while k < line.len()
        invariant
            k <= line@.len(),
            depth <= bounds.depth,
            in_string ==> run <= bounds.string,
            !in_string ==> run <= NUMBER_DIGITS,
        decreases line@.len() - k,
    {
        let b = line[k];
        k += 1;
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
                run = 0;
                continue;
            }
            if run == bounds.string {
                return Err(Refusal::StringTooLong);
            }
            run += 1;
            continue;
        }
        if b'0' <= b && b <= b'9' {
            if run == NUMBER_DIGITS {
                return Err(Refusal::NumberTooLarge);
            }
            run += 1;
            continue;
        }
        if b == b'"' {
            in_string = true;
        } else if b == b'{' || b == b'[' {
            if depth == bounds.depth {
                return Err(Refusal::TooDeep);
            }
            depth += 1;
        } else if b == b'}' || b == b']' {
            if depth == 0 {
                return Err(Refusal::Unbalanced);
            }
            depth -= 1;
        } else if !(b == b':' || b == b',' || b == b' ' || b == b'n' || b == b'u' || b == b'l') {
            return Err(Refusal::OutsideTheGrammar);
        }
        run = 0;
    }
    if in_string || depth != 0 {
        return Err(Refusal::Unbalanced);
    }
    Ok(())
}

} // verus!
