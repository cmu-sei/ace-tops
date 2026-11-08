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

use crate::gate::{Bounds, KEYS, NUMBER_DIGITS, Refusal};
use vstd::prelude::*;

verus! {

/// One token of a parsed line. Spans are byte offsets into the line, a string's between its quotes and still escaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token {
    Object { members: u32, end: u32 },
    List { items: u32, end: u32 },
    Key { start: u32, end: u32 },
    Text { start: u32, end: u32 },
    Int(u64),
    Null,
}

/// The tokens of one line, in order: allocated once, at the bound it is made with. Parsing never grows it past its `limit`
/// (nor past what a `u32` counts), so it asks for no memory beyond what the tape was given.
#[derive(Debug)]
pub struct Tape {
    pub tokens: Vec<Token>,
    pub limit: usize,
}

/// Every span on the tape lies inside a line of `n` bytes, and every container ends inside the tape.
pub open spec fn tokens_ok(tokens: Seq<Token>, n: nat) -> bool {
    forall|i: int|
        0 <= i < tokens.len() ==> match #[trigger] tokens[i] {
            Token::Key { start, end } => start <= end && end <= n,
            Token::Text { start, end } => start <= end && end <= n,
            Token::Object { end, .. } => end <= tokens.len(),
            Token::List { end, .. } => end <= tokens.len(),
            _ => true,
        }
}

pub open spec fn tape_ok(tape: &Tape, n: nat) -> bool {
    &&& tape.tokens@.len() <= tape.limit
    &&& tape.tokens@.len() <= u32::MAX
    &&& tokens_ok(tape.tokens@, n)
}

impl Tape {
    pub fn new(bounds: &Bounds) -> (t: Tape)
        ensures
            t.tokens@.len() == 0,
            t.limit == bounds.tokens,
    {
        Tape { tokens: Vec::with_capacity(bounds.tokens), limit: bounds.tokens }
    }
}

proof fn lemma_push_keeps(tokens: Seq<Token>, n: nat, t: Token)
    requires
        tokens_ok(tokens, n),
        match t {
            Token::Key { start, end } => start <= end && end <= n,
            Token::Text { start, end } => start <= end && end <= n,
            Token::Object { end, .. } => end <= tokens.len() + 1,
            Token::List { end, .. } => end <= tokens.len() + 1,
            _ => true,
        },
    ensures
        tokens_ok(tokens.push(t), n),
{
    let pushed = tokens.push(t);
    assert forall|i: int| 0 <= i < pushed.len() implies match #[trigger] pushed[i] {
        Token::Key { start, end } => start <= end && end <= n,
        Token::Text { start, end } => start <= end && end <= n,
        Token::Object { end, .. } => end <= pushed.len(),
        Token::List { end, .. } => end <= pushed.len(),
        _ => true,
    } by {
        if i < tokens.len() {
            assert(pushed[i] == tokens[i]);
        }
    }
}

fn push(tape: &mut Tape, token: Token, Ghost(n): Ghost<nat>) -> (r: Result<usize, Refusal>)
    requires
        tape_ok(old(tape), n),
        match token {
            Token::Key { start, end } => start <= end && end <= n,
            Token::Text { start, end } => start <= end && end <= n,
            Token::Object { end, .. } => end <= old(tape).tokens@.len() + 1,
            Token::List { end, .. } => end <= old(tape).tokens@.len() + 1,
            _ => true,
        },
    ensures
        final(tape).limit == old(tape).limit,
        tape_ok(final(tape), n),
        final(tape).tokens@.len() >= old(tape).tokens@.len(),
        r is Ok ==> r->Ok_0 == old(tape).tokens@.len() && final(tape).tokens@.len() == old(tape).tokens@.len() + 1,
        r is Err ==> final(tape).tokens@ == old(tape).tokens@,
{
    // A container's end is a u32: a tape holds no more than one counts.
    if tape.tokens.len() >= tape.limit || tape.tokens.len() >= u32::MAX as usize {
        return Err(Refusal::TooManyTokens);
    }
    proof {
        lemma_push_keeps(tape.tokens@, n, token);
    }
    tape.tokens.push(token);
    Ok(tape.tokens.len() - 1)
}

/// Sets the container at `at` to say it ends where the tape now ends.
fn close(tape: &mut Tape, at: usize, token: Token, Ghost(n): Ghost<nat>)
    requires
        tape_ok(old(tape), n),
        at < old(tape).tokens@.len(),
        match token {
            Token::Object { end, .. } => end == old(tape).tokens@.len(),
            Token::List { end, .. } => end == old(tape).tokens@.len(),
            _ => false,
        },
    ensures
        final(tape).limit == old(tape).limit,
        tape_ok(final(tape), n),
        final(tape).tokens@.len() == old(tape).tokens@.len(),
{
    let ghost before = tape.tokens@;
    tape.tokens.set(at, token);
    assert forall|i: int| 0 <= i < tape.tokens@.len() implies match #[trigger] tape.tokens@[i] {
        Token::Key { start, end } => start <= end && end <= n,
        Token::Text { start, end } => start <= end && end <= n,
        Token::Object { end, .. } => end <= tape.tokens@.len(),
        Token::List { end, .. } => end <= tape.tokens@.len(),
        _ => true,
    } by {
        if i != at {
            assert(tape.tokens@[i] == before[i]);
        }
    }
}

fn spaces(text: &[u8], at: &mut usize)
    requires
        *old(at) <= text@.len(),
    ensures
        *old(at) <= *final(at) <= text@.len(),
{
    while *at < text.len() && text[*at] == b' '
        invariant
            *old(at) <= *at <= text@.len(),
        decreases text@.len() - *at,
    {
        *at += 1;
    }
}

/// Whether the bytes `a` and `b` (start and end each) of `text` are the same.
fn same(text: &[u8], a: (u32, u32), b: (u32, u32)) -> bool
    requires
        a.0 <= a.1 <= text@.len(),
        b.0 <= b.1 <= text@.len(),
{
    if a.1 - a.0 != b.1 - b.0 {
        return false;
    }
    let len = a.1 - a.0;
    let mut k: u32 = 0;
    while k < len
        invariant
            len == a.1 - a.0,
            len == b.1 - b.0,
            a.0 <= a.1 <= text@.len(),
            b.0 <= b.1 <= text@.len(),
        decreases len - k,
    {
        if text[(a.0 + k) as usize] != text[(b.0 + k) as usize] {
            return false;
        }
        k += 1;
    }
    true
}

fn hex(b: u8) -> (r: Option<u32>)
    ensures
        r matches Some(v) ==> v < 16,
{
    if b'0' <= b && b <= b'9' {
        Some((b - b'0') as u32)
    } else if b'a' <= b && b <= b'f' {
        Some((b - b'a') as u32 + 10)
    } else if b'A' <= b && b <= b'F' {
        Some((b - b'A') as u32 + 10)
    } else {
        None
    }
}

/// Four hex digits at `at`, as a UTF-16 unit.
fn hex4(text: &[u8], at: &mut usize) -> (r: Result<u32, Refusal>)
    requires
        *old(at) <= text@.len(),
    ensures
        *old(at) <= *final(at) <= text@.len(),
        r matches Ok(v) ==> v <= 0xffff,
{
    if text.len() - *at < 4 {
        return Err(Refusal::BadEscape);
    }
    let mut unit: u32 = 0;
    let mut k: usize = 0;
    while k < 4
        invariant
            *old(at) <= *at,
            *at + 4 <= text@.len(),
            k <= 4,
            unit < pow16(k as nat),
        decreases 4 - k,
    {
        match hex(text[*at + k]) {
            None => {
                return Err(Refusal::BadEscape);
            },
            Some(v) => {
                proof { lemma_pow16_step(k as nat, unit as nat, v as nat); }
                unit = unit * 16 + v;
            },
        }
        k += 1;
    }
    proof { lemma_pow16_step(3, 0, 0); }
    *at += 4;
    Ok(unit)
}

pub open spec fn pow16(k: nat) -> nat
    decreases k,
{
    if k == 0 { 1 } else { 16 * pow16((k - 1) as nat) }
}

proof fn lemma_pow16_step(k: nat, unit: nat, v: nat)
    requires
        k < 4,
        unit < pow16(k),
        v < 16,
    ensures
        unit * 16 + v < pow16(k + 1),
        pow16(k + 1) <= 65536,
{
    assert(pow16(0) == 1);
    assert(pow16(1) == 16);
    assert(pow16(2) == 256);
    assert(pow16(3) == 4096);
    assert(pow16(4) == 65536);
}

/// A string at `at` (its opening quote), its escapes checked and left as written: its span between the quotes.
fn string(text: &[u8], at: &mut usize, bounds: &Bounds) -> (r: Result<(u32, u32), Refusal>)
    requires
        *old(at) < text@.len(),
        text@.len() <= u32::MAX,
    ensures
        *old(at) <= *final(at) <= text@.len(),
        r matches Ok((s, e)) ==> s <= e && e <= text@.len(),
        r is Ok ==> *final(at) > *old(at),
{
    *at += 1;
    let start = *at;
    loop
        invariant
            start <= *at <= text@.len(),
            *old(at) < start,
            text@.len() <= u32::MAX,
        decreases text@.len() - *at,
    {
        if *at >= text.len() {
            return Err(Refusal::Unbalanced);
        }
        if *at - start > bounds.string {
            return Err(Refusal::StringTooLong);
        }
        let b = text[*at];
        if b == b'"' {
            let end = *at;
            *at += 1;
            return Ok((start as u32, end as u32));
        } else if b == b'\\' {
            *at += 1;
            if *at >= text.len() {
                return Err(Refusal::BadEscape);
            }
            let e = text[*at];
            if e == b'"' || e == b'\\' || e == b'/' || e == b'b' || e == b'f' || e == b'n' || e == b'r' || e == b't' {
                *at += 1;
            } else if e == b'u' {
                *at += 1;
                let unit = hex4(text, at)?;
                if 0xdc00 <= unit && unit <= 0xdfff {
                    return Err(Refusal::BadEscape);
                }
                if 0xd800 <= unit && unit <= 0xdbff {
                    if text.len() - *at < 2 || text[*at] != b'\\' || text[*at + 1] != b'u' {
                        return Err(Refusal::BadEscape);
                    }
                    *at += 2;
                    let low = hex4(text, at)?;
                    if !(0xdc00 <= low && low <= 0xdfff) {
                        return Err(Refusal::BadEscape);
                    }
                }
            } else {
                return Err(Refusal::BadEscape);
            }
        } else if b < 0x20 || b == 0x7f {
            return Err(Refusal::Control);
        } else {
            *at += 1;
        }
    }
}

fn integer(text: &[u8], at: &mut usize) -> (r: Result<u64, Refusal>)
    requires
        *old(at) <= text@.len(),
    ensures
        *old(at) <= *final(at) <= text@.len(),
{
    let start = *at;
    let mut n: u64 = 0;
    while *at < text.len() && b'0' <= text[*at] && text[*at] <= b'9'
        invariant
            start == *old(at),
            start <= *at <= text@.len(),
        decreases text@.len() - *at,
    {
        if *at - start == NUMBER_DIGITS {
            return Err(Refusal::NumberTooLarge);
        }
        let d = (text[*at] - b'0') as u64;
        if n > 1844674407370955161u64 || (n == 1844674407370955161u64 && d > 5) {
            return Err(Refusal::NumberTooLarge);
        }
        n = n * 10 + d;
        *at += 1;
    }
    if *at - start > 1 && text[start] == b'0' {
        return Err(Refusal::BadNumber);
    }
    if *at < text.len() && (text[*at] == b'.' || text[*at] == b'e' || text[*at] == b'E' || text[*at] == b'-' || text[*at] == b'+') {
        return Err(Refusal::NotAValue);
    }
    Ok(n)
}

/// One value at `at`, at nesting `depth`: 1 for the line's own.
fn value(text: &[u8], at: &mut usize, depth: usize, bounds: &Bounds, tape: &mut Tape) -> (r: Result<(), Refusal>)
    requires
        *old(at) <= text@.len(),
        text@.len() <= u32::MAX,
        depth <= bounds.depth + 1,
        bounds.depth < usize::MAX,
        tape_ok(old(tape), text@.len()),
    ensures
        *old(at) <= *final(at) <= text@.len(),
        final(tape).limit == old(tape).limit,
        tape_ok(final(tape), text@.len()),
        final(tape).tokens@.len() >= old(tape).tokens@.len(),
    decreases bounds.depth + 1 - depth, 1nat,
{
    spaces(text, at);
    if *at >= text.len() {
        return Err(Refusal::NotAValue);
    }
    let b = text[*at];
    if b == b'{' {
        object(text, at, depth, bounds, tape)
    } else if b == b'[' {
        list(text, at, depth, bounds, tape)
    } else if b == b'"' {
        let (start, end) = string(text, at, bounds)?;
        push(tape, Token::Text { start, end }, Ghost(text@.len()))?;
        Ok(())
    } else if b'0' <= b && b <= b'9' {
        let n = integer(text, at)?;
        push(tape, Token::Int(n), Ghost(text@.len()))?;
        Ok(())
    } else if b == b'n' && text.len() - *at >= 4 && text[*at + 1] == b'u' && text[*at + 2] == b'l' && text[*at + 3] == b'l' {
        *at += 4;
        push(tape, Token::Null, Ghost(text@.len()))?;
        Ok(())
    } else {
        Err(Refusal::NotAValue)
    }
}

fn object(text: &[u8], at: &mut usize, depth: usize, bounds: &Bounds, tape: &mut Tape) -> (r: Result<(), Refusal>)
    requires
        *old(at) < text@.len(),
        text@.len() <= u32::MAX,
        depth <= bounds.depth + 1,
        bounds.depth < usize::MAX,
        tape_ok(old(tape), text@.len()),
    ensures
        *old(at) <= *final(at) <= text@.len(),
        final(tape).limit == old(tape).limit,
        tape_ok(final(tape), text@.len()),
        final(tape).tokens@.len() >= old(tape).tokens@.len(),
    decreases bounds.depth + 1 - depth, 0nat,
{
    if depth > bounds.depth {
        return Err(Refusal::TooDeep);
    }
    *at += 1;
    let n = Ghost(text@.len());
    let slot = push(tape, Token::Object { members: 0, end: 0 }, n)?;
    let mut keys: [(u32, u32); KEYS] = [(0, 0); KEYS];
    let mut members: usize = 0;
    spaces(text, at);
    if *at < text.len() && text[*at] == b'}' {
        *at += 1;
    } else {
        loop
            invariant
                *old(at) <= *at <= text@.len(),
                text@.len() <= u32::MAX,
                depth <= bounds.depth,
                bounds.depth < usize::MAX,
                tape.limit == old(tape).limit,
                tape_ok(tape, text@.len()),
                n@ == text@.len(),
                slot < tape.tokens@.len(),
                tape.tokens@.len() >= old(tape).tokens@.len(),
                members <= KEYS,
                forall|j: int| 0 <= j < members ==> (#[trigger] keys[j]).0 <= keys[j].1 && keys[j].1 <= text@.len(),
            decreases text@.len() - *at,
        {
            let ghost before = *at;
            spaces(text, at);
            if *at >= text.len() || text[*at] != b'"' {
                return Err(Refusal::NotAValue);
            }
            let key = string(text, at, bounds)?;
            if members == KEYS {
                return Err(Refusal::TooManyKeys);
            }
            let mut j: usize = 0;
            while j < members
                invariant
                    j <= members < KEYS,
                    key.0 <= key.1 <= text@.len(),
                    before < *at <= text@.len(),
                    *old(at) <= before,
                    text@.len() <= u32::MAX,
                    depth <= bounds.depth,
                    bounds.depth < usize::MAX,
                    tape.limit == old(tape).limit,
                    tape_ok(tape, text@.len()),
                    n@ == text@.len(),
                    slot < tape.tokens@.len(),
                    tape.tokens@.len() >= old(tape).tokens@.len(),
                    forall|m: int| 0 <= m < members ==> (#[trigger] keys[m]).0 <= keys[m].1 && keys[m].1 <= text@.len(),
                decreases members - j,
            {
                if same(text, keys[j], key) {
                    return Err(Refusal::DuplicateKey);
                }
                j += 1;
            }
            keys[members] = key;
            members += 1;
            push(tape, Token::Key { start: key.0, end: key.1 }, n)?;
            spaces(text, at);
            if *at >= text.len() || text[*at] != b':' {
                return Err(Refusal::NotAValue);
            }
            *at += 1;
            value(text, at, depth + 1, bounds, tape)?;
            spaces(text, at);
            if *at >= text.len() {
                return Err(Refusal::NotAValue);
            }
            if text[*at] == b',' {
                *at += 1;
            } else if text[*at] == b'}' {
                *at += 1;
                break;
            } else {
                return Err(Refusal::NotAValue);
            }
            assert(*at > before);
        }
    }
    let end = tape.tokens.len() as u32;
    close(tape, slot, Token::Object { members: members as u32, end }, n);
    Ok(())
}

fn list(text: &[u8], at: &mut usize, depth: usize, bounds: &Bounds, tape: &mut Tape) -> (r: Result<(), Refusal>)
    requires
        *old(at) < text@.len(),
        text@.len() <= u32::MAX,
        depth <= bounds.depth + 1,
        bounds.depth < usize::MAX,
        tape_ok(old(tape), text@.len()),
    ensures
        *old(at) <= *final(at) <= text@.len(),
        final(tape).limit == old(tape).limit,
        tape_ok(final(tape), text@.len()),
        final(tape).tokens@.len() >= old(tape).tokens@.len(),
    decreases bounds.depth + 1 - depth, 0nat,
{
    if depth > bounds.depth {
        return Err(Refusal::TooDeep);
    }
    *at += 1;
    let n = Ghost(text@.len());
    let slot = push(tape, Token::List { items: 0, end: 0 }, n)?;
    let mut items: usize = 0;
    spaces(text, at);
    if *at < text.len() && text[*at] == b']' {
        *at += 1;
    } else {
        loop
            invariant
                *old(at) <= *at <= text@.len(),
                text@.len() <= u32::MAX,
                depth <= bounds.depth,
                bounds.depth < usize::MAX,
                tape.limit == old(tape).limit,
                tape_ok(tape, text@.len()),
                n@ == text@.len(),
                slot < tape.tokens@.len(),
                tape.tokens@.len() >= old(tape).tokens@.len(),
                items <= bounds.items,
                items <= u32::MAX,
            decreases text@.len() - *at,
        {
            let ghost before = *at;
            if items == bounds.items || items == u32::MAX as usize {
                return Err(Refusal::TooManyItems);
            }
            value(text, at, depth + 1, bounds, tape)?;
            items += 1;
            spaces(text, at);
            if *at >= text.len() {
                return Err(Refusal::NotAValue);
            }
            if text[*at] == b',' {
                *at += 1;
            } else if text[*at] == b']' {
                *at += 1;
                break;
            } else {
                return Err(Refusal::NotAValue);
            }
            assert(*at > before);
        }
    }
    let end = tape.tokens.len() as u32;
    close(tape, slot, Token::List { items: items as u32, end }, n);
    Ok(())
}

/// Parses `text` onto `tape`, which it empties first: one value, and nothing after it but spaces. Whatever `text` and
/// `bounds` are, it returns, never panics, keeps the tape within its limit, and leaves every span inside the line.
pub fn parse(text: &[u8], bounds: &Bounds, tape: &mut Tape) -> (r: Result<(), Refusal>)
    ensures
        final(tape).limit == old(tape).limit,
        tape_ok(final(tape), text@.len()),
{
    tape.tokens.clear();
    if text.len() > bounds.line || text.len() > u32::MAX as usize {
        return Err(Refusal::TooLong);
    }
    if bounds.depth == usize::MAX {
        return Err(Refusal::TooDeep);
    }
    let mut at: usize = 0;
    value(text, &mut at, 1, bounds, tape)?;
    spaces(text, &mut at);
    if at != text.len() {
        return Err(Refusal::Trailing);
    }
    Ok(())
}

} // verus!
