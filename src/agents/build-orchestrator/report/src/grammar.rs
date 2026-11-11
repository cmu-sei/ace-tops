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

use crate::gate::{KEYS, Refusal};
use crate::tape::{Tape, Token};
use vstd::prelude::*;

verus! {

/// A kind of report a build may make: what it ran and what it produced or found. What happened to the build itself
/// (started, completed, failed, cancelled) is the orchestrator's to say, from the Job, and no kind of report
/// (build-orchestrator.md, revised 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    StageStarted,
    StageCompleted,
    SecurityAdvisoryFound,
    PackageStatusFound,
    ArtifactProduced,
    SbomAnalyzed,
    BinaryLinked,
    ContainerImageCreated,
    /// A fact about a thing the graph knows by its key: a subject, a namespaced name, maybe an object and a value, and the
    /// tool that found it. Which names a pipeline may report is its signed mapping's to say, not the grammar's.
    FactReported,
}

/// The objects of the grammar: a report of each kind, and what one holds.
#[derive(Clone, Copy)]
pub enum Schema {
    Report(Kind),
    Package,
    Edge,
    Layer,
}

/// What a field holds.
#[derive(Clone, Copy)]
pub enum Shape {
    /// A string.
    Text,
    /// A string, or `null`.
    MaybeText,
    /// A non-negative integer of at most this.
    Int(u64),
    /// A stage's outcome: one of its words.
    Outcome,
    /// A list of strings.
    Texts,
    /// A package, or `null`.
    MaybePackage,
    /// A list of packages.
    Packages,
    /// A list of dependency edges.
    Edges,
    /// A list of image layers.
    Layers,
    /// The report's `build_id`, a string or `null`: read and never believed, since the orchestrator stamps its own.
    Ignored,
}

pub open spec fn rank(schema: Schema) -> nat {
    match schema {
        Schema::Report(_) => 2,
        _ => 1,
    }
}

pub open spec fn shape_rank(shape: Shape) -> nat {
    match shape {
        Shape::MaybePackage | Shape::Packages | Shape::Edges | Shape::Layers => 1,
        _ => 0,
    }
}

fn eq_bytes(a: &[u8], b: &[u8]) -> (r: bool)
    ensures
        r == (a@ == b@),
{
    if a.len() != b.len() {
        return false;
    }
    let mut i: usize = 0;
    while i < a.len()
        invariant
            a@.len() == b@.len(),
            i <= a@.len(),
            forall|j: int| 0 <= j < i ==> a@[j] == b@[j],
        decreases a@.len() - i,
    {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    assert(a@ =~= b@);
    true
}

/// The kind a report's `type` names.
fn kind_named(name: &[u8]) -> Option<Kind> {
    if eq_bytes(name, b"stage_started") {
        Some(Kind::StageStarted)
    } else if eq_bytes(name, b"stage_completed") {
        Some(Kind::StageCompleted)
    } else if eq_bytes(name, b"security_advisory_found") {
        Some(Kind::SecurityAdvisoryFound)
    } else if eq_bytes(name, b"package_status_found") {
        Some(Kind::PackageStatusFound)
    } else if eq_bytes(name, b"artifact_produced") {
        Some(Kind::ArtifactProduced)
    } else if eq_bytes(name, b"sbom_analyzed") {
        Some(Kind::SbomAnalyzed)
    } else if eq_bytes(name, b"binary_linked") {
        Some(Kind::BinaryLinked)
    } else if eq_bytes(name, b"container_image_created") {
        Some(Kind::ContainerImageCreated)
    } else {
        None
    }
}

/// A field of `schema`: its place among the schema's fields, and what it holds; whether it must be there is `required`'s.
/// Every report has `type` (place 0, a kind's name, checked apart) and may have `build_id`. The fields are the event types'
/// own (`polar::events`): one whose type is an `Option` may be `null` or absent, one with a serde default may be absent.
fn field(schema: Schema, key: &[u8]) -> (r: Option<(usize, Shape)>)
    ensures
        r matches Some((place, shape)) ==> place < KEYS && shape_rank(shape) < rank(schema),
{
    match schema {
        Schema::Report(kind) => {
            if eq_bytes(key, b"type") {
                return Some((0, Shape::Text));
            }
            if eq_bytes(key, b"build_id") {
                return Some((1, Shape::Ignored));
            }
            match kind {
                Kind::StageStarted => {
                    if eq_bytes(key, b"stage_name") { Some((2, Shape::Text)) }
                    else if eq_bytes(key, b"stage_id") { Some((3, Shape::Text)) }
                    else if eq_bytes(key, b"at") { Some((4, Shape::Text)) }
                    else { None }
                },
                Kind::StageCompleted => {
                    if eq_bytes(key, b"stage_name") { Some((2, Shape::Text)) }
                    else if eq_bytes(key, b"stage_id") { Some((3, Shape::Text)) }
                    else if eq_bytes(key, b"duration_secs") { Some((4, Shape::Int(u64::MAX))) }
                    else if eq_bytes(key, b"outcome") { Some((5, Shape::Outcome)) }
                    else if eq_bytes(key, b"at") { Some((6, Shape::Text)) }
                    else { None }
                },
                Kind::SecurityAdvisoryFound => {
                    if eq_bytes(key, b"severity") { Some((2, Shape::Text)) }
                    else if eq_bytes(key, b"identifier") { Some((3, Shape::Text)) }
                    else if eq_bytes(key, b"in_artifact") { Some((4, Shape::MaybeText)) }
                    else if eq_bytes(key, b"kind") { Some((5, Shape::MaybeText)) }
                    else if eq_bytes(key, b"scanner") { Some((6, Shape::MaybeText)) }
                    else if eq_bytes(key, b"affected_package") { Some((7, Shape::MaybeText)) }
                    else if eq_bytes(key, b"cve_id") { Some((8, Shape::MaybeText)) }
                    else if eq_bytes(key, b"ghsa_id") { Some((9, Shape::MaybeText)) }
                    else if eq_bytes(key, b"fix_version") { Some((10, Shape::MaybeText)) }
                    else if eq_bytes(key, b"unaffected_constraint") { Some((11, Shape::MaybeText)) }
                    else if eq_bytes(key, b"advisory_url") { Some((12, Shape::MaybeText)) }
                    else { None }
                },
                Kind::PackageStatusFound => {
                    if eq_bytes(key, b"kind") { Some((2, Shape::Text)) }
                    else if eq_bytes(key, b"identifier") { Some((3, Shape::Text)) }
                    else if eq_bytes(key, b"package_name") { Some((4, Shape::Text)) }
                    else if eq_bytes(key, b"package_version") { Some((5, Shape::Text)) }
                    else if eq_bytes(key, b"in_artifact") { Some((6, Shape::MaybeText)) }
                    else if eq_bytes(key, b"affected_package") { Some((7, Shape::MaybeText)) }
                    else if eq_bytes(key, b"advisory_url") { Some((8, Shape::MaybeText)) }
                    else if eq_bytes(key, b"scanner") { Some((9, Shape::MaybeText)) }
                    else { None }
                },
                Kind::ArtifactProduced => {
                    if eq_bytes(key, b"artifact_content_hash") { Some((2, Shape::Text)) }
                    else if eq_bytes(key, b"artifact_type") { Some((3, Shape::Text)) }
                    else if eq_bytes(key, b"name") { Some((4, Shape::Text)) }
                    else if eq_bytes(key, b"content_type") { Some((5, Shape::Text)) }
                    else { None }
                },
                Kind::SbomAnalyzed => {
                    if eq_bytes(key, b"artifact_content_hash") { Some((2, Shape::Text)) }
                    else if eq_bytes(key, b"filename") { Some((3, Shape::Text)) }
                    else if eq_bytes(key, b"root") { Some((4, Shape::MaybePackage)) }
                    else if eq_bytes(key, b"components") { Some((5, Shape::Packages)) }
                    else if eq_bytes(key, b"edges") { Some((6, Shape::Edges)) }
                    else { None }
                },
                Kind::BinaryLinked => {
                    if eq_bytes(key, b"binary_content_hash") { Some((2, Shape::Text)) }
                    else if eq_bytes(key, b"binary_name") { Some((3, Shape::Text)) }
                    else if eq_bytes(key, b"root_purl") { Some((4, Shape::Text)) }
                    else if eq_bytes(key, b"sbom_content_hash") { Some((5, Shape::Text)) }
                    else if eq_bytes(key, b"binding_digest") { Some((6, Shape::Text)) }
                    else { None }
                },
                Kind::ContainerImageCreated => {
                    if eq_bytes(key, b"image_name") { Some((2, Shape::Text)) }
                    else if eq_bytes(key, b"tarball_hash") { Some((3, Shape::Text)) }
                    else if eq_bytes(key, b"config_digest") { Some((4, Shape::Text)) }
                    else if eq_bytes(key, b"layers") { Some((5, Shape::Layers)) }
                    else if eq_bytes(key, b"os") { Some((6, Shape::Text)) }
                    else if eq_bytes(key, b"arch") { Some((7, Shape::Text)) }
                    else if eq_bytes(key, b"created") { Some((8, Shape::Text)) }
                    else if eq_bytes(key, b"entrypoint") { Some((9, Shape::Text)) }
                    else if eq_bytes(key, b"cmd") { Some((10, Shape::Text)) }
                    else if eq_bytes(key, b"repo_tags") { Some((11, Shape::Texts)) }
                    else if eq_bytes(key, b"digest") { Some((12, Shape::Text)) }
                    else if eq_bytes(key, b"uri") { Some((13, Shape::Text)) }
                    else { None }
                },
                Kind::FactReported => None,
            }
        },
        Schema::Package => {
            if eq_bytes(key, b"purl") { Some((0, Shape::Text)) }
            else if eq_bytes(key, b"name") { Some((1, Shape::Text)) }
            else if eq_bytes(key, b"version") { Some((2, Shape::Text)) }
            else if eq_bytes(key, b"component_type") { Some((3, Shape::Text)) }
            else if eq_bytes(key, b"license") { Some((4, Shape::MaybeText)) }
            else if eq_bytes(key, b"source") { Some((5, Shape::MaybeText)) }
            else { None }
        },
        Schema::Edge => {
            if eq_bytes(key, b"from_ref") { Some((0, Shape::Text)) }
            else if eq_bytes(key, b"to_refs") { Some((1, Shape::Texts)) }
            else { None }
        },
        Schema::Layer => {
            if eq_bytes(key, b"order") { Some((0, Shape::Int(u32::MAX as u64))) }
            else if eq_bytes(key, b"diff_id") { Some((1, Shape::Text)) }
            else if eq_bytes(key, b"tar_path") { Some((2, Shape::Text)) }
            else { None }
        },
    }
}

/// Whether every field `schema` must have is among those `seen`.
fn complete(schema: Schema, seen: &[bool; KEYS]) -> bool {
    let mut place: usize = 0;
    while place < KEYS
        invariant
            place <= KEYS,
        decreases KEYS - place,
    {
        if !seen[place] && required(schema, place) {
            return false;
        }
        place += 1;
    }
    true
}

/// Whether the field at `place` of `schema` must be there: the places `field` gives with `true`.
fn required(schema: Schema, place: usize) -> bool {
    match schema {
        Schema::Report(kind) => {
            place == 0 || match kind {
                Kind::StageStarted => 2 <= place && place <= 4,
                Kind::StageCompleted => 2 <= place && place <= 6,
                Kind::SecurityAdvisoryFound => place == 2 || place == 3,
                Kind::PackageStatusFound => 2 <= place && place <= 5,
                Kind::ArtifactProduced => place == 2 || place == 3,
                Kind::SbomAnalyzed => place == 2 || place == 3 || place == 5 || place == 6,
                Kind::BinaryLinked => 2 <= place && place <= 5,
                Kind::ContainerImageCreated => 2 <= place && place <= 5,
                Kind::FactReported => false,
            }
        },
        Schema::Package => place <= 3,
        Schema::Edge => place <= 1,
        Schema::Layer => place <= 1,
    }
}

/// The token at `at`, if the tape has one there.
fn token(tape: &Tape, at: usize) -> (r: Result<Token, Refusal>)
    ensures
        r is Ok ==> at < tape.tokens@.len() && at < usize::MAX,
{
    if at < tape.tokens.len() { Ok(tape.tokens[at]) } else { Err(Refusal::NotAValue) }
}

/// Where the value at `at` ends on the tape: past a container's tokens, or past the one token of anything else. A
/// container that says it ends at or before itself, or past the tape, is not one the parser made, and is refused.
fn skip(tape: &Tape, at: usize) -> (r: Result<usize, Refusal>)
    ensures
        r matches Ok(next) ==> at < next <= tape.tokens@.len(),
{
    match token(tape, at)? {
        Token::Object { end, .. } | Token::List { end, .. } => {
            let end = end as usize;
            if end <= at || end > tape.tokens.len() { Err(Refusal::NotAValue) } else { Ok(end) }
        },
        _ => Ok(at + 1),
    }
}

/// The bytes of a span, if it lies inside the line.
fn span(text: &[u8], start: u32, end: u32) -> Result<&[u8], Refusal> {
    let (start, end) = (start as usize, end as usize);
    if start <= end && end <= text.len() {
        Ok(vstd::slice::slice_subrange(text, start, end))
    } else {
        Err(Refusal::NotAValue)
    }
}

/// The value at `at` against `shape`: where it ends on the tape.
fn check_value(text: &[u8], tape: &Tape, at: usize, shape: Shape) -> (r: Result<usize, Refusal>)
    ensures
        r matches Ok(next) ==> at < next <= tape.tokens@.len(),
    decreases shape_rank(shape) * 3 + 2,
{
    let t = token(tape, at)?;
    match shape {
        Shape::Text => {
            if let Token::Text { .. } = t { Ok(at + 1) } else { Err(Refusal::WrongType) }
        },
        Shape::MaybeText | Shape::Ignored => match t {
            Token::Text { .. } | Token::Null => Ok(at + 1),
            _ => Err(Refusal::WrongType),
        },
        Shape::Int(max) => match t {
            Token::Int(n) => if n <= max { Ok(at + 1) } else { Err(Refusal::NumberTooLarge) },
            _ => Err(Refusal::WrongType),
        },
        Shape::Outcome => match t {
            Token::Text { start, end } => {
                let word = span(text, start, end)?;
                if eq_bytes(word, b"succeeded") || eq_bytes(word, b"failed") || eq_bytes(word, b"skipped")
                    || eq_bytes(word, b"cancelled") {
                    Ok(at + 1)
                } else {
                    Err(Refusal::UnknownWord)
                }
            },
            _ => Err(Refusal::WrongType),
        },
        Shape::Texts => {
            let end = list_end(tape, at)?;
            let mut i = at + 1;
            while i < end
                invariant
                    at < i <= end <= tape.tokens@.len(),
                decreases end - i,
            {
                if let Token::Text { .. } = token(tape, i)? { i += 1; } else { return Err(Refusal::WrongType); }
            }
            Ok(end)
        },
        Shape::MaybePackage => match t {
            Token::Null => Ok(at + 1),
            _ => check_object(text, tape, at, Schema::Package),
        },
        Shape::Packages => check_objects(text, tape, at, Schema::Package),
        Shape::Edges => check_objects(text, tape, at, Schema::Edge),
        Shape::Layers => check_objects(text, tape, at, Schema::Layer),
    }
}

/// Where the list at `at` ends.
fn list_end(tape: &Tape, at: usize) -> (r: Result<usize, Refusal>)
    ensures
        r matches Ok(end) ==> at < end <= tape.tokens@.len(),
{
    match token(tape, at)? {
        Token::List { .. } => skip(tape, at),
        _ => Err(Refusal::WrongType),
    }
}

/// A list at `at` whose every item is an object of `schema`.
fn check_objects(text: &[u8], tape: &Tape, at: usize, schema: Schema) -> (r: Result<usize, Refusal>)
    requires
        rank(schema) == 1,
    ensures
        r matches Ok(next) ==> at < next <= tape.tokens@.len(),
    decreases rank(schema) * 3 + 1,
{
    let end = list_end(tape, at)?;
    let mut i = at + 1;
    while i < end
        invariant
            at < i <= end <= tape.tokens@.len(),
            rank(schema) == 1,
        decreases end - i,
    {
        let next = check_object(text, tape, i, schema)?;
        if next > end {
            return Err(Refusal::NotAValue);
        }
        i = next;
    }
    Ok(end)
}

/// The object at `at` against `schema`: every key one of the schema's, at most once, every value of its field's shape, and
/// every field the schema must have there.
fn check_object(text: &[u8], tape: &Tape, at: usize, schema: Schema) -> (r: Result<usize, Refusal>)
    ensures
        r matches Ok(next) ==> at < next <= tape.tokens@.len(),
    decreases rank(schema) * 3,
{
    let end = match token(tape, at)? {
        Token::Object { .. } => skip(tape, at)?,
        _ => return Err(Refusal::WrongType),
    };
    let mut seen = [false; KEYS];
    let mut i = at + 1;
    while i < end
        invariant
            at < i <= end <= tape.tokens@.len(),
        decreases end - i,
    {
        let (start, stop) = match token(tape, i)? {
            Token::Key { start, end } => (start, end),
            _ => return Err(Refusal::NotAValue),
        };
        let key = span(text, start, stop)?;
        let (place, shape) = match field(schema, key) {
            Some(f) => f,
            None => return Err(Refusal::UnknownKey),
        };
        if seen[place] {
            return Err(Refusal::DuplicateKey);
        }
        seen[place] = true;
        if i + 1 >= end {
            return Err(Refusal::NotAValue);
        }
        let next = check_value(text, tape, i + 1, shape)?;
        if next > end {
            return Err(Refusal::NotAValue);
        }
        i = next;
    }
    if complete(schema, &seen) { Ok(end) } else { Err(Refusal::MissingKey) }
}

/// The kind the report on `tape` says it is, by its `type`, which must be a kind a build may report.
fn kind_of(text: &[u8], tape: &Tape) -> (r: Result<Kind, Refusal>) {
    let end = match token(tape, 0)? {
        Token::Object { .. } => skip(tape, 0)?,
        _ => return Err(Refusal::NotAnObject),
    };
    let mut i: usize = 1;
    while i < end
        invariant
            0 < i <= end <= tape.tokens@.len(),
        decreases end - i,
    {
        let (start, stop) = match token(tape, i)? {
            Token::Key { start, end } => (start, end),
            _ => return Err(Refusal::NotAValue),
        };
        if i + 1 >= end {
            return Err(Refusal::NotAValue);
        }
        if eq_bytes(span(text, start, stop)?, b"type") {
            return match token(tape, i + 1)? {
                Token::Text { start, end } => match kind_named(span(text, start, end)?) {
                    Some(kind) => Ok(kind),
                    None => Err(Refusal::UnknownKind),
                },
                _ => Err(Refusal::WrongType),
            };
        }
        let next = skip(tape, i + 1)?;
        if next > end {
            return Err(Refusal::NotAValue);
        }
        i = next;
    }
    Err(Refusal::UnknownKind)
}

/// Checks a parsed line against the grammar of a report: its kind, by `type`, one a build may report; and for it, every
/// field named, typed and where it must be, an unknown field refused. Whatever `text` and `tape` are (the parser's, or
/// any other), it returns, never panics, and reads nothing outside either; it allocates nothing.
pub fn check(text: &[u8], tape: &Tape) -> (r: Result<Kind, Refusal>) {
    let kind = kind_of(text, tape)?;
    check_object(text, tape, 0, Schema::Report(kind))?;
    if tape.tokens.len() != skip(tape, 0)? {
        return Err(Refusal::Trailing);
    }
    Ok(kind)
}

} // verus!
