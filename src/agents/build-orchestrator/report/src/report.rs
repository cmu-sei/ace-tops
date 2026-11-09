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

//! A checked report, decoded into owned values: the one step that allocates, and the one not proved. It runs after
//! [`check`](crate::check), outside the locked-down worker (build-orchestrator.md, O2d2), and holds itself to the tape it is
//! given all the same: anything it cannot read is refused, never assumed.

use crate::{Bounds, HEADER, Kind, RECORD, Refusal, Tape, Token, check, kind_code, refusal_code};

/// What a build reported, as Polar's event types (`polar::events`) have it, without a `build_id`: the orchestrator stamps
/// its own on what it relays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Report {
    StageStarted {
        stage_name: String,
        stage_id: String,
        at: String,
    },
    StageCompleted {
        stage_name: String,
        stage_id: String,
        duration_secs: u64,
        outcome: StageOutcome,
        at: String,
    },
    SecurityAdvisoryFound(SecurityAdvisoryFound),
    PackageStatusFound(PackageStatusFound),
    ArtifactProduced {
        artifact_content_hash: String,
        artifact_type: String,
        name: String,
        content_type: String,
    },
    SbomAnalyzed(SbomAnalyzed),
    BinaryLinked {
        binary_content_hash: String,
        binary_name: String,
        root_purl: String,
        sbom_content_hash: String,
        binding_digest: String,
    },
    ContainerImageCreated(ContainerImageCreated),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageOutcome {
    Succeeded,
    Failed,
    Skipped,
    Cancelled,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityAdvisoryFound {
    pub severity: String,
    pub identifier: String,
    pub in_artifact: Option<String>,
    pub kind: Option<String>,
    pub scanner: Option<String>,
    pub affected_package: Option<String>,
    pub cve_id: Option<String>,
    pub ghsa_id: Option<String>,
    pub fix_version: Option<String>,
    pub unaffected_constraint: Option<String>,
    pub advisory_url: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackageStatusFound {
    pub kind: String,
    pub identifier: String,
    pub package_name: String,
    pub package_version: String,
    pub in_artifact: Option<String>,
    pub affected_package: Option<String>,
    pub advisory_url: Option<String>,
    pub scanner: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackageRef {
    pub purl: String,
    pub name: String,
    pub version: String,
    pub component_type: String,
    pub license: Option<String>,
    pub source: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DependencyEdge {
    pub from_ref: String,
    pub to_refs: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SbomAnalyzed {
    pub artifact_content_hash: String,
    pub filename: String,
    pub root: Option<PackageRef>,
    pub components: Vec<PackageRef>,
    pub edges: Vec<DependencyEdge>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Layer {
    pub order: u32,
    pub diff_id: String,
    pub tar_path: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerImageCreated {
    pub image_name: String,
    pub tarball_hash: String,
    pub config_digest: String,
    pub layers: Vec<Layer>,
    pub os: String,
    pub arch: String,
    pub created: String,
    pub entrypoint: String,
    pub cmd: String,
    pub repo_tags: Vec<String>,
    pub digest: String,
    pub uri: String,
}

impl Report {
    /// The report on `tape`, which [`parse`](crate::parse) made from `text`: checked first, then decoded. A tape that is not
    /// one the parser made from `text` is refused, never read past.
    pub fn read(text: &[u8], tape: &Tape) -> Result<Report, Refusal> {
        let kind = check(text, tape)?;
        let o = Object::at(text, tape, 0)?;
        Ok(match kind {
            Kind::StageStarted => Report::StageStarted {
                stage_name: o.text("stage_name")?,
                stage_id: o.text("stage_id")?,
                at: o.text("at")?,
            },
            Kind::StageCompleted => Report::StageCompleted {
                stage_name: o.text("stage_name")?,
                stage_id: o.text("stage_id")?,
                duration_secs: o.int("duration_secs")?,
                outcome: match o.text("outcome")?.as_str() {
                    "succeeded" => StageOutcome::Succeeded,
                    "failed" => StageOutcome::Failed,
                    "skipped" => StageOutcome::Skipped,
                    "cancelled" => StageOutcome::Cancelled,
                    _ => return Err(Refusal::UnknownWord),
                },
                at: o.text("at")?,
            },
            Kind::SecurityAdvisoryFound => Report::SecurityAdvisoryFound(SecurityAdvisoryFound {
                severity: o.text("severity")?,
                identifier: o.text("identifier")?,
                in_artifact: o.maybe_text("in_artifact")?,
                kind: o.maybe_text("kind")?,
                scanner: o.maybe_text("scanner")?,
                affected_package: o.maybe_text("affected_package")?,
                cve_id: o.maybe_text("cve_id")?,
                ghsa_id: o.maybe_text("ghsa_id")?,
                fix_version: o.maybe_text("fix_version")?,
                unaffected_constraint: o.maybe_text("unaffected_constraint")?,
                advisory_url: o.maybe_text("advisory_url")?,
            }),
            Kind::PackageStatusFound => Report::PackageStatusFound(PackageStatusFound {
                kind: o.text("kind")?,
                identifier: o.text("identifier")?,
                package_name: o.text("package_name")?,
                package_version: o.text("package_version")?,
                in_artifact: o.maybe_text("in_artifact")?,
                affected_package: o.maybe_text("affected_package")?,
                advisory_url: o.maybe_text("advisory_url")?,
                scanner: o.maybe_text("scanner")?,
            }),
            Kind::ArtifactProduced => Report::ArtifactProduced {
                artifact_content_hash: o.text("artifact_content_hash")?,
                artifact_type: o.text("artifact_type")?,
                name: o.text_or_empty("name")?,
                content_type: o.text_or_empty("content_type")?,
            },
            Kind::SbomAnalyzed => Report::SbomAnalyzed(SbomAnalyzed {
                artifact_content_hash: o.text("artifact_content_hash")?,
                filename: o.text("filename")?,
                root: match o.value("root") {
                    Some(at) if tape.tokens.get(at) != Some(&Token::Null) => {
                        Some(package(&Object::at(text, tape, at)?)?)
                    }
                    _ => None,
                },
                components: o
                    .objects("components")?
                    .iter()
                    .map(package)
                    .collect::<Result<_, _>>()?,
                edges: o
                    .objects("edges")?
                    .iter()
                    .map(|e| {
                        Ok(DependencyEdge {
                            from_ref: e.text("from_ref")?,
                            to_refs: e.texts("to_refs")?,
                        })
                    })
                    .collect::<Result<_, Refusal>>()?,
            }),
            Kind::BinaryLinked => Report::BinaryLinked {
                binary_content_hash: o.text("binary_content_hash")?,
                binary_name: o.text("binary_name")?,
                root_purl: o.text("root_purl")?,
                sbom_content_hash: o.text("sbom_content_hash")?,
                binding_digest: o.text_or_empty("binding_digest")?,
            },
            Kind::ContainerImageCreated => Report::ContainerImageCreated(ContainerImageCreated {
                image_name: o.text("image_name")?,
                tarball_hash: o.text("tarball_hash")?,
                config_digest: o.text("config_digest")?,
                layers: o
                    .objects("layers")?
                    .iter()
                    .map(|l| {
                        Ok(Layer {
                            order: u32::try_from(l.int("order")?)
                                .map_err(|_| Refusal::NumberTooLarge)?,
                            diff_id: l.text("diff_id")?,
                            tar_path: l.text_or_empty("tar_path")?,
                        })
                    })
                    .collect::<Result<_, Refusal>>()?,
                os: o.text_or_empty("os")?,
                arch: o.text_or_empty("arch")?,
                created: o.text_or_empty("created")?,
                entrypoint: o.text_or_empty("entrypoint")?,
                cmd: o.text_or_empty("cmd")?,
                repo_tags: match o.value("repo_tags") {
                    Some(_) => o.texts("repo_tags")?,
                    None => Vec::new(),
                },
                digest: o.text_or_empty("digest")?,
                uri: o.text_or_empty("uri")?,
            }),
        })
    }

    /// The kind of report this is.
    pub fn kind(&self) -> Kind {
        match self {
            Report::StageStarted { .. } => Kind::StageStarted,
            Report::StageCompleted { .. } => Kind::StageCompleted,
            Report::SecurityAdvisoryFound(_) => Kind::SecurityAdvisoryFound,
            Report::PackageStatusFound(_) => Kind::PackageStatusFound,
            Report::ArtifactProduced { .. } => Kind::ArtifactProduced,
            Report::SbomAnalyzed(_) => Kind::SbomAnalyzed,
            Report::BinaryLinked { .. } => Kind::BinaryLinked,
            Report::ContainerImageCreated(_) => Kind::ContainerImageCreated,
        }
    }

    /// The report a worker's `answer` says `line` is (build-orchestrator.md, O2d2), on the agent's side: the answer held
    /// to its exact shape and to `bounds`, its tape rebuilt, then checked again and decoded from the line's own bytes, as
    /// [`read`](Self::read) does; and the kind it claims must be the line's. A worker's refusal is taken as said: refusing
    /// is all a lying worker could gain by it. A worker that forged a tape the check passes could make the line say only
    /// what its author could have written, since every value is the line's own bytes.
    pub fn read_answer(line: &[u8], answer: &[u8], bounds: &Bounds) -> Result<Report, Refusal> {
        let word = |at: usize, width: usize| -> Result<u64, Refusal> {
            let bytes = answer.get(at..at + width).ok_or(Refusal::NotAValue)?;
            Ok(bytes
                .iter()
                .rev()
                .fold(0u64, |v, b| (v << 8) | u64::from(*b)))
        };
        let status = word(0, 4)?;
        if status != 0 {
            return Err(refusal_of(status).unwrap_or(Refusal::NotAValue));
        }
        let kind = word(4, 4)?;
        let count = usize::try_from(word(8, 8)?).map_err(|_| Refusal::TooManyTokens)?;
        // Multiplied out checked: under a bound past what a length counts, a forged count must not wrap to a short one.
        let shaped = RECORD
            .checked_mul(count)
            .and_then(|n| n.checked_add(HEADER));
        if count > bounds.tokens || shaped != Some(answer.len()) {
            return Err(Refusal::NotAValue);
        }
        let mut tape = Tape::new(&Bounds {
            tokens: count,
            ..*bounds
        });
        for i in 0..count {
            let at = HEADER + RECORD * i;
            let (tag, a, b) = (word(at, 4)?, word(at + 4, 4)?, word(at + 8, 8)?);
            let (a, b32) = (a as u32, u32::try_from(b));
            tape.tokens.push(match tag {
                1 => Token::Object {
                    members: a,
                    end: b32.map_err(|_| Refusal::NotAValue)?,
                },
                2 => Token::List {
                    items: a,
                    end: b32.map_err(|_| Refusal::NotAValue)?,
                },
                3 => Token::Key {
                    start: a,
                    end: b32.map_err(|_| Refusal::NotAValue)?,
                },
                4 => Token::Text {
                    start: a,
                    end: b32.map_err(|_| Refusal::NotAValue)?,
                },
                5 => Token::Int(b),
                6 => Token::Null,
                _ => return Err(Refusal::NotAValue),
            });
        }
        let report = Report::read(line, &tape)?;
        if u64::from(kind_code(report.kind())) != kind {
            return Err(Refusal::NotAValue);
        }
        Ok(report)
    }

    /// The line a build prints for this report, without [`PREFIX`](crate::PREFIX): one JSON object, as the grammar has
    /// it. What `read` gives back from it is this report.
    pub fn line(&self) -> String {
        let mut w = Writer::default();
        match self {
            Report::StageStarted {
                stage_name,
                stage_id,
                at,
            } => {
                w.kind("stage_started");
                w.text("stage_name", stage_name);
                w.text("stage_id", stage_id);
                w.text("at", at);
            }
            Report::StageCompleted {
                stage_name,
                stage_id,
                duration_secs,
                outcome,
                at,
            } => {
                w.kind("stage_completed");
                w.text("stage_name", stage_name);
                w.text("stage_id", stage_id);
                w.raw("duration_secs", &duration_secs.to_string());
                w.text(
                    "outcome",
                    match outcome {
                        StageOutcome::Succeeded => "succeeded",
                        StageOutcome::Failed => "failed",
                        StageOutcome::Skipped => "skipped",
                        StageOutcome::Cancelled => "cancelled",
                    },
                );
                w.text("at", at);
            }
            Report::SecurityAdvisoryFound(a) => {
                w.kind("security_advisory_found");
                w.text("severity", &a.severity);
                w.text("identifier", &a.identifier);
                w.maybe("in_artifact", &a.in_artifact);
                w.maybe("kind", &a.kind);
                w.maybe("scanner", &a.scanner);
                w.maybe("affected_package", &a.affected_package);
                w.maybe("cve_id", &a.cve_id);
                w.maybe("ghsa_id", &a.ghsa_id);
                w.maybe("fix_version", &a.fix_version);
                w.maybe("unaffected_constraint", &a.unaffected_constraint);
                w.maybe("advisory_url", &a.advisory_url);
            }
            Report::PackageStatusFound(p) => {
                w.kind("package_status_found");
                w.text("kind", &p.kind);
                w.text("identifier", &p.identifier);
                w.text("package_name", &p.package_name);
                w.text("package_version", &p.package_version);
                w.maybe("in_artifact", &p.in_artifact);
                w.maybe("affected_package", &p.affected_package);
                w.maybe("advisory_url", &p.advisory_url);
                w.maybe("scanner", &p.scanner);
            }
            Report::ArtifactProduced {
                artifact_content_hash,
                artifact_type,
                name,
                content_type,
            } => {
                w.kind("artifact_produced");
                w.text("artifact_content_hash", artifact_content_hash);
                w.text("artifact_type", artifact_type);
                w.text("name", name);
                w.text("content_type", content_type);
            }
            Report::SbomAnalyzed(s) => {
                w.kind("sbom_analyzed");
                w.text("artifact_content_hash", &s.artifact_content_hash);
                w.text("filename", &s.filename);
                w.raw("root", &s.root.as_ref().map_or("null".into(), package_line));
                w.raw("components", &list(s.components.iter().map(package_line)));
                w.raw(
                    "edges",
                    &list(s.edges.iter().map(|e| {
                        let mut o = Writer::default();
                        o.text("from_ref", &e.from_ref);
                        o.raw("to_refs", &list(e.to_refs.iter().map(|t| quoted(t))));
                        o.done()
                    })),
                );
            }
            Report::BinaryLinked {
                binary_content_hash,
                binary_name,
                root_purl,
                sbom_content_hash,
                binding_digest,
            } => {
                w.kind("binary_linked");
                w.text("binary_content_hash", binary_content_hash);
                w.text("binary_name", binary_name);
                w.text("root_purl", root_purl);
                w.text("sbom_content_hash", sbom_content_hash);
                w.text("binding_digest", binding_digest);
            }
            Report::ContainerImageCreated(c) => {
                w.kind("container_image_created");
                w.text("image_name", &c.image_name);
                w.text("tarball_hash", &c.tarball_hash);
                w.text("config_digest", &c.config_digest);
                w.raw(
                    "layers",
                    &list(c.layers.iter().map(|l| {
                        let mut o = Writer::default();
                        o.raw("order", &l.order.to_string());
                        o.text("diff_id", &l.diff_id);
                        o.text("tar_path", &l.tar_path);
                        o.done()
                    })),
                );
                w.text("os", &c.os);
                w.text("arch", &c.arch);
                w.text("created", &c.created);
                w.text("entrypoint", &c.entrypoint);
                w.text("cmd", &c.cmd);
                w.raw("repo_tags", &list(c.repo_tags.iter().map(|t| quoted(t))));
                w.text("digest", &c.digest);
                w.text("uri", &c.uri);
            }
        }
        w.done()
    }
}

fn package(o: &Object<'_>) -> Result<PackageRef, Refusal> {
    Ok(PackageRef {
        purl: o.text("purl")?,
        name: o.text("name")?,
        version: o.text("version")?,
        component_type: o.text("component_type")?,
        license: o.maybe_text("license")?,
        source: o.maybe_text("source")?,
    })
}

fn package_line(p: &PackageRef) -> String {
    let mut w = Writer::default();
    w.text("purl", &p.purl);
    w.text("name", &p.name);
    w.text("version", &p.version);
    w.text("component_type", &p.component_type);
    w.maybe("license", &p.license);
    w.maybe("source", &p.source);
    w.done()
}

/// One object on the tape: its members' keys, as written, and where each value is.
struct Object<'a> {
    text: &'a [u8],
    tape: &'a Tape,
    members: Vec<(&'a [u8], usize)>,
}

/// Where the value at `at` ends on the tape.
fn skip(tape: &Tape, at: usize) -> Result<usize, Refusal> {
    match tape.tokens.get(at).ok_or(Refusal::NotAValue)? {
        Token::Object { end, .. } | Token::List { end, .. } => {
            let end = *end as usize;
            if end <= at || end > tape.tokens.len() {
                Err(Refusal::NotAValue)
            } else {
                Ok(end)
            }
        }
        _ => Ok(at + 1),
    }
}

impl<'a> Object<'a> {
    fn at(text: &'a [u8], tape: &'a Tape, at: usize) -> Result<Self, Refusal> {
        let Some(Token::Object { .. }) = tape.tokens.get(at) else {
            return Err(Refusal::WrongType);
        };
        let end = skip(tape, at)?;
        let mut members = Vec::new();
        let mut i = at + 1;
        while i < end {
            let Some(&Token::Key { start, end: stop }) = tape.tokens.get(i) else {
                return Err(Refusal::NotAValue);
            };
            let key = text
                .get(start as usize..stop as usize)
                .ok_or(Refusal::NotAValue)?;
            members.push((key, i + 1));
            i = skip(tape, i + 1)?;
        }
        Ok(Object {
            text,
            tape,
            members,
        })
    }

    fn value(&self, name: &str) -> Option<usize> {
        self.members
            .iter()
            .find(|(key, _)| *key == name.as_bytes())
            .map(|&(_, at)| at)
    }

    fn token(&self, at: usize) -> Result<Token, Refusal> {
        self.tape.tokens.get(at).copied().ok_or(Refusal::NotAValue)
    }

    fn string_at(&self, at: usize) -> Result<String, Refusal> {
        match self.token(at)? {
            Token::Text { start, end } => unescape(
                self.text
                    .get(start as usize..end as usize)
                    .ok_or(Refusal::NotAValue)?,
            ),
            _ => Err(Refusal::WrongType),
        }
    }

    fn text(&self, name: &str) -> Result<String, Refusal> {
        self.string_at(self.value(name).ok_or(Refusal::MissingKey)?)
    }

    fn text_or_empty(&self, name: &str) -> Result<String, Refusal> {
        match self.value(name) {
            Some(at) => self.string_at(at),
            None => Ok(String::new()),
        }
    }

    fn maybe_text(&self, name: &str) -> Result<Option<String>, Refusal> {
        match self.value(name) {
            None => Ok(None),
            Some(at) if self.token(at)? == Token::Null => Ok(None),
            Some(at) => self.string_at(at).map(Some),
        }
    }

    fn int(&self, name: &str) -> Result<u64, Refusal> {
        match self.token(self.value(name).ok_or(Refusal::MissingKey)?)? {
            Token::Int(n) => Ok(n),
            _ => Err(Refusal::WrongType),
        }
    }

    /// The items of the list `name`, as tape positions.
    fn items(&self, name: &str) -> Result<Vec<usize>, Refusal> {
        let at = self.value(name).ok_or(Refusal::MissingKey)?;
        let Token::List { .. } = self.token(at)? else {
            return Err(Refusal::WrongType);
        };
        let end = skip(self.tape, at)?;
        let mut items = Vec::new();
        let mut i = at + 1;
        while i < end {
            items.push(i);
            i = skip(self.tape, i)?;
        }
        Ok(items)
    }

    fn texts(&self, name: &str) -> Result<Vec<String>, Refusal> {
        self.items(name)?
            .into_iter()
            .map(|at| self.string_at(at))
            .collect()
    }

    fn objects(&self, name: &str) -> Result<Vec<Object<'a>>, Refusal> {
        self.items(name)?
            .into_iter()
            .map(|at| Object::at(self.text, self.tape, at))
            .collect()
    }
}

/// A string as written between its quotes, its escapes undone. The parser checked them; whatever it did not make is
/// refused.
fn unescape(raw: &[u8]) -> Result<String, Refusal> {
    let raw = std::str::from_utf8(raw).map_err(|_| Refusal::NotUtf8)?;
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let e = chars.next().ok_or(Refusal::BadEscape)?;
        out.push(match e {
            '"' => '"',
            '\\' => '\\',
            '/' => '/',
            'b' => '\u{8}',
            'f' => '\u{c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'u' => {
                let unit = hex4(&mut chars)?;
                let scalar = if (0xd800..=0xdbff).contains(&unit) {
                    if chars.next() != Some('\\') || chars.next() != Some('u') {
                        return Err(Refusal::BadEscape);
                    }
                    let low = hex4(&mut chars)?;
                    if !(0xdc00..=0xdfff).contains(&low) {
                        return Err(Refusal::BadEscape);
                    }
                    0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00)
                } else {
                    unit
                };
                char::from_u32(scalar).ok_or(Refusal::BadEscape)?
            }
            _ => return Err(Refusal::BadEscape),
        });
    }
    Ok(out)
}

fn hex4(chars: &mut std::str::Chars<'_>) -> Result<u32, Refusal> {
    let mut unit = 0u32;
    for _ in 0..4 {
        unit = unit * 16
            + chars
                .next()
                .and_then(|c| c.to_digit(16))
                .ok_or(Refusal::BadEscape)?;
    }
    Ok(unit)
}

/// A string as JSON writes it: quotes and backslashes escaped, a control character as `\u00XX`.
fn quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn list(items: impl Iterator<Item = String>) -> String {
    format!("[{}]", items.collect::<Vec<_>>().join(", "))
}

/// An object, written a member at a time.
#[derive(Default)]
struct Writer {
    members: Vec<String>,
}

impl Writer {
    fn raw(&mut self, key: &str, value: &str) {
        self.members.push(format!("{}: {value}", quoted(key)));
    }
    fn text(&mut self, key: &str, value: &str) {
        self.raw(key, &quoted(value));
    }
    fn maybe(&mut self, key: &str, value: &Option<String>) {
        self.raw(key, &value.as_deref().map_or("null".into(), quoted));
    }
    fn kind(&mut self, name: &str) {
        self.text("type", name);
    }
    fn done(self) -> String {
        format!("{{{}}}", self.members.join(", "))
    }
}

/// The refusal a worker's answer names by its code (`refusal_code`), if it names one.
fn refusal_of(code: u64) -> Option<Refusal> {
    const ALL: [Refusal; 22] = [
        Refusal::TooLong,
        Refusal::Control,
        Refusal::NotUtf8,
        Refusal::OutsideTheGrammar,
        Refusal::Unbalanced,
        Refusal::TooDeep,
        Refusal::StringTooLong,
        Refusal::NumberTooLarge,
        Refusal::BadNumber,
        Refusal::BadEscape,
        Refusal::TooManyTokens,
        Refusal::TooManyKeys,
        Refusal::TooManyItems,
        Refusal::DuplicateKey,
        Refusal::NotAValue,
        Refusal::Trailing,
        Refusal::NotAnObject,
        Refusal::UnknownKind,
        Refusal::UnknownKey,
        Refusal::MissingKey,
        Refusal::WrongType,
        Refusal::UnknownWord,
    ];
    ALL.into_iter()
        .find(|r| u64::from(refusal_code(*r)) == code)
}
