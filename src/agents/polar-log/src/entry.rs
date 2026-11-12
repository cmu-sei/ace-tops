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

//! What a log holds (docs/architecture/record-store.md, "The shape"). An [`Entry`] is what its writer made: the event's
//! type, its version, whether a reader that does not know it must stop (critical, as X.509 marks an extension), the
//! writer's platform version, and the event itself as opaque bytes, so a reader learns all of that before it decodes, or
//! passes over, an event it does not know. A [`Leaf`] is what the log appends: the entry's bytes, when the log admitted
//! it, and who brought it, all in what is hashed. A [`Continuation`] is the first entry of a log that carries on an
//! older one.

use crate::cbor::{CborError, Decoder, Encoder};
use thiserror::Error;

/// Why bytes are not an entry, a leaf or a continuation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FormatError {
    #[error(transparent)]
    Cbor(#[from] CborError),
    #[error("an entry's type `{0}` is not a name of lower-case letters, digits, `.` and `-`")]
    Kind(String),
    #[error("an entry names no writer")]
    NoWriter,
    #[error("a leaf names no submitter")]
    NoSubmitter,
}

/// The longest type name.
pub const MAX_KIND: usize = 128;

/// Whether `kind` may name a type: 1 to [`MAX_KIND`] characters of `a-z`, `0-9`, `.` and `-`.
pub fn is_kind(kind: &str) -> bool {
    !kind.is_empty()
        && kind.len() <= MAX_KIND
        && kind
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
}

/// What a writer appends: an envelope readable before the event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The event's type (`evidence-record`, `credentials.revoke`): its name, never its shape.
    pub kind: String,
    /// The version of that type's shape.
    pub version: u64,
    /// Whether a reader that does not know this type and version must stop rather than pass over it.
    pub critical: bool,
    /// The writer's platform version, as polar-version's record gives it: a semver and the target, never a commit.
    pub writer: String,
    /// The event, encoded as its type and version say; opaque here.
    pub event: Vec<u8>,
}

impl Entry {
    /// The entry's one encoding: `{0: type, 1: version, 2: critical, 3: writer, 4: event}`.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.map(5)
            .key(0)
            .text(&self.kind)
            .key(1)
            .unsigned(self.version)
            .key(2)
            .boolean(self.critical)
            .key(3)
            .text(&self.writer)
            .key(4)
            .bytes(&self.event);
        e.finish()
    }

    /// The entry `bytes` hold, refused unless they are its one encoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let mut d = Decoder::new(bytes);
        d.map(5)?;
        d.key(0)?;
        let kind = d.text()?.to_string();
        d.key(1)?;
        let version = d.unsigned()?;
        d.key(2)?;
        let critical = d.boolean()?;
        d.key(3)?;
        let writer = d.text()?.to_string();
        d.key(4)?;
        let event = d.bytes()?.to_vec();
        d.end()?;
        if !is_kind(&kind) {
            return Err(FormatError::Kind(kind));
        }
        if writer.is_empty() {
            return Err(FormatError::NoWriter);
        }
        Ok(Self {
            kind,
            version,
            critical,
            writer,
            event,
        })
    }
}

/// What the log appends and hashes: an entry as its writer encoded it, when the log took it, and who brought it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    /// The entry's bytes, as written: [`Entry::decode`] reads them.
    pub entry: Vec<u8>,
    /// When the log admitted it, in Unix milliseconds: the log's word, never the writer's.
    pub admitted_at_ms: u64,
    /// Who brought it, as the broker or the TLS layer stamped them; the event's own signature says who made it.
    pub submitter: String,
}

impl Leaf {
    /// The leaf's one encoding: `{0: entry, 1: admitted at, 2: submitter}`.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.map(3)
            .key(0)
            .bytes(&self.entry)
            .key(1)
            .unsigned(self.admitted_at_ms)
            .key(2)
            .text(&self.submitter);
        e.finish()
    }

    /// The leaf `bytes` hold, refused unless they are its one encoding. The entry inside is not decoded here.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let mut d = Decoder::new(bytes);
        d.map(3)?;
        d.key(0)?;
        let entry = d.bytes()?.to_vec();
        d.key(1)?;
        let admitted_at_ms = d.unsigned()?;
        d.key(2)?;
        let submitter = d.text()?.to_string();
        d.end()?;
        if submitter.is_empty() {
            return Err(FormatError::NoSubmitter);
        }
        Ok(Self {
            entry,
            admitted_at_ms,
            submitter,
        })
    }
}

/// The type of a log's first entry when it carries on an older one.
pub const CONTINUATION: &str = "polar.log.continues";

/// A log carrying on an older one: what the old one was, and its end, named by a digest tagged with its algorithm (a
/// git repository's last commit is a SHA-1 id; a JSON ledger's last line a SHA-256), and how many entries it held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Continuation {
    /// What the old log was: `git`, `jsonl`, `polar-log`.
    pub old_kind: String,
    /// The digest's algorithm: `sha1`, `sha256`.
    pub alg: String,
    pub digest: Vec<u8>,
    pub count: u64,
}

impl Continuation {
    pub const VERSION: u64 = 1;

    /// The continuation's event bytes: `{0: old kind, 1: algorithm, 2: digest, 3: count}`.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.map(4)
            .key(0)
            .text(&self.old_kind)
            .key(1)
            .text(&self.alg)
            .key(2)
            .bytes(&self.digest)
            .key(3)
            .unsigned(self.count);
        e.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let mut d = Decoder::new(bytes);
        d.map(4)?;
        d.key(0)?;
        let old_kind = d.text()?.to_string();
        d.key(1)?;
        let alg = d.text()?.to_string();
        d.key(2)?;
        let digest = d.bytes()?.to_vec();
        d.key(3)?;
        let count = d.unsigned()?;
        d.end()?;
        Ok(Self {
            old_kind,
            alg,
            digest,
            count,
        })
    }

    /// The continuation as its log's first entry: critical, since a reader that does not know it cannot tell what
    /// the log's history begins with.
    pub fn entry(&self, writer: &str) -> Entry {
        Entry {
            kind: CONTINUATION.to_string(),
            version: Self::VERSION,
            critical: true,
            writer: writer.to_string(),
            event: self.encode(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        Entry {
            kind: "evidence-record".to_string(),
            version: 1,
            critical: true,
            writer: "3.1.0 x86_64-unknown-linux-musl".to_string(),
            event: b"{\"payload\":{}}".to_vec(),
        }
    }

    #[test]
    fn an_entry_reads_back_as_itself_and_its_envelope_comes_before_the_event() {
        let bytes = entry().encode();
        assert_eq!(Entry::decode(&bytes), Ok(entry()));
        // A reader that stops after the writer has read everything but the event.
        let mut d = Decoder::new(&bytes);
        d.map(5).unwrap();
        d.key(0).unwrap();
        assert_eq!(d.text(), Ok("evidence-record"));
        d.key(1).unwrap();
        assert_eq!(d.unsigned(), Ok(1));
        d.key(2).unwrap();
        assert_eq!(d.boolean(), Ok(true));
        d.key(3).unwrap();
        assert!(d.text().is_ok());
    }

    #[test]
    fn a_type_that_is_no_name_or_a_missing_writer_is_refused() {
        for kind in ["", "Evidence", "a b", "a/b", &"x".repeat(MAX_KIND + 1)] {
            let bytes = Entry {
                kind: kind.to_string(),
                ..entry()
            }
            .encode();
            assert_eq!(
                Entry::decode(&bytes),
                Err(FormatError::Kind(kind.to_string())),
                "{kind:?}"
            );
        }
        assert!(is_kind(&"x".repeat(MAX_KIND)));
        let bytes = Entry {
            writer: String::new(),
            ..entry()
        }
        .encode();
        assert_eq!(Entry::decode(&bytes), Err(FormatError::NoWriter));
    }

    #[test]
    fn a_leaf_carries_the_entry_as_written_and_names_who_brought_it() {
        let leaf = Leaf {
            entry: entry().encode(),
            admitted_at_ms: 1_794_356_365_123,
            submitter: "attestation-agent.polar.serviceaccount.cluster.local".to_string(),
        };
        assert_eq!(Leaf::decode(&leaf.encode()), Ok(leaf.clone()));
        let nobody = Leaf {
            submitter: String::new(),
            ..leaf
        };
        assert_eq!(
            Leaf::decode(&nobody.encode()),
            Err(FormatError::NoSubmitter)
        );
    }

    #[test]
    fn a_continuation_names_the_old_log_s_end_by_a_tagged_digest_and_is_critical() {
        let c = Continuation {
            old_kind: "git".to_string(),
            alg: "sha1".to_string(),
            digest: vec![0xab; 20],
            count: 38,
        };
        assert_eq!(Continuation::decode(&c.encode()), Ok(c.clone()));
        let e = c.entry("3.1.0 x86_64-unknown-linux-musl");
        assert_eq!(e.kind, CONTINUATION);
        assert!(e.critical);
        assert_eq!(Continuation::decode(&e.event), Ok(c));
    }
}
