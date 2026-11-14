/*
   ACE Tool

   Copyright 2026 Carnegie Mellon University.

   NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS
   FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
   EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
   PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE
   MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
   TRADEMARK, OR COPYRIGHT INFRINGEMENT.

   Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu
   for full terms.

   [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited
   distribution.  Please see Copyright notice for non-US Government use and distribution.

   This Software includes and/or makes use of Third-Party Software each subject to its own license.

   DM26-0670
*/

//! The schedules log (docs/architecture/record-store.md, "Bite 6"). polar-schedules is a tree of files, each new
//! version of a section written over the one before at its place, so its log carries changes to the tree: a file's
//! whole bytes, or its removal. The tree is derived from them. The store appends what a push or its own start changes;
//! the scheduler observer and polar-eden derive the tree as of any entry.

use polar_log::cbor::{CborError, Decoder, Encoder};
use polar_log::entry::{CONTINUATION, Entry};
use std::collections::BTreeMap;

/// The log polar-schedules' changes are kept in.
pub const SCHEDULES_LOG: &str = "schedules";

/// A file of the tree, its whole bytes: `{0: path, 1: bytes}`.
pub const FILE: &str = "schedules-file";

/// A file taken out of the tree: `{0: path}`.
pub const REMOVAL: &str = "schedules-removal";

/// The version of both types' shape this code writes and reads.
pub const VERSION: u64 = 1;

/// One change to the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    File { path: String, bytes: Vec<u8> },
    Removal { path: String },
}

impl Change {
    pub fn path(&self) -> &str {
        match self {
            Change::File { path, .. } | Change::Removal { path } => path,
        }
    }

    /// The change as an entry: critical, since a reader that passed over it would derive the wrong tree.
    pub fn entry(&self, writer: &str) -> Entry {
        let mut e = Encoder::new();
        let kind = match self {
            Change::File { path, bytes } => {
                e.map(2).key(0).text(path).key(1).bytes(bytes);
                FILE
            }
            Change::Removal { path } => {
                e.map(1).key(0).text(path);
                REMOVAL
            }
        };
        Entry {
            kind: kind.to_string(),
            version: VERSION,
            critical: true,
            writer: writer.to_string(),
            event: e.finish(),
        }
    }

    /// The change `entry` is, when it is of the schedules log's types at this version: none for any other entry, and
    /// why for one of those types whose event is not its one encoding, or names no path.
    pub fn of(entry: &Entry) -> Option<Result<Self, String>> {
        if entry.version != VERSION {
            return None;
        }
        let decoded = match entry.kind.as_str() {
            FILE => decode_file(&entry.event),
            REMOVAL => decode_removal(&entry.event),
            _ => return None,
        };
        Some(
            decoded
                .map_err(|e| e.to_string())
                .and_then(|change| match change.path() {
                    "" => Err("a change names no path".to_string()),
                    _ => Ok(change),
                }),
        )
    }
}

fn decode_file(event: &[u8]) -> Result<Change, CborError> {
    let mut d = Decoder::new(event);
    d.map(2)?;
    d.key(0)?;
    let path = d.text()?.to_string();
    d.key(1)?;
    let bytes = d.bytes()?.to_vec();
    d.end()?;
    Ok(Change::File { path, bytes })
}

fn decode_removal(event: &[u8]) -> Result<Change, CborError> {
    let mut d = Decoder::new(event);
    d.map(1)?;
    d.key(0)?;
    let path = d.text()?.to_string();
    d.end()?;
    Ok(Change::Removal { path })
}

/// Where a reading of the log stopped, and why: the tree is the one the entries before it make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// A critical entry of a type or version this does not know: a newer writer's, which a newer reader reads.
    Unknown {
        seq: u64,
        kind: String,
        version: u64,
    },
    /// An entry that is not one, or one of the log's own types that does not decode: damage or a writer's fault, never
    /// passed over.
    Malformed { seq: u64, why: String },
}

impl std::fmt::Display for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Stop::Unknown { seq, kind, version } => write!(
                f,
                "entry {seq} is of type {kind} version {version}, which this reader does not know and must not pass over"
            ),
            Stop::Malformed { seq, why } => write!(f, "entry {seq} is malformed: {why}"),
        }
    }
}

/// The files of polar-schedules as the log has them, by path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tree {
    files: BTreeMap<String, Vec<u8>>,
}

impl Tree {
    pub fn from_files(files: BTreeMap<String, Vec<u8>>) -> Self {
        Self { files }
    }

    pub fn files(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }

    /// The tree after `change`: a file put at its path, over what was there; a removal takes its path away.
    pub fn change(&mut self, change: &Change) {
        match change {
            Change::File { path, bytes } => {
                self.files.insert(path.clone(), bytes.clone());
            }
            Change::Removal { path } => {
                self.files.remove(path);
            }
        }
    }

    /// What makes this tree `to`: each file it holds that `to` does not, removed, then each file of `to` it does not hold
    /// with those bytes; each in path order. Nothing when the two are the same.
    pub fn changes_to(&self, to: &BTreeMap<String, Vec<u8>>) -> Vec<Change> {
        let removals = self
            .files
            .keys()
            .filter(|path| !to.contains_key(*path))
            .map(|path| Change::Removal { path: path.clone() });
        let files = to
            .iter()
            .filter(|(path, bytes)| self.files.get(*path) != Some(*bytes))
            .map(|(path, bytes)| Change::File {
                path: path.clone(),
                bytes: bytes.clone(),
            });
        removals.chain(files).collect()
    }

    /// The tree after the entry `entry` (its bytes, as a leaf carries them) at sequence `seq`, and the change it made. A
    /// continuation, or another type's entry that is not critical, changes nothing; a critical entry this does not know,
    /// or a malformed one, stops the reading, and the tree is left as it was.
    pub fn apply(&mut self, seq: u64, entry: &[u8]) -> Result<Option<Change>, Stop> {
        let entry = Entry::decode(entry).map_err(|e| Stop::Malformed {
            seq,
            why: e.to_string(),
        })?;
        match Change::of(&entry) {
            Some(Ok(change)) => {
                self.change(&change);
                Ok(Some(change))
            }
            Some(Err(why)) => Err(Stop::Malformed { seq, why }),
            None if entry.kind == CONTINUATION || !entry.critical => Ok(None),
            None => Err(Stop::Unknown {
                seq,
                kind: entry.kind,
                version: entry.version,
            }),
        }
    }
}

/// The tree the log's leaves (each a leaf's encoding) make, in order, and where it stopped if it did.
pub fn replay(leaves: &[Vec<u8>]) -> (Tree, Option<Stop>) {
    let mut tree = Tree::default();
    for (seq, bytes) in leaves.iter().enumerate() {
        let seq = seq as u64;
        let applied = polar_log::entry::Leaf::decode(bytes)
            .map_err(|e| Stop::Malformed {
                seq,
                why: e.to_string(),
            })
            .and_then(|leaf| tree.apply(seq, &leaf.entry));
        if let Err(stop) = applied {
            return (tree, Some(stop));
        }
    }
    (tree, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_log::entry::{Continuation, Leaf};

    const WRITER: &str = "3.1.0 x86_64-unknown-linux-musl";

    fn file(path: &str, text: &str) -> Change {
        Change::File {
            path: path.into(),
            bytes: text.into(),
        }
    }

    fn removal(path: &str) -> Change {
        Change::Removal { path: path.into() }
    }

    fn leaf(entry: &Entry) -> Vec<u8> {
        Leaf {
            entry: entry.encode(),
            admitted_at_ms: 1,
            submitter: "alice".into(),
        }
        .encode()
    }

    fn files(pairs: &[(&str, &str)]) -> BTreeMap<String, Vec<u8>> {
        pairs
            .iter()
            .map(|(p, t)| (p.to_string(), t.as_bytes().to_vec()))
            .collect()
    }

    /// Each change comes back from its entry as it went in, critical, at this version; an entry of another type is none
    /// of the log's.
    #[test]
    fn a_change_survives_its_entry_and_another_type_is_not_one() {
        for change in [
            file("permanent/a/configuration.dhall", "x"),
            removal("adhoc/b.dhall"),
        ] {
            let entry = change.entry(WRITER);
            assert!(entry.critical);
            assert_eq!(entry.version, VERSION);
            let back = Entry::decode(&entry.encode()).unwrap();
            assert_eq!(Change::of(&back), Some(Ok(change)));
        }
        let mut other = file("a", "x").entry(WRITER);
        other.kind = "evidence-record".into();
        assert_eq!(Change::of(&other), None);
        let mut newer = file("a", "x").entry(WRITER);
        newer.version = VERSION + 1;
        assert_eq!(Change::of(&newer), None);
    }

    #[test]
    fn a_change_that_names_no_path_or_does_not_decode_is_malformed() {
        assert!(matches!(
            Change::of(&file("", "x").entry(WRITER)),
            Some(Err(_))
        ));
        assert!(matches!(
            Change::of(&removal("").entry(WRITER)),
            Some(Err(_))
        ));
        // A file's event read as a removal's, and the other way, each has the wrong number of keys.
        let mut swapped = file("a", "x").entry(WRITER);
        swapped.kind = REMOVAL.into();
        assert!(matches!(Change::of(&swapped), Some(Err(_))));
        let mut swapped = removal("a").entry(WRITER);
        swapped.kind = FILE.into();
        assert!(matches!(Change::of(&swapped), Some(Err(_))));
    }

    /// A continuation and another type's entry that is not critical are passed over; a critical one this does not know
    /// stops the reading where it is, the tree as the entries before it made it; so does a leaf that is not one.
    #[test]
    fn the_replay_passes_over_what_it_may_and_stops_at_what_it_must_not() {
        let continuation = Continuation {
            old_kind: "git".into(),
            alg: "sha1".into(),
            digest: vec![7; 20],
            count: 3,
        }
        .entry(WRITER);
        let mut optional = file("a", "x").entry(WRITER);
        optional.kind = "schedules-note".into();
        optional.critical = false;
        let mut unknown = optional.clone();
        unknown.critical = true;
        let leaves = vec![
            leaf(&continuation),
            leaf(&file("a", "1").entry(WRITER)),
            leaf(&optional),
            leaf(&file("b", "2").entry(WRITER)),
            leaf(&unknown),
            leaf(&file("c", "3").entry(WRITER)),
        ];
        let (tree, stop) = replay(&leaves);
        assert_eq!(tree.files(), &files(&[("a", "1"), ("b", "2")]));
        assert_eq!(
            stop,
            Some(Stop::Unknown {
                seq: 4,
                kind: "schedules-note".into(),
                version: VERSION
            })
        );
        let said = stop.clone().unwrap().to_string();
        assert!(
            said.contains("entry 4") && said.contains("schedules-note"),
            "{said}"
        );
        let (tree, stop) = replay(&[leaf(&file("a", "1").entry(WRITER)), b"not a leaf".to_vec()]);
        assert_eq!(tree.files(), &files(&[("a", "1")]));
        assert!(
            matches!(stop, Some(Stop::Malformed { seq: 1, .. })),
            "{stop:?}"
        );
        assert!(
            stop.unwrap()
                .to_string()
                .starts_with("entry 1 is malformed")
        );
    }

    #[test]
    fn the_changes_to_a_tree_remove_first_then_write_and_are_none_between_equals() {
        let from = Tree::from_files(files(&[("a", "1"), ("b", "2"), ("c", "3")]));
        let to = files(&[("b", "2"), ("c", "4"), ("d", "5")]);
        assert_eq!(
            from.changes_to(&to),
            vec![removal("a"), file("c", "4"), file("d", "5")]
        );
        assert!(Tree::from_files(to.clone()).changes_to(&to).is_empty());
    }

    mod props {
        use super::*;
        use proptest::prelude::*;

        fn tree() -> impl Strategy<Value = BTreeMap<String, Vec<u8>>> {
            proptest::collection::btree_map(
                "[ab]/[xyz]",
                proptest::collection::vec(0u8..3, 0..3),
                0..5,
            )
        }

        fn change() -> impl Strategy<Value = Change> {
            prop_oneof![
                ("[ab]/[xyz]", proptest::collection::vec(0u8..3, 0..3))
                    .prop_map(|(path, bytes)| Change::File { path, bytes }),
                "[ab]/[xyz]".prop_map(|path| Change::Removal { path }),
            ]
        }

        fn leaves(changes: &[Change]) -> Vec<Vec<u8>> {
            changes.iter().map(|c| leaf(&c.entry(WRITER))).collect()
        }

        proptest! {
            /// Applying the changes from one tree to another gives the other, whatever the two were.
            #[test]
            fn the_changes_from_a_to_b_applied_to_a_give_b(a in tree(), b in tree()) {
                let mut tree = Tree::from_files(a.clone());
                for change in Tree::from_files(a).changes_to(&b) {
                    tree.change(&change);
                }
                prop_assert_eq!(tree.files(), &b);
            }

            /// The tree a log makes does not depend on how its changes were split among pushes: replaying the log
            /// whole, or tree by tree with each push's changes worked out against the tree before it, ends alike, and a
            /// path removed and written again holds its file.
            #[test]
            fn the_tree_is_the_last_word_on_each_path_however_the_pushes_fell(
                pushes in proptest::collection::vec(tree(), 0..5),
            ) {
                let mut log = Vec::new();
                let mut store = Tree::default();
                for push in &pushes {
                    let changes = store.changes_to(push);
                    for change in &changes {
                        store.change(change);
                    }
                    log.extend(changes);
                }
                let (replayed, stop) = replay(&leaves(&log));
                prop_assert_eq!(stop, None);
                prop_assert_eq!(replayed.files(), store.files());
                let last = pushes.last().cloned().unwrap_or_default();
                prop_assert_eq!(store.files(), &last);
            }

            /// Replaying entries gives the tree each change, applied in order, gives: the file last written at each path,
            /// unless a removal came after it.
            #[test]
            fn a_replayed_tree_holds_each_paths_last_file_unless_removed_after(
                changes in proptest::collection::vec(change(), 0..12),
            ) {
                let (tree, stop) = replay(&leaves(&changes));
                prop_assert_eq!(stop, None);
                let mut last: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
                for change in &changes {
                    match change {
                        Change::File { path, bytes } => last.insert(path.clone(), Some(bytes.clone())),
                        Change::Removal { path } => last.insert(path.clone(), None),
                    };
                }
                let expected: BTreeMap<String, Vec<u8>> =
                    last.into_iter().filter_map(|(p, b)| b.map(|b| (p, b))).collect();
                prop_assert_eq!(tree.files(), &expected);
            }
        }
    }
}
