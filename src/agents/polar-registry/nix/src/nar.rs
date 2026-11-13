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

//! The NAR, the archive Nix moves a store path's files in: one format with one spelling for each tree of files, so a
//! tree has exactly one archive and one hash. Every string is its length (eight bytes, little-endian), its bytes, and
//! zeros to a multiple of eight. The archive is `nix-archive-1` and a node: `(`, `type`, then a regular file
//! (`regular`, `executable` and an empty string if it is one, `contents` and its bytes), a symbolic link (`symlink`,
//! `target` and where it points) or a directory (`directory`, then for each entry in the byte order of its name, `entry`
//! `(` `name` the name `node` a node `)`), and `)`.
//!
//! Made from a tree on disk (`dump`), as `nix-store --dump` makes it, and read strictly (`decode`): every string's
//! padding zero, names neither empty nor `.` or `..` and with no `/` or NUL, entries strictly in order, nothing after the
//! end, and nesting at most `MAX_DEPTH` deep. Whatever `decode` accepts, `encode` gives back byte for byte.

use crate::FormatError;
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// The archive's first string.
pub const MAGIC: &[u8] = b"nix-archive-1";
/// How deep a directory may nest in an archive that is read.
pub const MAX_DEPTH: usize = 256;

/// A tree of files, as an archive holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Regular { executable: bool, contents: Vec<u8> },
    Symlink { target: Vec<u8> },
    Directory(BTreeMap<Vec<u8>, Node>),
}

/// Whether `name` may name an entry of a directory.
pub fn is_entry_name(name: &[u8]) -> bool {
    !name.is_empty() && name != b"." && name != b".." && !name.contains(&b'/') && !name.contains(&0)
}

fn put(out: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    out.write_all(&(bytes.len() as u64).to_le_bytes())?;
    out.write_all(bytes)?;
    out.write_all(&[0u8; 8][..padding(bytes.len() as u64)])
}

fn padding(len: u64) -> usize {
    ((8 - len % 8) % 8) as usize
}

/// The archive of `node`.
pub fn encode(node: &Node) -> Vec<u8> {
    let mut out = Vec::new();
    put(&mut out, MAGIC).expect("a Vec takes every write");
    encode_node(node, &mut out).expect("a Vec takes every write");
    out
}

fn encode_node(node: &Node, out: &mut impl Write) -> io::Result<()> {
    put(out, b"(")?;
    put(out, b"type")?;
    match node {
        Node::Regular {
            executable,
            contents,
        } => {
            put(out, b"regular")?;
            if *executable {
                put(out, b"executable")?;
                put(out, b"")?;
            }
            put(out, b"contents")?;
            put(out, contents)?;
        }
        Node::Symlink { target } => {
            put(out, b"symlink")?;
            put(out, b"target")?;
            put(out, target)?;
        }
        Node::Directory(entries) => {
            put(out, b"directory")?;
            for (name, child) in entries {
                put(out, b"entry")?;
                put(out, b"(")?;
                put(out, b"name")?;
                put(out, name)?;
                put(out, b"node")?;
                encode_node(child, out)?;
                put(out, b")")?;
            }
        }
    }
    put(out, b")")
}

/// Writes the archive of the tree at `path` to `out`, as `nix-store --dump` does: a regular file is executable when its
/// owner may execute it, a directory's entries go in the byte order of their names, and anything that is not a regular
/// file, a symbolic link or a directory is refused. A file that changes size while it is read is refused too.
pub fn dump(path: &Path, out: &mut impl Write) -> io::Result<()> {
    put(out, MAGIC)?;
    dump_node(path, out)
}

fn dump_node(path: &Path, out: &mut impl Write) -> io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    let kind = meta.file_type();
    put(out, b"(")?;
    put(out, b"type")?;
    if kind.is_file() {
        put(out, b"regular")?;
        if meta.permissions().mode() & 0o100 != 0 {
            put(out, b"executable")?;
            put(out, b"")?;
        }
        put(out, b"contents")?;
        let len = meta.len();
        out.write_all(&len.to_le_bytes())?;
        let copied = io::copy(&mut std::fs::File::open(path)?.take(len + 1), out)?;
        if copied != len {
            return Err(io::Error::other(format!(
                "{} changed size while it was read",
                path.display()
            )));
        }
        out.write_all(&[0u8; 8][..padding(len)])?;
    } else if kind.is_symlink() {
        put(out, b"symlink")?;
        put(out, b"target")?;
        put(out, std::fs::read_link(path)?.as_os_str().as_bytes())?;
    } else if kind.is_dir() {
        put(out, b"directory")?;
        let mut names = std::fs::read_dir(path)?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<io::Result<Vec<_>>>()?;
        names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        for name in names {
            put(out, b"entry")?;
            put(out, b"(")?;
            put(out, b"name")?;
            put(out, name.as_bytes())?;
            put(out, b"node")?;
            dump_node(&path.join(&name), out)?;
            put(out, b")")?;
        }
    } else {
        return Err(io::Error::other(format!(
            "{} is not a file, a link or a directory",
            path.display()
        )));
    }
    put(out, b")")
}

/// The tree an archive holds, read strictly.
pub fn decode(bytes: &[u8]) -> Result<Node, FormatError> {
    let mut reader = Reader { bytes, at: 0 };
    reader.expect(MAGIC)?;
    let node = reader.node(0)?;
    if reader.at != bytes.len() {
        return Err(FormatError::Nar(format!(
            "{} bytes after the end",
            bytes.len() - reader.at
        )));
    }
    Ok(node)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn refused(&self, why: impl std::fmt::Display) -> FormatError {
        FormatError::Nar(format!("at byte {}: {why}", self.at))
    }

    fn string(&mut self) -> Result<&'a [u8], FormatError> {
        let rest = &self.bytes[self.at..];
        let len: [u8; 8] = rest
            .get(..8)
            .and_then(|l| l.try_into().ok())
            .ok_or_else(|| self.refused("cut short"))?;
        let len = u64::from_le_bytes(len);
        let padded = len
            .checked_add(padding(len) as u64)
            .and_then(|p| usize::try_from(p).ok())
            .filter(|&p| p <= rest.len() - 8)
            .ok_or_else(|| self.refused("cut short"))?;
        let body = &rest[8..8 + len as usize];
        if rest[8 + len as usize..8 + padded].iter().any(|&b| b != 0) {
            return Err(self.refused("padding that is not zero"));
        }
        self.at += 8 + padded;
        Ok(body)
    }

    fn expect(&mut self, word: &[u8]) -> Result<(), FormatError> {
        let at = self.at;
        let got = self.string()?;
        if got != word {
            self.at = at;
            return Err(self.refused(format!(
                "{:?} where {:?} belongs",
                String::from_utf8_lossy(got),
                String::from_utf8_lossy(word)
            )));
        }
        Ok(())
    }

    fn node(&mut self, depth: usize) -> Result<Node, FormatError> {
        if depth > MAX_DEPTH {
            return Err(self.refused("nested too deep"));
        }
        self.expect(b"(")?;
        self.expect(b"type")?;
        let node = match self.string()? {
            b"regular" => {
                let mut word = self.string()?;
                let executable = word == b"executable";
                if executable {
                    self.expect(b"")?;
                    word = self.string()?;
                }
                if word != b"contents" {
                    return Err(self.refused("a regular file with no contents"));
                }
                Node::Regular {
                    executable,
                    contents: self.string()?.to_vec(),
                }
            }
            b"symlink" => {
                self.expect(b"target")?;
                let target = self.string()?;
                if target.is_empty() || target.contains(&0) {
                    return Err(self.refused("a link's target that is empty or holds a NUL"));
                }
                Node::Symlink {
                    target: target.to_vec(),
                }
            }
            b"directory" => {
                let mut entries = BTreeMap::new();
                let mut last: Option<&[u8]> = None;
                loop {
                    match self.string()? {
                        b")" => return Ok(Node::Directory(entries)),
                        b"entry" => {}
                        _ => return Err(self.refused("a directory holding what is not an entry")),
                    }
                    self.expect(b"(")?;
                    self.expect(b"name")?;
                    let name = self.string()?;
                    if !is_entry_name(name) {
                        return Err(self.refused("an entry's name that is not one"));
                    }
                    if last.is_some_and(|l| l >= name) {
                        return Err(self.refused("entries out of order, or one twice"));
                    }
                    last = Some(name);
                    self.expect(b"node")?;
                    let child = self.node(depth + 1)?;
                    self.expect(b")")?;
                    entries.insert(name.to_vec(), child);
                }
            }
            _ => return Err(self.refused("a node of no type Nix has")),
        };
        self.expect(b")")?;
        Ok(node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(contents: &[u8]) -> Node {
        Node::Regular {
            executable: false,
            contents: contents.to_vec(),
        }
    }

    #[test]
    fn a_tree_reads_back_from_its_archive() {
        let tree = Node::Directory(BTreeMap::from([
            (b"a".to_vec(), file(b"hello")),
            (
                b"bin".to_vec(),
                Node::Directory(BTreeMap::from([(
                    b"x".to_vec(),
                    Node::Regular {
                        executable: true,
                        contents: vec![0; 9],
                    },
                )])),
            ),
            (
                b"l".to_vec(),
                Node::Symlink {
                    target: b"a".to_vec(),
                },
            ),
        ]));
        assert_eq!(decode(&encode(&tree)).unwrap(), tree);
    }

    #[test]
    fn an_archive_with_bytes_after_it_or_cut_short_is_refused() {
        let nar = encode(&file(b"x"));
        let mut longer = nar.clone();
        longer.extend_from_slice(&[0; 8]);
        assert!(decode(&longer).is_err());
        for cut in [0, 7, 8, nar.len() - 1] {
            assert!(decode(&nar[..cut]).is_err(), "{cut}");
        }
    }

    #[test]
    fn padding_that_is_not_zero_is_refused() {
        let mut nar = encode(&file(b"x"));
        // The archive ends with the contents (8 bytes of length, `x`, 7 of padding) and the closing `)` (16 bytes).
        let at = nar.len() - 16 - 1;
        nar[at] = 1;
        assert_eq!(
            decode(&nar),
            Err(FormatError::Nar(format!(
                "at byte {}: padding that is not zero",
                nar.len() - 32
            )))
        );
    }

    #[test]
    fn a_length_past_the_archive_is_refused_without_reading_it() {
        let mut nar = Vec::new();
        put(&mut nar, MAGIC).unwrap();
        nar.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode(&nar).is_err());
    }

    #[test]
    fn an_entry_whose_name_is_not_one_is_refused() {
        for name in [&b""[..], b".", b"..", b"a/b", b"a\0b"] {
            let tree = Node::Directory(BTreeMap::from([(name.to_vec(), file(b"x"))]));
            assert!(decode(&encode(&tree)).is_err(), "{name:?}");
        }
        for name in [&b"..."[..], b".a", b"a b", b"\xff"] {
            let tree = Node::Directory(BTreeMap::from([(name.to_vec(), file(b"x"))]));
            assert_eq!(decode(&encode(&tree)).unwrap(), tree, "{name:?}");
        }
    }

    #[test]
    fn a_link_to_nowhere_or_with_a_nul_is_refused() {
        for target in [&b""[..], b"a\0b", b"\0"] {
            let link = Node::Symlink {
                target: target.to_vec(),
            };
            assert!(decode(&encode(&link)).is_err(), "{target:?}");
        }
    }

    fn nested(depth: usize) -> Node {
        (0..depth).fold(file(b"x"), |inner, _| {
            Node::Directory(BTreeMap::from([(b"d".to_vec(), inner)]))
        })
    }

    #[test]
    fn nesting_is_read_to_its_bound_and_no_deeper() {
        // The file at the bottom is the node at depth `MAX_DEPTH`.
        assert_eq!(
            decode(&encode(&nested(MAX_DEPTH))).unwrap(),
            nested(MAX_DEPTH)
        );
        assert!(decode(&encode(&nested(MAX_DEPTH + 1))).is_err());
    }

    #[test]
    fn a_file_holding_more_than_its_size_says_is_refused() {
        // A file in /proc says it is empty and is not.
        let mut out = Vec::new();
        let err = dump(Path::new("/proc/self/stat"), &mut out).unwrap_err();
        assert!(err.to_string().contains("changed size"), "{err}");
    }
}
