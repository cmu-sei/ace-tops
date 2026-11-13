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

//! A store path: `/nix/store/`, a 20-byte hash in Nix's base-32 (its *hash part*, which is how a binary cache is asked for
//! it), a dash and a name. A name is 1 to 211 characters of `A-Z a-z 0-9 + - . _ ? =`, and neither `.` nor `..`; Nix
//! refuses any other (checked against Nix 2.34: `.foo`, `-a` and `...` are names, `a b`, `.`, `..` and 212 characters
//! are not).

use crate::{FormatError, STORE_DIR, nix32};
use std::fmt;
use std::str::FromStr;

/// How many characters a hash part is.
pub const HASH_PART_LEN: usize = nix32::encoded_len(20);
/// The longest name Nix allows.
pub const MAX_NAME_LEN: usize = 211;

/// A store path in `/nix/store`, kept as its base name (`<hash part>-<name>`), which orders as Nix orders paths.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StorePath {
    base: String,
}

/// Whether `name` is a name Nix allows in a store path.
pub fn is_name(name: &str) -> bool {
    (1..=MAX_NAME_LEN).contains(&name.len())
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+-._?=".contains(&b))
}

/// Whether `text` is a hash part: 32 characters of Nix's base-32 that spell 20 bytes.
pub fn is_hash_part(text: &str) -> bool {
    nix32::decode::<20>(text).is_ok()
}

impl StorePath {
    /// The path whose base name is `base`, `<hash part>-<name>`: how a narinfo names its references and deriver.
    pub fn from_base(base: &str) -> Result<Self, FormatError> {
        let refused = || FormatError::StorePath(base.to_string());
        let (hash, name) = base.split_at_checked(HASH_PART_LEN).ok_or_else(refused)?;
        let name = name.strip_prefix('-').ok_or_else(refused)?;
        if !is_hash_part(hash) || !is_name(name) {
            return Err(refused());
        }
        Ok(Self {
            base: base.to_string(),
        })
    }

    /// The base name, `<hash part>-<name>`.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// The hash part: the 32 characters a cache is asked for the path's narinfo by.
    pub fn hash_part(&self) -> &str {
        &self.base[..HASH_PART_LEN]
    }

    /// The name after the hash part.
    pub fn name(&self) -> &str {
        &self.base[HASH_PART_LEN + 1..]
    }
}

impl fmt::Display for StorePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{STORE_DIR}/{}", self.base)
    }
}

impl fmt::Debug for StorePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for StorePath {
    type Err = FormatError;

    /// A whole path, `/nix/store/<hash part>-<name>`, with nothing after the name.
    fn from_str(text: &str) -> Result<Self, FormatError> {
        let base = text
            .strip_prefix(STORE_DIR)
            .and_then(|rest| rest.strip_prefix('/'))
            .ok_or_else(|| FormatError::StorePath(text.to_string()))?;
        Self::from_base(base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NIX: &str = "/nix/store/f0rfa5pcykqbv313j74x7l7wa8nl4bj4-nix-2.34.8";

    #[test]
    fn a_path_reads_into_its_parts_and_prints_as_it_was() {
        let p: StorePath = NIX.parse().unwrap();
        assert_eq!(p.hash_part(), "f0rfa5pcykqbv313j74x7l7wa8nl4bj4");
        assert_eq!(p.name(), "nix-2.34.8");
        assert_eq!(p.to_string(), NIX);
        assert_eq!(StorePath::from_base(p.base()).unwrap(), p);
    }

    #[test]
    fn names_are_held_to_nix_s_rule() {
        for name in [".foo", "-a", "...", "a?b=c", &"a".repeat(211)] {
            assert!(is_name(name), "{name}");
        }
        for name in ["", ".", "..", "a b", "a/b", "é", &"a".repeat(212)] {
            assert!(!is_name(name), "{name}");
        }
    }

    #[test]
    fn another_store_a_subpath_or_a_bad_hash_is_refused() {
        for text in [
            "/gnu/store/f0rfa5pcykqbv313j74x7l7wa8nl4bj4-nix-2.34.8",
            "/nix/store/f0rfa5pcykqbv313j74x7l7wa8nl4bj4-nix-2.34.8/bin/nix",
            "/nix/store/f0rfa5pcykqbv313j74x7l7wa8nl4bj4",
            "/nix/store/f0rfa5pcykqbv313j74x7l7wa8nl4bje-nix",
            "/nix/store/f0rfa5pcykqbv313j74x7l7wa8nl4bj-nix",
            "/nix/store//f0rfa5pcykqbv313j74x7l7wa8nl4bj4-nix",
        ] {
            assert!(text.parse::<StorePath>().is_err(), "{text}");
        }
    }

    #[test]
    fn a_path_debugs_as_it_displays() {
        let p: StorePath = NIX.parse().unwrap();
        assert_eq!(format!("{p:?}"), NIX);
    }
}
