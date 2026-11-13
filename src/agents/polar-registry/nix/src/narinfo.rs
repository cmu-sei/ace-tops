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

//! A narinfo: what a binary cache answers for a store path. Lines of `Key: value`, in the order Nix writes them:
//! `StorePath`, `URL` (where the archive is, relative to the cache), `Compression`, `FileHash` and `FileSize` (of the
//! archive as fetched), `NarHash` and `NarSize` (of the archive uncompressed, what Nix checks), `References` (base names,
//! separated by spaces), `Deriver`, a `Sig` line for each signature, and `CA`.
//!
//! Read strictly where it matters: the path, the archive's place, its hash and size are required, a key given twice is
//! refused (but for `Sig`), and every path and hash must be one. A key Nix does not write is passed over, as Nix does:
//! nothing in it is signed or served, since a narinfo is always written again from what was read.

use crate::hash::Sha256;
use crate::signature::{PublicKey, SecretKey, Signature};
use crate::store_path::StorePath;
use crate::{FormatError, STORE_DIR};
use std::collections::BTreeSet;
use std::fmt::Write as _;

/// The value `Deriver` takes when a cache does not know it.
const UNKNOWN_DERIVER: &str = "unknown-deriver";

/// What a cache says of a store path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarInfo {
    pub store_path: StorePath,
    pub url: String,
    pub compression: String,
    pub file_hash: Option<Sha256>,
    pub file_size: Option<u64>,
    pub nar_hash: Sha256,
    pub nar_size: u64,
    pub references: BTreeSet<StorePath>,
    pub deriver: Option<StorePath>,
    pub sigs: Vec<Signature>,
    pub ca: Option<String>,
}

/// What a cache's key signs for a path: `1;<path>;<NarHash>;<NarSize>;<references, as whole paths, separated by commas>`.
pub fn fingerprint(
    store_path: &StorePath,
    nar_hash: &Sha256,
    nar_size: u64,
    references: &BTreeSet<StorePath>,
) -> String {
    let references = references
        .iter()
        .map(|r| r.to_string())
        .collect::<Vec<_>>()
        .join(",");
    format!("1;{store_path};{nar_hash};{nar_size};{references}")
}

impl NarInfo {
    /// What a key signs for this path.
    pub fn fingerprint(&self) -> String {
        fingerprint(
            &self.store_path,
            &self.nar_hash,
            self.nar_size,
            &self.references,
        )
    }

    /// Adds `key`'s signature, in place of any made before by a key of that name.
    pub fn sign(&mut self, key: &SecretKey) {
        let sig = key.sign(&self.fingerprint());
        self.sigs.retain(|s| s.name != sig.name);
        self.sigs.push(sig);
    }

    /// Whether `key` signed this path as it is described.
    pub fn signed_by(&self, key: &PublicKey) -> bool {
        let fingerprint = self.fingerprint();
        self.sigs.iter().any(|s| key.verifies(&fingerprint, s))
    }

    /// The narinfo, as Nix writes it.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let mut line = |key: &str, value: &dyn std::fmt::Display| {
            let _ = writeln!(out, "{key}: {value}");
        };
        line("StorePath", &self.store_path);
        line("URL", &self.url);
        line("Compression", &self.compression);
        if let Some(h) = &self.file_hash {
            line("FileHash", h);
        }
        if let Some(s) = &self.file_size {
            line("FileSize", s);
        }
        line("NarHash", &self.nar_hash);
        line("NarSize", &self.nar_size);
        let references = self
            .references
            .iter()
            .map(StorePath::base)
            .collect::<Vec<_>>()
            .join(" ");
        line("References", &references);
        if let Some(d) = &self.deriver {
            line("Deriver", &d.base());
        }
        for s in &self.sigs {
            line("Sig", s);
        }
        if let Some(ca) = &self.ca {
            line("CA", ca);
        }
        out
    }

    /// A narinfo as a cache gives it.
    pub fn parse(text: &str) -> Result<Self, FormatError> {
        let refused = |why: String| FormatError::NarInfo(why);
        let mut store_path = None;
        let mut url = None;
        let mut compression = None;
        let mut file_hash = None;
        let mut file_size = None;
        let mut nar_hash = None;
        let mut nar_size = None;
        let mut references = None;
        let mut deriver = None;
        let mut ca = None;
        let mut sigs = Vec::new();
        fn once<T>(slot: &mut Option<T>, key: &str, value: T) -> Result<(), FormatError> {
            if slot.replace(value).is_some() {
                return Err(FormatError::NarInfo(format!("{key} twice")));
            }
            Ok(())
        }
        let size = |key: &str, v: &str| {
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(FormatError::NarInfo(format!("{key} not a number")));
            }
            v.parse::<u64>()
                .map_err(|_| FormatError::NarInfo(format!("{key} not a number")))
        };
        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            let (key, value) = line
                .split_once(": ")
                .ok_or_else(|| refused("a line that is not `Key: value`".into()))?;
            match key {
                "StorePath" => once(&mut store_path, key, value.parse::<StorePath>()?)?,
                "URL" => {
                    if value.is_empty() || value.bytes().any(|b| b.is_ascii_control()) {
                        return Err(refused("a URL that is not one".into()));
                    }
                    once(&mut url, key, value.to_string())?
                }
                "Compression" => {
                    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_alphanumeric()) {
                        return Err(refused("a compression that is not a word".into()));
                    }
                    once(&mut compression, key, value.to_string())?
                }
                "FileHash" => once(&mut file_hash, key, value.parse::<Sha256>()?)?,
                "FileSize" => once(&mut file_size, key, size(key, value)?)?,
                "NarHash" => once(&mut nar_hash, key, value.parse::<Sha256>()?)?,
                "NarSize" => once(&mut nar_size, key, size(key, value)?)?,
                "References" => {
                    let set = value
                        .split(' ')
                        .filter(|r| !r.is_empty())
                        .map(StorePath::from_base)
                        .collect::<Result<BTreeSet<_>, _>>()?;
                    once(&mut references, key, set)?
                }
                "Deriver" => {
                    let d = if value == UNKNOWN_DERIVER {
                        None
                    } else {
                        Some(StorePath::from_base(value)?)
                    };
                    once(&mut deriver, key, d)?
                }
                "Sig" => sigs.push(value.parse::<Signature>()?),
                "CA" => {
                    if value.is_empty() || value.bytes().any(|b| b.is_ascii_control() || b == b' ')
                    {
                        return Err(refused("a CA that is not one".into()));
                    }
                    once(&mut ca, key, value.to_string())?
                }
                _ => {}
            }
        }
        Ok(Self {
            store_path: store_path.ok_or_else(|| refused("no StorePath".into()))?,
            url: url.ok_or_else(|| refused("no URL".into()))?,
            compression: compression.unwrap_or_else(|| "bzip2".into()),
            file_hash,
            file_size,
            nar_hash: nar_hash.ok_or_else(|| refused("no NarHash".into()))?,
            nar_size: nar_size.ok_or_else(|| refused("no NarSize".into()))?,
            references: references.unwrap_or_default(),
            deriver: deriver.flatten(),
            sigs,
            ca,
        })
    }
}

/// The store directory the cache serves, as `nix-cache-info` says it, with its priority among a reader's caches.
pub fn cache_info(priority: u32) -> String {
    format!("StoreDir: {STORE_DIR}\nWantMassQuery: 1\nPriority: {priority}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "StorePath: /nix/store/f0rfa5pcykqbv313j74x7l7wa8nl4bj4-nix-2.34.8
URL: nar/0wn3grcalfdnl4rk5zxlnwgw532ld3a6lqkgry9l4sim1gca9363.nar
Compression: none
FileHash: sha256:0wn3grcalfdnl4rk5zxlnwgw532ld3a6lqkgry9l4sim1gca9363
FileSize: 4113736
NarHash: sha256:0wn3grcalfdnl4rk5zxlnwgw532ld3a6lqkgry9l4sim1gca9363
NarSize: 4113736
References: f0rfa5pcykqbv313j74x7l7wa8nl4bj4-nix-2.34.8 h4wfwic161kxrr74jlzla5lsm28hgary-glibc-2.44-25
Deriver: j0an1cgx0jfghhyrjn718vajxhv8ww8p-nix-2.34.8.drv
";

    #[test]
    fn a_narinfo_reads_and_writes_back_as_it_was() {
        let info = NarInfo::parse(SAMPLE).unwrap();
        assert_eq!(info.references.len(), 2);
        assert_eq!(info.render(), SAMPLE);
    }

    #[test]
    fn a_signature_covers_the_path_its_hash_size_and_references() {
        let key = SecretKey::from_seed("polar-test-1", [7; 32]).unwrap();
        let mut info = NarInfo::parse(SAMPLE).unwrap();
        info.sign(&key);
        assert!(info.signed_by(&key.public()));
        let mut changed = info.clone();
        changed.nar_size += 1;
        assert!(!changed.signed_by(&key.public()));
        let mut changed = info.clone();
        changed.references.pop_first();
        assert!(!changed.signed_by(&key.public()));
        // Where the archive is, and how it is compressed, are not signed: a cache may move them.
        let mut moved = info.clone();
        moved.url = "nar/elsewhere.nar.xz".into();
        assert!(moved.signed_by(&key.public()));
    }

    #[test]
    fn signing_again_replaces_the_key_s_own_signature() {
        let key = SecretKey::from_seed("polar-test-1", [7; 32]).unwrap();
        let mut info = NarInfo::parse(SAMPLE).unwrap();
        info.sign(&key);
        info.sign(&key);
        assert_eq!(info.sigs.len(), 1);
    }

    #[test]
    fn a_key_twice_or_a_missing_one_is_refused() {
        assert!(NarInfo::parse(&format!("{SAMPLE}NarSize: 1\n")).is_err());
        let without = SAMPLE.replace(
            "NarHash: sha256:0wn3grcalfdnl4rk5zxlnwgw532ld3a6lqkgry9l4sim1gca9363\n",
            "",
        );
        assert!(NarInfo::parse(&without).is_err());
        assert!(NarInfo::parse(&SAMPLE.replace("NarSize: 4113736", "NarSize: +4")).is_err());
    }

    #[test]
    fn a_key_nix_does_not_write_is_passed_over() {
        let info = NarInfo::parse(&format!("{SAMPLE}System: x86_64-linux\n")).unwrap();
        assert_eq!(info.render(), SAMPLE);
    }

    #[test]
    fn a_content_address_is_kept() {
        let with = format!(
            "{SAMPLE}CA: fixed:r:sha256:0wn3grcalfdnl4rk5zxlnwgw532ld3a6lqkgry9l4sim1gca9363\n"
        );
        let info = NarInfo::parse(&with).unwrap();
        assert_eq!(info.render(), with);
    }

    #[test]
    fn a_url_compression_or_content_address_that_is_not_one_is_refused() {
        for (key, bad) in [
            ("URL", ""),
            ("URL", "nar/a\tb"),
            ("Compression", ""),
            ("Compression", "x-z"),
            ("CA", ""),
            ("CA", "fixed:r sha256"),
            ("CA", "fixed\u{7f}"),
        ] {
            let text = match key {
                "CA" => format!("{SAMPLE}CA: {bad}\n"),
                _ => SAMPLE
                    .lines()
                    .map(|l| {
                        if l.starts_with(&format!("{key}: ")) {
                            format!("{key}: {bad}")
                        } else {
                            l.to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n"),
            };
            assert!(NarInfo::parse(&text).is_err(), "{key}: {bad:?}");
        }
    }

    #[test]
    fn nix_cache_info_names_the_store_and_the_priority() {
        assert_eq!(
            cache_info(40),
            "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n"
        );
    }
}
