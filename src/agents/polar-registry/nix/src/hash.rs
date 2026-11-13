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

//! A SHA-256 as Nix writes one: `sha256:` and the hash in Nix's base-32, which is how a narinfo states an archive's hash
//! and how a signature's fingerprint names it. Read in the other spellings Nix accepts too: `sha256:` and hex, and the
//! SRI form `sha256-` and base64 that `nix path-info --json` prints.

use crate::{FormatError, nix32};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256 as Hasher};
use std::fmt;
use std::str::FromStr;

/// A SHA-256.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sha256(pub [u8; 32]);

impl Sha256 {
    /// The hash of `bytes`.
    pub fn of(bytes: &[u8]) -> Self {
        Self(Hasher::digest(bytes).into())
    }

    /// The hash in Nix's base-32, with no prefix: how an archive is named in a cache.
    pub fn nix32(&self) -> String {
        nix32::encode(&self.0)
    }

    /// The hash in lower-case hex: how Polar's content store names a blob.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.nix32())
    }
}

impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Sha256 {
    type Err = FormatError;

    fn from_str(text: &str) -> Result<Self, FormatError> {
        let refused = || FormatError::Hash(text.to_string());
        if let Some(sri) = text.strip_prefix("sha256-") {
            let bytes = STANDARD.decode(sri).map_err(|_| refused())?;
            return Ok(Self(bytes.try_into().map_err(|_| refused())?));
        }
        let body = text.strip_prefix("sha256:").ok_or_else(refused)?;
        match body.len() {
            52 => nix32::decode::<32>(body).map(Self).map_err(|_| refused()),
            64 if body
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
            {
                let bytes = hex::decode(body).map_err(|_| refused())?;
                Ok(Self(bytes.try_into().map_err(|_| refused())?))
            }
            _ => Err(refused()),
        }
    }
}

/// A writer that hashes and counts what passes through it, for an archive whose hash and size are wanted as it is written.
pub struct Hashing<W> {
    inner: W,
    hasher: Hasher,
    count: u64,
}

impl<W> Hashing<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Hasher::new(),
            count: 0,
        }
    }

    /// The hash and count of everything written, and the writer.
    pub fn finish(self) -> (Sha256, u64, W) {
        (
            Sha256(self.hasher.finalize().into()),
            self.count,
            self.inner,
        )
    }
}

impl<W: std::io::Write> std::io::Write for Hashing<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_spellings_read_as_one_hash() {
        // One hash, as `nix path-info --json` and `nix hash convert` print it.
        let sri: Sha256 = "sha256-w4yk2As1akKTz29iatRoVIzCH7e0/zIzobY5qlh+w3I="
            .parse()
            .unwrap();
        let nix32: Sha256 = "sha256:0wn3grcalfdnl4rk5zxlnwgw532ld3a6lqkgry9l4sim1gca9363"
            .parse()
            .unwrap();
        let hex: Sha256 = "sha256:c38ca4d80b356a4293cf6f626ad468548cc21fb7b4ff3233a1b639aa587ec372"
            .parse()
            .unwrap();
        assert_eq!(sri, nix32);
        assert_eq!(nix32, hex);
        assert_eq!(
            sri.to_string(),
            "sha256:0wn3grcalfdnl4rk5zxlnwgw532ld3a6lqkgry9l4sim1gca9363"
        );
    }

    #[test]
    fn another_algorithm_or_a_short_hash_is_refused() {
        for text in [
            "sha512:0wn3grcalfdnl4rk5zxlnwgw532ld3a6lqkgry9l4sim1gca9363",
            "0wn3grcalfdnl4rk5zxlnwgw532ld3a6lqkgry9l4sim1gca9363",
            "sha256:0wn3grcalfdnl4rk5zxlnwgw532ld3a6lqkgry9l4sim1gca936",
            "sha256:C38CA4D80B356A4293CF6F626AD468548CC21FB7B4FF3233A1B639AA587EC372",
            "sha256-w4yk2As1akKTz29iatRoVIzCH7e0/zIzobY5qlh+w3",
        ] {
            assert!(text.parse::<Sha256>().is_err(), "{text}");
        }
    }

    #[test]
    fn what_is_written_through_is_hashed_and_counted() {
        use std::io::Write;
        let mut w = Hashing::new(Vec::new());
        w.write_all(b"nix").unwrap();
        let (hash, count, inner) = w.finish();
        assert_eq!(
            (hash, count, inner.as_slice()),
            (Sha256::of(b"nix"), 3, &b"nix"[..])
        );
    }

    #[test]
    fn a_hash_names_a_blob_in_hex_and_debugs_as_it_displays() {
        let hash = Sha256::of(b"");
        assert_eq!(
            hash.hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(format!("{hash:?}"), hash.to_string());
    }

    #[test]
    fn a_flush_reaches_the_writer_beneath() {
        struct Flushed(bool);
        impl std::io::Write for Flushed {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.0 = true;
                Ok(())
            }
        }
        use std::io::Write;
        let mut w = Hashing::new(Flushed(false));
        w.flush().unwrap();
        assert!(w.finish().2.0);
    }
}
