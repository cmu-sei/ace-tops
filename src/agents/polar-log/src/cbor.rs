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

//! The one subset of CBOR (RFC 8949) Polar's logs are written in, and the only form read back: deterministic encoding
//! (section 4.2.1), so one value has one encoding and a hash or signature of it means one thing. Unsigned integers,
//! byte strings, text strings, the two booleans, and maps whose keys are the integers 0 to n-1 in order: nothing else is
//! written, and a decoder that meets anything else, a longer form than needed, an indefinite length, a key out of
//! order, or bytes left over, refuses it. A length is never trusted beyond the bytes that are there.
//! (docs/architecture/record-store.md, "The shape": strict, by hand, rather than a general decoder that would also
//! take the non-canonical forms.)

use thiserror::Error;

const UNSIGNED: u8 = 0;
const BYTES: u8 = 2;
const TEXT: u8 = 3;
const MAP: u8 = 5;
const SIMPLE: u8 = 7;
const FALSE: u8 = 20;
const TRUE: u8 = 21;

/// Why bytes are not one of Polar's CBOR values.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CborError {
    #[error("the bytes end before the value does")]
    Short,
    #[error("a {expected} was expected, and the bytes hold major type {found}")]
    WrongType { expected: &'static str, found: u8 },
    #[error("a head that is not in its shortest form, or an indefinite length")]
    NotDeterministic,
    #[error("a map's key {found} where {expected} belongs")]
    Key { expected: u64, found: u64 },
    #[error("a map of {found} entries where {expected} belong")]
    Entries { expected: u64, found: u64 },
    #[error("a text string that is not UTF-8")]
    NotUtf8,
    #[error("{0} bytes are left over after the value")]
    Trailing(usize),
}

/// Writes values, each in its one deterministic form.
#[derive(Debug, Default)]
pub struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Self::default()
    }

    fn head(&mut self, major: u8, n: u64) {
        let major = major << 5;
        if n < 24 {
            self.bytes.push(major | n as u8);
        } else if n <= u64::from(u8::MAX) {
            self.bytes.push(major | 24);
            self.bytes.push(n as u8);
        } else if n <= u64::from(u16::MAX) {
            self.bytes.push(major | 25);
            self.bytes.extend_from_slice(&(n as u16).to_be_bytes());
        } else if n <= u64::from(u32::MAX) {
            self.bytes.push(major | 26);
            self.bytes.extend_from_slice(&(n as u32).to_be_bytes());
        } else {
            self.bytes.push(major | 27);
            self.bytes.extend_from_slice(&n.to_be_bytes());
        }
    }

    pub fn unsigned(&mut self, n: u64) -> &mut Self {
        self.head(UNSIGNED, n);
        self
    }

    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.head(BYTES, b.len() as u64);
        self.bytes.extend_from_slice(b);
        self
    }

    pub fn text(&mut self, t: &str) -> &mut Self {
        self.head(TEXT, t.len() as u64);
        self.bytes.extend_from_slice(t.as_bytes());
        self
    }

    pub fn boolean(&mut self, b: bool) -> &mut Self {
        self.bytes
            .push((SIMPLE << 5) | if b { TRUE } else { FALSE });
        self
    }

    /// A map of `entries` entries; the caller writes each key, 0 to entries-1 in order, then its value.
    pub fn map(&mut self, entries: u64) -> &mut Self {
        self.head(MAP, entries);
        self
    }

    pub fn key(&mut self, k: u64) -> &mut Self {
        self.unsigned(k)
    }

    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// Reads values, refusing any form but the deterministic one.
#[derive(Debug)]
pub struct Decoder<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn byte(&mut self) -> Result<u8, CborError> {
        let b = *self.bytes.get(self.at).ok_or(CborError::Short)?;
        self.at += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        let end = self.at.checked_add(n).ok_or(CborError::Short)?;
        let taken = self.bytes.get(self.at..end).ok_or(CborError::Short)?;
        self.at = end;
        Ok(taken)
    }

    fn head(&mut self, major: u8, expected: &'static str) -> Result<u64, CborError> {
        let initial = self.byte()?;
        if initial >> 5 != major {
            return Err(CborError::WrongType {
                expected,
                found: initial >> 5,
            });
        }
        let (n, least) = match initial & 0x1f {
            n @ 0..=23 => return Ok(u64::from(n)),
            24 => (u64::from(self.byte()?), 24),
            25 => (
                u64::from(u16::from_be_bytes(
                    self.take(2)?.try_into().expect("two bytes"),
                )),
                u64::from(u8::MAX) + 1,
            ),
            26 => (
                u64::from(u32::from_be_bytes(
                    self.take(4)?.try_into().expect("four bytes"),
                )),
                u64::from(u16::MAX) + 1,
            ),
            27 => (
                u64::from_be_bytes(self.take(8)?.try_into().expect("eight bytes")),
                u64::from(u32::MAX) + 1,
            ),
            _ => return Err(CborError::NotDeterministic),
        };
        if n < least {
            return Err(CborError::NotDeterministic);
        }
        Ok(n)
    }

    /// A length, taken no further than the bytes there: [`Decoder::take`] slices, never allocates, and refuses a
    /// length past the end.
    fn length(&mut self, major: u8, expected: &'static str) -> Result<usize, CborError> {
        let n = self.head(major, expected)?;
        usize::try_from(n).map_err(|_| CborError::Short)
    }

    pub fn unsigned(&mut self) -> Result<u64, CborError> {
        self.head(UNSIGNED, "unsigned integer")
    }

    pub fn bytes(&mut self) -> Result<&'a [u8], CborError> {
        let n = self.length(BYTES, "byte string")?;
        self.take(n)
    }

    pub fn text(&mut self) -> Result<&'a str, CborError> {
        let n = self.length(TEXT, "text string")?;
        std::str::from_utf8(self.take(n)?).map_err(|_| CborError::NotUtf8)
    }

    pub fn boolean(&mut self) -> Result<bool, CborError> {
        match self.byte()? {
            b if b == (SIMPLE << 5) | FALSE => Ok(false),
            b if b == (SIMPLE << 5) | TRUE => Ok(true),
            b => Err(CborError::WrongType {
                expected: "boolean",
                found: b >> 5,
            }),
        }
    }

    /// A map of exactly `entries` entries.
    pub fn map(&mut self, entries: u64) -> Result<(), CborError> {
        let found = self.head(MAP, "map")?;
        if found != entries {
            return Err(CborError::Entries {
                expected: entries,
                found,
            });
        }
        Ok(())
    }

    /// The next key, which must be `k`: keys are 0 to n-1, in order.
    pub fn key(&mut self, k: u64) -> Result<(), CborError> {
        let found = self.unsigned()?;
        if found != k {
            return Err(CborError::Key { expected: k, found });
        }
        Ok(())
    }

    /// Nothing may follow the value.
    pub fn end(self) -> Result<(), CborError> {
        match self.bytes.len() - self.at {
            0 => Ok(()),
            n => Err(CborError::Trailing(n)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8949, Appendix A's examples of the shortest forms.
    #[test]
    fn integers_are_written_in_their_shortest_form_as_the_rfc_s_examples() {
        for (n, hex) in [
            (0u64, "00"),
            (23, "17"),
            (24, "1818"),
            (255, "18ff"),
            (256, "190100"),
            (65_535, "19ffff"),
            (65_536, "1a00010000"),
            (4_294_967_295, "1affffffff"),
            (4_294_967_296, "1b0000000100000000"),
        ] {
            let mut e = Encoder::new();
            e.unsigned(n);
            let bytes = e.finish();
            assert_eq!(hex_of(&bytes), hex, "{n}");
            let mut d = Decoder::new(&bytes);
            assert_eq!(d.unsigned(), Ok(n));
            assert_eq!(d.end(), Ok(()));
        }
    }

    #[test]
    fn a_longer_form_than_needed_or_an_indefinite_length_is_refused() {
        for hex in [
            "1817",
            "1900ff",
            "1a0000ffff",
            "1b00000000ffffffff",
            "5f",
            "1c",
            "1d",
            "1e",
        ] {
            let bytes = bytes_of(hex);
            assert!(Decoder::new(&bytes).unsigned().is_err(), "{hex}");
        }
        let bytes = bytes_of("5f");
        assert_eq!(
            Decoder::new(&bytes).bytes(),
            Err(CborError::NotDeterministic)
        );
    }

    #[test]
    fn a_length_beyond_the_bytes_is_refused_before_anything_is_taken() {
        let bytes = bytes_of("5bffffffffffffffff00");
        assert_eq!(Decoder::new(&bytes).bytes(), Err(CborError::Short));
    }

    #[test]
    fn booleans_text_and_keys_read_back_and_anything_else_is_refused() {
        let mut e = Encoder::new();
        e.map(2).key(0).boolean(true).key(1).text("é");
        let bytes = e.finish();
        assert_eq!(hex_of(&bytes), "a200f50162c3a9");
        let mut d = Decoder::new(&bytes);
        d.map(2).unwrap();
        d.key(0).unwrap();
        assert_eq!(d.boolean(), Ok(true));
        d.key(1).unwrap();
        assert_eq!(d.text(), Ok("é"));
        assert_eq!(d.end(), Ok(()));

        let mut d = Decoder::new(&bytes);
        assert_eq!(
            d.map(3),
            Err(CborError::Entries {
                expected: 3,
                found: 2
            })
        );
        let mut d = Decoder::new(&bytes);
        d.map(2).unwrap();
        assert_eq!(
            d.key(1),
            Err(CborError::Key {
                expected: 1,
                found: 0
            })
        );
        assert!(
            Decoder::new(&bytes_of("62c328")).text().is_err(),
            "not UTF-8"
        );
        assert_eq!(
            Decoder::new(&bytes_of("f6")).boolean(),
            Err(CborError::WrongType {
                expected: "boolean",
                found: 7
            }),
            "null is not a boolean"
        );
        assert_eq!(
            Decoder::new(&bytes_of("40")).boolean(),
            Err(CborError::WrongType {
                expected: "boolean",
                found: 2
            })
        );
        assert_eq!(
            Decoder::new(&bytes_of("60")).unsigned(),
            Err(CborError::WrongType {
                expected: "unsigned integer",
                found: 3
            })
        );
        let two = bytes_of("0000");
        let mut d = Decoder::new(&two);
        d.unsigned().unwrap();
        assert_eq!(d.end(), Err(CborError::Trailing(1)));
    }

    fn hex_of(b: &[u8]) -> String {
        b.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn bytes_of(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
