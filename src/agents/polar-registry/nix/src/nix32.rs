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

//! Nix's base-32: its own alphabet (no `e`, `o`, `t` or `u`), read from the end, five bits a character, the first
//! character holding the bits past the last whole byte. A 20-byte store path hash is 32 characters; a SHA-256 is 52.

use crate::FormatError;

/// The alphabet, in the order of the values it spells.
pub const ALPHABET: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

/// How many characters spell `bytes` bytes.
pub const fn encoded_len(bytes: usize) -> usize {
    if bytes == 0 {
        0
    } else {
        (bytes * 8 - 1) / 5 + 1
    }
}

/// `bytes` in Nix's base-32.
pub fn encode(bytes: &[u8]) -> String {
    let len = encoded_len(bytes.len());
    let mut out = String::with_capacity(len);
    for n in (0..len).rev() {
        let b = n * 5;
        let (i, j) = (b / 8, b % 8);
        // `low` holds byte i's bits from bit j up, `high` byte i + 1's below 8 - j: they never overlap, so `|` here is
        // `^` too (that mutant survives, equivalent).
        let low = bytes[i] >> j;
        let high = if i + 1 < bytes.len() && j > 0 {
            bytes[i + 1] << (8 - j)
        } else {
            0
        };
        out.push(ALPHABET[usize::from((low | high) & 0x1f)] as char);
    }
    out
}

/// The `N` bytes `text` spells: exactly as many characters as spell `N` bytes, each of the alphabet, and no bit set past
/// the last byte, so every value has one spelling.
pub fn decode<const N: usize>(text: &str) -> Result<[u8; N], FormatError> {
    let refused = || FormatError::Nix32(text.to_string());
    if text.len() != encoded_len(N) {
        return Err(refused());
    }
    let mut out = [0u8; N];
    for (n, c) in text.bytes().rev().enumerate() {
        let digit = ALPHABET.iter().position(|&a| a == c).ok_or_else(refused)? as u16;
        let b = n * 5;
        let (i, j) = (b / 8, b % 8);
        let shifted = digit << j;
        out[i] |= (shifted & 0xff) as u8;
        let carry = (shifted >> 8) as u8;
        if i + 1 < N {
            out[i + 1] |= carry;
        } else if carry != 0 {
            return Err(refused());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_known_sha256_reads_as_nix_spells_it() {
        // `nix hash convert --hash-algo sha256 --to nix32` of the hex below.
        let hex = "c38ca4d80b356a4293cf6f626ad468548cc21fb7b4ff3233a1b639aa587ec372";
        let nix32 = "0wn3grcalfdnl4rk5zxlnwgw532ld3a6lqkgry9l4sim1gca9363";
        let bytes: [u8; 32] = hex::decode(hex).unwrap().try_into().unwrap();
        assert_eq!(encode(&bytes), nix32);
        assert_eq!(decode::<32>(nix32).unwrap(), bytes);
    }

    #[test]
    fn lengths_are_nix_s() {
        assert_eq!(encoded_len(20), 32);
        assert_eq!(encoded_len(32), 52);
    }

    #[test]
    fn a_letter_outside_the_alphabet_or_a_stray_high_bit_is_refused() {
        let ok = "0wn3grcalfdnl4rk5zxlnwgw532ld3a6lqkgry9l4sim1gca9363";
        assert!(decode::<32>(&ok.replace('w', "e")).is_err());
        assert!(decode::<32>(&ok[1..]).is_err());
        // 52 characters are 260 bits for 256: the first holds the value's last bit and four past it, so only 0 or 1 fit.
        assert!(decode::<32>(&format!("z{}", &ok[1..])).is_err());
    }
}
