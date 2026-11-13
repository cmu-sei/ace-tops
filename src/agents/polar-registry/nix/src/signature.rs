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

//! Nix's keys and signatures: a name, a colon, and base64 of an Ed25519 value. A public key is 32 bytes, a secret key
//! 64 (the seed, then the public key, as `nix key generate-secret` writes it), a signature 64. What a cache signs for a
//! path is its fingerprint (`narinfo::fingerprint`), and a signature names the key that made it, so a reader checks
//! each against the key of that name it trusts.

use crate::FormatError;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use std::fmt;
use std::str::FromStr;

/// Whether `name` may name a key: not empty, and no colon or white space, which would make its spelling ambiguous.
pub fn is_key_name(name: &str) -> bool {
    !name.is_empty()
        && !name
            .bytes()
            .any(|b| b == b':' || b.is_ascii_whitespace() || b.is_ascii_control())
}

fn split<const N: usize>(text: &str) -> Result<(String, [u8; N]), FormatError> {
    let refused = || FormatError::Signature(format!("{} characters", text.len()));
    let (name, value) = text.split_once(':').ok_or_else(refused)?;
    if !is_key_name(name) {
        return Err(refused());
    }
    let bytes = STANDARD.decode(value).map_err(|_| refused())?;
    Ok((name.to_string(), bytes.try_into().map_err(|_| refused())?))
}

/// A key a reader trusts.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub name: String,
    key: VerifyingKey,
}

/// A key a cache signs with. Its spelling is never printed by `Debug`.
pub struct SecretKey {
    pub name: String,
    key: SigningKey,
}

/// A signature, and the name of the key that made it.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Signature {
    pub name: String,
    pub bytes: [u8; 64],
}

impl SecretKey {
    /// The key of `name` whose seed is `seed`.
    pub fn from_seed(name: &str, seed: [u8; 32]) -> Result<Self, FormatError> {
        if !is_key_name(name) {
            return Err(FormatError::Signature(
                "a key's name that is not one".into(),
            ));
        }
        Ok(Self {
            name: name.to_string(),
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// The public key readers trust it by.
    pub fn public(&self) -> PublicKey {
        PublicKey {
            name: self.name.clone(),
            key: self.key.verifying_key(),
        }
    }

    /// Its signature of `fingerprint`.
    pub fn sign(&self, fingerprint: &str) -> Signature {
        Signature {
            name: self.name.clone(),
            bytes: self.key.sign(fingerprint.as_bytes()).to_bytes(),
        }
    }

    /// The key as Nix writes it, to be kept where only its holder reads it.
    pub fn to_nix(&self) -> String {
        format!(
            "{}:{}",
            self.name,
            STANDARD.encode(self.key.to_keypair_bytes())
        )
    }
}

impl FromStr for SecretKey {
    type Err = FormatError;

    /// The key as Nix writes it; its public half must be the seed's.
    fn from_str(text: &str) -> Result<Self, FormatError> {
        let (name, bytes) = split::<64>(text.trim_end())?;
        let key = SigningKey::from_keypair_bytes(&bytes)
            .map_err(|_| FormatError::Signature("a secret key whose halves differ".into()))?;
        Ok(Self { name, key })
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey({})", self.name)
    }
}

impl PublicKey {
    /// Whether `signature` is this key's, of `fingerprint`: made by a key of this name, and verifying, strictly, under it.
    pub fn verifies(&self, fingerprint: &str, signature: &Signature) -> bool {
        signature.name == self.name
            && self
                .key
                .verify_strict(
                    fingerprint.as_bytes(),
                    &ed25519_dalek::Signature::from_bytes(&signature.bytes),
                )
                .is_ok()
    }
}

impl FromStr for PublicKey {
    type Err = FormatError;

    fn from_str(text: &str) -> Result<Self, FormatError> {
        let (name, bytes) = split::<32>(text.trim_end())?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| FormatError::Signature("not a point Ed25519 has".into()))?;
        Ok(Self { name, key })
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.name, STANDARD.encode(self.key.as_bytes()))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Signature {
    type Err = FormatError;

    fn from_str(text: &str) -> Result<Self, FormatError> {
        let (name, bytes) = split::<64>(text)?;
        Ok(Self { name, bytes })
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.name, STANDARD.encode(self.bytes))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_verifies_under_its_own_key_only() {
        let key = SecretKey::from_seed("polar-test-1", [7; 32]).unwrap();
        let other = SecretKey::from_seed("polar-test-1", [8; 32]).unwrap();
        let renamed = SecretKey::from_seed("polar-test-2", [7; 32]).unwrap();
        let sig = key.sign("1;fingerprint");
        assert!(key.public().verifies("1;fingerprint", &sig));
        assert!(!key.public().verifies("1;fingerprinT", &sig));
        assert!(!other.public().verifies("1;fingerprint", &sig));
        assert!(!renamed.public().verifies("1;fingerprint", &sig));
    }

    #[test]
    fn keys_and_signatures_read_back_from_their_spelling() {
        let key = SecretKey::from_seed("polar-test-1", [7; 32]).unwrap();
        let again: SecretKey = key.to_nix().parse().unwrap();
        assert_eq!(again.public(), key.public());
        let public: PublicKey = key.public().to_string().parse().unwrap();
        assert_eq!(public, key.public());
        let sig = key.sign("x");
        assert_eq!(sig.to_string().parse::<Signature>().unwrap(), sig);
    }

    #[test]
    fn a_secret_key_whose_public_half_is_another_s_is_refused() {
        let mut bytes = SecretKey::from_seed("k", [7; 32])
            .unwrap()
            .key
            .to_keypair_bytes();
        bytes[32..].copy_from_slice(
            SecretKey::from_seed("k", [8; 32])
                .unwrap()
                .key
                .verifying_key()
                .as_bytes(),
        );
        assert!(
            format!("k:{}", STANDARD.encode(bytes))
                .parse::<SecretKey>()
                .is_err()
        );
    }

    #[test]
    fn a_secret_key_s_debug_names_it_and_shows_nothing_else() {
        let key = SecretKey::from_seed("k", [7; 32]).unwrap();
        assert_eq!(format!("{key:?}"), "SecretKey(k)");
    }

    #[test]
    fn a_key_s_name_that_is_not_one_is_refused() {
        for name in ["", "a:b", "a b", "a\tb", "a\u{1}"] {
            assert!(SecretKey::from_seed(name, [7; 32]).is_err(), "{name:?}");
        }
        assert!(SecretKey::from_seed("cache.nixos.org-1", [7; 32]).is_ok());
    }

    #[test]
    fn a_public_key_and_a_signature_debug_as_they_display() {
        let key = SecretKey::from_seed("k", [7; 32]).unwrap();
        let sig = key.sign("x");
        assert_eq!(format!("{:?}", key.public()), key.public().to_string());
        assert_eq!(format!("{sig:?}"), sig.to_string());
    }
}
