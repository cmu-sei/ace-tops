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

//! Checkpoints (C2SP tlog-checkpoint) in signed notes (C2SP signed-note), with signatures of type 0x02, ECDSA on P-256,
//! as transparency-dev's `formats/note` makes and checks them: the signature is ASN.1 DER over SHA-256 of the note
//! text; a key's ID is the first four bytes of SHA-256 of its DER-encoded SubjectPublicKeyInfo; a verifier key is
//! `<name>+<8 hex digits of the ID>+<base64(0x02 || DER SPKI)>`. Read 2026-11-10.
//!
//! A checkpoint's text is three lines: the log's origin, its size in decimal, and its root in base64. Extension lines
//! are allowed by the format and not recommended; Polar writes none and reads none. A verifier ignores signatures from
//! keys it does not know, refuses the note if a known key's signature fails, and refuses it unless one known key's
//! signature verifies.
//!
//! A witness co-signs a checkpoint as C2SP tlog-cosignature does, with ECDSA P-256 in place of its two algorithms
//! (decided 2026-11-11, so only Polar's code checks it; record-store.md, "Bite 5"): the message is `cosignature/v1`,
//! `time <T>` and the checkpoint's text, each line ending in a newline; the line is the key ID, T as a big-endian u64,
//! and the DER signature. Its type is signed-note's `0xff` followed by an identifier of Polar's, so a reader never
//! checks a co-signature over the note's own text; a co-signer's key ID is C2SP's, over its name, a newline, the type
//! and the key, so it never shares an ID with a checkpoint key.

use crate::merkle::Hash;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{DerSignature, Signature, SigningKey, VerifyingKey};
use p256::pkcs8::EncodePublicKey;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The signature type of ECDSA in a signed note.
pub const ECDSA: u8 = 0x02;

/// The type of a witness's co-signature: signed-note's `0xff`, kept for types it does not assign, and Polar's identifier.
pub const COSIGNATURE_TYPE: [u8; 30] = *b"\xffpolar.dev/cosignature/p256/v1";

/// The most signature lines read from a note; the format asks that at least 16 be taken.
pub const MAX_SIGNATURES: usize = 64;

/// The longest note read.
pub const MAX_NOTE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NoteError {
    #[error("the note is not a signed note: {0}")]
    Malformed(&'static str),
    #[error("the checkpoint is not one: {0}")]
    Checkpoint(&'static str),
    #[error("{0}'s signature does not verify")]
    BadSignature(String),
    #[error("no signature from a key that is trusted verifies")]
    Unsigned,
    #[error("the verifier key is not one: {0}")]
    Key(&'static str),
    #[error("the checkpoint is not witnessed: {0}")]
    Unwitnessed(&'static str),
}

/// How far past a reader's clock a co-signature may be dated: a minute (record-store.md, "Bite 5").
pub const MAX_AHEAD: u64 = 60;

/// A tree head as the log states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// The log's name, as its checkpoints and witnesses know it.
    pub origin: String,
    pub size: u64,
    pub root: Hash,
}

impl Checkpoint {
    /// The checkpoint's note text.
    pub fn text(&self) -> String {
        format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.size,
            BASE64.encode(self.root)
        )
    }

    /// The checkpoint a note's verified text states. Polar reads no extension lines.
    pub fn parse(text: &str) -> Result<Self, NoteError> {
        let body = text
            .strip_suffix('\n')
            .ok_or(NoteError::Checkpoint("it does not end with a newline"))?;
        let mut lines = body.split('\n');
        let (Some(origin), Some(size), Some(root), None) =
            (lines.next(), lines.next(), lines.next(), lines.next())
        else {
            return Err(NoteError::Checkpoint("it is not three lines"));
        };
        if origin.is_empty() {
            return Err(NoteError::Checkpoint("it names no origin"));
        }
        // A decimal with no sign, no leading zero, nothing else.
        if size.is_empty()
            || !size.bytes().all(|b| b.is_ascii_digit())
            || (size.len() > 1 && size.starts_with('0'))
        {
            return Err(NoteError::Checkpoint("its size is not a decimal"));
        }
        let size = size
            .parse::<u64>()
            .map_err(|_| NoteError::Checkpoint("its size is too large"))?;
        let root: Hash = BASE64
            .decode(root)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(NoteError::Checkpoint("its root is not a base64 hash"))?;
        Ok(Self {
            origin: origin.to_string(),
            size,
            root,
        })
    }
}

/// Whether `name` may name a key: not empty, no space, no `+`.
fn is_key_name(name: &str) -> bool {
    !name.is_empty() && !name.chars().any(|c| c.is_whitespace() || c == '+')
}

/// A key's ID: the first four bytes of SHA-256 of its DER SubjectPublicKeyInfo.
pub fn key_id(key: &VerifyingKey) -> u32 {
    let der = key.to_public_key_der().expect("a P-256 key encodes");
    let h = Sha256::digest(der.as_bytes());
    u32::from_be_bytes(h[..4].try_into().expect("four bytes"))
}

/// A co-signer's key ID: the first four bytes of SHA-256 of its name, a newline, the co-signature's type and its DER
/// SubjectPublicKeyInfo.
pub fn cosigner_key_id(name: &str, key: &VerifyingKey) -> u32 {
    let der = key.to_public_key_der().expect("a P-256 key encodes");
    let mut hashed = Sha256::new();
    hashed.update(name.as_bytes());
    hashed.update(b"\n");
    hashed.update(COSIGNATURE_TYPE);
    hashed.update(der.as_bytes());
    u32::from_be_bytes(hashed.finalize()[..4].try_into().expect("four bytes"))
}

/// What a witness signs for a checkpoint's `text` at `time`.
fn cosigned_message(text: &str, time: u64) -> String {
    format!("cosignature/v1\ntime {time}\n{text}")
}

/// Co-signs checkpoints as one named witness key.
pub struct Cosigner {
    name: String,
    key: SigningKey,
}

impl Cosigner {
    pub fn new(name: &str, key: SigningKey) -> Result<Self, NoteError> {
        if !is_key_name(name) {
            return Err(NoteError::Key(
                "its name is empty, or holds a space or a `+`",
            ));
        }
        Ok(Self {
            name: name.to_string(),
            key,
        })
    }

    /// The key the log and readers pin.
    pub fn verifier_key(&self) -> String {
        let der = self
            .key
            .verifying_key()
            .to_public_key_der()
            .expect("a P-256 key encodes");
        let mut blob = COSIGNATURE_TYPE.to_vec();
        blob.extend_from_slice(der.as_bytes());
        format!(
            "{}+{:08x}+{}",
            self.name,
            cosigner_key_id(&self.name, self.key.verifying_key()),
            BASE64.encode(blob)
        )
    }

    /// The co-signature line for a checkpoint's `text`, signed at `time` (Unix seconds).
    pub fn cosign_line(&self, text: &str, time: u64) -> String {
        let signature: Signature = self.key.sign(cosigned_message(text, time).as_bytes());
        let der: DerSignature = signature.to_der();
        let mut blob = cosigner_key_id(&self.name, self.key.verifying_key())
            .to_be_bytes()
            .to_vec();
        blob.extend_from_slice(&time.to_be_bytes());
        blob.extend_from_slice(der.as_bytes());
        format!("\u{2014} {} {}\n", self.name, BASE64.encode(blob))
    }
}

/// Signs notes as one named key.
pub struct NoteSigner {
    name: String,
    key: SigningKey,
}

impl NoteSigner {
    pub fn new(name: &str, key: SigningKey) -> Result<Self, NoteError> {
        if !is_key_name(name) {
            return Err(NoteError::Key(
                "its name is empty, or holds a space or a `+`",
            ));
        }
        Ok(Self {
            name: name.to_string(),
            key,
        })
    }

    /// The key witnesses and readers pin.
    pub fn verifier_key(&self) -> String {
        verifier_key(&self.name, self.key.verifying_key())
    }

    /// The signature line for `text`, a note's text ending in a newline.
    pub fn sign_line(&self, text: &str) -> String {
        let signature: Signature = self.key.sign(text.as_bytes());
        let der: DerSignature = signature.to_der();
        let mut blob = key_id(self.key.verifying_key()).to_be_bytes().to_vec();
        blob.extend_from_slice(der.as_bytes());
        format!("\u{2014} {} {}\n", self.name, BASE64.encode(blob))
    }

    /// `text` signed: the text, an empty line, and this key's signature line.
    pub fn sign(&self, text: &str) -> String {
        format!("{text}\n{}", self.sign_line(text))
    }
}

/// A key's verifier key string.
pub fn verifier_key(name: &str, key: &VerifyingKey) -> String {
    let der = key.to_public_key_der().expect("a P-256 key encodes");
    let mut blob = vec![ECDSA];
    blob.extend_from_slice(der.as_bytes());
    format!("{name}+{:08x}+{}", key_id(key), BASE64.encode(blob))
}

/// A key a note is checked against, read from its verifier key.
#[derive(Debug, Clone)]
pub struct NoteVerifier {
    name: String,
    id: u32,
    key: VerifyingKey,
    /// A witness's, which signs the co-signature message, not the note's text.
    cosigner: bool,
}

impl NoteVerifier {
    pub fn parse(vkey: &str) -> Result<Self, NoteError> {
        use p256::pkcs8::DecodePublicKey;
        let mut parts = vkey.splitn(3, '+');
        let (Some(name), Some(id), Some(blob)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(NoteError::Key("it is not name+id+key"));
        };
        if !is_key_name(name) {
            return Err(NoteError::Key(
                "its name is empty, or holds a space or a `+`",
            ));
        }
        if id.len() != 8
            || !id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(NoteError::Key("its ID is not eight lower-case hex digits"));
        }
        let id = u32::from_str_radix(id, 16).map_err(|_| NoteError::Key("its ID is not hex"))?;
        let blob = BASE64
            .decode(blob)
            .map_err(|_| NoteError::Key("its key is not canonical base64"))?;
        let (&kind, der) = blob
            .split_first()
            .ok_or(NoteError::Key("it holds no key"))?;
        let (cosigner, der) = if kind == ECDSA {
            (false, der)
        } else if let Some(der) = blob.strip_prefix(&COSIGNATURE_TYPE[..]) {
            (true, der)
        } else {
            return Err(NoteError::Key("it is not an ECDSA key"));
        };
        let key = VerifyingKey::from_public_key_der(der)
            .map_err(|_| NoteError::Key("it is not a P-256 key"))?;
        let expected = if cosigner {
            cosigner_key_id(name, &key)
        } else {
            key_id(&key)
        };
        if expected != id {
            return Err(NoteError::Key("its ID is not its key's"));
        }
        Ok(Self {
            name: name.to_string(),
            id,
            key,
            cosigner,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the key is a witness's, which signs the co-signature message.
    pub fn is_cosigner(&self) -> bool {
        self.cosigner
    }
}

/// A trusted key whose signature verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub name: String,
    /// A co-signer's time, as its line states it (Unix seconds); none for a key that signed the note's text.
    pub cosigned_at: Option<u64>,
}

/// A note opened: its text, and every trusted key whose signature verified, in the note's order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub text: String,
    pub by: Vec<Signed>,
}

/// The text of `note`, once one of `verifiers` has verified it, and the names of every trusted key whose signature
/// verified. A signature from a key not among them is ignored; a trusted key's that fails refuses the note.
pub fn open(note: &str, verifiers: &[NoteVerifier]) -> Result<(String, Vec<String>), NoteError> {
    let opened = open_signed(note, verifiers)?;
    Ok((
        opened.text,
        opened.by.into_iter().map(|signed| signed.name).collect(),
    ))
}

/// The checkpoint `note` states, as a reader takes it (record-store.md, "Bite 5"): signed by the pinned `store` key
/// and co-signed by the pinned `witness`, the co-signature dated no more than [`MAX_AHEAD`] past `now` (Unix seconds).
pub fn open_witnessed(
    note: &str,
    store: &NoteVerifier,
    witness: &NoteVerifier,
    now: u64,
) -> Result<Checkpoint, NoteError> {
    if store.cosigner || !witness.cosigner {
        return Err(NoteError::Key(
            "the store's key signs checkpoints and the witness's co-signs them",
        ));
    }
    let opened = open_signed(note, &[store.clone(), witness.clone()])?;
    let by = |name: &str| opened.by.iter().find(|s| s.name == name);
    if by(&store.name).is_none() {
        return Err(NoteError::Unwitnessed("the store's key did not sign it"));
    }
    let Some(cosigned) = by(&witness.name) else {
        return Err(NoteError::Unwitnessed(
            "the pinned witness did not co-sign it",
        ));
    };
    if cosigned.cosigned_at.unwrap_or(0) > now.saturating_add(MAX_AHEAD) {
        return Err(NoteError::Unwitnessed(
            "its co-signature is dated ahead of this clock",
        ));
    }
    Checkpoint::parse(&opened.text)
}

/// As `open`, with each co-signer's time: each trusted key is checked over its own message, a checkpoint key over the
/// note's text and a co-signer over the co-signature message its line's time makes.
pub fn open_signed(note: &str, verifiers: &[NoteVerifier]) -> Result<Opened, NoteError> {
    if note.len() > MAX_NOTE {
        return Err(NoteError::Malformed("it is longer than any note read"));
    }
    if note.chars().any(|c| c < ' ' && c != '\n') {
        return Err(NoteError::Malformed("it holds a control character"));
    }
    let split = note.rfind("\n\n").ok_or(NoteError::Malformed(
        "it has no empty line before its signatures",
    ))?;
    let text = &note[..split + 1];
    let signatures = &note[split + 2..];
    let signatures = signatures.strip_suffix('\n').ok_or(NoteError::Malformed(
        "its signatures do not end with a newline",
    ))?;
    let lines: Vec<&str> = signatures.split('\n').collect();
    if lines.len() > MAX_SIGNATURES {
        return Err(NoteError::Malformed("it has more signatures than are read"));
    }
    let mut verified = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for line in lines {
        let rest = line.strip_prefix("\u{2014} ").ok_or(NoteError::Malformed(
            "a signature line does not begin with an em dash",
        ))?;
        let (name, blob) = rest
            .split_once(' ')
            .ok_or(NoteError::Malformed("a signature line names no key"))?;
        if !is_key_name(name) {
            return Err(NoteError::Malformed(
                "a signature line's key name is not one",
            ));
        }
        let blob = BASE64
            .decode(blob)
            .map_err(|_| NoteError::Malformed("a signature is not canonical base64"))?;
        if blob.len() < 5 {
            return Err(NoteError::Malformed("a signature is too short"));
        }
        let id = u32::from_be_bytes(blob[..4].try_into().expect("four bytes"));
        if !seen.insert((name.to_string(), id)) {
            return Err(NoteError::Malformed(
                "two signature lines have the same key name and ID",
            ));
        }
        let Some(verifier) = verifiers.iter().find(|v| v.name == name && v.id == id) else {
            continue;
        };
        let (message, signature, cosigned_at) = if verifier.cosigner {
            if blob.len() < 4 + 8 + 1 {
                return Err(NoteError::Malformed("a co-signature is too short"));
            }
            let time = u64::from_be_bytes(blob[4..12].try_into().expect("eight bytes"));
            (cosigned_message(text, time), &blob[12..], Some(time))
        } else {
            (text.to_string(), &blob[4..], None)
        };
        let good = DerSignature::from_bytes(signature)
            .ok()
            .and_then(|der| Signature::try_from(der).ok())
            .is_some_and(|sig| verifier.key.verify(message.as_bytes(), &sig).is_ok());
        if !good {
            return Err(NoteError::BadSignature(name.to_string()));
        }
        verified.push(Signed {
            name: name.to_string(),
            cosigned_at,
        });
    }
    if verified.is_empty() {
        return Err(NoteError::Unsigned);
    }
    Ok(Opened {
        text: text.to_string(),
        by: verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    fn checkpoint() -> Checkpoint {
        Checkpoint {
            origin: "polar.local/evidence".to_string(),
            size: 38,
            root: [7; 32],
        }
    }

    #[test]
    fn a_checkpoint_is_three_lines_and_reads_back_as_itself() {
        let text = checkpoint().text();
        assert_eq!(
            text,
            format!("polar.local/evidence\n38\n{}\n", BASE64.encode([7u8; 32]))
        );
        assert_eq!(Checkpoint::parse(&text), Ok(checkpoint()));
        // An empty log's checkpoint: size 0, written as one zero.
        let empty = Checkpoint {
            size: 0,
            ..checkpoint()
        };
        assert_eq!(Checkpoint::parse(&empty.text()), Ok(empty));
        for bad in [
            "polar.local/evidence\n38\n",
            "polar.local/evidence\n38\nAAAA\n",
            "polar.local/evidence\n038\nBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\n",
            "polar.local/evidence\n+38\nBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\n",
            "\n38\nBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\n",
            "polar.local/evidence\n38\nBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\nextension\n",
            "polar.local/evidence\n38\nBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
        ] {
            assert!(Checkpoint::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_signed_note_opens_with_the_pinned_key_and_with_no_other() {
        let signer = NoteSigner::new("polar.local/store", key(1)).unwrap();
        let note = signer.sign(&checkpoint().text());
        let pinned = NoteVerifier::parse(&signer.verifier_key()).unwrap();
        let (text, by) = open(&note, std::slice::from_ref(&pinned)).unwrap();
        assert_eq!(Checkpoint::parse(&text), Ok(checkpoint()));
        assert_eq!(by, ["polar.local/store"]);
        // Another key of the same name is not this one.
        let other = NoteSigner::new("polar.local/store", key(2)).unwrap();
        let stranger = NoteVerifier::parse(&other.verifier_key()).unwrap();
        assert_eq!(open(&note, &[stranger]), Err(NoteError::Unsigned));
    }

    #[test]
    fn a_changed_text_fails_the_pinned_key_and_an_unknown_signature_is_passed_over() {
        let signer = NoteSigner::new("polar.local/store", key(1)).unwrap();
        let pinned = NoteVerifier::parse(&signer.verifier_key()).unwrap();
        let note = signer.sign(&checkpoint().text());
        let changed = note.replacen("\n38\n", "\n39\n", 1);
        assert_eq!(
            open(&changed, std::slice::from_ref(&pinned)),
            Err(NoteError::BadSignature("polar.local/store".to_string()))
        );
        // A witness's co-signature from a key the reader does not pin changes nothing.
        let witness = NoteSigner::new("polar.local/witness", key(3)).unwrap();
        let cosigned = format!("{note}{}", witness.sign_line(&checkpoint().text()));
        assert_eq!(
            open(&cosigned, std::slice::from_ref(&pinned)).unwrap().1,
            ["polar.local/store"]
        );
        let both = [
            pinned,
            NoteVerifier::parse(&witness.verifier_key()).unwrap(),
        ];
        assert_eq!(
            open(&cosigned, &both).unwrap().1,
            ["polar.local/store", "polar.local/witness"]
        );
    }

    #[test]
    fn a_verifier_key_must_be_its_key_s() {
        let signer = NoteSigner::new("polar.local/store", key(1)).unwrap();
        let vkey = signer.verifier_key();
        let (name, rest) = vkey.split_once('+').unwrap();
        let (_, blob) = rest.split_once('+').unwrap();
        assert!(
            NoteVerifier::parse(&format!("{name}+00000000+{blob}")).is_err(),
            "its ID is not its key's"
        );
        let id = &rest[..8];
        let not_eight = Err(NoteError::Key("its ID is not eight lower-case hex digits"));
        assert_eq!(
            NoteVerifier::parse(&format!("{name}+{}+{blob}", "ABCDEF12")).map(|_| ()),
            not_eight,
            "upper-case hex"
        );
        assert_eq!(
            NoteVerifier::parse(&format!("{name}+{}+{blob}", &id[..7])).map(|_| ()),
            not_eight,
            "seven digits"
        );
        assert_eq!(
            NoteVerifier::parse(&vkey).unwrap().name(),
            "polar.local/store"
        );
        assert!(NoteVerifier::parse("a b+00000000+AA==").is_err());
        assert!(NoteSigner::new("has+plus", key(1)).is_err());
        assert!(NoteSigner::new("", key(1)).is_err());
    }

    // The format asks that at least 16 signatures be read; Polar reads up to 64, and a note's size is bounded.
    #[test]
    fn up_to_the_bounds_a_note_is_read_and_past_them_it_is_not() {
        let signer = NoteSigner::new("polar.local/store", key(1)).unwrap();
        let pinned = NoteVerifier::parse(&signer.verifier_key()).unwrap();
        let text = checkpoint().text();
        let mut note = signer.sign(&text);
        for n in 2..=64u8 {
            let other = NoteSigner::new(&format!("polar.local/witness-{n}"), key(n)).unwrap();
            note.push_str(&other.sign_line(&text));
        }
        assert_eq!(note.matches('\u{2014}').count(), MAX_SIGNATURES);
        assert!(
            open(&note, std::slice::from_ref(&pinned)).is_ok(),
            "64 signatures"
        );
        let one_more = NoteSigner::new("polar.local/witness-65", key(65)).unwrap();
        note.push_str(&one_more.sign_line(&text));
        assert_eq!(
            open(&note, std::slice::from_ref(&pinned)),
            Err(NoteError::Malformed("it has more signatures than are read"))
        );
        // A long origin is fine up to the note's bound, and refused past it.
        let long = Checkpoint {
            origin: "o".repeat(4000),
            ..checkpoint()
        };
        assert!(open(&signer.sign(&long.text()), std::slice::from_ref(&pinned)).is_ok());
        // The bound is exact: a note of MAX_NOTE bytes is read, and one of a byte more is not.
        // Padded to the byte with a signature from a key not trusted, which is passed over, its name as long as needed.
        let base = signer.sign(
            &Checkpoint {
                origin: "o".repeat(MAX_NOTE - 1000),
                ..checkpoint()
            }
            .text(),
        );
        let note_of = |length: usize| {
            let blob = BASE64.encode([1, 2, 3, 4, 5]);
            let fixed = base.len() + "\u{2014}  \n".len() + blob.len();
            let note = format!("{base}\u{2014} {} {blob}\n", "p".repeat(length - fixed));
            assert_eq!(note.len(), length);
            note
        };
        assert!(open(&note_of(MAX_NOTE), std::slice::from_ref(&pinned)).is_ok());
        assert_eq!(
            open(&note_of(MAX_NOTE + 1), std::slice::from_ref(&pinned)),
            Err(NoteError::Malformed("it is longer than any note read"))
        );
    }

    /// A signature line holds a key ID and at least one byte of signature: four bytes are refused, and five from a key
    /// not trusted are passed over.
    #[test]
    fn a_signature_is_an_id_and_at_least_one_byte() {
        let signer = NoteSigner::new("polar.local/store", key(1)).unwrap();
        let pinned = NoteVerifier::parse(&signer.verifier_key()).unwrap();
        let note = signer.sign(&checkpoint().text());
        let line = |bytes: &[u8]| format!("\u{2014} polar.local/other {}\n", BASE64.encode(bytes));
        assert_eq!(
            open(
                &format!("{note}{}", line(&[1, 2, 3, 4])),
                std::slice::from_ref(&pinned)
            ),
            Err(NoteError::Malformed("a signature is too short"))
        );
        assert!(
            open(
                &format!("{note}{}", line(&[1, 2, 3, 4, 5])),
                std::slice::from_ref(&pinned)
            )
            .is_ok()
        );
    }

    #[test]
    fn what_is_not_a_signed_note_is_refused() {
        let signer = NoteSigner::new("polar.local/store", key(1)).unwrap();
        let pinned = NoteVerifier::parse(&signer.verifier_key()).unwrap();
        let note = signer.sign(&checkpoint().text());
        for bad in [
            note.replace("\u{2014}", "-"),
            note.trim_end_matches('\n').to_string(),
            note.replace("\n\n", "\n"),
            format!("{note}{}", note.lines().last().unwrap()).replace('\n', "\n") + "\n",
            note.replace("polar.local/evidence", "polar.local/evi\u{7}dence"),
        ] {
            assert!(
                open(&bad, std::slice::from_ref(&pinned)).is_err(),
                "{bad:?}"
            );
        }
    }

    const T: u64 = 1_731_300_000;

    fn store_and_witness() -> (NoteSigner, Cosigner, [NoteVerifier; 2]) {
        let store = NoteSigner::new("polar.local/checkpoint", key(1)).unwrap();
        let witness = Cosigner::new("polar.local/witness", key(3)).unwrap();
        let pinned = [
            NoteVerifier::parse(&store.verifier_key()).unwrap(),
            NoteVerifier::parse(&witness.verifier_key()).unwrap(),
        ];
        (store, witness, pinned)
    }

    /// A co-signed checkpoint opens with both keys pinned, and says which signed it and when the witness did.
    #[test]
    fn a_co_signed_checkpoint_opens_with_both_keys_each_over_its_own_message() {
        let (store, witness, pinned) = store_and_witness();
        let text = checkpoint().text();
        let note = format!("{}{}", store.sign(&text), witness.cosign_line(&text, T));
        let opened = open_signed(&note, &pinned).unwrap();
        assert_eq!(opened.text, text);
        assert_eq!(
            opened.by,
            [
                Signed {
                    name: "polar.local/checkpoint".to_string(),
                    cosigned_at: None
                },
                Signed {
                    name: "polar.local/witness".to_string(),
                    cosigned_at: Some(T)
                },
            ]
        );
        assert_eq!(
            open(&note, &pinned).unwrap().1,
            ["polar.local/checkpoint", "polar.local/witness"]
        );
        // The witness alone pinned: its co-signature is enough to open the note; requiring both is the reader's.
        assert_eq!(
            open(&note, &pinned[1..]).unwrap().1,
            ["polar.local/witness"]
        );
    }

    /// What is signed is C2SP tlog-cosignature's message, under ECDSA P-256 in DER, and the line is the key ID, the time
    /// as a big-endian u64, and the signature.
    #[test]
    fn a_co_signature_is_over_c2sp_s_message_with_its_time_in_the_line() {
        let witness = Cosigner::new("polar.local/witness", key(3)).unwrap();
        let text = checkpoint().text();
        let line = witness.cosign_line(&text, T);
        let blob = BASE64
            .decode(
                line.strip_prefix("\u{2014} polar.local/witness ")
                    .unwrap()
                    .trim_end(),
            )
            .unwrap();
        let id = u32::from_be_bytes(blob[..4].try_into().unwrap());
        assert_eq!(
            id,
            cosigner_key_id("polar.local/witness", key(3).verifying_key())
        );
        assert_eq!(u64::from_be_bytes(blob[4..12].try_into().unwrap()), T);
        let message = format!("cosignature/v1\ntime {T}\n{text}");
        let signature =
            Signature::try_from(DerSignature::from_bytes(&blob[12..]).unwrap()).unwrap();
        assert!(
            key(3)
                .verifying_key()
                .verify(message.as_bytes(), &signature)
                .is_ok()
        );
        // Its key ID is C2SP's for co-signers: over the name, a newline, the type and the key.
        let mut hashed = b"polar.local/witness\n".to_vec();
        hashed.extend_from_slice(&COSIGNATURE_TYPE);
        hashed.extend_from_slice(
            key(3)
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        );
        assert_eq!(id.to_be_bytes(), Sha256::digest(&hashed)[..4]);
    }

    /// A co-signature moved to another time or another checkpoint fails the witness's key, and one under the
    /// checkpoint's type, or from another key of the witness's name, is not the witness's at all.
    #[test]
    fn a_co_signature_verifies_only_over_the_message_it_signed() {
        let (store, witness, pinned) = store_and_witness();
        let text = checkpoint().text();
        let signed = store.sign(&text);
        let line = witness.cosign_line(&text, T);
        let bad = Err(NoteError::BadSignature("polar.local/witness".to_string()));
        // Another time, the signature kept.
        let mut blob = BASE64
            .decode(
                line.strip_prefix("\u{2014} polar.local/witness ")
                    .unwrap()
                    .trim_end(),
            )
            .unwrap();
        blob[4..12].copy_from_slice(&(T + 1).to_be_bytes());
        let moved = format!("\u{2014} polar.local/witness {}\n", BASE64.encode(&blob));
        assert_eq!(open(&format!("{signed}{moved}"), &pinned), bad);
        // Another checkpoint's co-signature.
        let other = Checkpoint {
            size: 39,
            ..checkpoint()
        }
        .text();
        let elsewhere = witness.cosign_line(&other, T);
        assert_eq!(open(&format!("{signed}{elsewhere}"), &pinned), bad);
        // The witness's key signing the note as a checkpoint key would: another key ID, so not the pinned witness's.
        let plain = NoteSigner::new("polar.local/witness", key(3))
            .unwrap()
            .sign_line(&text);
        assert_eq!(
            open(&format!("{signed}{plain}"), &pinned[1..]),
            Err(NoteError::Unsigned)
        );
        // Another key of the witness's name.
        let stranger = Cosigner::new("polar.local/witness", key(4))
            .unwrap()
            .cosign_line(&text, T);
        assert_eq!(
            open(&format!("{signed}{stranger}"), &pinned[1..]),
            Err(NoteError::Unsigned)
        );
        // A pinned co-signer's line with no time or no signature is refused.
        let id = cosigner_key_id("polar.local/witness", key(3).verifying_key()).to_be_bytes();
        for short in [
            [&id[..], &[1]].concat(),
            [&id[..], &T.to_be_bytes()[..]].concat(),
        ] {
            let line = format!("\u{2014} polar.local/witness {}\n", BASE64.encode(&short));
            assert_eq!(
                open(&format!("{signed}{line}"), &pinned),
                Err(NoteError::Malformed("a co-signature is too short")),
                "{} bytes",
                short.len()
            );
        }
        // A time and one byte is a co-signature, and a wrong one.
        let one_byte = [&id[..], &T.to_be_bytes()[..], &[0x30]].concat();
        let line = format!(
            "\u{2014} polar.local/witness {}\n",
            BASE64.encode(&one_byte)
        );
        assert_eq!(open(&format!("{signed}{line}"), &pinned), bad);
    }

    /// The same key gives a checkpoint key and a co-signer key that never share an ID, and each verifier key reads back
    /// as its own kind and no other.
    #[test]
    fn a_co_signer_s_verifier_key_is_its_own_kind() {
        let witness = Cosigner::new("polar.local/witness", key(3)).unwrap();
        let vkey = witness.verifier_key();
        assert_ne!(
            cosigner_key_id("polar.local/witness", key(3).verifying_key()),
            key_id(key(3).verifying_key())
        );
        let (name, rest) = vkey.split_once('+').unwrap();
        let (id, blob) = rest.split_once('+').unwrap();
        assert_eq!(name, "polar.local/witness");
        assert_eq!(
            NoteVerifier::parse(&vkey).unwrap().name(),
            "polar.local/witness"
        );
        assert!(NoteVerifier::parse(&vkey).unwrap().is_cosigner());
        let checkpoint_key = NoteSigner::new("polar.local/witness", key(3))
            .unwrap()
            .verifier_key();
        assert!(!NoteVerifier::parse(&checkpoint_key).unwrap().is_cosigner());
        let der = BASE64.decode(blob).unwrap();
        assert_eq!(der[..COSIGNATURE_TYPE.len()], COSIGNATURE_TYPE);
        // Another identifier after 0xff is not this type; nor is the checkpoint type with the co-signer's ID.
        let mut other = der.clone();
        other[COSIGNATURE_TYPE.len() - 1] ^= 1;
        assert_eq!(
            NoteVerifier::parse(&format!("{name}+{id}+{}", BASE64.encode(&other))).map(|_| ()),
            Err(NoteError::Key("it is not an ECDSA key"))
        );
        let mut as_checkpoint = vec![ECDSA];
        as_checkpoint.extend_from_slice(&der[COSIGNATURE_TYPE.len()..]);
        assert_eq!(
            NoteVerifier::parse(&format!("{name}+{id}+{}", BASE64.encode(&as_checkpoint)))
                .map(|_| ()),
            Err(NoteError::Key("its ID is not its key's"))
        );
        // The co-signer's ID under its own name only.
        assert_eq!(
            NoteVerifier::parse(&format!("polar.local/other+{id}+{blob}")).map(|_| ()),
            Err(NoteError::Key("its ID is not its key's"))
        );
        assert!(Cosigner::new("has space", key(3)).is_err());
    }

    /// docs/architecture/record-store.md, "Bite 5": a reader takes a checkpoint only when the store's key and the
    /// witness's both signed it, and the co-signature is dated no more than a minute past the reader's clock.
    #[test]
    fn a_reader_takes_a_checkpoint_only_with_both_signatures_and_a_co_signature_not_ahead() {
        let (store, witness, pinned) = store_and_witness();
        let [store_key, witness_key] = pinned.clone();
        let text = checkpoint().text();
        let signed = store.sign(&text);
        let both = format!("{signed}{}", witness.cosign_line(&text, T));
        assert_eq!(
            open_witnessed(&both, &store_key, &witness_key, T),
            Ok(checkpoint())
        );
        assert_eq!(
            open_witnessed(&both, &store_key, &witness_key, T - MAX_AHEAD),
            Ok(checkpoint())
        );
        assert_eq!(
            open_witnessed(&both, &store_key, &witness_key, T - MAX_AHEAD - 1),
            Err(NoteError::Unwitnessed(
                "its co-signature is dated ahead of this clock"
            ))
        );
        assert_eq!(
            open_witnessed(&signed, &store_key, &witness_key, T),
            Err(NoteError::Unwitnessed(
                "the pinned witness did not co-sign it"
            ))
        );
        // The witness's co-signature alone is not the store's checkpoint.
        let unsigned = format!("{text}\n{}", witness.cosign_line(&text, T));
        assert_eq!(
            open_witnessed(&unsigned, &store_key, &witness_key, T),
            Err(NoteError::Unwitnessed("the store's key did not sign it"))
        );
        // The witness pinned must be a co-signer, and the store's key must not be one.
        assert!(matches!(
            open_witnessed(&both, &store_key, &store_key, T),
            Err(NoteError::Key(_))
        ));
        assert!(matches!(
            open_witnessed(&both, &witness_key, &witness_key, T),
            Err(NoteError::Key(_))
        ));
    }
}
