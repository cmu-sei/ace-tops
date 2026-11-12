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

//! The ledger key (docs/architecture/record-store.md, "L2, checkpoints"): a P-256 key that signs the ledger's checkpoints
//! and nothing else. Made once and kept beside the ledger: a key made anew on every start would sign checkpoints no
//! earlier one could be checked against.

use p256::ecdsa::SigningKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use zeroize::Zeroizing;

/// A new key, from 32 random bytes that are a valid scalar.
fn generate() -> SigningKey {
    loop {
        let bytes = Zeroizing::new(rand::random::<[u8; 32]>());
        if let Ok(key) = SigningKey::from_slice(bytes.as_ref()) {
            return key;
        }
    }
}

/// The key at `path`, or a new one made and kept there (mode 0600) if there is none. A file that is not a P-256 key is
/// refused, never replaced.
pub fn load_or_generate(path: &str) -> Result<SigningKey, String> {
    let file = std::path::Path::new(path);
    if file.exists() {
        let pem = Zeroizing::new(
            std::fs::read_to_string(file).map_err(|e| format!("cannot read {path}: {e}"))?,
        );
        return SigningKey::from_pkcs8_pem(&pem)
            .map_err(|e| format!("{path} is not a P-256 private key: {e}"));
    }
    let key = generate();
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot make {}: {e}", parent.display()))?;
    }
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| format!("the ledger key does not encode: {e}"))?;
    // Made private from the start, never readable by others for a moment, and never over a file that appeared meanwhile.
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut open, 0o600);
    std::io::Write::write_all(
        &mut open
            .open(file)
            .map_err(|e| format!("cannot make {path}: {e}"))?,
        pem.as_bytes(),
    )
    .map_err(|e| format!("cannot write {path}: {e}"))?;
    Ok(key)
}

/// The key as PKCS#8 PEM, wiped when dropped: for its certificate's CSR.
pub fn pkcs8_pem(key: &SigningKey) -> Result<Zeroizing<String>, String> {
    key.to_pkcs8_pem(LineEnding::LF)
        .map(|pem| Zeroizing::new(pem.to_string()))
        .map_err(|e| format!("the ledger key does not encode: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_is_made_once_kept_private_and_read_back_as_itself() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys/ledger-key.pem");
        let path = path.to_str().unwrap();
        let made = load_or_generate(path).unwrap();
        let again = load_or_generate(path).unwrap();
        assert_eq!(
            made.verifying_key(),
            again.verifying_key(),
            "the same key on the next start"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let other = tempfile::tempdir().unwrap();
        let elsewhere = other.path().join("ledger-key.pem");
        assert_ne!(
            load_or_generate(elsewhere.to_str().unwrap())
                .unwrap()
                .verifying_key(),
            made.verifying_key(),
            "a key of its own where there was none"
        );
        std::fs::write(&elsewhere, "not a key").unwrap();
        assert!(load_or_generate(elsewhere.to_str().unwrap()).is_err());
        assert_eq!(
            std::fs::read_to_string(&elsewhere).unwrap(),
            "not a key",
            "never replaced"
        );
    }
}
