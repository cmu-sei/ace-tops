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

//! The credentials agent's escrow key: what every secret escrowed to this agent is sealed to, and what opens it, at
//! the moment an authorized consumer needs it. Generated once, then loaded on every restart (a new key on each start
//! would leave everything sealed to the last one unreadable).
//!
//! P-256, sealed to by HPKE (polar-escrow's `Suite::HpkeP256`), since 2026-11-10 (docs/architecture/key-custody.md,
//! "The credentials agent's keys, P-256"). Before then it was RSA: a start that finds the RSA key at its path makes a
//! P-256 key beside it ([`Loaded::Replacing`]), every secret sealed to the RSA key is sealed again to the new one
//! (`escrow_reseal`), and only then is the RSA key set aside and the new key put in its place ([`Replacing::finish`]).
//!
//! A key of its own, apart from this agent's mTLS key and its authority key: one key, one purpose.

use credentials_agent_common::escrow_secret::{EscrowError, EscrowedSecret};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use zeroize::Zeroizing;

pub const CREDENTIALS_ESCROW_KEY_PATH_ENV: &str = "CREDENTIALS_ESCROW_KEY_PATH";
pub const CREDENTIALS_ESCROW_KEY_PATH_DEFAULT: &str = "/var/lib/credentials-agent/escrow-key.pem";

#[derive(Debug, thiserror::Error)]
pub enum EscrowKeypairError {
    #[error("failed to encode escrow key: {0}")]
    Encoding(String),
    #[error("failed to read existing escrow key at {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse existing escrow key at {path}: {detail}")]
    Parse { path: String, detail: String },
    #[error("failed to write escrow key to {path}: {source}")]
    Write {
        path: String,
        source: std::io::Error,
    },
}

pub struct EscrowKeypair {
    private_key: p256::SecretKey,
    public_key_pem: String,
}

/// What [`EscrowKeypair::load_or_generate`] found at the path.
pub enum Loaded {
    /// A P-256 key, or none and one was made: nothing to move.
    Current(EscrowKeypair),
    /// The RSA key of before 2026-11-10: what is sealed to it is to be sealed again to the new key, then
    /// [`Replacing::finish`].
    Replacing(Replacing),
}

/// The move from the RSA escrow key to a P-256 one, under way. Until [`Replacing::finish`], the RSA key stays at the
/// path and the new key waits beside it, so a start that ends part way through takes up the same new key again.
pub struct Replacing {
    new: EscrowKeypair,
    old: rsa::RsaPrivateKey,
    old_public_key_pem: String,
    path: String,
}

fn pending_path(path: &str) -> String {
    format!("{path}.p256-pending")
}

/// Where the RSA key is set aside once nothing current is sealed to it.
pub fn retired_path(path: &str) -> String {
    format!("{path}.rsa-retired")
}

/// Writes `pem` to `path`, made mode 0600 from the start and never over a file already there.
fn write_private(path: &str, pem: &[u8]) -> Result<(), EscrowKeypairError> {
    let write = |source| EscrowKeypairError::Write {
        path: path.to_string(),
        source,
    };
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent).map_err(write)?;
    }
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut open, 0o600);
    std::io::Write::write_all(&mut open.open(path).map_err(write)?, pem).map_err(write)
}

impl EscrowKeypair {
    fn from_private_key(private_key: p256::SecretKey) -> Result<Self, EscrowKeypairError> {
        let public_key_pem = private_key
            .public_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| EscrowKeypairError::Encoding(e.to_string()))?;
        Ok(Self {
            private_key,
            public_key_pem,
        })
    }

    pub fn generate() -> Result<Self, EscrowKeypairError> {
        loop {
            let bytes = Zeroizing::new(rand::random::<[u8; 32]>());
            if let Ok(key) = p256::SecretKey::from_slice(bytes.as_ref()) {
                return Self::from_private_key(key);
            }
        }
    }

    /// The key at `path`, or a new one made and kept there if there is none. The RSA key of before 2026-11-10 is
    /// [`Loaded::Replacing`]; any other file is refused, never replaced.
    pub fn load_or_generate(path: &str) -> Result<Loaded, EscrowKeypairError> {
        if !std::path::Path::new(path).exists() {
            let keypair = Self::generate()?;
            write_private(path, keypair.private_key_pem()?.as_bytes())?;
            return Ok(Loaded::Current(keypair));
        }
        let pem = Zeroizing::new(std::fs::read_to_string(path).map_err(|source| {
            EscrowKeypairError::Read {
                path: path.to_string(),
                source,
            }
        })?);
        if let Ok(key) = p256::SecretKey::from_pkcs8_pem(&pem) {
            return Ok(Loaded::Current(Self::from_private_key(key)?));
        }
        let old = <rsa::RsaPrivateKey as rsa::pkcs8::DecodePrivateKey>::from_pkcs8_pem(&pem)
            .map_err(|e| EscrowKeypairError::Parse {
                path: path.to_string(),
                detail: format!("neither a P-256 nor an RSA private key: {e}"),
            })?;
        let old_public_key_pem =
            rsa::pkcs8::EncodePublicKey::to_public_key_pem(&old.to_public_key(), LineEnding::LF)
                .map_err(|e| EscrowKeypairError::Encoding(e.to_string()))?;
        let pending = pending_path(path);
        let new = if std::path::Path::new(&pending).exists() {
            match Self::load_or_generate(&pending)? {
                Loaded::Current(new) => new,
                Loaded::Replacing(_) => {
                    return Err(EscrowKeypairError::Parse {
                        path: pending,
                        detail: "not a P-256 private key".to_string(),
                    });
                }
            }
        } else {
            let new = Self::generate()?;
            write_private(&pending, new.private_key_pem()?.as_bytes())?;
            new
        };
        Ok(Loaded::Replacing(Replacing {
            new,
            old,
            old_public_key_pem,
            path: path.to_string(),
        }))
    }

    pub fn public_key_pem(&self) -> &str {
        &self.public_key_pem
    }

    /// The key as PKCS#8 PEM, wiped when dropped: for its certificate's CSR, and to keep it.
    pub fn private_key_pem(&self) -> Result<Zeroizing<String>, EscrowKeypairError> {
        self.private_key
            .to_pkcs8_pem(LineEnding::LF)
            .map(|pem| Zeroizing::new(pem.to_string()))
            .map_err(|e| EscrowKeypairError::Encoding(e.to_string()))
    }

    /// Opens a secret sealed to this key. The plaintext is wiped when dropped: the caller lets it go as soon as it is
    /// sealed again to whoever is to have it.
    pub fn open(&self, secret: &EscrowedSecret) -> Result<Zeroizing<Vec<u8>>, EscrowError> {
        secret.decrypt_p256(&self.private_key)
    }
}

impl Replacing {
    /// The P-256 key that replaces the RSA one: what new secrets are sealed to from this start on.
    pub fn new_keypair(&self) -> &EscrowKeypair {
        &self.new
    }

    pub fn old_public_key_pem(&self) -> &str {
        &self.old_public_key_pem
    }

    /// Opens a secret sealed to the RSA key, to seal it again to the new one.
    pub fn open_old(&self, secret: &EscrowedSecret) -> Result<Zeroizing<Vec<u8>>, EscrowError> {
        secret.decrypt(&self.old)
    }

    /// Once nothing current is sealed to the RSA key: sets it aside ([`retired_path`]), not deleted, and puts the new
    /// key in its place. Ended part way, the next start finds the RSA key still at the path and the new key beside it.
    pub fn finish(self) -> Result<EscrowKeypair, EscrowKeypairError> {
        let retired = retired_path(&self.path);
        if !std::path::Path::new(&retired).exists() {
            // The file as it was, byte for byte.
            let pem = Zeroizing::new(std::fs::read(&self.path).map_err(|source| {
                EscrowKeypairError::Read {
                    path: self.path.clone(),
                    source,
                }
            })?);
            write_private(&retired, &pem)?;
        }
        std::fs::rename(pending_path(&self.path), &self.path).map_err(|source| {
            EscrowKeypairError::Write {
                path: self.path.clone(),
                source,
            }
        })?;
        Ok(self.new)
    }

    /// The new key, the move left unfinished: the RSA key stays at the path, and the next start takes it up again.
    pub fn unfinished(self) -> EscrowKeypair {
        self.new
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// One keypair for every test that needs a valid one but not a particular one.
    pub(crate) fn test_keypair() -> std::sync::Arc<EscrowKeypair> {
        use std::sync::{Arc, OnceLock};
        static KEYPAIR: OnceLock<Arc<EscrowKeypair>> = OnceLock::new();
        KEYPAIR
            .get_or_init(|| Arc::new(EscrowKeypair::generate().unwrap()))
            .clone()
    }

    /// An RSA private key as PKCS#8 PEM, as the escrow key was before 2026-11-10; made once, RSA being slow to make.
    pub(crate) fn rsa_key_pem() -> &'static str {
        static PEM: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        PEM.get_or_init(|| {
            let key = rsa::RsaPrivateKey::new(&mut rand::rng(), 2048).unwrap();
            rsa::pkcs8::EncodePrivateKey::to_pkcs8_pem(&key, LineEnding::LF)
                .unwrap()
                .to_string()
        })
    }

    fn current(loaded: Loaded) -> EscrowKeypair {
        match loaded {
            Loaded::Current(keypair) => keypair,
            Loaded::Replacing(_) => panic!("expected the key at the path"),
        }
    }

    fn replacing(loaded: Loaded) -> Replacing {
        match loaded {
            Loaded::Replacing(replacing) => replacing,
            Loaded::Current(_) => panic!("expected the RSA key being replaced"),
        }
    }

    #[test]
    fn generates_a_pem_encoded_p256_public_key() {
        let keypair = EscrowKeypair::generate().unwrap();
        let pem = keypair.public_key_pem();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(pem.ends_with("-----END PUBLIC KEY-----\n"));
        assert!(
            <p256::PublicKey as p256::pkcs8::DecodePublicKey>::from_public_key_pem(pem).is_ok()
        );
    }

    #[test]
    fn two_generated_keypairs_are_genuinely_different() {
        let a = EscrowKeypair::generate().unwrap();
        let b = EscrowKeypair::generate().unwrap();
        assert_ne!(a.public_key_pem(), b.public_key_pem());
    }

    #[test]
    fn what_is_sealed_to_the_key_opens_with_it_and_by_hpke() {
        let keypair = test_keypair();
        let secret = EscrowedSecret::encrypt(b"token", keypair.public_key_pem()).unwrap();
        assert_eq!(
            secret.suite(),
            credentials_agent_common::escrow_secret::Suite::HpkeP256
        );
        assert_eq!(&*keypair.open(&secret).unwrap(), b"token");
        let other = EscrowKeypair::generate().unwrap();
        assert!(other.open(&secret).is_err());
    }

    #[test]
    fn load_or_generate_persists_a_new_keypair_when_none_exists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("escrow-key.pem");
        assert!(!path.exists());

        let keypair = current(EscrowKeypair::load_or_generate(path.to_str().unwrap()).unwrap());

        assert!(path.exists(), "a new keypair must be persisted to disk");
        assert!(!keypair.public_key_pem().is_empty());
    }

    #[test]
    fn load_or_generate_returns_the_same_key_on_a_second_call() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("escrow-key.pem");

        let first = current(EscrowKeypair::load_or_generate(path.to_str().unwrap()).unwrap());
        let second = current(EscrowKeypair::load_or_generate(path.to_str().unwrap()).unwrap());

        assert_eq!(first.public_key_pem(), second.public_key_pem());
    }

    #[cfg(unix)]
    #[test]
    fn persisted_key_file_has_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("escrow-key.pem");
        EscrowKeypair::load_or_generate(path.to_str().unwrap()).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "persisted escrow key must be mode 0600");
    }

    #[test]
    fn load_or_generate_creates_missing_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("nested")
            .join("dirs")
            .join("escrow-key.pem");
        assert!(!path.parent().unwrap().exists());

        EscrowKeypair::load_or_generate(path.to_str().unwrap()).unwrap();

        assert!(path.exists());
    }

    #[test]
    fn a_file_that_is_no_private_key_is_refused_and_left_as_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("escrow-key.pem");
        std::fs::write(&path, "not a key").unwrap();
        assert!(EscrowKeypair::load_or_generate(path.to_str().unwrap()).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not a key");
    }

    // docs/architecture/key-custody.md, "The credentials agent's keys, P-256", K2: the RSA key is replaced by a P-256 one
    // kept beside it until what was sealed to it is sealed again; then it is set aside, and the new key takes its place.
    #[cfg(unix)]
    #[test]
    fn the_rsa_key_is_replaced_by_a_p256_one_kept_beside_it_until_the_move_is_finished() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("escrow-key.pem");
        let path = path.to_str().unwrap();
        std::fs::write(path, rsa_key_pem()).unwrap();

        let first = replacing(EscrowKeypair::load_or_generate(path).unwrap());
        let sealed = EscrowedSecret::encrypt(b"old", first.old_public_key_pem()).unwrap();
        assert_eq!(&*first.open_old(&sealed).unwrap(), b"old");
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            rsa_key_pem(),
            "the RSA key stays until the move is finished"
        );
        let new_pem = first.new_keypair().public_key_pem().to_string();

        // A start that ended part way takes up the same new key, not another.
        let again = replacing(EscrowKeypair::load_or_generate(path).unwrap());
        assert_eq!(again.new_keypair().public_key_pem(), new_pem);

        assert_eq!(again.finish().unwrap().public_key_pem(), new_pem);
        // From now on the new key is the one at the path, and nothing waits beside it.
        assert_eq!(
            current(EscrowKeypair::load_or_generate(path).unwrap()).public_key_pem(),
            new_pem
        );
        assert!(!std::path::Path::new(&pending_path(path)).exists());
        // The RSA key is set aside as it was, private, not deleted.
        let retired = retired_path(path);
        assert_eq!(std::fs::read_to_string(&retired).unwrap(), rsa_key_pem());
        assert_eq!(
            std::fs::metadata(&retired).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn a_move_left_unfinished_leaves_the_rsa_key_at_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("escrow-key.pem");
        let path = path.to_str().unwrap();
        std::fs::write(path, rsa_key_pem()).unwrap();
        let new_pem = replacing(EscrowKeypair::load_or_generate(path).unwrap())
            .unfinished()
            .public_key_pem()
            .to_string();
        assert_eq!(std::fs::read_to_string(path).unwrap(), rsa_key_pem());
        assert!(!std::path::Path::new(&retired_path(path)).exists());
        assert_eq!(
            replacing(EscrowKeypair::load_or_generate(path).unwrap())
                .new_keypair()
                .public_key_pem(),
            new_pem
        );
    }
}
