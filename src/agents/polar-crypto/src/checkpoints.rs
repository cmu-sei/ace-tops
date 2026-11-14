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

//! A log's checkpoint key, kept by the crypto actor of the agent that keeps the logs (docs/plans/record-store/to-main.md).
//! The key is P-256, in a PKCS#8 PEM file on the workload's own volume: made once if the file is not there, readable by
//! the agent alone, and never replaced, since readers and witnesses pin it. The actor signs with it only a checkpoint of
//! one of this agent's own logs, in its one form: three lines (the origin `<identity>/<log>`, the size in decimal, the
//! root in base64) and nothing else. Its certificate, from the credentials agent, is kept beside it.
//!
//! A witness's co-signing key is kept the same way by the witness's crypto actor: it co-signs only a checkpoint of the
//! store it is pinned to, by that store's checkpoint verifier key in the agent's signed configuration, and stamps the
//! co-signature with its own clock's time.

use p256::ecdsa::SigningKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use polar_log::checkpoint::{Checkpoint, Cosigner, NoteSigner, NoteVerifier};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// The name the checkpoints are signed under, after the agent's identity: `<identity>/checkpoint`.
pub const KEY_NAME: &str = "checkpoint";

/// The name a witness co-signs under, after its identity: `<identity>/witness`.
pub const WITNESS_NAME: &str = "witness";

/// Why a checkpoint was not signed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointRefusal {
    #[error("this agent keeps no checkpoint key")]
    NoKey,
    #[error("this agent has no identity to name its logs by")]
    NoIdentity,
    #[error("it is not a checkpoint in its one form: {0}")]
    NotACheckpoint(String),
    #[error("its origin `{0}` is not one of this agent's logs")]
    NotItsLog(String),
    #[error("no store is pinned for this witness to co-sign for")]
    NoStore,
    #[error("its origin `{0}` is not one of the pinned store's logs")]
    NotTheStore(String),
}

/// Whether `name` is a log's name: one or more of a-z, 0-9 and -.
pub fn is_log_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Whether `text` is a checkpoint the agent `identity` may sign: one of its own logs' (`<identity>/<log>`), in the one
/// form a checkpoint is written in, so nothing else can ever be signed under the key.
pub fn judge(identity: &str, text: &str) -> Result<Checkpoint, CheckpointRefusal> {
    let checkpoint =
        Checkpoint::parse(text).map_err(|e| CheckpointRefusal::NotACheckpoint(e.to_string()))?;
    if checkpoint.text() != text {
        return Err(CheckpointRefusal::NotACheckpoint(
            "it is not written as a checkpoint is".to_string(),
        ));
    }
    match checkpoint.origin.strip_prefix(identity) {
        Some(rest) if rest.strip_prefix('/').is_some_and(is_log_name) => Ok(checkpoint),
        _ => Err(CheckpointRefusal::NotItsLog(checkpoint.origin.clone())),
    }
}

/// The store a witness co-signs for, from its pinned verifier key: the identity its checkpoint key is named by, when the
/// key is a store's checkpoint key (`<identity>/checkpoint`, a note signer's, not a co-signer's).
pub fn pinned_store(verifier_key: &str) -> Result<String, String> {
    let verifier = NoteVerifier::parse(verifier_key.trim()).map_err(|e| e.to_string())?;
    if verifier.is_cosigner() {
        return Err(format!(
            "the key `{}` is a co-signer's, not a store's checkpoint key",
            verifier.name()
        ));
    }
    verifier
        .name()
        .strip_suffix(&format!("/{KEY_NAME}"))
        .filter(|identity| !identity.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            format!(
                "the key `{}` is not a store's checkpoint key (`<identity>/{KEY_NAME}`)",
                verifier.name()
            )
        })
}

/// Whether `text` is a checkpoint a witness pinned to `store` (its identity) may co-sign: one of that store's logs', in
/// the one form a checkpoint is written in.
pub fn judge_cosign(store: &str, text: &str) -> Result<Checkpoint, CheckpointRefusal> {
    judge(store, text).map_err(|refusal| match refusal {
        CheckpointRefusal::NotItsLog(origin) => CheckpointRefusal::NotTheStore(origin),
        other => other,
    })
}

/// Where the key's certificate is kept: beside it, `<stem>.chain.pem`.
pub fn chain_path(key: &Path) -> PathBuf {
    let stem = key
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    key.with_file_name(format!("{stem}.chain.pem"))
}

/// The key at `path`, or a new one made there: owner-only, never over a file. A file that is not a P-256 key is
/// refused, never replaced.
pub fn load_or_make_key(path: &Path) -> Result<SigningKey, String> {
    let io = |e: std::io::Error| format!("{}: {e}", path.display());
    if path.exists() {
        let pem = Zeroizing::new(std::fs::read_to_string(path).map_err(io)?);
        return SigningKey::from_pkcs8_pem(&pem)
            .map_err(|e| format!("{} is not a P-256 key: {e}", path.display()));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(io)?;
    }
    let key = loop {
        if let Ok(key) = SigningKey::from_slice(&rand::random::<[u8; 32]>()) {
            break key;
        }
    };
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| format!("the new key does not encode: {e}"))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    std::io::Write::write_all(&mut options.open(path).map_err(io)?, pem.as_bytes()).map_err(io)?;
    Ok(key)
}

/// The agent's checkpoint key: what it signs with, its name, and its certificate once it has one.
pub struct CheckpointKey {
    path: PathBuf,
    identity: String,
    signer: NoteSigner,
    key_pem: Zeroizing<String>,
    public_der: Vec<u8>,
    /// The certificate and its CA chain, as PEM, and when it expires (Unix seconds).
    certificate: Option<(String, i64)>,
}

impl CheckpointKey {
    /// The key at `path` (made there if it is not), signing as `identity`'s, with the certificate kept beside it when
    /// it is this key's.
    pub fn open(path: &Path, identity: &str) -> Result<Self, String> {
        let key = load_or_make_key(path)?;
        let signer = NoteSigner::new(&format!("{identity}/{KEY_NAME}"), key.clone())
            .map_err(|e| format!("the checkpoint key cannot sign as {identity}: {e}"))?;
        let key_pem = Zeroizing::new(
            key.to_pkcs8_pem(LineEnding::LF)
                .map_err(|e| format!("the checkpoint key does not encode: {e}"))?
                .to_string(),
        );
        let public_der = key
            .verifying_key()
            .to_public_key_der()
            .map_err(|e| format!("the checkpoint key's public half does not encode: {e}"))?
            .as_bytes()
            .to_vec();
        let mut opened = Self {
            path: path.to_path_buf(),
            identity: identity.to_string(),
            signer,
            key_pem,
            public_der,
            certificate: None,
        };
        if let Ok(chain) = std::fs::read_to_string(chain_path(path)) {
            opened.certificate = opened.certifies(&chain);
        }
        Ok(opened)
    }

    /// `text`'s signature line, if it is a checkpoint of one of this agent's logs ([`judge`]).
    pub fn sign(&self, text: &str) -> Result<String, CheckpointRefusal> {
        judge(&self.identity, text)?;
        Ok(self.signer.sign_line(text))
    }

    /// The verifier key readers and witnesses pin.
    pub fn verifier_key(&self) -> String {
        self.signer.verifier_key()
    }

    /// A CSR for the key, naming the agent's identity and nothing else.
    pub fn csr(&self) -> Result<String, String> {
        cert_issuer_common::keypair::csr_for_private_key_pem(&self.identity, &[], &self.key_pem)
            .map_err(|e| format!("the checkpoint key's CSR: {e}"))
    }

    /// Its certificate and CA chain, as PEM, once it has one.
    pub fn certificate(&self) -> Option<&str> {
        self.certificate.as_ref().map(|(pem, _)| pem.as_str())
    }

    /// When its certificate expires, in Unix seconds, once it has one.
    pub fn expires_at(&self) -> Option<i64> {
        self.certificate.as_ref().map(|(_, at)| *at)
    }

    /// Takes `chain` (the certificate, then its CA chain) as the key's certificate if it is this key's, and keeps it
    /// beside the key; otherwise refuses it, and keeps what it had.
    pub fn keep_certificate(&mut self, chain: &str) -> Result<(), String> {
        let Some(certified) = self.certifies(chain) else {
            return Err("the certificate is not this checkpoint key's, for this agent".to_string());
        };
        let path = chain_path(&self.path);
        let staged = path.with_extension("pem.new");
        std::fs::write(&staged, chain)
            .and_then(|()| std::fs::rename(&staged, &path))
            .map_err(|e| format!("{}: {e}", path.display()))?;
        self.certificate = Some(certified);
        Ok(())
    }

    /// The certificate in `chain` and when it expires, when it is a certificate of this key naming this agent.
    fn certifies(&self, chain: &str) -> Option<(String, i64)> {
        let first = chain.split_inclusive("-----END CERTIFICATE-----").next()?;
        let (_, pem) = x509_parser::pem::parse_x509_pem(first.trim_start().as_bytes()).ok()?;
        let certificate = pem.parse_x509().ok()?;
        let named =
            cert_issuer_common::permission::extract_own_identity(first.trim_start()).ok()?;
        (certificate.public_key().raw == self.public_der.as_slice() && named == self.identity).then(
            || {
                (
                    chain.to_string(),
                    certificate.validity().not_after.timestamp(),
                )
            },
        )
    }
}

/// A witness's co-signing key: what it co-signs with, under `<identity>/witness`.
pub struct WitnessKey {
    cosigner: Cosigner,
}

impl WitnessKey {
    /// The key at `path` (made there if it is not), co-signing as `identity`'s witness.
    pub fn open(path: &Path, identity: &str) -> Result<Self, String> {
        let key = load_or_make_key(path)?;
        Ok(Self {
            cosigner: Cosigner::new(&format!("{identity}/{WITNESS_NAME}"), key)
                .map_err(|e| format!("the witness key cannot co-sign as {identity}: {e}"))?,
        })
    }

    /// `text`'s co-signature line at `time` (Unix seconds), if it is a checkpoint of one of `store`'s logs
    /// ([`judge_cosign`]).
    pub fn cosign(&self, store: &str, text: &str, time: u64) -> Result<String, CheckpointRefusal> {
        judge_cosign(store, text)?;
        Ok(self.cosigner.cosign_line(text, time))
    }

    /// The verifier key the store and readers pin.
    pub fn verifier_key(&self) -> String {
        self.cosigner.verifier_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_log::checkpoint::{NoteVerifier, open};
    use proptest::prelude::*;

    const STORE: &str = "polar-git-server.polar.serviceaccount.cluster.local";

    fn checkpoint(origin: &str, size: u64, root: [u8; 32]) -> String {
        Checkpoint {
            origin: origin.to_string(),
            size,
            root,
        }
        .text()
    }

    /// A certificate naming `identity` for the key in `key_pem`, from a CA of its own: the chain, as cert-issuer answers.
    fn certificate(identity: &str, key_pem: &str) -> String {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca = rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .self_signed(&ca_key)
            .unwrap();
        let issuer = rcgen::Issuer::new(rcgen::CertificateParams::default(), ca_key);
        let key = rcgen::KeyPair::from_pem(key_pem).unwrap();
        let leaf = rcgen::CertificateParams::new(vec![identity.to_string()])
            .unwrap()
            .signed_by(&key, &issuer)
            .unwrap();
        format!("{}{}", leaf.pem(), ca.pem())
    }

    #[test]
    fn the_key_is_made_once_kept_private_and_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logs/checkpoint-key.pem");
        let made = load_or_make_key(&path).unwrap();
        let mode = std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(&path).unwrap());
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(
            load_or_make_key(&path).unwrap(),
            made,
            "read back, not made again"
        );
        // A file that is not a key is refused, and left as it was.
        std::fs::write(&path, "not a key").unwrap();
        assert!(load_or_make_key(&path).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not a key");
    }

    /// The key made before this (the store's own, on acp: a PKCS#8 PEM P-256 key) is read as it is, so the pins that
    /// name it hold.
    #[test]
    fn a_key_already_there_is_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint-key.pem");
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        std::fs::write(&path, key.to_pkcs8_pem(LineEnding::LF).unwrap()).unwrap();
        let opened = CheckpointKey::open(&path, STORE).unwrap();
        let expected = NoteSigner::new(&format!("{STORE}/{KEY_NAME}"), key).unwrap();
        assert_eq!(opened.verifier_key(), expected.verifier_key());
    }

    #[test]
    fn a_certificate_is_kept_only_when_it_is_this_key_s_for_this_agent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint-key.pem");
        let mut key = CheckpointKey::open(&path, STORE).unwrap();
        assert_eq!(key.certificate(), None);
        let other = SigningKey::from_slice(&[9; 32]).unwrap();
        let other_pem = other.to_pkcs8_pem(LineEnding::LF).unwrap();
        for (what, chain) in [
            ("another key's", certificate(STORE, &other_pem)),
            ("another agent's", certificate("someone-else", &key.key_pem)),
        ] {
            assert!(key.keep_certificate(&chain).is_err(), "{what}");
            assert_eq!(key.certificate(), None, "{what}");
        }
        let own = certificate(STORE, &key.key_pem);
        key.keep_certificate(&own).unwrap();
        assert_eq!(key.certificate(), Some(own.as_str()));
        assert!(key.expires_at().is_some());
        // Kept beside the key, and read back at the next start.
        let reopened = CheckpointKey::open(&path, STORE).unwrap();
        assert_eq!(reopened.certificate(), Some(own.as_str()));
    }

    #[test]
    fn the_csr_names_the_agent_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let key = CheckpointKey::open(&dir.path().join("k.pem"), STORE).unwrap();
        let csr = key.csr().unwrap();
        let (_, pem) = x509_parser::pem::parse_x509_pem(csr.as_bytes()).unwrap();
        let (_, request) = <x509_parser::certification_request::X509CertificationRequest as
            x509_parser::prelude::FromDer<_>>::from_der(&pem.contents)
        .unwrap();
        assert_eq!(
            request.certification_request_info.subject_pki.raw,
            key.public_der.as_slice(),
            "for this key"
        );
        let names: Vec<String> = request
            .requested_extensions()
            .into_iter()
            .flatten()
            .filter_map(|e| match e {
                x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => Some(
                    san.general_names
                        .iter()
                        .map(|n| n.to_string())
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(names, [format!("DNSName({STORE})")]);
    }

    fn log_name() -> impl Strategy<Value = String> {
        "[a-z0-9-]{1,12}"
    }

    proptest! {
        /// A checkpoint of one of the agent's own logs, of any size and root, is signed, and the signature is the
        /// key's under the name readers pin: the note opens under the verifier key.
        #[test]
        fn a_checkpoint_of_its_own_log_is_signed_and_opens_under_its_key(
            log in log_name(),
            size in any::<u64>(),
            root in any::<[u8; 32]>(),
        ) {
            let dir = tempfile::tempdir().unwrap();
            let key = CheckpointKey::open(&dir.path().join("k.pem"), STORE).unwrap();
            let text = checkpoint(&format!("{STORE}/{log}"), size, root);
            let line = key.sign(&text).unwrap();
            let verifier = NoteVerifier::parse(&key.verifier_key()).unwrap();
            let (opened, _) = open(&format!("{text}\n{line}"), &[verifier]).unwrap();
            prop_assert_eq!(opened, text);
        }

        /// Nothing but a checkpoint of one of the agent's own logs is signed: another agent's, a name that is not a
        /// log's, or the right checkpoint written any other way.
        #[test]
        fn nothing_but_a_checkpoint_of_its_own_log_is_signed(
            log in log_name(),
            size in any::<u64>(),
            root in any::<[u8; 32]>(),
            other in "[a-zA-Z0-9./ -]{0,20}",
            change in 0usize..6,
        ) {
            let text = checkpoint(&format!("{STORE}/{log}"), size, root);
            let bad = match change {
                // Another agent's log.
                0 => checkpoint(&format!("other.{STORE}/{log}"), size, root),
                // The agent's identity, but no log's name after it.
                1 => checkpoint(&format!("{STORE}/{log}/{other}"), size, root),
                2 => checkpoint(STORE, size, root),
                // An extension line, or the closing newline gone.
                3 => format!("{text}{other}\n"),
                4 => text.trim_end_matches('\n').to_string(),
                // Something else entirely.
                _ => other.clone(),
            };
            prop_assume!(bad != text);
            prop_assert!(judge(STORE, &bad).is_err(), "{bad:?}");
        }
    }

    const WITNESS: &str = "attestation-agent.polar.serviceaccount.cluster.local";

    /// The store's checkpoint key and its pin, as the witness's signed configuration carries it.
    fn store_key() -> (CheckpointKey, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (
            CheckpointKey::open(&dir.path().join("k.pem"), STORE).unwrap(),
            dir,
        )
    }

    #[test]
    fn a_store_is_pinned_by_its_checkpoint_key_and_by_nothing_else() {
        let (store, _dir) = store_key();
        assert_eq!(pinned_store(&store.verifier_key()).unwrap(), STORE);
        assert_eq!(
            pinned_store(crate::environment::EXAMPLE_STORE).unwrap(),
            STORE,
            "the scaffold's example is a store's"
        );
        let dir = tempfile::tempdir().unwrap();
        let witness = WitnessKey::open(&dir.path().join("w.pem"), WITNESS).unwrap();
        assert!(
            pinned_store(&witness.verifier_key()).is_err(),
            "a witness's key"
        );
        let not_a_checkpoint_key = NoteSigner::new(
            &format!("{STORE}/other"),
            SigningKey::from_slice(&[3; 32]).unwrap(),
        )
        .unwrap()
        .verifier_key();
        assert!(pinned_store(&not_a_checkpoint_key).is_err());
        assert!(pinned_store("not a key").is_err());
    }

    /// The witness key already on the cluster (acp's, PKCS#8 PEM P-256, under `<identity>/witness`) is read as it is, so
    /// the store's pin of it holds.
    #[test]
    fn a_witness_key_already_there_is_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("witness-key.pem");
        let key = SigningKey::from_slice(&[5; 32]).unwrap();
        std::fs::write(&path, key.to_pkcs8_pem(LineEnding::LF).unwrap()).unwrap();
        let expected = Cosigner::new(&format!("{WITNESS}/{WITNESS_NAME}"), key).unwrap();
        assert_eq!(
            WitnessKey::open(&path, WITNESS).unwrap().verifier_key(),
            expected.verifier_key()
        );
    }

    proptest! {
        /// A checkpoint of one of the pinned store's logs, signed by the store, is co-signed so that a reader holding
        /// both pins takes it, at the time stated.
        #[test]
        fn a_checkpoint_of_the_pinned_store_is_cosigned_as_a_reader_takes_it(
            log in log_name(),
            size in any::<u64>(),
            root in any::<[u8; 32]>(),
            at in 0u64..4_000_000_000,
        ) {
            let (store, _store_dir) = store_key();
            let dir = tempfile::tempdir().unwrap();
            let witness = WitnessKey::open(&dir.path().join("w.pem"), WITNESS).unwrap();
            let text = checkpoint(&format!("{STORE}/{log}"), size, root);
            let note = format!(
                "{text}\n{}{}",
                store.sign(&text).unwrap(),
                witness.cosign(STORE, &text, at).unwrap()
            );
            let opened = polar_log::checkpoint::open_witnessed(
                &note,
                &NoteVerifier::parse(&store.verifier_key()).unwrap(),
                &NoteVerifier::parse(&witness.verifier_key()).unwrap(),
                at,
            )
            .unwrap();
            prop_assert_eq!(opened.text(), text);
        }

        /// Nothing but a checkpoint of the pinned store's logs is co-signed: another store's, or the right one written
        /// any other way.
        #[test]
        fn nothing_but_the_pinned_store_s_checkpoint_is_cosigned(
            log in log_name(),
            size in any::<u64>(),
            root in any::<[u8; 32]>(),
            other in "[a-zA-Z0-9./ -]{0,20}",
            change in 0usize..5,
        ) {
            let text = checkpoint(&format!("{STORE}/{log}"), size, root);
            let bad = match change {
                0 => checkpoint(&format!("{WITNESS}/{log}"), size, root),
                1 => checkpoint(&format!("{STORE}/{log}/{other}"), size, root),
                2 => format!("{text}{other}\n"),
                3 => text.trim_end_matches('\n').to_string(),
                _ => other.clone(),
            };
            prop_assume!(bad != text);
            prop_assert!(judge_cosign(STORE, &bad).is_err(), "{bad:?}");
        }
    }
}
