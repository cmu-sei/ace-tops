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

//! The ledger's checkpoints (docs/architecture/record-store.md, "L2, checkpoints"): its tree's size and root, signed
//! with the ledger key, a P-256 key of its own that signs nothing else, certified as a checkpoint key. The latest is
//! kept beside the ledger, so that an agent finding a ledger that is not the one it signed (an older copy put back,
//! which would forget every revocation since) refuses to serve it, as it refuses a ledger it cannot read.

use crate::ledger::LedgerKey;
use polar_log::checkpoint::{Checkpoint, NoteSigner, NoteVerifier};
use polar_log::file::FileLog;
use std::path::{Path, PathBuf};

/// Where the latest checkpoint of the ledger at `ledger` is kept: beside it, as `.checkpoint`.
pub fn kept_path(ledger: &Path) -> PathBuf {
    ledger.with_extension("checkpoint")
}

/// Where the ledger key's latest certificate is kept: beside the key, as `.crt`.
pub fn certificate_path(key: &Path) -> PathBuf {
    key.with_extension("crt")
}

/// The ledger's name in its checkpoints, as the store names a log of its own: its keeper's identity and `ledger`.
pub fn origin(identity: &str) -> String {
    format!("{identity}/ledger")
}

/// The ledger key's name in a checkpoint's signature line, as the store names its own key.
pub fn key_name(identity: &str) -> String {
    format!("{identity}/checkpoint")
}

/// Writes `bytes` to `path` whole or not at all: to a new file beside it, synced, renamed over it, and the directory
/// synced, so a crash leaves the one before or this one.
pub fn write_whole(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut fresh = path.as_os_str().to_owned();
    fresh.push(".new");
    let fresh = PathBuf::from(fresh);
    let failed = |path: &Path| {
        let path = path.display().to_string();
        move |e: std::io::Error| format!("writing {path}: {e}")
    };
    {
        let mut file = std::fs::File::create(&fresh).map_err(failed(&fresh))?;
        std::io::Write::write_all(&mut file, bytes).map_err(failed(&fresh))?;
        file.sync_all().map_err(failed(&fresh))?;
    }
    std::fs::rename(&fresh, path).map_err(failed(path))?;
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(failed(dir))?;
    }
    Ok(())
}

/// What signs the ledger's checkpoints, and the size of the one it keeps.
pub struct Checkpoints {
    signer: NoteSigner,
    origin: String,
    kept: PathBuf,
    signed: Option<u64>,
}

/// What opening the ledger's checkpoints found.
pub enum Kept {
    Ready(Checkpoints),
    /// Why the ledger is not the one this agent signed, in one line.
    Refused(String),
}

impl Checkpoints {
    /// The ledger key, made at the first start and never replaced, and the checkpoint kept beside the ledger at
    /// `ledger`, which `log` must still hold: signed by that key, naming this ledger, and its tree the ledger's own at
    /// its size. A kept checkpoint whose key is gone is refused, and no key is made in its place.
    pub fn open(ledger: &Path, log: &FileLog, key: &LedgerKey) -> Result<Kept, String> {
        let kept = kept_path(ledger);
        let note = match std::fs::read_to_string(&kept) {
            Ok(note) => Some(note),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("reading {}: {e}", kept.display())),
        };
        let shown = kept.display().to_string();
        let refused = |why: String| {
            Ok(Kept::Refused(format!(
                "{why}: it is not the ledger this agent signed (an older copy put back?), and it serves nothing until \
                 the ledger it signed is put back, or a person removes {shown} to accept the ledger as it is"
            )))
        };
        if note.is_some() && !Path::new(&key.path).exists() {
            return refused(format!(
                "the ledger's last checkpoint is kept at {shown}, but the key that signed it, at {}, is gone",
                key.path
            ));
        }
        let signing_key = crate::authority_key::load_or_generate(&key.path)?;
        let signer = NoteSigner::new(&key_name(&key.identity), signing_key)
            .map_err(|e| format!("the ledger key's name: {e}"))?;
        let origin = origin(&key.identity);
        let mut checkpoints = Checkpoints {
            signer,
            origin,
            kept,
            signed: None,
        };
        let Some(note) = note else {
            return Ok(Kept::Ready(checkpoints));
        };
        let verifier = NoteVerifier::parse(&checkpoints.signer.verifier_key())
            .map_err(|e| format!("the ledger key's verifier: {e}"))?;
        let checkpoint = match polar_log::checkpoint::open(&note, &[verifier])
            .map_err(|e| e.to_string())
            .and_then(|(text, _)| Checkpoint::parse(&text).map_err(|e| e.to_string()))
        {
            Ok(checkpoint) => checkpoint,
            Err(e) => {
                return refused(format!(
                    "the ledger's last checkpoint is not one the ledger key signed ({e})"
                ));
            }
        };
        if checkpoint.origin != checkpoints.origin {
            return refused(format!(
                "the ledger's last checkpoint is of `{}`, not of this ledger, `{}`",
                checkpoint.origin, checkpoints.origin
            ));
        }
        if checkpoint.size > log.size() {
            return refused(format!(
                "the ledger holds {} entries, and its last checkpoint was signed at {}",
                log.size(),
                checkpoint.size
            ));
        }
        let root = polar_log::merkle::root(&log.hashes()[..checkpoint.size as usize]);
        if root != checkpoint.root {
            return refused(format!(
                "the ledger's first {} entries are not those its last checkpoint was signed over",
                checkpoint.size
            ));
        }
        checkpoints.signed = Some(checkpoint.size);
        Ok(Kept::Ready(checkpoints))
    }

    /// Signs `log`'s tree and keeps the checkpoint, unless the one kept is already of its size: the size kept, if a new
    /// one was.
    pub fn sign(&mut self, log: &FileLog) -> Result<Option<u64>, String> {
        let size = log.size();
        if self.signed == Some(size) {
            return Ok(None);
        }
        let note = self.signer.sign(
            &Checkpoint {
                origin: self.origin.clone(),
                size,
                root: log.root(),
            }
            .text(),
        );
        write_whole(&self.kept, note.as_bytes())?;
        self.signed = Some(size);
        Ok(Some(size))
    }

    /// The size of the checkpoint kept, if there is one.
    pub fn signed(&self) -> Option<u64> {
        self.signed
    }

    /// The ledger key's verifier key: what a reader opens its checkpoints with.
    pub fn verifier_key(&self) -> String {
        self.signer.verifier_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_log::entry::Leaf;
    use proptest::prelude::*;

    const IDENTITY: &str = "credentials-agent.polar.serviceaccount.cluster.local";

    fn leaf(n: u64) -> Leaf {
        Leaf {
            entry: format!("entry {n}").into_bytes(),
            admitted_at_ms: n,
            submitter: "credentials-agent".to_string(),
        }
    }

    /// A ledger at `path` holding `leaves`, made anew.
    fn ledger(path: &Path, leaves: &[Leaf]) -> FileLog {
        let _ = std::fs::remove_file(path);
        let mut log = FileLog::open(path).unwrap().log;
        if !leaves.is_empty() {
            log.append_all(leaves).unwrap();
        }
        log
    }

    fn key(dir: &Path) -> LedgerKey {
        LedgerKey {
            path: dir.join("ledger-key.pem").display().to_string(),
            identity: IDENTITY.to_string(),
        }
    }

    fn ready(kept: Kept) -> Checkpoints {
        match kept {
            Kept::Ready(checkpoints) => checkpoints,
            Kept::Refused(why) => panic!("refused: {why}"),
        }
    }

    fn refused(kept: Kept) -> String {
        match kept {
            Kept::Ready(_) => panic!("not refused"),
            Kept::Refused(why) => why,
        }
    }

    #[test]
    fn a_checkpoint_is_signed_over_the_ledger_s_tree_kept_beside_it_and_opened_with_the_ledger_key()
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let log = ledger(&path, &[leaf(0), leaf(1), leaf(2)]);
        let mut checkpoints = ready(Checkpoints::open(&path, &log, &key(dir.path())).unwrap());
        assert_eq!(checkpoints.signed(), None, "nothing kept before the first");
        assert!(Path::new(&key(dir.path()).path).exists(), "the key is made");
        assert_eq!(checkpoints.sign(&log).unwrap(), Some(3));
        assert_eq!(checkpoints.sign(&log).unwrap(), None, "the same tree again");

        let note = std::fs::read_to_string(dir.path().join("ledger.checkpoint")).unwrap();
        let verifier = NoteVerifier::parse(&checkpoints.verifier_key()).unwrap();
        let (text, by) = polar_log::checkpoint::open(&note, &[verifier]).unwrap();
        assert_eq!(by, vec![format!("{IDENTITY}/checkpoint")]);
        assert_eq!(
            Checkpoint::parse(&text).unwrap(),
            Checkpoint {
                origin: format!("{IDENTITY}/ledger"),
                size: 3,
                root: log.root(),
            }
        );
    }

    #[test]
    fn the_key_and_the_kept_checkpoint_outlive_a_restart_and_a_grown_ledger_is_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let mut log = ledger(&path, &[leaf(0), leaf(1)]);
        let mut first = ready(Checkpoints::open(&path, &log, &key(dir.path())).unwrap());
        first.sign(&log).unwrap();
        log.append(&leaf(2)).unwrap();
        drop(log);
        let log = FileLog::open(&path).unwrap().log;
        let again = ready(Checkpoints::open(&path, &log, &key(dir.path())).unwrap());
        assert_eq!(again.signed(), Some(2), "the kept one, behind the ledger");
        assert_eq!(again.verifier_key(), first.verifier_key(), "the same key");
    }

    #[test]
    fn a_ledger_rolled_back_or_rewritten_behind_its_checkpoint_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let log = ledger(&path, &[leaf(0), leaf(1), leaf(2)]);
        ready(Checkpoints::open(&path, &log, &key(dir.path())).unwrap())
            .sign(&log)
            .unwrap();
        drop(log);

        let older = ledger(&path, &[leaf(0), leaf(1)]);
        let why = refused(Checkpoints::open(&path, &older, &key(dir.path())).unwrap());
        assert!(
            why.contains("holds 2 entries, and its last checkpoint was signed at 3"),
            "{why}"
        );
        assert!(why.contains("ledger.checkpoint to accept"), "{why}");
        drop(older);

        let other = ledger(&path, &[leaf(0), leaf(1), leaf(9), leaf(3)]);
        let why = refused(Checkpoints::open(&path, &other, &key(dir.path())).unwrap());
        assert!(why.contains("first 3 entries are not those"), "{why}");
    }

    #[test]
    fn a_checkpoint_under_another_key_or_of_another_ledger_is_refused_and_a_lost_key_is_not_made_again()
     {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let log = ledger(&path, &[leaf(0)]);
        ready(Checkpoints::open(&path, &log, &key(dir.path())).unwrap())
            .sign(&log)
            .unwrap();

        let elsewhere = tempfile::tempdir().unwrap();
        let why = refused(Checkpoints::open(&path, &log, &key(elsewhere.path())).unwrap());
        assert!(why.contains("is gone"), "{why}");
        assert!(
            !Path::new(&key(elsewhere.path()).path).exists(),
            "no key is made in its place"
        );

        let another = key(elsewhere.path());
        crate::authority_key::load_or_generate(&another.path).unwrap();
        let why = refused(Checkpoints::open(&path, &log, &another).unwrap());
        assert!(why.contains("not one the ledger key signed"), "{why}");

        let renamed = LedgerKey {
            identity: "cassini.polar.serviceaccount.cluster.local".to_string(),
            ..key(dir.path())
        };
        let why = refused(Checkpoints::open(&path, &log, &renamed).unwrap());
        assert!(why.contains("not one the ledger key signed"), "{why}");
    }

    #[test]
    fn a_ledger_with_no_checkpoint_kept_is_ready_and_signed_from_where_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let log = ledger(&path, &[leaf(0), leaf(1)]);
        let mut checkpoints = ready(Checkpoints::open(&path, &log, &key(dir.path())).unwrap());
        assert_eq!(checkpoints.sign(&log).unwrap(), Some(2));
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// Whatever appends and signatures come in whatever order, the ledger reopens as its own; cut back behind the
        /// last checkpoint signed, it is refused, and cut back no further than it, it is not.
        #[test]
        fn a_ledger_is_refused_exactly_when_it_no_longer_holds_its_last_checkpoint(
            steps in proptest::collection::vec(any::<bool>(), 1..24),
            cut in 0usize..24,
        ) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("ledger.log");
            let mut leaves = Vec::new();
            let mut log = ledger(&path, &[]);
            let mut checkpoints = ready(Checkpoints::open(&path, &log, &key(dir.path())).unwrap());
            for append in steps {
                if append {
                    let next = leaf(leaves.len() as u64);
                    log.append(&next).unwrap();
                    leaves.push(next);
                } else {
                    checkpoints.sign(&log).unwrap();
                }
            }
            let signed = checkpoints.signed();
            drop(log);
            let reopened = FileLog::open(&path).unwrap().log;
            prop_assert!(matches!(Checkpoints::open(&path, &reopened, &key(dir.path())).unwrap(), Kept::Ready(_)));
            drop(reopened);

            let kept = cut.min(leaves.len());
            let cut_back = ledger(&path, &leaves[..kept]);
            let opened = Checkpoints::open(&path, &cut_back, &key(dir.path())).unwrap();
            prop_assert_eq!(
                matches!(opened, Kept::Refused(_)),
                signed.is_some_and(|signed| (kept as u64) < signed)
            );
        }
    }
}
