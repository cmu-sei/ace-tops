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

//! Every secret sealed to the RSA escrow key sealed again to its P-256 replacement, at the first start with it
//! (docs/architecture/key-custody.md, "The credentials agent's keys, P-256", K2). Each is a new `SecretStored` for the
//! same name, kept as its owner stored it (`stored_by`, labels), so the ledger's history still holds the old one and
//! the current one opens with the new key. Done before any request is taken, so nothing is stored meanwhile.

use crate::escrow::{EscrowKeypair, Replacing};
use crate::ledger::LedgerMessage;
use credentials_agent_common::escrow_secret::EscrowedSecret;
use credentials_agent_common::events::CredentialsEvent;
use ractor::ActorRef;
use tracing::{error, info, warn};

/// What sealing again did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Resealed {
    /// Sealed again to the new key.
    pub moved: Vec<String>,
    /// Already sealed to the new key: an earlier start moved them.
    pub already: Vec<String>,
    /// Sealed to the RSA key and not moved, each with why: the RSA key is kept at its path until there are none.
    pub failed: Vec<(String, String)>,
    /// Sealed to neither key: nothing here opens them, before or after, so they do not hold the move back.
    pub neither: Vec<String>,
}

impl Resealed {
    /// Whether nothing current is left sealed to the RSA key, so that it may be set aside.
    pub fn complete(&self) -> bool {
        self.failed.is_empty()
    }
}

/// Seals every current secret sealed to `replacing`'s RSA key again to its new key, appending each to `ledger` as
/// stored at `now` (milliseconds).
pub async fn reseal(
    ledger: &ActorRef<LedgerMessage>,
    replacing: &Replacing,
    now: i64,
) -> Result<Resealed, String> {
    let stored = ractor::call!(ledger, LedgerMessage::StoredSecrets)
        .map_err(|e| format!("the ledger did not list the stored secrets: {e}"))?;
    let new_pem = replacing.new_keypair().public_key_pem();
    let mut done = Resealed::default();
    for (name, held) in stored {
        let to = held.secret.encrypted_to_pem();
        if to == new_pem {
            done.already.push(name);
            continue;
        }
        if to != replacing.old_public_key_pem() {
            done.neither.push(name);
            continue;
        }
        let sealed = replacing
            .open_old(&held.secret)
            .map_err(|e| format!("it does not open with the RSA key: {e}"))
            .and_then(|plaintext| {
                EscrowedSecret::encrypt(&plaintext, new_pem)
                    .map_err(|e| format!("it cannot be sealed to the new key: {e}"))
            });
        let secret = match sealed {
            Ok(secret) => secret,
            Err(why) => {
                done.failed.push((name, why));
                continue;
            }
        };
        let event = CredentialsEvent::SecretStored {
            name: name.clone(),
            secret,
            stored_by: held.stored_by,
            timestamp: now,
            labels: held.labels,
        };
        match ractor::call!(ledger, |reply| LedgerMessage::Append { event, reply }) {
            Ok(Ok(())) => done.moved.push(name),
            Ok(Err(e)) => done.failed.push((name, format!("not recorded: {e}"))),
            Err(e) => done
                .failed
                .push((name, format!("the ledger did not answer: {e}"))),
        }
    }
    Ok(done)
}

/// Replaces the RSA escrow key: every secret sealed to it is sealed again ([`reseal`]), and the RSA key is set aside only
/// if none is left; otherwise it stays at its path and the next start tries again. Either way, the new key is the one
/// this start seals to and opens with.
pub async fn replace(
    ledger: &ActorRef<LedgerMessage>,
    replacing: Replacing,
    now: i64,
) -> Result<EscrowKeypair, String> {
    let done = reseal(ledger, &replacing, now).await?;
    for (name, why) in &done.failed {
        error!(secret = %name, "not sealed again to the new escrow key: {why}");
    }
    if !done.neither.is_empty() {
        warn!(secrets = ?done.neither, "stored secrets sealed to neither escrow key: nothing here opens them");
    }
    if done.complete() {
        info!(
            moved = done.moved.len(),
            already = done.already.len(),
            "the escrow key is now P-256; the RSA key is set aside"
        );
        replacing.finish().map_err(|e| e.to_string())
    } else {
        warn!(
            failed = done.failed.len(),
            "the RSA escrow key stays at its path until every secret sealed to it is sealed again"
        );
        Ok(replacing.unfinished())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::escrow::{EscrowKeypair, Loaded};
    use crate::ledger::tests::{append, spawn_ledger};

    fn stored(name: &str, secret: EscrowedSecret, by: &str, kind: &str) -> CredentialsEvent {
        CredentialsEvent::SecretStored {
            name: name.to_string(),
            secret,
            stored_by: by.to_string(),
            timestamp: 1,
            labels: [("kind".to_string(), kind.to_string())].into(),
        }
    }

    async fn held(ledger: &ActorRef<LedgerMessage>, name: &str) -> crate::state::StoredSecret {
        ractor::call!(ledger, |reply| LedgerMessage::CheckSecret {
            name: name.to_string(),
            reply
        })
        .unwrap()
        .unwrap()
    }

    #[tokio::test]
    async fn what_was_sealed_to_the_rsa_key_is_sealed_again_to_the_new_one_kept_as_its_owner_stored_it()
     {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("escrow-key.pem");
        let key_path = key_path.to_str().unwrap();
        std::fs::write(key_path, crate::escrow::tests::rsa_key_pem()).unwrap();
        let Loaded::Replacing(replacing) = EscrowKeypair::load_or_generate(key_path).unwrap()
        else {
            panic!("the RSA key is replaced");
        };
        let log = dir.path().join("events.jsonl");
        let ledger = spawn_ledger(log.to_str().unwrap()).await;
        let old = replacing.old_public_key_pem().to_string();
        let new = replacing.new_keypair().public_key_pem().to_string();
        let stranger = EscrowKeypair::generate().unwrap();
        for event in [
            stored(
                "github-sei",
                EscrowedSecret::encrypt(b"one", &old).unwrap(),
                "git-repo-observer",
                "token",
            ),
            stored(
                "jira",
                EscrowedSecret::encrypt(b"two", &old).unwrap(),
                "jira-observer",
                "token",
            ),
            stored(
                "moved",
                EscrowedSecret::encrypt(b"three", &new).unwrap(),
                "gitlab-observer",
                "token",
            ),
            stored(
                "stranger",
                EscrowedSecret::encrypt(b"four", stranger.public_key_pem()).unwrap(),
                "x",
                "token",
            ),
        ] {
            append(&ledger, event).await.unwrap();
        }

        let done = reseal(&ledger, &replacing, 7).await.unwrap();
        assert_eq!(done.moved, ["github-sei", "jira"]);
        assert_eq!(done.already, ["moved"]);
        assert_eq!(done.neither, ["stranger"]);
        assert!(done.complete());

        for (name, plaintext, by) in [
            ("github-sei", b"one", "git-repo-observer"),
            ("jira", b"two", "jira-observer"),
        ] {
            let now = held(&ledger, name).await;
            assert_eq!(
                &*replacing.new_keypair().open(&now.secret).unwrap(),
                plaintext
            );
            assert_eq!(now.stored_by, by);
            assert_eq!(
                now.labels,
                [("kind".to_string(), "token".to_string())].into()
            );
        }
        // The one already moved and the stranger's are left as they were.
        assert_eq!(
            &*replacing
                .new_keypair()
                .open(&held(&ledger, "moved").await.secret)
                .unwrap(),
            b"three"
        );
        assert_eq!(
            held(&ledger, "stranger").await.secret.encrypted_to_pem(),
            stranger.public_key_pem()
        );

        // Again, as after a start that ended before the key was put in place: nothing more is appended.
        let again = reseal(&ledger, &replacing, 8).await.unwrap();
        assert!(again.moved.is_empty());
        assert_eq!(again.already, ["github-sei", "jira", "moved"]);
    }

    #[tokio::test]
    async fn a_secret_that_does_not_open_with_the_rsa_key_holds_the_move_back() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("escrow-key.pem");
        let key_path = key_path.to_str().unwrap();
        std::fs::write(key_path, crate::escrow::tests::rsa_key_pem()).unwrap();
        let Loaded::Replacing(replacing) = EscrowKeypair::load_or_generate(key_path).unwrap()
        else {
            panic!("the RSA key is replaced");
        };
        let ledger = spawn_ledger(dir.path().join("events.jsonl").to_str().unwrap()).await;
        // Names the RSA key, but was sealed to another: it cannot be opened, so it cannot be moved.
        let other_rsa = {
            let key = rsa::RsaPrivateKey::new(&mut rand::rng(), 2048).unwrap();
            rsa::pkcs8::EncodePublicKey::to_public_key_pem(
                &key.to_public_key(),
                rsa::pkcs8::LineEnding::LF,
            )
            .unwrap()
        };
        let mut forged =
            serde_json::to_value(EscrowedSecret::encrypt(b"x", &other_rsa).unwrap()).unwrap();
        forged["encrypted_to_pem"] =
            serde_json::Value::String(replacing.old_public_key_pem().to_string());
        let forged: EscrowedSecret = serde_json::from_value(forged).unwrap();
        append(&ledger, stored("broken", forged, "x", "token"))
            .await
            .unwrap();

        let done = reseal(&ledger, &replacing, 7).await.unwrap();
        assert_eq!(done.failed.len(), 1, "{done:?}");
        assert!(!done.complete());
        assert_eq!(
            held(&ledger, "broken").await.secret.encrypted_to_pem(),
            replacing.old_public_key_pem()
        );

        // So the RSA key stays where it is, and nothing is set aside.
        let new = replace(&ledger, replacing, 8).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(key_path).unwrap(),
            crate::escrow::tests::rsa_key_pem()
        );
        assert!(!std::path::Path::new(&crate::escrow::retired_path(key_path)).exists());
        let Loaded::Replacing(again) = EscrowKeypair::load_or_generate(key_path).unwrap() else {
            panic!("still being replaced");
        };
        assert_eq!(again.new_keypair().public_key_pem(), new.public_key_pem());
    }

    #[tokio::test]
    async fn once_everything_is_sealed_again_the_new_key_takes_the_rsa_key_s_place() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("escrow-key.pem");
        let key_path = key_path.to_str().unwrap();
        std::fs::write(key_path, crate::escrow::tests::rsa_key_pem()).unwrap();
        let Loaded::Replacing(replacing) = EscrowKeypair::load_or_generate(key_path).unwrap()
        else {
            panic!("the RSA key is replaced");
        };
        let ledger = spawn_ledger(dir.path().join("events.jsonl").to_str().unwrap()).await;
        let sealed = EscrowedSecret::encrypt(b"one", replacing.old_public_key_pem()).unwrap();
        append(
            &ledger,
            stored("github-sei", sealed, "git-repo-observer", "token"),
        )
        .await
        .unwrap();

        let new = replace(&ledger, replacing, 7).await.unwrap();
        let Loaded::Current(at_path) = EscrowKeypair::load_or_generate(key_path).unwrap() else {
            panic!("the new key is at the path");
        };
        assert_eq!(at_path.public_key_pem(), new.public_key_pem());
        assert_eq!(
            &*new.open(&held(&ledger, "github-sei").await.secret).unwrap(),
            b"one"
        );
        assert!(std::path::Path::new(&crate::escrow::retired_path(key_path)).exists());
    }
}
