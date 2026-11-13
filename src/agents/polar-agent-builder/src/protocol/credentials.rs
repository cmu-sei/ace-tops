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

//! The `credentials` runtime section an agent gets by declaring its credentials (`PolarAgent::CREDENTIALS`), written once
//! here: the shape, judged without opening anything, and handing each version to the CryptoActor, which opens each entry
//! in the custody daemon, keeps it with its binding and escrows it (docs/architecture/signed-configuration.md).
//! Nothing of the domain's touches it. A problem names an entry and a field and never holds a value.

use crate::crypto::SectionKeeper;
use crate::runtime::{RuntimeSection, SectionAuthority};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use polar_crypto::registry::{SecretBinding, SecretKind};
use polar_escrow::EscrowedSecret;
use serde_json::Value;
use tracing::{info, warn};

pub use polar_crypto::registry::{host_matches, pattern_problem};

/// What the section is called in a document.
pub const SECTION_NAME: &str = "credentials";
/// Longest entry name, as `polar_escrow::binding_context` takes it.
pub const MAX_NAME: usize = 64;
/// Longest user name.
pub const MAX_USERNAME: usize = polar_crypto::registry::MAX_USERNAME;

/// What the section's body may hold: `polar-sign` checks a document against this, and makes each secret from what is typed.
const BODY: &str = r#"{"credentials": {"list_of": {"name": {"type": "text of lowercase letters, digits and hyphens", "required": true, "doc": "what the credential is called"}, "host_pattern": {"type": "host pattern", "required": true, "doc": "the only hosts this credential is ever sent to: a host name, or *. and a domain, or several of those separated by commas; for an ssh-key, also one address"}, "kind": {"type": "token | user-password | ssh-key", "required": true, "doc": "token: a bearer token; user-password: a user name and a secret; ssh-key: an ssh private key, for git over ssh"}, "username": {"type": "ciphertext", "required": false, "secret": true, "doc": "the user name the credential logs in as, sealed as the secret is, since a credential is its user name and its secret together: required for a user-password; given to git, oauth2 for a token and git for an ssh-key unless named. In the signed document it is base64 of an EscrowedSecret for this agent, bound to <agent>|credentials|<version>|<name>|username; polar-sign makes that from what you type"}, "host_key": {"type": "text: a SHA-256 fingerprint", "required": false, "doc": "required for an ssh-key, and only for one: each of the server's host keys as ssh-keygen -l writes it (SHA256:...), separated by commas, since which it shows is negotiated; the key is offered to no server that shows another"}, "secret": {"type": "ciphertext", "required": true, "secret": true, "doc": "the secret itself. In the signed document it is base64 of an EscrowedSecret for this agent, bound to <agent>|credentials|<version>|<name>|secret; polar-sign makes that from what you type"}}}}"#;

/// The section of an agent that takes at most `MAX` credentials, `doc` saying what they are for. Replaced whole by each
/// version, so an entry left out is withdrawn.
pub const fn section<const MAX: usize>(doc: &'static str) -> RuntimeSection {
    RuntimeSection {
        authority: SectionAuthority::Runtime,
        name: SECTION_NAME,
        doc,
        body: BODY,
        validate: validate::<MAX>,
    }
}

fn validate<const MAX: usize>(body: &Value) -> Result<(), Vec<String>> {
    parse(body, MAX).map(|_| ())
}

/// One entry, as the document gives it. The secret is still the base64 of the ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) name: String,
    pub(crate) host_pattern: String,
    pub(crate) kind: SecretKind,
    pub(crate) username: Option<String>,
    pub(crate) host_key: Option<String>,
    pub(crate) secret: String,
}

/// The entries of a body, or every problem with it. Judges the shape and whether each secret is, by its bytes, an
/// escrowed secret; nothing is opened.
pub(crate) fn parse(body: &Value, max: usize) -> Result<Vec<Entry>, Vec<String>> {
    let Some(object) = body.as_object() else {
        return Err(vec!["the body must be an object".to_string()]);
    };
    let mut problems: Vec<String> = object
        .keys()
        .filter(|k| k.as_str() != "credentials")
        .map(|k| format!("`{k}` is not a field of this section"))
        .collect();
    let Some(list) = object.get("credentials").and_then(Value::as_array) else {
        problems.push("`credentials` must be a list of entries".to_string());
        return Err(problems);
    };
    if list.len() > max {
        problems.push(format!(
            "`credentials` has {} entries, and at most {max} are taken",
            list.len()
        ));
    }
    let mut entries: Vec<Entry> = Vec::new();
    for (i, item) in list.iter().enumerate() {
        match entry(i, item) {
            Ok(entry) => {
                if entries.iter().any(|e| e.name == entry.name) {
                    problems.push(format!(
                        "entry {i}: the name `{}` is used more than once",
                        entry.name
                    ));
                }
                entries.push(entry);
            }
            Err(mut more) => problems.append(&mut more),
        }
    }
    if problems.is_empty() {
        Ok(entries)
    } else {
        Err(problems)
    }
}

fn name_problem(name: &str) -> Option<&'static str> {
    if name.is_empty() || name.len() > MAX_NAME {
        Some("must be 1 to 64 characters")
    } else if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        Some("may have only lowercase letters, digits and hyphens")
    } else {
        None
    }
}

fn entry(i: usize, item: &Value) -> Result<Entry, Vec<String>> {
    let Some(object) = item.as_object() else {
        return Err(vec![format!("entry {i}: must be an object")]);
    };
    let mut problems = Vec::new();
    for key in object.keys() {
        if ![
            "name",
            "host_pattern",
            "kind",
            "username",
            "host_key",
            "secret",
        ]
        .contains(&key.as_str())
        {
            problems.push(format!("entry {i}: `{key}` is not a field of an entry"));
        }
    }
    let text = |key: &str| object.get(key).and_then(Value::as_str);

    let name = text("name").unwrap_or_default().to_string();
    let named = match text("name") {
        None => {
            problems.push(format!("entry {i}: `name` must be text"));
            false
        }
        Some(n) => match name_problem(n) {
            Some(why) => {
                problems.push(format!("entry {i}: `name` {why}"));
                false
            }
            None => true,
        },
    };
    // The entry is named by its name from here on, and by its position when it has none it can be called by: a name
    // that was refused may be anything, a value pasted into the wrong field among them.
    let label = if named {
        format!("entry `{name}`")
    } else {
        format!("entry {i}")
    };

    let host_pattern = text("host_pattern").unwrap_or_default().to_string();
    if text("host_pattern").is_none() {
        problems.push(format!("{label}: `host_pattern` must be text"));
    }

    let kind = match object
        .get("kind")
        .map(|k| serde_json::from_value(k.clone()))
    {
        Some(Ok(kind)) => Some(kind),
        _ => {
            problems.push(format!(
                "{label}: `kind` must be `token`, `user-password` or `ssh-key`"
            ));
            None
        }
    };

    // A user name is sealed, as the secret is: a credential is the two together, and neither is in the clear here. What
    // it opens to is judged where it is opened, by the CryptoActor (`registry::is_username`).
    let username = match object.get("username") {
        None | Some(Value::Null) => None,
        Some(Value::String(u)) => match secret_problem(u) {
            None => Some(u.clone()),
            Some(why) => {
                problems.push(format!(
                    "{label}: `username` {why}: a user name is sealed, as the secret is, and polar-sign seals it"
                ));
                None
            }
        },
        Some(_) => {
            problems.push(format!("{label}: `username` must be text"));
            None
        }
    };
    if kind == Some(SecretKind::UserPassword) && username.is_none() {
        problems.push(format!(
            "{label}: a `user-password` credential needs a `username`"
        ));
    }

    let host_key = match object.get("host_key") {
        None | Some(Value::Null) => None,
        Some(Value::String(pin)) => Some(pin.clone()),
        Some(_) => {
            problems.push(format!("{label}: `host_key` must be text"));
            None
        }
    };
    // The rules for where a credential may go are the registry's, judged here as the CryptoActor will judge them: an ssh
    // key pins a host key and may name an address; nothing else does either. Its messages hold no value.
    match kind {
        Some(kind) if text("host_pattern").is_some() => {
            let binding = SecretBinding {
                host_pattern: host_pattern.clone(),
                kind,
                username: None,
                host_key: host_key.clone(),
            };
            if let Err(e) = binding.check() {
                let field = if host_key.is_some() || kind == SecretKind::SshKey {
                    "`host_key` or `host_pattern`"
                } else {
                    "`host_pattern`"
                };
                problems.push(format!("{label}: {field}: {e}"));
            }
        }
        None => {
            if let Some(why) = text("host_pattern").and_then(pattern_problem) {
                problems.push(format!("{label}: `host_pattern`: {why}"));
            }
        }
        Some(_) => {}
    }

    let secret = text("secret").unwrap_or_default().to_string();
    match text("secret") {
        None => problems.push(format!("{label}: `secret` must be text")),
        Some(s) => {
            if let Some(why) = secret_problem(s) {
                problems.push(format!("{label}: `secret` {why}"));
            }
        }
    }

    match (problems.is_empty(), kind) {
        (true, Some(kind)) => Ok(Entry {
            name,
            host_pattern,
            kind,
            username,
            host_key,
            secret,
        }),
        _ => Err(problems),
    }
}

/// Why a secret field is not the base64 of an escrowed secret, without saying what it holds.
fn secret_problem(secret: &str) -> Option<&'static str> {
    match EscrowedSecret::from_document_text(secret) {
        Ok(_) => None,
        Err(polar_escrow::DocumentTextError::NotBase64) => Some("is not standard base64"),
        Err(polar_escrow::DocumentTextError::Empty) => Some("is empty"),
        Err(polar_escrow::DocumentTextError::NotASecret) => Some("is not an escrowed secret"),
    }
}

/// What an entry was bound to when it was encrypted (docs/architecture/signed-configuration.md, "Binding"): the one
/// definition the author's tool uses too (`polar_escrow::binding_context`).
pub(crate) fn context(
    agent: &str,
    version: u64,
    name: &str,
    field: &str,
) -> Result<Vec<u8>, polar_escrow::ContextError> {
    polar_escrow::binding_context(agent, SECTION_NAME, version, name, field)
}

/// What became of a version of the section, announced to the domain ([`super::ProtocolHandle::credentials_applied`]).
/// Names and reasons, never a value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialsApplied {
    pub version: u64,
    /// Registered with the CryptoActor.
    pub registered: Vec<String>,
    /// Refused or failed, with the reason.
    pub failed: Vec<(String, String)>,
    /// Withdrawn: registered before, and not in this version.
    pub withdrawn: Vec<String>,
}

/// Hands a version of the section to the CryptoActor: each entry is registered, then every name this version does not list
/// is withdrawn, whether or not its own entries registered, since a version is the whole section. An entry that fails is
/// reported by name and does not stop the rest.
pub(crate) async fn apply(
    crypto: &dyn SectionKeeper,
    agent: &str,
    version: u64,
    entries: &[Entry],
) -> CredentialsApplied {
    let mut applied = CredentialsApplied {
        version,
        ..Default::default()
    };
    for entry in entries {
        let Ok(secret) = STANDARD.decode(&entry.secret) else {
            applied
                .failed
                .push((entry.name.clone(), "the secret is not base64".to_string()));
            continue;
        };
        let context = match context(agent, version, &entry.name, "secret") {
            Ok(context) => context,
            Err(e) => {
                warn!(credential = %entry.name, "could not register the credential: {e}");
                applied.failed.push((entry.name.clone(), e.to_string()));
                continue;
            }
        };
        let username = match &entry.username {
            None => None,
            Some(sealed) => {
                let part = STANDARD
                    .decode(sealed)
                    .ok()
                    .zip(self::context(agent, version, &entry.name, "username").ok());
                match part {
                    Some((ciphertext, context)) => Some(polar_crypto::SealedPart {
                        ciphertext,
                        context,
                    }),
                    None => {
                        applied.failed.push((
                            entry.name.clone(),
                            "the user name could not be read".to_string(),
                        ));
                        continue;
                    }
                }
            }
        };
        let binding = SecretBinding {
            host_pattern: entry.host_pattern.clone(),
            kind: entry.kind,
            username: None,
            host_key: entry.host_key.clone(),
        };
        match crypto
            .register_secret(
                entry.name.clone(),
                SECTION_NAME.to_string(),
                secret,
                context,
                username,
                binding,
            )
            .await
        {
            Ok(()) => applied.registered.push(entry.name.clone()),
            Err(e) => {
                warn!(credential = %entry.name, "could not register the credential: {e}");
                applied.failed.push((entry.name.clone(), e.to_string()));
            }
        }
    }
    let keep = entries.iter().map(|e| e.name.clone()).collect();
    match crypto.replace_section(SECTION_NAME.to_string(), keep).await {
        Ok(withdrawn) => applied.withdrawn = withdrawn,
        Err(e) => applied.failed.push((
            "(the section)".to_string(),
            format!("what this version leaves out was not withdrawn: {e}"),
        )),
    }
    info!(
        version,
        registered = applied.registered.len(),
        failed = applied.failed.len(),
        withdrawn = applied.withdrawn.len(),
        "credentials section applied"
    );
    applied
}

#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;
    use polar_crypto::CryptoError;
    use std::sync::Mutex;

    /// The public half of one key, made once: generating an RSA key is slow.
    fn public_pem() -> &'static str {
        use rsa::pkcs8::EncodePublicKey;
        static PEM: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        PEM.get_or_init(|| {
            let mut rng = rand::rng();
            let key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
            key.to_public_key()
                .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
                .unwrap()
        })
    }

    /// A real escrowed secret, base64 as a document carries it.
    pub(crate) fn ciphertext(plaintext: &[u8], context: &[u8]) -> String {
        let escrowed = EscrowedSecret::encrypt_bound(plaintext, public_pem(), context).unwrap();
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&escrowed).unwrap();
        STANDARD.encode(bytes.as_slice())
    }

    /// What the fake was asked to register: the name, the section, the context and the binding.
    pub(crate) type Registered = (String, String, Vec<u8>, SecretBinding);

    /// A CryptoActor that records what it was told, and refuses the names it is told to.
    #[derive(Default)]
    pub(crate) struct FakeCrypto {
        pub(crate) registered: Mutex<Vec<Registered>>,
        pub(crate) refuse: Vec<String>,
        pub(crate) kept: Mutex<Vec<Vec<String>>>,
        pub(crate) withdraws: Vec<String>,
        /// Each name registered, with the context its sealed user name was handed on with, if it had one.
        pub(crate) usernames: Mutex<Vec<(String, Option<Vec<u8>>)>>,
    }

    #[async_trait::async_trait]
    impl SectionKeeper for FakeCrypto {
        async fn register_secret(
            &self,
            name: String,
            section: String,
            _secret: Vec<u8>,
            context: Vec<u8>,
            username: Option<polar_crypto::SealedPart>,
            binding: SecretBinding,
        ) -> Result<(), CryptoError> {
            if self.refuse.contains(&name) {
                return Err(CryptoError::SecretNotRegistered(name));
            }
            self.usernames
                .lock()
                .unwrap()
                .push((name.clone(), username.map(|u| u.context)));
            self.registered
                .lock()
                .unwrap()
                .push((name, section, context, binding));
            Ok(())
        }
        async fn replace_section(
            &self,
            _: String,
            keep: Vec<String>,
        ) -> Result<Vec<String>, CryptoError> {
            self.kept.lock().unwrap().push(keep);
            Ok(self.withdraws.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::{FakeCrypto, ciphertext};
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn token_entry(name: &str) -> Value {
        json!({
            "name": name,
            "host_pattern": "site.example.org",
            "kind": "token",
            "secret": ciphertext(b"pat-token", b"context"),
        })
    }

    static ONE: RuntimeSection = section::<1>("the one credential");

    #[test]
    fn the_section_is_declared_soundly_and_says_what_polar_sign_checks_against() {
        assert!(crate::runtime::check_declarations(&[&ONE]).is_empty());
        assert_eq!(ONE.name, "credentials");
        let body: Value = serde_json::from_str(ONE.body).unwrap();
        let fields = &body["credentials"]["list_of"];
        for field in [
            "name",
            "host_pattern",
            "kind",
            "username",
            "host_key",
            "secret",
        ] {
            assert!(fields.get(field).is_some(), "{field}");
        }
        assert_eq!(fields["secret"]["secret"], true);
    }

    #[test]
    fn a_sound_body_gives_its_entries() {
        let username = ciphertext(b"me@example.org", b"x");
        let entries = parse(
            &json!({"credentials": [token_entry("a-site"), {
                "name": "cloud", "host_pattern": "*.atlassian.net", "kind": "user-password",
                "username": username, "secret": ciphertext(b"api-token", b"x")}]}),
            2,
        )
        .unwrap();
        assert_eq!(entries[0].name, "a-site");
        assert_eq!(entries[0].kind, SecretKind::Token);
        assert_eq!(entries[0].username, None);
        assert_eq!(entries[1].kind, SecretKind::UserPassword);
        assert_eq!(entries[1].username.as_deref(), Some(username.as_str()));
        assert_eq!(parse(&json!({"credentials": []}), 1), Ok(Vec::new()));
    }

    /// A token and a user-password in one signed version, which `polar-sign` could not write until 2026-11-06: the token's
    /// username, which it leaves out, comes back from the signed file as null, and is no username.
    #[test]
    fn a_token_and_a_user_password_in_one_signed_version_read_back_as_they_were_written() {
        let username = ciphertext(b"me@example.org", b"x");
        let body = json!({"credentials": [token_entry("a-site"), {
            "name": "cloud", "host_pattern": "*.atlassian.net", "kind": "user-password",
            "username": username, "secret": ciphertext(b"api-token", b"x")}]});
        let signed = polar_sign::dhall(&body).expect("one list");
        let read = polar_sign::evaluate(&signed).unwrap();
        assert_eq!(read["credentials"][0]["username"], Value::Null);
        let entries = parse(&read, 2).unwrap();
        assert_eq!(entries[0].username, None);
        assert_eq!(entries[1].username.as_deref(), Some(username.as_str()));
    }

    /// polar-sign, given this section's own schema, seals a typed user name as it seals the secret: each under its own
    /// field of the same entry, so the two cannot be paired with another entry's.
    #[test]
    fn polar_sign_seals_a_typed_user_name_under_its_own_field_of_the_entry() {
        let description: Value = serde_json::from_str(BODY).unwrap();
        let mut body = json!({"credentials": [{
            "name": "cloud", "host_pattern": "*.atlassian.net", "kind": "user-password",
            "username": "me@example.org", "secret": "api-token"}]});
        let mut calls: Vec<(String, String)> = Vec::new();
        let mut encrypt = |plaintext: &[u8], context: &[u8]| {
            calls.push((
                String::from_utf8(plaintext.to_vec()).unwrap(),
                String::from_utf8(context.to_vec()).unwrap(),
            ));
            Ok(format!("SEALED-{}", calls.len()))
        };
        let mut no_stdin = || Err("no standard input".to_string());
        polar_sign::seal::seal_body(
            &description,
            &mut body,
            "jira-observer",
            SECTION_NAME,
            4,
            &mut encrypt,
            &mut no_stdin,
        )
        .unwrap();
        drop(encrypt);
        calls.sort();
        assert_eq!(
            calls,
            [
                (
                    "api-token".to_string(),
                    "jira-observer|credentials|4|cloud|secret".to_string()
                ),
                (
                    "me@example.org".to_string(),
                    "jira-observer|credentials|4|cloud|username".to_string()
                ),
            ]
        );
        assert!(!body.to_string().contains("me@example.org"));
    }

    /// A credential is its user name and its secret together, and a signed document holds neither in the clear: a user name
    /// written as text is refused, saying it is sealed as the secret is, and the schema marks it secret, so polar-sign
    /// seals it.
    #[test]
    fn a_user_name_in_the_clear_is_refused_and_the_schema_marks_it_secret() {
        let problems = parse(
            &json!({"credentials": [{
                "name": "cloud", "host_pattern": "*.atlassian.net", "kind": "user-password",
                "username": "me@example.org", "secret": ciphertext(b"api-token", b"x")}]}),
            2,
        )
        .unwrap_err()
        .join(" | ");
        assert!(
            problems.contains("`username` is not standard base64: a user name is sealed"),
            "{problems}"
        );
        let fields: Value = serde_json::from_str(BODY).unwrap();
        let fields = &fields["credentials"]["list_of"];
        assert_eq!(fields["username"]["secret"], true);
        assert_eq!(fields["username"]["type"], "ciphertext");
    }

    #[test]
    fn the_declared_limit_is_what_the_section_takes() {
        let two = json!({"credentials": [token_entry("a"), token_entry("b")]});
        let problems = (ONE.validate)(&two).unwrap_err();
        assert!(problems[0].contains("at most 1"), "{problems:?}");
        assert_eq!(parse(&two, 2).map(|e| e.len()), Ok(2));
    }

    #[test]
    fn every_problem_is_named_and_the_rest_are_still_found() {
        let problems = parse(
            &json!({"extra": 1, "credentials": [
                {"name": "Bad", "host_pattern": "*", "kind": "nonsense", "secret": "not base64!", "stranger": 1},
                {"name": "u", "host_pattern": "a.example.org", "kind": "user-password", "secret": ciphertext(b"x", b"y")},
                token_entry("dup"), token_entry("dup"),
            ]}),
            8,
        )
        .unwrap_err()
        .join(" | ");
        for expected in [
            "`extra` is not a field",
            "`stranger` is not a field",
            "`name` may have only",
            "`host_pattern`",
            "`kind` must be",
            "`secret` is not standard base64",
            "needs a `username`",
            "used more than once",
        ] {
            assert!(problems.contains(expected), "{expected}: {problems}");
        }
    }

    #[test]
    fn a_body_with_no_list_is_refused_and_says_what_it_has_instead() {
        let problems = parse(&json!({"other": []}), 1).unwrap_err();
        assert!(
            problems.iter().any(|p| p.contains("`other`")),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("`credentials` must be a list")),
            "{problems:?}"
        );
        assert_eq!(
            parse(&json!([]), 1).unwrap_err(),
            vec!["the body must be an object".to_string()]
        );
    }

    #[tokio::test]
    async fn a_version_registers_each_entry_with_its_binding_and_context_and_withdraws_the_rest() {
        let crypto = FakeCrypto {
            refuse: vec!["refused".to_string()],
            withdraws: vec!["old".to_string()],
            ..Default::default()
        };
        let entries = parse(
            &json!({"credentials": [token_entry("good"), token_entry("refused"), {
                "name": "cloud", "host_pattern": "*.atlassian.net", "kind": "user-password",
                "username": ciphertext(b"me@example.org", b"x"), "secret": ciphertext(b"api-token", b"x")}]}),
            8,
        )
        .unwrap();
        let applied = apply(&crypto, "an-agent", 3, &entries).await;
        assert_eq!(applied.version, 3);
        assert_eq!(
            applied.registered,
            vec!["good".to_string(), "cloud".to_string()]
        );
        assert_eq!(applied.failed.len(), 1);
        assert_eq!(applied.failed[0].0, "refused");
        assert_eq!(applied.withdrawn, vec!["old".to_string()]);

        let registered = crypto.registered.lock().unwrap();
        let (name, section, context, binding) = &registered[0];
        assert_eq!(name, "good");
        assert_eq!(section, "credentials");
        assert_eq!(context.as_slice(), b"an-agent|credentials|3|good|secret");
        assert_eq!(binding.host_pattern, "site.example.org");
        // The user name goes on sealed, under its own field's context, and never in the binding.
        let usernames = crypto.usernames.lock().unwrap();
        assert!(usernames.contains(&("good".to_string(), None)));
        assert!(usernames.contains(&(
            "cloud".to_string(),
            Some(b"an-agent|credentials|3|cloud|username".to_vec())
        )));
        assert!(registered.iter().all(|(_, _, _, b)| b.username.is_none()));
        // Every name was kept: what the version lists is not withdrawn, registered or not.
        assert_eq!(
            crypto.kept.lock().unwrap()[0],
            vec![
                "good".to_string(),
                "refused".to_string(),
                "cloud".to_string()
            ]
        );
    }

    /// A version with no entry withdraws what was there.
    #[tokio::test]
    async fn a_version_with_no_entry_keeps_nothing() {
        let crypto = FakeCrypto {
            withdraws: vec!["jira".to_string()],
            ..Default::default()
        };
        let applied = apply(&crypto, "an-agent", 8, &[]).await;
        assert!(applied.registered.is_empty());
        assert_eq!(applied.withdrawn, vec!["jira".to_string()]);
        assert_eq!(crypto.kept.lock().unwrap()[0], Vec::<String>::new());
    }

    /// The fingerprint of a host key, as `ssh-keygen -l` writes it.
    const PIN: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// Where a binding is not usable, the problem names the field to change: a host key, which only an ssh key has, or the
    /// host pattern; and an entry with no host pattern is told so once, not judged again with an empty one.
    #[test]
    fn a_binding_that_cannot_be_used_names_the_field_to_change_once() {
        let problems = |entry: Value| parse(&json!({"credentials": [entry]}), 2).unwrap_err();
        let mut no_pattern = token_entry("t");
        no_pattern.as_object_mut().unwrap().remove("host_pattern");
        assert_eq!(
            problems(no_pattern),
            ["entry `t`: `host_pattern` must be text"]
        );

        let mut token_with_pin = token_entry("t");
        token_with_pin["host_key"] = json!(PIN);
        let got = problems(token_with_pin);
        assert!(
            got.len() == 1 && got[0].starts_with("entry `t`: `host_key` or `host_pattern`:"),
            "{got:?}"
        );

        let ssh_without_pin = json!({
            "name": "s", "host_pattern": "git.example.org", "kind": "ssh-key",
            "secret": ciphertext(b"key", b"context")});
        let got = problems(ssh_without_pin);
        assert!(
            got.len() == 1 && got[0].starts_with("entry `s`: `host_key` or `host_pattern`:"),
            "{got:?}"
        );

        let mut token_bad_pattern = token_entry("t");
        token_bad_pattern["host_pattern"] = json!("*");
        let got = problems(token_bad_pattern);
        assert!(
            got.len() == 1 && got[0].starts_with("entry `t`: `host_pattern`:"),
            "{got:?}"
        );
    }

    fn ssh_entry(host_pattern: &str, host_key: Option<&str>) -> Value {
        let mut entry = json!({
            "name": "gitea",
            "host_pattern": host_pattern,
            "kind": "ssh-key",
            "secret": ciphertext(b"-----BEGIN OPENSSH PRIVATE KEY-----", b"context"),
        });
        if let Some(pin) = host_key {
            entry["host_key"] = json!(pin);
        }
        entry
    }

    #[tokio::test]
    async fn an_ssh_key_for_an_address_is_registered_with_the_host_key_it_pins() {
        let entries = parse(
            &json!({"credentials": [ssh_entry("52.235.181.217", Some(PIN))]}),
            1,
        )
        .unwrap();
        assert_eq!(entries[0].kind, SecretKind::SshKey);
        assert_eq!(entries[0].host_key.as_deref(), Some(PIN));
        let crypto = FakeCrypto::default();
        let applied = apply(&crypto, "an-agent", 1, &entries).await;
        assert_eq!(applied.registered, vec!["gitea".to_string()]);
        let binding = &crypto.registered.lock().unwrap()[0].3;
        assert_eq!(
            (
                binding.host_pattern.as_str(),
                binding.kind,
                binding.host_key.as_deref()
            ),
            ("52.235.181.217", SecretKind::SshKey, Some(PIN))
        );
    }

    #[test]
    fn an_ssh_key_names_its_servers_host_key_and_nothing_else_names_one_or_an_address() {
        let refused = |entry: Value| {
            parse(&json!({"credentials": [entry]}), 1)
                .unwrap_err()
                .join(" | ")
        };
        assert!(refused(ssh_entry("52.235.181.217", None)).contains("host key"));
        assert!(refused(ssh_entry("52.235.181.217", Some("SHA256:short"))).contains("host key"));
        let mut pinned_token = token_entry("a-site");
        pinned_token["host_key"] = json!(PIN);
        assert!(refused(pinned_token).contains("host key"));
        let mut token_to_an_address = token_entry("a-site");
        token_to_an_address["host_pattern"] = json!("52.235.181.217");
        assert!(refused(token_to_an_address).contains("host_pattern"));
        // A name pattern is as good for an ssh key as for any other.
        assert!(
            parse(
                &json!({"credentials": [ssh_entry("*.example.org", Some(PIN))]}),
                1
            )
            .is_ok()
        );
    }

    /// An ssh key's host key comes back from the signed file, and a token's, which it leaves out, as null and no key.
    #[test]
    fn an_ssh_key_and_a_token_in_one_signed_version_read_back_as_they_were_written() {
        let body =
            json!({"credentials": [token_entry("a-site"), ssh_entry("52.235.181.217", Some(PIN))]});
        let signed = polar_sign::dhall(&body).expect("one list");
        let read = polar_sign::evaluate(&signed).unwrap();
        let entries = parse(&read, 2).unwrap();
        assert_eq!(entries[0].host_key, None);
        assert_eq!(entries[1].host_key.as_deref(), Some(PIN));
    }

    proptest! {
        /// Whatever a body holds, no problem repeats what its fields hold: a secret pasted into any of them stays out of
        /// what is reported.
        #[test]
        fn no_problem_says_what_a_field_holds(
            value in "Z[A-Za-z0-9+/ !]{24,40}",
            field in proptest::sample::select(vec!["name", "host_pattern", "kind", "username", "host_key", "secret", "stranger"]),
        ) {
            let mut item = json!({"name": "a", "host_pattern": "a.example.org", "kind": "token", "secret": "x"});
            item[field] = json!(value);
            let problems = parse(&json!({"credentials": [item]}), 1).unwrap_err().join(" | ");
            prop_assert!(!problems.contains(&value), "{problems}");
        }
    }
}
