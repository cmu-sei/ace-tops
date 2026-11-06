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

//! Asking a running agent for its configuration, the asked side (docs/architecture/dynamic-settings.md, "Asking an agent
//! what is in force"). Every Cassini client hears questions on one topic, and the builder answers those addressed to it
//! from the ConfigurationActor, which keeps what is in force. The domain is never asked (docs/architecture/soft-state.md,
//! "Self-state and introspection").
//!
//! A question is a signed document, for what the asker's certificate says: the broker stamps an identity and nothing
//! more. In order, refusing at the first failure, as a signed update is judged:
//!
//! 1. the signature holds, under the signing domain of a question and no other;
//! 2. it is a question, read strictly, addressed to this agent;
//! 3. its signer is who the broker says published it, so a question seen once cannot be sent by someone else;
//! 4. Cedar, `Action::"read-configuration"` on `Agent::"<agent>"`; where it is silent, the certificate: who holds
//!    `c:update-configuration` may ask;
//! 5. the certificate is not revoked, and the question is within its time.
//!
//! A refused question gets no answer and a warning naming the asker. The answer holds no secret: a declared secret's
//! value stays here, and so does any value that repeats one. Other values go as they are, which is why the answer goes
//! back to whoever may ask, and not to the graph.

use crate::ConfigurationHandle;
use crate::Subscription;
use crate::command::{TimeRules, Window, check_window};
use crate::policy_authority::AuthorityRequest;
use crate::runtime::RuntimeValue;
use crate::signed::{Rejection, UpdateVerifier};
use cassini_client::{OfflineBehavior, PublishRequest};
use polar::cassini::{CassiniClient, TcpClient};
use polar_env::{Config, Mutability};
use polar_scheduler_common::running::{
    ANSWERS_TOPIC, MAX_QUESTION_VALIDITY_SECS, QUESTION_TYPE, QUESTIONS_TOPIC, RunningBuild,
    RunningConfiguration, RunningSection, RunningSetting, encode_answer,
};
use polar_signing::authority::AuthorityRefusal;
use polar_signing::{Domain, SignerInfo};
use ractor::ActorRef;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, info, warn};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Question {
    /// Checked before this is read; here because the payload is read strictly.
    #[serde(rename = "type")]
    #[allow(dead_code)]
    kind: String,
    id: String,
    target: Target,
    issued_at: u64,
    not_after: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    agent: String,
}

/// A question whose signature, shape and asker have been checked, and whose signer has not yet been judged.
pub struct OpenedQuestion {
    signer: SignerInfo,
    certificate_pem: String,
    payload: Value,
    question: Question,
}

impl OpenedQuestion {
    pub fn signer(&self) -> &SignerInfo {
        &self.signer
    }

    pub fn payload(&self) -> &Value {
        &self.payload
    }

    /// What is being asked of policy.
    pub fn request(&self, agent: &str) -> AuthorityRequest {
        AuthorityRequest {
            principal: self
                .signer
                .identity
                .clone()
                .unwrap_or_else(|| self.signer.serial.clone()),
            certificate_pem: self.certificate_pem.clone(),
            action: "read-configuration",
            resources: vec![("Agent", agent.to_string())],
        }
    }
}

/// Stage one: the signature holds, it is a question for this agent, and its signer is who the broker says sent it.
pub fn open(
    verifier: &UpdateVerifier,
    document: &Value,
    published_by: Option<&str>,
) -> Result<OpenedQuestion, Rejection> {
    let common = &verifier.common;
    let (document, signer) = common.signed_in(Domain::RUNNING_CONFIGURATION_QUESTION, document)?;
    let kind = document.payload.get("type").and_then(Value::as_str);
    if kind != Some(QUESTION_TYPE) {
        return Err(Rejection::WrongType {
            wanted: QUESTION_TYPE,
            got: kind.unwrap_or("nothing").to_string(),
        });
    }
    let question: Question = serde_json::from_value(document.payload.clone())
        .map_err(|e| Rejection::Payload(e.to_string()))?;
    common.check_target(question.target.agent.clone())?;
    if published_by.is_none() || signer.identity.as_deref() != published_by {
        return Err(Rejection::Unauthorized(AuthorityRefusal(format!(
            "the question is signed by {}, and the broker says {} sent it",
            signer.identity.as_deref().unwrap_or("nobody it can name"),
            published_by.unwrap_or("nobody it can name"),
        ))));
    }
    let certificate_pem = document
        .signature
        .certificate_chain
        .first()
        .cloned()
        .unwrap_or_default();
    Ok(OpenedQuestion {
        signer,
        certificate_pem,
        payload: document.payload,
        question,
    })
}

/// The last stage: the certificate has not been revoked, and the question is within its time. Gives its id.
pub fn close(verifier: &UpdateVerifier, opened: OpenedQuestion) -> Result<String, Rejection> {
    let common = &verifier.common;
    common.check_not_revoked(&opened.signer)?;
    let window = Window {
        issued_at: opened.question.issued_at,
        not_before: None,
        not_after: opened.question.not_after,
    };
    let rules = TimeRules {
        max_validity_secs: MAX_QUESTION_VALIDITY_SECS,
        ..TimeRules::default()
    };
    let now = u64::try_from(common.now()).unwrap_or(0);
    check_window(&window, &rules, now).map_err(Rejection::Window)?;
    Ok(opened.question.id)
}

/// What is in force, as the agent says it: every declared variable, with nothing that repeats a secret.
pub fn settings(config: &Config) -> Vec<RunningSetting> {
    let secrets = config.secret_values();
    config
        .report()
        .into_iter()
        .map(|resolved| {
            let withheld = resolved.secret
                || resolved.value.as_deref().is_some_and(|value| {
                    secrets.iter().any(|s| {
                        s.chars().count() >= polar_health::report::MIN_SECRET_CHARS
                            && value.contains(s.as_str())
                    })
                });
            RunningSetting {
                section: resolved.section.to_string(),
                name: resolved.name.to_string(),
                value: if withheld { None } else { resolved.value },
                source: resolved.source.as_str().to_string(),
                dynamic: resolved.mutability == Mutability::Dynamic,
                withheld,
            }
        })
        .collect()
}

/// The digest of a section's body as its signed document holds it: SHA-256 of its canonical form, in hex.
fn body_sha256(body: &Value) -> String {
    use sha2::Digest;
    let canonical = polar_signing::canonical::encode(body).unwrap_or_default();
    format!("{:x}", sha2::Sha256::digest(canonical))
}

/// The answer to the question `id`.
pub fn answer(
    id: String,
    agent: &str,
    config: &Config,
    version: u64,
    runtime: &HashMap<String, RuntimeValue>,
) -> RunningConfiguration {
    let mut sections: Vec<RunningSection> = runtime
        .iter()
        .map(|(name, value)| RunningSection {
            name: name.clone(),
            version: value.version,
            id: value.id.clone(),
            body_sha256: body_sha256(&value.body),
        })
        .collect();
    sections.sort_by(|a, b| a.name.cmp(&b.name));
    let built = polar_version::record(agent);
    RunningConfiguration {
        id,
        agent: agent.to_string(),
        version,
        settings: settings(config),
        sections,
        build: RunningBuild {
            name: built.name,
            version: built.version,
            release: built.release,
            target: built.target,
        },
        at_unix_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    }
}

/// The agent a question says it is for, read without trusting it: every agent hears every question, and this only saves
/// verifying the ones for others. One that says it is for this agent is judged from the start.
fn addressed_to(document: &Value) -> Option<&str> {
    document.pointer("/payload/target/agent")?.as_str()
}

/// The subscription to the questions: each goes to the infrastructure supervisor, with the identity the broker stamped
/// on it.
pub fn subscription(deliver_to: ActorRef<crate::InfrastructureSupervisorMessage>) -> Subscription {
    Subscription::new(QUESTIONS_TOPIC.to_string(), move |incoming| {
        if let Err(e) = deliver_to.cast(
            crate::InfrastructureSupervisorMessage::RunningConfigurationQuestion {
                payload: incoming.payload,
                published_by: incoming.published_by,
            },
        ) {
            warn!(
                "a question about the configuration could not be handed to the infrastructure: {e}"
            );
        }
    })
}

/// What answering needs, owned, so a question is answered off the supervisor's own thread.
#[derive(Clone)]
pub(crate) struct Answerer {
    pub(crate) agent: String,
    pub(crate) configuration: ConfigurationHandle,
    pub(crate) client: TcpClient,
}

impl Answerer {
    pub(crate) async fn answer(&self, payload: Vec<u8>, published_by: Option<String>) {
        let asker = published_by.as_deref().unwrap_or("unverified").to_string();
        let document: Value = match serde_json::from_slice(&payload) {
            Ok(document) => document,
            Err(why) => {
                warn!(requester = %asker, "dropped a message on {QUESTIONS_TOPIC}: {why}");
                return;
            }
        };
        if addressed_to(&document) != Some(self.agent.as_str()) {
            debug!("a question for another agent");
            return;
        }
        let answer = match self.configuration.question(document, published_by).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(rejection)) => {
                warn!(requester = %asker, %rejection, "a question about the configuration was refused");
                return;
            }
            Err(why) => {
                warn!(requester = %asker, "a question about the configuration could not be answered: {why}");
                return;
            }
        };
        let payload = match encode_answer(&answer) {
            Ok(payload) => payload,
            Err(why) => {
                warn!("the answer about the configuration could not be encoded: {why}");
                return;
            }
        };
        match self.client.publish(PublishRequest {
            topic: ANSWERS_TOPIC.to_string(),
            payload,
            trace_ctx: None,
            // An answer that cannot go now is stale by the time it could: the asker tries again.
            offline_behavior: OfflineBehavior::Drop,
            // Who answered is the broker's word, so the identity goes with it.
            share_identity: true,
        }) {
            Ok(()) => info!(requester = %asker, "answered a question about the configuration"),
            Err(e) => warn!("could not answer on {ANSWERS_TOPIC}: {e:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_env::{Defaulted, Described, Optional, Required, Section};
    use polar_scheduler_common::running::question_payload;
    use proptest::prelude::*;

    static HOST: Required<String> = Required::text("HOST", "the host");
    static POLL: Defaulted<u64> = Defaulted::number("POLL", "how often", "60").dynamic();
    static NOTE: Optional<String> = Optional::text("NOTE", "a note").dynamic();
    static TOKEN: Optional<String> = Optional::text("TOKEN", "a token").secret();
    static VARS: &[&dyn Described] = &[&HOST, &POLL, &NOTE, &TOKEN];
    fn no_relations(_: &dyn polar_env::Env) -> Vec<String> {
        vec![]
    }
    static SECTION: Section = Section {
        name: "test",
        vars: VARS,
        relations: no_relations,
    };

    fn config(pairs: &[(&str, &str)]) -> Config {
        let env: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::builder(&env).register(&SECTION).build()
    }

    fn named<'a>(settings: &'a [RunningSetting], name: &str) -> &'a RunningSetting {
        settings.iter().find(|s| s.name == name).unwrap()
    }

    #[test]
    fn the_answer_says_each_value_and_where_it_came_from_and_never_a_secret() {
        let mut c = config(&[("HOST", "h"), ("TOKEN", "hunter2-hunter2"), ("NOTE", "n")]);
        c.replace_overrides(&[("POLL", "120")]).unwrap();
        let s = settings(&c);
        let host = named(&s, "HOST");
        assert_eq!(
            (host.value.as_deref(), host.source.as_str(), host.dynamic),
            (Some("h"), "env", false)
        );
        let poll = named(&s, "POLL");
        assert_eq!(
            (poll.value.as_deref(), poll.source.as_str(), poll.dynamic),
            (Some("120"), "override", true)
        );
        let token = named(&s, "TOKEN");
        assert_eq!(
            (
                token.value.as_deref(),
                token.withheld,
                token.source.as_str()
            ),
            (None, true, "env")
        );
        assert!(!format!("{s:?}").contains("hunter2"));
    }

    #[test]
    fn a_variable_nobody_set_says_so() {
        let s = settings(&config(&[("HOST", "h")]));
        let note = named(&s, "NOTE");
        assert_eq!(
            (note.value.as_deref(), note.source.as_str()),
            (None, "unset")
        );
        assert_eq!(named(&s, "POLL").source, "default");
    }

    #[test]
    fn a_runtime_section_is_given_by_its_version_and_never_its_body() {
        let runtime = HashMap::from([
            (
                "zeta".to_string(),
                RuntimeValue {
                    version: 4,
                    id: "z-4".to_string(),
                    body: serde_json::json!({"held": "not-for-you"}),
                    signer: "alice".to_string(),
                },
            ),
            (
                "alpha".to_string(),
                RuntimeValue {
                    version: 2,
                    id: "a-2".to_string(),
                    body: serde_json::json!({}),
                    signer: "alice".to_string(),
                },
            ),
        ]);
        let a = answer("q".to_string(), "a", &config(&[("HOST", "h")]), 7, &runtime);
        assert_eq!(a.version, 7);
        assert_eq!(
            a.sections,
            vec![
                RunningSection {
                    name: "alpha".to_string(),
                    version: 2,
                    id: "a-2".to_string(),
                    body_sha256: body_sha256(&serde_json::json!({})),
                },
                RunningSection {
                    name: "zeta".to_string(),
                    version: 4,
                    id: "z-4".to_string(),
                    body_sha256: body_sha256(&serde_json::json!({"held": "not-for-you"})),
                },
            ]
        );
        assert!(!format!("{a:?}").contains("not-for-you"));
        // The digest is of the canonical body: what `polar-sign check` computes of the signed section.
        assert_eq!(
            a.sections[0].body_sha256,
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
        assert_eq!(a.build.name, "a");
        assert_eq!(a.build.version, polar_version::PLATFORM);
    }

    proptest! {
        /// Whatever the secret and however a value repeats it, the secret is not in what leaves the agent.
        #[test]
        fn no_value_that_repeats_a_secret_leaves(
            secret in "[a-zA-Z0-9]{4,24}",
            before in "[a-z:/.]{0,10}",
            after in "[a-z:/.]{0,10}",
            repeats in any::<bool>(),
        ) {
            let note = if repeats { format!("{before}{secret}{after}") } else { format!("{before}{after}") };
            let c = config(&[("HOST", "h"), ("TOKEN", &secret), ("NOTE", &note)]);
            let s = settings(&c);
            for setting in &s {
                prop_assert!(!setting.value.as_deref().unwrap_or("").contains(&secret), "{setting:?}");
            }
            prop_assert_eq!(named(&s, "NOTE").withheld, note.contains(&secret));
        }

        /// One value for each variable declared, whatever is set: nothing goes missing and nothing is made up.
        #[test]
        fn the_answer_names_every_declared_variable_once(note in proptest::option::of("[a-z]{0,8}")) {
            let mut pairs = vec![("HOST", "h")];
            if let Some(note) = &note {
                pairs.push(("NOTE", note));
            }
            let names: Vec<String> = settings(&config(&pairs)).into_iter().map(|s| s.name).collect();
            prop_assert_eq!(names, ["HOST", "POLL", "NOTE", "TOKEN"]);
        }
    }

    #[test]
    fn a_question_says_whom_it_is_for_without_being_believed() {
        let document = serde_json::json!({"payload": question_payload("a", "q", 1, 2)});
        assert_eq!(addressed_to(&document), Some("a"));
        assert_eq!(addressed_to(&serde_json::json!({"payload": {}})), None);
        assert_eq!(addressed_to(&serde_json::json!(7)), None);
    }

    /// The promise the whole of this makes: sign what the template gives from an agent's answer, with nothing edited, and
    /// another agent given only that document runs on the same values. So a restart loses nothing, and the file is a
    /// baseline that is true.
    #[test]
    fn a_file_written_from_the_answer_and_signed_unchanged_keeps_what_is_running() {
        let scaffold = polar_sign::scaffold::Scaffold::parse(
            &serde_json::json!({
                "agent": {"name": "a"},
                "sections": [{"name": "test", "variables": [
                    {"name": "POLL", "type": "whole number", "mutability": "dynamic", "default": "60"},
                    {"name": "NOTE", "type": "text", "mutability": "dynamic"},
                    {"name": "HOST", "type": "text", "mutability": "static"},
                    {"name": "TOKEN", "type": "text", "mutability": "static", "secret": true}
                ]}]
            })
            .to_string(),
        )
        .unwrap();
        let rendered = [
            ("HOST", "h"),
            ("NOTE", "as rendered"),
            ("TOKEN", "hunter2-hunter2"),
        ];
        for signed in [
            vec![],
            vec![("POLL", "120")],
            vec![("NOTE", "from \"a\" signer\n// not a comment")],
            vec![("POLL", "5"), ("NOTE", "x")],
        ] {
            let mut running = config(&rendered);
            running.replace_overrides(&signed).unwrap();
            let asked = answer("q".to_string(), "a", &running, 4, &HashMap::new());
            let text = polar_sign::template::running_settings_template(&scaffold, &asked).unwrap();
            let file = polar_sign::lenient::parse(&text).unwrap();
            assert_eq!(file["version"], 5);
            let named: Vec<(String, String)> = file["settings"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
                .collect();
            let named: Vec<(&str, &str)> = named
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            let mut restarted = config(&rendered);
            restarted.replace_overrides(&named).unwrap();
            assert_eq!(restarted.report(), running.report(), "{text}");
        }
    }
}
