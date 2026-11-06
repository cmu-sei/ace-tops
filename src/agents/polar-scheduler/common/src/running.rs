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

//! Asking a running agent for its configuration (docs/architecture/dynamic-settings.md, "Asking an agent what is in
//! force"): the words on the wire, which the agent, the tool that asks and the one that writes a document from the
//! answer all read.
//!
//! A question is a signed document, under its own signing domain, so the agent knows what its asker's certificate
//! carries and a signature made for this can do nothing else. Every agent hears questions on one topic,
//! [`QUESTIONS_TOPIC`], and answers those addressed to it on [`ANSWERS_TOPIC`]. There is one of each because a person's
//! certificate names no topics, so what lets one ask is a Cedar rule, and a rule names a topic exactly.

use rkyv::{Archive, Deserialize, Serialize};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

/// Where a question is asked. Every agent subscribes; a person publishes here only if policy permits it.
pub const QUESTIONS_TOPIC: &str = "polar-running-configuration-questions";

/// Where every agent answers. Nothing in the catalog subscribes; a person does, if policy permits it.
pub const ANSWERS_TOPIC: &str = "polar-running-configuration-answers";

/// The longest a question may stay valid: it is asked and answered in seconds.
pub const MAX_QUESTION_VALIDITY_SECS: u64 = 300;

/// The value of a question's `type`.
pub const QUESTION_TYPE: &str = "running-configuration-question";

/// What a question's payload says. Signed, so the target and the window are the asker's own.
pub fn question_payload(
    agent: &str,
    id: &str,
    issued_at: u64,
    not_after: u64,
) -> serde_json::Value {
    serde_json::json!({
        "type": QUESTION_TYPE,
        "id": id,
        "target": { "agent": agent },
        "issued_at": issued_at,
        "not_after": not_after,
    })
}

/// One variable as it resolves now. A secret's value never leaves the agent.
#[derive(
    Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize, SerdeSerialize, SerdeDeserialize,
)]
pub struct RunningSetting {
    pub section: String,
    pub name: String,
    /// The value as text. None when it is not set, or is withheld.
    pub value: Option<String>,
    /// Where it came from: `override` (a signed document), `env` or `file` (the render), `default` or `unset`.
    pub source: String,
    /// Whether a signed document may change it.
    pub dynamic: bool,
    /// A declared secret, or a value that repeats one: `value` is withheld.
    pub withheld: bool,
}

/// A runtime section the agent holds: the signed document's id and version, and the digest of its body (SHA-256 of its
/// canonical form, as `polar_signing::canonical` writes it), which says which body it is and nothing of what it holds.
/// Never the body, which may hold a secret.
#[derive(
    Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize, SerdeSerialize, SerdeDeserialize,
)]
pub struct RunningSection {
    pub name: String,
    pub version: u64,
    pub id: String,
    pub body_sha256: String,
}

/// The build an agent runs, as its `polar_version::record` says it.
#[derive(
    Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize, SerdeSerialize, SerdeDeserialize,
)]
pub struct RunningBuild {
    pub name: String,
    /// The platform version.
    pub version: String,
    pub release: bool,
    pub target: String,
}

/// What an agent says of its configuration in force.
#[derive(
    Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize, SerdeSerialize, SerdeDeserialize,
)]
pub struct RunningConfiguration {
    /// The question's `id`.
    pub id: String,
    pub agent: String,
    /// The version of the last signed document of settings it applied: 0 if none since it started.
    pub version: u64,
    pub settings: Vec<RunningSetting>,
    pub sections: Vec<RunningSection>,
    /// Since 2026-11-06, with each section's id and digest: an answer is read only by a tool of the same build, so the
    /// tool that asks is upgraded with the agents (a breaking change, recorded for the migration in `remaining-work.md`).
    pub build: RunningBuild,
    pub at_unix_secs: u64,
}

/// An answer as it goes on the wire.
pub fn encode_answer(answer: &RunningConfiguration) -> Result<Vec<u8>, String> {
    rkyv::to_bytes::<rkyv::rancor::Error>(answer)
        .map(|bytes| bytes.to_vec())
        .map_err(|e| e.to_string())
}

/// An answer off the wire. It is checked, so bytes that are not an answer are an error and not undefined behaviour.
pub fn decode_answer(payload: &[u8]) -> Result<RunningConfiguration, String> {
    rkyv::from_bytes::<RunningConfiguration, rkyv::rancor::Error>(payload)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn setting() -> impl Strategy<Value = RunningSetting> {
        (
            "[a-z]{1,8}",
            "[A-Z_]{1,12}",
            proptest::option::of("\\PC{0,20}"),
            "override|env|file|default|unset",
            any::<bool>(),
            any::<bool>(),
        )
            .prop_map(
                |(section, name, value, source, dynamic, withheld)| RunningSetting {
                    section,
                    name,
                    value,
                    source,
                    dynamic,
                    withheld,
                },
            )
    }

    fn answer() -> impl Strategy<Value = RunningConfiguration> {
        (
            "\\PC{0,12}",
            "[a-z-]{1,20}",
            any::<u64>(),
            proptest::collection::vec(setting(), 0..8),
            proptest::collection::vec(
                (
                    "[a-z]{1,8}",
                    any::<u64>(),
                    "[a-z0-9-]{0,12}",
                    "[0-9a-f]{64}",
                ),
                0..4,
            ),
            (
                "[a-z-]{1,20}",
                "[0-9.+a-z]{1,12}",
                any::<bool>(),
                "[a-z0-9_-]{1,24}",
            ),
            any::<u64>(),
        )
            .prop_map(
                |(id, agent, version, settings, sections, build, at_unix_secs)| {
                    RunningConfiguration {
                        id,
                        agent,
                        version,
                        settings,
                        sections: sections
                            .into_iter()
                            .map(|(name, version, id, body_sha256)| RunningSection {
                                name,
                                version,
                                id,
                                body_sha256,
                            })
                            .collect(),
                        build: RunningBuild {
                            name: build.0,
                            version: build.1,
                            release: build.2,
                            target: build.3,
                        },
                        at_unix_secs,
                    }
                },
            )
    }

    proptest! {
        #[test]
        fn an_answer_reads_back_as_it_was_written(answer in answer()) {
            prop_assert_eq!(decode_answer(&encode_answer(&answer).unwrap()).unwrap(), answer);
        }

        /// What the tool prints is what a machine or the template reads.
        #[test]
        fn an_answer_reads_back_from_json(answer in answer()) {
            let text = serde_json::to_string(&answer).unwrap();
            prop_assert_eq!(serde_json::from_str::<RunningConfiguration>(&text).unwrap(), answer);
        }

        #[test]
        fn bytes_that_are_not_an_answer_are_refused_and_do_not_panic(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = decode_answer(&bytes);
        }
    }

    #[test]
    fn a_question_says_what_it_is_and_whom_it_asks() {
        let q = question_payload("jira-observer", "q1", 10, 70);
        assert_eq!(q["type"], QUESTION_TYPE);
        assert_eq!(q["target"]["agent"], "jira-observer");
        assert_eq!(q["not_after"], 70);
    }
}
