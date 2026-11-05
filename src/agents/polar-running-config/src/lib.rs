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

//! Asking a running agent for its configuration, the asking side (docs/architecture/dynamic-settings.md, "Asking an
//! agent what is in force"): what the tool does on each thing the broker says, with nothing running.

use cassini_types::ClientEvent;
use polar_scheduler_common::running::{
    ANSWERS_TOPIC, QUESTIONS_TOPIC, RunningConfiguration, decode_answer,
};

/// What to do next.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    Nothing,
    /// Listen for answers. First, so the answer cannot go by before anyone hears it.
    Subscribe,
    /// Put the question.
    Ask,
    Answered(Box<RunningConfiguration>),
    Failed(String),
}

/// What it means to be refused on one of the two topics: a person's certificate names no topics, so only policy lets
/// one use them.
fn refused(what: &str, topic: &str, reason: &str) -> Step {
    Step::Failed(format!(
        "the broker refused to let you {what} on {topic}: {reason}. Asking needs the rules in \
         infra/seeds/signed/policy.cedar in the policy in force"
    ))
}

/// Whether an answer is the one asked for: to this question, about this agent, and from it by the broker's word.
pub fn is_the_answer(
    answer: &RunningConfiguration,
    id: &str,
    agent: &str,
    published_by: Option<&str>,
) -> bool {
    answer.id == id
        && answer.agent == agent
        && published_by.and_then(cert_issuer_common::identity::workload_of) == Some(agent)
}

/// The tool's one question.
pub struct Asking {
    pub agent: String,
    pub id: String,
}

impl Asking {
    pub fn on(&self, event: ClientEvent) -> Step {
        match event {
            // Again after a reconnection: a new session holds no subscription.
            ClientEvent::Registered { .. } => Step::Subscribe,
            ClientEvent::ClientSubscribed { topic } if topic == ANSWERS_TOPIC => Step::Ask,
            ClientEvent::SubscribeRefused { topic, reason } if topic == ANSWERS_TOPIC => {
                refused("listen", &topic, &reason)
            }
            ClientEvent::PublishRefused { topic, reason } if topic == QUESTIONS_TOPIC => {
                refused("ask", &topic, &reason)
            }
            ClientEvent::PublishDropped { topic, reason }
            | ClientEvent::PublishDeferred { topic, reason }
                if topic == QUESTIONS_TOPIC =>
            {
                Step::Failed(format!(
                    "the broker could not take the question now: {reason}. Try again"
                ))
            }
            ClientEvent::RegistrationRefused { reason, .. } => {
                Step::Failed(format!("the broker refused the connection: {reason}"))
            }
            ClientEvent::MessagePublished {
                topic,
                payload,
                published_by,
                ..
            } if topic == ANSWERS_TOPIC => match decode_answer(&payload) {
                Ok(answer)
                    if is_the_answer(&answer, &self.id, &self.agent, published_by.as_deref()) =>
                {
                    Step::Answered(Box::new(answer))
                }
                // Anyone asking hears every answer. Not ours.
                _ => Step::Nothing,
            },
            _ => Step::Nothing,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_scheduler_common::running::encode_answer;
    use proptest::prelude::*;

    const AGENT: &str = "jira-observer";
    const STAMP: &str = "jira-observer.polar.serviceaccount.cluster.local";

    fn asking() -> Asking {
        Asking {
            agent: AGENT.to_string(),
            id: "q1".to_string(),
        }
    }

    fn answer(id: &str, agent: &str) -> RunningConfiguration {
        RunningConfiguration {
            id: id.to_string(),
            agent: agent.to_string(),
            version: 3,
            settings: vec![],
            sections: vec![],
            at_unix_secs: 1,
        }
    }

    fn delivered(topic: &str, payload: Vec<u8>, stamp: Option<&str>) -> ClientEvent {
        ClientEvent::MessagePublished {
            topic: topic.to_string(),
            payload,
            trace_ctx: None,
            published_by: stamp.map(str::to_string),
            published_instance: None,
        }
    }

    #[test]
    fn it_listens_first_then_asks_then_takes_its_answer() {
        let a = asking();
        assert_eq!(
            a.on(ClientEvent::Registered {
                registration_id: "r".to_string()
            }),
            Step::Subscribe
        );
        assert_eq!(
            a.on(ClientEvent::ClientSubscribed {
                topic: ANSWERS_TOPIC.to_string()
            }),
            Step::Ask
        );
        let good = answer("q1", AGENT);
        assert_eq!(
            a.on(delivered(
                ANSWERS_TOPIC,
                encode_answer(&good).unwrap(),
                Some(STAMP)
            )),
            Step::Answered(Box::new(good))
        );
    }

    #[test]
    fn a_refusal_says_what_was_refused_and_what_would_admit_it() {
        for event in [
            ClientEvent::SubscribeRefused {
                topic: ANSWERS_TOPIC.to_string(),
                reason: "no".to_string(),
            },
            ClientEvent::PublishRefused {
                topic: QUESTIONS_TOPIC.to_string(),
                reason: "no".to_string(),
            },
        ] {
            let Step::Failed(why) = asking().on(event) else {
                panic!("a refusal is the end of it");
            };
            assert!(why.contains("policy.cedar"), "{why}");
        }
    }

    #[test]
    fn what_goes_by_on_other_topics_or_is_not_an_answer_is_ignored() {
        let a = asking();
        assert_eq!(
            a.on(ClientEvent::SubscribeRefused {
                topic: "other".to_string(),
                reason: "no".to_string()
            }),
            Step::Nothing
        );
        assert_eq!(
            a.on(delivered(ANSWERS_TOPIC, vec![1, 2, 3], Some(STAMP))),
            Step::Nothing
        );
        let good = encode_answer(&answer("q1", AGENT)).unwrap();
        assert_eq!(a.on(delivered("other", good, Some(STAMP))), Step::Nothing);
    }

    proptest! {
        /// An answer counts only if it answers this question, is about this agent, and the broker says that agent sent it:
        /// another agent, or anyone who may publish there, cannot speak for it.
        #[test]
        fn only_the_agent_asked_can_answer(
            right_id in any::<bool>(),
            right_agent in any::<bool>(),
            stamp in prop_oneof![
                Just(Some(STAMP)),
                Just(Some("kube-observer.polar.serviceaccount.cluster.local")),
                Just(Some("jira-observer")),
                Just(Some("d983a3d2-9b61-41c5-88a0-d123fb50ba33")),
                Just(None),
            ],
        ) {
            let a = answer(if right_id { "q1" } else { "q2" }, if right_agent { AGENT } else { "kube-observer" });
            let taken = is_the_answer(&a, "q1", AGENT, stamp);
            prop_assert_eq!(taken, right_id && right_agent && stamp == Some(STAMP));
        }
    }
}
