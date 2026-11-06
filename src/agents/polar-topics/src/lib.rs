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

//! The topic types a scaffold prints (what an agent does with a topic, what causes it, where it comes from) and the topic
//! gate's rule ([`gate`]), with no runtime, so the authority model and the tools that judge a deployment's facts read
//! them as the agents write and apply them (docs/architecture/http-observers.md, "Evidence", bite 5). The agent builder
//! computes an agent's set and re-exports these as `polar_agent_builder::topics`.

use serde::{Deserialize, Serialize};

pub mod gate;

/// What an agent does with a topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Publish,
    Subscribe,
}

impl Access {
    pub fn as_str(self) -> &'static str {
        match self {
            Access::Publish => "publish",
            Access::Subscribe => "subscribe",
        }
    }
}

/// What makes an agent publish on a topic, as its code knows it (docs/architecture/authority-model.md, "Decisions":
/// local causes, derived paths, and the vocabulary of causes). An agent says only what its own code does: the
/// authority derives the paths through the system from everyone's causes. Every cause but `Topic` is an entry, a way
/// in from outside the agent's subscriptions, which a subscription may answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    /// A message arrived on a topic the agent subscribes to.
    Topic(&'static str),
    /// A request on a route the agent serves.
    Http(&'static str),
    /// The agent registered with Cassini (again).
    Registered,
    /// The agent's own interval.
    Timer(&'static str),
    /// Something outside Polar the agent watches.
    Outside(&'static str),
}

/// A [`Cause`] as the set holds it and the scaffold prints it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "name", rename_all = "snake_case")]
pub enum CauseEntry {
    Topic(String),
    Http(String),
    Registered,
    Timer(String),
    Outside(String),
}

impl From<Cause> for CauseEntry {
    fn from(cause: Cause) -> Self {
        match cause {
            Cause::Topic(name) => CauseEntry::Topic(name.to_string()),
            Cause::Http(route) => CauseEntry::Http(route.to_string()),
            Cause::Registered => CauseEntry::Registered,
            Cause::Timer(name) => CauseEntry::Timer(name.to_string()),
            Cause::Outside(source) => CauseEntry::Outside(source.to_string()),
        }
    }
}

impl CauseEntry {
    /// The name it carries, if any: a topic, a route, a timer, a source.
    pub fn name(&self) -> Option<&str> {
        match self {
            CauseEntry::Topic(n)
            | CauseEntry::Http(n)
            | CauseEntry::Timer(n)
            | CauseEntry::Outside(n) => Some(n),
            CauseEntry::Registered => None,
        }
    }
}

/// Why a topic implied for an agent is in its set: each rule is a fact about the agent, and these are all
/// the rules there are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rule {
    /// Every agent that is a Cassini client: its configuration and command topics, asking for a replay and
    /// reporting outcomes, the credentials agent's authority topics, and pulled health (its question topic and the
    /// answers').
    Agent,
    /// An agent whose self-test is on probes itself on its own topic.
    SelfTest,
    /// An agent that needs `Encryption` has a crypto actor, which makes the credentials agent's requests.
    Encryption,
    /// An agent with the `SoftState` capability (it declares a graph read) has a state actor, which asks the state
    /// agent; it hears the answer on its own reply topic, which the `Agent` rule gives every client
    /// (docs/architecture/soft-state.md).
    SoftState,
}

impl Rule {
    /// Every rule there is.
    pub const ALL: [Rule; 4] = [
        Rule::Agent,
        Rule::SelfTest,
        Rule::Encryption,
        Rule::SoftState,
    ];

    /// The group whose members the rule applies to (docs/architecture/policy-enforcement.md, "Decisions"): the
    /// certificate carries it as `g:<group>`, so the broker knows what the agent knows.
    pub fn group(self) -> &'static str {
        match self {
            Rule::Agent => "cassini-client",
            Rule::SelfTest => "self-test",
            Rule::Encryption => "encryption",
            Rule::SoftState => "soft-state",
        }
    }

    /// The rule a group stands for; none for a group that implies no topics.
    pub fn for_group(group: &str) -> Option<Rule> {
        Rule::ALL.into_iter().find(|rule| rule.group() == group)
    }

    pub fn describe(self) -> &'static str {
        match self {
            Rule::Agent => "every agent that is a Cassini client",
            Rule::SelfTest => "the agent's self-test is on",
            Rule::Encryption => "the agent needs encryption (its crypto actor)",
            Rule::SoftState => "the agent reads its own soft state (its state actor)",
        }
    }
}

/// Where a topic in the set comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "from", rename_all = "snake_case")]
pub enum Origin {
    /// The agent declared it, for this purpose; `waits` says why nothing in the catalog is on its other side.
    Declared {
        purpose: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        waits: Option<String>,
    },
    /// One of the agent's families, expanded for one workload it serves.
    Family {
        pattern: String,
        workload: String,
        purpose: String,
    },
    /// A rule implied it.
    Implied { rule: Rule, why: String },
}

/// One topic of the set, as the scaffold prints it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopicEntry {
    pub name: String,
    pub access: Access,
    #[serde(flatten)]
    pub origin: Origin,
    /// For a publish, what causes it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub causes: Vec<CauseEntry>,
    /// For a subscription, the entries it answers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub answers: Vec<CauseEntry>,
    /// For a publish nothing causes, why the agent publishes it of its own accord.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unprompted: Option<String>,
}
