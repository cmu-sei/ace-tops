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

//! The topic gate's rule, on its own: what an agent may do with a topic, given what policy said and the agent's own set
//! (Cedar first, then the floor). The gate (`polar_agent_builder::topic_gate`) asks policy and applies it; the authority
//! model judges a policy by it, so the judgement and the enforcement cannot disagree.

use crate::Access;
use polar_policy::Decision;

/// What the agent's policy said about one use of a topic, as the gate reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySaid {
    /// No policy actor is running yet.
    NotRunning,
    /// It answered.
    Decided(Decision),
    /// It is running and has no rules.
    NoPolicyLoaded,
    /// It could not be consulted.
    Unavailable(String),
}

/// The rule, on its own: whether an agent may use `topic` this way, given what policy said and whether the topic
/// is in the agent's set.
pub fn rule(said: &PolicySaid, in_set: bool, topic: &str, access: Access) -> Result<(), String> {
    let floor = || {
        if in_set {
            Ok(())
        } else {
            Err(format!(
                "this agent does not {} on `{topic}`: it is not among its declared or implied topics, and no policy \
                 permits it",
                access.as_str()
            ))
        }
    };
    match said {
        PolicySaid::Decided(Decision::Allow) => Ok(()),
        PolicySaid::Decided(Decision::Deny) => Err(format!(
            "policy forbids this agent to {} on `{topic}`",
            access.as_str()
        )),
        PolicySaid::Decided(Decision::NotDetermined)
        | PolicySaid::NoPolicyLoaded
        | PolicySaid::NotRunning => floor(),
        PolicySaid::Unavailable(why) => Err(format!(
            "policy could not be consulted about `{topic}` ({why}), so nothing is sent"
        )),
    }
}

/// A Cedar entity reference, with the id escaped so that nothing in it can end the reference early or name
/// another entity. `None` for an id with a control character in it, which is not a name.
pub fn entity(kind: &str, id: &str) -> Option<String> {
    if id.chars().any(char::is_control) {
        return None;
    }
    Some(format!(
        "{kind}::\"{}\"",
        id.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}
