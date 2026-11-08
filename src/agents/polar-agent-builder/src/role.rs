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

//! What part an agent plays in Polar, declared once (`PolarAgent::ROLE`) and printed in its scaffold, so what holds of
//! observers, processors and the rest is checked of the agents that say they are one, never judged by a name or a pool
//! (the catalog's `pool` is where a workload is scheduled, not what it does).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// Watches something outside Polar and publishes what it sees, as seen; it holds no graph capability and leaves
    /// every meaning downstream.
    Observer,
    /// Turns observations into the graph's state: what an older name calls a consumer.
    Processor,
    /// Decides what other agents work on, and tells them.
    Controller,
    /// Answers requests from other agents or from people: the broker, the certificate authority, the git server, the
    /// credentials agent, the state agent, attestation.
    Service,
    /// Exists to test other workloads, and is deployed only for that.
    Harness,
}

impl Role {
    pub const ALL: [Role; 5] = [
        Role::Observer,
        Role::Processor,
        Role::Controller,
        Role::Service,
        Role::Harness,
    ];

    /// The name the scaffold prints.
    pub const fn name(self) -> &'static str {
        match self {
            Role::Observer => "observer",
            Role::Processor => "processor",
            Role::Controller => "controller",
            Role::Service => "service",
            Role::Harness => "harness",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_role_is_printed_by_its_name_and_read_back() {
        for role in Role::ALL {
            let text = serde_json::to_string(&role).unwrap();
            assert_eq!(text, format!("\"{}\"", role.name()));
            assert_eq!(serde_json::from_str::<Role>(&text).unwrap(), role);
        }
        assert!(serde_json::from_str::<Role>("\"consumer\"").is_err());
    }
}
