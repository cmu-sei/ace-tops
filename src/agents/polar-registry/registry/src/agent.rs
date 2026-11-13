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

//! What polar-registry is, as the infrastructure asks to be told: see `polar_agent_builder::PolarAgent`.

use crate::supervisor::{RegistrySupervisor, SHUTDOWN_BUDGET};
use polar_agent_builder::protocol::OperationDecl;
use polar_agent_builder::{Capability, Configured, PolarAgent, Role, StartError};
use ractor::Actor;
use std::time::Duration;

/// The agent's name.
pub const AGENT_NAME: &str = "polar-registry";

pub struct Registry;

impl PolarAgent for Registry {
    const NAME: &'static str = AGENT_NAME;
    const ROLE: Role = Role::Service;
    const PURPOSE: &'static str = "Holds what builds read, by the digest of its content, and serves it to the tools that \
                                   read it: Nix's binary cache first, signed with Polar's key";
    const NEEDS: &'static [Capability] = &[];
    const SHUTDOWN_BUDGET: Duration = SHUTDOWN_BUDGET;
    const OPERATIONS: &'static [OperationDecl] = crate::upstream::OPERATIONS;
    const SECTIONS: &'static [&'static polar_env::Section] = &[&crate::settings::SECTION];
    const HELP: Option<&'static str> = Some(
        "polar-registry keeps a content store on its volume (POLAR_REGISTRY_ROOT): each blob named by the SHA-256 of its \
         content and kept compressed, nothing kept that is not what it was said to be. Over it, it serves Nix's binary \
         cache protocol on POLAR_REGISTRY_LISTEN, every path signed with the key in POLAR_REGISTRY_NIX_KEY. A path it does \
         not hold is faulted in from the upstream cache (POLAR_REGISTRY_NIX_UPSTREAM, trusted by \
         POLAR_REGISTRY_NIX_UPSTREAM_KEY) when POLAR_REGISTRY_NIX_FAULTS is on, through its one declared operation, and \
         every fault is recorded in faults.jsonl on its volume. Reads are anonymous: what is read carries its own proof.",
    );

    async fn start(configured: Configured) -> Result<(), StartError> {
        configured.init_logging(AGENT_NAME);
        let name = format!("{AGENT_NAME}.supervisor");
        let (_, handle) = Actor::spawn(Some(name.clone()), RegistrySupervisor, configured)
            .await
            .map_err(|e| format!("{name} failed to start: {e}"))?;
        handle
            .await
            .map_err(|e| format!("{name} task failed: {e}"))?;
        // A registry that is no longer serving must be restarted.
        Err(format!("{name} stopped").into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    polar_agent_builder::polar_agent_tests!(Registry);

    #[test]
    fn it_goes_out_only_to_its_upstream_cache_with_no_credential() {
        let scaffold = polar_agent_builder::agent::scaffold_document::<Registry>();
        let ops: Vec<_> = scaffold
            .operations
            .iter()
            .map(|o| (o.name.as_str(), o.protocol.as_str()))
            .collect();
        assert_eq!(ops, [("nix.upstream", "http")]);
    }
}
