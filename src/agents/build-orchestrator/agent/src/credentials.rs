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

//! The orchestrator's `credentials` runtime section: the credentials a mapped repository's source may be fetched with, each
//! only for the hosts it names. The builder judges each version and hands it to the CryptoActor, and the git handler asks for
//! the one a mapping names, so nothing here ever has it (docs/architecture/protocol-handlers.md).

use polar_agent_builder::RuntimeSection;
use polar_agent_builder::protocol::credentials::section;

/// Most entries one version may carry.
pub const MAX_ENTRIES: usize = 256;

pub static CREDENTIALS: RuntimeSection = section::<MAX_ENTRIES>(
    "Credentials a mapped repository's source may be fetched with, each only for the hosts it names. A mapping names the one \
     it wants. Replaced whole by each version, so an entry left out is withdrawn.",
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_section_is_declared_soundly() {
        assert!(polar_agent_builder::runtime::check_declarations(&[&CREDENTIALS]).is_empty());
    }
}
