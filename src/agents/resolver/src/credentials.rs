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

//! The resolver's `credentials` runtime section: what it presents to the registries that need one, each entry bound to the
//! hosts it names (docs/architecture/protocol-handlers.md, "The protocols"). The builder judges each version and hands it
//! to the CryptoActor, and the handler presents what the binding of a registry's host says, so nothing here ever has it.

use polar_agent_builder::RuntimeSection;
use polar_agent_builder::protocol::credentials::section;

/// Most entries one version may carry: one for each private registry a deployment reads.
pub const MAX_ENTRIES: usize = 64;

pub static CREDENTIALS: RuntimeSection = section::<MAX_ENTRIES>(
    "The credentials the resolver presents to private registries, chosen by the host of the image: the entry whose host \
     pattern names that host most closely. An entry names the registry and the host that takes its logins if that is \
     another: registry.gitlab.com,gitlab.com. A user-password goes to whichever the registry's challenge asks for, and a \
     token goes to the registry as it is. A registry no entry names is asked with no credential. Replaced whole by each \
     version: an entry left out is withdrawn.",
);
