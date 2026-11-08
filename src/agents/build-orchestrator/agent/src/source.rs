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

//! A build's source step: its source fetched through the orchestrator's protocol handlers and put in the registry as an
//! archive, by digest, for the build's fetch to unpack (docs/architecture/build-orchestrator.md, decision 1). A trait, so a
//! job actor is tested without a registry; the agent's one implementation refuses until the git handler fetches and the
//! registry takes the archive (O3), so a build fails at its source and says so.

use orchestrator_core::types::{SourceArchive, SourceRef};

#[ractor::async_trait]
pub trait Source: Send + Sync {
    /// The archive `source` is in, or why there is none.
    async fn prepare(&self, source: &SourceRef) -> Result<SourceArchive, String>;
}

/// The source step as it stands: none yet.
pub struct NotYet;

#[ractor::async_trait]
impl Source for NotYet {
    async fn prepare(&self, _: &SourceRef) -> Result<SourceArchive, String> {
        Err(
            "the orchestrator does not fetch a build's source yet (build-orchestrator.md, O3)"
                .into(),
        )
    }
}
