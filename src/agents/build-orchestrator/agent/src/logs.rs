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

//! A build's log, kept once its pod has ended (docs/architecture/build-orchestrator.md, O4): a blob in the registry in the
//! cluster, and a small OCI manifest naming it, tagged by the build's id in `build-logs`, so the registry's garbage
//! collection keeps it and it is found by the build ("blob plus a manifest", as a source is). The execution event names
//! it by its digest. Through the same declared push as the source, to the host the orchestrator's configuration names.

use crate::push::{EMPTY, blob, digest_of, manifest_of, put_manifest};
use polar_agent_builder::protocol::ProtocolHandle;

/// Where every build's log goes.
pub const REPOSITORY: &str = "build-logs";
/// What a log's manifest is an artifact of.
pub const ARTIFACT_TYPE: &str = "application/vnd.polar.build-log.v1";
/// What its one layer is: the pod's log as the API gave it, both containers' lines in the order they came.
pub const LOG_TYPE: &str = "application/vnd.polar.build-log.v1.txt";

/// Keeps a build's log and gives its digest.
#[ractor::async_trait]
pub trait KeepLog: Send + Sync {
    async fn keep(&self, build_id: &str, log: &[u8]) -> Result<String, String>;
}

/// The registry in the cluster, through the protocol handler.
pub struct RegistryLogs {
    protocols: ProtocolHandle,
}

impl RegistryLogs {
    pub fn new(protocols: ProtocolHandle) -> Self {
        Self { protocols }
    }
}

#[ractor::async_trait]
impl KeepLog for RegistryLogs {
    /// The log, the empty config and the manifest, in that order, so a manifest never names what is not there.
    async fn keep(&self, build_id: &str, log: &[u8]) -> Result<String, String> {
        blob(&self.protocols, REPOSITORY, log, "log").await?;
        blob(&self.protocols, REPOSITORY, EMPTY, "empty config").await?;
        let digest = digest_of(log);
        put_manifest(
            &self.protocols,
            REPOSITORY,
            build_id,
            manifest_of(ARTIFACT_TYPE, LOG_TYPE, &digest, log.len()),
        )
        .await?;
        Ok(digest)
    }
}
