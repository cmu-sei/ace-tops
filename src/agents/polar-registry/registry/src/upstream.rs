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

//! The Nix cache's way to its upstream: one declared operation, `nix.upstream`, a GET at the host its variable holds
//! (`settings::UPSTREAM`), with no credential, made by the builder's HTTP handler, which judges it and records it as it
//! does every request an agent makes (docs/architecture/protocol-handlers.md). So applying the catalog signs off where
//! the cache goes, and a fault reaches nowhere else.

use crate::faults::{Fetch, Upstream};
use polar_agent_builder::protocol::http::{Http, Reply, Request, StatusCode};
use polar_agent_builder::protocol::{
    Location, Operation, OperationDecl, ProtocolHandle, ProtocolKind, ReadFailure,
};

/// The upstream cache's variable, by name.
pub const UPSTREAM_VAR: &str = "POLAR_REGISTRY_NIX_UPSTREAM";

/// Asks the upstream cache for a narinfo or an archive.
pub const NIX_UPSTREAM: OperationDecl = OperationDecl {
    name: "nix.upstream",
    doc: "asks the upstream binary cache for a path's narinfo, and then its archive, when the Nix cache does not hold \
          the path; both are checked against the upstream's signature before anything is kept",
    protocol: ProtocolKind::HTTP,
    location: Location::Configured {
        variable: UPSTREAM_VAR,
        credential: None,
    },
};

/// Every operation the registry declares.
pub const OPERATIONS: &[OperationDecl] = &[NIX_UPSTREAM];

struct Get(Request);

impl Operation for Get {
    type Protocol = Http;
    type Output = (StatusCode, Vec<u8>);
    const DECL: OperationDecl = NIX_UPSTREAM;
    fn request(&self) -> Request {
        self.0.clone()
    }
    fn read(&self, reply: &Reply) -> Result<Self::Output, ReadFailure> {
        Ok((reply.status, reply.body.clone()))
    }
}

/// Faults' way out: the builder's protocol handler.
pub struct Handled(pub ProtocolHandle);

#[async_trait::async_trait]
impl Fetch for Handled {
    async fn get(
        &self,
        upstream: &Upstream,
        path: &str,
        limit: u64,
    ) -> Result<Option<Vec<u8>>, String> {
        if upstream.via != NIX_UPSTREAM.name {
            return Err(format!(
                "no operation of this agent's reaches {}",
                upstream.url
            ));
        }
        let (status, body) = self
            .0
            .ask(Get(Request::get(path)))
            .await
            .map_err(|failure| failure.to_string())?;
        match status {
            StatusCode::OK if body.len() as u64 > limit => {
                Err(format!("larger than {limit} bytes"))
            }
            StatusCode::OK => Ok(Some(body)),
            StatusCode::NOT_FOUND => Ok(None),
            other => Err(format!("the upstream answered {other}")),
        }
    }
}
