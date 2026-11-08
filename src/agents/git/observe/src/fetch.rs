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

//! What the observer asks of the git protocol: a repository up to date, and where each of its refs now stands against what
//! was published of it. The handler judges the request, brings the clone up to date and has the credential; `read` has only
//! the clone (docs/architecture/protocol-handlers.md).

use crate::{Checkpoint, GitRepoWorker, RefPlan, plan_ref};
use git_agent_common::RepoObservationConfig;
use polar_agent_builder::protocol::ReadFailure;
use polar_agent_builder::protocol::git::{Fetched, Git, Request};
use polar_agent_builder::protocol::{
    Credential, Failure, Location, Operation, OperationDecl, ProtocolHandle, ProtocolKind,
};
use std::collections::HashMap;
use std::path::Path;
use tracing::warn;

/// A repository that names its credential goes where that credential's signed binding allows.
pub const FETCH: OperationDecl = OperationDecl {
    name: "git.fetch",
    doc: "brings up to date a repository that names its credential, at a host the credential is bound to",
    protocol: ProtocolKind::GIT,
    location: Location::Bound {
        credential: Credential::Chosen,
    },
};

/// A repository that names none goes wherever the controller says, with nothing to present.
pub const FETCH_PUBLIC: OperationDecl = OperationDecl {
    name: "git.fetch-public",
    doc: "brings up to date a repository that names no credential, at the address the controller gave",
    protocol: ProtocolKind::GIT,
    location: Location::Arbitrary,
};

pub const OPERATIONS: &[OperationDecl] = &[FETCH, FETCH_PUBLIC];

/// What each ref observed would publish, once the repository is up to date: those configured, or if there are none, the
/// repository's default branch. A ref that could not be read is left out.
pub type Walk = Vec<(String, RefPlan)>;

/// The request's own values, and what `read` needs of them.
struct Asked {
    request: Request,
    refs: Vec<String>,
    checkpoints: HashMap<String, Checkpoint>,
    max_depth: usize,
}

impl Asked {
    fn read(&self, reply: &Fetched) -> Walk {
        let repository = &reply.repository;
        let refs = match self.refs.is_empty() {
            true => GitRepoWorker::resolve_default_refs(repository),
            false => self.refs.clone(),
        };
        let mut plans = Vec::with_capacity(refs.len());
        for ref_name in &refs {
            let checkpoint = self.checkpoints.get(ref_name).cloned().unwrap_or_default();
            match plan_ref(repository, ref_name, &checkpoint, self.max_depth) {
                Ok(plan) => plans.push((ref_name.clone(), plan)),
                Err(e) => warn!("ref {ref_name} could not be walked ({e}), skipping"),
            }
        }
        plans
    }
}

struct WithCredential {
    credential: String,
    asked: Asked,
}

impl Operation for WithCredential {
    type Protocol = Git;
    type Output = Walk;
    const DECL: OperationDecl = FETCH;

    fn request(&self) -> Request {
        self.asked.request.clone()
    }
    fn credential(&self) -> Option<String> {
        Some(self.credential.clone())
    }
    fn read(&self, reply: &Fetched) -> Result<Walk, ReadFailure> {
        Ok(self.asked.read(reply))
    }
}

struct Public(Asked);

impl Operation for Public {
    type Protocol = Git;
    type Output = Walk;
    const DECL: OperationDecl = FETCH_PUBLIC;

    fn request(&self) -> Request {
        self.0.request.clone()
    }
    fn read(&self, reply: &Fetched) -> Result<Walk, ReadFailure> {
        Ok(self.0.read(reply))
    }
}

/// Brings the repository up to date in the clone at `clone_at`, and says what each of its refs would publish from
/// `checkpoints`. Waiting holds only the worker that asked.
pub async fn fetch(
    protocols: &ProtocolHandle,
    config: &RepoObservationConfig,
    clone_at: &Path,
    checkpoints: &HashMap<String, Checkpoint>,
) -> Result<Walk, Failure> {
    let asked = Asked {
        request: Request::new(
            config.repo_url.clone(),
            clone_at,
            config.remotes.clone(),
            config.shallow_depth,
        ),
        refs: config.refs.clone(),
        checkpoints: checkpoints.clone(),
        max_depth: config.max_depth,
    };
    match &config.credential {
        Some(name) => {
            protocols
                .ask(WithCredential {
                    credential: name.clone(),
                    asked,
                })
                .await
        }
        None => protocols.ask(Public(asked)).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use git_agent_common::remote::https_host;
    use polar_agent_builder::protocol::{Protocol, Target};
    use proptest::prelude::*;

    fn handler_reads(url: &str) -> Result<Target, String> {
        Git::target(&Request::new(url, "/nowhere", Vec::new(), None), None)
    }

    proptest! {
        /// The controller and the handler read a repository's host alike: what the controller takes, the handler judges for
        /// the same host, as encrypted.
        #[test]
        fn what_the_controller_takes_the_handler_reads_the_same_way(
            authority in "[a-zA-Z0-9.:@\\\\%-]{0,24}",
            rest in "([/?#][a-z.]{0,8})?",
        ) {
            let url = format!("https://{authority}{rest}");
            if let Ok(host) = https_host(&url) {
                prop_assert_eq!(
                    handler_reads(&url),
                    Ok(Target {
                        host,
                        encrypted: true,
                        access: None
                    })
                );
            }
        }
    }

    #[test]
    fn the_address_of_a_repository_is_read_alike_for_the_ones_that_have_one() {
        for url in [
            "https://github.com/org/repo.git",
            "https://GitHub.com:8443/o/r.git",
            "https://github.com",
        ] {
            assert_eq!(
                handler_reads(url).unwrap().host,
                https_host(url).unwrap(),
                "{url}"
            );
        }
    }
}
