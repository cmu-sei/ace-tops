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

//! What the GitLab observer is, as the infrastructure asks to be told: see `polar_agent_builder::PolarAgent`.

use gitlab_common::{OBSERVATIONS_TOPIC, OBSERVER_NAME};
use polar_agent_builder::protocol::credentials::section;
use polar_agent_builder::protocol::{Credential, Location, OperationDecl, ProtocolKind};
use polar_agent_builder::{
    Capability, Cause, Configured, PolarAgent, Role, RuntimeSection, StartError, TopicDecl,
};
use polar_http_observer::{CREDENTIALED_SOURCES, Kind};
use std::time::Duration;

/// Reads a page its signed `sources` give, with no credential: a GitLab whose API answers anyone.
pub const READ: OperationDecl = OperationDecl {
    name: "gitlab.page.read",
    doc: "reads a GitLab page its signed sources give, with no credential",
    protocol: ProtocolKind::HTTP,
    location: Location::Arbitrary,
};

/// Reads a page its signed `sources` give, with the token the source names, which goes only to a host its signed binding
/// names.
pub const READ_WITH_TOKEN: OperationDecl = OperationDecl {
    name: "gitlab.page.read-with-token",
    doc: "reads a GitLab page its signed sources give, with the token the source names, bound to its host",
    protocol: ProtocolKind::HTTP,
    location: Location::Bound {
        credential: Credential::Chosen,
    },
};

/// Most tokens one version may carry: one for each GitLab a deployment reads, and a few more.
pub const MAX_CREDENTIALS: usize = 16;

pub static CREDENTIALS: RuntimeSection = section::<MAX_CREDENTIALS>(
    "The tokens the GitLab observer reads with, each bound to the hosts it may go to: a personal, group or project access \
     token with read_api, presented as a bearer token. A source names the one it is read with. Replaced whole by each \
     version: an entry left out is withdrawn.",
);

pub struct GitlabObserver;

impl Kind for GitlabObserver {
    const NAME: &'static str = OBSERVER_NAME;
    const TOPIC: &'static str = OBSERVATIONS_TOPIC;
    const OPERATION: OperationDecl = READ;
    const CREDENTIALED: Option<OperationDecl> = Some(READ_WITH_TOKEN);
}

impl PolarAgent for GitlabObserver {
    const NAME: &'static str = OBSERVER_NAME;
    const ROLE: Role = Role::Observer;
    const PURPOSE: &'static str = "Reads what its signed sources ask of GitLab's GraphQL API and publishes each page for the processor";
    const NEEDS: &'static [Capability] = &[];
    const SHUTDOWN_BUDGET: Duration = polar_http_observer::observer::SHUTDOWN_BUDGET;
    const TOPICS: &'static [TopicDecl] = &[TopicDecl::publish(
        OBSERVATIONS_TOPIC,
        "each page as it came, for the processor",
    )
    .because(&[Cause::Timer("read")])];
    const RUNTIME: &'static [&'static RuntimeSection] = &[&CREDENTIALED_SOURCES];
    const CREDENTIALS: Option<&'static RuntimeSection> = Some(&CREDENTIALS);
    const OPERATIONS: &'static [OperationDecl] = &[READ, READ_WITH_TOKEN];
    const HELP: Option<&'static str> = Some(
        "The observer reads each source its signed `sources` section names, on that source's interval: a GraphQL query \
         POSTed to GitLab's /api/graphql, paged by its cursor, and following each item with a query of its own when the \
         source says so. Each page is published as it came. It parses nothing it does not page by, and never touches the \
         graph. A source that names a credential is read with that token, which goes only to a host its signed binding \
         names. With no section signed it reads nothing.",
    );

    async fn start(configured: Configured) -> Result<(), StartError> {
        polar_http_observer::start::<GitlabObserver>(configured).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    polar_agent_builder::polar_agent_tests!(GitlabObserver);
}
