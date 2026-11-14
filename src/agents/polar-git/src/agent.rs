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

use crate::supervisor::{PolarGitSupervisor, SERVICE_NAME, SHUTDOWN_BUDGET};
use polar_agent_builder::{Capability, Cause, Configured, PolarAgent, Role, StartError, TopicDecl};
use polar_env::Section;
use ractor::Actor;
use std::time::Duration;

pub struct PolarGit;

impl PolarAgent for PolarGit {
    const NAME: &'static str = SERVICE_NAME;
    const ROLE: Role = Role::Service;
    const PURPOSE: &'static str = "Hosts people's source code over git smart HTTP: the one service inside the boundary that takes direct connections, judging each git operation by Cedar policy and reporting all of it over Cassini";
    const NEEDS: &'static [Capability] = &[Capability::Cassini];
    const SHUTDOWN_BUDGET: Duration = SHUTDOWN_BUDGET;
    const TOPICS: &'static [TopicDecl] = &[TopicDecl::publish(
        crate::events::GIT_EVENTS_TOPIC,
        "every fetch, repository made, push (each ref it moved, and how) and refusal, with who did it",
    )
    .because(&[
        Cause::Http(crate::http::INFO_REFS_ROUTE),
        Cause::Http(crate::http::UPLOAD_PACK_ROUTE),
        Cause::Http(crate::http::RECEIVE_PACK_ROUTE),
    ])
    .waiting(
        "nothing in the catalog reads polar-git's events yet: the git processor is to put them in the graph \
         (docs/architecture/polar-git.md)",
    )];
    const SECTIONS: &'static [&'static Section] = &[&crate::settings::SECTION];
    const HELP: Option<&'static str> = Some(
        "polar-git hosts people's repositories over git smart HTTP. Every connection presents a Polar certificate, \
         and each git operation (read, push, force push, delete a branch, tag, make a repository) is asked of Cedar \
         policy as an action on the repository, its owner the one who made it; where policy is silent nothing is \
         allowed. A push to a repository that is not there makes it, when its pusher may. Everything it does, \
         refusals included, is published on polar-git-events. People reach it through git-remote-polar.",
    );

    async fn start(configured: Configured) -> Result<(), StartError> {
        configured.init_logging(SERVICE_NAME);
        let (_supervisor, handle) = Actor::spawn(
            Some(format!("{SERVICE_NAME}.supervisor")),
            PolarGitSupervisor,
            configured,
        )
        .await
        .map_err(|e| format!("the polar-git supervisor did not start: {e}"))?;
        handle
            .await
            .map_err(|e| format!("the polar-git supervisor task failed: {e}"))?;
        Err("the polar-git supervisor stopped".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    polar_agent_builder::polar_agent_tests!(PolarGit);
}
