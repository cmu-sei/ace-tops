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

//! What the OpenAPI observer is, as the infrastructure asks to be told: see `polar_agent_builder::PolarAgent`.

use openapi_common::{OBSERVATIONS_TOPIC, OBSERVER_NAME};
use polar_agent_builder::protocol::{Location, OperationDecl, ProtocolKind};
use polar_agent_builder::{
    Capability, Cause, Configured, PolarAgent, Role, RuntimeSection, StartError, TopicDecl,
};
use polar_http_observer::{Kind, SOURCES};
use std::time::Duration;

/// Reads a document at an address its signed `sources` give, with no credential.
pub const READ: OperationDecl = OperationDecl {
    name: "openapi.document.read",
    doc: "reads an OpenAPI or Swagger document at an address its signed sources give, with no credential",
    protocol: ProtocolKind::HTTP,
    location: Location::Arbitrary,
};

pub struct OpenApiObserver;

impl Kind for OpenApiObserver {
    const NAME: &'static str = OBSERVER_NAME;
    const TOPIC: &'static str = OBSERVATIONS_TOPIC;
    const OPERATION: OperationDecl = READ;
}

impl PolarAgent for OpenApiObserver {
    const NAME: &'static str = OBSERVER_NAME;
    const ROLE: Role = Role::Observer;
    const PURPOSE: &'static str = "Reads the OpenAPI and Swagger documents its signed sources name and publishes them for the processor";
    const NEEDS: &'static [Capability] = &[];
    const SHUTDOWN_BUDGET: Duration = polar_http_observer::observer::SHUTDOWN_BUDGET;
    const TOPICS: &'static [TopicDecl] = &[TopicDecl::publish(
        OBSERVATIONS_TOPIC,
        "each document as it came, for the processor",
    )
    .because(&[Cause::Timer("read")])];
    const RUNTIME: &'static [&'static RuntimeSection] = &[&SOURCES];
    const OPERATIONS: &'static [OperationDecl] = &[READ];
    const HELP: Option<&'static str> = Some(
        "The observer reads each source its signed `sources` section names, on that source's interval, and publishes what it \
         read as it came. It parses nothing and never touches the graph. With no section signed it reads nothing. The egress \
         section says how a source is reached.",
    );

    async fn start(configured: Configured) -> Result<(), StartError> {
        polar_http_observer::start::<OpenApiObserver>(configured).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    polar_agent_builder::polar_agent_tests!(OpenApiObserver);

    #[test]
    fn it_publishes_only_its_one_topic_and_its_one_operation_can_carry_no_credential() {
        assert_eq!(<OpenApiObserver as PolarAgent>::TOPICS.len(), 1);
        assert_eq!(READ.location, Location::Arbitrary);
    }
}
