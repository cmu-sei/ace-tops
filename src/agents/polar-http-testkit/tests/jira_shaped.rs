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

//! A Jira-shaped kind, for tests only (docs/architecture/http-observers.md, "Evidence", bite 7; the maintainer: "a test kind
//! only"). Jira's projects, groups and group members come as pages of one envelope; this pair reads them through the kit
//! as any kind is read, and then as a deployment would: page by page, over TLS, with a token bound to the host. The
//! `jira-observer` is not this, and stays as it is.

use polar_agent_builder::protocol::credentials::section;
use polar_agent_builder::protocol::{Credential, Location, OperationDecl, ProtocolKind};
use polar_agent_builder::runtime::SectionAuthority;
use polar_agent_builder::{
    Capability, Cause, Configured, EdgeDecl, GraphDecl, PolarAgent, Role, RuntimeSection,
    StartError, TopicDecl,
};
use polar_http_observer::paging::{Paging, Style};
use polar_http_observer::{CREDENTIALED_SOURCES, Kind as ObserverKind};
use polar_http_processor::{Kind as ProcessorKind, SECTION_BODY, SECTION_NAME, judge, node_shapes};
use polar_http_testkit::{Pair, block_on, signed_in_force};
use polar_projection::{Bounds, Write};
use serde_json::Value;
use std::time::Duration;

const OBSERVER: &str = "jira-shaped-observer";
const PROCESSOR: &str = "jira-shaped-processor";
const TOPIC: &str = "polar.jira-shaped.observations";
const TOKEN: &str = "a-personal-access-token-found-nowhere-else";

const READ: OperationDecl = OperationDecl {
    name: "jira-shaped.page.read",
    doc: "reads a page its signed sources give, with no credential",
    protocol: ProtocolKind::HTTP,
    location: Location::Arbitrary,
};

const READ_WITH: OperationDecl = OperationDecl {
    name: "jira-shaped.page.read-with-credential",
    doc: "reads a page its signed sources give, with the credential the source names, bound to its host",
    protocol: ProtocolKind::HTTP,
    location: Location::Bound {
        credential: Credential::Chosen,
    },
};

static CREDENTIALS: RuntimeSection = section::<8>(
    "The tokens a Jira-shaped source is read with, each bound to the hosts it may go to.",
);

struct JiraShapedObserver;

impl ObserverKind for JiraShapedObserver {
    const NAME: &'static str = OBSERVER;
    const TOPIC: &'static str = TOPIC;
    const OPERATION: OperationDecl = READ;
    const CREDENTIALED: Option<OperationDecl> = Some(READ_WITH);
}

impl PolarAgent for JiraShapedObserver {
    const NAME: &'static str = OBSERVER;
    const ROLE: Role = Role::Observer;
    const PURPOSE: &'static str = "Reads Jira-shaped pages for the kit's tests";
    const NEEDS: &'static [Capability] = &[];
    const SHUTDOWN_BUDGET: Duration = polar_http_observer::observer::SHUTDOWN_BUDGET;
    const TOPICS: &'static [TopicDecl] =
        &[
            TopicDecl::publish(TOPIC, "each page as it came, for the processor")
                .because(&[Cause::Timer("read")]),
        ];
    const RUNTIME: &'static [&'static RuntimeSection] = &[&CREDENTIALED_SOURCES];
    const CREDENTIALS: Option<&'static RuntimeSection> = Some(&CREDENTIALS);
    const OPERATIONS: &'static [OperationDecl] = &[READ, READ_WITH];

    async fn start(configured: Configured) -> Result<(), StartError> {
        polar_http_observer::start::<JiraShapedObserver>(configured).await
    }
}

polar_http_processor::schema! {
    labels {
        JiraTestProject [id] "each project",
        JiraTestGroup [group_id] "each group",
        JiraTestUser [account_id] "each user: a project's lead or a group's member",
    }
    edges {
        JiraTestProject LED_BY JiraTestUser "a project's lead",
    }
}

fn validate(body: &Value) -> Result<(), Vec<String>> {
    judge(body, SCHEMA)
}

static PROJECTION: RuntimeSection = RuntimeSection {
    authority: SectionAuthority::Runtime,
    name: SECTION_NAME,
    doc: "How a Jira-shaped page becomes nodes and edges.",
    body: SECTION_BODY,
    validate,
};

fn shapes() -> Vec<polar::graph::controller::NodeShape> {
    node_shapes(SCHEMA)
}

struct JiraShapedProcessor;

impl ProcessorKind for JiraShapedProcessor {
    const NAME: &'static str = PROCESSOR;
    const OBSERVER: &'static str = OBSERVER;
    const TOPIC: &'static str = TOPIC;
    const BOUNDS: Bounds<'static> = SCHEMA;
}

impl PolarAgent for JiraShapedProcessor {
    const NAME: &'static str = PROCESSOR;
    const ROLE: Role = Role::Processor;
    const PURPOSE: &'static str = "Writes Jira-shaped pages into the graph for the kit's tests";
    const NEEDS: &'static [Capability] = &[Capability::GraphWrite];
    const SHUTDOWN_BUDGET: Duration = polar_http_processor::SHUTDOWN_BUDGET;
    const TOPICS: &'static [TopicDecl] = &[TopicDecl::subscribe(
        TOPIC,
        "the pages the observer read, written to the graph",
    )];
    const RUNTIME: &'static [&'static RuntimeSection] = &[&PROJECTION];
    const GRAPH: &'static [GraphDecl] = LABELS;
    const GRAPH_KEYS: &'static [fn() -> Vec<polar::graph::controller::NodeShape>] = &[shapes];
    const GRAPH_EDGES: &'static [EdgeDecl] = EDGES;

    async fn start(configured: Configured) -> Result<(), StartError> {
        polar_http_processor::start::<JiraShapedProcessor>(configured).await
    }
}

mod observer_declares {
    polar_agent_builder::polar_agent_tests!(super::JiraShapedObserver);
}

mod processor_declares {
    polar_agent_builder::polar_agent_tests!(super::JiraShapedProcessor);
}

polar_http_testkit::polar_http_tests! {
    observer: JiraShapedObserver,
    processor: JiraShapedProcessor,
    mapping: "tests/jira-shaped/mapping.dhall",
    samples: "tests/jira-shaped/samples",
}

fn labels(observed: &[polar_http_testkit::Observed]) -> Vec<String> {
    let mut labels: Vec<String> = observed
        .iter()
        .flat_map(|o| &o.writes)
        .map(|w| match w {
            Write::Node { id, .. } => id.label.clone(),
            Write::Edge { kind, .. } => kind.clone(),
        })
        .collect();
    labels.sort();
    labels
}

/// Projects as Jira's search pages them: each page names the next at `nextPage`, every page goes over TLS with the token
/// the source names, and each is published and written as it is read.
#[test]
fn projects_are_read_page_by_page_by_cursor_with_their_token_and_each_page_is_written() {
    block_on(async {
        let kit = kit();
        let mapping = signed_in_force::<JiraShapedProcessor>(&kit).await;
        let mut pair =
            Pair::<JiraShapedObserver>::credentialed(PROCESSOR, mapping, "jira", TOKEN).await;
        let paging = Paging {
            style: Style::Cursor {
                next: "/nextPage".to_string(),
            },
            max_pages: 10,
        };
        let observed = pair
            .read_paged(
                "projects",
                paging,
                &kit.documents(&["projects-1", "projects-2"]),
            )
            .await;
        assert_eq!(observed.len(), 2, "one observation a page");
        assert_eq!(
            labels(&observed),
            [
                "JiraTestProject",
                "JiraTestProject",
                "JiraTestProject",
                "JiraTestUser",
                "JiraTestUser",
                "LED_BY",
                "LED_BY"
            ]
        );
        assert_eq!(
            pair.authorizations().await,
            vec![Some(format!("Bearer {TOKEN}")); 2],
            "every page with the token"
        );
    });
}

/// Group members as Jira pages them by `startAt`: each page asks from the members read so far, an empty page is the last,
/// and a member Jira does not identify is skipped, which is what skipped means.
#[test]
fn members_are_read_by_offset_until_an_empty_page_and_one_not_identified_is_skipped() {
    block_on(async {
        let kit = kit();
        let mapping = signed_in_force::<JiraShapedProcessor>(&kit).await;
        let mut pair =
            Pair::<JiraShapedObserver>::credentialed(PROCESSOR, mapping, "jira", TOKEN).await;
        let paging = Paging {
            style: Style::Offset {
                param: "startAt".to_string(),
                items: "/values".to_string(),
            },
            max_pages: 10,
        };
        let observed = pair
            .read_paged(
                "members-of-developers",
                paging,
                &kit.documents(&["members-1", "members-2", "members-end"]),
            )
            .await;
        assert_eq!(observed.len(), 3);
        assert_eq!(labels(&observed), ["JiraTestUser", "JiraTestUser"]);
        let skipped: Vec<usize> = observed.iter().map(|o| o.skipped).collect();
        assert_eq!(skipped, [0, 1, 0]);
        assert_eq!(pair.authorizations().await.len(), 3);
    });
}
