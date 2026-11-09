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

//! What the builder does with an agent's graph controller, against a real Neo4j (one container for this test binary,
//! `polar-test-graph`).

use polar::graph::controller::{
    DynamicNodeKey, GraphControllerActor, GraphControllerArgs, GraphControllerMsg, GraphOp,
    Property,
};
use polar::graph::environment::{GraphSettings, GraphTls};
use polar_agent_builder::stop_graph_controller;
use polar_test_graph::{clear_graph, dump, neo4j};
use ractor::concurrency::Duration;

const LABEL: &str = "DrainProbe";
const QUEUED: usize = 200;

/// Every write queued when the controller is asked to stop is written before it stops: a stop that came ahead of the
/// queue would lose what the agent had already handed over.
#[tokio::test]
async fn stopping_the_controller_writes_everything_queued_first() {
    let graph = neo4j();
    let _runtime = polar_test_graph::enter();
    clear_graph(graph).await;
    let c = polar_test_graph::connection();
    let settings = GraphSettings {
        database: "neo4j".to_string(),
        user: c.user,
        password: c.password,
        endpoint: c.bolt,
        tls: GraphTls::None,
    };
    let (controller, handle) = ractor::Actor::spawn(
        None,
        GraphControllerActor,
        GraphControllerArgs::new(std::sync::Arc::new(ractor::OutputPort::default()))
            .with_settings(settings),
    )
    .await
    .unwrap();

    for i in 0..QUEUED {
        let key = DynamicNodeKey::new(LABEL, "id", i.to_string()).unwrap();
        controller
            .cast(GraphControllerMsg::Op(GraphOp::UpsertNode {
                key: Box::new(key),
                props: Vec::<Property>::new(),
            }))
            .unwrap();
    }
    stop_graph_controller(controller, Duration::from_secs(60)).await;
    handle.await.unwrap();

    let written = dump(graph)
        .await
        .into_iter()
        .filter(|line| line.contains(LABEL))
        .count();
    assert_eq!(written, QUEUED, "every queued write is in the graph");
}
