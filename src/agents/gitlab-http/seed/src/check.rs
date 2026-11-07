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

//! What the GitLab pair's graph holds, held to what the seed said it should ([`crate::expected`]): asked of Neo4j's HTTP endpoint, by the
//! same names, each node and edge expected either there or missing. What the graph holds besides (GitLab's own root, a job a pipeline
//! run again made) is said, and is no failure: the expectation is what is there at least.

use crate::expected::{Edge, Expected};
use anyhow::{Context, Result, anyhow};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use url::Url;

/// The graph's GitLab nodes, by label and name, and its edges between them, named as the expectation names them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Graph {
    pub nodes: BTreeSet<(String, String)>,
    pub edges: BTreeSet<Edge>,
}

/// The Cypher that reads them: a row of two is a node (label, name), a row of three an edge (type, from, to).
pub fn statements() -> Vec<&'static str> {
    vec![
        "MATCH (n:GitlabUser) RETURN 'GitlabUser', n.username",
        "MATCH (n:GitlabGroup) RETURN 'GitlabGroup', n.full_path",
        "MATCH (n:GitlabProject) RETURN 'GitlabProject', n.full_path",
        "MATCH (n:GitlabRunner) RETURN 'GitlabRunner', n.description",
        "MATCH (n:GitlabInstance) RETURN 'GitlabInstance', n.origin",
        "MATCH (p:GitlabProject)-[:HAS_PIPELINE]->(n:GitlabPipeline) RETURN 'GitlabPipeline', p.full_path + '@' + n.ref",
        "MATCH (p:GitlabProject)-[:HAS_PIPELINE]->(:GitlabPipeline)-[:HAS_JOB]->(j:GitlabJob) RETURN 'GitlabJob', p.full_path + '/' + j.name",
        "MATCH (n:GitlabContainerRepository) RETURN 'GitlabContainerRepository', n.path",
        "MATCH (n:GitlabPackage) RETURN 'GitlabPackage', n.name + '@' + n.version",
        "MATCH (a:GitlabGroup)-[:SUBGROUP_OF]->(b:GitlabGroup) RETURN 'SUBGROUP_OF', a.full_path, b.full_path",
        "MATCH (a:GitlabGroup)-[:HAS_MEMBER]->(b:GitlabUser) RETURN 'HAS_MEMBER', a.full_path, b.username",
        "MATCH (a:GitlabProject)-[:HAS_PIPELINE]->(b:GitlabPipeline) RETURN 'HAS_PIPELINE', a.full_path, a.full_path + '@' + b.ref",
        "MATCH (p:GitlabProject)-[:HAS_PIPELINE]->(a:GitlabPipeline)-[:HAS_JOB]->(b:GitlabJob) RETURN 'HAS_JOB', p.full_path + '@' + a.ref, p.full_path + '/' + b.name",
        "MATCH (p:GitlabProject)-[:HAS_PIPELINE]->(:GitlabPipeline)-[:HAS_JOB]->(a:GitlabJob)-[:EXECUTED_BY]->(b:GitlabRunner) RETURN 'EXECUTED_BY', p.full_path + '/' + a.name, b.description",
        "MATCH (a:GitlabProject)-[:HAS_CONTAINER_REPOSITORY]->(b:GitlabContainerRepository) RETURN 'HAS_CONTAINER_REPOSITORY', a.full_path, b.path",
        "MATCH (a:GitlabProject)-[:HAS_PACKAGE]->(b:GitlabPackage) RETURN 'HAS_PACKAGE', a.full_path, b.name + '@' + b.version",
    ]
}

/// The graph from Neo4j's answer to [`statements`]; a row with a null (a node with no such property) names nothing.
pub fn graph_from(answer: &Value) -> Result<Graph> {
    if let Some(error) = answer["errors"].as_array().and_then(|e| e.first()) {
        return Err(anyhow!(
            "Neo4j refused: {} {}",
            error["code"].as_str().unwrap_or(""),
            error["message"].as_str().unwrap_or("")
        ));
    }
    let mut graph = Graph::default();
    for result in answer["results"].as_array().into_iter().flatten() {
        for row in result["data"].as_array().into_iter().flatten() {
            let cells: Option<Vec<String>> = row["row"]
                .as_array()
                .and_then(|r| r.iter().map(|c| c.as_str().map(String::from)).collect());
            match cells.as_deref() {
                Some([label, name]) => {
                    graph.nodes.insert((label.clone(), name.clone()));
                }
                Some([kind, from, to]) => {
                    graph.edges.insert(Edge {
                        kind: kind.clone(),
                        from: from.clone(),
                        to: to.clone(),
                    });
                }
                _ => {}
            }
        }
    }
    Ok(graph)
}

/// What a check found: what was expected and is missing, and what is there besides.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    pub missing_nodes: Vec<(String, String)>,
    pub missing_edges: Vec<Edge>,
    pub beyond: Vec<(String, String)>,
}

impl Report {
    pub fn passed(&self) -> bool {
        self.missing_nodes.is_empty() && self.missing_edges.is_empty()
    }
}

pub fn compare(expected: &Expected, graph: &Graph) -> Report {
    let wanted: BTreeSet<(String, String)> = expected
        .nodes
        .iter()
        .flat_map(|(l, ns)| ns.iter().map(move |n| (l.clone(), n.clone())))
        .collect();
    Report {
        missing_nodes: wanted.difference(&graph.nodes).cloned().collect(),
        missing_edges: expected.edges.difference(&graph.edges).cloned().collect(),
        beyond: graph.nodes.difference(&wanted).cloned().collect(),
    }
}

/// Neo4j's HTTP endpoint, as `neo4j` with its password, presenting a client certificate when it asks for one (Polar's does).
pub struct Neo4j {
    http: reqwest::Client,
    base: Url,
    password: String,
}

impl Neo4j {
    /// `base` is Neo4j's own address (its certificate is checked against the name); `connect`, where to reach it; `ca`, the CA
    /// its certificate chains to; `identity`, a PEM of a client certificate and its key.
    pub fn new(
        base: Url,
        password: String,
        ca: Option<&[u8]>,
        identity: Option<&[u8]>,
        connect: Option<SocketAddr>,
    ) -> Result<Self> {
        // rustls, which a PEM identity is made for, whatever else the workspace's reqwest is built with.
        let mut builder = reqwest::Client::builder().use_rustls_tls();
        if let Some(pem) = ca {
            builder = builder.tls_built_in_root_certs(false).add_root_certificate(
                reqwest::Certificate::from_pem(pem).context("the CA is not a PEM certificate")?,
            );
        }
        if let Some(pem) = identity {
            builder = builder.identity(
                reqwest::Identity::from_pem(pem)
                    .context("the client certificate and key are not PEM")?,
            );
        }
        let mut base = base;
        if let Some(addr) = connect {
            let host = base
                .host_str()
                .ok_or_else(|| anyhow!("{base} has no host"))?
                .to_string();
            base.set_port(Some(addr.port()))
                .map_err(|_| anyhow!("{base} cannot take a port"))?;
            builder = builder.resolve(&host, addr);
        }
        Ok(Neo4j {
            http: builder.build()?,
            base,
            password,
        })
    }

    pub async fn graph(&self) -> Result<Graph> {
        let body = json!({ "statements": statements().iter().map(|s| json!({ "statement": s })).collect::<Vec<_>>() });
        let response = self
            .http
            .post(self.base.join("/db/neo4j/tx/commit")?)
            .basic_auth("neo4j", Some(&self.password))
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow!("asking Neo4j: {}", e.without_url()))?;
        if !response.status().is_success() {
            return Err(anyhow!("asking Neo4j: {}", response.status()));
        }
        graph_from(
            &response
                .json()
                .await
                .context("Neo4j's answer is not JSON")?,
        )
    }
}
