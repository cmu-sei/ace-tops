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

//! What the GitLab pair's graph should hold once it has read the dataset (docs/architecture/http-observers.md, G3's labels and edges), by
//! the names people use: a user by username, a group or project by full path, the runner by its description, a project's pipeline as
//! `<project>@main`, a job as `<project>/<job>`, a registry's repository by its project's path, a package as `<name>@<version>`. GitLab's own ids are not known before it makes things, and are not what anyone checks
//! by. It says what is there at least: GitLab has users of its own (root, its bots), and a re-run makes nothing new.

use crate::dataset::Dataset;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// An edge as the G3 mapping draws it: from the parent rule's node to the child's.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Edge {
    #[serde(rename = "type")]
    pub kind: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Expected {
    pub origin: String,
    /// By label, the names of the nodes it should hold.
    pub nodes: BTreeMap<String, BTreeSet<String>>,
    pub edges: BTreeSet<Edge>,
}

/// The pipeline the seed's CI runs for `project`, on `main`.
pub fn pipeline_of(project: &str) -> String {
    format!("{project}@main")
}

pub fn expected(d: &Dataset, origin: &str, runner: &str) -> Expected {
    let mut nodes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut add = |label: &str, name: String| {
        nodes.entry(label.to_string()).or_default().insert(name);
    };
    add("GitlabInstance", origin.to_string());
    add("GitlabRunner", runner.to_string());
    let mut edges = BTreeSet::new();
    let mut edge = |kind: &str, from: &str, to: &str| {
        edges.insert(Edge {
            kind: kind.into(),
            from: from.into(),
            to: to.into(),
        });
    };
    for u in &d.users {
        add("GitlabUser", u.username.clone());
    }
    for g in &d.groups {
        add("GitlabGroup", g.full_path.clone());
        if let Some(parent) = &g.parent {
            edge("SUBGROUP_OF", &g.full_path, parent);
        }
    }
    for m in &d.memberships {
        edge("HAS_MEMBER", &m.group, &m.username);
    }
    for p in &d.projects {
        add("GitlabProject", p.full_path.clone());
        let Some(ci) = &p.ci else { continue };
        let pipeline = pipeline_of(&p.full_path);
        add("GitlabPipeline", pipeline.clone());
        edge("HAS_PIPELINE", &p.full_path, &pipeline);
        for job in &ci.jobs {
            let name = format!("{}/{job}", p.full_path);
            add("GitlabJob", name.clone());
            edge("HAS_JOB", &pipeline, &name);
            edge("EXECUTED_BY", &name, runner);
        }
    }
    add("GitlabProject", d.mirror.full_path.clone());
    // A project's registry's repository is named by the project's path; a package by its name and version.
    add("GitlabContainerRepository", d.image.project.clone());
    edge(
        "HAS_CONTAINER_REPOSITORY",
        &d.image.project,
        &d.image.project,
    );
    let package = format!("{}@{}", d.package.name, d.package.version);
    add("GitlabPackage", package.clone());
    edge("HAS_PACKAGE", &d.package.project, &package);
    Expected {
        origin: origin.to_string(),
        nodes,
        edges,
    }
}
