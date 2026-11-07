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

//! The dataset and what it should become hold to their rules for any size.

use gitlab_seed::dataset::{Size, dataset};
use gitlab_seed::expected::expected;
use proptest::prelude::*;

const ORIGIN: &str = "https://gitlab.gitlab-test.svc.cluster.local";

fn size() -> impl Strategy<Value = Size> {
    (1usize..20, 1usize..40, 0usize..8).prop_map(|(users, projects, ci)| Size {
        users,
        projects,
        ci_projects: ci.min(projects),
    })
}

proptest! {
    /// The same size gives the same dataset, and what it should become, every time.
    #[test]
    fn the_dataset_and_its_expectation_are_deterministic(size in size()) {
        prop_assert_eq!(dataset(&size), dataset(&size));
        prop_assert_eq!(expected(&dataset(&size), ORIGIN, "polar-test"), expected(&dataset(&size), ORIGIN, "polar-test"));
    }

    /// It is the size asked: so many users, each a member of one group, so many projects, so many with CI.
    #[test]
    fn the_dataset_is_the_size_asked(size in size()) {
        let d = dataset(&size);
        prop_assert_eq!(d.users.len(), size.users);
        prop_assert_eq!(d.projects.len(), size.projects);
        // The image and the package are in projects it makes, and the mirror is a project of its own, in a group it makes.
        prop_assert!(d.projects.iter().any(|p| p.full_path == d.image.project));
        prop_assert!(d.projects.iter().any(|p| p.full_path == d.package.project));
        prop_assert!(!d.projects.iter().any(|p| p.full_path == d.mirror.full_path));
        prop_assert!(!d.mirror.readme && d.mirror.ci.is_none());
        prop_assert_eq!(d.projects.iter().filter(|p| p.ci.is_some()).count(), size.ci_projects);
        prop_assert_eq!(d.memberships.len(), size.users);
        for u in &d.users {
            prop_assert_eq!(d.memberships.iter().filter(|m| m.username == u.username).count(), 1);
        }
        // Every project and membership is in a group the dataset makes, and every group's parent is one it makes first.
        let paths: Vec<&str> = d.groups.iter().map(|g| g.full_path.as_str()).collect();
        for p in &d.projects { prop_assert!(paths.contains(&p.namespace.as_str())); }
        for m in &d.memberships { prop_assert!(paths.contains(&m.group.as_str())); }
        for (i, g) in d.groups.iter().enumerate() {
            if let Some(parent) = &g.parent { prop_assert!(paths[..i].contains(&parent.as_str())); }
        }
    }

    /// Every edge it expects joins two nodes it expects, of the labels the mapping draws that edge between.
    #[test]
    fn every_expected_edge_joins_expected_nodes(size in size()) {
        let e = expected(&dataset(&size), ORIGIN, "polar-test");
        for edge in &e.edges {
            let (from, to) = match edge.kind.as_str() {
                "SUBGROUP_OF" => ("GitlabGroup", "GitlabGroup"),
                "HAS_MEMBER" => ("GitlabGroup", "GitlabUser"),
                "HAS_PIPELINE" => ("GitlabProject", "GitlabPipeline"),
                "HAS_JOB" => ("GitlabPipeline", "GitlabJob"),
                "EXECUTED_BY" => ("GitlabJob", "GitlabRunner"),
                "HAS_CONTAINER_REPOSITORY" => ("GitlabProject", "GitlabContainerRepository"),
                "HAS_PACKAGE" => ("GitlabProject", "GitlabPackage"),
                other => { prop_assert!(false, "an edge the mapping does not draw: {}", other); unreachable!() }
            };
            prop_assert!(e.nodes[from].contains(&edge.from), "{:?}", edge);
            prop_assert!(e.nodes[to].contains(&edge.to), "{:?}", edge);
        }
        prop_assert!(e.nodes["GitlabInstance"].contains(ORIGIN));
        prop_assert_eq!(e.edges.iter().filter(|x| x.kind == "HAS_MEMBER").count(), size.users);
        let jobs: usize = dataset(&size).projects.iter().filter_map(|p| p.ci.as_ref()).map(|c| c.jobs.len()).sum();
        prop_assert_eq!(e.edges.iter().filter(|x| x.kind == "EXECUTED_BY").count(), jobs);
    }
}

#[test]
fn the_default_dataset_is_the_one_planned() {
    let d = dataset(&Size::default());
    assert_eq!(
        (d.users.len(), d.groups.len(), d.projects.len()),
        (12, 3, 30)
    );
    assert_eq!(d.mirror.full_path, "polar-seed/polar");
    assert_eq!(d.image.tags, ["1.0", "latest"]);
    assert_eq!(
        (
            d.package.name.as_str(),
            d.package.version.as_str(),
            d.package.files.len()
        ),
        ("seed-tools", "1.0.0", 2)
    );
    let e = gitlab_seed::expected::expected(&d, "https://gitlab.example", "polar-test");
    assert_eq!(e.nodes["GitlabProject"].len(), 31, "thirty and the mirror");
    assert!(e.nodes["GitlabContainerRepository"].contains(&d.image.project));
    assert!(e.nodes["GitlabPackage"].contains("seed-tools@1.0.0"));
    assert_eq!(d.projects.iter().filter(|p| p.ci.is_some()).count(), 6);
    assert_eq!(
        d.groups
            .iter()
            .map(|g| g.full_path.as_str())
            .collect::<Vec<_>>(),
        [
            "polar-seed",
            "polar-seed/platform",
            "polar-seed/platform/agents"
        ]
    );
    // One CI keeps an artifact, and the file the runner reads says so.
    let with_artifact: Vec<_> = d
        .projects
        .iter()
        .filter_map(|p| p.ci.as_ref())
        .filter(|c| c.artifact)
        .collect();
    assert_eq!(with_artifact.len(), 1);
    assert!(with_artifact[0].file().contains("artifacts:"));
}
