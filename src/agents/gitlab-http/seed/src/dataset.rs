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

//! The known dataset: users, groups nested three deep, each user a member of one, projects across the groups, some with CI the runner
//! runs. Pure: the same size gives the same dataset, by the same names, every time.

/// How much to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Size {
    pub users: usize,
    pub projects: usize,
    /// The first projects with CI, at most `projects`.
    pub ci_projects: usize,
}

impl Default for Size {
    /// The planned dataset: a dozen users, thirty projects (three pages of ten), six with CI.
    fn default() -> Self {
        Size {
            users: 12,
            projects: 30,
            ci_projects: 6,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub username: String,
    pub name: String,
    pub email: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub path: String,
    pub full_path: String,
    /// Its parent's full path; a parent comes before its subgroups.
    pub parent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    /// The group's full path.
    pub group: String,
    pub username: String,
    /// GitLab's access level: 20 reporter, 30 developer, 40 maintainer.
    pub access_level: u8,
}

/// A project's CI: its jobs, run in that order by the runner, and whether the first keeps an artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ci {
    pub jobs: Vec<String>,
    pub artifact: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub path: String,
    /// Its group's full path.
    pub namespace: String,
    pub full_path: String,
    pub ci: Option<Ci>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dataset {
    pub users: Vec<User>,
    pub groups: Vec<Group>,
    pub memberships: Vec<Membership>,
    pub projects: Vec<Project>,
}

/// The group every other is in, and its nesting.
pub const TOP: &str = "polar-seed";
const NESTED: [&str; 2] = ["platform", "agents"];
const LEVELS: [u8; 3] = [30, 40, 20];
/// The CI's jobs: one stage each, in order.
const JOBS: [&str; 2] = ["build", "test"];

pub fn dataset(size: &Size) -> Dataset {
    let mut groups = vec![Group {
        path: TOP.into(),
        full_path: TOP.into(),
        parent: None,
    }];
    for path in NESTED {
        let parent = groups
            .last()
            .map(|g| g.full_path.clone())
            .unwrap_or_default();
        groups.push(Group {
            path: path.into(),
            full_path: format!("{parent}/{path}"),
            parent: Some(parent),
        });
    }
    let users: Vec<User> = (1..=size.users)
        .map(|i| User {
            username: format!("seed-user-{i:02}"),
            name: format!("Seed User {i:02}"),
            email: format!("seed-user-{i:02}@seed.example"),
        })
        .collect();
    let memberships = users
        .iter()
        .enumerate()
        .map(|(i, u)| Membership {
            group: groups[i % groups.len()].full_path.clone(),
            username: u.username.clone(),
            access_level: LEVELS[i % LEVELS.len()],
        })
        .collect();
    let projects = (1..=size.projects)
        .map(|i| {
            let namespace = groups[(i - 1) % groups.len()].full_path.clone();
            let path = format!("project-{i:02}");
            Project {
                full_path: format!("{namespace}/{path}"),
                path,
                namespace,
                ci: (i <= size.ci_projects).then(|| Ci {
                    jobs: JOBS.iter().map(|j| j.to_string()).collect(),
                    artifact: i == 1,
                }),
            }
        })
        .collect();
    Dataset {
        users,
        groups,
        memberships,
        projects,
    }
}

impl Ci {
    /// The `.gitlab-ci.yml` the runner reads: a stage per job, each a line of shell, the first keeping a small artifact if asked.
    pub fn file(&self) -> String {
        let mut out = format!("stages: [{}]\n", self.jobs.join(", "));
        for (i, job) in self.jobs.iter().enumerate() {
            out.push_str(&format!("\n{job}:\n  stage: {job}\n  script:\n    - echo \"{job} for the seed\" > {job}.txt\n"));
            if i == 0 && self.artifact {
                out.push_str(&format!(
                    "  artifacts:\n    paths: [{job}.txt]\n    expire_in: never\n"
                ));
            }
        }
        out
    }
}
