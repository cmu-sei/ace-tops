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

//! `gitlab-seed`: makes the test GitLab's known dataset, what is missing of it, and prints what the GitLab pair's graph should then hold
//! (docs/architecture/http-observers.md, G4b1). Root's token on stdin. The configuration under test's `ready` script runs it through a
//! port-forward (infra/under-test/gitlab/ready.nu).
//!
//!   gitlab-seed --url https://gitlab.gitlab-test.svc.cluster.local --connect 127.0.0.1:<port> --ca <cluster CA> < token

#[global_allocator]
static GLOBAL: polar_scudo::Scudo = polar_scudo::Scudo;

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use gitlab_seed::dataset::{Size, dataset};
use gitlab_seed::expected::expected;
use gitlab_seed::gitlab::{Gitlab, finished};
use std::collections::BTreeMap;
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use url::Url;

/// How many times a failed pipeline is run again.
const RETRIES: usize = 2;

#[derive(Parser)]
#[command(
    about = "Make the test GitLab's known dataset, and print what the GitLab pair's graph should then hold"
)]
struct Args {
    /// GitLab's own address, the origin its nodes are keyed by.
    #[arg(long)]
    url: Url,
    /// Where to reach it (a port-forward); the name in --url is still the one its certificate is checked against.
    #[arg(long)]
    connect: Option<SocketAddr>,
    /// The CA its certificate chains to (the cluster's), in place of the system's roots.
    #[arg(long)]
    ca: Option<PathBuf>,
    /// The runner's description, which its jobs are executed by.
    #[arg(long, default_value = "polar-test")]
    runner: String,
    /// How long the CI may take to finish.
    #[arg(long, default_value_t = 900)]
    wait_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mut token = String::new();
    std::io::stdin()
        .read_to_string(&mut token)
        .context("reading the token from stdin")?;
    let token = token.trim().to_string();
    if token.is_empty() {
        bail!("no token on stdin");
    }
    let ca = args
        .ca
        .as_ref()
        .map(std::fs::read)
        .transpose()
        .context("reading the CA")?;
    let gitlab = Gitlab::new(args.url.clone(), token, ca.as_deref(), args.connect)?;
    let d = dataset(&Size::default());

    let mut users = BTreeMap::new();
    for u in &d.users {
        users.insert(u.username.clone(), gitlab.ensure_user(u).await?);
    }
    let mut groups = BTreeMap::new();
    for g in &d.groups {
        let parent = g.parent.as_ref().map(|p| groups[p]);
        groups.insert(g.full_path.clone(), gitlab.ensure_group(g, parent).await?);
    }
    for m in &d.memberships {
        gitlab
            .ensure_member(groups[&m.group], users[&m.username], m.access_level)
            .await?;
    }
    let mut with_ci = Vec::new();
    for p in &d.projects {
        let id = gitlab.ensure_project(p, groups[&p.namespace]).await?;
        if let Some(ci) = &p.ci {
            gitlab
                .ensure_file(id, ".gitlab-ci.yml", &ci.file(), "The seed's CI")
                .await?;
            with_ci.push((p.full_path.clone(), id));
        }
    }
    eprintln!(
        "made what was missing: {} users, {} groups, {} projects",
        d.users.len(),
        d.groups.len(),
        d.projects.len()
    );

    // Each CI's pipeline on main, to its end: the runner has run its jobs. One that failed (a job's pod that could not start, a
    // run cut short) is run again, twice at most, so a seed run again repairs what an earlier one left.
    let deadline = Instant::now() + Duration::from_secs(args.wait_secs);
    for (path, id) in &with_ci {
        let mut retried = 0;
        loop {
            let latest = gitlab.pipelines(*id).await?.into_iter().next();
            match latest {
                Some(p) if p.status == "success" => break,
                Some(p) if p.status == "failed" && retried < RETRIES => {
                    eprintln!("{path}: its pipeline {} failed: running it again", p.id);
                    gitlab.retry_pipeline(*id, p.id).await?;
                    retried += 1;
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                Some(p) if finished(&p.status) => {
                    bail!("{path}: its pipeline {} ended {}", p.id, p.status)
                }
                _ if Instant::now() > deadline => {
                    return Err(anyhow!(
                        "{path}: its pipeline did not finish in {}s",
                        args.wait_secs
                    ));
                }
                _ => tokio::time::sleep(Duration::from_secs(5)).await,
            }
        }
    }
    eprintln!("the runner ran every pipeline: {}", with_ci.len());

    let origin = args.url.origin().ascii_serialization();
    println!(
        "{}",
        serde_json::to_string_pretty(&expected(&d, &origin, &args.runner))?
    );
    Ok(())
}
