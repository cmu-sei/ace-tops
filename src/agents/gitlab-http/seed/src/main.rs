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
//! (docs/architecture/http-observers.md, G4b1); and holds the graph to that (G4d). Root's token, or Neo4j's password, on stdin. The
//! configuration under test's `ready` script runs `make` through a port-forward (infra/under-test/gitlab/ready.nu), and its `check.nu`
//! runs `check`.
//!
//!   gitlab-seed make --url https://gitlab.gitlab-test.svc.cluster.local --connect 127.0.0.1:<port> --ca <cluster CA> ... < token
//!   gitlab-seed check --expected <file> --url https://polar-db-svc.polar-graph.svc.cluster.local:7473 --connect ... < password

#[global_allocator]
static GLOBAL: polar_scudo::Scudo = polar_scudo::Scudo;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use clap::{Parser, Subcommand};
use gitlab_seed::check::{Neo4j, compare};
use gitlab_seed::dataset::{Dataset, Size, dataset};
use gitlab_seed::expected::Expected;
use gitlab_seed::expected::expected;
use gitlab_seed::gitlab::{Gitlab, finished};
use gitlab_seed::oci::image;
use gitlab_seed::registry::Registry;
use std::collections::BTreeMap;
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use url::Url;

/// How many times a failed pipeline is run again.
const RETRIES: usize = 2;

#[derive(Parser)]
#[command(about = "The test GitLab's known dataset: made, and the GitLab pair's graph held to it")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Make what is missing of the dataset, and print what the GitLab pair's graph should then hold. Root's token on stdin.
    Make(Args),
    /// Hold the graph to what `make` printed: every node and edge it expects, by name. Neo4j's password on stdin; fails when
    /// anything expected is missing, and says what is there besides.
    Check(CheckArgs),
}

#[derive(clap::Args)]
struct CheckArgs {
    /// What `make` printed.
    #[arg(long)]
    expected: PathBuf,
    /// Neo4j's HTTP endpoint, by the name its certificate carries.
    #[arg(long)]
    url: Url,
    /// Where to reach it (a port-forward).
    #[arg(long)]
    connect: Option<SocketAddr>,
    /// The CA its certificate chains to.
    #[arg(long)]
    ca: Option<PathBuf>,
    /// A client certificate Neo4j takes, and its key (an administrator's).
    #[arg(long)]
    cert: Option<PathBuf>,
    #[arg(long)]
    key: Option<PathBuf>,
}

#[derive(clap::Args)]
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
    /// GitLab's container registry's own address.
    #[arg(long)]
    registry_url: Url,
    /// Where to reach the registry (a port-forward).
    #[arg(long)]
    registry_connect: Option<SocketAddr>,
    /// The repository whose `main` the mirror holds (this checkout of Polar).
    #[arg(long)]
    repo: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Make(args) => make(args).await,
        Command::Check(args) => check(args).await,
    }
}

async fn check(args: CheckArgs) -> Result<()> {
    let mut password = String::new();
    std::io::stdin()
        .read_to_string(&mut password)
        .context("reading the password from stdin")?;
    let expected: Expected = serde_json::from_slice(
        &std::fs::read(&args.expected).context("reading what was expected")?,
    )
    .context("what was expected is not what `make` prints")?;
    let read = |p: &Option<PathBuf>| p.as_ref().map(std::fs::read).transpose();
    let ca = read(&args.ca).context("reading the CA")?;
    let identity = match (read(&args.cert)?, read(&args.key)?) {
        (Some(mut cert), Some(key)) => {
            cert.extend_from_slice(&key);
            Some(cert)
        }
        (None, None) => None,
        _ => bail!("a client certificate takes both --cert and --key"),
    };
    let neo4j = Neo4j::new(
        args.url,
        password.trim().to_string(),
        ca.as_deref(),
        identity.as_deref(),
        args.connect,
    )?;
    let report = compare(&expected, &neo4j.graph().await?);
    let wanted: usize = expected.nodes.values().map(|n| n.len()).sum();
    println!("{}", serde_json::to_string_pretty(&report)?);
    eprintln!(
        "{} of {wanted} nodes and {} of {} edges expected are there; {} nodes besides",
        wanted - report.missing_nodes.len(),
        expected.edges.len() - report.missing_edges.len(),
        expected.edges.len(),
        report.beyond.len()
    );
    if !report.passed() {
        bail!("the graph does not hold what the seed made");
    }
    Ok(())
}

async fn make(args: Args) -> Result<()> {
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
    let gitlab = Gitlab::new(args.url.clone(), token.clone(), ca.as_deref(), args.connect)?;
    let registry = Registry::new(
        args.registry_url.clone(),
        args.url.clone(),
        token.clone(),
        ca.as_deref(),
        args.registry_connect,
        args.connect,
    )?;

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
    let ids: BTreeMap<String, u64> = with_ids(&gitlab, &d, &groups).await?;
    let img = image(
        &d.image
            .files
            .iter()
            .map(|(name, content)| (name.as_str(), content.as_bytes()))
            .collect::<Vec<_>>(),
    );
    registry.push(&d.image.project, &img, &d.image.tags).await?;
    gitlab
        .ensure_package(ids[&d.package.project], &d.package)
        .await?;
    let mirror = gitlab
        .ensure_project(&d.mirror, groups[&d.mirror.namespace])
        .await?;
    if !gitlab.has_branch(mirror, "main").await? {
        push_mirror(&args, &token, ca.is_some(), &d.mirror.full_path)?;
    }
    eprintln!(
        "made what was missing: {} users, {} groups, {} projects, an image, a package and a mirror",
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

/// The projects' ids by full path (each found, made already).
async fn with_ids(
    gitlab: &Gitlab,
    d: &Dataset,
    groups: &BTreeMap<String, u64>,
) -> Result<BTreeMap<String, u64>> {
    let mut ids = BTreeMap::new();
    for p in &d.projects {
        ids.insert(
            p.full_path.clone(),
            gitlab.ensure_project(p, groups[&p.namespace]).await?,
        );
    }
    Ok(ids)
}

/// This checkout's `main` pushed to the mirror, whole. git reaches GitLab where the seed does (`--connect`), trusting `--ca` alone,
/// and is given the token in a header from its environment, never on its command line.
fn push_mirror(args: &Args, token: &str, with_ca: bool, project: &str) -> Result<()> {
    let host = args
        .url
        .host_str()
        .ok_or_else(|| anyhow!("{} has no host", args.url))?;
    let mut target = args.url.clone();
    let mut command = std::process::Command::new("git");
    command.arg("-C").arg(&args.repo);
    if let Some(addr) = args.connect {
        target
            .set_port(Some(addr.port()))
            .map_err(|_| anyhow!("{} cannot take a port", args.url))?;
        command.arg("-c").arg(format!(
            "http.curloptResolve={host}:{}:{}",
            addr.port(),
            addr.ip()
        ));
    }
    if with_ca && let Some(ca) = &args.ca {
        command
            .arg("-c")
            .arg(format!("http.sslCAInfo={}", ca.display()));
    }
    target.set_path(&format!("/{project}.git"));
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("root:{token}"));
    let pushed = command
        .args(["push", "--quiet", target.as_str(), "main:refs/heads/main"])
        // The trust above is the only trust: none from the environment.
        .env_remove("GIT_SSL_CAINFO")
        .env_remove("SSL_CERT_FILE")
        .env_remove("NIX_SSL_CERT_FILE")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "http.extraHeader")
        .env(
            "GIT_CONFIG_VALUE_0",
            format!("Authorization: Basic {basic}"),
        )
        .output()
        .context("running git")?;
    if !pushed.status.success() {
        bail!(
            "pushing main to {project}: {}",
            String::from_utf8_lossy(&pushed.stderr)
                .lines()
                .last()
                .unwrap_or_default()
        );
    }
    Ok(())
}
