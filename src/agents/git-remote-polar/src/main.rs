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

//! `git-remote-polar <remote> <url>`: git runs it for a `polar://` URL (src/lib.rs says what it does).

use git_remote_polar::{Lookup, config_env, plan};
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode};

/// The environment, and git's configuration as `git config --get` gives it (git runs a helper inside the repository).
struct Real;

impl Lookup for Real {
    fn env(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
    fn git_config(&self, key: &str) -> Option<String> {
        let out = Command::new("git")
            .args(["config", "--get", key])
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let (Some(remote), Some(url)) = (args.get(1), args.get(2)) else {
        eprintln!(
            "usage: git-remote-polar <remote> <polar://[host:port/]repository> (git runs it for a polar:// URL)"
        );
        return ExitCode::from(2);
    };
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let plan = match plan(url, &Real, home.as_deref()) {
        Ok(plan) => plan,
        Err(why) => {
            eprintln!("git-remote-polar: {why}");
            return ExitCode::from(2);
        }
    };
    let already = std::env::var("GIT_CONFIG_COUNT")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    // git's own HTTPS transport speaks to polar-git from here, as this process.
    let error = Command::new("git")
        .args(["remote-https", remote, &plan.https_url])
        .envs(config_env(&plan.config, already))
        .exec();
    eprintln!("git-remote-polar: cannot run git remote-https: {error}");
    ExitCode::from(1)
}

// Every Polar binary allocates with Scudo (docs/architecture/broker-baseline.md, "Decided").
#[global_allocator]
static GLOBAL: polar_scudo::Scudo = polar_scudo::Scudo;
