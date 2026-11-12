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

//! The deployment copy's git, with the `git` command, until up.nu makes the copy and the observer runs
//! no program (docs/architecture/runtime-attestation.md, slice C, C2, O3). Everything else it reads
//! from Polar's git server over Cassini (src/reads.rs).
//!
//! The command, not libgit2: the servers know who is asking from the client certificate, and libgit2
//! cannot present one.

use anyhow::{Context, anyhow};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The certificates git uses to reach the remote. All unset: git's usual trust, no client
/// certificate.
#[derive(Debug, Clone, Default)]
pub struct GitTls {
    pub ca_cert: Option<PathBuf>,
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
}

impl GitTls {
    fn command(&self) -> Command {
        let mut cmd = Command::new("git");
        cmd.env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0");
        if let Some(ca) = &self.ca_cert {
            cmd.arg("-c")
                .arg(format!("http.sslCAInfo={}", ca.display()));
        }
        if let Some(cert) = &self.client_cert {
            cmd.arg("-c")
                .arg(format!("http.sslCert={}", cert.display()));
        }
        if let Some(key) = &self.client_key {
            cmd.arg("-c").arg(format!("http.sslKey={}", key.display()));
        }
        cmd
    }
}

fn run(mut cmd: Command, what: &str) -> Result<String, anyhow::Error> {
    let out = cmd
        .output()
        .with_context(|| format!("cannot run git {what}"))?;
    if !out.status.success() {
        return Err(anyhow!(
            "git {what} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// A git remote and how to reach it.
#[derive(Debug, Clone)]
pub struct Remote {
    pub url: String,
    pub tls: GitTls,
}

/// Copies `main` from `source` to `target` through a bare repository at `work`, and says the commit `target` now has. It only ever moves `target` forward, and every commit of the
/// history goes with it, for the server to judge. Running it again takes what is new.
pub fn copy_main(source: &Remote, target: &Remote, work: &Path) -> Result<String, anyhow::Error> {
    const HELD: &str = "refs/polar/copy";
    let in_work = |tls: &GitTls| {
        let mut cmd = tls.command();
        cmd.current_dir(work);
        cmd
    };
    std::fs::create_dir_all(work).with_context(|| format!("cannot make {}", work.display()))?;
    let mut init = in_work(&GitTls::default());
    init.args(["init", "--quiet", "--bare", "."]);
    run(init, "init")?;
    let mut fetch = in_work(&source.tls);
    fetch.args([
        "fetch",
        "--quiet",
        "--force",
        &source.url,
        &format!("refs/heads/main:{HELD}"),
    ]);
    run(fetch, "fetch")?;
    let mut push = in_work(&target.tls);
    push.args([
        "push",
        "--quiet",
        &target.url,
        &format!("{HELD}:refs/heads/main"),
    ]);
    run(push, "push")?;
    let mut held = in_work(&GitTls::default());
    held.args(["rev-parse", HELD]);
    Ok(run(held, "rev-parse")?.trim().to_string())
}
