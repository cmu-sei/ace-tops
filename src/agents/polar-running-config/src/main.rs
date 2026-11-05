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

//! `polar-running-config <agent>`: asks a running agent for its configuration in force, over Cassini, with the asker's
//! own certificate, and prints the answer as JSON; with `--template`, a file to edit and sign, filled in from it. Design:
//! docs/architecture/dynamic-settings.md. The work is in the library, for whatever else comes to ask.

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use polar_running_config::{ask, client_config, question};
use polar_sign::scaffold::Scaffold;
use std::path::PathBuf;
use std::time::Duration;

/// Where `just port-forwards-up broker` puts the broker on this machine.
const LOCAL_BROKER: &str = "127.0.0.1:18081";
/// The name on the broker's certificate, in a cluster on the usual domain.
const BROKER_NAME: &str = "cassini-ip-svc.polar.svc.cluster.local";

#[derive(Parser)]
#[command(
    name = "polar-running-config",
    about = "Ask a running agent what configuration is in force"
)]
struct Cli {
    /// The agent's name, as it calls itself.
    agent: String,
    /// Whose certificate and key to ask with: <dir>/<user>.crt and .key; $USER by default. They need to be in the group
    /// config-readers, or a policy that permits it.
    #[arg(long)]
    user: Option<String>,
    /// Where they are, with ca.pem; ~/.config/polar-admin by default.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Where the broker is, as host:port; POLAR_BROKER_ADDR, or the forward `just port-forwards-up broker` starts.
    #[arg(long)]
    broker: Option<String>,
    /// The name on the broker's certificate; POLAR_BROKER_NAME, or the usual one.
    #[arg(long)]
    server_name: Option<String>,
    /// How long to wait for the answer, in seconds. A refused question gets none.
    #[arg(long, default_value_t = 15)]
    wait: u64,
    /// Print a file to edit and sign with `polar-sign sign`, not the answer.
    #[arg(long)]
    template: bool,
    /// The agent's scaffold, for --template; <dir>/scaffolds/<agent>.json by default.
    #[arg(long, requires = "template")]
    scaffold: Option<PathBuf>,
}

fn env_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[tokio::main]
async fn main() -> Result<()> {
    polar_version::exit_if_asked("polar-running-config");
    let cli = Cli::parse();
    let dir = match cli.dir {
        Some(dir) => dir,
        None => PathBuf::from(env_var("HOME").context("HOME is not set: say where with --dir")?)
            .join(".config/polar-admin"),
    };
    let user = cli
        .user
        .or_else(|| env_var("USER"))
        .context("USER is not set: say whose certificate with --user")?;
    let broker = cli
        .broker
        .or_else(|| env_var("POLAR_BROKER_ADDR"))
        .unwrap_or_else(|| LOCAL_BROKER.to_string());
    let server_name = cli
        .server_name
        .or_else(|| env_var("POLAR_BROKER_NAME"))
        .unwrap_or_else(|| BROKER_NAME.to_string());
    // Before the broker is troubled: a template it could not write is no use.
    let scaffold = if cli.template {
        Some(
            Scaffold::load(&cli.agent, cli.scaffold.as_deref(), &dir)
                .map_err(anyhow::Error::msg)?,
        )
    } else {
        None
    };

    let identity = polar_sign::load_identity(&dir, &user).map_err(|e| {
        anyhow!("{e}: run `just user-cert-install {user}` or `just admin-claim` first")
    })?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("the clock is before 1970")?
        .as_secs();
    let asked = question(&cli.agent, &identity, now, cli.wait)?;
    let config = client_config(&dir, &user, &broker, &server_name)?;
    let answer = ask(asked, config, Duration::from_secs(cli.wait)).await?;

    match scaffold {
        Some(scaffold) => print!(
            "{}",
            polar_sign::template::running_settings_template(&scaffold, &answer)
                .map_err(anyhow::Error::msg)?
        ),
        None => println!("{}", serde_json::to_string_pretty(&answer)?),
    }
    Ok(())
}

// Every Polar binary allocates with Scudo (docs/architecture/broker-baseline.md, "Decided").
#[global_allocator]
static GLOBAL: polar_scudo::Scudo = polar_scudo::Scudo;
