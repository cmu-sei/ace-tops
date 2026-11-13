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

//! build-fetch: the source-fetch init container of a build's pod (src/lib.rs). It exits 0 only when the workspace holds
//! the source the orchestrator named, and the pod's pipeline never starts otherwise.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    polar_version::exit_if_asked("build-fetch");
    let _ = rustls::crypto::ring::default_provider().install_default();
    let probing = std::env::args().nth(1).as_deref() == Some(build_fetch::probe::PROBE_ARG);
    // The probe's lines are read back by the orchestrator, into why a build is refused: plain text, with no colour.
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(!probing)
        .init();
    if probing {
        return probe().await;
    }
    let config = polar_env::Config::builder(&polar_env::ProcessEnv)
        .register(&build_fetch::SECTION)
        .build();
    let problems = config.check();
    if !problems.is_empty() {
        tracing::error!("the fetch's configuration is not sound: {problems:?}");
        return ExitCode::FAILURE;
    }
    match build_fetch::run(&config).await {
        Ok(()) => {
            tracing::info!("the source is in the workspace");
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// The canary's probe (src/probe.rs): one line for each address, and success only when every one did as required.
async fn probe() -> ExitCode {
    let config = polar_env::Config::builder(&polar_env::ProcessEnv)
        .register(&build_fetch::probe::PROBE_SECTION)
        .build();
    let problems = config.check();
    if !problems.is_empty() {
        tracing::error!("the probe's configuration is not sound: {problems:?}");
        return ExitCode::FAILURE;
    }
    match build_fetch::probe::run(&config).await {
        Ok(seen) => {
            seen.iter().for_each(|s| tracing::info!("{}", s.line()));
            tracing::info!("the network is enforced as the builds' policy says");
            ExitCode::SUCCESS
        }
        Err(seen) => {
            for s in &seen {
                if s.as_required() {
                    tracing::info!("{}", s.line());
                } else {
                    tracing::error!("{}", s.line());
                }
            }
            tracing::error!("the network is not enforced as the builds' policy says");
            ExitCode::FAILURE
        }
    }
}

// Every Polar binary allocates with Scudo (docs/architecture/broker-baseline.md, "Decided").
#[global_allocator]
static GLOBAL: polar_scudo::Scudo = polar_scudo::Scudo;
