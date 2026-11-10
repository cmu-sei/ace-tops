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

//! `polar-sign template` gives a file to fill in for an agent's runtime section or settings; `polar-sign sign`
//! checks it, seals its secrets, signs it and, with `--push`, puts it in the schedules repository;
//! `polar-sign configuration` and `runtime` sign a change given on the command line; `polar-sign verify`
//! checks a signed document; `polar-sign projection test` holds a deployment's mapping to its samples and signs a
//! record of what it found; `polar-sign check` judges what one instance declares and signs its verdicts. Design: `docs/architecture/signed-configuration.md`, and for the test
//! `docs/architecture/http-observers.md`, "Evidence".

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use polar_env::Env;
use polar_sign::flow::{Signing, sign_file};
use polar_sign::scaffold::Scaffold;
use polar_sign::{
    author, evidence, fetch, load_identity, next, parse_body, parse_change, push, runtime_payload,
    sign_to_dhall, split_pem, template, verify_source,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "polar-sign",
    about = "Sign and check Polar configuration documents"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sign a configuration update for an agent with your certificate and key.
    ///
    /// Writes one Dhall file to commit to the schedules repository (to stdout unless --out is
    /// given). The signer needs the c:update-configuration capability, and the agent refuses a
    /// version that is not higher than the last it applied.
    Configuration {
        /// The agent's name, as it calls itself (its service name).
        #[arg(long)]
        agent: String,
        /// Must be higher than the last version the agent applied.
        #[arg(long)]
        version: u64,
        /// A change, NAME=VALUE. Only variables the agent declares dynamic can be changed, and never a secret one. The
        /// document replaces the last one: a setting it does not name goes back to its rendered value.
        #[arg(long = "set", value_name = "NAME=VALUE", required = true)]
        changes: Vec<String>,
        /// The agent's scaffold (`<agent> --scaffold`), which the changes are judged by; <dir>/scaffolds/<agent>.json by
        /// default. Nothing is signed without it.
        #[arg(long)]
        scaffold: Option<PathBuf>,
        /// The item's id; a new one if not given.
        #[arg(long)]
        id: Option<String>,
        /// The first version of the agent the document is for (a platform version, such as 3.1.0); any if not given.
        #[arg(long)]
        from: Option<String>,
        /// The version of the agent it is no longer for; none if not given. An agent outside the range refuses it.
        #[arg(long)]
        below: Option<String>,
        /// Whose certificate and key to sign with: <dir>/<user>.crt and .key. Required: it is never assumed.
        #[arg(long)]
        user: String,
        /// Where they are; ~/.config/polar-admin by default.
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Sign a runtime section for an agent: its policy, its groups, the repositories it watches.
    ///
    /// The body is JSON, an object, as the agent declared that section (`<agent> --help` lists them).
    /// The signer needs the capability the section asks for (c:update-runtime unless the agent says
    /// otherwise: c:update-policy for `policy`, c:update-groups for `groups`), and the agent refuses a
    /// version that is not higher than the last it applied to that section.
    Runtime {
        #[arg(long)]
        agent: String,
        /// The section's name.
        #[arg(long)]
        section: String,
        #[arg(long)]
        version: u64,
        /// The body as JSON, or --body-file.
        #[arg(long, conflicts_with = "body_file")]
        body: Option<String>,
        /// A file holding the body as JSON; `-` reads standard input.
        #[arg(long)]
        body_file: Option<PathBuf>,
        /// A file holding a projection in Dhall, checked against its type and against the agent's schema in its
        /// scaffold: the body, in place of --body or --body-file.
        #[arg(long, conflicts_with_all = ["body", "body_file"])]
        projection: Option<PathBuf>,
        /// The agent's scaffold (`<agent> --scaffold`), which the section is judged by; <dir>/scaffolds/<agent>.json by
        /// default. Nothing is signed without it.
        #[arg(long)]
        scaffold: Option<PathBuf>,
        #[arg(long)]
        id: Option<String>,
        /// The first version of the agent the section is for; any if not given.
        #[arg(long)]
        from: Option<String>,
        /// The version of the agent it is no longer for; none if not given.
        #[arg(long)]
        below: Option<String>,
        /// A migration the section needs, ID=FILE (its `.cypher` file, committed at migrations/<agent>/<ID>.cypher): the
        /// agent holds the section until a signed record that it was applied arrives (`polar-sign migration applied`).
        #[arg(long = "migration", value_name = "ID=FILE")]
        migrations: Vec<String>,
        /// As --migration, for one that runs after the section is in force: the agent does not wait for it.
        #[arg(long = "migration-after", value_name = "ID=FILE")]
        migrations_after: Vec<String>,
        #[arg(long)]
        user: String,
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print a file to fill in for an agent: one of its runtime sections, or the settings a signed document may
    /// change. It comes from the agent's own scaffold, with the defaults the agent declares and a comment on every
    /// field, and the secret fields marked.
    ///
    /// Edit it, then `polar-sign sign` it. `polar-sign template <agent>` alone lists what the agent takes.
    Template {
        /// The agent's name, as it calls itself.
        agent: String,
        /// The runtime section to print a template for.
        section: Option<String>,
        /// Print the template for the agent's settings instead.
        #[arg(long, conflicts_with = "section")]
        settings: bool,
        /// Fill the settings in from what the agent says is in force: a file holding what `polar-running-config`
        /// printed, or `-` for standard input.
        #[arg(long, requires = "settings", value_name = "ANSWER")]
        running: Option<PathBuf>,
        /// The agent's scaffold (`<agent> --scaffold`); <dir>/scaffolds/<agent>.json by default.
        #[arg(long)]
        scaffold: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Check a file made from a template, seal its secrets, sign it with your certificate and key and write the
    /// signed Dhall file (to standard output unless --out or --push is given).
    ///
    /// The file is checked against the agent's scaffold first: nothing is signed if a field is missing, strange
    /// or of the wrong kind. A secret you typed in the clear (or `-`, to be asked for it on standard input) is
    /// encrypted so that only that agent can open it, to the agent's escrow certificate, which is fetched from
    /// the credentials agent's gateway and checked against your CA before it is trusted. With --push the file is
    /// committed to the schedules repository at permanent/<agent>/<section>.dhall and pushed.
    Sign {
        /// The file made from a template.
        file: PathBuf,
        #[arg(long)]
        user: String,
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long)]
        scaffold: Option<PathBuf>,
        /// The credentials agent's gateway; POLAR_OBSERVER_URL, or http://localhost:8081, by default.
        #[arg(long)]
        observer_url: Option<String>,
        /// The identity the agent's escrow certificate must carry, if not <agent>.polar.serviceaccount.cluster.local.
        #[arg(long)]
        escrow_identity: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
        /// Commit the signed file to the schedules repository and push it.
        #[arg(long)]
        push: bool,
        /// The schedules repository (anything `git clone` takes); POLAR_SCHEDULES_URL by default.
        #[arg(long)]
        repo: Option<String>,
        /// Where the tool keeps its clone; ~/.cache/polar-sign/schedules by default.
        #[arg(long)]
        workdir: Option<PathBuf>,
        /// KEY=VALUE for every git command of the push (`git -c`), such as http.curloptResolve.
        #[arg(long = "git-config", value_name = "KEY=VALUE")]
        git_config: Vec<String>,
    },
    /// Write the file for the next version of a signed runtime section, or of an agent's settings, from the latest version
    /// in the schedules repository, verified as an agent verifies it (to standard output unless --out is given).
    ///
    /// Its body is as it was and its id kept, its version one higher. A sealed secret is not carried, since it is bound to
    /// its version: it is left null for you to type again, and the file says which. Edit what changes, then `polar-sign
    /// sign` it. Nothing is signed and no key is read; your certificate is only what reaches the git server.
    Next {
        /// The agent's name, as it calls itself.
        agent: String,
        /// The runtime section; --settings for the agent's settings instead.
        section: Option<String>,
        #[arg(long, conflicts_with = "section")]
        settings: bool,
        /// Whose certificate reaches the git server: <dir>/<user>.crt and .key.
        #[arg(long)]
        user: String,
        #[arg(long)]
        dir: Option<PathBuf>,
        /// The CA certificate the latest version must chain to; <dir>/ca.pem by default.
        #[arg(long)]
        ca: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
        /// The schedules repository (anything `git clone` takes); POLAR_SCHEDULES_URL by default.
        #[arg(long)]
        repo: Option<String>,
        /// Where the tool keeps its clone; ~/.cache/polar-sign/schedules by default.
        #[arg(long)]
        workdir: Option<PathBuf>,
        /// KEY=VALUE for every git command (`git -c`), such as http.curloptResolve.
        #[arg(long = "git-config", value_name = "KEY=VALUE")]
        git_config: Vec<String>,
    },
    /// Sign a deployment's record with the pipeline's certificate and key, to standard output (`deploy-repo.nu publish`).
    Record {
        /// The record, as JSON.
        payload: PathBuf,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        key: PathBuf,
    },
    /// Check a signed document the way a receiver checks its signature: the layout, the chain to the
    /// CA, the signer's certificate and the signature. Says who signed it and what it asks for.
    Verify {
        file: PathBuf,
        /// The CA certificate to trust; <dir>/ca.pem by default.
        #[arg(long)]
        ca: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
        /// The file is an evidence record (`polar-sign projection test`), not a configuration document.
        #[arg(long)]
        evidence: bool,
    },
    /// Judge what one instance of Polar declares, from checkouts of its signed repositories, and sign the verdicts.
    ///
    /// Reads the deployment (its last commit, signed by the pipeline, its record and the authority model the render gave
    /// the credentials agent), polar-schedules (every signed section) and polar-evidence, verifying each as an agent
    /// would, and the agents' scaffolds. Each invariant, by its id, holds, is violated, or is no longer covered (there was
    /// evidence, for another version), with the lines that show it; and what each workload could touch is reported.
    /// Report only: the tool fails when it cannot judge, never for a verdict. The record is signed in the evidence domain
    /// (to standard output unless --out or --push).
    Check {
        /// A checkout of the deployment repository.
        #[arg(long)]
        deployment: PathBuf,
        /// A checkout of polar-schedules.
        #[arg(long)]
        schedules: PathBuf,
        /// A checkout of polar-evidence.
        #[arg(long)]
        evidence: PathBuf,
        /// The agents' scaffolds; <dir>/scaffolds by default.
        #[arg(long)]
        scaffolds: Option<PathBuf>,
        /// The deployment CA's certificate, which the pipeline's signatures chain to (~/.config/polar-deploy/<target>/ca.pem).
        #[arg(long)]
        deploy_ca: PathBuf,
        /// Whose certificate and key sign the verdicts, and ask the agents with --ask.
        #[arg(long)]
        user: String,
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
        /// Ask every agent that reads a signed document what it holds in force, over Cassini, and judge that too: each
        /// of its pods answers. Needs the asker in the group config-readers, as `polar-running-config` does.
        #[arg(long)]
        ask: bool,
        /// With --ask, where the broker is, as host:port; POLAR_BROKER_ADDR, or the forward `just port-forwards-up broker`
        /// starts.
        #[arg(long, requires = "ask")]
        broker: Option<String>,
        /// With --ask, the name on the broker's certificate; POLAR_BROKER_NAME, or the usual one.
        #[arg(long, requires = "ask")]
        server_name: Option<String>,
        /// With --ask, how long to hear answers, in seconds: every pod of every agent answers within it.
        #[arg(long, requires = "ask", default_value_t = 15)]
        wait: u64,
        /// Commit the record to the evidence repository and push it.
        #[arg(long)]
        push: bool,
        /// The evidence repository (anything `git clone` takes); POLAR_EVIDENCE_URL by default.
        #[arg(long)]
        repo: Option<String>,
        /// Where the tool keeps its clone; ~/.cache/polar-sign/evidence by default.
        #[arg(long)]
        workdir: Option<PathBuf>,
        /// KEY=VALUE for every git command of the push (`git -c`).
        #[arg(long = "git-config", value_name = "KEY=VALUE")]
        git_config: Vec<String>,
    },
    /// Migrations a runtime section names, which an administrator applies.
    Migration {
        #[command(subcommand)]
        command: MigrationCommand,
    },
    /// What a projection, a mapping an HTTP processor writes the graph by, does.
    Projection {
        #[command(subcommand)]
        command: ProjectionCommand,
    },
}

#[derive(Subcommand)]
enum MigrationCommand {
    /// Sign a record that you applied a migration, for the agent holding the section that names it: who, when, its
    /// file's digest and what you saw. Written to standard output unless --out or --push; with --push, committed at
    /// migrations/<agent>/<id>.applied.dhall in the schedules repository, which the scheduler delivers.
    Applied {
        #[arg(long)]
        agent: String,
        /// The runtime section that names the migration.
        #[arg(long)]
        section: String,
        /// The migration's id, as the section names it.
        #[arg(long)]
        id: String,
        /// The migration's file, as applied.
        #[arg(long)]
        file: PathBuf,
        /// What applying it reported (the counts, the rows changed), in a line.
        #[arg(long)]
        report: String,
        #[arg(long)]
        user: String,
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        push: bool,
        /// The schedules repository; POLAR_SCHEDULES_URL by default.
        #[arg(long)]
        repo: Option<String>,
        #[arg(long)]
        workdir: Option<PathBuf>,
        #[arg(long = "git-config", value_name = "KEY=VALUE")]
        git_config: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ProjectionCommand {
    /// Hold a deployment's mapping to the checks a kind's own is held to, and sign a record of what was found.
    ///
    /// The mapping must be inside the schema the agent's scaffold gives; signed as the section and read back as the
    /// agent reads its file, it must be the same projection; and each sample beside it, <name>.json as a service
    /// returns it, must become what <name>.expected.json says, read with the sample's name as its source. The record
    /// names all of them by digest, with this tool's version and the result, and is signed with your certificate and
    /// key in the evidence domain, so it is never taken for a configuration document. It is written whether the mapping
    /// passes or not (to standard output unless --out or --push), and the tool fails if it does not pass.
    Test {
        /// The mapping, in Dhall, as it is signed with `polar-sign runtime --projection`.
        mapping: PathBuf,
        /// The agent the mapping is for, as it calls itself.
        #[arg(long)]
        agent: String,
        /// Its runtime section that takes the mapping.
        #[arg(long)]
        section: String,
        /// The samples' folder; beside the mapping, named as it is without `.dhall`, by default.
        #[arg(long)]
        samples: Option<PathBuf>,
        /// The agent's scaffold (`<agent> --scaffold`); <dir>/scaffolds/<agent>.json by default.
        #[arg(long)]
        scaffold: Option<PathBuf>,
        /// Write what each sample becomes now beside it, as what it is expected to become, and sign nothing. Read
        /// each before committing it: it is then what the mapping is held to.
        #[arg(long, conflicts_with_all = ["push", "out"])]
        bless: bool,
        /// Whose certificate and key to sign the record with: <dir>/<user>.crt and .key.
        #[arg(long, required_unless_present = "bless")]
        user: Option<String>,
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
        /// Commit the record to the evidence repository and push it.
        #[arg(long)]
        push: bool,
        /// The evidence repository (anything `git clone` takes); POLAR_EVIDENCE_URL by default.
        #[arg(long)]
        repo: Option<String>,
        /// Where the tool keeps its clone; ~/.cache/polar-sign/evidence by default.
        #[arg(long)]
        workdir: Option<PathBuf>,
        /// KEY=VALUE for every git command of the push (`git -c`).
        #[arg(long = "git-config", value_name = "KEY=VALUE")]
        git_config: Vec<String>,
    },
}

/// What a payload asks for, in a few words: the section of a runtime document, the variables of a
/// configuration one.
fn what_it_changes(payload: &serde_json::Value) -> String {
    if let Some(section) = payload["section"].as_str() {
        return format!("section: {section}");
    }
    let names = payload["changes"]
        .as_array()
        .map(|c| {
            c.iter()
                .filter_map(|c| c["name"].as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    format!("changing: {names}")
}

fn default_dir(given: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(dir) = given {
        return Ok(dir);
    }
    let home = polar_env::ProcessEnv
        .var("HOME")
        .context("HOME is not set: say where your certificate is with --dir")?;
    Ok(PathBuf::from(home).join(".config/polar-admin"))
}

fn env_var(name: &str) -> Option<String> {
    polar_env::ProcessEnv.var(name).filter(|v| !v.is_empty())
}

/// The time now, in seconds since the epoch.
fn now() -> Result<i64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("the clock is before 1970")?
        .as_secs() as i64)
}

/// The CA certificates in `path`.
fn read_trust(path: &std::path::Path) -> Result<Vec<String>> {
    let trust = split_pem(
        &std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?,
    );
    if trust.is_empty() {
        bail!("{} holds no certificate", path.display());
    }
    Ok(trust)
}

/// Where the tool keeps its clone of a repository: --workdir, or polar-sign/<name> in the user's cache.
fn workdir_for(given: Option<PathBuf>, name: &str) -> Result<PathBuf> {
    if let Some(w) = given {
        return Ok(w);
    }
    let base = env_var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| env_var("HOME").map(|h| PathBuf::from(h).join(".cache")));
    Ok(base
        .context("HOME is not set: say where to keep the clone with --workdir")?
        .join("polar-sign")
        .join(name))
}

/// `git -c` for a push: the user's certificate and the CA for the Polar git server over HTTPS, then whatever was given.
fn git_config_for(
    remote: &str,
    dir: &std::path::Path,
    user: &str,
    given: &[String],
) -> Result<Vec<(String, String)>> {
    let mut config: Vec<(String, String)> = Vec::new();
    if remote.starts_with("https://") {
        for (key, name) in [
            ("http.sslCAInfo", "ca.pem".to_string()),
            ("http.sslCert", format!("{user}.crt")),
            ("http.sslKey", format!("{user}.key")),
        ] {
            config.push((
                key.to_string(),
                dir.join(name).to_string_lossy().to_string(),
            ));
        }
    }
    for item in given {
        config.push(parse_change(item).map_err(anyhow::Error::msg)?);
    }
    Ok(config)
}

/// The agent's scaffold, from --scaffold or the folder `nu infra/resolve.nu scaffolds <dir>` fills.
fn load_scaffold(agent: &str, given: Option<PathBuf>, dir: &std::path::Path) -> Result<Scaffold> {
    Scaffold::load(agent, given.as_deref(), dir).map_err(anyhow::Error::msg)
}

/// Standard input, read when an author wrote `-` for a secret.
fn read_secret_from_stdin() -> Result<String, String> {
    let mut text = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)
        .map_err(|e| format!("cannot read standard input: {e}"))?;
    Ok(text.trim_end_matches(['\n', '\r']).to_string())
}

fn write_or_print(text: &str, out: Option<&std::path::Path>, what: &str) -> Result<()> {
    match out {
        Some(path) => {
            std::fs::write(path, text)
                .with_context(|| format!("cannot write {}", path.display()))?;
            eprintln!("wrote {} ({what})", path.display());
        }
        None => print!("{text}"),
    }
    Ok(())
}

/// What a running agent said, as `polar-running-config` printed it: from a file, or standard input for `-`.
fn read_answer(
    path: &std::path::Path,
) -> Result<polar_scheduler_common::running::RunningConfiguration> {
    let text = if path == std::path::Path::new("-") {
        std::io::read_to_string(std::io::stdin()).context("cannot read standard input")?
    } else {
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?
    };
    serde_json::from_str(&text).context("that is not what polar-running-config prints")
}

fn main() -> Result<()> {
    polar_version::exit_if_asked("polar-sign");
    match Cli::parse().command {
        Command::Template {
            agent,
            section,
            settings,
            running,
            scaffold,
            dir,
            out,
        } => {
            let dir = default_dir(dir)?;
            let scaffold = load_scaffold(&agent, scaffold, &dir)?;
            if section.is_none() && !settings {
                println!("{} takes these runtime sections:", scaffold.agent);
                for r in &scaffold.runtime {
                    println!("  {}  {}", r.name, r.doc);
                }
                println!(
                    "and has {} setting(s) a signed document may change (--settings)",
                    scaffold.dynamic_variables().count()
                );
                return Ok(());
            }
            let text = match section {
                Some(section) => template::runtime_template(&scaffold, &section),
                None => match running {
                    Some(answer) => {
                        template::running_settings_template(&scaffold, &read_answer(&answer)?)
                    }
                    None => template::settings_template(&scaffold),
                },
            }
            .map_err(anyhow::Error::msg)?;
            write_or_print(
                &text,
                out.as_deref(),
                "fill it in, then `polar-sign sign` it",
            )?;
        }
        Command::Record { payload, cert, key } => {
            let read = |path: &PathBuf| {
                std::fs::read_to_string(path)
                    .with_context(|| format!("cannot read {}", path.display()))
            };
            let signed = polar_sign::sign_record(&read(&payload)?, &read(&cert)?, &read(&key)?)
                .map_err(anyhow::Error::msg)?;
            print!("{signed}");
        }
        Command::Sign {
            file,
            user,
            dir,
            scaffold,
            observer_url,
            escrow_identity,
            out,
            push: push_it,
            repo,
            workdir,
            git_config,
        } => {
            let dir = default_dir(dir)?;
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("cannot read {}", file.display()))?;
            let input = author::read_input(&text).map_err(anyhow::Error::msg)?;
            let scaffold = load_scaffold(&input.agent, scaffold, &dir)?;
            let identity = load_identity(&dir, &user).map_err(anyhow::Error::msg)?;
            let trust = read_trust(&dir.join("ca.pem"))?;
            let now = now()?;
            let observer_url = observer_url
                .or_else(|| env_var("POLAR_OBSERVER_URL"))
                .unwrap_or_else(|| "http://localhost:8081".to_string());
            let how = Signing {
                identity: &identity,
                trust_pem: &trust,
                now,
                escrow_identity: escrow_identity.as_deref(),
            };
            let fetch_certificate = |id: &str| fetch::fetch_certificate(&observer_url, id);
            let signed = match sign_file(
                &text,
                &scaffold,
                &how,
                &fetch_certificate,
                &mut read_secret_from_stdin,
            ) {
                Ok(signed) => signed,
                Err(problems) => {
                    for p in &problems {
                        eprintln!("  {p}");
                    }
                    bail!(
                        "nothing was signed: {} problem(s) in {}",
                        problems.len(),
                        file.display()
                    );
                }
            };
            let what = format!(
                "{} for {}, version {}, {} secret(s) sealed",
                signed.section.as_deref().unwrap_or("settings"),
                signed.agent,
                signed.version,
                signed.sealed.encrypted
            );
            if push_it {
                let (signer, _) =
                    verify_source(&signed.dhall, &trust, now).map_err(anyhow::Error::msg)?;
                let remote = repo.or_else(|| env_var("POLAR_SCHEDULES_URL")).context(
                    "--push needs the schedules repository: --repo, or POLAR_SCHEDULES_URL",
                )?;
                let workdir = workdir_for(workdir, "schedules")?;
                let config = git_config_for(&remote, &dir, &user, &git_config)?;
                let relative = push::place(&signed.agent, signed.section.as_deref());
                let username = signer.username.clone().unwrap_or_else(|| user.clone());
                let message = push::message(
                    &signed.agent,
                    signed.section.as_deref(),
                    signed.version,
                    &username,
                );
                let plan = push::Plan {
                    remote: &remote,
                    workdir: &workdir,
                    relative: &relative,
                    content: &signed.dhall,
                    message: &message,
                    author_name: &username,
                    author_email: signer.email.as_deref().unwrap_or("polar-sign@invalid"),
                    git_config: &config,
                };
                match push::push(&plan).map_err(anyhow::Error::msg)? {
                    push::Pushed::Pushed => eprintln!("pushed {relative} ({what})"),
                    push::Pushed::Unchanged => {
                        eprintln!("{relative} already holds exactly this file; nothing was pushed")
                    }
                }
                if let Some(path) = out {
                    write_or_print(&signed.dhall, Some(&path), &what)?;
                }
            } else {
                write_or_print(&signed.dhall, out.as_deref(), &what)?;
            }
        }
        Command::Configuration {
            agent,
            version,
            changes,
            scaffold,
            id,
            from,
            below,
            user,
            dir,
            out,
        } => {
            let changes = changes
                .iter()
                .map(|c| parse_change(c))
                .collect::<Result<Vec<_>, _>>()
                .map_err(anyhow::Error::msg)?;
            let range = polar_sign::range_of(from.as_deref(), below.as_deref())
                .map_err(anyhow::Error::msg)?;
            // Judged by the agent's scaffold as `sign` judges it: never a secret setting, never one fixed while it runs.
            let scaffold = load_scaffold(&agent, scaffold, &default_dir(dir.clone())?)?;
            let settings = changes
                .iter()
                .map(|(name, value)| (name.clone(), serde_json::Value::String(value.clone())))
                .collect::<serde_json::Map<_, _>>();
            let input = author::Input {
                agent: agent.clone(),
                version,
                id,
                document: author::Document::Settings {
                    settings: serde_json::Value::Object(settings),
                },
            };
            let prepared = author::prepare_sealed(input, &scaffold)
                .map_err(|problems| anyhow::anyhow!(problems.join("\n")))?;
            let payload = polar_sign::for_versions(prepared.payload, &range);
            let identity = load_identity(&default_dir(dir)?, &user).map_err(anyhow::Error::msg)?;
            let file = sign_to_dhall(payload, &identity).map_err(anyhow::Error::msg)?;
            match out {
                Some(path) => {
                    std::fs::write(&path, &file)
                        .with_context(|| format!("cannot write {}", path.display()))?;
                    eprintln!(
                        "wrote {} ({} change(s) for {agent}, version {version})",
                        path.display(),
                        changes.len()
                    );
                }
                None => print!("{file}"),
            }
        }
        Command::Runtime {
            agent,
            section,
            version,
            body,
            body_file,
            projection,
            scaffold,
            id,
            from,
            below,
            migrations,
            migrations_after,
            user,
            dir,
            out,
        } => {
            let range = polar_sign::range_of(from.as_deref(), below.as_deref())
                .map_err(anyhow::Error::msg)?;
            let mut named = Vec::new();
            for (given, after) in migrations
                .iter()
                .map(|m| (m, false))
                .chain(migrations_after.iter().map(|m| (m, true)))
            {
                let (id, file) = given
                    .split_once('=')
                    .with_context(|| format!("--migration {given}: give ID=FILE"))?;
                let bytes = std::fs::read(file).with_context(|| format!("cannot read {file}"))?;
                named.push(polar_sign::Migration {
                    id: id.to_string(),
                    sha256: polar_sign::migration_sha256(&bytes),
                    after,
                });
            }
            let text = match (body, body_file) {
                (None, None) if projection.is_some() => String::new(),
                (Some(text), None) => text,
                (None, Some(path)) if path.as_os_str() == "-" => {
                    let mut text = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)
                        .context("cannot read the body from standard input")?;
                    text
                }
                (None, Some(path)) => std::fs::read_to_string(&path)
                    .with_context(|| format!("cannot read {}", path.display()))?,
                _ => bail!("give the body with --body or --body-file"),
            };
            // Judged as the agent would judge it, by its scaffold: nothing is signed blind.
            let scaffold = load_scaffold(&agent, scaffold, &default_dir(dir.clone())?)?;
            let payload = match projection {
                Some(path) => {
                    let source = std::fs::read_to_string(&path)
                        .with_context(|| format!("cannot read {}", path.display()))?;
                    let body = polar_sign::projection_for(&scaffold, &section, &source)
                        .map_err(|problems| anyhow::anyhow!(problems.join("\n")))?;
                    // Nothing is signed that every agent would refuse.
                    polar_sign::runtime_problems(&section, &body).map_err(anyhow::Error::msg)?;
                    let id = id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                    runtime_payload(&agent, &section, version, &id, body)
                }
                None => {
                    let body = parse_body(&text).map_err(anyhow::Error::msg)?;
                    polar_sign::runtime_problems(&section, &body).map_err(anyhow::Error::msg)?;
                    // As `sign` judges it, and a secret must already be sealed: one in plaintext is refused, never signed.
                    let input = author::Input {
                        agent: agent.clone(),
                        version,
                        id,
                        document: author::Document::Runtime {
                            section: section.clone(),
                            body,
                        },
                    };
                    author::prepare_sealed(input, &scaffold)
                        .map_err(|problems| anyhow::anyhow!(problems.join("\n")))?
                        .payload
                }
            };
            let payload =
                polar_sign::with_migrations(polar_sign::for_versions(payload, &range), &named);
            let identity = load_identity(&default_dir(dir)?, &user).map_err(anyhow::Error::msg)?;
            let file = sign_to_dhall(payload, &identity).map_err(anyhow::Error::msg)?;
            match out {
                Some(path) => {
                    std::fs::write(&path, &file)
                        .with_context(|| format!("cannot write {}", path.display()))?;
                    eprintln!(
                        "wrote {} (section {section} for {agent}, version {version})",
                        path.display()
                    );
                }
                None => print!("{file}"),
            }
        }
        Command::Check {
            deployment,
            schedules,
            evidence: evidence_dir,
            scaffolds,
            deploy_ca,
            user,
            dir,
            out,
            ask,
            broker,
            server_name,
            wait,
            push: push_it,
            repo,
            workdir,
            git_config,
        } => {
            let dir = default_dir(dir)?;
            let trust = read_trust(&dir.join("ca.pem"))?;
            let deploy_trust = read_trust(&deploy_ca)?;
            let scaffolds = scaffolds.unwrap_or_else(|| dir.join("scaffolds"));
            let now = now()?;
            let read = polar_sign::instance::read::read(
                &polar_sign::instance::read::Sources {
                    deployment: &deployment,
                    schedules: &schedules,
                    evidence: &evidence_dir,
                    scaffolds: &scaffolds,
                },
                &polar_sign::instance::read::Trusts {
                    polar: &trust,
                    deployment: &deploy_trust,
                },
                now,
            )
            .map_err(anyhow::Error::msg)?;
            for line in &read.left_out {
                eprintln!("left out: {line}");
            }
            let mut facts = read.facts;
            let identity = load_identity(&dir, &user).map_err(anyhow::Error::msg)?;
            if ask {
                let asked = polar_sign::instance::agents_to_ask(&facts.model);
                let questions = asked
                    .iter()
                    .map(|agent| polar_running_config::question(agent, &identity, now as u64, wait))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                let broker = broker
                    .or_else(|| env_var("POLAR_BROKER_ADDR"))
                    .unwrap_or_else(|| "127.0.0.1:18081".to_string());
                let server_name = server_name
                    .or_else(|| env_var("POLAR_BROKER_NAME"))
                    .unwrap_or_else(|| "cassini-ip-svc.polar.svc.cluster.local".to_string());
                let config =
                    polar_running_config::client_config(&dir, &user, &broker, &server_name)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                eprintln!("asking {} agents, for {wait} s", asked.len());
                let heard = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .context("cannot start the runtime that asks")?
                    .block_on(polar_running_config::survey(
                        questions,
                        config,
                        std::time::Duration::from_secs(wait),
                    ))
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                facts.running = Some(polar_sign::instance::Running { asked, heard });
            }
            let checked = polar_sign::instance::check(&facts);
            for v in &checked.verdicts {
                eprintln!("{} {}: {}", v.status.as_str(), v.id, v.statement);
                if v.status != polar_sign::instance::Status::Holds {
                    for line in &v.witness {
                        eprintln!("  {line}");
                    }
                }
            }
            let mut record = polar_sign::instance::record(&facts, &checked, now);
            record["left_out"] = serde_json::json!(read.left_out);
            let signed = evidence::sign_record(record, &identity).map_err(anyhow::Error::msg)?;
            let holding = checked
                .verdicts
                .iter()
                .filter(|v| v.status == polar_sign::instance::Status::Holds)
                .count();
            let what = format!(
                "{} of {} invariants hold on {}",
                holding,
                checked.verdicts.len(),
                facts.instance.target
            );
            if push_it {
                let (signer, _) =
                    evidence::verify_record(&signed, &trust, now).map_err(anyhow::Error::msg)?;
                let remote = repo.or_else(|| env_var("POLAR_EVIDENCE_URL")).context(
                    "--push needs the evidence repository: --repo, or POLAR_EVIDENCE_URL",
                )?;
                let workdir = workdir_for(workdir, "evidence")?;
                let config = git_config_for(&remote, &dir, &user, &git_config)?;
                let relative = polar_sign::instance::place(&facts.instance.target, &signed);
                let username = signer.username.clone().unwrap_or_else(|| user.clone());
                let message =
                    polar_sign::instance::message(&facts.instance.target, &checked, &username);
                let plan = push::Plan {
                    remote: &remote,
                    workdir: &workdir,
                    relative: &relative,
                    content: &signed,
                    message: &message,
                    author_name: &username,
                    author_email: signer.email.as_deref().unwrap_or("polar-sign@invalid"),
                    git_config: &config,
                };
                match push::push(&plan).map_err(anyhow::Error::msg)? {
                    push::Pushed::Pushed => eprintln!("pushed {relative} ({what})"),
                    push::Pushed::Unchanged => {
                        eprintln!(
                            "{relative} already holds exactly this record; nothing was pushed"
                        )
                    }
                }
            } else {
                write_or_print(&signed, out.as_deref(), &what)?;
            }
        }
        Command::Migration {
            command:
                MigrationCommand::Applied {
                    agent,
                    section,
                    id,
                    file,
                    report,
                    user,
                    dir,
                    out,
                    push: push_it,
                    repo,
                    workdir,
                    git_config,
                },
        } => {
            let dir = default_dir(dir)?;
            let bytes =
                std::fs::read(&file).with_context(|| format!("cannot read {}", file.display()))?;
            let sha256 = polar_sign::migration_sha256(&bytes);
            let payload =
                polar_sign::applied_payload(&agent, &section, &id, &sha256, now()? as u64, &report);
            let identity = load_identity(&dir, &user).map_err(anyhow::Error::msg)?;
            let signed = sign_to_dhall(payload, &identity).map_err(anyhow::Error::msg)?;
            let what = format!("migration {id} of {agent}'s {section}, applied");
            if push_it {
                let trust = read_trust(&dir.join("ca.pem"))?;
                let (signer, _) =
                    verify_source(&signed, &trust, now()?).map_err(anyhow::Error::msg)?;
                let remote = repo.or_else(|| env_var("POLAR_SCHEDULES_URL")).context(
                    "--push needs the schedules repository: --repo, or POLAR_SCHEDULES_URL",
                )?;
                let workdir = workdir_for(workdir, "schedules")?;
                let config = git_config_for(&remote, &dir, &user, &git_config)?;
                let relative = format!("migrations/{agent}/{id}.applied.dhall");
                let username = signer.username.clone().unwrap_or_else(|| user.clone());
                let message = format!(
                    "chore({agent}): migration {id} applied\n\n{report}\n\nSigned by {username} with polar-sign."
                );
                let plan = push::Plan {
                    remote: &remote,
                    workdir: &workdir,
                    relative: &relative,
                    content: &signed,
                    message: &message,
                    author_name: &username,
                    author_email: signer.email.as_deref().unwrap_or("polar-sign@invalid"),
                    git_config: &config,
                };
                match push::push(&plan).map_err(anyhow::Error::msg)? {
                    push::Pushed::Pushed => eprintln!("pushed {relative} ({what})"),
                    push::Pushed::Unchanged => {
                        eprintln!("{relative} already holds exactly this record")
                    }
                }
            } else {
                write_or_print(&signed, out.as_deref(), &what)?;
            }
        }
        Command::Projection {
            command:
                ProjectionCommand::Test {
                    mapping,
                    agent,
                    section,
                    samples,
                    scaffold,
                    bless,
                    user,
                    dir,
                    out,
                    push: push_it,
                    repo,
                    workdir,
                    git_config,
                },
        } => {
            let dir = default_dir(dir)?;
            let source = std::fs::read_to_string(&mapping)
                .with_context(|| format!("cannot read {}", mapping.display()))?;
            let samples = samples.unwrap_or_else(|| mapping.with_extension(""));
            let parsed = load_scaffold(&agent, scaffold.clone(), &dir)?;
            if bless {
                let written = evidence::bless(&parsed, &section, &source, &samples)
                    .map_err(|problems| anyhow::anyhow!(problems.join("\n")))?;
                for path in &written {
                    eprintln!("wrote {path}");
                }
                eprintln!("read each before committing it: it is now what the mapping is held to");
                return Ok(());
            }
            let user = user.context("--user: whose certificate and key sign the record")?;
            let scaffold_path = Scaffold::path(&agent, scaffold.as_deref(), &dir);
            let scaffold_text = std::fs::read_to_string(&scaffold_path)
                .with_context(|| format!("cannot read {}", scaffold_path.display()))?;
            let identity = load_identity(&dir, &user).map_err(anyhow::Error::msg)?;
            let trust = read_trust(&dir.join("ca.pem"))?;
            let now = now()?;
            let mapping_name = mapping
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let tested = evidence::projection_test(
                &evidence::ProjectionTest {
                    scaffold: &scaffold_text,
                    section: &section,
                    mapping: &source,
                    mapping_name: &mapping_name,
                    samples: &samples,
                },
                &identity,
                &trust,
                now,
            )
            .map_err(anyhow::Error::msg)?;
            for detail in &tested.details {
                eprintln!("{detail}\n");
            }
            let signed = evidence::sign_record(tested.record.clone(), &identity)
                .map_err(anyhow::Error::msg)?;
            let what = format!(
                "{}'s {section} mapping {}",
                tested.agent,
                if tested.passed() { "passes" } else { "fails" }
            );
            if push_it {
                let (signer, _) =
                    evidence::verify_record(&signed, &trust, now).map_err(anyhow::Error::msg)?;
                let remote = repo.or_else(|| env_var("POLAR_EVIDENCE_URL")).context(
                    "--push needs the evidence repository: --repo, or POLAR_EVIDENCE_URL",
                )?;
                let workdir = workdir_for(workdir, "evidence")?;
                let config = git_config_for(&remote, &dir, &user, &git_config)?;
                let relative = evidence::place(&tested.agent, &section, &signed);
                let username = signer.username.clone().unwrap_or_else(|| user.clone());
                let message = evidence::message(&tested.agent, &section, &tested, &username);
                let plan = push::Plan {
                    remote: &remote,
                    workdir: &workdir,
                    relative: &relative,
                    content: &signed,
                    message: &message,
                    author_name: &username,
                    author_email: signer.email.as_deref().unwrap_or("polar-sign@invalid"),
                    git_config: &config,
                };
                match push::push(&plan).map_err(anyhow::Error::msg)? {
                    push::Pushed::Pushed => eprintln!("pushed {relative} ({what})"),
                    push::Pushed::Unchanged => {
                        eprintln!(
                            "{relative} already holds exactly this record; nothing was pushed"
                        )
                    }
                }
            } else {
                write_or_print(&signed, out.as_deref(), &what)?;
            }
            if !tested.passed() {
                bail!(
                    "{what}: {} problem(s), and the record says so",
                    tested.details.len()
                );
            }
        }
        Command::Next {
            agent,
            section,
            settings,
            user,
            dir,
            ca,
            out,
            repo,
            workdir,
            git_config,
        } => {
            if section.is_none() && !settings {
                anyhow::bail!("name the section, or --settings for {agent}'s settings");
            }
            let dir = default_dir(dir)?;
            let trust = read_trust(&ca.unwrap_or_else(|| dir.join("ca.pem")))?;
            let remote = repo
                .or_else(|| env_var("POLAR_SCHEDULES_URL"))
                .context("next reads the schedules repository: --repo, or POLAR_SCHEDULES_URL")?;
            let workdir = workdir_for(workdir, "schedules")?;
            let config = git_config_for(&remote, &dir, &user, &git_config)?;
            let latest = next::latest(
                &remote,
                &workdir,
                &config,
                &agent,
                section.as_deref(),
                &trust,
                now()?,
            )
            .map_err(anyhow::Error::msg)?;
            let file =
                next::file_for(&agent, section.as_deref(), &latest).map_err(anyhow::Error::msg)?;
            let what = format!(
                "the next version of {agent}'s {}",
                section.as_deref().unwrap_or("settings")
            );
            write_or_print(&file, out.as_deref(), &what)?;
        }
        Command::Verify {
            file,
            ca,
            dir,
            evidence: is_evidence,
        } => {
            let ca_path = match ca {
                Some(path) => path,
                None => default_dir(dir)?.join("ca.pem"),
            };
            let trust = read_trust(&ca_path)?;
            let source = std::fs::read_to_string(&file)
                .with_context(|| format!("cannot read {}", file.display()))?;
            let (signer, payload) = if is_evidence {
                evidence::verify_record(&source, &trust, now()?)
            } else {
                verify_source(&source, &trust, now()?)
            }
            .map_err(anyhow::Error::msg)?;
            println!(
                "signed by {} <{}> (identity {}, certificate {})",
                signer.username.as_deref().unwrap_or("?"),
                signer.email.as_deref().unwrap_or("?"),
                signer.identity.as_deref().unwrap_or("?"),
                signer.serial
            );
            if is_evidence {
                println!(
                    "{} of {}'s {} mapping (sha256 {}): {}",
                    payload["type"].as_str().unwrap_or("?"),
                    payload["subject"]["agent"].as_str().unwrap_or("?"),
                    payload["subject"]["section"].as_str().unwrap_or("?"),
                    payload["mapping"]["sha256"].as_str().unwrap_or("?"),
                    if payload["result"]["passed"] == true {
                        "passed"
                    } else {
                        "failed"
                    }
                );
                for problem in payload["result"]["problems"]
                    .as_array()
                    .into_iter()
                    .flatten()
                {
                    println!("  {}", problem.as_str().unwrap_or("?"));
                }
                return Ok(());
            }
            let capabilities: Vec<String> = signer
                .capabilities
                .iter()
                .map(|c| c.to_san_string())
                .collect();
            println!("capabilities: {}", capabilities.join(" "));
            println!(
                "type {}, for {}, version {}, {}",
                payload["type"].as_str().unwrap_or("?"),
                payload["target"]["agent"].as_str().unwrap_or("?"),
                payload["version"],
                what_it_changes(&payload)
            );
        }
    }
    Ok(())
}

// Every Polar binary allocates with Scudo (docs/architecture/broker-baseline.md, "Decided").
#[global_allocator]
static GLOBAL: polar_scudo::Scudo = polar_scudo::Scudo;
