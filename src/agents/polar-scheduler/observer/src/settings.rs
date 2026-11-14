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

//! What the scheduler observer reads from its configuration, declared once.

use polar_env::{Config, ConfigError, Defaulted, Described, Optional, Section};

pub static LOCAL_PATH: Defaulted<String> = Defaulted::path(
    "POLAR_SCHEDULER_LOCAL_PATH",
    polar_env::Access::WriteDir,
    "where the schedules repository is checked out; the observer watches this directory",
    "/tmp/polar-schedules",
);

pub static SCHEDULES_REPO: Optional<String> = Optional::text(
    "POLAR_SCHEDULER_SCHEDULES_REPO",
    "the repository on Polar's git server the checkout is kept as, read over Cassini; unset, the observer \
     watches the local directory only",
);

pub static SYNC_INTERVAL: Optional<u64> = Optional::number(
    "POLAR_SCHEDULER_SYNC_INTERVAL",
    "seconds between reads of the repository; 0 or unset means only a change the Polar git server \
     announces, and the observer joining Cassini, start one",
);

pub static DEPLOYMENT_REPO: Optional<String> = Optional::text(
    "POLAR_SCHEDULER_DEPLOYMENT_REPO",
    "the deployment repository on Polar's git server, read over Cassini, whose signed record is delivered to the attestation agent (docs/architecture/runtime-attestation.md); unset, none is",
);

/// How often the deployment's record is looked for.
pub static DEPLOYMENT_RECORD_SECS: Defaulted<u64> = Defaulted::seconds(
    "POLAR_SCHEDULER_DEPLOYMENT_RECORD_SECS",
    "how often, in seconds, the observer looks in the deployment repository for the signed record to deliver to the \
     attestation agent; at least 1",
    "30",
)
.dynamic();

/// The store's checkpoint key, which the schedules log is held to (docs/architecture/record-store.md, "Bite 6").
pub static STORE_KEY: Optional<String> = Optional::text(
    "POLAR_SCHEDULER_STORE_KEY",
    "the store's checkpoint key (`<identity>/checkpoint+<id>+<key>`), as the git server logs it when its logs open; the \
     schedules log is delivered only as a checkpoint signed by it and co-signed by POLAR_SCHEDULER_WITNESS_KEY shows \
     it (docs/architecture/record-store.md, \"Bite 6\"). Signed at run time, in the observer's own settings, which it \
     takes from the log it reads",
)
.dynamic();

/// The witness's key, whose co-signature the schedules log is held to.
pub static WITNESS_KEY: Optional<String> = Optional::text(
    "POLAR_SCHEDULER_WITNESS_KEY",
    "the witness's verifier key (`<identity>/witness+<id>+<key>`), as the attestation agent logs it at its start; with \
     POLAR_SCHEDULER_STORE_KEY, what the schedules log is held to. Signed at run time",
)
.dynamic();

/// A number of seconds in force, as the timer it sets: at least one.
pub fn seconds<V>(config: &Config, variable: &V) -> Result<std::time::Duration, String>
where
    V: polar_env::Readable<Out = u64>,
{
    config
        .read(variable)
        .map(|secs| std::time::Duration::from_secs(secs.max(1)))
        .map_err(|e| e.to_string())
}

static VARIABLES: &[&dyn Described] = &[
    &DEPLOYMENT_REPO,
    &DEPLOYMENT_RECORD_SECS,
    &LOCAL_PATH,
    &SCHEDULES_REPO,
    &STORE_KEY,
    &SYNC_INTERVAL,
    &WITNESS_KEY,
];

pub static SECTION: Section = Section {
    name: "polar-scheduler-observer",
    vars: VARIABLES,
    relations: |_| Vec::new(),
};

pub struct ObserverSettings {
    pub local_path: String,
    /// The repository on Polar's git server the checkout is kept as.
    pub schedules_repo: Option<String>,
    pub sync_interval_secs: Option<u64>,
    /// The deployment repository on Polar's git server, whose signed record is delivered.
    pub deployment_repo: Option<String>,
}

impl ObserverSettings {
    pub fn read(config: &Config) -> Result<Self, ConfigError> {
        Ok(Self {
            local_path: config.read(&LOCAL_PATH)?,
            schedules_repo: config.read(&SCHEDULES_REPO)?,
            sync_interval_secs: config.read(&SYNC_INTERVAL)?,
            deployment_repo: config.read(&DEPLOYMENT_REPO)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    fn config(pairs: &[(&str, &str)]) -> Config {
        let env: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::builder(&env).register(&SECTION).build()
    }

    #[test]
    fn the_section_is_sound_and_its_defaults_parse() {
        assert_eq!(SECTION.defaults_problems(), Vec::<String>::new());
    }

    #[test]
    fn nothing_is_required_and_the_path_has_a_default() {
        let settings = ObserverSettings::read(&config(&[])).unwrap();
        assert_eq!(settings.local_path, "/tmp/polar-schedules");
        assert_eq!(settings.schedules_repo, None);
        assert_eq!(settings.deployment_repo, None);
        assert_eq!(settings.sync_interval_secs, None);
        assert!(config(&[]).check().is_empty());
    }

    #[test]
    fn what_is_set_is_used() {
        let settings = ObserverSettings::read(&config(&[
            ("POLAR_SCHEDULER_LOCAL_PATH", "/data/schedules"),
            ("POLAR_SCHEDULER_SCHEDULES_REPO", "polar-schedules"),
            ("POLAR_SCHEDULER_DEPLOYMENT_REPO", "deployment"),
            ("POLAR_SCHEDULER_SYNC_INTERVAL", "60"),
        ]))
        .unwrap();
        assert_eq!(settings.local_path, "/data/schedules");
        assert_eq!(settings.sync_interval_secs, Some(60));
        assert_eq!(settings.schedules_repo.as_deref(), Some("polar-schedules"));
        assert_eq!(settings.deployment_repo.as_deref(), Some("deployment"));
    }

    #[test]
    fn an_interval_that_is_not_a_number_is_a_problem_before_the_agent_starts() {
        let problems = config(&[("POLAR_SCHEDULER_SYNC_INTERVAL", "soon")]).check();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("POLAR_SCHEDULER_SYNC_INTERVAL"),
            "{problems:?}"
        );
    }
}
