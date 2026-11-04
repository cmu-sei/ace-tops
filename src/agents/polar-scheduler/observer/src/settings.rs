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

pub static LOCAL_PATH: Defaulted<String> = Defaulted::text(
    "POLAR_SCHEDULER_LOCAL_PATH",
    "where the schedules repository is checked out; the observer watches this directory",
    "/tmp/polar-schedules",
);

pub static REMOTE_URL: Optional<String> = Optional::text(
    "POLAR_SCHEDULER_REMOTE_URL",
    "the git remote the schedules are cloned from and kept in step with; unset, the observer \
     watches the local directory only",
);

pub static SYNC_INTERVAL: Optional<u64> = Optional::number(
    "POLAR_SCHEDULER_SYNC_INTERVAL",
    "seconds between pulls of the remote; 0 or unset means only a change announced by the \
     Polar git server triggers one. A remote that is not the Polar git server announces nothing, \
     so it needs an interval",
);

pub static GIT_CA_CERT: Optional<String> = Optional::text(
    "POLAR_SCHEDULER_GIT_CA_CERT",
    "path to the CA certificate (PEM) the git remote's certificate is verified against; unset, \
     git uses its usual trust",
);

pub static GIT_CLIENT_CERT: Optional<String> = Optional::text(
    "POLAR_SCHEDULER_GIT_CLIENT_CERT",
    "path to the certificate (PEM) presented to the git remote, which is how the Polar git \
     server knows who is asking; set together with POLAR_SCHEDULER_GIT_CLIENT_KEY",
);

pub static GIT_CLIENT_KEY: Optional<String> = Optional::text(
    "POLAR_SCHEDULER_GIT_CLIENT_KEY",
    "path to the private key (PEM) for POLAR_SCHEDULER_GIT_CLIENT_CERT",
);

pub static DEPLOYMENT_URL: Optional<String> = Optional::text(
    "POLAR_SCHEDULER_DEPLOYMENT_URL",
    "the deployment repository on Polar's git server, read with this workload's certificate, whose signed record is delivered to the attestation agent (docs/architecture/runtime-attestation.md); unset, none is",
);

pub static DEPLOYMENT_SOURCE_URL: Optional<String> = Optional::text(
    "POLAR_SCHEDULER_DEPLOYMENT_SOURCE_URL",
    "the bootstrap repository to copy the deployment from, until the handoff to Polar's git server is done (docs/architecture/cluster-bootstrap.md); unset, nothing is copied",
);

pub static DEPLOYMENT_SOURCE_CA: Optional<String> = Optional::text(
    "POLAR_SCHEDULER_DEPLOYMENT_SOURCE_CA",
    "path to the deployment CA's certificate (PEM), which the bootstrap repository's server's certificate is verified against",
);

pub static DEPLOYMENT_SOURCE_CERT: Optional<String> = Optional::text(
    "POLAR_SCHEDULER_DEPLOYMENT_SOURCE_CERT",
    "path to this agent's certificate of the deployment PKI (PEM), presented to the bootstrap repository's server",
);

pub static DEPLOYMENT_SOURCE_KEY: Optional<String> = Optional::text(
    "POLAR_SCHEDULER_DEPLOYMENT_SOURCE_KEY",
    "path to the private key (PEM) for POLAR_SCHEDULER_DEPLOYMENT_SOURCE_CERT",
);

pub static DEPLOYMENT_TARGET_URL: Optional<String> = Optional::text(
    "POLAR_SCHEDULER_DEPLOYMENT_TARGET_URL",
    "the deployment repository on Polar's git server, which the copy goes to with this agent's own certificate",
);

/// How often the deployment's record is looked for.
pub static DEPLOYMENT_RECORD_SECS: Defaulted<u64> = Defaulted::seconds(
    "POLAR_SCHEDULER_DEPLOYMENT_RECORD_SECS",
    "how often, in seconds, the observer looks in the deployment repository for the signed record to deliver to the \
     attestation agent; at least 1",
    "30",
)
.dynamic();

/// How often the deployment is copied to Polar's git server, until the handoff.
pub static DEPLOYMENT_COPY_SECS: Defaulted<u64> = Defaulted::seconds(
    "POLAR_SCHEDULER_DEPLOYMENT_COPY_SECS",
    "how often, in seconds, the observer looks for what is new to copy to Polar's git server, until the handoff is \
     done; at least 1",
    "10",
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
    &DEPLOYMENT_URL,
    &DEPLOYMENT_SOURCE_URL,
    &DEPLOYMENT_SOURCE_CA,
    &DEPLOYMENT_SOURCE_CERT,
    &DEPLOYMENT_SOURCE_KEY,
    &DEPLOYMENT_TARGET_URL,
    &DEPLOYMENT_RECORD_SECS,
    &DEPLOYMENT_COPY_SECS,
    &LOCAL_PATH,
    &REMOTE_URL,
    &SYNC_INTERVAL,
    &GIT_CA_CERT,
    &GIT_CLIENT_CERT,
    &GIT_CLIENT_KEY,
];

pub static SECTION: Section = Section {
    name: "polar-scheduler-observer",
    vars: VARIABLES,
    relations: |env| {
        // The copy needs all of it, or none: half of it set is a deployment that thinks it is handing off and is not.
        let set = [
            DEPLOYMENT_SOURCE_URL.name(),
            DEPLOYMENT_SOURCE_CA.name(),
            DEPLOYMENT_SOURCE_CERT.name(),
            DEPLOYMENT_SOURCE_KEY.name(),
            DEPLOYMENT_TARGET_URL.name(),
        ];
        let present = set.iter().filter(|name| env.var(name).is_some()).count();
        if present != 0 && present != set.len() {
            vec![format!(
                "{} must be set together, or not at all",
                set.join(", ")
            )]
        } else {
            Vec::new()
        }
    },
};

pub struct ObserverSettings {
    pub local_path: String,
    pub remote_url: Option<String>,
    pub sync_interval_secs: Option<u64>,
    pub git_ca_cert: Option<String>,
    pub git_client_cert: Option<String>,
    pub git_client_key: Option<String>,
    /// The deployment repository on Polar's git server, whose signed record is delivered.
    pub deployment_url: Option<String>,
    /// The bootstrap repository to copy from, with the target: set only until the handoff is done.
    pub deployment_copy: Option<DeploymentCopy>,
}

/// Where the deployment is copied from and to.
pub struct DeploymentCopy {
    pub source_url: String,
    pub source_ca: String,
    pub source_cert: String,
    pub source_key: String,
    pub target_url: String,
}

impl ObserverSettings {
    pub fn read(config: &Config) -> Result<Self, ConfigError> {
        Ok(Self {
            local_path: config.read(&LOCAL_PATH)?,
            remote_url: config.read(&REMOTE_URL)?,
            sync_interval_secs: config.read(&SYNC_INTERVAL)?,
            git_ca_cert: config.read(&GIT_CA_CERT)?,
            git_client_cert: config.read(&GIT_CLIENT_CERT)?,
            git_client_key: config.read(&GIT_CLIENT_KEY)?,
            deployment_url: config.read(&DEPLOYMENT_URL)?,
            deployment_copy: match (
                config.read(&DEPLOYMENT_SOURCE_URL)?,
                config.read(&DEPLOYMENT_SOURCE_CA)?,
                config.read(&DEPLOYMENT_SOURCE_CERT)?,
                config.read(&DEPLOYMENT_SOURCE_KEY)?,
                config.read(&DEPLOYMENT_TARGET_URL)?,
            ) {
                (
                    Some(source_url),
                    Some(source_ca),
                    Some(source_cert),
                    Some(source_key),
                    Some(target_url),
                ) => Some(DeploymentCopy {
                    source_url,
                    source_ca,
                    source_cert,
                    source_key,
                    target_url,
                }),
                _ => None,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_deployment_copy_is_all_of_its_settings_or_none() {
        let all = |name: &str| {
            name.starts_with("POLAR_SCHEDULER_DEPLOYMENT_")
                .then(|| "x".to_string())
        };
        assert!((SECTION.relations)(&all).is_empty());
        assert!((SECTION.relations)(&|_: &str| None).is_empty());
        let some =
            |name: &str| (name == "POLAR_SCHEDULER_DEPLOYMENT_SOURCE_URL").then(|| "x".to_string());
        assert_eq!((SECTION.relations)(&some).len(), 1);
    }
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
        assert_eq!(settings.remote_url, None);
        assert_eq!(settings.sync_interval_secs, None);
        assert_eq!(settings.git_client_cert, None);
        assert!(config(&[]).check().is_empty());
    }

    #[test]
    fn what_is_set_is_used() {
        let settings = ObserverSettings::read(&config(&[
            ("POLAR_SCHEDULER_LOCAL_PATH", "/data/schedules"),
            (
                "POLAR_SCHEDULER_REMOTE_URL",
                "https://git.example/polar-schedules.git",
            ),
            ("POLAR_SCHEDULER_SYNC_INTERVAL", "60"),
            ("POLAR_SCHEDULER_GIT_CA_CERT", "/c/ca.pem"),
            ("POLAR_SCHEDULER_GIT_CLIENT_CERT", "/c/cert.pem"),
            ("POLAR_SCHEDULER_GIT_CLIENT_KEY", "/c/key.pem"),
        ]))
        .unwrap();
        assert_eq!(settings.local_path, "/data/schedules");
        assert_eq!(settings.sync_interval_secs, Some(60));
        assert_eq!(settings.git_client_key.as_deref(), Some("/c/key.pem"));
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
