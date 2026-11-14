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

//! What the git server reads from its configuration, declared once.

// Where the server's key is (TLS_SERVER_CERT_CHAIN, TLS_SERVER_KEY, POLAR_CUSTODY_SOCKET) is declared once, by the crypto
// actor's `keys` section, and its TLS is the crypto actor's (docs/plans/crypto-actor.md); this section still requires that
// the server has its key, below.
use polar_crypto::environment::SERVER_KEY_FILE;
use polar_custody::environment::one_key;
use polar_env::{Config, ConfigError, Defaulted, Described, Optional, Required, Section};

pub const DEFAULT_PORT: &str = "8443";

pub static PORT: Defaulted<u16> = Defaulted::number(
    "POLAR_GIT_SERVER_PORT",
    "the port the git server listens on, on every address",
    DEFAULT_PORT,
);

pub static REPO_ROOT: Required<String> = Required::path(
    "POLAR_GIT_SERVER_REPO_ROOT",
    polar_env::Access::WriteDir,
    "the directory the bare repositories live in; it must be persistent storage",
);

pub static LOG_ROOT: Defaulted<String> = Defaulted::path(
    "POLAR_GIT_SERVER_LOG_ROOT",
    polar_env::Access::WriteDir,
    "the directory the store's signed logs live in, with the checkpoint key the crypto actor keeps beside them; \
     persistent storage, beside the repositories (docs/architecture/record-store.md)",
    "/var/lib/polar-git-server/logs",
);

/// The seeds the image was built with: the Nix build sets the variable to the store path holding
/// `infra/seeds`. Elsewhere there are none unless the variable is set at run time.
pub const DEFAULT_SEED_ROOT: &str = match option_env!("POLAR_GIT_SERVER_BUILT_SEED_ROOT") {
    Some(path) => path,
    None => "/nonexistent/polar-git-server-seeds",
};

pub static SEED_ROOT: Defaulted<String> = Defaulted::path(
    "POLAR_GIT_SERVER_SEED_ROOT",
    polar_env::Access::ReadDir,
    "the directory a relative `seed` in POLAR_GIT_SERVER_REPOS is resolved against; the image \
     carries the deployment's seed trees here",
    DEFAULT_SEED_ROOT,
);

pub static REPOS: Required<String> = Required::text(
    "POLAR_GIT_SERVER_REPOS",
    "JSON declaring the repositories, who may read and write each, and the directory each is \
     seeded from the first time it is created: \
     {\"admins\": [..], \"repos\": [{\"name\", \"readers\", \"writers\", \"seed\"}]}",
);

/// The witness the store's logs are brought to (src/witness.rs).
pub static WITNESS_KEY: Optional<String> = Optional::text(
    "POLAR_GIT_SERVER_WITNESS_KEY",
    "the witness's verifier key (`<identity>/witness+<id>+<key>`), as the attestation agent logs it at its start; the \
     store submits each log's checkpoints to it and serves only what it co-signed (docs/architecture/record-store.md, \
     \"Bite 5\"). Signed at run time; unset, nothing is witnessed and readers are served no checkpoint",
)
.dynamic();

const KEY_DOC: &str = "path to the private key (PEM) for the server's certificate; this or POLAR_CUSTODY_SOCKET, the custody daemon holding it, not both";

pub static CA_CERT: Required<String> = Required::path(
    "POLAR_GIT_SERVER_CA_CERT",
    polar_env::Access::ReadFile,
    "path to the CA certificate (PEM) that clients' certificates must chain to",
);

pub static DEPLOYMENT_CA: Optional<String> = Optional::path(
    "POLAR_GIT_SERVER_DEPLOYMENT_CA",
    polar_env::Access::ReadFile,
    "path to the deployment CA's certificate (PEM), whose clients are also taken, named `deployment:<name>` so that it speaks \
     for no one in Polar: how Flux reads the deployment (docs/architecture/cluster-bootstrap.md)",
);

pub static ADMINS: Optional<Vec<String>> = Optional::list(
    "POLAR_GIT_SERVER_ADMINS",
    "identities, comma-separated, that may do anything to every repository and create new ones, \
     in addition to the `admins` in POLAR_GIT_SERVER_REPOS: the DNS name in the certificate of \
     each person (their account's identity) or workload. Kept apart from the repositories because \
     who administers a server is a fact about the deployment, and the repositories are not",
);

static VARIABLES: &[&dyn Described] = &[
    &PORT,
    &REPO_ROOT,
    &LOG_ROOT,
    &SEED_ROOT,
    &REPOS,
    &ADMINS,
    &CA_CERT,
    &DEPLOYMENT_CA,
    &WITNESS_KEY,
];

pub static SECTION: Section = Section {
    name: "polar-git-server",
    vars: VARIABLES,
    relations: |env| {
        one_key(env, &SERVER_KEY_FILE, KEY_DOC)
            .err()
            .map(|e| e.to_string())
            .into_iter()
            .collect()
    },
};

pub struct GitServerSettings {
    pub port: u16,
    pub repo_root: String,
    pub log_root: String,
    pub seed_root: String,
    pub repos: String,
    pub admins: Vec<String>,
    pub ca_cert: String,
    pub deployment_ca: Option<String>,
}

impl GitServerSettings {
    pub fn read(config: &Config) -> Result<Self, ConfigError> {
        Ok(Self {
            port: config.read(&PORT)?,
            repo_root: config.read(&REPO_ROOT)?,
            log_root: config.read(&LOG_ROOT)?,
            seed_root: config.read(&SEED_ROOT)?,
            repos: config.read(&REPOS)?,
            admins: config.read(&ADMINS)?.unwrap_or_default(),
            ca_cert: config.read(&CA_CERT)?,
            deployment_ca: config.read(&DEPLOYMENT_CA)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// The Cassini client's variables, as the pod gives them: its key a file, or with the custody socket the daemon's.
    const CLIENT: [(&str, &str); 4] = [
        ("TLS_CLIENT_CERT", "/c/client-cert.pem"),
        ("TLS_CA_CERT", "/c/ca.pem"),
        ("BROKER_ADDR", "cassini:8080"),
        ("CASSINI_SERVER_NAME", "cassini"),
    ];

    fn config(pairs: &[(&str, &str)]) -> Config {
        let custody = pairs.iter().any(|(k, _)| *k == "POLAR_CUSTODY_SOCKET");
        let client_key = (!custody).then_some(("TLS_CLIENT_KEY", "/c/client-key.pem"));
        let env: HashMap<String, String> = CLIENT
            .iter()
            .chain(client_key.iter())
            .chain(pairs.iter())
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        // As the agent registers them: the builder's base sections (the crypto actor's `keys`, which declares the custody
        // socket, among them), its own section, and the Cassini client's.
        polar_agent_builder::environment::base_sections()
            .into_iter()
            .fold(Config::builder(&env), |builder, section| {
                builder.register(section)
            })
            .register(&SECTION)
            .register(&cassini_client::environment::SECTION)
            .build()
    }

    const ALL: [(&str, &str); 5] = [
        ("POLAR_GIT_SERVER_REPO_ROOT", "/data"),
        ("POLAR_GIT_SERVER_REPOS", "{}"),
        ("TLS_SERVER_CERT_CHAIN", "/c/cert.pem"),
        ("TLS_SERVER_KEY", "/c/key.pem"),
        ("POLAR_GIT_SERVER_CA_CERT", "/c/ca.pem"),
    ];

    /// The witness's key is pinned in its signed settings (infra/seed.nu, `witness_pins`): with the sections it
    /// registers, an update naming it is taken.
    #[test]
    fn the_witness_s_key_is_a_settings_update_it_takes() {
        let witness = "attestation-agent.polar.serviceaccount.cluster.local/witness+00000000+AAAA";
        let mut config = config(&ALL);
        assert_eq!(
            config.apply_overrides(&[(WITNESS_KEY.desc().name, witness)]),
            Ok(vec![WITNESS_KEY.desc().name])
        );
        assert_eq!(WITNESS_KEY.read(&config).unwrap().as_deref(), Some(witness));
    }

    #[test]
    fn the_section_is_sound_and_its_defaults_parse() {
        assert_eq!(SECTION.defaults_problems(), Vec::<String>::new());
    }

    #[test]
    fn no_administrators_are_named_unless_the_deployment_names_them() {
        assert_eq!(
            GitServerSettings::read(&config(&ALL)).unwrap().admins,
            Vec::<String>::new()
        );
        let mut set = ALL.to_vec();
        set.push(("POLAR_GIT_SERVER_ADMINS", "uuid-one, uuid-two"));
        assert_eq!(
            GitServerSettings::read(&config(&set)).unwrap().admins,
            vec!["uuid-one", "uuid-two"]
        );
    }

    #[test]
    fn the_port_is_8443_unless_set() {
        assert_eq!(GitServerSettings::read(&config(&ALL)).unwrap().port, 8443);
        let mut set = ALL.to_vec();
        set.push(("POLAR_GIT_SERVER_PORT", "9443"));
        assert_eq!(GitServerSettings::read(&config(&set)).unwrap().port, 9443);
    }

    #[test]
    fn what_the_server_cannot_do_without_is_a_problem_before_it_starts() {
        let problems = config(&[]).check();
        for name in [
            "POLAR_GIT_SERVER_REPO_ROOT",
            "POLAR_GIT_SERVER_REPOS",
            "POLAR_GIT_SERVER_CA_CERT",
        ] {
            assert!(
                problems.iter().any(|p| p.contains(name)),
                "{name}: {problems:?}"
            );
        }
        assert!(config(&ALL).check().is_empty());
        // The key is judged with the custody socket, once the variables it is judged with are given.
        let mut keyless = ALL.to_vec();
        keyless.retain(|(k, _)| *k != "TLS_SERVER_KEY");
        let problems = config(&keyless).check().join(" | ");
        assert!(
            problems.contains("TLS_SERVER_KEY") && problems.contains("POLAR_CUSTODY_SOCKET"),
            "{problems}"
        );
    }

    // docs/architecture/key-custody.md, step 4: the server's key may be the custody daemon's server slot.
    #[test]
    fn the_key_may_be_the_custody_daemon_s_and_is_one_or_the_other() {
        let mut custody = ALL.to_vec();
        custody.retain(|(k, _)| *k != "TLS_SERVER_KEY");
        custody.push(("POLAR_CUSTODY_SOCKET", "/run/polar-custody/custody.sock"));
        assert!(config(&custody).check().is_empty());
        let mut both = ALL.to_vec();
        both.push(("POLAR_CUSTODY_SOCKET", "/run/polar-custody/custody.sock"));
        assert!(config(&both).check().join(" | ").contains("set one"));
        assert!(config(&ALL).check().is_empty());
    }
}
