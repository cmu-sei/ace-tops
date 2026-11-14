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

//! What polar-git reads from its configuration, declared once.

// Where its server key is (TLS_SERVER_CERT_CHAIN, TLS_SERVER_KEY, POLAR_CUSTODY_SOCKET) is declared once, by the crypto
// actor's `keys` section, and its TLS is the crypto actor's (docs/plans/crypto-actor.md); this section requires only that
// it is given a server certificate, below, since it serves nothing without one.
use polar_crypto::environment::SERVER_CERT_FILE;
use polar_env::{Config, ConfigError, Defaulted, Described, Required, Section};

pub static PORT: Defaulted<u16> = Defaulted::number(
    "POLAR_GIT_PORT",
    "the port polar-git listens on, on every address",
    "8443",
);

pub static REPO_ROOT: Required<String> = Required::path(
    "POLAR_GIT_REPO_ROOT",
    polar_env::Access::WriteDir,
    "the directory people's repositories live in; it must be persistent storage",
);

pub static CA_CERT: Required<String> = Required::path(
    "POLAR_GIT_CA_CERT",
    polar_env::Access::ReadFile,
    "path to the CA certificate (PEM) that every client's certificate must chain to: Polar's",
);

static VARIABLES: &[&dyn Described] = &[&PORT, &REPO_ROOT, &CA_CERT];

pub static SECTION: Section = Section {
    name: "polar-git",
    vars: VARIABLES,
    relations: |env| match SERVER_CERT_FILE.read(env) {
        Ok(Some(_)) => Vec::new(),
        Ok(None) => vec![format!(
            "{} is not set: polar-git serves people over TLS, and its crypto actor needs its server certificate",
            SERVER_CERT_FILE.name()
        )],
        Err(e) => vec![e.to_string()],
    },
};

pub struct PolarGitSettings {
    pub port: u16,
    pub repo_root: String,
    pub ca_cert: String,
}

impl PolarGitSettings {
    pub fn read(config: &Config) -> Result<Self, ConfigError> {
        Ok(Self {
            port: config.read(&PORT)?,
            repo_root: config.read(&REPO_ROOT)?,
            ca_cert: config.read(&CA_CERT)?,
        })
    }
}
