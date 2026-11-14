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

//! The environment the crypto actor reads, each variable declared once.
//!
//! The actor derives its own identity from the client certificate the pod was issued, believes a
//! recipient's key under the pod's pinned CA, and asks the pod's custody daemon to unwrap what is
//! sealed to its escrow key. The certificate and the CA are the Cassini client's variables (`TLS_CLIENT_CERT`,
//! `TLS_CA_CERT`), declared once by `cassini-client`; the custody socket, `POLAR_CUSTODY_SOCKET`, is declared by
//! `polar-custody` and registered here, in [`KEYS`].

use cassini_client::environment::{TLS_CA_CERT, TLS_CLIENT_CERT};
use polar_custody::environment::CUSTODY_SOCKET;
use polar_env::{Access, Described, Env, Optional, Section};

static VARIABLES: &[&dyn Described] = &[];

/// What the crypto actor reads beyond the Cassini client's own variables. Applies to every
/// agent with the encryption capability, which always has the Cassini client too.
pub static SECTION: Section = Section {
    name: "crypto",
    vars: VARIABLES,
    relations: |_| Vec::new(),
};

/// The agent's client certificate file, read for its TLS only where the custody daemon does not hold its key.
pub const CLIENT_CERT_FILE: Optional<String> = Optional::path(
    "TLS_CLIENT_CERT",
    Access::ReadFile,
    "path to the agent's client certificate (PEM); its TLS presents it with TLS_CLIENT_KEY where no custody daemon holds the key",
);
/// The key of the agent's client certificate, where no custody daemon holds it.
pub const CLIENT_KEY_FILE: Optional<String> = Optional::path(
    "TLS_CLIENT_KEY",
    Access::ReadFile,
    "path to the private key of the agent's client certificate; this or POLAR_CUSTODY_SOCKET, not both",
);
/// The agent's server certificate chain file, read for its TLS only where the custody daemon does not hold its key.
pub const SERVER_CERT_FILE: Optional<String> = Optional::path(
    "TLS_SERVER_CERT_CHAIN",
    Access::ReadFile,
    "path to the agent's own server certificate (PEM); its TLS presents it with TLS_SERVER_KEY where no custody daemon holds the key",
);
/// The key of the agent's server certificate, where no custody daemon holds it.
pub const SERVER_KEY_FILE: Optional<String> = Optional::path(
    "TLS_SERVER_KEY",
    Access::ReadFile,
    "path to the private key of the agent's server certificate; this or POLAR_CUSTODY_SOCKET, not both",
);

/// Where a workload keeps a log's checkpoint key, on its own volume: the crypto actor makes it there once if it is not
/// there, and never replaces it, since readers and witnesses pin it (docs/plans/record-store/to-main.md). Only a workload
/// with the `checkpoints` capability is given it.
pub const STORE_CHECKPOINT_KEY: Optional<String> = Optional::path(
    "POLAR_STORE_CHECKPOINT_KEY",
    Access::WriteFile,
    "path to the private key (PKCS#8 PEM, P-256) the agent signs its logs' checkpoints with; its crypto actor makes it \
     there once if it is not there, and never replaces it",
);

/// Where a witness keeps its co-signing key, on its own volume: the crypto actor makes it there once if it is not there,
/// and never replaces it, since the store and readers pin it (docs/plans/record-store/to-main.md, bite 2).
pub const WITNESS_COSIGNING_KEY: Optional<String> = Optional::path(
    "POLAR_WITNESS_COSIGNING_KEY",
    Access::WriteFile,
    "path to the private key (PKCS#8 PEM, P-256) the agent co-signs a store's checkpoints with, as its witness; its \
     crypto actor makes it there once if it is not there, and never replaces it",
);

/// Where a workload that has no signing key in custody keeps the key it signs its evidence records with, on its own
/// volume: the crypto actor makes it there once if it is not there, and never replaces it (docs/plans/crypto-actor.md).
/// The credentials agent's: it comes up before anything could fetch it a custody signing key. Only a workload with the
/// `record-key` capability is given it.
pub const RECORD_KEY: Optional<String> = Optional::path(
    "POLAR_RECORD_KEY",
    Access::WriteFile,
    "path to the private key (PKCS#8 PEM, P-256) the agent signs its evidence records with, where no custody daemon \
     holds a signing key for it; its crypto actor makes it there once if it is not there, and never replaces it",
);

/// A store's checkpoint verifier key, of a key no store holds: for tests and the scaffold's example.
pub const EXAMPLE_STORE: &str = "polar-git-server.polar.serviceaccount.cluster.local/checkpoint+f857ae4e+AjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABG/wO5SSQc4drdQ1GeaWDgqFtBppoFwygQOqK84VlMoWPE91OlW/AdxT9sCwx+7ni0DG/30lqW4igrmJzvccFEo=";

/// The store a witness co-signs for: its checkpoint verifier key, from the agent's signed configuration, which the
/// crypto actor follows and holds every co-signature to. Its name is the attestation agent's, as the signed
/// configuration already carries it (docs/architecture/runtime-attestation.md, "The witness of the store's logs").
pub static WITNESSED_STORE: Optional<String> = Optional::new(
    "POLAR_ATTESTATION_WITNESSED_STORE",
    "the verifier key of the store's checkpoint key (`<identity>/checkpoint+<id>+<key>`), whose logs the witness \
     co-signs; unset, it co-signs nothing",
    "a store's checkpoint verifier key",
    |raw| crate::checkpoints::pinned_store(raw).map(|_| raw.trim().to_string()),
)
.dynamic()
.example(EXAMPLE_STORE);

// The client certificate (TLS_CLIENT_CERT) is the Cassini client's to declare and require: it is the agent's identity
// certificate, which every Cassini client is given; read here by its name.
static KEY_VARIABLES: &[&dyn Described] = &[
    &CUSTODY_SOCKET,
    &CLIENT_KEY_FILE,
    &SERVER_CERT_FILE,
    &SERVER_KEY_FILE,
    &STORE_CHECKPOINT_KEY,
    &WITNESS_COSIGNING_KEY,
    &WITNESSED_STORE,
    &RECORD_KEY,
];

/// Where the agent's keys are: the custody daemon's socket, or, where a cluster runs without the daemon, its key files.
/// Every agent has a crypto actor (docs/plans/crypto-actor.md), so the builder registers this for every agent and
/// service, and these variables are declared here alone. A component that needs a key (the Cassini client, the broker)
/// says so in its own section's rules.
pub static KEYS: Section = Section {
    name: "keys",
    vars: KEY_VARIABLES,
    relations: key_relations,
};

/// What an agent with the `checkpoints` capability needs of `keys`: where its checkpoint key is.
pub static CHECKPOINTS: Section = Section {
    name: "checkpoints",
    vars: &[],
    relations: |env| match STORE_CHECKPOINT_KEY.read(env) {
        Ok(Some(_)) => Vec::new(),
        Ok(None) => vec![format!(
            "{} is not set: an agent that keeps a log's checkpoint key is told where it is",
            STORE_CHECKPOINT_KEY.name()
        )],
        Err(e) => vec![e.to_string()],
    },
};

/// What an agent with the `record-key` capability needs of `keys`: where its record key is.
pub static RECORD_KEYS: Section = Section {
    name: "record-key",
    vars: &[],
    relations: |env| match RECORD_KEY.read(env) {
        Ok(Some(_)) => Vec::new(),
        Ok(None) => vec![format!(
            "{} is not set: an agent that signs records with a key of its own is told where it is",
            RECORD_KEY.name()
        )],
        Err(e) => vec![e.to_string()],
    },
};

/// A key file goes with its certificate file, and never with the custody daemon's socket: the daemon holds the key, or
/// the file does.
fn key_relations(env: &dyn Env) -> Vec<String> {
    let set = |var: &Optional<String>| matches!(var.read(env), Ok(Some(_)));
    let socket = set(&CUSTODY_SOCKET);
    let mut problems = Vec::new();
    for (certificate, key) in [
        (&CLIENT_CERT_FILE, &CLIENT_KEY_FILE),
        (&SERVER_CERT_FILE, &SERVER_KEY_FILE),
    ] {
        if set(key) && socket {
            problems.push(format!(
                "{} is set as well as {}: the custody daemon holds the key, or the file does; set one",
                key.name(),
                CUSTODY_SOCKET.name()
            ));
        }
        if set(key) && !set(certificate) {
            problems.push(format!(
                "{} is set without {}: a key file goes with its certificate",
                key.name(),
                certificate.name()
            ));
        }
    }
    problems
}

/// The key files an agent was given, as (certificate, key), where the custody daemon does not hold its keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyFiles {
    pub client: Option<(String, String)>,
    pub server: Option<(String, String)>,
    /// A log's checkpoint key, for an agent that keeps one: a key file wherever the custody daemon runs, until custody
    /// can hold a named key that outlives its pod.
    pub checkpoint: Option<String>,
    /// A witness's co-signing key.
    pub cosigning: Option<String>,
    /// The key an agent signs its evidence records with where custody holds none for it.
    pub record: Option<String>,
}

impl KeyFiles {
    /// What `env` names: a pair where both of its variables are set.
    pub fn from_env(env: &dyn Env) -> Result<Self, String> {
        let read = |var: &Optional<String>| var.read(env).map_err(|e| e.to_string());
        let pair = |certificate: Option<String>, key: Option<String>| certificate.zip(key);
        Ok(Self {
            client: pair(read(&CLIENT_CERT_FILE)?, read(&CLIENT_KEY_FILE)?),
            server: pair(read(&SERVER_CERT_FILE)?, read(&SERVER_KEY_FILE)?),
            checkpoint: read(&STORE_CHECKPOINT_KEY)?,
            cosigning: read(&WITNESS_COSIGNING_KEY)?,
            record: read(&RECORD_KEY)?,
        })
    }
}

/// Everything the crypto actor is configured with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CryptoSettings {
    /// The certificate this agent was issued, whose identity the actor takes as its own.
    pub own_certificate_path: String,
    /// The custody daemon's socket, when the pod has one: it holds the escrow key, and unwraps for this actor
    /// (docs/architecture/key-custody.md, "Part A's bootstrap: the custodian").
    pub custody_socket: Option<String>,
    /// The CA the pod pins, which a recipient's escrow certificate must chain to.
    pub ca_cert_path: String,
    /// The agent's key files, for its TLS where the custody daemon does not hold its keys.
    pub key_files: KeyFiles,
}

impl CryptoSettings {
    /// Reads from `env`, naming every variable that is missing or malformed.
    pub fn from_env(env: &dyn Env) -> Result<Self, String> {
        let mut problems = Vec::new();
        let mut take = |read: Result<String, polar_env::EnvError>| match read {
            Ok(value) => value,
            Err(error) => {
                problems.push(error.to_string());
                String::new()
            }
        };
        let own_certificate_path = take(TLS_CLIENT_CERT.read(env));
        let ca_cert_path = take(TLS_CA_CERT.read(env));
        let custody_socket = match CUSTODY_SOCKET.read(env) {
            Ok(socket) => socket.filter(|s| !s.trim().is_empty()),
            Err(error) => {
                problems.push(error.to_string());
                None
            }
        };
        let key_files = KeyFiles::from_env(env).unwrap_or_else(|e| {
            problems.push(e);
            KeyFiles::default()
        });
        if !problems.is_empty() {
            return Err(problems.join("; "));
        }
        Ok(Self {
            own_certificate_path,
            custody_socket,
            ca_cert_path,
            key_files,
        })
    }
}

impl CryptoSettings {
    /// Reads from `env` for an agent that escrows secrets (`escrow`), as [`from_env`](Self::from_env), or for one that
    /// does not: every agent has a crypto actor (docs/plans/crypto-actor.md), and one that does not escrow takes no
    /// identity or pinned CA from it, so neither is read; only the custody daemon's socket.
    pub fn from_env_for(env: &dyn Env, escrow: bool) -> Result<Self, String> {
        if escrow {
            return Self::from_env(env);
        }
        let custody_socket = CUSTODY_SOCKET
            .read(env)
            .map_err(|e| e.to_string())?
            .filter(|s| !s.trim().is_empty());
        let key_files = KeyFiles::from_env(env)?;
        // A checkpoint names its log by the agent's identity, a witness co-signs as its identity, and a record key is
        // certified for it, so an agent that keeps any of these keys reads its own certificate for it, as one that
        // escrows does.
        let keeps_a_key = key_files.checkpoint.is_some()
            || key_files.cosigning.is_some()
            || key_files.record.is_some();
        let own_certificate_path = if keeps_a_key {
            TLS_CLIENT_CERT.read(env).unwrap_or_default()
        } else {
            String::new()
        };
        Ok(Self {
            own_certificate_path,
            custody_socket,
            ca_cert_path: String::new(),
            key_files,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// An agent that does not escrow takes no identity or pinned CA from its crypto actor, set or not; one that escrows
    /// must have both.
    #[test]
    fn an_agent_that_does_not_escrow_needs_no_identity_or_pinned_ca() {
        let none = CryptoSettings::from_env_for(&env(&[]), false).unwrap();
        assert_eq!(
            (
                none.own_certificate_path.as_str(),
                none.ca_cert_path.as_str(),
                none.custody_socket
            ),
            ("", "", None)
        );
        assert!(CryptoSettings::from_env_for(&env(&[]), true).is_err());
        let given = CryptoSettings::from_env_for(
            &env(&[
                ("TLS_CLIENT_CERT", "/c/cert.pem"),
                ("TLS_CA_CERT", "/c/ca.pem"),
                ("POLAR_CUSTODY_SOCKET", "/s"),
            ]),
            false,
        )
        .unwrap();
        assert_eq!(
            (
                given.own_certificate_path.as_str(),
                given.ca_cert_path.as_str(),
                given.custody_socket.as_deref()
            ),
            ("", "", Some("/s"))
        );
    }

    #[test]
    fn the_custody_daemon_s_socket_and_the_pinned_ca_are_the_client_s_own_variables() {
        let s = CryptoSettings::from_env(&env(&[
            ("TLS_CLIENT_CERT", "/c/cert.pem"),
            ("TLS_CA_CERT", "/c/ca.pem"),
            ("POLAR_CUSTODY_SOCKET", "/run/custody/custody.sock"),
        ]))
        .unwrap();
        assert_eq!(
            s.custody_socket.as_deref(),
            Some("/run/custody/custody.sock")
        );
        assert_eq!(s.ca_cert_path, "/c/ca.pem");
        let s = CryptoSettings::from_env(&env(&[
            ("TLS_CLIENT_CERT", "/c/cert.pem"),
            ("TLS_CA_CERT", "/c/ca.pem"),
        ]))
        .unwrap();
        assert_eq!(s.custody_socket, None, "no daemon: no escrow key");
        let error =
            CryptoSettings::from_env(&env(&[("TLS_CLIENT_CERT", "/c/cert.pem")])).unwrap_err();
        assert!(error.contains("TLS_CA_CERT"), "{error}");
    }

    #[test]
    fn a_missing_certificate_path_is_named_with_what_it_is_for() {
        let error = CryptoSettings::from_env(&env(&[])).unwrap_err();
        assert!(error.contains("TLS_CLIENT_CERT"), "{error}");
        assert!(error.contains("certificate"), "{error}");
    }

    /// The token and the kernel key's handle went with the workload's own escrow bootstrap: an old pod's
    /// `KUBERNETES_SA_TOKEN` or `POLAR_ESCROW_KEY_HANDLE` is not declared, so it is not even read.
    #[test]
    fn the_section_declares_nothing_of_its_own() {
        let names: Vec<_> = SECTION.describe().iter().map(|v| v.name).collect();
        assert!(
            names.is_empty(),
            "TLS_CLIENT_CERT is the client's: {names:?}"
        );
        assert!(
            SECTION.check(&env(&[])).is_empty(),
            "nothing in it is required"
        );
    }
}
