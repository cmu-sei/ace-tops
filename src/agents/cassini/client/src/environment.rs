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

//! The environment a Cassini client reads, each variable declared once.
//!
//! The client needs to know where the broker is and which certificates to present. Those
//! were read with `env::var("X")?`, whose error says only that a variable was not found and
//! never which. They are declared here instead, so a missing one is named with what it is
//! for, and [`SECTION`] lets anything that judges an environment (the agent builder at
//! startup, the render-time checker for the pod a workload will get) judge these too.

use polar_env::{Described, Env, Optional, Required, Section};

pub const TLS_CLIENT_CERT: Required<String> = Required::path(
    "TLS_CLIENT_CERT",
    polar_env::Access::ReadFile,
    "path to this agent's client certificate, which it presents to the broker",
);

// Read here by name, to say a client has its key; declared by the crypto actor's `keys` section, which the client never
// reads a key through (docs/plans/crypto-actor.md).
const TLS_CLIENT_KEY: Optional<String> = Optional::path(
    "TLS_CLIENT_KEY",
    polar_env::Access::ReadFile,
    "path to the private key for this agent's client certificate",
);
const CUSTODY_SOCKET: Optional<String> = Optional::path(
    "POLAR_CUSTODY_SOCKET",
    polar_env::Access::Socket,
    "path to the custody daemon's socket",
);

pub const TLS_CA_CERT: Required<String> = Required::path(
    "TLS_CA_CERT",
    polar_env::Access::ReadFile,
    "path to the CA certificate the broker's certificate is verified against",
);

pub const BROKER_ADDR: Required<String> =
    Required::text("BROKER_ADDR", "the broker's address, host:port");

pub const CASSINI_SERVER_NAME: Required<String> = Required::text(
    "CASSINI_SERVER_NAME",
    "the name on the broker's certificate, which the connection is verified against",
);

pub const CASSINI_QUEUE_PATH: Optional<String> = Optional::path(
    "CASSINI_QUEUE_PATH",
    polar_env::Access::WriteFile,
    "where the client keeps a local queue of messages it could not deliver (none when unset)",
);

// Where the client's key is (TLS_CLIENT_KEY, POLAR_CUSTODY_SOCKET) is declared once, by the crypto actor's `keys`
// section, which the builder registers for every agent (docs/plans/crypto-actor.md); this section still requires that a
// client has its key, below. Its certificate is its identity, and declared here.
static VARIABLES: &[&dyn Described] = &[
    &TLS_CLIENT_CERT,
    &TLS_CA_CERT,
    &BROKER_ADDR,
    &CASSINI_SERVER_NAME,
    &CASSINI_QUEUE_PATH,
];

/// What a Cassini client reads. Applies to every agent that connects to the broker.
pub static SECTION: Section = Section {
    name: "cassini-client",
    vars: VARIABLES,
    relations: |env| key_problem(env).into_iter().collect(),
};

/// That a client is given its key, a file or the custody daemon's, or what is wrong; that it is not given both is the
/// `keys` section's to say.
pub fn key_problem(env: &dyn Env) -> Option<String> {
    let given = |var: &Optional<String>| matches!(var.read(env), Ok(Some(_)));
    (!given(&TLS_CLIENT_KEY) && !given(&CUSTODY_SOCKET)).then(|| {
        format!(
            "neither {} nor {} is set: the client's key is a file, or the custody daemon holds it",
            TLS_CLIENT_KEY.name(),
            CUSTODY_SOCKET.name()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CassiniSettings;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    const ALL: &[(&str, &str)] = &[
        ("TLS_CLIENT_CERT", "/c/cert.pem"),
        ("TLS_CLIENT_KEY", "/c/key.pem"),
        ("TLS_CA_CERT", "/c/ca.pem"),
        ("BROKER_ADDR", "cassini:8080"),
        ("CASSINI_SERVER_NAME", "cassini.local"),
    ];

    #[test]
    fn a_complete_environment_gives_the_client_its_coordinates() {
        let config = CassiniSettings::from_env(&env(ALL)).unwrap();
        assert_eq!(config.client_certificate_path, "/c/cert.pem");
        assert_eq!(config.ca_certificate_path, "/c/ca.pem");
        assert_eq!(config.broker_endpoint, "cassini:8080");
        assert_eq!(config.server_name, "cassini.local");
    }

    #[test]
    fn every_missing_variable_is_named_with_what_it_is_for() {
        let error =
            CassiniSettings::from_env(&env(&[("BROKER_ADDR", "cassini:8080")])).unwrap_err();
        for name in [
            "TLS_CLIENT_CERT",
            "TLS_CLIENT_KEY",
            "TLS_CA_CERT",
            "CASSINI_SERVER_NAME",
        ] {
            assert!(error.contains(name), "{name} missing from: {error}");
        }
        assert!(!error.contains("BROKER_ADDR"), "{error}");
        assert!(error.contains("broker"), "says what they are for: {error}");
    }

    #[test]
    fn a_blank_variable_counts_as_missing() {
        let mut pairs = ALL.to_vec();
        pairs.retain(|(k, _)| *k != "BROKER_ADDR");
        pairs.push(("BROKER_ADDR", "  "));
        let error = CassiniSettings::from_env(&env(&pairs)).unwrap_err();
        assert!(error.contains("BROKER_ADDR"), "{error}");
    }

    #[test]
    fn the_section_checks_the_same_things_the_client_needs() {
        assert!(SECTION.check(&env(ALL)).is_empty());
        // The four required; that the client has a key, a file or the socket, is judged once they are given, as a relation.
        let problems = SECTION.check(&env(&[]));
        assert_eq!(problems.len(), 4, "{problems:?}");
        let mut pairs = ALL.to_vec();
        pairs.retain(|(k, _)| *k != "TLS_CLIENT_KEY");
        let problems = SECTION.check(&env(&pairs));
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("TLS_CLIENT_KEY"), "{problems:?}");
        assert!(problems[0].contains("POLAR_CUSTODY_SOCKET"), "{problems:?}");
    }

    /// Every way the two can be given (unset, blank, a path): the client has a key when either is, and the section and
    /// the reading say the same. That not both are given is the crypto actor's `keys` section's to say, not the client's;
    /// the client reads no key, so which one it is is not its business.
    #[test]
    fn a_client_has_its_key_when_a_key_file_or_the_custody_socket_is_given() {
        let states = [None, Some("  "), Some("/given")];
        let given = |v: Option<&str>| v.is_some_and(|v| !v.trim().is_empty());
        for key in states {
            for socket in states {
                let mut pairs = ALL.to_vec();
                pairs.retain(|(k, _)| *k != "TLS_CLIENT_KEY");
                pairs.extend(key.map(|v| ("TLS_CLIENT_KEY", v)));
                pairs.extend(socket.map(|v| ("POLAR_CUSTODY_SOCKET", v)));
                let read = CassiniSettings::from_env(&env(&pairs));
                let judged = SECTION.check(&env(&pairs));
                assert_eq!(judged.is_empty(), read.is_ok(), "{pairs:?}: {judged:?}");
                assert_eq!(
                    read.is_ok(),
                    given(key) || given(socket),
                    "{pairs:?}: {read:?}"
                );
                if let Err(error) = read {
                    assert!(error.contains("TLS_CLIENT_KEY"), "{error}");
                    assert!(error.contains("POLAR_CUSTODY_SOCKET"), "{error}");
                }
            }
        }
    }

    #[test]
    fn the_queue_path_is_optional() {
        assert!(
            SECTION
                .describe()
                .iter()
                .any(|v| v.name == "CASSINI_QUEUE_PATH")
        );
        assert!(SECTION.check(&env(ALL)).is_empty());
    }
}
