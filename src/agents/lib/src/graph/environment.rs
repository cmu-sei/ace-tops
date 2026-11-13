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

//! The environment the graph controller reads, each variable declared once.
//!
//! [`GraphSettings::from_env`] is the one place these are read and the one place the rule
//! between the TLS variables lives, so the controller, the agent builder's startup check and
//! the render-time checker cannot disagree about what a sound graph environment is.

use polar_env::{Described, Env, EnvError, Optional, Required, Section};

pub const GRAPH_DB: Required<String> = Required::text("GRAPH_DB", "the Neo4j database name");
pub const GRAPH_USER: Required<String> = Required::text("GRAPH_USER", "the Neo4j user");
pub const GRAPH_PASSWORD: Required<String> =
    Required::text("GRAPH_PASSWORD", "the Neo4j user's password").secret();
pub const GRAPH_ENDPOINT: Required<String> = Required::text(
    "GRAPH_ENDPOINT",
    "the Neo4j address, for example bolt+s://host:7687",
);
pub const GRAPH_CA_CERT: Optional<String> = Optional::path(
    "GRAPH_CA_CERT",
    polar_env::Access::ReadFile,
    "path to the CA certificate Neo4j's certificate is verified against; set, the agent connects over mutual TLS, presenting its own client certificate, the crypto actor's",
);

static VARIABLES: &[&dyn Described] = &[
    &GRAPH_DB,
    &GRAPH_USER,
    &GRAPH_PASSWORD,
    &GRAPH_ENDPOINT,
    &GRAPH_CA_CERT,
];

/// How the controller secures its connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphTls {
    /// Mutual TLS: verify the server against the CA, and present the agent's own client certificate. The pod has one
    /// client certificate, presented to Neo4j as to Cassini, and its TLS is the crypto actor's (docs/plans/crypto-actor.md):
    /// the controller is given the configuration, and reads no key.
    Mutual { ca: String },
    /// No TLS configuration beyond what the endpoint scheme implies.
    None,
}

/// Everything the graph controller reads.
#[derive(Debug, Clone)]
pub struct GraphSettings {
    pub database: String,
    pub user: String,
    pub password: String,
    pub endpoint: String,
    pub tls: GraphTls,
}

impl GraphSettings {
    /// Reads and judges the graph environment. Every problem is reported together, each
    /// naming the variable and what it is for.
    pub fn from_env(env: &dyn Env) -> Result<Self, String> {
        let mut problems = Vec::new();
        let mut take = |read: Result<String, EnvError>| match read {
            Ok(value) => value,
            Err(error) => {
                problems.push(error.to_string());
                String::new()
            }
        };
        let database = take(GRAPH_DB.read(env));
        let user = take(GRAPH_USER.read(env));
        let password = take(GRAPH_PASSWORD.read(env));
        let endpoint = take(GRAPH_ENDPOINT.read(env));

        let tls = match GRAPH_CA_CERT.read(env) {
            Ok(Some(ca)) => GraphTls::Mutual { ca },
            Ok(None) => GraphTls::None,
            Err(error) => {
                problems.push(error.to_string());
                GraphTls::None
            }
        };

        if !problems.is_empty() {
            return Err(problems.join("; "));
        }
        Ok(Self {
            database,
            user,
            password,
            endpoint,
            tls,
        })
    }
}

/// What must hold between the graph variables. Run only when each parses.
fn relations(env: &dyn Env) -> Vec<String> {
    match GraphSettings::from_env(env) {
        Ok(_) => Vec::new(),
        Err(problem) => vec![problem],
    }
}

/// What the graph controller reads. Applies to every agent with the graph-write capability.
pub static SECTION: Section = Section {
    name: "graph",
    vars: VARIABLES,
    relations,
};

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

    const BASE: &[(&str, &str)] = &[
        ("GRAPH_DB", "neo4j"),
        ("GRAPH_USER", "neo4j"),
        ("GRAPH_PASSWORD", "hunter2"),
        ("GRAPH_ENDPOINT", "bolt+s://db:7687"),
    ];

    fn with(extra: &[(&'static str, &'static str)]) -> HashMap<String, String> {
        env(&[BASE, extra].concat())
    }

    #[test]
    fn no_tls_variables_means_no_tls_configuration() {
        let s = GraphSettings::from_env(&env(BASE)).unwrap();
        assert_eq!(s.tls, GraphTls::None);
        assert_eq!(
            (s.database.as_str(), s.endpoint.as_str()),
            ("neo4j", "bolt+s://db:7687")
        );
    }

    /// The CA alone makes mutual TLS: the agent presents its own client certificate, whose key is the crypto actor's.
    #[test]
    fn the_ca_makes_mutual_tls_with_the_agent_s_own_key() {
        let s = GraphSettings::from_env(&with(&[("GRAPH_CA_CERT", "/ca.pem")])).unwrap();
        assert_eq!(
            s.tls,
            GraphTls::Mutual {
                ca: "/ca.pem".into()
            }
        );
    }

    /// The agent's key variables are the crypto actor's: the graph reads none of them, set or not.
    #[test]
    fn the_agent_s_key_variables_say_nothing_to_the_graph() {
        let keys = [
            ("GRAPH_CLIENT_CERT", "/c.pem"),
            ("GRAPH_CLIENT_KEY", "/k.pem"),
            ("TLS_CLIENT_KEY", "/k.pem"),
            ("POLAR_CUSTODY_SOCKET", "/custody/custody.sock"),
        ];
        assert_eq!(
            GraphSettings::from_env(&with(&keys)).unwrap().tls,
            GraphTls::None
        );
        let with_ca = [&keys[..], &[("GRAPH_CA_CERT", "/ca.pem")][..]].concat();
        assert_eq!(
            GraphSettings::from_env(&with(&with_ca)).unwrap().tls,
            GraphTls::Mutual {
                ca: "/ca.pem".into()
            }
        );
    }

    #[test]
    fn the_section_judges_as_the_controller_reads() {
        for given in [&[][..], &[("GRAPH_CA_CERT", "/ca.pem")][..]] {
            let env = with(given);
            assert_eq!(
                SECTION.check(&env).is_empty(),
                GraphSettings::from_env(&env).is_ok(),
                "{given:?}"
            );
        }
        let missing = env(&[("GRAPH_CA_CERT", "/ca.pem")]);
        assert_eq!(
            SECTION.check(&missing).is_empty(),
            GraphSettings::from_env(&missing).is_ok()
        );
    }

    #[test]
    fn every_missing_required_variable_is_named() {
        let error = GraphSettings::from_env(&env(&[])).unwrap_err();
        for name in ["GRAPH_DB", "GRAPH_USER", "GRAPH_PASSWORD", "GRAPH_ENDPOINT"] {
            assert!(error.contains(name), "{name}: {error}");
        }
    }

    #[test]
    fn the_password_is_never_in_a_message() {
        let error = GraphSettings::from_env(&env(&[("GRAPH_PASSWORD", "hunter2")])).unwrap_err();
        assert!(!error.contains("hunter2"), "{error}");
        let described = SECTION.describe();
        assert!(
            described
                .iter()
                .any(|v| v.name == "GRAPH_PASSWORD" && v.secret)
        );
    }

    #[test]
    fn the_section_judges_the_same_rule() {
        assert!(SECTION.check(&env(BASE)).is_empty());
        assert!(
            SECTION
                .check(&with(&[("GRAPH_CA_CERT", "/ca.pem")]))
                .is_empty()
        );
        assert!(
            !SECTION
                .check(&env(&[("GRAPH_CA_CERT", "/ca.pem")]))
                .is_empty()
        );
    }
}
