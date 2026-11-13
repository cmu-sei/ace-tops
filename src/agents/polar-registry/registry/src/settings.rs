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

//! What polar-registry reads from its configuration, declared once (docs/plans/registry/nix-cache.md):
//!
//! - the deployment's facts, Static: its volume, where it listens, the key its Nix cache signs with, and its upstream
//!   cache with the key that cache is trusted by (a default for each that is not the cluster's to say);
//! - its run-time settings, Dynamic, so a signed update changes them in a running agent: whether faults are taken, and
//!   the largest archive a fault fetches.

use crate::faults::Upstream;
use crate::upstream::{NIX_UPSTREAM, UPSTREAM_VAR};
use polar_agent_builder::protocol::http::MAX_BODY;
use polar_env::{Access, Config, Defaulted, Described, Env, Required, Section};
use polar_registry_nix::signature::PublicKey;

pub static ROOT: Required<String> = Required::path(
    "POLAR_REGISTRY_ROOT",
    Access::WriteDir,
    "the registry's volume: its content store, its Nix cache's narinfos and its record of faults; the pod's own, written \
     by nothing else",
);

pub static LISTEN: Defaulted<String> = Defaulted::text(
    "POLAR_REGISTRY_LISTEN",
    "the address the registry serves on, `address:port`",
    "0.0.0.0:5000",
);

pub static NIX_KEY: Required<String> = Required::path(
    "POLAR_REGISTRY_NIX_KEY",
    Access::ReadFile,
    "the file holding the key the Nix cache signs with, as `nix key generate-secret` writes it (to be held by custody \
     instead: docs/plans/registry/nix-cache.md)",
);

pub static UPSTREAM: Defaulted<String> = Defaulted::text(
    UPSTREAM_VAR,
    "the binary cache a path the Nix cache does not hold is faulted in from, `https://host`; the operation that reaches \
     it is declared at its host (`upstream::NIX_UPSTREAM`)",
    "https://cache.nixos.org",
);

pub static UPSTREAM_KEY: Defaulted<String> = Defaulted::text(
    "POLAR_REGISTRY_NIX_UPSTREAM_KEY",
    "the key the upstream cache is trusted by, as Nix writes a public key: a narinfo from it is taken only when this key \
     signed it",
    "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=",
);

pub static FAULTS: Defaulted<bool> = Defaulted::flag(
    "POLAR_REGISTRY_NIX_FAULTS",
    "whether a path the Nix cache does not hold is faulted in from its upstream; off, it is refused, and the refusal is \
     recorded",
    "false",
)
.dynamic();

pub static MAX_ARCHIVE: Defaulted<u64> = Defaulted::number(
    "POLAR_REGISTRY_NIX_MAX_ARCHIVE",
    "the largest archive a fault fetches, in bytes, as it is sent: at least 1, and no more than the builder's HTTP \
     handler reads of a reply",
    "268435456",
)
.dynamic();

/// The deployment's facts.
pub static DEPLOYMENT: &[&dyn Described] = &[&ROOT, &LISTEN, &NIX_KEY, &UPSTREAM, &UPSTREAM_KEY];

/// The run-time settings, followed as one group.
pub static TUNING: &[&dyn Described] = &[&FAULTS, &MAX_ARCHIVE];

static VARIABLES: &[&dyn Described] = &[
    &ROOT,
    &LISTEN,
    &NIX_KEY,
    &UPSTREAM,
    &UPSTREAM_KEY,
    &FAULTS,
    &MAX_ARCHIVE,
];

/// The section polar-registry registers.
pub static SECTION: Section = Section {
    name: "polar-registry",
    vars: VARIABLES,
    relations,
};

fn relations(env: &dyn Env) -> Vec<String> {
    let mut problems = Vec::new();
    if let Ok(key) = UPSTREAM_KEY.read(env)
        && key.parse::<PublicKey>().is_err()
    {
        problems.push(format!(
            "{} is not a public key as Nix writes one",
            UPSTREAM_KEY.name()
        ));
    }
    if let Ok(url) = UPSTREAM.read(env)
        && !is_cache_address(&url)
    {
        problems.push(format!(
            "{} is not `http(s)://host[:port]`",
            UPSTREAM.name()
        ));
    }
    if let Ok(bytes) = MAX_ARCHIVE.read(env)
        && (bytes == 0 || bytes > MAX_BODY as u64)
    {
        problems.push(format!(
            "{} must be at least 1 and at most {MAX_BODY}, what the HTTP handler reads of a reply",
            MAX_ARCHIVE.name()
        ));
    }
    problems
}

/// Whether `url` is a cache's address: `http://` or `https://`, then a host and maybe a port, and nothing after.
pub fn is_cache_address(url: &str) -> bool {
    let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    else {
        return false;
    };
    !rest.is_empty()
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b))
}

/// Where the registry is, and what it trusts.
#[derive(Debug, Clone)]
pub struct Deployment {
    pub root: String,
    pub listen: String,
    pub nix_key: String,
    pub upstream: Upstream,
}

/// The run-time settings in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tuning {
    pub faults: bool,
    pub max_archive: u64,
}

pub fn deployment(config: &Config) -> Result<Deployment, String> {
    let read = |e: polar_env::ConfigError| e.to_string();
    Ok(Deployment {
        root: config.read(&ROOT).map_err(read)?,
        listen: config.read(&LISTEN).map_err(read)?,
        nix_key: config.read(&NIX_KEY).map_err(read)?,
        upstream: Upstream {
            url: config.read(&UPSTREAM).map_err(read)?,
            key: config
                .read(&UPSTREAM_KEY)
                .map_err(read)?
                .parse()
                .map_err(|e| format!("{}: {e}", UPSTREAM_KEY.name()))?,
            via: NIX_UPSTREAM.name,
        },
    })
}

pub fn tuning(config: &Config) -> Result<Tuning, String> {
    let read = |e: polar_env::ConfigError| e.to_string();
    Ok(Tuning {
        faults: config.read(&FAULTS).map_err(read)?,
        max_archive: config.read(&MAX_ARCHIVE).map_err(read)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_env::Mutability;
    use std::collections::HashMap;

    fn config(pairs: &[(&str, &str)]) -> Config {
        let mut env: HashMap<String, String> = [
            ("POLAR_REGISTRY_ROOT", "/var/lib/polar-registry"),
            ("POLAR_REGISTRY_NIX_KEY", "/etc/polar-registry/nix-key"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        for (k, v) in pairs {
            env.insert(k.to_string(), v.to_string());
        }
        Config::builder(&env).register(&SECTION).build()
    }

    #[test]
    fn the_section_is_sound_and_its_defaults_parse() {
        assert_eq!(SECTION.defaults_problems(), Vec::<String>::new());
    }

    #[test]
    fn every_variable_is_a_fact_or_a_setting() {
        let names =
            |vars: &[&dyn Described]| -> Vec<&str> { vars.iter().map(|v| v.desc().name).collect() };
        let mut both = names(DEPLOYMENT);
        both.extend(names(TUNING));
        assert_eq!(both, names(VARIABLES));
        for var in TUNING {
            assert_eq!(
                var.desc().mutability,
                Mutability::Dynamic,
                "{}",
                var.desc().name
            );
        }
        for var in DEPLOYMENT {
            assert_eq!(
                var.desc().mutability,
                Mutability::Static,
                "{}",
                var.desc().name
            );
        }
    }

    #[test]
    fn the_defaults_are_cache_nixos_org_and_faults_off() {
        let config = config(&[]);
        assert!(config.check().is_empty(), "{:?}", config.check());
        let d = deployment(&config).unwrap();
        assert_eq!(d.upstream.url, "https://cache.nixos.org");
        assert_eq!(d.upstream.key.name, "cache.nixos.org-1");
        assert_eq!(d.upstream.via, NIX_UPSTREAM.name);
        assert_eq!(d.listen, "0.0.0.0:5000");
        assert_eq!(
            tuning(&config).unwrap(),
            Tuning {
                faults: false,
                max_archive: MAX_BODY as u64
            }
        );
    }

    #[test]
    fn an_upstream_key_address_or_bound_that_is_not_one_is_refused() {
        for (name, value) in [
            ("POLAR_REGISTRY_NIX_UPSTREAM_KEY", "not-a-key"),
            ("POLAR_REGISTRY_NIX_UPSTREAM", "ftp://cache.nixos.org"),
            ("POLAR_REGISTRY_NIX_UPSTREAM", "https://cache.nixos.org/nix"),
            ("POLAR_REGISTRY_NIX_UPSTREAM", "https://"),
            ("POLAR_REGISTRY_NIX_MAX_ARCHIVE", "0"),
            ("POLAR_REGISTRY_NIX_MAX_ARCHIVE", "268435457"),
        ] {
            assert!(
                !config(&[(name, value)]).check().is_empty(),
                "{name}={value}"
            );
        }
        for (name, value) in [
            ("POLAR_REGISTRY_NIX_UPSTREAM", "http://127.0.0.1:8080"),
            ("POLAR_REGISTRY_NIX_MAX_ARCHIVE", "1"),
        ] {
            assert!(
                config(&[(name, value)]).check().is_empty(),
                "{name}={value}"
            );
        }
    }
}
