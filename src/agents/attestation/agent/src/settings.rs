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

//! The variables the attestation agent reads itself.

use polar_env::{Described, Env, Required, Section};

/// Which namespaces it watches: those its Role in each lets it read, which the capability `pod-read` renders from the same list.
pub static NAMESPACES: Required<String> = Required::text(
    "POLAR_ATTESTATION_NAMESPACES",
    "the namespaces whose pods the attestation agent attests, comma-separated: Polar's own (docs/architecture/runtime-attestation.md)",
);

/// The deployment CA's certificate, which the record is checked against. Trusted for that alone.
pub static DEPLOYMENT_CA: Required<String> = Required::path(
    "POLAR_ATTESTATION_DEPLOYMENT_CA",
    polar_env::Access::ReadFile,
    "path to the deployment CA's certificate (PEM), which the signed record of the deployment chains to (docs/architecture/runtime-attestation.md); it has no other authority here",
);

/// Where the witness of the store's logs keeps its key and what it holds: a directory on the agent's own volume
/// (docs/architecture/runtime-attestation.md, "The witness of the store's logs").
pub static WITNESS_ROOT: Required<String> = Required::text(
    "POLAR_ATTESTATION_WITNESS_ROOT",
    "the directory on the agent's own volume where the witness of the store's logs keeps its key and the checkpoints it co-signed (docs/architecture/runtime-attestation.md, \"The witness of the store's logs\")",
);

// The store whose logs it witnesses (POLAR_ATTESTATION_WITNESSED_STORE) and where its co-signing key is
// (POLAR_WITNESS_COSIGNING_KEY) are the crypto actor's `keys` section's to declare, which every agent registers: a
// variable is declared once (polar_crypto::environment, which the builder re-exports).

static VARIABLES: &[&dyn Described] = &[&NAMESPACES, &DEPLOYMENT_CA, &WITNESS_ROOT];

/// The section the attestation agent registers.
pub static SECTION: Section = Section {
    name: "attestation",
    vars: VARIABLES,
    relations,
};

fn relations(env: &dyn Env) -> Vec<String> {
    if NAMESPACES.read(env).is_ok_and(|raw| parse(&raw).is_empty()) {
        vec![format!(
            "{} must name at least one namespace",
            NAMESPACES.name()
        )]
    } else {
        Vec::new()
    }
}

fn parse(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(String::from)
        .collect()
}

/// Where the deployment CA's certificate is, from the agent's snapshot.
pub fn deployment_ca(env: &dyn Env) -> Result<String, String> {
    DEPLOYMENT_CA.read(env).map_err(|e| e.to_string())
}

/// Where the witness keeps what it holds, from the agent's snapshot.
pub fn witness_root(env: &dyn Env) -> Result<String, String> {
    WITNESS_ROOT.read(env).map_err(|e| e.to_string())
}

/// The namespaces, from the agent's snapshot.
pub fn namespaces(env: &dyn Env) -> Result<Vec<String>, String> {
    NAMESPACES
        .read(env)
        .map(|raw| parse(&raw))
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn its_namespaces_are_a_list_and_not_an_empty_one() {
        let given = |value: &'static str| {
            move |name: &str| (name == "POLAR_ATTESTATION_NAMESPACES").then(|| value.to_string())
        };
        assert_eq!(
            namespaces(&given("polar, polar-graph,,polar-auth")).unwrap(),
            ["polar", "polar-graph", "polar-auth"]
        );
        assert!(relations(&given(" , ")).len() == 1);
        assert!(relations(&given("polar")).is_empty());
        assert!(namespaces(&|_: &str| None).is_err());
    }

    /// The store it witnesses is pinned in its signed settings (infra/seed.nu, `witness_pins`): with the sections it
    /// registers, an update naming the store's key is taken, and one that is not a store's key is refused.
    #[test]
    fn the_store_it_witnesses_is_a_settings_update_it_takes() {
        let env: std::collections::HashMap<String, String> = [
            ("POLAR_ATTESTATION_NAMESPACES", "polar"),
            ("POLAR_ATTESTATION_DEPLOYMENT_CA", "/c/ca.pem"),
            ("POLAR_ATTESTATION_WITNESS_ROOT", "/w"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let config = || {
            polar_agent_builder::environment::base_sections()
                .into_iter()
                .fold(polar_env::Config::builder(&env), |builder, section| {
                    builder.register(section)
                })
                .register(&SECTION)
                .build()
        };
        let pin = polar_agent_builder::crypto::WITNESSED_STORE.desc().name;
        let store = polar_agent_builder::crypto::EXAMPLE_STORE;
        assert_eq!(config().apply_overrides(&[(pin, store)]), Ok(vec![pin]));
        assert!(config().apply_overrides(&[(pin, "not a key")]).is_err());
    }
}
