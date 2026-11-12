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

static VARIABLES: &[&dyn Described] = &[&NAMESPACES, &DEPLOYMENT_CA];

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
}
