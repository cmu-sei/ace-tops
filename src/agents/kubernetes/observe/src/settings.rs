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

//! What kube-observer reads from its configuration, declared once: how long a watch that ended waits before it is asked
//! for again. The API's address and the token are the ones Kubernetes gives every pod, and no variable of its.

use crate::watches::Waits;
use polar_env::{Config, Defaulted, Described, Env, Section};
use std::time::Duration;

pub static LOST_SECS: Defaulted<u64> = Defaulted::seconds(
    "POLAR_KUBE_WATCH_LOST_SECS",
    "how long a watch that lost the Kubernetes API waits before it is asked for again, in seconds; at least 1",
    "5",
)
.dynamic();

pub static REFUSED_SECS: Defaulted<u64> = Defaulted::seconds(
    "POLAR_KUBE_WATCH_REFUSED_SECS",
    "how long a watch the Kubernetes API refused, or of a kind it does not serve, waits before it is asked for again, \
     in seconds; at least 1. Flux's kinds are not in every cluster",
    "300",
)
.dynamic();

pub static VARIABLES: &[&dyn Described] = &[&LOST_SECS, &REFUSED_SECS];

fn relations(env: &dyn Env) -> Vec<String> {
    [
        (LOST_SECS.read(env), LOST_SECS.name()),
        (REFUSED_SECS.read(env), REFUSED_SECS.name()),
    ]
    .into_iter()
    .filter(|(secs, _)| matches!(secs, Ok(0)))
    .map(|(_, name)| format!("{name} must be at least 1"))
    .collect()
}

/// The section kube-observer registers.
pub static SECTION: Section = Section {
    name: "kube-observer",
    vars: VARIABLES,
    relations,
};

/// The waits in force.
pub fn waits(config: &Config) -> Result<Waits, String> {
    Ok(Waits {
        lost: Duration::from_secs(config.read(&LOST_SECS).map_err(|e| e.to_string())?),
        refused: Duration::from_secs(config.read(&REFUSED_SECS).map_err(|e| e.to_string())?),
    })
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
    fn the_waits_are_what_they_were_unless_the_deployment_says_otherwise() {
        assert_eq!(SECTION.defaults_problems(), Vec::<String>::new());
        assert_eq!(
            waits(&config(&[])).unwrap(),
            Waits {
                lost: Duration::from_secs(5),
                refused: Duration::from_secs(300)
            }
        );
    }

    #[test]
    fn a_wait_of_nothing_is_refused() {
        for name in [
            "POLAR_KUBE_WATCH_LOST_SECS",
            "POLAR_KUBE_WATCH_REFUSED_SECS",
        ] {
            let said = config(&[(name, "0")]).check();
            assert_eq!(said.len(), 1, "{said:?}");
            assert!(said[0].contains(name), "{said:?}");
        }
    }
}
