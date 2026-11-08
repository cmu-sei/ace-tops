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

//! What build-processor reads from its configuration, declared once: how long a started build may go unheard of before
//! it is judged lost (`crate::aging`). Dynamic, so a signed update changes it in a running agent.

use polar_env::{Config, Defaulted, Described, Env, Section};
use std::time::Duration;

/// The bound a deployment that says nothing has: a day, since a build may take hours. Held by the test that the
/// declared default is it.
pub const DEFAULT_LOST_AFTER: Duration = Duration::from_secs(86_400);

/// The least bound: a build is heard of at its start and its stages, and a minute is shorter than any of them.
const LEAST_SECS: u64 = 60;

pub static LOST_AFTER_SECS: Defaulted<u64> = Defaulted::seconds(
    "POLAR_BUILD_LOST_AFTER_SECS",
    "how long a started build may go unheard of (its start or any of its stages) before build-processor judges it lost, \
     in seconds; at least 60. Whether a build is still doing anything is a monitoring signal; until that is read, a \
     bounded time ends it",
    "86400",
)
.dynamic();

pub static VARIABLES: &[&dyn Described] = &[&LOST_AFTER_SECS];

fn relations(env: &dyn Env) -> Vec<String> {
    match LOST_AFTER_SECS.read(env) {
        Ok(secs) if secs < LEAST_SECS => vec![format!(
            "{} must be at least {LEAST_SECS}",
            LOST_AFTER_SECS.name()
        )],
        _ => Vec::new(),
    }
}

/// The section build-processor registers.
pub static SECTION: Section = Section {
    name: "build-processor",
    vars: VARIABLES,
    relations,
};

/// The bound in force.
pub fn lost_after(config: &Config) -> Result<Duration, String> {
    Ok(Duration::from_secs(
        config.read(&LOST_AFTER_SECS).map_err(|e| e.to_string())?,
    ))
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
    fn the_section_is_sound_and_its_defaults_parse() {
        assert_eq!(SECTION.defaults_problems(), Vec::<String>::new());
    }

    #[test]
    fn a_day_unless_the_deployment_says_otherwise() {
        assert_eq!(lost_after(&config(&[])).unwrap(), DEFAULT_LOST_AFTER);
        assert!(config(&[]).check().is_empty());
        assert_eq!(
            lost_after(&config(&[("POLAR_BUILD_LOST_AFTER_SECS", "7200")])).unwrap(),
            Duration::from_secs(7200)
        );
    }

    #[test]
    fn a_bound_under_a_minute_is_refused() {
        assert!(
            config(&[("POLAR_BUILD_LOST_AFTER_SECS", "60")])
                .check()
                .is_empty()
        );
        assert!(
            !config(&[("POLAR_BUILD_LOST_AFTER_SECS", "59")])
                .check()
                .is_empty()
        );
    }
}
