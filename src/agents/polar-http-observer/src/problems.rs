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

//! What is wrong with the sources right now, as one standing problem for the agent's health. Nothing outside looks into a
//! domain, so this is how an operator hears that a source has stopped working: asking the agent, or the state agent's record
//! of it, says which one and why. It does not end the agent, and the other sources go on.

use polar_agent_builder::{HealthHandle, HoldReason};
use std::collections::BTreeMap;

/// How many sources a standing problem names. The health report's message is short.
const NAMED: usize = 3;

/// The problem each source has, by how many reads in a row have had one.
#[derive(Debug)]
pub struct SourceProblems {
    /// How many in a row make it a standing problem, so a blip is not reported as one.
    threshold: u32,
    sources: BTreeMap<String, (u32, String)>,
}

impl SourceProblems {
    pub fn new(threshold: u32) -> Self {
        Self {
            threshold,
            sources: BTreeMap::new(),
        }
    }

    pub fn failed(&mut self, source: &str, why: impl Into<String>) {
        let entry = self
            .sources
            .entry(source.to_string())
            .or_insert((0, String::new()));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = why.into();
    }

    pub fn succeeded(&mut self, source: &str) {
        self.sources.remove(source);
    }

    /// Forgets every source not named: one taken out of the list has no problem any more.
    pub fn keep_only<'a>(&mut self, sources: impl IntoIterator<Item = &'a str>) {
        let kept: Vec<&str> = sources.into_iter().collect();
        self.sources.retain(|name, _| kept.contains(&name.as_str()));
    }

    /// The standing problem, if there is one.
    pub fn standing(&self) -> Option<String> {
        let standing: Vec<(&String, &String)> = self
            .sources
            .iter()
            .filter(|(_, (count, _))| *count >= self.threshold)
            .map(|(name, (_, why))| (name, why))
            .collect();
        if standing.is_empty() {
            return None;
        }
        let named: Vec<String> = standing
            .iter()
            .take(NAMED)
            .map(|(name, why)| format!("`{name}`: {why}"))
            .collect();
        let more = standing.len().saturating_sub(NAMED);
        Some(if more == 0 {
            named.join("; ")
        } else {
            format!("{}; and {more} more", named.join("; "))
        })
    }
}

/// What health should be told, so it is told once and only when that changes.
#[derive(Debug, PartialEq, Eq)]
pub enum HealthChange {
    Hold(String),
    Release,
}

/// What health was last told.
#[derive(Debug, Default)]
pub struct Reported {
    held: Option<String>,
}

impl Reported {
    /// What to tell health, given what should stand now.
    pub fn next(&mut self, wanted: Option<String>) -> Option<HealthChange> {
        if self.held == wanted {
            return None;
        }
        self.held = wanted.clone();
        Some(match wanted {
            Some(message) => HealthChange::Hold(message),
            None => HealthChange::Release,
        })
    }

    /// Makes health say what should stand now. A restart does not help a source, so it is a configuration problem to the
    /// health actor: held and said, with the agent left running.
    pub fn tell(&mut self, health: &HealthHandle, wanted: Option<String>) {
        match self.next(wanted) {
            Some(HealthChange::Hold(message)) => health.hold(HoldReason::Configuration, message),
            Some(HealthChange::Release) => health.release(HoldReason::Configuration),
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn a_blip_is_not_a_standing_problem_and_a_second_in_a_row_is() {
        let mut problems = SourceProblems::new(2);
        problems.failed("a", "it answered 503");
        assert_eq!(problems.standing(), None);
        problems.succeeded("a");
        problems.failed("a", "it answered 503");
        assert_eq!(problems.standing(), None, "the run was broken by a success");
        problems.failed("a", "it answered 404");
        assert_eq!(problems.standing().unwrap(), "`a`: it answered 404");
    }

    #[test]
    fn it_says_which_sources_and_how_many_more() {
        let mut problems = SourceProblems::new(1);
        for name in ["a", "b", "c", "d", "e"] {
            problems.failed(name, "no");
        }
        assert_eq!(
            problems.standing().unwrap(),
            "`a`: no; `b`: no; `c`: no; and 2 more"
        );
    }

    #[test]
    fn a_source_taken_out_of_the_list_has_no_problem_any_more() {
        let mut problems = SourceProblems::new(1);
        problems.failed("gone", "no");
        problems.failed("kept", "no");
        problems.keep_only(["kept", "other"]);
        assert_eq!(problems.standing().unwrap(), "`kept`: no");
    }

    #[test]
    fn health_is_told_once_and_only_when_it_changes() {
        let mut reported = Reported::default();
        assert_eq!(reported.next(None), None, "nothing was held");
        let a = || Some("a".to_string());
        assert_eq!(
            reported.next(a()),
            Some(HealthChange::Hold("a".to_string()))
        );
        assert_eq!(reported.next(a()), None);
        assert_eq!(
            reported.next(Some("b".to_string())),
            Some(HealthChange::Hold("b".to_string()))
        );
        assert_eq!(reported.next(None), Some(HealthChange::Release));
        assert_eq!(reported.next(None), None);
    }

    proptest! {
        /// After any events: a source stands exactly when its last `threshold` events all failed.
        #[test]
        fn a_source_stands_exactly_when_its_latest_reads_all_failed(
            threshold in 1u32..4,
            events in prop::collection::vec(any::<bool>(), 0..24),
        ) {
            let mut problems = SourceProblems::new(threshold);
            for failed in &events {
                if *failed { problems.failed("a", "no") } else { problems.succeeded("a") }
            }
            let run = events.iter().rev().take_while(|failed| **failed).count() as u32;
            prop_assert_eq!(problems.standing().is_some(), run >= threshold);
        }

        /// Whatever the sequence, what was last told is what was last wanted.
        #[test]
        fn what_health_was_told_ends_as_what_was_wanted(
            wanted in prop::collection::vec(prop::option::of("[ab]"), 0..16),
        ) {
            let mut reported = Reported::default();
            let mut told: Option<String> = None;
            for w in &wanted {
                match reported.next(w.clone()) {
                    Some(HealthChange::Hold(m)) => told = Some(m),
                    Some(HealthChange::Release) => told = None,
                    None => {}
                }
                prop_assert_eq!(&told, w);
            }
        }
    }
}
