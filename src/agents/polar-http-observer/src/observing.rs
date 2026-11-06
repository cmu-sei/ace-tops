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

//! What the observer decides, apart from the actor that carries it out: given what happened, what to do next. The actor
//! reads, publishes, waits and tells health; this says when, so a property can hold it to a simple model over any
//! sequence of lists, reads and a shutdown (docs/architecture/http-observers.md, "Evidence").

use crate::problems::{HealthChange, Reported, SourceProblems};
use crate::sources::Source;
use polar_agent_builder::protocol::Failure;
use ractor::concurrency::Duration;
use std::collections::BTreeMap;
use tracing::{debug, info, warn};

/// Two reads in a row, so a host's blip is not reported as a problem.
pub const FAILED_READS_TO_REPORT: u32 = 2;

/// What happened.
#[derive(Debug)]
pub enum Event {
    /// The sources in force, whole.
    Sources(Vec<Source>),
    /// It is time to read this source.
    Due {
        name: String,
        generation: u64,
    },
    /// A read came back.
    Read {
        name: String,
        generation: u64,
        outcome: Result<Vec<u8>, Failure>,
    },
    PrepareShutdown,
}

/// What to do next.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// Read a source now, off the actor, and say [`Event::Read`] with what came back.
    Fetch {
        name: String,
        generation: u64,
        url: String,
        /// The credential it is read with, if it names one.
        credential: Option<String>,
    },
    /// Publish what a source said.
    Publish {
        source: String,
        body: Vec<u8>,
    },
    /// Say [`Event::Due`] for it after this long.
    Again {
        name: String,
        generation: u64,
        after: Duration,
    },
    Health(HealthChange),
    /// Nothing more is read or published: the infrastructure may go on with the shutdown.
    ProceedWithShutdown,
}

/// What a read says of a source's health: a problem, or that it is well, or nothing when the host only asked for time.
pub(crate) fn note_read(
    problems: &mut SourceProblems,
    source: &str,
    outcome: &Result<Vec<u8>, Failure>,
) {
    match outcome {
        Ok(_) => problems.succeeded(source),
        Err(Failure::Backoff { .. } | Failure::NotYet { .. }) => {}
        Err(failure) => problems.failed(source, failure.to_string()),
    }
}

/// When a source is read next, given how the last read went: its interval, or longer if the host asked for time.
pub fn next_read(interval: Duration, outcome: &Result<Vec<u8>, Failure>) -> Duration {
    match outcome {
        Err(Failure::Backoff { wait, .. }) | Err(Failure::NotYet { wait }) => interval.max(*wait),
        _ => interval,
    }
}

/// The sources in force, each with a generation, so what was scheduled or read under an older version of a source says so
/// when it comes back and is dropped.
#[derive(Debug, Default)]
struct Schedule {
    sources: BTreeMap<String, (Source, u64)>,
    next_generation: u64,
}

impl Schedule {
    /// Takes a new list whole. What is unchanged keeps its time, what is gone is forgotten, and what is new or changed is
    /// returned, to be read now.
    fn replace(&mut self, sources: Vec<Source>) -> Vec<(String, u64)> {
        let mut kept = BTreeMap::new();
        let mut start = Vec::new();
        for source in sources {
            let name = source.name.clone();
            match self.sources.remove(&name) {
                Some((held, generation)) if held == source => {
                    kept.insert(name, (held, generation));
                }
                _ => {
                    self.next_generation += 1;
                    start.push((name.clone(), self.next_generation));
                    kept.insert(name, (source, self.next_generation));
                }
            }
        }
        self.sources = kept;
        start
    }

    /// The source, if `generation` is still the one in force.
    fn current(&self, name: &str, generation: u64) -> Option<&Source> {
        self.sources
            .get(name)
            .filter(|(_, held)| *held == generation)
            .map(|(source, _)| source)
    }
}

/// An observer's decisions.
#[derive(Debug)]
pub struct Observing {
    schedule: Schedule,
    problems: SourceProblems,
    reported: Reported,
    shutting_down: bool,
}

impl Default for Observing {
    fn default() -> Self {
        Self {
            schedule: Schedule::default(),
            problems: SourceProblems::new(FAILED_READS_TO_REPORT),
            reported: Reported::default(),
            shutting_down: false,
        }
    }
}

impl Observing {
    pub fn on(&mut self, event: Event) -> Vec<Step> {
        let mut steps = Vec::new();
        match event {
            Event::Sources(list) => {
                info!("{} source(s) in force", list.len());
                self.problems
                    .keep_only(list.iter().map(|s| s.name.as_str()));
                self.health(&mut steps);
                for (name, generation) in self.schedule.replace(list) {
                    self.fetch(&name, generation, &mut steps);
                }
            }
            Event::Due { name, generation } => self.fetch(&name, generation, &mut steps),
            Event::Read {
                name,
                generation,
                outcome,
            } => {
                let Some(source) = self.schedule.current(&name, generation) else {
                    debug!("a read of `{name}` came back after its source changed");
                    return steps;
                };
                if self.shutting_down {
                    return steps;
                }
                let after = next_read(Duration::from_secs(source.interval_secs), &outcome);
                note_read(&mut self.problems, &name, &outcome);
                self.health(&mut steps);
                match outcome {
                    Ok(body) => steps.push(Step::Publish {
                        source: name.clone(),
                        body,
                    }),
                    Err(failure) => {
                        warn!("could not read `{name}`, and will try again in {after:?}: {failure}")
                    }
                }
                steps.push(Step::Again {
                    name,
                    generation,
                    after,
                });
            }
            Event::PrepareShutdown => {
                info!("PrepareShutdown received; a read in flight is not published");
                self.shutting_down = true;
                steps.push(Step::ProceedWithShutdown);
            }
        }
        steps
    }

    /// A read of the source, if `generation` is still its own and nothing is shutting down.
    fn fetch(&self, name: &str, generation: u64, steps: &mut Vec<Step>) {
        if let (Some(source), false) = (self.schedule.current(name, generation), self.shutting_down)
        {
            steps.push(Step::Fetch {
                name: name.to_string(),
                generation,
                url: source.url.clone(),
                credential: source.credential.clone(),
            });
        }
    }

    fn health(&mut self, steps: &mut Vec<Step>) {
        if let Some(change) = self.reported.next(self.problems.standing()) {
            steps.push(Step::Health(change));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::sample::Index;
    use std::collections::BTreeSet;

    fn source(name: &str, url: &str, secs: u64) -> Source {
        Source {
            name: name.to_string(),
            url: url.to_string(),
            interval_secs: secs,
            credential: None,
        }
    }

    /// A generated source: its address, interval and credential, each from a few, so lists repeat and differ by one.
    fn generated(name: &str, (u, secs, credential): &(u8, u64, Option<u8>)) -> Source {
        Source {
            credential: credential.map(|c| format!("credential-{c}")),
            ..source(name, &format!("http://h/{u}"), *secs)
        }
    }

    #[test]
    fn a_failure_or_success_waits_its_interval_and_a_shorter_wait_from_a_host_does_not_shorten_it()
    {
        let interval = Duration::from_secs(600);
        assert_eq!(next_read(interval, &Ok(vec![])), interval);
        assert_eq!(
            next_read(interval, &Err(Failure::Transient("x".into()))),
            interval
        );
        let short = Err(Failure::NotYet {
            wait: Duration::from_secs(1),
        });
        assert_eq!(next_read(interval, &short), interval);
    }

    #[test]
    fn a_failed_read_counts_against_its_source_and_a_host_asking_for_time_does_not() {
        let mut problems = SourceProblems::new(2);
        let failed: Result<Vec<u8>, Failure> = Err(Failure::Read("it answered 404".to_string()));
        let wait = Duration::from_secs(1);
        note_read(&mut problems, "a", &failed);
        note_read(
            &mut problems,
            "a",
            &Err(Failure::Backoff { status: 429, wait }),
        );
        note_read(&mut problems, "a", &Err(Failure::NotYet { wait }));
        assert_eq!(
            problems.standing(),
            None,
            "one failure, and a host asking for time"
        );
        note_read(&mut problems, "a", &failed);
        assert!(problems.standing().unwrap().contains("it answered 404"));
        note_read(&mut problems, "a", &Ok(vec![]));
        assert_eq!(problems.standing(), None);
    }

    #[test]
    fn a_new_list_reads_only_what_is_new_or_changed_and_forgets_what_is_gone() {
        let mut schedule = Schedule::default();
        let started = schedule.replace(vec![
            source("a", "http://h/a", 60),
            source("b", "http://h/b", 60),
        ]);
        assert_eq!(started.len(), 2);
        let a = started.iter().find(|(n, _)| n == "a").unwrap().1;
        let b = started.iter().find(|(n, _)| n == "b").unwrap().1;

        let again = schedule.replace(vec![
            source("a", "http://h/a", 60),
            source("b", "http://h/moved", 60),
            source("c", "http://h/c", 60),
        ]);
        let names: Vec<&str> = again.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["b", "c"]);
        assert!(
            schedule.current("a", a).is_some(),
            "unchanged keeps its time"
        );
        assert!(
            schedule.current("b", b).is_none(),
            "what was scheduled under the old address is dropped"
        );

        assert!(schedule.replace(vec![]).is_empty());
        assert!(schedule.current("a", a).is_none(), "gone");
    }

    #[test]
    fn a_read_is_published_and_the_source_read_again_at_its_interval() {
        let mut observing = Observing::default();
        let steps = observing.on(Event::Sources(vec![source("a", "http://h/a", 60)]));
        let [Step::Fetch { generation, .. }] = steps[..] else {
            panic!("{steps:?}")
        };
        let steps = observing.on(Event::Read {
            name: "a".to_string(),
            generation,
            outcome: Ok(b"{}".to_vec()),
        });
        assert_eq!(
            steps,
            [
                Step::Publish {
                    source: "a".to_string(),
                    body: b"{}".to_vec()
                },
                Step::Again {
                    name: "a".to_string(),
                    generation,
                    after: Duration::from_secs(60)
                }
            ]
        );
        assert_eq!(
            observing.on(Event::PrepareShutdown),
            [Step::ProceedWithShutdown]
        );
        assert!(
            observing
                .on(Event::Due {
                    name: "a".to_string(),
                    generation
                })
                .is_empty(),
            "nothing is read while shutting down"
        );
    }

    proptest! {
        /// After any sequence of lists: exactly the last list is in force, each at one generation.
        #[test]
        fn the_schedule_holds_exactly_the_last_list(
            lists in prop::collection::vec(prop::collection::btree_map("[a-c]", (0u8..3, 60u64..63), 0..4), 1..6)
        ) {
            let mut schedule = Schedule::default();
            let mut last = Vec::new();
            for list in lists {
                last = list.into_iter().map(|(n, (u, s))| source(&n, &format!("http://h/{u}"), s)).collect::<Vec<_>>();
                schedule.replace(last.clone());
            }
            let held: Vec<Source> = schedule.sources.values().map(|(s, _)| s.clone()).collect();
            prop_assert_eq!(held, last);
        }
    }

    /// What can happen to an observer, with a generation picked from those it has handed out, so stale ones come back.
    #[derive(Debug, Clone)]
    enum Happens {
        Sources(BTreeMap<String, (u8, u64, Option<u8>)>),
        Due(String, Index),
        Read(String, Index, Outcome),
        PrepareShutdown,
    }

    #[derive(Debug, Clone)]
    enum Outcome {
        Document(u8),
        Failed,
        Backoff(u64),
        NotYet(u64),
    }

    impl Outcome {
        fn result(&self) -> Result<Vec<u8>, Failure> {
            match self {
                Outcome::Document(b) => Ok(vec![*b]),
                Outcome::Failed => Err(Failure::Read("it answered 404".to_string())),
                Outcome::Backoff(secs) => Err(Failure::Backoff {
                    status: 429,
                    wait: Duration::from_secs(*secs),
                }),
                Outcome::NotYet(secs) => Err(Failure::NotYet {
                    wait: Duration::from_secs(*secs),
                }),
            }
        }
    }

    fn happens() -> impl Strategy<Value = Happens> {
        let name = || "[a-d]".prop_map(String::from);
        prop_oneof![
            2 => prop::collection::btree_map("[a-c]", (0u8..2, 60u64..62, prop::option::of(0u8..2)), 0..4)
                .prop_map(Happens::Sources),
            3 => (name(), any::<Index>()).prop_map(|(n, g)| Happens::Due(n, g)),
            6 => (name(), any::<Index>(), prop_oneof![
                any::<u8>().prop_map(Outcome::Document),
                Just(Outcome::Failed),
                (0u64..120).prop_map(Outcome::Backoff),
                (0u64..120).prop_map(Outcome::NotYet),
            ]).prop_map(|(n, g, o)| Happens::Read(n, g, o)),
            1 => Just(Happens::PrepareShutdown),
        ]
    }

    proptest! {
        /// Held to a model over any sequence: a source is read only at the generation its latest version was given and
        /// while it is listed; a read is published only then, and the source read again once, at its interval or the
        /// host's longer wait; nothing is read or published once shutting down; and health holds exactly the sources
        /// whose last two reads failed, a host asking for time counting for neither.
        #[test]
        fn an_observer_does_what_the_model_says_after_any_events(
            events in prop::collection::vec(happens(), 1..40)
        ) {
            let mut observing = Observing::default();
            // The model.
            let mut listed: BTreeMap<String, Source> = BTreeMap::new();
            let mut live: BTreeMap<String, u64> = BTreeMap::new();
            let mut failures: BTreeMap<String, u32> = BTreeMap::new();
            let mut shut = false;
            let mut issued: Vec<u64> = vec![0];
            let mut told: Option<String> = None;

            for happened in events {
                let pick = |g: &Index| issued[g.index(issued.len())];
                let steps = match &happened {
                    Happens::Sources(list) => {
                        let list: Vec<Source> = list
                            .iter()
                            .map(|(n, generating)| generated(n, generating))
                            .collect();
                        let changed: BTreeSet<String> = list
                            .iter()
                            .filter(|s| listed.get(&s.name) != Some(s))
                            .map(|s| s.name.clone())
                            .collect();
                        let steps = observing.on(Event::Sources(list.clone()));
                        let mut fetched = BTreeSet::new();
                        for step in &steps {
                            match step {
                                Step::Fetch { name, generation, url, credential } => {
                                    prop_assert!(!shut);
                                    prop_assert!(!issued.contains(generation), "a new version, a new generation");
                                    let of = list.iter().find(|s| &s.name == name).unwrap();
                                    prop_assert_eq!(url, &of.url);
                                    prop_assert_eq!(credential, &of.credential, "read with the credential it names");
                                    issued.push(*generation);
                                    live.insert(name.clone(), *generation);
                                    fetched.insert(name.clone());
                                }
                                Step::Health(_) => {}
                                other => prop_assert!(false, "{:?}", other),
                            }
                        }
                        if !shut {
                            prop_assert_eq!(fetched, changed.clone(), "what is new or changed is read now, and only that");
                        } else {
                            // Not read, and no longer live: a read of the older version must not count.
                            for name in &changed {
                                live.remove(name);
                            }
                        }
                        listed = list.into_iter().map(|s| (s.name.clone(), s)).collect();
                        live.retain(|name, _| listed.contains_key(name));
                        failures.retain(|name, _| listed.contains_key(name));
                        steps
                    }
                    Happens::Due(name, g) => {
                        let generation = pick(g);
                        let steps = observing.on(Event::Due { name: name.clone(), generation });
                        let expected: Vec<Step> = match (shut, live.get(name)) {
                            (false, Some(held)) if *held == generation => vec![Step::Fetch {
                                name: name.clone(),
                                generation,
                                url: listed[name].url.clone(),
                                credential: listed[name].credential.clone(),
                            }],
                            _ => vec![],
                        };
                        prop_assert_eq!(&steps, &expected);
                        steps
                    }
                    Happens::Read(name, g, outcome) => {
                        let generation = pick(g);
                        let steps = observing.on(Event::Read {
                            name: name.clone(),
                            generation,
                            outcome: outcome.result(),
                        });
                        let current = !shut && live.get(name) == Some(&generation);
                        if !current {
                            prop_assert!(steps.is_empty(), "{:?}", steps);
                        } else {
                            let interval = Duration::from_secs(listed[name].interval_secs);
                            let after = match outcome {
                                Outcome::Backoff(secs) | Outcome::NotYet(secs) => interval.max(Duration::from_secs(*secs)),
                                _ => interval,
                            };
                            let mut expected = Vec::new();
                            if let Outcome::Document(b) = outcome {
                                expected.push(Step::Publish { source: name.clone(), body: vec![*b] });
                            }
                            expected.push(Step::Again { name: name.clone(), generation, after });
                            let others: Vec<&Step> = steps.iter().filter(|s| !matches!(s, Step::Health(_))).collect();
                            prop_assert_eq!(others, expected.iter().collect::<Vec<_>>());
                            match outcome {
                                Outcome::Document(_) => {
                                    failures.remove(name);
                                }
                                Outcome::Failed => *failures.entry(name.clone()).or_default() += 1,
                                Outcome::Backoff(_) | Outcome::NotYet(_) => {}
                            }
                        }
                        steps
                    }
                    Happens::PrepareShutdown => {
                        shut = true;
                        let steps = observing.on(Event::PrepareShutdown);
                        prop_assert_eq!(&steps, &[Step::ProceedWithShutdown]);
                        steps
                    }
                };
                for step in steps {
                    match step {
                        Step::Health(HealthChange::Hold(message)) => told = Some(message),
                        Step::Health(HealthChange::Release) => told = None,
                        _ => {}
                    }
                }
                let standing: Vec<&String> = failures
                    .iter()
                    .filter(|(_, n)| **n >= FAILED_READS_TO_REPORT)
                    .map(|(name, _)| name)
                    .collect();
                prop_assert_eq!(told.is_some(), !standing.is_empty(), "{:?} {:?}", told, failures);
                for name in listed.keys() {
                    let named = told.as_deref().is_some_and(|t| t.contains(&format!("`{name}`")));
                    prop_assert_eq!(named, standing.contains(&name), "{:?} {:?}", told, failures);
                }
            }
        }
    }
}
