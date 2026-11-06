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

use crate::paging::{Next, Page, PageRequest, Pick};
use crate::problems::{HealthChange, Reported, SourceProblems};
use crate::sources::Source;
use polar_agent_builder::protocol::Failure;
use ractor::concurrency::Duration;
use std::collections::{BTreeMap, VecDeque};
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
    /// A page of a read came back: `page` is which, from 0, and `item` which item's follow-up, as its [`Step::Fetch`] said.
    Read {
        name: String,
        generation: u64,
        page: u32,
        item: Option<u32>,
        outcome: Result<Page, Failure>,
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
        /// Which page of the read this is, from 0: of the source, or of an item's follow-up.
        page: u32,
        /// Which item of the read this follows, from 0; none for a page of the source.
        item: Option<u32>,
        asked: Box<PageRequest>,
    },
    /// Publish what a source said: one page of it, and the origin it was read from.
    Publish {
        source: String,
        origin: String,
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

/// When a source is read next, given how the last read went: its interval, or longer if the host asked for time.
pub fn next_read<T>(interval: Duration, outcome: &Result<T, Failure>) -> Duration {
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
    /// Each read under way, by source: where it is.
    reading: BTreeMap<String, Reading>,
}

impl Default for Observing {
    fn default() -> Self {
        Self {
            schedule: Schedule::default(),
            problems: SourceProblems::new(FAILED_READS_TO_REPORT),
            reported: Reported::default(),
            shutting_down: false,
            reading: BTreeMap::new(),
        }
    }
}

/// Where a read of a source is: the page in hand, of the source or of an item's follow-up, what is left of it, and the
/// first problem it met, which its source is held to when it ends.
#[derive(Debug)]
struct Reading {
    generation: u64,
    /// The source's page in hand, or last read.
    page: u32,
    /// The source's next page, once this page's items are followed.
    next: Option<Next>,
    /// This page's items not yet followed.
    items: VecDeque<serde_json::Map<String, serde_json::Value>>,
    /// Items taken to be followed in this read, which `max_items` bounds.
    taken: u32,
    /// The item being followed, its variables, and its page in hand.
    following: Option<(u32, serde_json::Map<String, serde_json::Value>, u32)>,
    trouble: Option<String>,
}

impl Reading {
    fn awaits(&self, page: u32, item: Option<u32>) -> bool {
        match (&self.following, item) {
            (None, None) => self.page == page,
            (Some((i, _, p)), Some(item)) => *i == item && *p == page,
            _ => false,
        }
    }

    fn note(&mut self, problem: String) {
        self.trouble.get_or_insert(problem);
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
                page,
                item,
                outcome,
            } => self.read(name, generation, page, item, outcome, &mut steps),
            Event::PrepareShutdown => {
                info!("PrepareShutdown received; a read in flight is not published");
                self.shutting_down = true;
                steps.push(Step::ProceedWithShutdown);
            }
        }
        steps
    }

    /// A read of the source from its first page, if `generation` is still its own and nothing is shutting down.
    fn fetch(&mut self, name: &str, generation: u64, steps: &mut Vec<Step>) {
        if let (Some(source), false) = (self.schedule.current(name, generation), self.shutting_down)
        {
            steps.push(Step::Fetch {
                name: name.to_string(),
                generation,
                page: 0,
                item: None,
                asked: Box::new(page_of(source, source.url.clone(), None)),
            });
            self.reading.insert(
                name.to_string(),
                Reading {
                    generation,
                    page: 0,
                    next: None,
                    items: VecDeque::new(),
                    taken: 0,
                    following: None,
                    trouble: None,
                },
            );
        }
    }

    /// A page of a read came back. One not of the read under way, at the place it is, is dropped.
    fn read(
        &mut self,
        name: String,
        generation: u64,
        page: u32,
        item: Option<u32>,
        outcome: Result<Page, Failure>,
        steps: &mut Vec<Step>,
    ) {
        let Some(source) = self.schedule.current(&name, generation).cloned() else {
            debug!("a read of `{name}` came back after its source changed");
            return;
        };
        let awaited = self
            .reading
            .get(&name)
            .is_some_and(|r| r.generation == generation && r.awaits(page, item));
        if self.shutting_down || !awaited {
            return;
        }
        let interval = Duration::from_secs(source.interval_secs);
        let mut reading = self.reading.remove(&name).expect("awaited");
        let page = match outcome {
            Err(failure @ (Failure::Backoff { .. } | Failure::NotYet { .. })) => {
                // The host asked for time: the read ends, and nothing is asked of it before then.
                let after = next_read(interval, &Err::<(), _>(failure.clone()));
                warn!("`{name}` asked for time, and is read again in {after:?}: {failure}");
                return self.end(name, generation, reading, after, true, steps);
            }
            Err(failure) if item.is_none() => {
                warn!("could not read `{name}`, and will try again in {interval:?}: {failure}");
                reading.note(failure.to_string());
                return self.end(name, generation, reading, interval, false, steps);
            }
            Err(failure) => {
                // One item's follow-up failing is a problem for the source; the read goes on to the next item.
                warn!(
                    "could not follow item {} of `{name}`: {failure}",
                    item.unwrap_or_default()
                );
                reading.note(format!("an item's follow-up: {failure}"));
                reading.following = None;
                return self.advance(name, generation, &source, reading, steps);
            }
            Ok(page_read) => page_read,
        };
        steps.push(Step::Publish {
            source: name.clone(),
            origin: crate::sources::origin(&source.url),
            body: page.body,
        });
        let each = source.graphql.as_ref().and_then(|g| g.each.as_ref());
        match (&mut reading.following, each) {
            (Some((_, _, item_page)), Some(each)) => {
                let max_pages = each.paging.as_ref().map_or(1, |p| p.max_pages);
                match page.next {
                    Some(Next::After(cursor)) if *item_page + 1 < max_pages => {
                        *item_page += 1;
                        let (index, variables, item_page) = reading.following.clone().expect("following");
                        steps.push(Step::Fetch {
                            name: name.clone(),
                            generation,
                            page: item_page,
                            item: Some(index),
                            asked: Box::new(follow_up(&source, each, variables, Some(cursor))),
                        });
                        self.reading.insert(name, reading);
                        return;
                    }
                    Some(_) => reading.note(format!(
                        "an item's follow-up has more than its {max_pages} page(s): its paging's `max_pages` bounds one item"
                    )),
                    None => {}
                }
                reading.following = None;
            }
            _ => {
                let max_pages = source.paging.as_ref().map_or(1, |p| p.max_pages);
                match page.next {
                    Some(next) if page_after(reading.page) < max_pages => reading.next = Some(next),
                    Some(_) => reading.note(format!(
                        "{max_pages} page(s) were read and the host names more: its paging's `max_pages` bounds one read"
                    )),
                    None => {}
                }
                if let Some(each) = each {
                    for variables in page.items {
                        if reading.taken < each.max_items {
                            reading.taken += 1;
                            reading.items.push_back(variables);
                        } else {
                            reading.note(format!(
                                "more than {} items were read: its `each`'s `max_items` bounds one read",
                                each.max_items
                            ));
                        }
                    }
                }
                if page.unfollowable > 0 {
                    reading.note(format!(
                        "{} item(s) lack a variable their follow-up takes, and were not followed",
                        page.unfollowable
                    ));
                }
            }
        }
        self.advance(name, generation, &source, reading, steps);
    }

    /// The read's next page: the next item's follow-up, else the source's next page, else the read is done.
    fn advance(
        &mut self,
        name: String,
        generation: u64,
        source: &Source,
        mut reading: Reading,
        steps: &mut Vec<Step>,
    ) {
        let each = source.graphql.as_ref().and_then(|g| g.each.as_ref());
        if let (Some(each), Some(variables)) = (each, reading.items.pop_front()) {
            let index = reading.taken - reading.items.len() as u32 - 1;
            steps.push(Step::Fetch {
                name: name.clone(),
                generation,
                page: 0,
                item: Some(index),
                asked: Box::new(follow_up(source, each, variables.clone(), None)),
            });
            reading.following = Some((index, variables, 0));
            self.reading.insert(name, reading);
            return;
        }
        if let Some(next) = reading.next.take() {
            reading.page = page_after(reading.page);
            let (url, after) = match next {
                Next::At(url) => (url, None),
                Next::After(cursor) => (source.url.clone(), Some(cursor)),
            };
            steps.push(Step::Fetch {
                name: name.clone(),
                generation,
                page: reading.page,
                item: None,
                asked: Box::new(page_of(source, url, after)),
            });
            self.reading.insert(name, reading);
            return;
        }
        let interval = Duration::from_secs(source.interval_secs);
        self.end(name, generation, reading, interval, false, steps);
    }

    /// The read is over: its source is held to the first problem it met, or is well, and is read again `after` this. A host
    /// that asked for time says nothing of the source's health.
    fn end(
        &mut self,
        name: String,
        generation: u64,
        reading: Reading,
        after: Duration,
        host_asked_for_time: bool,
        steps: &mut Vec<Step>,
    ) {
        match (reading.trouble, host_asked_for_time) {
            (Some(problem), _) => self.problems.failed(&name, problem),
            (None, false) => self.problems.succeeded(&name),
            (None, true) => {}
        }
        self.health(steps);
        steps.push(Step::Again {
            name,
            generation,
            after,
        });
    }

    fn health(&mut self, steps: &mut Vec<Step>) {
        if let Some(change) = self.reported.next(self.problems.standing()) {
            steps.push(Step::Health(change));
        }
    }
}

fn page_after(page: u32) -> u32 {
    page.saturating_add(1)
}

/// A page of the source: at `url`, after `after` for a GraphQL page past the first, its items picked when it follows them.
fn page_of(source: &Source, url: String, after: Option<String>) -> PageRequest {
    let graphql = source.graphql.as_ref();
    PageRequest {
        url,
        credential: source.credential.clone(),
        paging: source.paging.as_ref().map(|p| p.style.clone()),
        query: graphql.map(|g| g.query.clone()),
        after,
        variables: serde_json::Map::new(),
        pick: graphql.and_then(|g| g.each.as_ref()).map(|each| Pick {
            items: each.items.clone(),
            variables: each.variables.clone(),
        }),
    }
}

/// A page of an item's follow-up: the source's own address, the follow-up's query with the item's variables.
fn follow_up(
    source: &Source,
    each: &crate::graphql::Each,
    variables: serde_json::Map<String, serde_json::Value>,
    after: Option<String>,
) -> PageRequest {
    PageRequest {
        url: source.url.clone(),
        credential: source.credential.clone(),
        paging: each.paging.as_ref().map(|p| p.style.clone()),
        query: Some(each.query.clone()),
        after,
        variables,
        pick: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graphql::{Each, GraphQl, Variable};
    use crate::paging::{Next, Paging, Style};
    use proptest::prelude::*;
    use proptest::sample::Index;
    use std::collections::BTreeSet;

    fn source(name: &str, url: &str, secs: u64) -> Source {
        Source {
            name: name.to_string(),
            url: url.to_string(),
            interval_secs: secs,
            credential: None,
            paging: None,
            graphql: None,
        }
    }

    /// A generated source: its address, interval, credential and paging, each from a few, so lists repeat and differ by
    /// one; a GraphQL one may follow each item of its pages, at most a few, by pages of its own.
    fn generated(name: &str, (u, secs, credential, pages, graphql, each): &Generated) -> Source {
        Source {
            credential: credential.map(|c| format!("credential-{c}")),
            paging: pages.map(|max_pages| Paging {
                style: if *graphql {
                    Style::GraphQl {
                        connection: "/data/c".to_string(),
                    }
                } else {
                    Style::Link
                },
                max_pages: u32::from(max_pages),
            }),
            graphql: graphql.then(|| GraphQl {
                query: "query($after: String) { c(after: $after) { pageInfo { endCursor hasNextPage } } }".to_string(),
                each: each.map(|(max_items, follow_pages)| Each {
                    items: "/data/c/nodes".to_string(),
                    query: "query($id: ID!, $after: String) { i(id: $id) { d(after: $after) { pageInfo { endCursor hasNextPage } } } }".to_string(),
                    variables: vec![Variable { name: "id".to_string(), from: "/id".to_string() }],
                    paging: follow_pages.map(|max_pages| Paging {
                        style: Style::GraphQl { connection: "/data/i/d".to_string() },
                        max_pages: u32::from(max_pages),
                    }),
                    max_items: u32::from(max_items),
                }),
            }),
            ..source(name, &format!("http://h/{u}"), *secs)
        }
    }

    /// A source's address, interval, credential, pages, whether it is a GraphQL query, and what it follows each item with.
    type Generated = (
        u8,
        u64,
        Option<u8>,
        Option<u8>,
        bool,
        Option<(u8, Option<u8>)>,
    );

    fn item_vars(id: u32) -> serde_json::Map<String, serde_json::Value> {
        serde_json::Map::from_iter([("id".to_string(), serde_json::json!(id))])
    }

    #[test]
    fn a_failure_or_success_waits_its_interval_and_a_shorter_wait_from_a_host_does_not_shorten_it()
    {
        let interval = Duration::from_secs(600);
        assert_eq!(next_read(interval, &Ok::<_, Failure>(vec![0u8])), interval);
        assert_eq!(
            next_read(interval, &Err::<(), _>(Failure::Transient("x".into()))),
            interval
        );
        let short: Result<(), Failure> = Err(Failure::NotYet {
            wait: Duration::from_secs(1),
        });
        assert_eq!(next_read(interval, &short), interval);
    }

    /// A read that fails counts against its source, twice in a row a problem; a host asking for time counts neither way;
    /// a read that comes back whole clears it.
    #[test]
    fn a_failed_read_counts_against_its_source_and_a_host_asking_for_time_does_not() {
        let mut observing = Observing::default();
        let steps = observing.on(Event::Sources(vec![source("a", "http://h/a", 60)]));
        let [Step::Fetch { generation, .. }] = steps[..] else {
            panic!("{steps:?}")
        };
        let mut read = |outcome: Result<Page, Failure>| {
            let steps = observing.on(Event::Read {
                name: "a".to_string(),
                generation,
                page: 0,
                item: None,
                outcome,
            });
            let held = steps.iter().find_map(|s| match s {
                Step::Health(HealthChange::Hold(m)) => Some(Some(m.clone())),
                Step::Health(HealthChange::Release) => Some(None),
                _ => None,
            });
            observing.on(Event::Due {
                name: "a".to_string(),
                generation,
            });
            held
        };
        let failed = || Err(Failure::Read("it answered 404".to_string()));
        let wait = Duration::from_secs(1);
        assert_eq!(read(failed()), None, "one failure is a blip");
        assert_eq!(read(Err(Failure::Backoff { status: 429, wait })), None);
        assert_eq!(read(Err(Failure::NotYet { wait })), None);
        let held = read(failed()).expect("a change").expect("held");
        assert!(held.contains("it answered 404"), "{held}");
        let whole = Page {
            body: vec![],
            next: None,
            items: vec![],
            unfollowable: 0,
        };
        assert_eq!(read(Ok(whole)), Some(None), "released");
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
        let steps = observing.on(Event::Sources(vec![source(
            "a",
            "https://h.example:8443/a?x=1",
            60,
        )]));
        let [Step::Fetch { generation, .. }] = steps[..] else {
            panic!("{steps:?}")
        };
        let steps = observing.on(Event::Read {
            name: "a".to_string(),
            generation,
            page: 0,
            item: None,
            outcome: Ok(Page {
                body: b"{}".to_vec(),
                next: None,
                items: vec![],
                unfollowable: 0,
            }),
        });
        assert_eq!(
            steps,
            [
                Step::Publish {
                    source: "a".to_string(),
                    origin: "https://h.example:8443".to_string(),
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

    /// What can happen to an observer, with a generation picked from those it has handed out, so stale ones come back. A
    /// read names the place it is of, or `None` for wherever the read under way is, so reads mostly land where they are
    /// awaited and sometimes do not.
    #[derive(Debug, Clone)]
    enum Happens {
        Sources(BTreeMap<String, Generated>),
        Due(String, Index),
        Read(String, Index, Option<(u32, Option<u32>)>, Outcome),
        PrepareShutdown,
    }

    #[derive(Debug, Clone)]
    enum Outcome {
        /// A page: its byte, the next page if it names one (by cursor, true, or by address), how many items it holds, and
        /// how many of them lack a variable.
        Document(u8, Option<(bool, u8)>, u8, u8),
        Failed,
        Backoff(u64),
        NotYet(u64),
    }

    fn happens() -> impl Strategy<Value = Happens> {
        let name = || "[a-d]".prop_map(String::from);
        let generated = (
            0u8..2,
            60u64..62,
            prop::option::of(0u8..2),
            prop::option::of(1u8..3),
            any::<bool>(),
            prop::option::of((1u8..4, prop::option::of(1u8..3))),
        );
        prop_oneof![
            2 => prop::collection::btree_map("[a-c]", generated, 0..4).prop_map(Happens::Sources),
            3 => (name(), any::<Index>()).prop_map(|(n, g)| Happens::Due(n, g)),
            10 => (name(), any::<Index>(), prop::option::weighted(0.15, (0u32..3, prop::option::of(0u32..3))), prop_oneof![
                6 => (any::<u8>(), prop::option::of((any::<bool>(), 0u8..3)), prop_oneof![1 => Just(0u8), 3 => 1u8..4], prop_oneof![4 => Just(0u8), 1 => Just(1u8)])
                    .prop_map(|(b, n, i, u)| Outcome::Document(b, n, i, u)),
                2 => Just(Outcome::Failed),
                1 => (0u64..120).prop_map(Outcome::Backoff),
                1 => (0u64..120).prop_map(Outcome::NotYet),
            ]).prop_map(|(n, g, at, o)| Happens::Read(n, g, at, o)),
            1 => Just(Happens::PrepareShutdown),
        ]
    }

    /// A read under way, as the model holds it.
    #[derive(Debug, Clone)]
    struct ModelRead {
        generation: u64,
        page: u32,
        next: Option<Next>,
        items: VecDeque<u32>,
        taken: u32,
        following: Option<(u32, u32, u32)>,
        trouble: bool,
    }

    /// What a page of the source is asked with, as the spec says: its address, its query and cursor, its items picked.
    fn source_page(source: &Source, url: String, after: Option<String>) -> PageRequest {
        let each = source.graphql.as_ref().and_then(|g| g.each.as_ref());
        PageRequest {
            url,
            credential: source.credential.clone(),
            paging: source.paging.as_ref().map(|p| p.style.clone()),
            query: source.graphql.as_ref().map(|g| g.query.clone()),
            after,
            variables: serde_json::Map::new(),
            pick: each.map(|e| Pick {
                items: e.items.clone(),
                variables: e.variables.clone(),
            }),
        }
    }

    /// What a page of an item's follow-up is asked with: the source's address, the follow-up's query, the item's id.
    fn item_page(source: &Source, id: u32, after: Option<String>) -> PageRequest {
        let each = source
            .graphql
            .as_ref()
            .and_then(|g| g.each.as_ref())
            .expect("each");
        PageRequest {
            url: source.url.clone(),
            credential: source.credential.clone(),
            paging: each.paging.as_ref().map(|p| p.style.clone()),
            query: Some(each.query.clone()),
            after,
            variables: item_vars(id),
            pick: None,
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]
        /// Held to a model over any sequence: a read is taken only at the place it is (the source's page in hand, or the
        /// item and follow-up page in hand) and at its source's generation, while listed and not shutting down; a page is
        /// published, its items queued up to `max_items`, each item's follow-up read to its last page within its bound,
        /// then the source's next page within its bound, then the read ends and waits its interval; a source page that
        /// fails ends the read, an item's follow-up that fails is a problem and the read goes on, a host asking for time
        /// ends the read and says nothing of health; and health holds exactly the sources whose last two reads met a
        /// problem.
        #[test]
        fn an_observer_does_what_the_model_says_after_any_events(
            events in prop::collection::vec(happens(), 1..60)
        ) {
            let mut observing = Observing::default();
            let mut listed: BTreeMap<String, Source> = BTreeMap::new();
            let mut live: BTreeMap<String, u64> = BTreeMap::new();
            let mut reads: BTreeMap<String, ModelRead> = BTreeMap::new();
            let mut failures: BTreeMap<String, u32> = BTreeMap::new();
            let mut shut = false;
            let mut issued: Vec<u64> = vec![0];
            let mut told: Option<String> = None;
            let mut item_ids: u32 = 0;

            let start = |name: &str, generation: u64, reads: &mut BTreeMap<String, ModelRead>| {
                reads.insert(name.to_string(), ModelRead {
                    generation, page: 0, next: None, items: VecDeque::new(), taken: 0, following: None, trouble: false,
                });
            };

            for happened in events {
                let pick = |g: &Index| issued[g.index(issued.len())];
                let mut expected: Vec<Step> = Vec::new();
                let steps = match &happened {
                    Happens::Sources(list) => {
                        let list: Vec<Source> = list.iter().map(|(n, g)| generated(n, g)).collect();
                        let changed: BTreeSet<String> = list
                            .iter()
                            .filter(|s| listed.get(&s.name) != Some(s))
                            .map(|s| s.name.clone())
                            .collect();
                        let steps = observing.on(Event::Sources(list.clone()));
                        let mut fetched = BTreeSet::new();
                        for step in &steps {
                            match step {
                                Step::Fetch { name, generation, page, item, asked } => {
                                    prop_assert!(!shut);
                                    prop_assert!(!issued.contains(generation), "a new version, a new generation");
                                    let of = list.iter().find(|s| &s.name == name).unwrap();
                                    prop_assert_eq!((*page, *item), (0, None), "a read starts at its first page");
                                    prop_assert_eq!(asked.as_ref(), &source_page(of, of.url.clone(), None));
                                    issued.push(*generation);
                                    live.insert(name.clone(), *generation);
                                    start(name, *generation, &mut reads);
                                    fetched.insert(name.clone());
                                }
                                Step::Health(_) => {}
                                other => prop_assert!(false, "{:?}", other),
                            }
                        }
                        if !shut {
                            prop_assert_eq!(fetched, changed.clone(), "what is new or changed is read now, and only that");
                        } else {
                            for name in &changed {
                                live.remove(name);
                                reads.remove(name);
                            }
                        }
                        listed = list.into_iter().map(|s| (s.name.clone(), s)).collect();
                        live.retain(|name, _| listed.contains_key(name));
                        reads.retain(|name, _| listed.contains_key(name));
                        failures.retain(|name, _| listed.contains_key(name));
                        for step in &steps {
                            if let Step::Health(HealthChange::Hold(m)) = step { told = Some(m.clone()); }
                            if let Step::Health(HealthChange::Release) = step { told = None; }
                        }
                        // This event's steps are checked above, and health against the failures below.
                        steps
                    }
                    Happens::Due(name, g) => {
                        let generation = pick(g);
                        let steps = observing.on(Event::Due { name: name.clone(), generation });
                        if let (false, Some(held)) = (shut, live.get(name)) && *held == generation {
                            let source = &listed[name];
                            expected.push(Step::Fetch {
                                name: name.clone(), generation, page: 0, item: None,
                                asked: Box::new(source_page(source, source.url.clone(), None)),
                            });
                            start(name, generation, &mut reads);
                        }
                        steps
                    }
                    Happens::Read(name, g, at, outcome) => {
                        let generation = pick(g);
                        // Wherever the read under way is, or the place named.
                        let (page, item) = match (at, reads.get(name)) {
                            (Some(at), _) => *at,
                            (None, Some(r)) => match r.following {
                                Some((index, _, p)) => (p, Some(index)),
                                None => (r.page, None),
                            },
                            (None, None) => (0, None),
                        };
                        let ids: Vec<u32> = match outcome {
                            Outcome::Document(_, _, n, _) => (0..u32::from(*n)).map(|_| { item_ids += 1; item_ids }).collect(),
                            _ => vec![],
                        };
                        let result = match outcome {
                            Outcome::Document(b, next, _, unfollowable) => Ok(Page {
                                body: vec![*b],
                                next: next.map(|(cursor, n)| if cursor { Next::After(format!("c{n}")) } else { Next::At(format!("http://h/next/{n}")) }),
                                items: ids.iter().map(|id| item_vars(*id)).collect(),
                                unfollowable: usize::from(*unfollowable),
                            }),
                            Outcome::Failed => Err(Failure::Read("it answered 404".to_string())),
                            Outcome::Backoff(secs) => Err(Failure::Backoff { status: 429, wait: Duration::from_secs(*secs) }),
                            Outcome::NotYet(secs) => Err(Failure::NotYet { wait: Duration::from_secs(*secs) }),
                        };
                        let steps = observing.on(Event::Read { name: name.clone(), generation, page, item, outcome: result });
                        let awaited = !shut
                            && live.get(name) == Some(&generation)
                            && reads.get(name).is_some_and(|r| r.generation == generation && match r.following {
                                Some((index, _, p)) => item == Some(index) && page == p,
                                None => item.is_none() && page == r.page,
                            });
                        if awaited {
                            let source = listed[name].clone();
                            let each = source.graphql.as_ref().and_then(|g| g.each.as_ref()).cloned();
                            let interval = Duration::from_secs(source.interval_secs);
                            let mut read = reads.remove(name).unwrap();
                            // Whether the read ends now, after how long, and whether the host asked for time.
                            let mut ended: Option<(Duration, bool)> = None;
                            match outcome {
                                Outcome::Backoff(secs) | Outcome::NotYet(secs) => {
                                    ended = Some((interval.max(Duration::from_secs(*secs)), true));
                                }
                                Outcome::Failed if item.is_none() => {
                                    read.trouble = true;
                                    ended = Some((interval, false));
                                }
                                Outcome::Failed => {
                                    read.trouble = true;
                                    read.following = None;
                                }
                                Outcome::Document(b, next, _, unfollowable) => {
                                    expected.push(Step::Publish { source: name.clone(), origin: "http://h".to_string(), body: vec![*b] });
                                    match (read.following, &each) {
                                        (Some((index, id, p)), Some(each)) => {
                                            let max = each.paging.as_ref().map_or(1, |p| p.max_pages);
                                            match next {
                                                Some((true, n)) if p + 1 < max => {
                                                    read.following = Some((index, id, p + 1));
                                                    expected.push(Step::Fetch {
                                                        name: name.clone(), generation, page: p + 1, item: Some(index),
                                                        asked: Box::new(item_page(&source, id, Some(format!("c{n}")))),
                                                    });
                                                }
                                                Some(_) => { read.trouble = true; read.following = None; }
                                                None => read.following = None,
                                            }
                                        }
                                        _ => {
                                            let max = source.paging.as_ref().map_or(1, |p| p.max_pages);
                                            match next {
                                                Some((cursor, n)) if read.page + 1 < max => {
                                                    read.next = Some(if *cursor { Next::After(format!("c{n}")) } else { Next::At(format!("http://h/next/{n}")) });
                                                }
                                                Some(_) => read.trouble = true,
                                                None => {}
                                            }
                                            if let Some(each) = &each {
                                                for id in &ids {
                                                    if read.taken < each.max_items {
                                                        read.taken += 1;
                                                        read.items.push_back(*id);
                                                    } else {
                                                        read.trouble = true;
                                                    }
                                                }
                                            }
                                            if *unfollowable > 0 {
                                                read.trouble = true;
                                            }
                                        }
                                    }
                                }
                            }
                            // Then the next page of the read: an item's, the source's, or none, and the read ends.
                            if ended.is_none() && !matches!(expected.last(), Some(Step::Fetch { .. })) {
                                if let (Some(each), Some(id)) = (&each, read.items.pop_front()) {
                                    let _ = each;
                                    let index = read.taken - read.items.len() as u32 - 1;
                                    read.following = Some((index, id, 0));
                                    expected.push(Step::Fetch {
                                        name: name.clone(), generation, page: 0, item: Some(index),
                                        asked: Box::new(item_page(&source, id, None)),
                                    });
                                } else if let Some(next) = read.next.take() {
                                    read.page += 1;
                                    let (url, after) = match next {
                                        Next::At(url) => (url, None),
                                        Next::After(c) => (source.url.clone(), Some(c)),
                                    };
                                    expected.push(Step::Fetch {
                                        name: name.clone(), generation, page: read.page, item: None,
                                        asked: Box::new(source_page(&source, url, after)),
                                    });
                                } else {
                                    ended = Some((interval, false));
                                }
                            }
                            match ended {
                                Some((after, asked_for_time)) => {
                                    match (read.trouble, asked_for_time) {
                                        (true, _) => *failures.entry(name.clone()).or_default() += 1,
                                        (false, false) => { failures.remove(name); }
                                        (false, true) => {}
                                    }
                                    expected.push(Step::Again { name: name.clone(), generation, after });
                                }
                                None => { reads.insert(name.clone(), read); }
                            }
                        }
                        steps
                    }
                    Happens::PrepareShutdown => {
                        shut = true;
                        expected.push(Step::ProceedWithShutdown);
                        observing.on(Event::PrepareShutdown)
                    }
                };
                let others: Vec<&Step> = steps.iter().filter(|s| !matches!(s, Step::Health(_))).collect();
                if !matches!(happened, Happens::Sources(_)) {
                    prop_assert_eq!(others, expected.iter().collect::<Vec<_>>(), "after {:?}", happened);
                }
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
