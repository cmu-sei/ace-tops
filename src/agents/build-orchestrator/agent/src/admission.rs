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

//! How many builds run at once (Vaughn's, with the cap a Dynamic setting and adoption added).
//!
//! Every build is a Job with a pipeline that may use several CPUs and gigabytes, so the number running together is
//! capped: a build over the cap waits its turn rather than exhausting the node, and starts when a place is free, in the
//! order it came. A cap raised by a signed update starts as many waiting builds as now fit; a cap lowered stops none,
//! and the next start waits until the running are under it. A Job a restarted orchestrator adopts is running whatever
//! the cap, and holds a place until it ends.

use orchestrator_core::types::BuildRequest;
use std::collections::{HashSet, VecDeque};
use uuid::Uuid;

/// What became of a request.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // a request is moved once, into the build it starts or the line it waits in
pub enum Admitted {
    /// There is room: start it now.
    Now(BuildRequest),
    /// There is not; it is held, at this place in the line (1 is next).
    Waiting(usize),
    /// A build of this id is already running or waiting.
    Duplicate,
}

pub struct Admission {
    cap: usize,
    running: HashSet<Uuid>,
    waiting: VecDeque<BuildRequest>,
}

impl Admission {
    /// At most `cap` builds at once, and at least one so that something can run.
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            running: HashSet::new(),
            waiting: VecDeque::new(),
        }
    }

    pub fn cap(&self) -> usize {
        self.cap
    }

    pub fn running(&self) -> usize {
        self.running.len()
    }

    pub fn waiting(&self) -> usize {
        self.waiting.len()
    }

    pub fn request(&mut self, request: BuildRequest) -> Admitted {
        let id = request.build_id;
        if self.running.contains(&id) || self.waiting.iter().any(|w| w.build_id == id) {
            return Admitted::Duplicate;
        }
        if self.running.len() < self.cap {
            self.running.insert(id);
            Admitted::Now(request)
        } else {
            self.waiting.push_back(request);
            Admitted::Waiting(self.waiting.len())
        }
    }

    /// A Job found running at start: it holds a place, whatever the cap. False if the build is already known.
    pub fn adopt(&mut self, build_id: Uuid) -> bool {
        if self.waiting.iter().any(|w| w.build_id == build_id) {
            return false;
        }
        self.running.insert(build_id)
    }

    /// A build ended, however it did. The requests now at the front of the line that there is room for are the next to
    /// start, in order.
    pub fn finished(&mut self, build_id: Uuid) -> Vec<BuildRequest> {
        self.running.remove(&build_id);
        self.fill()
    }

    /// The cap a signed update set. The waiting builds that now fit start, in order; none running is stopped.
    pub fn set_cap(&mut self, cap: usize) -> Vec<BuildRequest> {
        self.cap = cap.max(1);
        self.fill()
    }

    fn fill(&mut self) -> Vec<BuildRequest> {
        let mut started = Vec::new();
        while self.running.len() < self.cap {
            let Some(next) = self.waiting.pop_front() else {
                break;
            };
            self.running.insert(next.build_id);
            started.push(next);
        }
        started
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchestrator_core::types::SourceRef;

    fn request() -> BuildRequest {
        BuildRequest {
            build_id: Uuid::new_v4(),
            source: SourceRef::Git {
                url: "https://example.test/r.git".into(),
                commit_sha: "a".repeat(40),
            },
            pipeline_image: None,
            requested_at: chrono::Utc::now(),
            metadata: Default::default(),
            command: vec![],
        }
    }

    fn ids(started: Vec<BuildRequest>) -> Vec<Uuid> {
        started.into_iter().map(|r| r.build_id).collect()
    }

    #[test]
    fn builds_start_until_the_cap_and_then_wait_in_order() {
        let mut a = Admission::new(2);
        let (r1, r2, r3, r4) = (request(), request(), request(), request());
        assert!(matches!(a.request(r1.clone()), Admitted::Now(_)));
        assert!(matches!(a.request(r2.clone()), Admitted::Now(_)));
        assert!(matches!(a.request(r3.clone()), Admitted::Waiting(1)));
        assert!(matches!(a.request(r4.clone()), Admitted::Waiting(2)));
        assert_eq!(a.running(), 2);
        assert_eq!(ids(a.finished(r1.build_id)), [r3.build_id]);
        assert_eq!(ids(a.finished(r2.build_id)), [r4.build_id]);
        assert!(a.finished(r3.build_id).is_empty());
        assert_eq!(a.running(), 1);
    }

    #[test]
    fn a_build_that_ends_while_others_wait_is_replaced_only_once() {
        let mut a = Admission::new(1);
        let (r1, r2, r3) = (request(), request(), request());
        a.request(r1.clone());
        a.request(r2.clone());
        a.request(r3.clone());
        assert_eq!(ids(a.finished(r1.build_id)), [r2.build_id]);
        // The same build ending again changes nothing: r2 holds the one place.
        assert!(a.finished(r1.build_id).is_empty());
        assert_eq!(a.running(), 1);
    }

    #[test]
    fn a_request_seen_twice_is_one_build() {
        let mut a = Admission::new(1);
        let (r1, r2) = (request(), request());
        a.request(r1.clone());
        a.request(r2.clone());
        assert!(matches!(a.request(r1), Admitted::Duplicate));
        assert!(matches!(a.request(r2), Admitted::Duplicate));
    }

    #[test]
    fn the_cap_is_at_least_one() {
        let mut a = Admission::new(0);
        assert_eq!(a.cap(), 1);
        assert!(matches!(a.request(request()), Admitted::Now(_)));
        assert!(a.set_cap(0).is_empty());
        assert_eq!(a.cap(), 1);
    }

    #[test]
    fn a_raised_cap_starts_who_waits_and_a_lowered_one_stops_nobody() {
        let mut a = Admission::new(1);
        let (r1, r2, r3, r4) = (request(), request(), request(), request());
        for r in [&r1, &r2, &r3, &r4] {
            a.request(r.clone());
        }
        assert_eq!(ids(a.set_cap(3)), [r2.build_id, r3.build_id]);
        assert!(a.set_cap(1).is_empty());
        assert_eq!(a.running(), 3);
        assert!(a.finished(r1.build_id).is_empty());
        assert!(a.finished(r2.build_id).is_empty());
        assert_eq!(ids(a.finished(r3.build_id)), [r4.build_id]);
    }

    #[test]
    fn an_adopted_build_holds_a_place_whatever_the_cap() {
        let mut a = Admission::new(1);
        let adopted = Uuid::new_v4();
        assert!(a.adopt(adopted));
        assert!(!a.adopt(adopted));
        assert!(a.adopt(Uuid::new_v4()));
        assert_eq!(a.running(), 2);
        let r = request();
        assert!(matches!(a.request(r.clone()), Admitted::Waiting(1)));
        assert!(a.finished(adopted).is_empty());
        assert_eq!(a.running(), 1);
    }
}
