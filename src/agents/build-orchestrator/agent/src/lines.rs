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

//! The report lines in a build's log, found as the log comes, a piece at a time (docs/architecture/build-orchestrator.md,
//! "Settled with it"): a line that begins with `orchestrator_report::PREFIX` is a report, every other line the build's own
//! output, passed over. A report line is kept up to its bound and no further: one longer is known only by its length,
//! and refused. Nothing else of the log is kept, so what a build prints costs the orchestrator no more than its bound.
//!
//! The pieces may split the log anywhere, a line or the prefix included: what is found is the same however it was split.

use orchestrator_report::PREFIX;

/// A report line found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// What followed the prefix, within its bound.
    Report(Vec<u8>),
    /// A report longer than its bound, by how much followed the prefix.
    TooLong(usize),
}

enum At {
    /// The start of a line: the bytes of it so far, all of them the prefix's.
    Start(Vec<u8>),
    /// In a report, what followed the prefix so far.
    Report(Vec<u8>),
    /// In a report past its bound, how long it is so far.
    TooLong(usize),
    /// In a line that is not a report.
    Other,
}

pub struct Lines {
    bound: usize,
    at: At,
}

impl Lines {
    /// A report line is kept up to `bound` bytes after its prefix.
    pub fn new(bound: usize) -> Self {
        Self {
            bound,
            at: At::Start(Vec::new()),
        }
    }

    /// The report lines that `piece` ends.
    pub fn feed(&mut self, piece: &[u8]) -> Vec<Line> {
        let mut found = Vec::new();
        let mut rest = piece;
        while !rest.is_empty() {
            let (part, ends) = match rest.iter().position(|b| *b == b'\n') {
                Some(at) => (&rest[..at], Some(at)),
                None => (rest, None),
            };
            self.take(part);
            match ends {
                Some(at) => {
                    found.extend(self.end());
                    rest = &rest[at + 1..];
                }
                None => rest = &[],
            }
        }
        found
    }

    /// The last line, if the log ended without a newline.
    pub fn finish(mut self) -> Option<Line> {
        self.end()
    }

    /// Part of a line, with no newline in it.
    fn take(&mut self, mut part: &[u8]) {
        let prefix = PREFIX.as_bytes();
        if let At::Start(seen) = &mut self.at {
            let need = prefix.len() - seen.len();
            let head = &part[..need.min(part.len())];
            if prefix[seen.len()..seen.len() + head.len()] != *head {
                self.at = At::Other;
                return;
            }
            seen.extend_from_slice(head);
            part = &part[head.len()..];
            if seen.len() < prefix.len() {
                return;
            }
            self.at = At::Report(Vec::new());
        }
        match &mut self.at {
            At::Report(kept) if kept.len() + part.len() <= self.bound => {
                kept.extend_from_slice(part)
            }
            At::Report(kept) => self.at = At::TooLong(kept.len() + part.len()),
            At::TooLong(len) => *len += part.len(),
            At::Other | At::Start(_) => {}
        }
    }

    /// The line ends: a report if it was one.
    fn end(&mut self) -> Option<Line> {
        match std::mem::replace(&mut self.at, At::Start(Vec::new())) {
            At::Report(kept) => Some(Line::Report(kept)),
            At::TooLong(len) => Some(Line::TooLong(len)),
            At::Start(_) | At::Other => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(log: &[u8], bound: usize, piece: usize) -> Vec<Line> {
        let mut lines = Lines::new(bound);
        let mut found: Vec<Line> = log.chunks(piece).flat_map(|p| lines.feed(p)).collect();
        found.extend(lines.finish());
        found
    }

    #[test]
    fn reports_are_found_and_the_rest_passed_over() {
        let log =
            b"building...\npolar-report {\"a\": 1}\npolar-reportx\npolar-report \npolar-report {}";
        for piece in [1, 2, 5, 13, 1000] {
            assert_eq!(
                all(log, 64, piece),
                [
                    Line::Report(b"{\"a\": 1}".to_vec()),
                    Line::Report(Vec::new()),
                    Line::Report(b"{}".to_vec())
                ],
                "{piece}"
            );
        }
    }

    #[test]
    fn a_report_past_its_bound_is_known_by_its_length_alone() {
        let log = b"polar-report 0123456789\npolar-report 01234\n";
        assert_eq!(
            all(log, 5, 3),
            [Line::TooLong(10), Line::Report(b"01234".to_vec())]
        );
    }
}
