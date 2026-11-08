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

//! Any bytes, through every step of the report reader: the gate, the parser and the check (proved), then the decoding
//! (not proved, and so this target's real subject). None may panic; and whatever reads as a report, written out again,
//! reads back as the same report.

#![no_main]

use libfuzzer_sys::fuzz_target;
use orchestrator_report::{Bounds, Report, Tape, gate, parse};

fn read(bytes: &[u8], bounds: &Bounds, tape: &mut Tape) -> Option<Report> {
    gate(bytes, bounds).ok()?;
    parse(bytes, bounds, tape).ok()?;
    Report::read(bytes, tape).ok()
}

fuzz_target!(|bytes: &[u8]| {
    let bounds = Bounds {
        line: 64 * 1024,
        tokens: 4096,
        ..Bounds::default()
    };
    let mut tape = Tape::new(&bounds);
    if let Some(report) = read(bytes, &bounds, &mut tape) {
        let line = report.line();
        let again = read(line.as_bytes(), &bounds, &mut tape);
        assert_eq!(again.as_ref(), Some(&report), "{line}");
    }
});
