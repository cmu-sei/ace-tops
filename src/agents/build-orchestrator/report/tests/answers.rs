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

//! A worker's answer (build-orchestrator.md, O2d2), made and read in-process: what it carries back is what reading the line
//! directly gives, and an answer that is not one a worker of these bounds makes is refused.

use orchestrator_report::*;
use proptest::prelude::*;

/// What the agent gets for `line` reading it itself, through the gate, the parser, the check and the decoding.
fn direct(line: &[u8], bounds: &Bounds) -> Result<Report, Refusal> {
    gate(line, bounds)?;
    let mut tape = Tape::new(bounds);
    parse(line, bounds, &mut tape)?;
    Report::read(line, &tape)
}

/// What the agent gets for `line` by way of a worker's answer.
fn by_answer(line: &[u8], bounds: &Bounds) -> Result<Report, Refusal> {
    let mut tape = Tape::new(bounds);
    let mut out = vec![0u8; answer_len(bounds)];
    let n = answer(line, bounds, &mut tape, &mut out);
    Report::read_answer(line, &out[..n], bounds)
}

fn small() -> Bounds {
    Bounds {
        tokens: 256,
        ..Bounds::default()
    }
}

const STAGE: &str = r#"{"type": "stage_completed", "stage_name": "build", "stage_id": "s1", "duration_secs": 12, "outcome": "failed", "at": "t"}"#;

#[test]
fn an_answer_carries_a_report_and_a_refusal_as_reading_directly_does() {
    let bounds = small();
    for line in [
        STAGE,
        r#"{"type": "execution_started"}"#,
        "{\"a\":\n1}",
        r#"{"type": "stage_started"}"#,
        "[1, 2",
    ] {
        assert_eq!(
            by_answer(line.as_bytes(), &bounds),
            direct(line.as_bytes(), &bounds),
            "{line}"
        );
    }
}

#[test]
fn an_answer_not_shaped_as_a_worker_makes_one_is_refused() {
    let bounds = small();
    let mut tape = Tape::new(&bounds);
    let mut out = vec![0u8; answer_len(&bounds)];
    let n = answer(STAGE.as_bytes(), &bounds, &mut tape, &mut out);
    let good = &out[..n];
    assert!(Report::read_answer(STAGE.as_bytes(), good, &bounds).is_ok());
    assert!(
        Report::read_answer(STAGE.as_bytes(), &good[..n - 1], &bounds).is_err(),
        "cut short"
    );
    let mut longer = good.to_vec();
    longer.extend_from_slice(&[0; 16]);
    assert!(
        Report::read_answer(STAGE.as_bytes(), &longer, &bounds).is_err(),
        "a record too many"
    );
    let fewer = Bounds {
        tokens: 2,
        ..bounds
    };
    assert!(
        Report::read_answer(STAGE.as_bytes(), good, &fewer).is_err(),
        "more tokens than the bound"
    );
    let mut other_kind = good.to_vec();
    other_kind[4] = 1;
    assert!(
        Report::read_answer(STAGE.as_bytes(), &other_kind, &bounds).is_err(),
        "a kind the line is not"
    );
    // A buffer too small for the tape: the worker refuses rather than write past it.
    let mut tight = vec![0u8; HEADER + RECORD * 3];
    let n = answer(STAGE.as_bytes(), &bounds, &mut tape, &mut tight);
    assert_eq!(
        Report::read_answer(STAGE.as_bytes(), &tight[..n], &bounds),
        Err(Refusal::TooManyTokens)
    );
}

/// A count of records past what a length counts, under a bound that allows it, is refused, never an overflow: found by
/// a Kani harness on another branch, where the answer's length was its header and records multiplied out unchecked.
#[test]
fn a_count_past_what_a_length_counts_is_refused_never_an_overflow() {
    let unbounded = Bounds {
        tokens: usize::MAX,
        ..small()
    };
    // 2^60 + 1 records: sixteen times that wraps to 16, so the unchecked length was this answer's own 32.
    let mut forged = vec![0u8; HEADER + RECORD];
    forged[8..16].copy_from_slice(&((1u64 << 60) + 1).to_le_bytes());
    assert_eq!(
        Report::read_answer(b"", &forged, &unbounded),
        Err(Refusal::NotAValue)
    );
}

proptest! {
    /// Whatever the bytes, an answer gives the agent exactly what reading them directly would.
    #[test]
    fn whatever_the_bytes_the_answer_is_what_reading_them_gives(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let bounds = small();
        prop_assert_eq!(by_answer(&bytes, &bounds), direct(&bytes, &bounds));
    }

    /// Any one byte of an answer changed: reading it never panics.
    #[test]
    fn a_tampered_answer_never_panics(at in 0usize..512, byte in any::<u8>()) {
        let bounds = small();
        let mut tape = Tape::new(&bounds);
        let mut out = vec![0u8; answer_len(&bounds)];
        let n = answer(STAGE.as_bytes(), &bounds, &mut tape, &mut out);
        let mut answer = out[..n].to_vec();
        let at = at % answer.len();
        answer[at] = byte;
        let _ = Report::read_answer(STAGE.as_bytes(), &answer, &bounds);
    }
}
