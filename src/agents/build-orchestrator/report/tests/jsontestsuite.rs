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

//! The report reader against JSONTestSuite's parsing cases (`tests/jsontestsuite`, its README): no case a JSON parser must
//! refuse (`n_`) passes the gate and the parser; a case JSON accepts (`y_`) is refused only for what the report grammar
//! leaves out on purpose; and no case of any kind makes the gate, the parser or the check panic.

use orchestrator_report::{Bounds, Refusal, Tape, check, gate, parse};

/// What the gate and the parser make of `bytes`: nothing, if they pass, or the first refusal. Whatever they made, the check
/// is asked of it too: it must return, whatever the tape holds.
fn read(bytes: &[u8], bounds: &Bounds, tape: &mut Tape) -> Option<Refusal> {
    let refused = gate(bytes, bounds)
        .err()
        .or_else(|| parse(bytes, bounds, tape).err());
    let _ = check(bytes, tape);
    refused
}

/// What the report grammar leaves out of JSON on purpose: a boolean, a sign, a fraction or an exponent (outside the grammar),
/// a raw newline or DEL (a control character), a key twice.
const LEFT_OUT: [Refusal; 3] = [
    Refusal::OutsideTheGrammar,
    Refusal::Control,
    Refusal::DuplicateKey,
];

#[test]
fn no_case_json_refuses_is_read_and_no_case_makes_the_reader_panic() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/jsontestsuite");
    let bounds = Bounds::default();
    let mut tape = Tape::new(&bounds);
    let (mut cases, mut accepted_y, mut total_y) = (0, 0, 0);
    let mut wrongly_read = Vec::new();
    let mut wrongly_refused = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if !name.ends_with(".json") {
            continue;
        }
        cases += 1;
        let bytes = std::fs::read(&path).unwrap();
        let refused = read(&bytes, &bounds, &mut tape);
        if name.starts_with("n_") && refused.is_none() {
            wrongly_read.push(name.clone());
        }
        if name.starts_with("y_") {
            total_y += 1;
            match refused {
                None => accepted_y += 1,
                Some(why) if LEFT_OUT.contains(&why) => {}
                Some(why) => wrongly_refused.push(format!("{name}: {why:?}")),
            }
        }
    }
    assert_eq!(cases, 318, "the suite's parsing cases, all of them");
    assert!(
        wrongly_read.is_empty(),
        "read, though JSON refuses them: {wrongly_read:?}"
    );
    assert!(
        wrongly_refused.is_empty(),
        "refused for more than the grammar leaves out: {wrongly_refused:?}"
    );
    println!(
        "JSONTestSuite: of {total_y} cases JSON accepts, the report grammar reads {accepted_y}"
    );
}
