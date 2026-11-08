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

//! The gate and the parser, by example: what a report is, and each way a line is not one.

use orchestrator_report::{Bounds, KEYS, Refusal, Tape, Token, gate, parse, refusal_code};

fn gated(line: &str) -> Result<(), Refusal> {
    gate(line.as_bytes(), &Bounds::default())
}

fn parsed(text: &str) -> Result<Vec<Token>, Refusal> {
    let bounds = Bounds::default();
    let mut tape = Tape::new(&Bounds {
        tokens: 64,
        ..bounds
    });
    parse(text.as_bytes(), &bounds, &mut tape).map(|()| tape.tokens.clone())
}

#[test]
fn a_report_passes_the_gate() {
    assert_eq!(
        gated(r#"{"type": "stage_started", "stage_name": "build \"all\"", "n": [1, 22, null]}"#),
        Ok(())
    );
}

#[test]
fn what_no_report_has_is_refused_at_the_gate() {
    for (line, why) in [
        ("{\"a\":\"\u{7}\"}", Refusal::Control),
        ("{\"a\":1}\n", Refusal::Control),
        ("{\"a\":\t1}", Refusal::Control),
        ("{\"a\":-1}", Refusal::OutsideTheGrammar),
        ("{\"a\":1.5}", Refusal::OutsideTheGrammar),
        ("{\"a\":1e5}", Refusal::OutsideTheGrammar),
        ("{\"a\":true}", Refusal::OutsideTheGrammar),
        ("{\"a\":1}}", Refusal::Unbalanced),
        ("{\"a\":\"1}", Refusal::Unbalanced),
        ("[[[[[[[1]]]]]]]", Refusal::TooDeep),
        ("{\"a\":123456789012345678901}", Refusal::NumberTooLarge),
    ] {
        assert_eq!(gated(line), Err(why), "{line:?}");
    }
    for bytes in [
        &[b'"', 0xff, b'"'][..],
        &[b'"', 0xc0, 0x80, b'"'],
        &[b'"', 0xed, 0xa0, 0x80, b'"'],
    ] {
        assert_eq!(
            gate(bytes, &Bounds::default()),
            Err(Refusal::NotUtf8),
            "{bytes:x?}: invalid, overlong, a surrogate"
        );
    }
}

#[test]
fn a_string_and_a_line_are_held_to_their_bounds() {
    let bounds = Bounds {
        line: 16,
        string: 4,
        ..Bounds::default()
    };
    assert_eq!(gate(br#"{"abcd":1}"#, &bounds), Ok(()));
    assert_eq!(
        gate(br#"{"abcde":1}"#, &bounds),
        Err(Refusal::StringTooLong)
    );
    assert_eq!(
        gate(br#"{"ab\"d":1}"#, &bounds),
        Err(Refusal::StringTooLong),
        "an escape is two bytes"
    );
    assert_eq!(
        gate(br#"{"a":1234567890123}"#, &bounds),
        Err(Refusal::TooLong)
    );
}

#[test]
fn what_a_string_holds_is_not_the_grammar_outside_one() {
    assert_eq!(gated(r#"{"a": "-1.5e3 true {[ \\ \" ]}"}"#), Ok(()));
}

#[test]
fn a_line_is_its_tokens_in_order_each_container_saying_where_it_ends() {
    let line = r#"{"a": [1, "x"], "b": null}"#;
    // A span is between its quotes.
    let at = |s: &str| line.find(s).unwrap() as u32 + 1;
    assert_eq!(
        parsed(line),
        Ok(vec![
            Token::Object { members: 2, end: 7 },
            Token::Key {
                start: at("\"a\""),
                end: at("\"a\"") + 1
            },
            Token::List { items: 2, end: 5 },
            Token::Int(1),
            Token::Text {
                start: at("\"x\""),
                end: at("\"x\"") + 1
            },
            Token::Key {
                start: at("\"b\""),
                end: at("\"b\"") + 1
            },
            Token::Null,
        ])
    );
}

#[test]
fn what_the_grammar_does_not_have_is_refused_by_the_parser() {
    for (text, why) in [
        (r#"{"a": 1, "a": 2}"#, Refusal::DuplicateKey),
        (r#"{"a": 01}"#, Refusal::BadNumber),
        (r#"{"a": 18446744073709551616}"#, Refusal::NumberTooLarge),
        (r#"{"a": 1.5}"#, Refusal::NotAValue),
        (r#"{"a": -1}"#, Refusal::NotAValue),
        (r#"{"a": true}"#, Refusal::NotAValue),
        (r#"{"a": "\x"}"#, Refusal::BadEscape),
        (r#"{"a": "\ud800"}"#, Refusal::BadEscape),
        (r#"{"a": "\udc00"}"#, Refusal::BadEscape),
        (r#"{"a": "\ud800A"}"#, Refusal::BadEscape),
        (r#"{"a": "\u12"}"#, Refusal::BadEscape),
        (r#"{"a": 1} {}"#, Refusal::Trailing),
        (r#"{"a": 1,}"#, Refusal::NotAValue),
        (r#"{"a" 1}"#, Refusal::NotAValue),
        (r#"{"a": [1}"#, Refusal::NotAValue),
        ("{\"a\": \"\u{1}\"}", Refusal::Control),
        (r#"{"a": "x"#, Refusal::Unbalanced),
    ] {
        assert_eq!(parsed(text), Err(why), "{text}");
    }
    assert!(
        parsed(r#"{"a": "😀 é \n \" \\ \/"}"#).is_ok(),
        "a pair, and every escape JSON has"
    );
}

#[test]
fn an_object_has_at_most_its_keys_and_a_tape_its_tokens() {
    let keys: Vec<String> = (0..=KEYS).map(|i| format!("\"k{i}\": 1")).collect();
    assert_eq!(
        parsed(&format!("{{{}}}", keys.join(", "))),
        Err(Refusal::TooManyKeys)
    );
    assert!(parsed(&format!("{{{}}}", keys[..KEYS].join(", "))).is_ok());
    let long: Vec<String> = (0..64).map(|i| i.to_string()).collect();
    assert_eq!(
        parsed(&format!("[{}]", long.join(","))),
        Err(Refusal::TooManyTokens)
    );
}

#[test]
fn a_tape_is_never_grown() {
    let bounds = Bounds {
        tokens: 8,
        ..Bounds::default()
    };
    let mut tape = Tape::new(&bounds);
    let capacity = tape.tokens.capacity();
    for text in ["[1,2,3,4,5,6,7,8,9,10]", "{\"a\": [1, 2]}", "[[[[1]]]]"] {
        let _ = parse(text.as_bytes(), &bounds, &mut tape);
        assert_eq!(tape.tokens.capacity(), capacity, "{text}");
    }
}

/// Every refusal says what was wrong, in a sentence of its own, and never what the line said: its message is the same
/// whatever line it refuses, so nothing of the line reaches a log by it.
#[test]
fn every_refusal_says_what_was_wrong_and_nothing_of_the_line() {
    let all = [
        Refusal::TooLong,
        Refusal::Control,
        Refusal::NotUtf8,
        Refusal::OutsideTheGrammar,
        Refusal::Unbalanced,
        Refusal::TooDeep,
        Refusal::StringTooLong,
        Refusal::NumberTooLarge,
        Refusal::BadNumber,
        Refusal::BadEscape,
        Refusal::TooManyTokens,
        Refusal::TooManyKeys,
        Refusal::TooManyItems,
        Refusal::DuplicateKey,
        Refusal::NotAValue,
        Refusal::Trailing,
        Refusal::NotAnObject,
        Refusal::UnknownKind,
        Refusal::UnknownKey,
        Refusal::MissingKey,
        Refusal::WrongType,
        Refusal::UnknownWord,
    ];
    let mut messages: Vec<String> = all.iter().map(|r| r.to_string()).collect();
    assert!(
        messages.iter().all(|m| m.split_whitespace().count() >= 4),
        "{messages:?}"
    );
    messages.sort();
    messages.dedup();
    assert_eq!(messages.len(), all.len(), "each its own");
    // Each has its own code in a worker's answer, from 1.
    let mut codes: Vec<u32> = all.iter().map(|r| refusal_code(*r)).collect();
    codes.sort();
    assert_eq!(codes, (1..=all.len() as u32).collect::<Vec<_>>());
    // The same refusal of two lines that share nothing says the same.
    let one = parsed(r#"{"secret-token-1": 1, "secret-token-1": 2}"#).unwrap_err();
    let other = parsed(r#"{"x": 1, "x": 2}"#).unwrap_err();
    assert_eq!((one, one.to_string()), (other, other.to_string()));
    assert!(!one.to_string().contains("secret-token-1"));
}
