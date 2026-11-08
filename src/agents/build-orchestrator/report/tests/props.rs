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

//! Properties of the gate and the parser over generated lines. The proofs (Verus) say what holds for every input of the
//! code as written; these check the build that runs, with Verus erased, against the same properties and against
//! `std`'s own reading of UTF-8.

use orchestrator_report::{Bounds, Refusal, Tape, Token, gate, parse};
use proptest::prelude::*;

/// A value of the grammar.
#[derive(Debug, Clone)]
enum V {
    Null,
    Int(u64),
    Text(String),
    List(Vec<V>),
    Object(Vec<(String, V)>),
}

/// How many tokens a value is on the tape: one for each value, and one for each key.
fn tokens_of(v: &V) -> usize {
    match v {
        V::Null | V::Int(_) | V::Text(_) => 1,
        V::List(items) => 1 + items.iter().map(tokens_of).sum::<usize>(),
        V::Object(members) => 1 + members.iter().map(|(_, v)| 1 + tokens_of(v)).sum::<usize>(),
    }
}

/// A string as JSON writes it: quotes and backslashes escaped, a control character as `\u00XX`, a non-BMP character as a
/// surrogate pair when `pairs`.
fn quoted(s: &str, pairs: bool) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c if pairs && (c as u32) > 0xffff => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn written(v: &V, pairs: bool) -> String {
    match v {
        V::Null => "null".into(),
        V::Int(n) => n.to_string(),
        V::Text(s) => quoted(s, pairs),
        V::List(items) => format!(
            "[{}]",
            items
                .iter()
                .map(|v| written(v, pairs))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        V::Object(members) => format!(
            "{{{}}}",
            members
                .iter()
                .map(|(k, v)| format!("{}: {}", quoted(k, pairs), written(v, pairs)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn value() -> impl Strategy<Value = V> {
    let leaf = prop_oneof![
        Just(V::Null),
        any::<u64>().prop_map(V::Int),
        "\\PC{0,12}".prop_map(V::Text),
        "[\"\\\\\n\u{1}\u{7f}é😀a]{0,6}".prop_map(V::Text),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..6).prop_map(V::List),
            proptest::collection::btree_map("[a-z]{1,4}", inner, 0..6)
                .prop_map(|members| V::Object(members.into_iter().collect())),
        ]
    })
}

fn object() -> impl Strategy<Value = V> {
    proptest::collection::btree_map("[a-z_]{1,8}", value(), 0..8)
        .prop_map(|m| V::Object(m.into_iter().collect()))
}

proptest! {
    /// Where a line holds no control character and fits its bound, the gate refuses it as not UTF-8 exactly when the
    /// standard library cannot read it as UTF-8: Verus's definition (`vstd::utf8::valid_utf8`) and `std`'s agree.
    #[test]
    fn the_gate_reads_utf8_as_std_does(bytes in proptest::collection::vec(0x20u8..=0xff, 0..64)) {
        let bytes: Vec<u8> = bytes.into_iter().filter(|&b| b != 0x7f).collect();
        let not_utf8 = gate(&bytes, &Bounds::default()) == Err(Refusal::NotUtf8);
        prop_assert_eq!(not_utf8, std::str::from_utf8(&bytes).is_err());
    }

    /// Any value of the grammar, written as JSON writes it (with surrogate pairs or without), passes the gate and parses,
    /// one token for each value and each key.
    #[test]
    fn a_value_of_the_grammar_parses_to_its_tokens(v in object(), pairs in any::<bool>()) {
        let line = written(&v, pairs);
        let bounds = Bounds::default();
        prop_assert_eq!(gate(line.as_bytes(), &bounds), Ok(()), "{}", line);
        let mut tape = Tape::new(&bounds);
        prop_assert_eq!(parse(line.as_bytes(), &bounds, &mut tape), Ok(()), "{}", line);
        prop_assert_eq!(tape.tokens.len(), tokens_of(&v));
    }

    /// Anything after the one value but spaces is refused, whatever it is.
    #[test]
    fn what_follows_a_report_is_refused(v in object(), tail in "[^ ]{1,4}") {
        let line = format!("{} {}", written(&v, false), tail);
        let bounds = Bounds::default();
        let mut tape = Tape::new(&bounds);
        prop_assert!(parse(line.as_bytes(), &bounds, &mut tape).is_err(), "{}", line);
    }

    /// For any bytes and small bounds, the build that runs keeps what was proved: it returns, the tape holds no more than
    /// its limit, and every span lies inside the line.
    #[test]
    fn the_running_build_keeps_what_was_proved(
        bytes in proptest::collection::vec(any::<u8>(), 0..96),
        tokens in 0usize..12,
        depth in 0usize..4,
    ) {
        let bounds = Bounds { tokens, depth, string: 8, items: 4, ..Bounds::default() };
        let mut tape = Tape::new(&bounds);
        let _ = gate(&bytes, &bounds);
        let _ = parse(&bytes, &bounds, &mut tape);
        prop_assert!(tape.tokens.len() <= tokens);
        for t in &tape.tokens {
            if let Token::Key { start, end } | Token::Text { start, end } = *t {
                prop_assert!(start <= end && (end as usize) <= bytes.len());
            }
        }
    }
}
