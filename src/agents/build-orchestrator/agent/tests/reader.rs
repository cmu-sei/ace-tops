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

//! The agent's report reader in a real worker, forked as the builder forks it (`reader::DECL`, from the configuration) and
//! locked as seccomp's strict mode locks a process: it reads each line as reading it directly does, at the bounds a
//! request carries when they are narrower than its own, and never wider. A binary with its own main, since libtest's threads would stop the fork.

use build_orchestrator::reader::{BOUNDS_LEN, DECL, request};
use build_orchestrator::settings::{SECTION, narrowed};
use orchestrator_report::*;
use polar_agent_builder::worker::WorkerError;
use polar_env::Config;
use std::collections::HashMap;

fn config(pairs: &[(&str, &str)]) -> Config {
    let mut env: HashMap<String, String> = HashMap::new();
    for (k, v) in [
        ("POLAR_ORCHESTRATOR_NAMESPACE", "polar-builds"),
        ("POLAR_ORCHESTRATOR_TEMPLATE", "build-runner"),
        (
            "POLAR_ORCHESTRATOR_REGISTRY",
            "http://registry.polar-registry.svc.cluster.local:5000",
        ),
        (
            "POLAR_ORCHESTRATOR_CLONES",
            "/var/lib/build-orchestrator/clones",
        ),
    ]
    .iter()
    .chain(pairs)
    {
        env.insert(k.to_string(), v.to_string());
    }
    let config = Config::builder(&env).register(&SECTION).build();
    assert!(config.check().is_empty(), "{:?}", config.check());
    config
}

fn direct(line: &[u8], bounds: &Bounds) -> Result<Report, Refusal> {
    gate(line, bounds)?;
    let mut tape = Tape::new(bounds);
    parse(line, bounds, &mut tape)?;
    Report::read(line, &tape)
}

fn main() {
    let forked = Bounds {
        line: 64 * 1024,
        string: 4096,
        depth: 5,
        tokens: 4096,
        items: 1024,
    };
    let mut worker = (DECL.fork)(&config(&[
        ("POLAR_ORCHESTRATOR_REPORT_LINE_BYTES", "65536"),
        ("POLAR_ORCHESTRATOR_REPORT_DEPTH", "5"),
        ("POLAR_ORCHESTRATOR_REPORT_TOKENS", "4096"),
        ("POLAR_ORCHESTRATOR_REPORT_ITEMS", "1024"),
    ]))
    .expect("the reader forks from its configuration");
    assert_eq!(worker.max_request(), BOUNDS_LEN + forked.line);
    let mut passed = 0;

    let seeds = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../report/fuzz/seeds");
    let mut lines: Vec<Vec<u8>> = std::fs::read_dir(&seeds)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    assert!(lines.len() >= 8, "the report crate's seeds");
    lines.extend([
        br#"{"type": "execution_started", "build_id": "b"}"#.to_vec(),
        b"{\"a\": [1, 2,".to_vec(),
        vec![0xff, 0xfe, b'{'],
        b"[[[[[[[[1]]]]]]]]".to_vec(),
    ]);
    for line in &lines {
        let answered = worker.ask(&request(&forked, line)).expect("an answer");
        assert_eq!(
            Report::read_answer(line, &answered, &forked),
            direct(line, &forked),
            "{}",
            String::from_utf8_lossy(line)
        );
    }
    println!(
        "  ok    {} lines read in the worker as directly, at the bounds it was forked with",
        lines.len()
    );
    passed += 1;

    // Narrowed by a signed update: each bound, read at the narrower, and the next line at the full bounds again.
    let sbom = lines
        .iter()
        .find(|l| l.windows(13).any(|w| w == b"sbom_analyzed"))
        .expect("an SBOM seed")
        .clone();
    assert!(direct(&sbom, &forked).is_ok());
    for (signed, refusal) in [
        (
            Bounds {
                line: sbom.len() - 1,
                ..forked
            },
            Refusal::TooLong,
        ),
        (Bounds { depth: 1, ..forked }, Refusal::TooDeep),
        (
            Bounds {
                string: 2,
                ..forked
            },
            Refusal::StringTooLong,
        ),
        (
            Bounds {
                tokens: 4,
                ..forked
            },
            Refusal::TooManyTokens,
        ),
    ] {
        let at = narrowed(&forked, &signed);
        let answered = worker.ask(&request(&at, &sbom)).expect("an answer");
        assert_eq!(
            Report::read_answer(&sbom, &answered, &at),
            Err(refusal),
            "{at:?}"
        );
        assert_eq!(direct(&sbom, &at), Err(refusal), "{at:?}");
        let answered = worker.ask(&request(&forked, &sbom)).expect("an answer");
        assert!(Report::read_answer(&sbom, &answered, &forked).is_ok());
    }
    println!("  ok    a narrowed bound refuses what it should, and the full bounds read it again");
    passed += 1;

    // Asked for more than it was forked with, it reads at its own: deeper nesting stays refused, more tokens are not made.
    let wide = Bounds {
        line: usize::MAX,
        string: usize::MAX,
        depth: 100,
        tokens: usize::MAX,
        items: usize::MAX,
    };
    let deep = b"[[[[[[[[1]]]]]]]]";
    let answered = worker.ask(&request(&wide, deep)).expect("an answer");
    assert_eq!(
        Report::read_answer(deep, &answered, &forked),
        Err(Refusal::TooDeep)
    );
    let many = format!("[{}1]", "1, ".repeat(5000));
    let answered = worker
        .ask(&request(&wide, many.as_bytes()))
        .expect("an answer");
    assert_eq!(
        answered.len(),
        HEADER,
        "a refusal, not a tape: {}",
        answered.len()
    );
    assert_eq!(
        Report::read_answer(many.as_bytes(), &answered, &wide).err(),
        direct(many.as_bytes(), &forked).err()
    );
    // A line past its own bound is not sent at all.
    let long = vec![b' '; forked.line + 1];
    assert_eq!(
        worker.ask(&request(&wide, &long)),
        Err(WorkerError::TooLong(BOUNDS_LEN + forked.line + 1))
    );
    println!("  ok    a request asking for wider bounds is read at the worker's own");
    passed += 1;

    // A request too short to carry its bounds is refused, and the worker is still there.
    let answered = worker.ask(b"{}").expect("an answer");
    assert!(Report::read_answer(b"{}", &answered, &forked).is_err());
    let answered = worker.ask(&request(&forked, &sbom)).expect("an answer");
    assert!(Report::read_answer(&sbom, &answered, &forked).is_ok());
    println!("  ok    a request without its bounds is refused, and the worker reads on");
    passed += 1;

    println!("all {passed} passed");
}
