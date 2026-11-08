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

//! Properties of what build-orchestrator is told: the `mappings` section read back as written, and refused, naming the
//! entry and never the value, wherever it is spoiled; the run-time settings' quantities and bounds.

use build_orchestrator::admission::{Admission, Admitted};
use build_orchestrator::lines::{Line, Lines};
use build_orchestrator::mappings::{Mapping, parse};
use build_orchestrator::push::{ARCHIVE_TYPE, digest_of, manifest, reference};
use build_orchestrator::settings::{SECTION, milli, narrowed};
use orchestrator_core::types::SourceArchive;
use orchestrator_core::types::{BuildRequest, Privileges, SourceRef};
use orchestrator_report::Bounds;
use polar::graph::nodes::git::RepoId;
use polar_env::Config;
use proptest::prelude::*;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// A marker no generated valid value holds, so a problem that echoes a spoiled value is seen.
const MARK: &str = "zqxmarkzqx";

fn mapping() -> impl Strategy<Value = Mapping> {
    (
        "[a-z]{1,8}",
        proptest::collection::vec("[a-z0-9-]{1,8}", 1..4),
        "[0-9a-f]{64}",
        proptest::option::of(proptest::collection::vec("[ -~]{1,12}", 1..5)),
        any::<bool>(),
        any::<bool>(),
        proptest::collection::vec("[A-Z][A-Z_]{0,10}", 0..4),
        proptest::collection::vec("[a-z0-9-]{1,12}", 0..4),
    )
        .prop_map(
            |(host, path, digest, command, root, escalate, caps, credentials)| {
                let url = format!("https://{host}.example/{}", path.join("/"));
                Mapping {
                    repo: RepoId::from_url(&url),
                    url,
                    pipeline_image: format!("registry.polar/pipelines/ci@sha256:{digest}"),
                    command,
                    privileges: Privileges {
                        run_as_root: root,
                        allow_privilege_escalation: escalate,
                        add_capabilities: caps,
                    },
                    credentials,
                }
            },
        )
}

/// Mappings of distinct repositories.
fn mappings() -> impl Strategy<Value = Vec<Mapping>> {
    proptest::collection::vec(mapping(), 0..6).prop_map(|mut all| {
        let mut seen = Vec::new();
        all.retain(|m| {
            let new = !seen.contains(&m.repo);
            seen.push(m.repo.clone());
            new
        });
        all
    })
}

/// A mapping as an author writes it: what is left at its default, left out.
fn written(m: &Mapping) -> Value {
    let mut entry = json!({"url": m.url, "pipeline_image": m.pipeline_image});
    if let Some(command) = &m.command {
        entry["command"] = json!(command);
    }
    if m.privileges != Privileges::default() {
        entry["privileges"] = json!({
            "run_as_root": m.privileges.run_as_root,
            "allow_privilege_escalation": m.privileges.allow_privilege_escalation,
            "add_capabilities": m.privileges.add_capabilities,
        });
    }
    if !m.credentials.is_empty() {
        entry["credentials"] = json!(m.credentials);
    }
    entry
}

fn body(all: &[Mapping]) -> Value {
    json!({"repositories": all.iter().map(written).collect::<Vec<_>>()})
}

/// One way to spoil an entry: the field a problem must name, and the entry spoiled.
fn spoil(entry: &mut Value, how: usize) -> &'static str {
    let object = entry.as_object_mut().unwrap();
    match how {
        0 => {
            object.insert("url".into(), json!(format!("http://{MARK}.example/x")));
            "`url`"
        }
        1 => {
            object.insert(
                "url".into(),
                json!(format!("https://{MARK}:pw@x.example/x")),
            );
            "`url`"
        }
        2 => {
            object.remove("url");
            "`url` is required"
        }
        3 => {
            object.insert("pipeline_image".into(), json!(format!("reg/{MARK}:latest")));
            "`pipeline_image`"
        }
        4 => {
            object.remove("pipeline_image");
            "`pipeline_image` is required"
        }
        5 => {
            object.insert("command".into(), json!([MARK, ""]));
            "`command`"
        }
        6 => {
            object.insert("command".into(), json!(MARK));
            "`command`"
        }
        7 => {
            object.insert(
                "privileges".into(),
                json!({"add_capabilities": [format!("CAP_{MARK}")]}),
            );
            "`privileges.add_capabilities`"
        }
        8 => {
            object.insert("privileges".into(), json!({"privileged": true}));
            "`privileges.privileged`"
        }
        9 => {
            object.insert("privileges".into(), json!({"run_as_root": MARK}));
            "`privileges.run_as_root`"
        }
        10 => {
            object.insert("credentials".into(), json!([format!("{MARK}_UPPER")]));
            "`credentials`"
        }
        _ => {
            object.insert(format!("{MARK}-Key"), json!(1));
            "is not a field of an entry"
        }
    }
}

fn config(pairs: &[(&str, String)]) -> Config {
    let mut env: HashMap<String, String> = HashMap::from([
        (
            "POLAR_ORCHESTRATOR_NAMESPACE".to_string(),
            "polar-builds".to_string(),
        ),
        (
            "POLAR_ORCHESTRATOR_TEMPLATE".to_string(),
            "build-runner".to_string(),
        ),
        (
            "POLAR_ORCHESTRATOR_REGISTRY".to_string(),
            "http://registry.polar-registry.svc.cluster.local:5000".to_string(),
        ),
    ]);
    for (k, v) in pairs {
        env.insert(k.to_string(), v.clone());
    }
    Config::builder(&env).register(&SECTION).build()
}

const SUFFIXES: [(&str, u128); 14] = [
    ("", 1000),
    ("m", 1),
    ("k", 1_000_000),
    ("M", 1_000_000_000),
    ("G", 1_000_000_000_000),
    ("T", 1_000_000_000_000_000),
    ("P", 1_000_000_000_000_000_000),
    ("E", 1_000_000_000_000_000_000_000),
    ("Ki", 1024 * 1000),
    ("Mi", (1 << 20) * 1000),
    ("Gi", (1 << 30) * 1000),
    ("Ti", (1 << 40) * 1000),
    ("Pi", (1 << 50) * 1000),
    ("Ei", (1 << 60) * 1000),
];

fn quantity() -> impl Strategy<Value = (String, u128)> {
    (0u64..1_000_000, 0..SUFFIXES.len()).prop_map(|(n, s)| {
        let (suffix, unit) = SUFFIXES[s];
        (format!("{n}{suffix}"), u128::from(n) * unit)
    })
}

fn bounds() -> impl Strategy<Value = Bounds> {
    (
        1usize..1 << 24,
        1usize..1 << 16,
        1usize..64,
        1usize..1 << 20,
        1usize..1 << 17,
    )
        .prop_map(|(line, string, depth, tokens, items)| Bounds {
            line,
            string,
            depth,
            tokens,
            items,
        })
}

/// What can happen to admission.
#[derive(Debug, Clone)]
enum Event {
    Request,
    /// One of the running builds ends: which, by its place among them.
    Finish(prop::sample::Index),
    SetCap(usize),
    Adopt,
    /// A request already running or waiting is made again.
    Again(prop::sample::Index),
}

fn event() -> impl Strategy<Value = Event> {
    prop_oneof![
        4 => Just(Event::Request),
        3 => any::<prop::sample::Index>().prop_map(Event::Finish),
        1 => (0usize..5).prop_map(Event::SetCap),
        1 => Just(Event::Adopt),
        1 => any::<prop::sample::Index>().prop_map(Event::Again),
    ]
}

fn build(n: u128) -> BuildRequest {
    BuildRequest {
        build_id: Uuid::from_u128(n),
        source: SourceRef::Git {
            url: "https://git.example.org/a/b.git".into(),
            commit_sha: "a".repeat(40),
        },
        pipeline_image: None,
        requested_at: chrono::DateTime::UNIX_EPOCH,
        metadata: Default::default(),
        command: vec![],
    }
}

/// A line of a log, without its newline: a report, something that begins like one, or the build's own output.
fn log_line() -> impl Strategy<Value = Vec<u8>> {
    let body = proptest::collection::vec(
        any::<u8>().prop_filter("no newline", |b| *b != b'\n'),
        0..40,
    );
    prop_oneof![
        body.clone()
            .prop_map(|b| [b"polar-report ".to_vec(), b].concat()),
        (0usize..13, body.clone())
            .prop_map(|(n, b)| [b"polar-report ".to_vec()[..n].to_vec(), b].concat()),
        body,
    ]
}

proptest! {
    /// Any archive's manifest names it by its digest and size, as its one layer, and nothing else; and the reference a
    /// build's pod is given reads back as an archive pinned by that digest, at the registry's host.
    #[test]
    fn a_sources_manifest_and_reference_name_its_archive_exactly(
        archive in proptest::collection::vec(any::<u8>(), 0..256),
        host in "[a-z][a-z0-9-]{0,12}(\\.[a-z][a-z0-9-]{0,12}){0,3}",
        port in 1u16..,
        https in any::<bool>(),
    ) {
        let digest = digest_of(&archive);
        prop_assert_eq!(digest.len(), "sha256:".len() + 64);
        let parsed: Value = serde_json::from_slice(&manifest(&digest, archive.len())).unwrap();
        let layers = parsed["layers"].as_array().unwrap();
        prop_assert_eq!(layers.len(), 1);
        prop_assert_eq!(&layers[0]["digest"], &Value::from(digest.clone()));
        prop_assert_eq!(&layers[0]["size"], &Value::from(archive.len()));
        prop_assert_eq!(&layers[0]["mediaType"], &Value::from(ARCHIVE_TYPE));
        let scheme = if https { "https" } else { "http" };
        let named = reference(&format!("{scheme}://{host}:{port}"), &digest);
        prop_assert!(named.starts_with(&format!("{host}:{port}/build-sources@")), "{}", named);
        let pinned = SourceArchive::new(named).unwrap();
        prop_assert_eq!(pinned.sha256(), &digest["sha256:".len()..]);
    }

    /// Whatever a log holds and wherever its pieces split it, the lines found are its report lines, in order: each what
    /// follows the prefix when it is within the bound, and only its length when it is not.
    #[test]
    fn the_reports_found_are_the_logs_however_it_is_split(
        lines in proptest::collection::vec(log_line(), 0..12),
        ends_with_newline in any::<bool>(),
        bound in 0usize..32,
        cuts in proptest::collection::vec(any::<prop::sample::Index>(), 0..8),
    ) {
        let mut log = lines.join(&b'\n');
        if ends_with_newline && !lines.is_empty() {
            log.push(b'\n');
        }
        let expected: Vec<Line> = lines
            .iter()
            .filter_map(|line| line.strip_prefix(b"polar-report "))
            .map(|rest| if rest.len() <= bound { Line::Report(rest.to_vec()) } else { Line::TooLong(rest.len()) })
            .collect();
        let mut at: Vec<usize> = cuts.iter().map(|c| c.index(log.len() + 1)).collect();
        at.extend([0, log.len()]);
        at.sort_unstable();
        let mut finder = Lines::new(bound);
        let mut found = Vec::new();
        for pair in at.windows(2) {
            found.extend(finder.feed(&log[pair[0]..pair[1]]));
        }
        found.extend(finder.finish());
        prop_assert_eq!(found, expected);
    }

    /// Whatever happens, in any order: no place is idle while a build waits, a build starts once, the waiting start in
    /// the order they came, and what admission counts is what has started and not ended.
    #[test]
    fn admission_keeps_its_places_and_its_line(cap in 0usize..4, events in proptest::collection::vec(event(), 0..64)) {
        let mut admission = Admission::new(cap);
        let mut next = 0u128;
        let mut running: Vec<Uuid> = Vec::new();
        let mut waiting: Vec<Uuid> = Vec::new();
        let mut started: HashSet<Uuid> = HashSet::new();
        let start = |ids: Vec<BuildRequest>,
                     running: &mut Vec<Uuid>,
                     waiting: &mut Vec<Uuid>,
                     started: &mut HashSet<Uuid>|
         -> Result<(), TestCaseError> {
            for r in ids {
                prop_assert_eq!(Some(&r.build_id), waiting.first(), "the waiting start in the order they came");
                waiting.remove(0);
                prop_assert!(started.insert(r.build_id), "a build starts once");
                running.push(r.build_id);
            }
            Ok(())
        };
        for event in events {
            match event {
                Event::Request => {
                    next += 1;
                    match admission.request(build(next)) {
                        Admitted::Now(r) => {
                            prop_assert!(waiting.is_empty(), "none jumps the line");
                            running.push(r.build_id);
                            started.insert(r.build_id);
                        }
                        Admitted::Waiting(place) => {
                            waiting.push(Uuid::from_u128(next));
                            prop_assert_eq!(place, waiting.len());
                        }
                        Admitted::Duplicate => prop_assert!(false, "a new build is no duplicate"),
                    }
                }
                Event::Finish(which) if !running.is_empty() => {
                    let id = running.remove(which.index(running.len()));
                    let released = admission.finished(id);
                    start(released, &mut running, &mut waiting, &mut started)?;
                }
                Event::Finish(_) => {}
                Event::SetCap(cap) => {
                    let released = admission.set_cap(cap);
                    start(released, &mut running, &mut waiting, &mut started)?;
                }
                Event::Adopt => {
                    next += 1;
                    prop_assert!(admission.adopt(Uuid::from_u128(next)));
                    running.push(Uuid::from_u128(next));
                    started.insert(Uuid::from_u128(next));
                }
                Event::Again(which) => {
                    let known: Vec<Uuid> = running.iter().chain(&waiting).copied().collect();
                    if !known.is_empty() {
                        let id = known[which.index(known.len())];
                        prop_assert!(matches!(admission.request(build(id.as_u128())), Admitted::Duplicate));
                        prop_assert!(!admission.adopt(id) || !waiting.contains(&id));
                    }
                }
            }
            prop_assert_eq!(admission.running(), running.len());
            prop_assert_eq!(admission.waiting(), waiting.len());
            prop_assert!(waiting.is_empty() || admission.running() >= admission.cap(), "no place idle while a build waits");
            prop_assert!(admission.cap() >= 1);
        }
    }

    /// Any mappings, written as an author writes them, read back as themselves, in order.
    #[test]
    fn mappings_read_back_as_written(all in mappings()) {
        prop_assert_eq!(parse(&body(&all)), Ok(all));
    }

    /// Spoil any one entry in any one way: the section is refused, a problem names that entry and the field, and no
    /// problem echoes the value.
    #[test]
    fn a_spoiled_entry_is_named_and_never_echoed(all in mappings().prop_filter("one at least", |a| !a.is_empty()),
                                                 which in any::<prop::sample::Index>(), how in 0usize..12) {
        let i = which.index(all.len());
        let mut written = body(&all);
        let field = spoil(&mut written["repositories"][i], how);
        let problems = parse(&written).unwrap_err();
        prop_assert!(
            problems.iter().any(|p| p.starts_with(&format!("entry {i}: ")) && p.contains(field)),
            "entry {} {}: {:?}", i, field, problems
        );
        prop_assert!(!problems.iter().any(|p| p.contains(MARK)), "{:?}", problems);
    }

    /// A repository named twice is refused, wherever the second is.
    #[test]
    fn a_repository_is_mapped_once(all in mappings().prop_filter("one at least", |a| !a.is_empty()),
                                   which in any::<prop::sample::Index>(), at in any::<prop::sample::Index>()) {
        let again = all[which.index(all.len())].clone();
        let mut twice = all.clone();
        twice.insert(at.index(all.len() + 1), again);
        let problems = parse(&body(&twice)).unwrap_err();
        prop_assert!(problems.iter().any(|p| p.contains("mapped more than once")), "{:?}", problems);
    }

    /// A quantity reads as its number times its unit, in thousandths.
    #[test]
    fn a_quantity_reads_as_its_number_and_unit((text, value) in quantity()) {
        prop_assert_eq!(milli(&text), Some(value));
    }

    /// A request above its limit is refused, and one at or below it is not, whatever the units.
    #[test]
    fn a_request_is_no_more_than_its_limit((request, r) in quantity(), (limit, l) in quantity()) {
        let problems = config(&[
            ("POLAR_ORCHESTRATOR_MEMORY_REQUEST", request),
            ("POLAR_ORCHESTRATOR_MEMORY_LIMIT", limit),
        ])
        .check();
        let refused = problems.iter().any(|p| p.contains("POLAR_ORCHESTRATOR_MEMORY_REQUEST must be no more than"));
        prop_assert_eq!(refused, r > l, "{:?}", problems);
    }

    /// The bounds a line is read at are never wider than the worker's, nor than what is signed, and are what is signed
    /// whenever that is no wider than the worker's.
    #[test]
    fn a_signed_bound_narrows_and_never_widens(forked in bounds(), signed in bounds()) {
        let at = narrowed(&forked, &signed);
        let fields = |b: &Bounds| [b.line, b.string, b.depth, b.tokens, b.items];
        for ((a, f), s) in fields(&at).into_iter().zip(fields(&forked)).zip(fields(&signed)) {
            prop_assert!(a <= f && a <= s);
            prop_assert!(a == f || a == s);
        }
        prop_assert_eq!(narrowed(&forked, &at), at);
        if fields(&signed).into_iter().zip(fields(&forked)).all(|(s, f)| s <= f) {
            prop_assert_eq!(at, signed);
        }
    }
}
